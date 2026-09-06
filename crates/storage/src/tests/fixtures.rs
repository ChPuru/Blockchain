//! A deterministic chain builder for the store's tests.
//!
//! It produces blocks whose shape exercises the parts of the store that are
//! easy to get wrong: a coinbase, ordinary spends of earlier blocks' outputs,
//! and — on request — a *chained* pair where one transaction spends an output
//! created by an earlier transaction in the same block. That last case is the
//! one that punishes applying a [`StateDiff`]'s spends before its creations.
//!
//! Nothing here validates anything. `ferrum-storage` is below `ferrum-chain`
//! and stores what it is told; the fixtures only need to be *consistent*.

use std::collections::BTreeMap;

use ferrum_crypto::{hash160, merkle_root};
use ferrum_types::{
    Amount, Block, BlockHash, BlockHeader, BlockSeal, Coin, CompactTarget, Hash32, OutPoint,
    Script, Transaction, TxIn, TxOut,
};

use crate::tables::{BlockIndexEntry, BlockStatus, header_hash, txid};
use crate::view::StateDiff;

/// Value of every coinbase output the fixtures mint.
pub(crate) const SUBSIDY: u64 = 50 * 100_000_000;

/// A `OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG` script.
pub(crate) fn p2pkh(pkh: &[u8; 20]) -> Script {
    let mut v = vec![0x76, 0xa9, 0x14];
    v.extend_from_slice(pkh);
    v.extend_from_slice(&[0x88, 0xac]);
    Script::new(v)
}

/// A stable 20-byte "address" for a small integer.
pub(crate) fn pkh(n: u64) -> [u8; 20] {
    hash160(&n.to_be_bytes())
}

/// One built block plus everything `Store::connect_block` needs for it.
#[derive(Clone, Debug)]
pub(crate) struct Built {
    /// The block itself.
    pub(crate) block: Block,
    /// Its hash.
    pub(crate) hash: BlockHash,
    /// Its height.
    pub(crate) height: u64,
    /// The index entry the store should file it under.
    pub(crate) entry: BlockIndexEntry,
    /// The UTXO-set change it makes.
    pub(crate) diff: StateDiff,
}

/// Builds a chain, tracking the UTXO set as it goes.
#[derive(Clone, Debug, Default)]
pub(crate) struct ChainBuilder {
    /// The running UTXO set, mirroring what the store should hold.
    pub(crate) utxo: BTreeMap<OutPoint, Coin>,
    /// Outpoints later blocks may spend.
    pub(crate) spendable: Vec<OutPoint>,
    /// Hash of the last block built.
    pub(crate) tip: BlockHash,
    /// Height of the last block built; `None` before the first.
    pub(crate) height: Option<u64>,
}

impl ChainBuilder {
    /// A builder positioned before genesis.
    pub(crate) fn new() -> Self {
        ChainBuilder { tip: BlockHash::ZERO, ..Self::default() }
    }

    /// The height the next block will take.
    pub(crate) fn next_height(&self) -> u64 {
        self.height.map_or(0, |h| h + 1)
    }

    /// Build the next block with `spends` ordinary spends and, when `chained`
    /// is set, one in-block chain: transaction *A* creates an output and
    /// transaction *B* spends it before the block is over.
    pub(crate) fn next(&mut self, spends: usize, chained: bool) -> Built {
        let height = self.next_height();
        let mut created: Vec<(OutPoint, Coin)> = Vec::new();
        let mut spent: Vec<(OutPoint, Coin)> = Vec::new();
        let mut working = self.utxo.clone();
        let mut txs: Vec<Transaction> = Vec::new();

        // -- coinbase --------------------------------------------------
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(Script::new(vec![0x08, (height & 0xff) as u8]))],
            outputs: vec![TxOut::new(Amount::from_grains(SUBSIDY), p2pkh(&pkh(height)))],
            lock_time: 0,
        };
        record(&coinbase, height, true, &mut created, &mut working);
        txs.push(coinbase);

        // -- ordinary spends -------------------------------------------
        for i in 0..spends {
            let Some(op) = self.spendable.pop() else { break };
            let Some(coin) = working.remove(&op) else { continue };
            let tx = Transaction {
                version: 1,
                inputs: vec![TxIn::new(op, Script::new(vec![0x51]))],
                outputs: vec![TxOut::new(coin.value, p2pkh(&pkh(height * 1_000 + i as u64)))],
                lock_time: 0,
            };
            spent.push((op, coin));
            record(&tx, height, false, &mut created, &mut working);
            txs.push(tx);
        }

        // -- an in-block chain ------------------------------------------
        let chain_source = if chained { self.spendable.pop() } else { None };
        if let Some((op, coin)) = chain_source.and_then(|op| working.remove(&op).map(|c| (op, c))) {
            let a = Transaction {
                version: 1,
                inputs: vec![TxIn::new(op, Script::new(vec![0x51]))],
                outputs: vec![TxOut::new(coin.value, p2pkh(&pkh(height + 900_000)))],
                lock_time: 0,
            };
            spent.push((op, coin));
            record(&a, height, false, &mut created, &mut working);
            let mid = OutPoint::new(txid(&a), 0);
            txs.push(a);

            let mid_coin = working.remove(&mid).expect("just recorded");
            let b = Transaction {
                version: 1,
                inputs: vec![TxIn::new(mid, Script::new(vec![0x51]))],
                outputs: vec![TxOut::new(mid_coin.value, p2pkh(&pkh(height + 800_000)))],
                lock_time: 0,
            };
            spent.push((mid, mid_coin));
            record(&b, height, false, &mut created, &mut working);
            txs.push(b);
        }

        self.utxo = working;
        self.assemble(txs, created, spent)
    }

    /// A coinbase-only block paying an arbitrary locking script, so tests can
    /// drive the address indexer with shapes the default fixture never emits.
    pub(crate) fn next_paying_to(&mut self, script: Script) -> Built {
        let height = self.next_height();
        let mut created = Vec::new();
        let mut working = self.utxo.clone();
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(Script::new(vec![0x08, (height & 0xff) as u8]))],
            outputs: vec![TxOut::new(Amount::from_grains(SUBSIDY), script)],
            lock_time: 0,
        };
        record(&coinbase, height, true, &mut created, &mut working);
        self.utxo = working;
        self.assemble(vec![coinbase], created, Vec::new())
    }

    /// Turn a transaction list and its diff into a block, and advance.
    fn assemble(
        &mut self,
        txs: Vec<Transaction>,
        created: Vec<(OutPoint, Coin)>,
        spent: Vec<(OutPoint, Coin)>,
    ) -> Built {
        let height = self.next_height();
        let leaves: Vec<Hash32> = txs.iter().map(|t| txid(t).hash()).collect();
        let header = BlockHeader {
            version: 1,
            prev_hash: self.tip,
            merkle_root: merkle_root(&leaves),
            timestamp_ms: 1_700_000_000_000 + height * 120_000,
            bits: CompactTarget(0x1d00_ffff),
            nonce: height,
        };
        let block = Block::new(header, txs, BlockSeal::POW);
        let hash = header_hash(&block.header);
        let mut work = [0u8; 32];
        work[24..].copy_from_slice(&(height + 1).to_be_bytes());
        let entry = BlockIndexEntry::from_block(&block, height, work, BlockStatus::Valid)
            .expect("fixture blocks are small");

        self.spendable.retain(|op| self.utxo.contains_key(op));
        for (op, _) in &created {
            if self.utxo.contains_key(op) {
                self.spendable.push(*op);
            }
        }
        self.tip = hash;
        self.height = Some(height);

        Built { block, hash, height, entry, diff: StateDiff { spent, created } }
    }

    /// Build `n` blocks, alternating between plain and chained shapes.
    ///
    /// The shape is a function of the block's **height**, not of the loop
    /// index, so `build(10)` followed by `build(6)` produces exactly the chain
    /// a single `build(16)` would. Tests that compare a reorganised store
    /// against a replay from zero depend on that.
    pub(crate) fn build(&mut self, n: usize) -> Vec<Built> {
        (0..n)
            .map(|_| {
                let h = self.next_height();
                let spends = if self.spendable.is_empty() { 0 } else { (h % 3) as usize };
                self.next(spends, h % 4 == 3)
            })
            .collect()
    }
}

/// Record a transaction's outputs into the created list and the working set.
fn record(
    tx: &Transaction,
    height: u64,
    is_coinbase: bool,
    created: &mut Vec<(OutPoint, Coin)>,
    working: &mut BTreeMap<OutPoint, Coin>,
) {
    let id = txid(tx);
    for (vout, out) in tx.outputs.iter().enumerate() {
        let op = OutPoint::new(id, vout as u32);
        let coin = Coin {
            value: out.value,
            script_pubkey: out.script_pubkey.clone(),
            height,
            is_coinbase,
        };
        created.push((op, coin.clone()));
        working.insert(op, coin);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builder_produces_a_contiguous_chain() {
        let mut b = ChainBuilder::new();
        let built = b.build(6);
        assert_eq!(built.len(), 6);
        for (i, blk) in built.iter().enumerate() {
            assert_eq!(blk.height, i as u64);
            assert_eq!(blk.entry.height, i as u64);
            if i > 0 {
                assert_eq!(blk.block.header.prev_hash, built[i - 1].hash);
            } else {
                assert_eq!(blk.block.header.prev_hash, BlockHash::ZERO);
            }
        }
    }

    #[test]
    fn hashes_are_unique() {
        let mut b = ChainBuilder::new();
        let built = b.build(20);
        let mut hashes: Vec<BlockHash> = built.iter().map(|x| x.hash).collect();
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(hashes.len(), 20);
    }

    #[test]
    fn later_blocks_actually_spend() {
        let mut b = ChainBuilder::new();
        let built = b.build(12);
        assert!(built.iter().any(|x| !x.diff.spent.is_empty()), "no block spent anything");
    }

    #[test]
    fn a_chained_block_spends_an_output_it_created() {
        let mut b = ChainBuilder::new();
        b.build(6);
        let chained = b.next(0, true);
        let created: Vec<OutPoint> = chained.diff.created.iter().map(|(o, _)| *o).collect();
        assert!(
            chained.diff.spent.iter().any(|(o, _)| created.contains(o)),
            "the chained shape must spend one of its own outputs"
        );
    }

    #[test]
    fn the_running_utxo_set_matches_the_applied_diffs() {
        let mut b = ChainBuilder::new();
        let built = b.build(10);
        let mut expected: BTreeMap<OutPoint, Coin> = BTreeMap::new();
        for blk in &built {
            for (op, coin) in &blk.diff.created {
                expected.insert(*op, coin.clone());
            }
            for (op, _) in &blk.diff.spent {
                expected.remove(op);
            }
        }
        assert_eq!(expected, b.utxo);
    }

    #[test]
    fn splitting_a_build_gives_the_same_chain() {
        let mut whole = ChainBuilder::new();
        let a = whole.build(16);
        let mut split = ChainBuilder::new();
        let mut b = split.build(10);
        b.extend(split.build(6));
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.hash, y.hash);
            assert_eq!(x.diff, y.diff);
        }
    }

    #[test]
    fn the_merkle_root_commits_to_the_transactions() {
        let mut b = ChainBuilder::new();
        let blk = b.next(0, false);
        let leaves: Vec<Hash32> = blk.block.txs.iter().map(|t| txid(t).hash()).collect();
        assert_eq!(blk.block.header.merkle_root, merkle_root(&leaves));
    }
}
