//! Fixtures: standard transactions that need no key management, and a real
//! devnet chain for the reorg tests.
//!
//! # Why P2SH-of-`OP_1` and not `OP_1`
//!
//! Relay policy refuses any output [`classify`] does not name, and a bare
//! `OP_1` is `NonStandard`. So every fixture here pays to
//! `p2sh_of(OP_1)` — a genuine standard template — and unlocks it with a
//! `script_sig` that pushes the one-byte redeem script. That keeps the
//! fixtures about mempool behaviour instead of about signing, while still
//! exercising the standardness rule rather than tunnelling under it.
//!
//! [`classify`]: ferrum_script::templates::classify

use std::sync::Arc;

use ferrum_chain::{ChainManager, StoreHeaderView, build_coinbase_script_sig, compute_merkle_root};
use ferrum_consensus::{EngineRouter, HeaderView, PowEngine, compact_to_target, hash_meets_target};
use ferrum_script::templates::{op_return, p2sh_of};
use ferrum_storage::{
    MapView, OverlayView, StateView, Store, StoreConfig, header_hash, txid as txid_of,
};
use ferrum_types::{
    Amount, Block, BlockHash, BlockHeader, BlockSeal, ChainParams, Coin, CompactTarget, Hash32,
    OutPoint, Script, Transaction, TxIn, TxOut, Txid,
};

use crate::{MempoolConfig, MempoolEntry};

/// Devnet parameters with a one-block coinbase maturity, so a fixture does not
/// have to mine a hundred blocks to spend anything.
#[must_use]
pub fn params() -> ChainParams {
    let mut p = ChainParams::devnet();
    p.coinbase_maturity = 1;
    p
}

/// A config on [`params`] with the relay floor disabled, for tests that are
/// about something other than fees.
#[must_use]
pub fn cfg() -> MempoolConfig {
    MempoolConfig::new(params()).with_min_fee_rate(0)
}

/// The redeem script every fixture output is locked behind: `OP_1`.
#[must_use]
pub fn redeem() -> Script {
    Script::new(vec![0x51])
}

/// The standard `script_pubkey` every fixture pays to.
#[must_use]
pub fn locked() -> Script {
    p2sh_of(&redeem())
}

/// The `script_sig` that satisfies [`locked`]: a single push of [`redeem`].
#[must_use]
pub fn unlock() -> Script {
    Script::new(vec![0x01, 0x51])
}

/// A transaction spending `inputs` and paying each of `outputs` grains to
/// [`locked`].
#[must_use]
pub fn tx(inputs: &[OutPoint], outputs: &[u64]) -> Transaction {
    Transaction {
        version: 1,
        inputs: inputs.iter().map(|op| TxIn::new(*op, unlock())).collect(),
        outputs: outputs.iter().map(|v| TxOut::new(Amount::from_grains(*v), locked())).collect(),
        lock_time: 0,
    }
}

/// [`tx`] with `pad` bytes of `OP_RETURN` payload appended as a final output,
/// so a test can move a transaction's size without moving its value.
#[must_use]
pub fn padded_tx(inputs: &[OutPoint], outputs: &[u64], pad: usize) -> Transaction {
    let mut t = tx(inputs, outputs);
    let payload = vec![0xabu8; pad];
    let script = op_return(&payload).expect("payload within the 80-byte limit");
    t.outputs.push(TxOut::new(Amount::ZERO, script));
    t
}

/// [`tx`] with a `lock_time` and a non-final sequence on every input.
#[must_use]
pub fn timelocked_tx(inputs: &[OutPoint], outputs: &[u64], lock_time: u32) -> Transaction {
    let mut t = tx(inputs, outputs);
    t.lock_time = lock_time;
    for input in &mut t.inputs {
        // `u32::MAX` on every input makes a transaction final regardless of
        // `lock_time` (SPEC §4.3), so the fixture must opt out of it.
        input.sequence = 0;
    }
    t
}

/// The id of a transaction.
#[must_use]
pub fn id(t: &Transaction) -> Txid {
    txid_of(t)
}

/// The outpoint of `t`'s output `vout`.
#[must_use]
pub fn out(t: &Transaction, vout: u32) -> OutPoint {
    OutPoint::new(id(t), vout)
}

/// An outpoint of a transaction nothing in the fixture has ever seen.
#[must_use]
pub fn unknown_out(seed: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid(Hash32::from_bytes([seed; 32])), vout)
}

/// A coin paying `value` grains to [`locked`].
#[must_use]
pub fn coin(value: u64, height: u64, is_coinbase: bool) -> Coin {
    Coin { value: Amount::from_grains(value), script_pubkey: locked(), height, is_coinbase }
}

/// A view holding the listed coins.
#[must_use]
pub fn view_with(entries: &[(OutPoint, Coin)]) -> MapView {
    entries.iter().cloned().collect()
}

/// A view holding one coin of `value` grains at `seed`, and that outpoint.
#[must_use]
pub fn funded(seed: u8, value: u64) -> (MapView, OutPoint) {
    let op = unknown_out(seed, 0);
    (view_with(&[(op, coin(value, 1, false))]), op)
}

/// The entry a pool holds for `t`, or a panic naming the missing id.
#[must_use]
pub fn entry_of(pool: &crate::Mempool, t: &Transaction) -> MempoolEntry {
    pool.get(&id(t)).unwrap_or_else(|| panic!("{} is not in the pool", id(t)))
}

// ---------------------------------------------------------------- real chain

/// A whole devnet chain — store, engines, manager — with genesis connected.
///
/// The reorg tests are built on this rather than on a hand-rolled fixture
/// because a mempool that reconciles correctly against a made-up
/// `disconnected`/`connected` pair and incorrectly against the real thing is
/// exactly the bug this crate is most likely to have.
pub struct TestChain {
    /// The store, which is also the [`StateView`] the mempool reads.
    pub store: Arc<Store>,
    /// The parameters in force.
    pub params: ChainParams,
    /// The engine router.
    pub engines: Arc<EngineRouter>,
    /// The chain manager.
    pub chain: ChainManager,
}

impl std::fmt::Debug for TestChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestChain").field("tip", &self.chain.tip()).finish_non_exhaustive()
    }
}

impl TestChain {
    /// A fresh in-memory chain on [`params`], with genesis connected.
    pub fn new() -> Self {
        Self::with_params(params())
    }

    /// A fresh in-memory chain on custom parameters.
    pub fn with_params(params: ChainParams) -> Self {
        let store = Arc::new(
            Store::open_in_memory(StoreConfig::default().with_chain_id(params.chain_id))
                .expect("in-memory store opens"),
        );
        let engines = Arc::new(EngineRouter::new(params.clone()).expect("router builds"));
        let chain = ChainManager::open(Arc::clone(&store), params.clone(), Arc::clone(&engines))
            .expect("manager opens");
        chain.init_genesis().expect("genesis initialises");
        TestChain { store, params, engines, chain }
    }

    /// The active tip.
    pub fn tip(&self) -> (BlockHash, u64) {
        self.chain.tip()
    }

    /// The active tip's height.
    pub fn height(&self) -> u64 {
        self.chain.tip().1
    }

    /// The median time past of the active tip, in seconds.
    pub fn mtp(&self) -> u64 {
        let (hash, _) = self.tip();
        StoreHeaderView::new(&self.store, &self.params).median_time_past(&hash).unwrap_or(0)
    }

    /// The store as a state view.
    pub fn view(&self) -> &dyn StateView {
        self.store.as_ref()
    }

    /// Build a valid block on `parent` carrying `txs`.
    pub fn mine_on(&self, parent: &BlockHash, txs: Vec<Transaction>, extra_nonce: u64) -> Block {
        let entry = self.store.get_header(parent).expect("read").expect("known parent");
        let height = entry.height.saturating_add(1);
        let view = StoreHeaderView::new(&self.store, &self.params);
        let engine = self.engines.engine_for_height(height);
        let bits = engine.next_bits(&entry.header, &view).expect("next_bits");
        let mtp_s = view.median_time_past(parent).unwrap_or(0);
        let stamp = entry
            .header
            .timestamp_ms
            .saturating_add(self.params.target_spacing_ms)
            .max(mtp_s.saturating_mul(1_000).saturating_add(1));

        let fees = self.fees_of(&txs, height);
        let reward = self.params.block_subsidy(height).checked_add(fees).expect("reward fits");
        let mut all = vec![coinbase(height, reward, &extra_nonce.to_le_bytes())];
        all.extend(txs);
        block_of(all, *parent, stamp, bits)
    }

    /// Mine `txs` onto the current tip and accept the block.
    pub fn mine_and_accept(&self, txs: Vec<Transaction>) -> Block {
        let (tip, _) = self.tip();
        let block = self.mine_on(&tip, txs, 0);
        self.chain.accept_block(block.clone()).expect("block accepts");
        block
    }

    /// Accept a block, returning the outcome.
    pub fn accept(&self, block: Block) -> ferrum_chain::AcceptOutcome {
        self.chain.accept_block(block).expect("block accepts")
    }

    /// The block stored under `hash`.
    pub fn block(&self, hash: &BlockHash) -> Block {
        self.store.get_block(hash).expect("read").expect("body stored")
    }

    /// The spendable coinbase outpoint of the block at `height`.
    pub fn coinbase_out(&self, height: u64) -> OutPoint {
        let hash = self.store.hash_at_height(height).expect("read").expect("height on chain");
        let block = self.block(&hash);
        let cb = block.coinbase().expect("coinbase present");
        out(cb, 0)
    }

    /// Total fees the listed transactions pay, resolving in-block dependencies.
    fn fees_of(&self, txs: &[Transaction], height: u64) -> Amount {
        let base: &dyn StateView = self.store.as_ref();
        let mut overlay = OverlayView::new(base);
        let mut fees = Amount::ZERO;
        for t in txs {
            let mut inputs = Amount::ZERO;
            for input in &t.inputs {
                if let Some(c) = overlay.get_coin(&input.prev_out).expect("read") {
                    inputs = inputs.checked_add(c.value).expect("input sum fits");
                }
            }
            let outputs = t.total_output().unwrap_or(Amount::ZERO);
            fees = fees.checked_add(inputs.saturating_sub(outputs)).expect("fee sum fits");
            for input in &t.inputs {
                let _ = overlay.spend(&input.prev_out).expect("read");
            }
            let tid = id(t);
            for (vout, o) in t.outputs.iter().enumerate() {
                let index = u32::try_from(vout).expect("vout fits");
                overlay.add(OutPoint::new(tid, index), Coin::new(o.clone(), height, false));
            }
        }
        fees
    }
}

/// A coinbase paying `value` to [`locked`].
#[must_use]
pub fn coinbase(height: u64, value: Amount, extra: &[u8]) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn::coinbase(
            build_coinbase_script_sig(height, extra).expect("extra fits the script_sig window"),
        )],
        outputs: vec![TxOut::new(value, locked())],
        lock_time: 0,
    }
}

/// Grind a nonce until the header meets its own target.
#[must_use]
pub fn seal_pow(mut header: BlockHeader) -> BlockHeader {
    let target = compact_to_target(header.bits).expect("test bits expand");
    loop {
        if hash_meets_target(&header_hash(&header), target) {
            return header;
        }
        PowEngine::advance_search(&mut header);
    }
}

/// Build and seal a block over an explicit parent.
#[must_use]
pub fn block_of(
    txs: Vec<Transaction>,
    prev_hash: BlockHash,
    timestamp_ms: u64,
    bits: CompactTarget,
) -> Block {
    let header = seal_pow(BlockHeader {
        version: 1,
        prev_hash,
        merkle_root: compute_merkle_root(&txs),
        timestamp_ms,
        bits,
        nonce: 0,
    });
    Block::new(header, txs, BlockSeal::POW)
}
