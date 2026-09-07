//! The per-request work budget the explorer routes run under.
//!
//! These tests drive the handlers against a hand-written [`ChainProvider`] that
//! counts block-body reads, because the thing under test is *how much work one
//! HTTP request can cause*, and that is a number the real fixture cannot make
//! visible. Every transaction in this chain lives in its own block, which is
//! the worst case for a lookup that resolves one transaction by decoding a
//! whole block.

use std::sync::Arc;

use ferrum_consensus::BlockTemplate;
use ferrum_crypto::Address;
use ferrum_storage::{BlockIndexEntry, BlockStatus, TxLocation};
use ferrum_types::{
    Amount, Block, BlockHash, BlockHeader, BlockSeal, ChainParams, Coin, Hash32, Network, OutPoint,
    Script, Transaction, TxIn, TxOut, Txid,
};
use parking_lot::Mutex;

use crate::error::{RpcError, RpcErrorCode};
use crate::handlers::lookup::{BlockRead, BlockReader, SPEND_SCAN_LIMIT};
use crate::handlers::{address, explorer};
use crate::provider::{ChainProvider, SubmitOutcome};
use crate::tests::fixture::{StubMempool, key};

/// A chain where every transaction sits at index 0 of its own block.
///
/// [`ChainProvider::block`] counts its calls: that counter is the cost the
/// explorer imposes on the node, one whole-block Borsh decode at a time.
#[derive(Debug)]
struct CountingChain {
    params: ChainParams,
    /// How many outputs the transaction under test pays.
    outputs: usize,
    /// How many rows the address index answers a history query with.
    history_rows: usize,
    /// Block-body reads so far.
    reads: Mutex<u64>,
}

impl CountingChain {
    fn new(outputs: usize, history_rows: usize) -> Self {
        CountingChain { params: ChainParams::devnet(), outputs, history_rows, reads: Mutex::new(0) }
    }

    /// How many whole blocks have been read and decoded.
    fn reads(&self) -> u64 {
        *self.reads.lock()
    }

    /// The script every synthetic output pays.
    fn script() -> Script {
        let (_, public) = key(7);
        Address::p2pkh(Network::Devnet, &public).script_pubkey()
    }

    /// The block that holds `txid`. Distinct per transaction on purpose: a
    /// per-request cache must not be what makes these tests pass.
    fn block_of(txid: &Txid) -> BlockHash {
        let mut bytes = txid.0.to_bytes();
        // Flip a byte so a block hash is never equal to the txid it holds.
        bytes[0] ^= 0xff;
        BlockHash(Hash32::from_bytes(bytes))
    }

    /// The block stored under `hash`, derived from the hash so the chain needs
    /// no state.
    ///
    /// The single transaction's one input spends an outpoint that belongs to
    /// nothing, so a spender scan never finds a match and always runs to its
    /// limit.
    fn body(&self, hash: &BlockHash) -> Block {
        let mut bytes = hash.0.to_bytes();
        bytes[1] ^= 0xff;
        let funding = OutPoint::new(Txid(Hash32::from_bytes(bytes)), 0);
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn::new(funding, Script::EMPTY)],
            outputs: (0..self.outputs)
                .map(|_| TxOut::new(Amount::from_grains(1_000), Self::script()))
                .collect(),
            lock_time: 0,
        };
        let header = BlockHeader {
            version: 1,
            prev_hash: BlockHash::ZERO,
            merkle_root: Hash32::ZERO,
            timestamp_ms: 1_700_000_000_000,
            bits: self.params.genesis_bits,
            nonce: 0,
        };
        Block::new(header, vec![tx], BlockSeal::POW)
    }

    /// The id of the transaction the test asks about.
    ///
    /// Any id will do: this chain answers `tx_location` for every txid, and the
    /// block it names holds a transaction with `outputs` already-spent outputs.
    fn subject_txid() -> Txid {
        Txid(Hash32::from_bytes([0x11u8; 32]))
    }
}

impl ChainProvider for CountingChain {
    fn params(&self) -> &ChainParams {
        &self.params
    }

    fn tip(&self) -> Result<(BlockHash, u64), RpcError> {
        Ok((BlockHash(Hash32::from_bytes([9u8; 32])), 100))
    }

    fn tip_work(&self) -> Result<[u8; 32], RpcError> {
        Ok([0u8; 32])
    }

    fn engine_id_at(&self, _height: u64) -> u8 {
        BlockSeal::ENGINE_POW
    }

    fn finalized_height(&self) -> Option<u64> {
        None
    }

    fn index_enabled(&self) -> bool {
        true
    }

    fn block(&self, hash: &BlockHash) -> Result<Option<Block>, RpcError> {
        *self.reads.lock() += 1;
        Ok(Some(self.body(hash)))
    }

    fn header_entry(&self, hash: &BlockHash) -> Result<Option<BlockIndexEntry>, RpcError> {
        // A header lookup does not read a body, so it does not count.
        Ok(Some(
            BlockIndexEntry::from_block(&self.body(hash), 1, [0u8; 32], BlockStatus::Valid)
                .expect("a one-transaction block fits an index entry"),
        ))
    }

    fn hash_at_height(&self, _height: u64) -> Result<Option<BlockHash>, RpcError> {
        Ok(None)
    }

    fn coin(&self, _out_point: &OutPoint) -> Result<Option<Coin>, RpcError> {
        // Nothing is unspent, so every output takes the spender-scan path.
        Ok(None)
    }

    fn utxo_count(&self) -> Result<u64, RpcError> {
        Ok(0)
    }

    fn state_root(&self) -> Result<Hash32, RpcError> {
        Ok(Hash32::ZERO)
    }

    fn tx_location(&self, txid: &Txid) -> Result<Option<TxLocation>, RpcError> {
        Ok(Some(TxLocation::new(Self::block_of(txid), 0)))
    }

    fn address_history(
        &self,
        _key: &[u8],
        _from_height: u64,
        limit: usize,
    ) -> Result<Vec<(u64, Txid)>, RpcError> {
        Ok((0..limit.min(self.history_rows)).map(|i| (1u64, row_txid(i))).collect())
    }

    fn address_history_after(
        &self,
        _key: &[u8],
        after: Option<(u64, u32)>,
        limit: usize,
    ) -> Result<Vec<(u64, u32, Txid)>, RpcError> {
        let start = after.map_or(0usize, |(_, idx)| usize::try_from(idx).unwrap_or(usize::MAX));
        Ok((start..self.history_rows.min(start.saturating_add(limit)))
            .map(|i| (1u64, u32::try_from(i).unwrap_or(u32::MAX), row_txid(i)))
            .collect())
    }

    fn utxos_for_scripts(&self, _scripts: &[Script]) -> Result<Vec<(OutPoint, Coin)>, RpcError> {
        Ok(Vec::new())
    }

    fn submit_block(&self, _block: Block) -> Result<SubmitOutcome, RpcError> {
        Err(RpcError::new(RpcErrorCode::InternalError, "the counting chain accepts no blocks"))
    }

    fn build_template(
        &self,
        _payout: &Script,
        _extra_nonce: u64,
        _txs: Vec<Transaction>,
        _now_ms: u64,
    ) -> Result<BlockTemplate, RpcError> {
        Err(RpcError::new(RpcErrorCode::TemplateFailed, "the counting chain builds no templates"))
    }
}

/// A distinct, deterministic transaction id for history row `i`.
fn row_txid(i: usize) -> Txid {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_le_bytes());
    bytes[31] = 0xaa;
    Txid(Hash32::from_bytes(bytes))
}

#[test]
fn the_transaction_page_budgets_its_spender_scan_across_all_outputs() {
    // Six spent outputs, and an address whose history answers with the full
    // `SPEND_SCAN_LIMIT` of candidates every time it is asked.
    let chain = Arc::new(CountingChain::new(6, SPEND_SCAN_LIMIT));
    let pool = StubMempool::new();
    let subject = CountingChain::subject_txid();

    let view = explorer::tx_view(&*chain, &pool, &subject.to_hex()).expect("the page renders");
    assert_eq!(view.outputs.len(), 6);

    // The scan limit is a budget for the *request*, not for each output: six
    // outputs must not cost six times the scan.
    let allowed = u64::try_from(SPEND_SCAN_LIMIT).unwrap_or(u64::MAX) + 8;
    assert!(
        chain.reads() <= allowed,
        "one transaction page read {} whole blocks; the per-request budget allows {allowed}",
        chain.reads()
    );
}

#[test]
fn the_reader_decodes_one_block_once() {
    let chain = CountingChain::new(1, 0);
    let mut reader = BlockReader::new(&chain);
    let hash = BlockHash(Hash32::from_bytes([0x55u8; 32]));
    assert!(matches!(reader.read(&hash).expect("read"), BlockRead::Found(_)));
    assert!(matches!(reader.read(&hash).expect("read"), BlockRead::Found(_)));
    assert_eq!(chain.reads(), 1, "the second read decoded the same block again");
    assert!(!reader.truncated());
}

#[test]
fn the_reader_always_answers_once_and_then_stops() {
    let chain = CountingChain::new(1, 0);
    // One byte of budget: enough for the first read, whatever the block costs.
    let mut reader = BlockReader::with_budget(&chain, 1, 0);
    let first = BlockHash(Hash32::from_bytes([0x56u8; 32]));
    let second = BlockHash(Hash32::from_bytes([0x57u8; 32]));

    assert!(matches!(reader.read(&first).expect("read"), BlockRead::Found(_)));
    assert!(!reader.truncated(), "the first read is always allowed");
    assert!(matches!(reader.read(&second).expect("read"), BlockRead::OverBudget));
    assert!(reader.truncated(), "a refused read must be visible to the caller");
    assert_eq!(chain.reads(), 1);
}

#[test]
fn an_address_walk_that_runs_out_of_budget_reports_an_incomplete_balance() {
    // Two hundred history rows, each in a block of its own, and a budget that
    // covers one of them.
    let chain = CountingChain::new(1, 200);
    let pool = StubMempool::new();
    let (_, public) = key(7);
    let address = Address::p2pkh(Network::Devnet, &public);

    let mut reader = BlockReader::with_budget(&chain, 1, 0);
    let report = address::address_report_with(&mut reader, &pool, &address.encode())
        .expect("the page renders");

    assert!(!report.complete, "a balance the walk did not finish must not be reported as fact");
    assert!(chain.reads() <= 2, "the walk read {} blocks past its budget", chain.reads());
}
