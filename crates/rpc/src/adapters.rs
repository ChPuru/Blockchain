//! The production [`ChainProvider`]: a `ChainManager` plus its `Store`.
//!
//! Every method here is synchronous and touches `redb`. Nothing in this file is
//! `async`, and that is deliberate — it makes the "did you remember
//! `spawn_blocking`?" question answerable by looking at the *caller* rather
//! than by auditing the whole crate. The only callers are inside
//! [`crate::context::blocking`].
//!
//! # `submitblock` is a block-entry path like any other
//!
//! SPEC §3.2 rule 10 — `timestamp_ms <= now + max_future_block_time_ms` — is
//! the one validation rule that reads a clock, which is why it lives above the
//! `apply_block` seam rather than inside it. The node applies it in
//! `Relay::accept_block`, so gossip, sync and the miner all get it. An RPC
//! submission does not go through `Relay`, and a consensus rule that one entry
//! point enforces and another does not is a split waiting to happen: the block
//! this node accepts is the block every peer rejects, and the miner then builds
//! on a tip nobody will follow. So [`ChainHandle`] carries a clock and checks
//! the same rule here, with the same consequence `Relay` gives it — refused,
//! and **not** recorded invalid, because our clock is what made it
//! unacceptable and in an hour it may be fine.

use std::sync::Arc;

use ferrum_chain::{AcceptOutcome, ChainManager};
use ferrum_consensus::{BlockTemplate, Work, check_future_time};
use ferrum_storage::{BlockIndexEntry, Store, TxLocation};
use ferrum_types::{
    Block, BlockHash, ChainParams, Coin, Hash32, OutPoint, Script, Transaction, Txid,
};

use crate::context::{Clock, SystemClock};
use crate::error::{RpcError, RpcErrorCode};
use crate::provider::{ChainProvider, SubmitOutcome};

/// A [`ChainProvider`] backed by the real chain.
#[derive(Clone, Debug)]
pub struct ChainHandle {
    chain: Arc<ChainManager>,
    store: Arc<Store>,
    index_enabled: bool,
    clock: Arc<dyn Clock>,
}

impl ChainHandle {
    /// Wrap a running chain, on the system clock.
    ///
    /// `index_enabled` mirrors `StoreConfig::index_transactions`; the store
    /// does not publish it, and answering "why is `getbalance` failing?" with
    /// a clear code beats letting the query fail deeper down.
    #[must_use]
    pub fn new(chain: Arc<ChainManager>, index_enabled: bool) -> Self {
        Self::with_clock(chain, index_enabled, Arc::new(SystemClock))
    }

    /// [`ChainHandle::new`] on an injected clock.
    ///
    /// The clock is only read by [`ChainProvider::submit_block`], for the
    /// future-time rule described in the module docs. Injecting it is what lets
    /// a test pin "now" and show that the *same block* is refused by one clock
    /// and accepted by another — which is also the proof that a refusal here
    /// records nothing.
    #[must_use]
    pub fn with_clock(
        chain: Arc<ChainManager>,
        index_enabled: bool,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let store = Arc::clone(chain.store());
        ChainHandle { chain, store, index_enabled, clock }
    }

    /// The chain manager underneath, for callers that need more than the trait.
    #[must_use]
    pub fn chain(&self) -> &Arc<ChainManager> {
        &self.chain
    }

    /// The store underneath.
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }
}

impl ChainProvider for ChainHandle {
    fn params(&self) -> &ChainParams {
        self.chain.params()
    }

    fn tip(&self) -> Result<(BlockHash, u64), RpcError> {
        Ok(self.chain.tip())
    }

    fn tip_work(&self) -> Result<[u8; 32], RpcError> {
        let (hash, _) = self.chain.tip();
        Ok(self.chain.total_work(&hash).unwrap_or(Work::ZERO).to_be_bytes())
    }

    fn engine_id_at(&self, height: u64) -> u8 {
        self.chain.engines().engine_id_for_height(height)
    }

    fn finalized_height(&self) -> Option<u64> {
        let (_, height) = self.chain.tip();
        let view = ferrum_chain::StoreHeaderView::new(&self.store, self.chain.params());
        self.chain.engines().engine_for_height(height).finalized_height(&view)
    }

    fn index_enabled(&self) -> bool {
        self.index_enabled
    }

    fn block(&self, hash: &BlockHash) -> Result<Option<Block>, RpcError> {
        Ok(self.store.get_block(hash)?)
    }

    fn header_entry(&self, hash: &BlockHash) -> Result<Option<BlockIndexEntry>, RpcError> {
        Ok(self.store.get_header(hash)?)
    }

    fn hash_at_height(&self, height: u64) -> Result<Option<BlockHash>, RpcError> {
        Ok(self.store.hash_at_height(height)?)
    }

    fn coin(&self, out_point: &OutPoint) -> Result<Option<Coin>, RpcError> {
        Ok(self.store.get_coin(out_point)?)
    }

    fn utxo_count(&self) -> Result<u64, RpcError> {
        Ok(self.store.utxo_count()?)
    }

    fn state_root(&self) -> Result<Hash32, RpcError> {
        Ok(self.store.state_root()?)
    }

    fn tx_location(&self, txid: &Txid) -> Result<Option<TxLocation>, RpcError> {
        if !self.index_enabled {
            return Err(RpcError::index_disabled("looking a transaction up by id"));
        }
        Ok(self.store.tx_location(txid)?)
    }

    fn address_history(
        &self,
        key: &[u8],
        from_height: u64,
        limit: usize,
    ) -> Result<Vec<(u64, Txid)>, RpcError> {
        if !self.index_enabled {
            return Err(RpcError::index_disabled("address history"));
        }
        Ok(self.store.address_history(key, from_height, limit)?)
    }

    fn address_history_after(
        &self,
        key: &[u8],
        after: Option<(u64, u32)>,
        limit: usize,
    ) -> Result<Vec<(u64, u32, Txid)>, RpcError> {
        if !self.index_enabled {
            return Err(RpcError::index_disabled("address history"));
        }
        Ok(self.store.address_history_after(key, after, limit)?)
    }

    fn utxos_for_scripts(&self, scripts: &[Script]) -> Result<Vec<(OutPoint, Coin)>, RpcError> {
        // A `BTreeSet` rather than a `Vec` scan: the faucet wallet hands over
        // its whole address book, and consensus-adjacent code never iterates a
        // hash container.
        let wanted: std::collections::BTreeSet<&[u8]> =
            scripts.iter().map(Script::as_bytes).collect();
        if wanted.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in self.store.iter_utxos()? {
            let (out_point, coin) = entry?;
            if wanted.contains(coin.script_pubkey.as_bytes()) {
                out.push((out_point, coin));
            }
        }
        Ok(out)
    }

    fn submit_block(&self, block: Block) -> Result<SubmitOutcome, RpcError> {
        let hash = ferrum_storage::header_hash(&block.header);
        // SPEC §3.2 rule 10, applied before anything reaches the seam. See the
        // module docs: this is the only block-entry path that does not go
        // through `Relay`, and the rule has to hold on all of them.
        check_future_time(&block.header, self.clock.now_ms(), self.chain.params()).map_err(
            |e| {
                tracing::warn!(
                    %hash,
                    timestamp_ms = block.header.timestamp_ms,
                    "submitted block is too far in the future; refused without recording it invalid"
                );
                RpcError::from(e)
            },
        )?;
        let outcome = self.chain.accept_block(block)?;
        // Orphans that were waiting on this block are now connectable. Doing
        // it here rather than in `ChainManager::accept_block` keeps the
        // outcome we return describing *this* block; see the manager's docs.
        if let Err(e) = self.chain.accept_orphan_descendants(&hash) {
            tracing::warn!(hash = %hash, error = %e, "draining orphans after submitblock failed");
        }
        Ok(match outcome {
            AcceptOutcome::Extended(h) => SubmitOutcome::Extended(h),
            AcceptOutcome::Reorged { from, to, disconnected, connected } => {
                SubmitOutcome::Reorged {
                    from,
                    to,
                    disconnected: disconnected.len(),
                    connected: connected.len(),
                }
            }
            AcceptOutcome::SideChain(h) => SubmitOutcome::SideChain(h),
            AcceptOutcome::Duplicate => SubmitOutcome::Duplicate,
            AcceptOutcome::Orphan => SubmitOutcome::Orphan,
            // `AcceptOutcome` is `#[non_exhaustive]`: a future variant reads
            // as "held, not connected", which is the safe answer for a caller
            // deciding whether to keep mining on this block.
            _ => SubmitOutcome::Orphan,
        })
    }

    fn build_template(
        &self,
        payout: &Script,
        extra_nonce: u64,
        txs: Vec<Transaction>,
        now_ms: u64,
    ) -> Result<BlockTemplate, RpcError> {
        self.chain
            .build_template(payout, extra_nonce, txs, now_ms)
            .map_err(|e| RpcError::new(RpcErrorCode::TemplateFailed, e.to_string()))
    }
}
