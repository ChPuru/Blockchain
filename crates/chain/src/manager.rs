//! [`ChainManager`] — the one place a block becomes part of history.
//!
//! Everything the node, the RPC layer and the miner do to the chain goes
//! through here, and every path ends in the same routine
//! ([`crate::reorg::connect_tip_block`]), so there is exactly one implementation
//! of "what it means to accept a block".
//!
//! # Concurrency
//!
//! Acceptance is serialised by one mutex. `redb` would serialise the writes
//! anyway, but fork choice reads the tip, decides, and then writes — and a
//! decision made against a tip that moved in between is a decision about a
//! chain that no longer exists. The tip itself is cached behind an `RwLock` so
//! that readers never queue behind a validating block.
//!
//! # Layout
//!
//! [`events`] owns [`AcceptOutcome`], [`ChainEvent`] and the bounded fan-out;
//! [`orphans`] owns the capped pool of parentless blocks. Both are the parts
//! that grow, and both are load-shedding rather than unbounded.

pub mod events;
pub mod orphans;

use std::sync::Arc;
use std::sync::mpsc::Receiver;

use ferrum_consensus::{BlockTemplate, EngineRouter, HeaderView, Work};
use ferrum_storage::{BlockIndexEntry, BlockStatus, EmptyView, Store, header_hash};
use ferrum_types::{Block, BlockHash, BlockHeader, ChainParams, Script, Transaction};
use parking_lot::{Mutex, RwLock};

use crate::ctx::BlockCtx;
use crate::error::ChainError;
use crate::fork_choice::{TipCandidate, cumulative_work, is_better};
use crate::genesis::genesis_block;
use crate::reorg::{ReorgPlan, connect_tip_block, entry_of, execute_reorg, plan_reorg};
use crate::validate::check_block_sanity;
use crate::view::StoreHeaderView;

pub use self::events::{AcceptOutcome, CHAIN_EVENT_CAPACITY, ChainEvent, EventBus};
pub use self::orphans::{MAX_ORPHAN_BLOCKS, OrphanPool};

/// The cached active tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TipState {
    hash: BlockHash,
    height: u64,
    total_work: Work,
}

impl TipState {
    const EMPTY: TipState = TipState { hash: BlockHash::ZERO, height: 0, total_work: Work::ZERO };

    fn candidate(self) -> TipCandidate {
        TipCandidate::new(self.hash, self.height, self.total_work)
    }
}

/// The chain: a store, an engine router and the rules that connect them.
#[derive(Debug)]
pub struct ChainManager {
    store: Arc<Store>,
    params: ChainParams,
    engines: Arc<EngineRouter>,
    tip: RwLock<TipState>,
    accept_lock: Mutex<()>,
    events: EventBus,
    orphans: Mutex<OrphanPool>,
}

impl ChainManager {
    /// Open a chain over an existing store.
    ///
    /// Does **not** create genesis; call [`ChainManager::init_genesis`] for
    /// that. Opening and initialising are separate so that a node can inspect a
    /// datadir without writing to it.
    ///
    /// # Errors
    ///
    /// [`ChainError::Storage`] if the tip cannot be read, and
    /// [`ChainError::MissingHeaderEntry`] if the tip names a header the store
    /// does not have — which means the database is corrupt.
    pub fn open(
        store: Arc<Store>,
        params: ChainParams,
        engines: Arc<EngineRouter>,
    ) -> Result<Self, ChainError> {
        let tip = match store.tip()? {
            Some((hash, height)) => {
                let entry = entry_of(&store, &hash)?;
                TipState { hash, height, total_work: Work::from_be_bytes(&entry.total_work) }
            }
            None => TipState::EMPTY,
        };
        Ok(ChainManager {
            store,
            params,
            engines,
            tip: RwLock::new(tip),
            accept_lock: Mutex::new(()),
            events: EventBus::new(),
            orphans: Mutex::new(OrphanPool::default()),
        })
    }

    /// The store behind this chain.
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The parameters this chain validates against.
    #[must_use]
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// The engine router this chain dispatches on.
    #[must_use]
    pub fn engines(&self) -> &Arc<EngineRouter> {
        &self.engines
    }

    /// Create the genesis block if the store is empty. Idempotent.
    ///
    /// Genesis is *computed* from [`ChainParams`], never read from a file. If
    /// the store already holds a different block at height 0 this fails rather
    /// than adopting it: a node whose genesis differs from its peers' cannot
    /// sync with them, and finding that out at startup is the point.
    ///
    /// # Errors
    ///
    /// [`ChainError::GenesisMismatch`] when the datadir belongs to another
    /// chain, plus the usual storage and validation failures.
    pub fn init_genesis(&self) -> Result<BlockHash, ChainError> {
        let _guard = self.accept_lock.lock();
        let block = genesis_block(&self.params);
        let hash = header_hash(&block.header);

        if self.store.tip()?.is_some() {
            let existing =
                self.store.hash_at_height(0)?.ok_or(ChainError::MissingHeaderEntry(hash))?;
            if existing != hash {
                return Err(ChainError::GenesisMismatch { expected: hash, actual: existing });
            }
            return Ok(hash);
        }

        let engine = self.engines.engine_for_height(0);
        let ctx = BlockCtx {
            height: 0,
            // Genesis has no parent; `apply_block` requires only that its
            // `prev_hash` is zero, and reads nothing else from this field.
            prev_header: BlockHeader::default(),
            median_time_past_s: 0,
            params: self.params.clone(),
            engine_id: engine.engine_id(),
        };
        let diff = crate::apply::apply_block(&EmptyView, &block, &ctx)?;
        let total_work = engine.work(&block.header);
        let entry =
            BlockIndexEntry::from_block(&block, 0, total_work.to_be_bytes(), BlockStatus::Valid)?;
        self.store.connect_block(&hash, 0, &entry, &diff, &block)?;
        self.store.set_engine(engine.engine_id())?;
        *self.tip.write() = TipState { hash, height: 0, total_work };
        tracing::info!(hash = %hash, network = %self.params.network, "genesis initialised");
        self.emit(ChainEvent::NewTip { hash, height: 0, total_work: total_work.to_be_bytes() });
        Ok(hash)
    }

    /// The active tip and its height.
    #[must_use]
    pub fn tip(&self) -> (BlockHash, u64) {
        let tip = *self.tip.read();
        (tip.hash, tip.height)
    }

    /// Cumulative work to `h`, if the store knows it.
    #[must_use]
    pub fn total_work(&self, h: &BlockHash) -> Option<Work> {
        match self.store.get_header(h) {
            Ok(entry) => entry.map(|e| Work::from_be_bytes(&e.total_work)),
            Err(e) => {
                tracing::warn!(hash = %h, error = %e, "total work lookup failed");
                None
            }
        }
    }

    /// How many orphan blocks are held.
    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.orphans.lock().len()
    }

    /// Validate `header` against its parent and record it without a body.
    ///
    /// This is the headers-first sync path: a header chain is cheap to validate
    /// and cheap to discard, so a peer feeding a bogus chain costs bandwidth
    /// and nothing else.
    ///
    /// # Errors
    ///
    /// [`ChainError::UnknownParent`] when the parent is not stored, and
    /// [`ChainError::Consensus`] for a header rule.
    pub fn accept_header(&self, header: BlockHeader) -> Result<(), ChainError> {
        let _guard = self.accept_lock.lock();
        let hash = header_hash(&header);
        if let Some(existing) = self.store.get_header(&hash)? {
            if existing.status == BlockStatus::Invalid {
                return Err(ChainError::KnownInvalid(hash));
            }
            return Ok(());
        }
        let parent = self
            .store
            .get_header(&header.prev_hash)?
            .ok_or(ChainError::UnknownParent(header.prev_hash))?;
        if parent.status == BlockStatus::Invalid {
            return Err(ChainError::KnownInvalid(header.prev_hash));
        }
        let height = parent.height.checked_add(1).ok_or(ChainError::Arithmetic("header height"))?;
        let engine = self.engines.engine_for_height(height);
        let view = StoreHeaderView::new(&self.store, &self.params);
        engine.validate_header(&header, &parent.header, &view)?;

        let total_work =
            cumulative_work(Work::from_be_bytes(&parent.total_work), engine.work(&header))
                .ok_or(ChainError::Arithmetic("cumulative work"))?;
        let entry = BlockIndexEntry {
            header,
            height,
            total_work: total_work.to_be_bytes(),
            status: BlockStatus::HeaderOnly,
            tx_count: 0,
            size: 0,
            seal_engine: engine.engine_id(),
        };
        self.store.store_header(&entry)?;
        Ok(())
    }

    /// Store, validate and — if it wins fork choice — connect `block`.
    ///
    /// # Errors
    ///
    /// [`ChainError::Validation`] or [`ChainError::Consensus`] when the block
    /// breaks a rule, [`ChainError::KnownInvalid`] when it or its parent was
    /// already rejected, and [`ChainError::Storage`] on a database failure.
    /// An unknown parent is **not** an error: it is
    /// [`AcceptOutcome::Orphan`].
    pub fn accept_block(&self, block: Block) -> Result<AcceptOutcome, ChainError> {
        let _guard = self.accept_lock.lock();
        self.accept_locked(block)
    }

    /// Re-offer the orphans whose parent is `of`, and their descendants.
    ///
    /// Called by the node after a successful [`ChainManager::accept_block`].
    /// Kept separate rather than folded into acceptance so that the outcome
    /// returned for a submitted block always describes *that* block: a caller
    /// that saw `SideChain` and then a reorg triggered by an unblocked orphan
    /// gets two honest answers instead of one misleading one.
    ///
    /// # Errors
    ///
    /// Propagates the first hard failure; a block that is simply invalid is
    /// reported in the returned list and does not stop the drain.
    pub fn accept_orphan_descendants(
        &self,
        of: &BlockHash,
    ) -> Result<Vec<(BlockHash, AcceptOutcome)>, ChainError> {
        let mut out = Vec::new();
        let mut queue: Vec<BlockHash> = vec![*of];
        while let Some(parent) = queue.pop() {
            let ready = self.orphans.lock().take_children_of(&parent);
            for block in ready {
                let hash = header_hash(&block.header);
                let guard = self.accept_lock.lock();
                let result = self.accept_locked(block);
                drop(guard);
                match result {
                    Ok(outcome) => {
                        queue.push(hash);
                        out.push((hash, outcome));
                    }
                    Err(e) => {
                        tracing::warn!(hash = %hash, error = %e, "orphan failed on connection");
                    }
                }
            }
        }
        Ok(out)
    }

    /// Build a candidate block from `txs` for the given payout script.
    ///
    /// # Errors
    ///
    /// See [`crate::template::build_template`].
    pub fn build_template(
        &self,
        payout: &Script,
        extra_nonce: u64,
        txs: Vec<Transaction>,
        now_ms: u64,
    ) -> Result<BlockTemplate, ChainError> {
        crate::template::build_template(
            &self.store,
            &self.params,
            &self.engines,
            payout,
            extra_nonce,
            txs,
            now_ms,
        )
    }

    /// An exponential back-off block locator: the last ten tips, then doubling
    /// gaps back to genesis.
    ///
    /// Thirty-odd hashes describe any chain length, which is what lets a peer
    /// find the fork point in one round trip instead of a binary search over
    /// the network.
    #[must_use]
    pub fn locator(&self) -> Vec<BlockHash> {
        let (_, tip_height) = self.tip();
        if self.store.tip().ok().flatten().is_none() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut height = tip_height;
        let mut step: u64 = 1;
        let mut taken: usize = 0;
        loop {
            if let Ok(Some(hash)) = self.store.hash_at_height(height) {
                out.push(hash);
            }
            if height == 0 {
                break;
            }
            if taken >= 10 {
                step = step.saturating_mul(2);
            }
            taken = taken.saturating_add(1);
            height = height.saturating_sub(step);
        }
        out
    }

    /// The newest block in `locator` that is on the active chain.
    #[must_use]
    pub fn find_fork_point(&self, locator: &[BlockHash]) -> Option<(BlockHash, u64)> {
        for hash in locator {
            let entry = self.store.get_header(hash).ok().flatten()?;
            if self.store.hash_at_height(entry.height).ok().flatten() == Some(*hash) {
                return Some((*hash, entry.height));
            }
        }
        None
    }

    /// Active-chain headers after the locator's fork point, at most `max`.
    #[must_use]
    pub fn headers_from(&self, locator: &[BlockHash], max: usize) -> Vec<BlockHeader> {
        let start = match self.find_fork_point(locator) {
            Some((_, height)) => height.saturating_add(1),
            None => 0,
        };
        let (_, tip_height) = self.tip();
        let mut out = Vec::new();
        let mut height = start;
        while out.len() < max && height <= tip_height {
            let Ok(Some(hash)) = self.store.hash_at_height(height) else {
                break;
            };
            let Ok(Some(entry)) = self.store.get_header(&hash) else {
                break;
            };
            out.push(entry.header);
            height = height.saturating_add(1);
        }
        out
    }

    /// Subscribe to [`ChainEvent`]s over a bounded channel.
    ///
    /// A subscriber that stops draining is load-shed, never allowed to grow the
    /// queue; see [`CHAIN_EVENT_CAPACITY`].
    #[must_use]
    pub fn subscribe(&self) -> Receiver<ChainEvent> {
        self.events.subscribe()
    }

    // ------------------------------------------------------------- internals

    /// [`ChainManager::accept_block`] with the acceptance lock already held.
    fn accept_locked(&self, block: Block) -> Result<AcceptOutcome, ChainError> {
        let hash = header_hash(&block.header);

        if let Some(existing) = self.store.get_header(&hash)? {
            match existing.status {
                BlockStatus::Invalid => return Err(ChainError::KnownInvalid(hash)),
                // Connected at least once, so the body is in the store by
                // construction (`connect_block` writes both in one
                // transaction) and it is either the chain or a branch that
                // already lost.
                BlockStatus::Valid => return Ok(AcceptOutcome::Duplicate),
                // Stored but never connected. There is nothing to re-validate,
                // yet the block may still be owed the tip: a reorg on to it can
                // have been deferred because a *sibling's* body had not arrived
                // yet, and re-offering the branch tip is how that retry reaches
                // us. Running fork choice again is cheap; refusing to is how a
                // node stalls one block below the network.
                BlockStatus::HaveData => {
                    self.repair_missing_body(&existing, &block)?;
                    let candidate = TipCandidate::new(
                        hash,
                        existing.height,
                        Work::from_be_bytes(&existing.total_work),
                    );
                    return self.choose_tip(&block.header.prev_hash, candidate, true);
                }
                // A header we already validated, whose body has now arrived.
                BlockStatus::HeaderOnly => {}
            }
        }

        check_block_sanity(&block, &self.params)?;

        let Some(parent) = self.store.get_header(&block.header.prev_hash)? else {
            self.orphans.lock().insert(hash, block);
            return Ok(AcceptOutcome::Orphan);
        };
        if parent.status == BlockStatus::Invalid {
            return Err(ChainError::KnownInvalid(block.header.prev_hash));
        }

        let height = parent.height.checked_add(1).ok_or(ChainError::Arithmetic("block height"))?;
        let engine = self.engines.engine_for_height(height);
        {
            let view = StoreHeaderView::new(&self.store, &self.params);
            engine.validate_header(&block.header, &parent.header, &view)?;
            engine.validate_seal(&block, &view)?;
        }

        let total_work =
            cumulative_work(Work::from_be_bytes(&parent.total_work), engine.work(&block.header))
                .ok_or(ChainError::Arithmetic("cumulative work"))?;

        // Persist header and body before deciding: a block we have validated
        // the header of is worth keeping even if it loses fork choice, because
        // the branch it is on may win later.
        //
        // **Body first, header second.** These are two separate `redb`
        // transactions, each committed and fsynced on its own, so a crash
        // between them is a state the store keeps forever. In this order it
        // keeps an orphaned body — harmless, and overwritten the next time the
        // block is offered. In the other order it keeps a `HaveData` status
        // with no body behind it: sync computes "do I need this body?" from
        // that byte and never asks again, gossip answers `Duplicate`, and the
        // block can never be connected. A pointer is written after the data it
        // names, which is the same invariant `Store::connect_block` is built
        // around.
        let entry = BlockIndexEntry::from_block(
            &block,
            height,
            total_work.to_be_bytes(),
            BlockStatus::HaveData,
        )?;
        self.store.store_block_body(&hash, &block)?;
        self.store.store_header(&entry)?;

        let candidate = TipCandidate::new(hash, height, total_work);
        self.choose_tip(&block.header.prev_hash, candidate, false)
    }

    /// Fork choice for a block whose header and body are already stored.
    ///
    /// `known` says whether the block was in the store before this call, which
    /// is the only difference in what a caller is told when the block does not
    /// win: a block offered twice is a `Duplicate`, a block offered once is on
    /// a `SideChain`.
    fn choose_tip(
        &self,
        prev_hash: &BlockHash,
        candidate: TipCandidate,
        known: bool,
    ) -> Result<AcceptOutcome, ChainError> {
        let hash = candidate.hash;
        let incumbent = self.tip.read().candidate();
        if !is_better(&candidate, &incumbent) {
            tracing::debug!(hash = %hash, height = candidate.height, "block is not the best chain");
            return Ok(if known {
                AcceptOutcome::Duplicate
            } else {
                AcceptOutcome::SideChain(hash)
            });
        }

        if *prev_hash == incumbent.hash {
            if let Err(e) = connect_tip_block(&self.store, &self.params, &self.engines, &hash) {
                self.record_failure(&hash, &e);
                return Err(e);
            }
            self.refresh_tip()?;
            let tip = *self.tip.read();
            tracing::info!(hash = %hash, height = candidate.height, "new tip");
            self.emit(ChainEvent::NewTip {
                hash: tip.hash,
                height: tip.height,
                total_work: tip.total_work.to_be_bytes(),
            });
            return Ok(AcceptOutcome::Extended(hash));
        }

        self.reorganise(incumbent.hash, hash)
    }

    /// Put the body back when the index claims one the store does not have.
    ///
    /// The only way to reach that state is a crash between the two writes in
    /// [`ChainManager::accept_locked`] on a build that wrote them in the other
    /// order. Nothing else repairs it — sync reads `HaveData` as "I already
    /// have this" — so the block is re-validated and re-stored here rather than
    /// left to a reindex. The body is sanity-checked first: a peer may offer
    /// any bytes it likes under a header hash we already know.
    fn repair_missing_body(
        &self,
        existing: &BlockIndexEntry,
        block: &Block,
    ) -> Result<(), ChainError> {
        let hash = existing.block_hash();
        if self.store.get_block(&hash)?.is_some() {
            return Ok(());
        }
        tracing::warn!(
            hash = %hash,
            "the block index claims a body the store does not have; re-storing it"
        );
        check_block_sanity(block, &self.params)?;
        self.store.store_block_body(&hash, block)?;
        // Rewrite the entry too: one written without a body carries no
        // `tx_count` or `size` either, and those are what the RPC reports.
        let repaired = BlockIndexEntry::from_block(
            block,
            existing.height,
            existing.total_work,
            BlockStatus::HaveData,
        )?;
        self.store.store_header(&repaired)?;
        Ok(())
    }

    /// Move the active chain from `from` to `to`.
    fn reorganise(&self, from: BlockHash, to: BlockHash) -> Result<AcceptOutcome, ChainError> {
        let plan: ReorgPlan = plan_reorg(&self.store, &from, &to)?;
        {
            let view = StoreHeaderView::new(&self.store, &self.params);
            let (_, tip_height) = view.tip();
            let engine = self.engines.engine_for_height(tip_height);
            if let Some(finalized) = engine.finalized_height(&view)
                && plan.fork_height < finalized
            {
                return Err(ChainError::ReorgBelowFinalized {
                    fork_height: plan.fork_height,
                    finalized_height: finalized,
                });
            }
        }

        let outcome = match execute_reorg(&self.store, &self.params, &self.engines, &plan) {
            Ok(outcome) => outcome,
            Err(e) => {
                // A reorg that failed part-way has rolled itself back, but the
                // store's tip may still not be the one the cache names — and if
                // it is not, every later block is judged against a chain that
                // does not exist. Re-read before reporting the failure.
                if let Err(refresh) = self.refresh_tip() {
                    tracing::error!(
                        error = %refresh,
                        "could not refresh the tip cache after a failed reorg"
                    );
                }
                return Err(e);
            }
        };
        self.refresh_tip()?;
        let tip = *self.tip.read();
        tracing::info!(
            from = %from,
            to = %tip.hash,
            disconnected = outcome.disconnected.len(),
            connected = outcome.connected.len(),
            fork_height = plan.fork_height,
            "reorg complete: new tip"
        );
        self.emit(ChainEvent::Reorg {
            from,
            to: tip.hash,
            disconnected: outcome.disconnected.clone(),
            connected: outcome.connected.clone(),
        });
        self.emit(ChainEvent::NewTip {
            hash: tip.hash,
            height: tip.height,
            total_work: tip.total_work.to_be_bytes(),
        });
        Ok(AcceptOutcome::Reorged {
            from,
            to,
            disconnected: outcome.disconnected,
            connected: outcome.connected,
        })
    }

    /// Re-read the tip from the store into the cache.
    fn refresh_tip(&self) -> Result<(), ChainError> {
        let state = match self.store.tip()? {
            Some((hash, height)) => {
                let entry = entry_of(&self.store, &hash)?;
                TipState { hash, height, total_work: Work::from_be_bytes(&entry.total_work) }
            }
            None => TipState::EMPTY,
        };
        *self.tip.write() = state;
        Ok(())
    }

    /// Deal with a failed connect: condemn the block only if the chain did.
    ///
    /// `BlockStatus::Invalid` is permanent, inherited by every descendant, and
    /// the node bans peers that offer anything carrying it. Only a rule the
    /// block itself broke may write it — a validation or consensus error, which
    /// every node reproduces. A storage failure, a corrupt table or a tip that
    /// moved under us says nothing about the block: recording those as a
    /// verdict turns a full disk into a node that is stuck below the network
    /// forever and bans everyone serving the honest chain.
    ///
    /// Either way the tip cache is re-read. A connect can fail *because* the
    /// cache was stale (`NonContiguousConnect`), and leaving it stale means the
    /// next block is judged against a tip the store does not have.
    fn record_failure(&self, hash: &BlockHash, error: &ChainError) {
        if crate::reorg::is_consensus_verdict(error) {
            self.mark_invalid(hash);
        } else {
            tracing::error!(
                hash = %hash,
                error = %error,
                "could not connect this block; leaving its status alone so it can be retried"
            );
        }
        if let Err(e) = self.refresh_tip() {
            tracing::error!(error = %e, "could not refresh the tip cache after a failed connect");
        }
    }

    /// Record that a block is invalid, best effort.
    fn mark_invalid(&self, hash: &BlockHash) {
        match self.store.get_header(hash) {
            Ok(Some(entry)) => {
                let invalid = BlockIndexEntry { status: BlockStatus::Invalid, ..entry };
                if let Err(e) = self.store.store_header(&invalid) {
                    tracing::warn!(hash = %hash, error = %e, "could not mark block invalid");
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(hash = %hash, error = %e, "could not read block to invalidate")
            }
        }
    }

    /// Fan an event out, dropping subscribers that are gone or too far behind.
    fn emit(&self, event: ChainEvent) {
        self.events.emit(&event);
    }
}
