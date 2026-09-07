//! Gossip in and out, and the validation verdict that goes back to the sender.
//!
//! # The verdict is the point
//!
//! Gossipsub runs in explicit-validation mode (CONTRACT §10.1), so nothing this
//! node receives is forwarded until it says so. Every message therefore ends in
//! exactly one [`GossipVerdict`], and an invalid one is reported as
//! [`ferrum_p2p::MessageAcceptance::Reject`] so it feeds gossipsub's **P₄
//! invalid-message score**. That single hookup is the cheapest denial-of-service
//! defence available, and it only works if the mapping from "why we said no" to
//! "Reject or Ignore" is correct.
//!
//! Getting it *wrong* in either direction is expensive:
//!
//! - Rejecting a message we merely could not judge — an orphan block, a
//!   transaction whose fee is below **our** relay floor, a read that failed on
//!   **our** disk — penalises an honest peer for our own state. Do that at
//!   scale and a node scores its way into isolation.
//! - Ignoring a genuinely invalid block wastes the one defence we have.
//!
//! So: consensus-invalid is `Reject`; policy verdicts and anything transient
//! are `Ignore`.
//!
//! # The two-hour future-time rule lives here
//!
//! [`Relay::accept_block`] calls [`ferrum_consensus::check_future_time`] before
//! handing anything to the chain. This is the **one** clock-dependent rule in
//! the protocol (SPEC §3.2 rule 10) and it deliberately sits above the
//! state-transition seam, in the node, rather than inside `apply_block`.
//!
//! The reason is not tidiness. `apply_block` is a pure function of
//! (pre-state, block, context); if it read a clock, re-validating block 400
//! would depend on *when* you re-validate it, and a node replaying history
//! would reject blocks that were valid when they were mined. Keeping the rule
//! above the seam is exactly what lets a historical block be re-validated
//! identically forever.
//!
//! A block that fails it is **not** marked invalid in the store. It is refused
//! now and may be perfectly acceptable in ten minutes, so nothing is recorded
//! against it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ferrum_chain::{AcceptOutcome, ChainError, ChainManager, StoreHeaderView};
use ferrum_consensus::{HeaderView, check_future_time};
use ferrum_mempool::{AcceptResult, Mempool, MempoolError};
use ferrum_p2p::MessageAcceptance;
use ferrum_types::{Block, BlockHash, Transaction, Txid};

use crate::error::NodeError;
use crate::telemetry::{NodeMetrics, log_reorg};

/// What to tell gossipsub about a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GossipVerdict {
    /// Valid: forward it, and score the sender well.
    Accept,
    /// Invalid by consensus: do not forward, and lower the sender's P₄ score.
    Reject,
    /// Neither: do not forward, do not score. Duplicates, orphans, policy
    /// refusals and our own failures all land here.
    Ignore,
}

impl GossipVerdict {
    /// The libp2p value this verdict becomes.
    #[must_use]
    pub const fn acceptance(self) -> MessageAcceptance {
        match self {
            GossipVerdict::Accept => MessageAcceptance::Accept,
            GossipVerdict::Reject => MessageAcceptance::Reject,
            GossipVerdict::Ignore => MessageAcceptance::Ignore,
        }
    }

    /// A short static name, for logs and metrics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            GossipVerdict::Accept => "accept",
            GossipVerdict::Reject => "reject",
            GossipVerdict::Ignore => "ignore",
        }
    }
}

/// How a block offered by the network was judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRejection {
    /// Timestamped more than `max_future_block_time_ms` ahead of our clock.
    ///
    /// Kept separate from every other rejection because it is the one verdict
    /// that can change without the block changing.
    TooFarInFuture,
    /// Broke a consensus rule. Permanently invalid.
    Invalid,
    /// We could not tell: a storage failure, an arithmetic guard, a chain the
    /// engine refuses to reorganise. Not the sender's fault.
    Transient,
}

/// What accepting a block from the network did.
#[derive(Debug)]
pub struct BlockRelayOutcome {
    /// The block's hash.
    pub hash: BlockHash,
    /// What to tell gossipsub.
    pub verdict: GossipVerdict,
    /// What the chain did, when it got that far.
    pub outcome: Option<AcceptOutcome>,
    /// Why it was refused, when it was.
    pub rejection: Option<BlockRejection>,
    /// The failure, for the log.
    pub error: Option<String>,
}

impl BlockRelayOutcome {
    /// Whether this node should announce the block onwards.
    #[must_use]
    pub fn should_announce(&self) -> bool {
        matches!(
            self.outcome,
            Some(AcceptOutcome::Extended(_) | AcceptOutcome::Reorged { .. })
        )
    }
}

/// What offering a transaction to the mempool did.
#[derive(Debug)]
pub struct TxRelayOutcome {
    /// The transaction's id.
    pub txid: Txid,
    /// What to tell gossipsub.
    pub verdict: GossipVerdict,
    /// What the pool did, when it got that far.
    pub result: Option<AcceptResult>,
    /// Why it was refused, when it was.
    pub error: Option<MempoolError>,
}

impl TxRelayOutcome {
    /// Whether this node should relay the transaction onwards.
    #[must_use]
    pub fn should_relay(&self) -> bool {
        matches!(self.result, Some(AcceptResult::Accepted { .. }))
    }

    /// Orphans this arrival unblocked, which are new to us and must be relayed.
    #[must_use]
    pub fn promoted(&self) -> &[Txid] {
        match &self.result {
            Some(AcceptResult::Accepted { promoted, .. }) => promoted,
            _ => &[],
        }
    }
}

/// Map a chain verdict onto a gossip verdict.
///
/// The whole of the P₄ hookup for blocks, in one function so it can be tested
/// exhaustively rather than inferred from a call site.
#[must_use]
pub fn block_verdict(result: &Result<AcceptOutcome, ChainError>) -> GossipVerdict {
    match result {
        Ok(AcceptOutcome::Extended(_) | AcceptOutcome::Reorged { .. } | AcceptOutcome::SideChain(_)) => {
            GossipVerdict::Accept
        }
        // Already had it, or cannot judge it yet. Neither says anything about
        // the sender, and gossipsub's duplicate cache already handles the
        // first case.
        Ok(AcceptOutcome::Duplicate | AcceptOutcome::Orphan) => GossipVerdict::Ignore,
        // `AcceptOutcome` is `#[non_exhaustive]`. An outcome a future version
        // adds must not be scored against the sender by default: silence is
        // the safe direction when we do not know what happened.
        Ok(_) => GossipVerdict::Ignore,

        // Consensus verdicts: the block is invalid for everyone, forever.
        Err(ChainError::Validation(_) | ChainError::Consensus(_) | ChainError::KnownInvalid(_)) => {
            GossipVerdict::Reject
        }

        // Everything else is ours, not theirs: a failed read, an arithmetic
        // guard, a reorg the engine will not perform. Punishing a peer for our
        // own disk is how a node scores itself into isolation.
        Err(_) => GossipVerdict::Ignore,
    }
}

/// Classify a chain failure for the operator's log and for metrics.
#[must_use]
pub fn block_rejection(e: &ChainError) -> BlockRejection {
    match e {
        ChainError::Validation(_) | ChainError::Consensus(_) | ChainError::KnownInvalid(_) => {
            BlockRejection::Invalid
        }
        _ => BlockRejection::Transient,
    }
}

/// Map a mempool verdict onto a gossip verdict.
///
/// **Almost every `MempoolError` is a policy opinion**, and a policy opinion
/// must never lower a peer's score: a block containing a transaction our
/// mempool refused is still perfectly valid (SPEC §10), so a peer relaying one
/// has done nothing wrong. Only the handful of verdicts that mean "nobody can
/// ever mine this" are `Reject`.
#[must_use]
pub fn tx_verdict(result: &Result<AcceptResult, MempoolError>) -> GossipVerdict {
    match result {
        Ok(AcceptResult::Accepted { .. }) => GossipVerdict::Accept,
        Ok(AcceptResult::AlreadyInPool { .. } | AcceptResult::Orphan { .. }) => {
            GossipVerdict::Ignore
        }
        // `AcceptResult` is `#[non_exhaustive]`; see `block_verdict`.
        Ok(_) => GossipVerdict::Ignore,
        Err(e) => {
            if is_consensus_invalid(e) {
                GossipVerdict::Reject
            } else {
                GossipVerdict::Ignore
            }
        }
    }
}

/// Whether a mempool verdict means the transaction can never be mined.
///
/// The four that qualify are the context-free rules of SPEC §4.1, the
/// push-only `script_sig` rule (a *consensus* rule in Ferrum, SPEC §5.1), a
/// coinbase outside its block, and a script that does not verify. Everything
/// else — fee floor, standardness, size, conflicts, pool pressure — is local
/// policy.
#[must_use]
pub fn is_consensus_invalid(e: &MempoolError) -> bool {
    matches!(
        e,
        MempoolError::Coinbase
            | MempoolError::Sanity(_)
            | MempoolError::NonPushOnlyScriptSig { .. }
            | MempoolError::ScriptVerification { .. }
            | MempoolError::InputSumOverflow
            | MempoolError::InsufficientInputValue { .. }
    )
}

/// The node's clock, as one line of trait so tests can move time.
///
/// Wall-clock time enters the system in exactly two places: here, and
/// `build_template`'s `now_ms`. Everything else is a pure function of its
/// arguments (SPEC §8).
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

/// The real clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        // `clippy.toml` disallows `SystemTime::now` workspace-wide to keep a
        // clock out of the state-transition path. `ferrum_rpc::now_ms` takes
        // that exception exactly once, in a named function; taking it a second
        // time here would be a second place for it to drift.
        ferrum_rpc::now_ms()
    }
}

/// A clock a test can move.
#[derive(Debug, Default)]
pub struct FixedClock(AtomicU64);

impl FixedClock {
    /// A clock stopped at `now_ms`.
    #[must_use]
    pub fn new(now_ms: u64) -> Self {
        FixedClock(AtomicU64::new(now_ms))
    }

    /// Move it.
    pub fn set(&self, now_ms: u64) {
        self.0.store(now_ms, Ordering::Relaxed);
    }
}

impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Everything the node does with a block or a transaction that arrived from
/// somewhere else.
///
/// Synchronous, because `ferrum-chain`, `ferrum-storage` and `ferrum-mempool`
/// are. The async tasks in [`crate::node`] reach it through
/// `tokio::task::spawn_blocking`; a `redb` call on the async runtime is a
/// two-second p95 latency bug (CONTRACT §7).
#[derive(Debug)]
pub struct Relay {
    chain: Arc<ChainManager>,
    mempool: Arc<Mempool>,
    metrics: Arc<NodeMetrics>,
    clock: Arc<dyn Clock>,
}

impl Relay {
    /// Build a relay over a chain and a mempool.
    #[must_use]
    pub fn new(
        chain: Arc<ChainManager>,
        mempool: Arc<Mempool>,
        metrics: Arc<NodeMetrics>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Relay { chain, mempool, metrics, clock }
    }

    /// The chain this relay feeds.
    #[must_use]
    pub fn chain(&self) -> &Arc<ChainManager> {
        &self.chain
    }

    /// The mempool this relay feeds.
    #[must_use]
    pub fn mempool(&self) -> &Arc<Mempool> {
        &self.mempool
    }

    /// The metrics this relay updates.
    #[must_use]
    pub fn metrics(&self) -> &Arc<NodeMetrics> {
        &self.metrics
    }

    /// The current time in milliseconds, from this relay's clock.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Validate and connect a block that arrived from the network.
    ///
    /// The future-time bound is checked here, against this node's clock, before
    /// anything reaches the state-transition seam. See the module docs for why
    /// that rule cannot live inside `apply_block`.
    pub fn accept_block(&self, block: Block) -> BlockRelayOutcome {
        self.accept_block_at(block, self.now_ms())
    }

    /// [`Relay::accept_block`] against an explicit clock reading.
    ///
    /// Exposed so a test can pin "now" without a global clock, and so the sync
    /// path can take one reading for a whole window of blocks.
    pub fn accept_block_at(&self, block: Block, now_ms: u64) -> BlockRelayOutcome {
        let hash = ferrum_storage::header_hash(&block.header);

        // ---- the one clock-dependent rule (SPEC 3.2 rule 10) --------------
        // Above the seam, deliberately. `apply_block` must stay a pure
        // function of (pre-state, block, ctx) so that re-validating block 400
        // gives the same answer forever. A block refused here is NOT recorded
        // as invalid: our clock, not the block, is what made it unacceptable,
        // and in ten minutes it may be fine.
        if let Err(e) = check_future_time(&block.header, now_ms, self.chain.params()) {
            tracing::warn!(
                %hash,
                timestamp_ms = block.header.timestamp_ms,
                now_ms,
                "block is too far in the future; refused without recording it invalid"
            );
            self.metrics.block_rejected();
            return BlockRelayOutcome {
                hash,
                verdict: GossipVerdict::Reject,
                outcome: None,
                rejection: Some(BlockRejection::TooFarInFuture),
                error: Some(e.to_string()),
            };
        }

        let result = self.chain.accept_block(block);
        let verdict = block_verdict(&result);

        match result {
            Ok(outcome) => {
                self.on_accepted(&hash, &outcome);
                BlockRelayOutcome {
                    hash,
                    verdict,
                    outcome: Some(outcome),
                    rejection: None,
                    error: None,
                }
            }
            Err(e) => {
                let rejection = block_rejection(&e);
                if rejection == BlockRejection::Invalid {
                    self.metrics.block_rejected();
                    tracing::warn!(%hash, error = %e, "block rejected");
                } else {
                    tracing::warn!(%hash, error = %e, "block could not be judged");
                }
                BlockRelayOutcome {
                    hash,
                    verdict,
                    outcome: None,
                    rejection: Some(rejection),
                    error: Some(e.to_string()),
                }
            }
        }
    }

    /// Offer a transaction to the mempool.
    pub fn accept_transaction(&self, tx: Transaction) -> TxRelayOutcome {
        let txid = ferrum_storage::txid(&tx);
        let (height, mtp_s) = match self.tip_context() {
            Ok(v) => v,
            Err(e) => {
                // Our own failure: never scored against the sender.
                tracing::warn!(%txid, error = %e, "could not read the tip to judge a transaction");
                return TxRelayOutcome {
                    txid,
                    verdict: GossipVerdict::Ignore,
                    result: None,
                    error: Some(MempoolError::View { detail: e.to_string() }),
                };
            }
        };

        let result =
            self.mempool.accept(tx, self.chain.store().as_ref(), height, mtp_s);
        let verdict = tx_verdict(&result);
        match result {
            Ok(accepted) => {
                if matches!(accepted, AcceptResult::Accepted { .. }) {
                    self.metrics.tx_accepted();
                }
                self.metrics.set_mempool(self.mempool.len(), self.mempool.size_bytes());
                TxRelayOutcome { txid, verdict, result: Some(accepted), error: None }
            }
            Err(e) => {
                if verdict == GossipVerdict::Reject {
                    self.metrics.tx_rejected();
                }
                tracing::debug!(%txid, error = %e, verdict = verdict.name(), "transaction refused");
                TxRelayOutcome { txid, verdict, result: None, error: Some(e) }
            }
        }
    }

    /// The tip height and its median time past in seconds.
    ///
    /// # Errors
    ///
    /// [`NodeError::Chain`] when the store has no tip, which means
    /// `init_genesis` was never called.
    pub fn tip_context(&self) -> Result<(u64, u64), NodeError> {
        let (hash, height) = self.chain.tip();
        let view = StoreHeaderView::new(self.chain.store(), self.chain.params());
        let mtp_s = view.median_time_past(&hash).unwrap_or(0);
        Ok((height, mtp_s))
    }

    /// Bookkeeping after the chain accepted a block: mempool reconciliation,
    /// metrics, the reorg log line, and unblocked orphans.
    fn on_accepted(&self, hash: &BlockHash, outcome: &AcceptOutcome) {
        match outcome {
            AcceptOutcome::Extended(_) => {
                self.metrics.block_accepted();
                if let Ok(Some(block)) = self.chain.store().get_block(hash) {
                    self.mempool.remove_confirmed(&block.txs);
                }
                self.after_tip_move();
            }
            AcceptOutcome::Reorged { from, to, disconnected, connected } => {
                self.metrics.block_accepted();
                self.metrics.reorg(disconnected.len());
                // The line devnet/heal.sh greps for. It is part of the
                // contract, not a debug aid: it is how an operator sees what
                // the losing node did.
                log_reorg(from, to, disconnected.len(), connected.len());
                self.reconcile_reorg(disconnected, connected);
                self.after_tip_move();
            }
            AcceptOutcome::SideChain(_) => {
                // Stored and valid, but it did not win. Nothing to reconcile.
            }
            AcceptOutcome::Duplicate | AcceptOutcome::Orphan => {}
            // `#[non_exhaustive]`: an outcome we do not recognise gets no
            // bookkeeping rather than the wrong bookkeeping.
            _ => {}
        }

        // A connected block may unblock orphans we are already holding, and
        // each of those may unblock more.
        match self.chain.accept_orphan_descendants(hash) {
            Ok(unblocked) if !unblocked.is_empty() => {
                tracing::info!(count = unblocked.len(), "connected orphan descendants");
                self.after_tip_move();
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "draining orphans failed"),
        }
    }

    /// Re-add transactions from disconnected blocks and evict what the new
    /// branch spent.
    fn reconcile_reorg(&self, disconnected: &[BlockHash], connected: &[BlockHash]) {
        let store = self.chain.store();
        let load = |hashes: &[BlockHash]| -> Vec<Block> {
            hashes.iter().filter_map(|h| store.get_block(h).ok().flatten()).collect()
        };
        let (_, height) = self.chain.tip();
        self.mempool.reconcile_reorg(
            &load(disconnected),
            &load(connected),
            store.as_ref(),
            height,
        );
    }

    /// Refresh the gauges that follow the tip.
    fn after_tip_move(&self) {
        let (_, height) = self.chain.tip();
        self.metrics.set_height(height);
        self.metrics.set_mempool(self.mempool.len(), self.mempool.size_bytes());
        // Orphans held by the mempool can now be promotable.
        let (height, mtp_s) = match self.tip_context() {
            Ok(v) => v,
            Err(_) => return,
        };
        let promoted = self.mempool.promote_orphans(self.chain.store().as_ref(), height, mtp_s);
        if !promoted.is_empty() {
            tracing::debug!(count = promoted.len(), "promoted orphan transactions");
        }
    }
}

#[cfg(test)]
mod tests;
