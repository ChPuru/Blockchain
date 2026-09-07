//! Reorganisation: walk to the common ancestor, disconnect down, connect
//! forward, and roll the whole thing back if any connect fails (SPEC §7.2).
//!
//! # Why a half-applied reorg is worse than a rejected one
//!
//! Every step here is reversible because every connected block wrote an **undo
//! record** — the value, script, height and coinbase flag of every output it
//! spent, in input order. That is what lets step 2 restore the UTXO set without
//! replaying from genesis, and it cannot be retrofitted: the records for
//! historical blocks do not exist, so adding undo data later forces a full
//! reindex on every deployed node.
//!
//! If a connect fails half-way, the store is at a state no chain ever had. The
//! only honest response is to put it back exactly where it started and mark the
//! candidate branch `Invalid`, which is what [`execute_reorg`] does. A reorg
//! that stopped half-way and reported success would leave a node validating
//! every future block against a UTXO set no other node has.
//!
//! **Guaranteed property, asserted in the test suite:** disconnecting *N*
//! blocks and reconnecting them yields a byte-identical UTXO set and an
//! identical `state_root`.

use ferrum_consensus::{EngineRouter, HeaderView};
use ferrum_storage::{BlockIndexEntry, BlockStatus, Store, header_hash};
use ferrum_types::{BlockHash, ChainParams};

use crate::apply::apply_block;
use crate::ctx::BlockCtx;
use crate::error::ChainError;
use crate::view::StoreHeaderView;

/// What a reorganisation would do, computed before anything is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorgPlan {
    /// The last block the two branches share.
    pub fork_hash: BlockHash,
    /// Its height. The reorg rewrites everything strictly above it.
    pub fork_height: u64,
    /// Blocks to disconnect, **tip first** — the order `disconnect_tip` needs.
    pub disconnect: Vec<BlockHash>,
    /// Blocks to connect, **ancestor first** — the order they must be applied.
    pub connect: Vec<BlockHash>,
}

impl ReorgPlan {
    /// How many blocks come off the active chain.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.disconnect.len()
    }

    /// Whether this plan only extends the current tip, touching nothing.
    #[must_use]
    pub fn is_fast_forward(&self) -> bool {
        self.disconnect.is_empty()
    }
}

/// What a completed reorganisation did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorgOutcome {
    /// Blocks removed from the active chain, tip first.
    pub disconnected: Vec<BlockHash>,
    /// Blocks added to the active chain, ancestor first.
    pub connected: Vec<BlockHash>,
}

/// Read one header index entry, or say which one is missing.
///
/// # Errors
///
/// [`ChainError::MissingHeaderEntry`] when the store has no entry, and
/// [`ChainError::Storage`] on a database failure.
pub fn entry_of(store: &Store, hash: &BlockHash) -> Result<BlockIndexEntry, ChainError> {
    store.get_header(hash)?.ok_or(ChainError::MissingHeaderEntry(*hash))
}

/// Compute the plan that moves the active chain from `from` to `to`.
///
/// Walks both branches back to their common ancestor by height and then in
/// lock-step. Both tips must be known headers; the walk never touches block
/// bodies, so a plan can be computed for a branch whose bodies are still being
/// downloaded.
///
/// # Errors
///
/// [`ChainError::MissingHeaderEntry`] if the walk leaves the known tree, and
/// [`ChainError::NoCommonAncestor`] if the two branches reach genesis without
/// meeting — which means the store holds two different genesis blocks and is
/// corrupt.
pub fn plan_reorg(
    store: &Store,
    from: &BlockHash,
    to: &BlockHash,
) -> Result<ReorgPlan, ChainError> {
    let mut a_hash = *from;
    let mut b_hash = *to;
    let mut a = entry_of(store, &a_hash)?;
    let mut b = entry_of(store, &b_hash)?;

    let mut disconnect: Vec<BlockHash> = Vec::new();
    let mut connect: Vec<BlockHash> = Vec::new();

    // Bring both cursors to the same height first; only then can a lock-step
    // walk find the ancestor without re-reading the whole chain.
    while a.height > b.height {
        disconnect.push(a_hash);
        a_hash = a.header.prev_hash;
        a = entry_of(store, &a_hash)?;
    }
    while b.height > a.height {
        connect.push(b_hash);
        b_hash = b.header.prev_hash;
        b = entry_of(store, &b_hash)?;
    }

    while a_hash != b_hash {
        if a.height == 0 || b.height == 0 {
            return Err(ChainError::NoCommonAncestor { a: *from, b: *to });
        }
        disconnect.push(a_hash);
        connect.push(b_hash);
        a_hash = a.header.prev_hash;
        b_hash = b.header.prev_hash;
        a = entry_of(store, &a_hash)?;
        b = entry_of(store, &b_hash)?;
    }

    connect.reverse();
    Ok(ReorgPlan { fork_hash: a_hash, fork_height: a.height, disconnect, connect })
}

/// Validate and connect one block on top of the current tip.
///
/// This is the single place a block is added to the active chain — the miner's
/// path, the sync path and the reorg path all come through here, so there is
/// exactly one implementation of "what it means to accept a block".
///
/// The order is: engine header checks (which need the header chain), engine
/// seal checks, then [`apply_block`] for the pure state transition, then one
/// `redb` write transaction with the tip written last.
///
/// # Errors
///
/// [`ChainError::Consensus`] for a header or seal rule, [`ChainError::Validation`]
/// for a block rule, and [`ChainError::Storage`] for a database failure.
pub fn connect_tip_block(
    store: &Store,
    params: &ChainParams,
    engines: &EngineRouter,
    hash: &BlockHash,
) -> Result<(), ChainError> {
    let block = store.get_block(hash)?.ok_or(ChainError::MissingBlockBody(*hash))?;
    let entry = entry_of(store, hash)?;
    let parent_hash = block.header.prev_hash;
    let parent = entry_of(store, &parent_hash)?;

    let view = StoreHeaderView::new(store, params);
    let engine = engines.engine_for_height(entry.height);

    // The header rules that need the chain: version, parentage, the difficulty
    // transition, the proof of work and the timestamp lower bound.
    engine.validate_header(&block.header, &parent.header, &view)?;
    engine.validate_seal(&block, &view)?;

    let median_time_past_s =
        view.median_time_past(&parent_hash).ok_or(ChainError::MissingHeaderEntry(parent_hash))?;

    let ctx = BlockCtx {
        height: entry.height,
        prev_header: parent.header,
        median_time_past_s,
        params: params.clone(),
        engine_id: engine.engine_id(),
    };
    let diff = apply_block(store, &block, &ctx)?;

    let block_work = engine.work(&block.header);
    let parent_work = ferrum_consensus::Work::from_be_bytes(&parent.total_work);
    let total_work = crate::fork_choice::cumulative_work(parent_work, block_work)
        .ok_or(ChainError::Arithmetic("cumulative work"))?;

    let stored = BlockIndexEntry {
        total_work: total_work.to_be_bytes(),
        status: BlockStatus::Valid,
        ..entry
    };
    store.connect_block(hash, stored.height, &stored, &diff, &block)?;
    Ok(())
}

/// Carry out `plan`, restoring the original tip if any connect fails.
///
/// # Missing bodies are not a verdict
///
/// [`plan_reorg`] walks headers, so it happily plans a reorg onto a branch
/// whose bodies are still downloading. That is *not* a reason to condemn the
/// branch, so the bodies are checked up front and a gap aborts the reorg with
/// [`ChainError::MissingBlockBody`] before anything is written and without
/// recording a status. The same distinction governs the connect loop: only a
/// consensus verdict — [`ChainError::Validation`] or [`ChainError::Consensus`]
/// — marks the branch `Invalid`. A storage failure says nothing about the
/// block, and `Invalid` is permanent and inherited.
///
/// # Errors
///
/// The failing block's own error, after the store has been put back. If the
/// rollback itself fails the store is inconsistent and
/// [`ChainError::ReorgRollbackFailed`] says so loudly rather than pretending
/// otherwise.
pub fn execute_reorg(
    store: &Store,
    params: &ChainParams,
    engines: &EngineRouter,
    plan: &ReorgPlan,
) -> Result<ReorgOutcome, ChainError> {
    // Before touching the store: every block we are about to connect must have
    // a body. Finding this out half-way through would cost a rollback, and
    // — worse — used to be indistinguishable from "this branch is invalid".
    for hash in &plan.connect {
        let entry = entry_of(store, hash)?;
        if !entry.status.has_data() {
            tracing::debug!(
                hash = %hash,
                height = entry.height,
                "reorg deferred: the body for this block has not arrived yet"
            );
            return Err(ChainError::MissingBlockBody(*hash));
        }
    }

    let mut undone: Vec<BlockHash> = Vec::with_capacity(plan.disconnect.len());
    for expected in &plan.disconnect {
        let got = match store.disconnect_tip() {
            Ok(got) => got,
            Err(e) => {
                // Each disconnect is its own committed transaction, so the
                // blocks already off the chain stay off unless we put them
                // back. Restore before reporting, exactly as the branch below
                // does for a tip that moved.
                tracing::warn!(
                    error = %e,
                    disconnected = undone.len(),
                    "reorg disconnect failed; rolling back to the original tip"
                );
                roll_back(store, params, engines, &[], &undone)?;
                return Err(ChainError::Storage(e));
            }
        };
        undone.push(got);
        if got != *expected {
            // The tip moved under us. Put back what came off and refuse.
            roll_back(store, params, engines, &[], &undone)?;
            return Err(ChainError::ReorgRollbackFailed {
                detail: format!("expected to disconnect {expected}, store gave {got}"),
            });
        }
    }
    tracing::debug!(
        depth = plan.disconnect.len(),
        fork_height = plan.fork_height,
        "disconnected to the fork point"
    );

    let mut connected: Vec<BlockHash> = Vec::with_capacity(plan.connect.len());
    for hash in &plan.connect {
        match connect_tip_block(store, params, engines, hash) {
            Ok(()) => connected.push(*hash),
            Err(e) => {
                tracing::warn!(
                    hash = %hash,
                    error = %e,
                    "reorg connect failed; rolling back to the original tip"
                );
                roll_back(store, params, engines, &connected, &undone)?;
                if is_consensus_verdict(&e) {
                    mark_branch_invalid(store, &plan.connect, hash);
                }
                return Err(e);
            }
        }
    }

    Ok(ReorgOutcome { disconnected: undone, connected })
}

/// Undo a partially applied reorg: drop everything connected, then restore the
/// blocks that were disconnected, oldest last.
///
/// # Errors
///
/// [`ChainError::ReorgRollbackFailed`] — reaching it means the store no longer
/// matches any chain, and only a reindex can fix that.
fn roll_back(
    store: &Store,
    params: &ChainParams,
    engines: &EngineRouter,
    connected: &[BlockHash],
    undone: &[BlockHash],
) -> Result<(), ChainError> {
    for hash in connected.iter().rev() {
        store.disconnect_tip().map_err(|e| ChainError::ReorgRollbackFailed {
            detail: format!("could not disconnect {hash} during rollback: {e}"),
        })?;
    }
    // `undone` is tip-first, so restoring it means walking it backwards.
    for hash in undone.iter().rev() {
        connect_tip_block(store, params, engines, hash).map_err(|e| {
            ChainError::ReorgRollbackFailed {
                detail: format!("could not reconnect {hash} during rollback: {e}"),
            }
        })?;
    }
    tracing::info!(restored = undone.len(), "rolled back to the original tip");
    Ok(())
}

/// Whether `error` is the chain's verdict on the *block*, rather than a report
/// about this node.
///
/// `BlockStatus::Invalid` is permanent and inherited, and every path that reads
/// it — [`crate::ChainManager::accept_block`], `accept_header`, and the node's
/// gossip verdict, which bans the peer that offered it — treats it as proof the
/// block breaks a rule. Only a rule can produce that: a validation or consensus
/// error is reproducible on every node, whereas a full disk, a corrupt table or
/// a tip that moved is a fact about this machine at this moment. Recording the
/// second as the first turns one bad night into a permanently stuck node that
/// bans everyone serving the honest chain.
#[must_use]
pub fn is_consensus_verdict(error: &ChainError) -> bool {
    matches!(error, ChainError::Validation(_) | ChainError::Consensus(_))
}

/// Mark the failing block and everything after it on its branch `Invalid`.
///
/// Best effort: a store that cannot record the verdict is already reporting
/// errors elsewhere, and refusing the reorg matters more than remembering why.
/// The consequence of a lost mark is that the branch is re-validated and
/// re-rejected next time, which is slow but never wrong.
fn mark_branch_invalid(store: &Store, branch: &[BlockHash], from: &BlockHash) {
    let mut reached = false;
    for hash in branch {
        if hash == from {
            reached = true;
        }
        if !reached {
            continue;
        }
        match store.get_header(hash) {
            Ok(Some(entry)) => {
                let invalid = BlockIndexEntry { status: BlockStatus::Invalid, ..entry };
                if let Err(e) = store.store_header(&invalid) {
                    tracing::warn!(hash = %hash, error = %e, "could not mark block invalid");
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(hash = %hash, error = %e, "could not read block to invalidate")
            }
        }
    }
}

/// The hash of a stored entry, for callers that have the entry but not the key.
#[must_use]
pub fn entry_hash(entry: &BlockIndexEntry) -> BlockHash {
    header_hash(&entry.header)
}
