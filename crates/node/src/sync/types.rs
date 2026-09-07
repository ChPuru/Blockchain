//! The value types headers-first sync produces, and the rule that decides
//! whose fault a failure is.
//!
//! Kept apart from the driver in [`super`] so that the one interesting
//! decision here - [`header_failure_is_bannable`] - is read on its own
//! rather than buried in a three-phase loop.

use ferrum_chain::ChainError;
use ferrum_p2p::PeerId;
use ferrum_types::{Block, BlockHash};

/// What one header/body/connect round did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncRound {
    /// The peer's chain is no better than ours.
    UpToDate,
    /// The peer had nothing after our locator, or nothing new.
    NoHeaders,
    /// Progress.
    Progressed {
        /// Headers accepted.
        headers: usize,
        /// Bodies connected.
        blocks: usize,
    },
}

impl SyncRound {
    /// Whether the round moved the chain at all.
    #[must_use]
    pub const fn made_progress(&self) -> bool {
        matches!(self, SyncRound::Progressed { .. })
    }
}

/// Totals across a whole [`SyncManager::sync_to_best_peer`] call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncStats {
    /// Rounds run.
    pub rounds: usize,
    /// Headers accepted.
    pub headers: usize,
    /// Bodies connected.
    pub blocks: usize,
}

impl SyncStats {
    /// Whether anything was learned.
    #[must_use]
    pub const fn made_progress(&self) -> bool {
        self.headers > 0 || self.blocks > 0
    }
}

/// One block body, and the peer that served it.
///
/// Attribution is kept all the way to the connect pass so that "a peer that
/// serves an invalid block is disconnected" (SPEC 12) can name the right peer
/// when a window was spread across several of them.
#[derive(Debug)]
pub struct ServedBlock {
    /// Who served it.
    pub peer: PeerId,
    /// The body.
    pub block: Block,
}

/// What one header batch did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderBatch {
    /// Hashes, in chain order, whose bodies this node still needs.
    pub wanted: Vec<BlockHash>,
    /// How many headers were accepted before the batch ended.
    pub accepted: usize,
    /// Why the batch stopped short, when it did. Never a peer's fault: the
    /// bannable failures are returned as [`NodeError::PeerMisbehaved`].
    pub stalled: Option<String>,
}

/// Whether a header failure is the peer's fault or ours.
///
/// This distinction is the whole of SPEC 12's disconnect rule.
/// [`ferrum_consensus::ConsensusError::is_missing_context`] exists for exactly
/// it: a header the difficulty rule cannot evaluate *yet* says nothing about
/// the peer that sent it.
///
/// The case that matters in practice is the **ASERT anchor**. The anchor is the
/// block at height 1, and `HeaderView::header_at_height` reads the *active*
/// chain by contract (CONTRACT 6.4), so a node still at height 0 cannot
/// evaluate the difficulty transition for a header above height 1 until block 1
/// has connected. Headers-first sync therefore accepts what it can, downloads
/// and connects those bodies, and the next round validates the rest: one extra
/// round on a cold start, and none thereafter.
#[must_use]
pub fn header_failure_is_bannable(e: &ChainError) -> bool {
    match e {
        ChainError::Consensus(c) => !c.is_missing_context(),
        // A header whose parent we do not have, in a batch the peer derived
        // from *our own* locator, is a chain that does not connect to ours.
        ChainError::Validation(_) | ChainError::KnownInvalid(_) | ChainError::UnknownParent(_) => {
            true
        }
        // Storage, arithmetic, a reorg we refuse: ours, not theirs.
        _ => false,
    }
}
