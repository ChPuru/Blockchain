//! Adversarial scenarios (CONTRACT §14).
//!
//! One module per mandatory case. Every scenario is **red then green**: it
//! shows the attack being rejected for a *named* reason, and it shows the
//! honest construction that differs from the attack in one detail being
//! accepted. Both halves matter. A red-only test passes when the block is
//! rejected for the wrong reason; a green-only test passes when the rule is
//! deleted.
//!
//! | Module | The attack |
//! |---|---|
//! | [`timestamp`] | moving timestamps to steer the difficulty controller |
//! | [`side_chain`] | a 100-block invalid branch, offered to waste a node |
//! | [`double_spend`] | spending one coin twice inside a single block |
//! | [`overflow`] | output and input sums that wrap or leave the money range |
//! | [`replay`] | replaying a testnet signature on another chain |
//! | [`expensive_block`] | a block engineered to cost the most to validate |
//! | [`deep_reorg`] | a reorganisation deeper than a mempool remembers |
//! | [`coinbase`] | a coinbase overpaying itself by one grain |
//! | [`duplicate_txid`] | BIP-30: two identical transactions, one UTXO entry |
//! | [`script_encoding`] | non-minimal `ScriptNum` and push encodings |
//!
//! Every rejection is checked through [`judge`], which runs **both** executors
//! and refuses to answer unless they agree. A scenario therefore proves two
//! things at once: that the rule exists, and that both implementations of it
//! say the same thing.

use ferrum_chain::{BlockCtx, ValidationError, apply_block};
use ferrum_storage::{StateDiff, StateView};
use ferrum_types::Block;

use crate::chain_builder::ChainBuilder;
use crate::error::SimError;
use crate::reference::apply_block_reference;

pub mod coinbase;
pub mod deep_reorg;
pub mod double_spend;
pub mod duplicate_txid;
pub mod expensive_block;
pub mod overflow;
pub mod replay;
pub mod script_encoding;
pub mod side_chain;
pub mod timestamp;

/// What both executors said about a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Valid, with this effect on the UTXO set.
    Accepted(StateDiff),
    /// Invalid, for this reason.
    Rejected(ValidationError),
}

impl Verdict {
    /// The rejection reason, if the block was rejected.
    #[must_use]
    pub fn rejection(&self) -> Option<&ValidationError> {
        match self {
            Verdict::Rejected(e) => Some(e),
            Verdict::Accepted(_) => None,
        }
    }

    /// The state diff, if the block was accepted.
    #[must_use]
    pub fn diff(&self) -> Option<&StateDiff> {
        match self {
            Verdict::Accepted(d) => Some(d),
            Verdict::Rejected(_) => None,
        }
    }

    /// Whether the block was accepted.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        matches!(self, Verdict::Accepted(_))
    }
}

/// Validate `block` with **both** executors and return their shared verdict.
///
/// # Errors
///
/// [`SimError::ExecutorDisagreement`] when production and the reference
/// disagree about the block. That is a finding, not a harness failure, and it
/// is reported as loudly as any consensus bug.
pub fn judge(pre: &dyn StateView, block: &Block, ctx: &BlockCtx) -> Result<Verdict, SimError> {
    let production = apply_block(pre, block, ctx);
    let reference = apply_block_reference(pre, block, ctx);
    match (production, reference) {
        (Ok(a), Ok(b)) if a == b => Ok(Verdict::Accepted(a)),
        (Err(a), Err(b)) if a == b => Ok(Verdict::Rejected(a)),
        (a, b) => Err(SimError::ExecutorDisagreement {
            production: format!("{a:?}"),
            reference: format!("{b:?}"),
        }),
    }
}

/// A devnet chain mined `extra` blocks past coinbase maturity, so there is
/// something to spend.
///
/// # Errors
///
/// [`SimError`] if a block cannot be built.
pub fn matured_chain(seed: u64, extra: usize) -> Result<ChainBuilder, SimError> {
    let mut chain = ChainBuilder::devnet(seed)?;
    let maturity = usize::try_from(chain.params().coinbase_maturity).unwrap_or(100);
    chain.advance(maturity.saturating_add(extra))?;
    Ok(chain)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_types::Hash32;

    use super::*;
    use crate::chain_builder::BlockPlan;
    use crate::prng::XorShift64;

    #[test]
    fn judge_agrees_on_an_honest_block() {
        let mut chain = ChainBuilder::devnet(XorShift64::SCENARIO_SEED).unwrap();
        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        let block = chain.build_block(&BlockPlan::default()).unwrap();
        assert!(judge(&pre, &block, &ctx).unwrap().is_accepted());
    }

    #[test]
    fn judge_reports_a_shared_rejection() {
        let mut chain = ChainBuilder::devnet(XorShift64::SCENARIO_SEED).unwrap();
        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        let block = chain
            .build_block(&BlockPlan { merkle_root: Some(Hash32::ZERO), ..BlockPlan::default() })
            .unwrap();
        let verdict = judge(&pre, &block, &ctx).unwrap();
        assert!(matches!(verdict.rejection(), Some(ValidationError::MerkleRootMismatch { .. })));
    }

    #[test]
    fn a_matured_chain_has_something_to_spend() {
        let chain = matured_chain(7, 3).unwrap();
        assert!(!chain.mature(chain.height() + 1).is_empty());
    }
}
