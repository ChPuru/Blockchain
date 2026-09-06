//! **Attack:** offer a node a hundred-block branch with more work than its own
//! chain, one block of which is invalid.
//!
//! The branch is expensive to *produce* and, if a node handled it naively,
//! catastrophic to consume. Two failure modes are being tested for:
//!
//! 1. **A half-applied reorganisation.** The node disconnects ten of its own
//!    blocks, connects nine of the attacker's, hits the invalid one and stops.
//!    It is now validating every future block against a UTXO set that no other
//!    node has, and only a reindex recovers. SPEC §7.2 step 4 requires the
//!    whole reorg be rolled back to the original tip and the branch marked
//!    `Invalid`; the store must end up **byte-identical** to how it started.
//! 2. **Unbounded work per peer.** Once the defective block is known invalid,
//!    nothing built on it may ever be applied. Its immediate child is refused
//!    outright, because the parent header is on record as `Invalid`; the rest
//!    of the branch names parents the node has never stored, so it is held as
//!    orphans under a bounded cap rather than validated. Either way the cost
//!    is a lookup, not a replay.
//!
//! The fixture puts the invalid block exactly where it hurts most: at the
//! first height where the branch out-works the honest chain, so the node is
//! already mid-reorganisation when it finds the defect.
//!
//! **Red:** the branch never becomes the tip, the failure names
//! [`ferrum_chain::ValidationError::CoinbaseOverpayment`], and the UTXO set is unchanged
//! byte for byte.
//! **Green:** a branch of the same shape whose blocks are all *valid* does
//! replace the honest tip — so the rejection above is the invalid block being
//! caught, not the reorg machinery being broken.

use ferrum_chain::AcceptOutcome;
use ferrum_types::{Block, BlockHash};

use crate::chain_builder::{BlockPlan, ChainBuilder};
use crate::error::SimError;
use crate::node::SimNode;

/// How long the honest chain is before the branch is offered.
pub const HONEST_HEIGHT: usize = 20;

/// How many blocks the attacker's branch carries.
pub const BRANCH_LENGTH: usize = 100;

/// The height the branch forks at.
pub const FORK_HEIGHT: u64 = 10;

/// The extra nonce the branch's coinbases carry, so that its blocks are not
/// byte-identical to the honest chain's at the same heights.
pub const BRANCH_NONCE: u64 = 0xbad0_0001;

/// Build an honest chain of `HONEST_HEIGHT` blocks and feed it to a node.
///
/// # Errors
///
/// [`SimError`] if a block cannot be built or is rejected.
pub fn honest_node(seed: u64) -> Result<(SimNode, ChainBuilder), SimError> {
    let node = SimNode::devnet()?;
    let mut chain = ChainBuilder::devnet(seed)?;
    for _ in 0..HONEST_HEIGHT {
        let block = chain.build_block(&BlockPlan::default())?;
        chain.connect(&block);
        node.accept_expecting_extension(block)?;
    }
    Ok((node, chain))
}

/// Build a branch off `FORK_HEIGHT` of `chain`.
///
/// When `invalid_at` is `Some(h)`, the branch's block at height `h` claims one
/// grain more than it is owed; every other block is valid.
///
/// # Errors
///
/// [`SimError`] if a block cannot be built.
pub fn build_branch(chain: &ChainBuilder, invalid_at: Option<u64>) -> Result<Vec<Block>, SimError> {
    let mut fork = chain.fork_at(FORK_HEIGHT)?;
    fork.set_extra_nonce(BRANCH_NONCE);
    let mut blocks = Vec::with_capacity(BRANCH_LENGTH);
    for _ in 0..BRANCH_LENGTH {
        let height = fork.height().saturating_add(1);
        let bonus = u64::from(invalid_at == Some(height));
        let block =
            fork.build_block(&BlockPlan { coinbase_bonus: bonus, ..BlockPlan::default() })?;
        fork.connect(&block);
        blocks.push(block);
    }
    Ok(blocks)
}

/// The branch height at which a node first abandons the honest chain.
///
/// Fork choice is by cumulative work, and ties break on the **lower block
/// hash** — so the branch can win at the height where it merely *equals* the
/// honest chain in work, not only above it. Which of the two happens depends
/// on a hash, so the fixture measures it rather than assuming it: the invalid
/// block is then placed exactly there, where the node is already
/// mid-reorganisation when it finds the defect.
///
/// # Errors
///
/// [`SimError`] if the dry run cannot be built, or if the branch never wins.
pub fn first_winning_height(seed: u64) -> Result<u64, SimError> {
    let (node, chain) = honest_node(seed)?;
    let branch = build_branch(&chain, None)?;
    for (index, block) in branch.iter().enumerate() {
        let height =
            FORK_HEIGHT.saturating_add(u64::try_from(index).unwrap_or(0)).saturating_add(1);
        if node.accept(block.clone())?.moved_the_tip() {
            return Ok(height);
        }
    }
    Err(SimError::fixture("the branch never won"))
}

/// Offer every block of `branch` to `node`, recording what happened.
///
/// # Errors
///
/// Never: a rejected block is recorded, not propagated. The `Result` exists so
/// that the caller can use `?` uniformly.
pub fn offer_branch(node: &SimNode, branch: &[Block]) -> Result<Vec<BranchOutcome>, SimError> {
    let mut out = Vec::with_capacity(branch.len());
    for block in branch {
        let hash = ferrum_storage::header_hash(&block.header);
        let result = node.accept(block.clone());
        out.push(BranchOutcome {
            hash,
            outcome: result.as_ref().ok().cloned(),
            error: result.err().map(|e| e.to_string()),
            validation: None,
        });
    }
    Ok(out)
}

/// What a node did with one block of the branch.
#[derive(Clone, Debug)]
pub struct BranchOutcome {
    /// The block's hash.
    pub hash: BlockHash,
    /// The acceptance outcome, if it was accepted at all.
    pub outcome: Option<AcceptOutcome>,
    /// The rejection, rendered, if it was not.
    pub error: Option<String>,
    /// The consensus verdict, when the caller extracted one.
    pub validation: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_chain::{ChainError, ValidationError};

    use super::*;

    /// The branch height at which a node abandons the honest chain, measured
    /// rather than assumed — see [`first_winning_height`].
    fn trigger_height(seed: u64) -> u64 {
        first_winning_height(seed).unwrap()
    }

    /// How many branch blocks the node accepts as a side chain before the
    /// trigger.
    fn before_trigger(trigger: u64) -> usize {
        usize::try_from(trigger - FORK_HEIGHT - 1).unwrap()
    }

    // ---- red -----------------------------------------------------------

    #[test]
    fn an_invalid_branch_never_replaces_the_honest_tip() {
        let trigger = trigger_height(71);
        let (node, chain) = honest_node(71).unwrap();
        let before_tip = node.tip();
        let before_root = node.state_root().unwrap();
        let before_utxo = node.utxo_snapshot().unwrap();
        assert_eq!(before_tip.1, HONEST_HEIGHT as u64);

        let branch = build_branch(&chain, Some(trigger)).unwrap();
        assert_eq!(branch.len(), BRANCH_LENGTH);

        let mut applied = 0usize;
        let mut first_rejection: Option<ValidationError> = None;
        for block in &branch {
            match node.accept(block.clone()) {
                Ok(outcome) => {
                    if outcome.moved_the_tip() {
                        applied += 1;
                    }
                }
                Err(e) => {
                    if first_rejection.is_none() {
                        first_rejection = match e {
                            ChainError::Validation(v) => Some(v),
                            _ => None,
                        };
                    }
                }
            }
        }

        assert!(
            matches!(first_rejection, Some(ValidationError::CoinbaseOverpayment { .. })),
            "the branch must fail on its defect, got {first_rejection:?}"
        );
        assert_eq!(applied, 0, "not one block of the branch may be applied");
        assert!(before_trigger(trigger) < BRANCH_LENGTH, "the defect is inside the branch");

        // SPEC §7.2 step 4: the store is exactly where it started.
        assert_eq!(node.tip(), before_tip, "the honest tip must survive");
        assert_eq!(node.state_root().unwrap(), before_root);
        assert_eq!(node.utxo_snapshot().unwrap(), before_utxo, "byte-identical UTXO set");
    }

    #[test]
    fn nothing_built_on_the_invalid_block_is_ever_applied() {
        let trigger = trigger_height(72);
        let (node, chain) = honest_node(72).unwrap();
        let branch = build_branch(&chain, Some(trigger)).unwrap();
        let cutoff = before_trigger(trigger);

        // Everything below the defect is a valid side chain: stored, and
        // ignored because it does not out-work the honest tip.
        for block in branch.iter().take(cutoff) {
            let outcome = node.accept(block.clone()).unwrap();
            assert!(matches!(outcome, AcceptOutcome::SideChain(_)), "got {outcome:?}");
        }

        // The defect is refused by name.
        let defect = branch.get(cutoff).expect("the defect is inside the branch");
        let err = node.accept(defect.clone()).unwrap_err();
        assert!(
            matches!(err.validation(), Some(ValidationError::CoinbaseOverpayment { .. })),
            "got {err}"
        );

        // Its immediate child names a parent the node has recorded as invalid,
        // so it is refused outright rather than stored.
        let child = branch.get(cutoff + 1).expect("the defect has a child");
        assert!(node.accept(child.clone()).is_err(), "a child of an invalid block is refused");

        // The rest name parents the node never stored. They are held as
        // orphans under a bounded cap — never validated, never applied.
        for block in branch.iter().skip(cutoff + 2) {
            if let Ok(outcome) = node.accept(block.clone()) {
                assert!(
                    matches!(outcome, AcceptOutcome::Orphan),
                    "an unconnectable block must be held, not applied: {outcome:?}"
                );
            }
        }
        assert_eq!(node.tip().1, HONEST_HEIGHT as u64);
    }

    #[test]
    fn the_invalid_block_is_the_one_that_would_have_won() {
        // If the defect were below the honest tip's work the node would never
        // reach it, and the test would prove nothing about rollback.
        let trigger = trigger_height(73);
        let (node, chain) = honest_node(73).unwrap();
        let branch = build_branch(&chain, Some(trigger)).unwrap();
        let cutoff = before_trigger(trigger);
        for block in branch.iter().take(cutoff) {
            node.accept(block.clone()).unwrap();
        }
        assert_eq!(node.tip().1, HONEST_HEIGHT as u64, "still the honest tip");

        let winner = branch.get(cutoff).expect("the trigger block exists");
        let err = node.accept(winner.clone()).unwrap_err();
        assert!(
            matches!(err.validation(), Some(ValidationError::CoinbaseOverpayment { .. })),
            "got {err}"
        );
        assert_eq!(node.tip().1, HONEST_HEIGHT as u64, "the reorg was rolled back");
    }

    // ---- green ---------------------------------------------------------

    #[test]
    fn a_valid_branch_of_the_same_shape_does_replace_the_tip() {
        // The control: the machinery works, so the rejection above is the
        // defect being caught rather than reorganisation being broken.
        let trigger = trigger_height(74);
        let (node, chain) = honest_node(74).unwrap();
        let branch = build_branch(&chain, None).unwrap();

        let mut reorged = false;
        for block in &branch {
            if let Ok(AcceptOutcome::Reorged { disconnected, connected, .. }) =
                node.accept(block.clone())
            {
                reorged = true;
                assert_eq!(
                    disconnected.len(),
                    HONEST_HEIGHT - FORK_HEIGHT as usize,
                    "the honest blocks above the fork point come off"
                );
                assert_eq!(
                    connected.len(),
                    usize::try_from(trigger - FORK_HEIGHT).unwrap(),
                    "the branch is connected up to the winning block"
                );
            }
        }
        assert!(reorged, "a longer valid branch must win");
        assert_eq!(node.tip().1, (FORK_HEIGHT as usize + BRANCH_LENGTH) as u64);
    }

    #[test]
    fn a_branch_with_less_work_is_stored_but_ignored() {
        let (node, chain) = honest_node(75).unwrap();
        let before = node.tip();
        let mut fork = chain.fork_at(FORK_HEIGHT).unwrap();
        fork.set_extra_nonce(BRANCH_NONCE);
        for _ in 0..5 {
            let block = fork.build_block(&BlockPlan::default()).unwrap();
            fork.connect(&block);
            let outcome = node.accept(block.clone()).unwrap();
            assert!(matches!(outcome, AcceptOutcome::SideChain(_)), "got {outcome:?}");
            assert!(node.has_block(&ferrum_storage::header_hash(&block.header)).unwrap());
        }
        assert_eq!(node.tip(), before);
    }
}
