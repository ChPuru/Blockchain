//! Tests for the BFT subtree.
//!
//! Split by subject so no file runs long:
//!
//! - [`commit`] — the vote preimage, the signing digests and `2f+1`
//!   certificate verification;
//! - [`machine`] — the round machine, one validator at a time, including both
//!   halves of the locking rule;
//! - [`harness`] — a deterministic in-memory network of four validators;
//! - [`fork`] — the engine face and the PoW to BFT boundary.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

mod commit;
mod fork;
mod harness;
mod machine;

use core::time::Duration;

use ferrum_types::{BlockHash, ChainParams};

use super::tests_support::{validator_ids, validator_key};
use super::*;
use crate::bft::vote::VoteKind;

/// Devnet parameters with `n` validators and BFT active from genesis.
pub(crate) fn params(n: usize) -> ChainParams {
    let mut p = ChainParams::devnet();
    p.bft_activation_height = Some(0);
    p.bft_validators = validator_ids(n);
    p
}

/// A BFT engine over `n` validators, with no signing key.
pub(crate) fn engine(n: usize) -> BftEngine {
    BftEngine::new(params(n), None).unwrap()
}

/// A validator set of `n` members.
pub(crate) fn set(n: usize) -> ValidatorSet {
    ValidatorSet::new(validator_ids(n)).unwrap()
}

/// A block hash made of one repeated byte.
pub(crate) fn hash(byte: u8) -> BlockHash {
    BlockHash::from_bytes([byte; 32])
}

/// A round machine for validator `index` in a set of `n`.
pub(crate) fn machine_for(index: usize, n: usize) -> BftMachine {
    BftMachine::new(
        params(n).chain_id,
        set(n),
        Some(validator_key(index)),
        TimeoutConfig::default(),
    )
}

/// A signed vote of `kind` from validator `index`.
pub(crate) fn signed_vote(
    index: u16,
    kind: VoteKind,
    height: u64,
    round: u32,
    block: BlockHash,
) -> SignedVote {
    let vote = VoteMsg::new(ChainParams::devnet().chain_id, height, round, block);
    SignedVote::sign(&validator_key(usize::from(index)), index, kind, vote)
}

/// A signed prevote from validator `index`.
pub(crate) fn prevote(index: u16, height: u64, round: u32, block: BlockHash) -> SignedVote {
    signed_vote(index, VoteKind::Prevote, height, round, block)
}

/// A signed precommit from validator `index`.
pub(crate) fn precommit(index: u16, height: u64, round: u32, block: BlockHash) -> SignedVote {
    signed_vote(index, VoteKind::Precommit, height, round, block)
}

/// A signed proposal from validator `index`.
pub(crate) fn proposal(
    index: u16,
    height: u64,
    round: u32,
    block: BlockHash,
    pol_round: Option<u32>,
) -> Proposal {
    Proposal::sign(
        &validator_key(usize::from(index)),
        ChainParams::devnet().chain_id,
        index,
        height,
        round,
        block,
        pol_round,
    )
}

/// A commit signed by validators `indices`, over `(height, round, hash)`.
pub(crate) fn commit_signed_by(
    p: &ChainParams,
    indices: &[u16],
    height: u64,
    round: u32,
    block: BlockHash,
) -> BftCommit {
    let v = VoteMsg::new(p.chain_id, height, round, block);
    let digest = precommit_digest(&v);
    let signatures = indices
        .iter()
        .map(|i| (*i, validator_key(usize::from(*i)).sign_deterministic(&digest)))
        .collect();
    BftCommit::new(height, round, block, signatures)
}

// ---------------------------------------------------------------------------
// Reading actions
// ---------------------------------------------------------------------------

/// Every proposal broadcast in `actions`.
pub(crate) fn proposals_in(actions: &[BftAction]) -> Vec<Proposal> {
    actions
        .iter()
        .filter_map(|a| match a {
            BftAction::Broadcast(BftMessage::Proposal(p)) => Some(*p),
            _ => None,
        })
        .collect()
}

/// Every prevote broadcast in `actions`.
pub(crate) fn prevotes_in(actions: &[BftAction]) -> Vec<SignedVote> {
    actions
        .iter()
        .filter_map(|a| match a {
            BftAction::Broadcast(BftMessage::Prevote(v)) => Some(*v),
            _ => None,
        })
        .collect()
}

/// Every precommit broadcast in `actions`.
pub(crate) fn precommits_in(actions: &[BftAction]) -> Vec<SignedVote> {
    actions
        .iter()
        .filter_map(|a| match a {
            BftAction::Broadcast(BftMessage::Precommit(v)) => Some(*v),
            _ => None,
        })
        .collect()
}

/// Every timer armed in `actions`.
pub(crate) fn timeouts_in(actions: &[BftAction]) -> Vec<(Timeout, Duration)> {
    actions
        .iter()
        .filter_map(|a| match a {
            BftAction::ScheduleTimeout(t, d) => Some((*t, *d)),
            _ => None,
        })
        .collect()
}

/// Every decision in `actions`.
pub(crate) fn decisions_in(actions: &[BftAction]) -> Vec<BlockHash> {
    actions
        .iter()
        .filter_map(|a| match a {
            BftAction::Decide(h) => Some(*h),
            _ => None,
        })
        .collect()
}
