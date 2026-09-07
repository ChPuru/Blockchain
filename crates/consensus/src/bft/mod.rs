//! The BFT engine: Tendermint-shaped, permissioned, safety over liveness.
//!
//! # The subtree
//!
//! | Module | What lives there |
//! |---|---|
//! | [`validators`] | the fixed validator set, `f`, `2f+1`, the proposer schedule |
//! | [`vote`] | [`VoteMsg`], [`SignedVote`], [`Proposal`], [`BftCommit`] and the three signing digests |
//! | [`state`] | [`RoundState`], [`Step`], the vote tally and the timeout schedule |
//! | [`event`] | [`BftEvent`] in, [`BftAction`] out — the whole driver interface |
//! | [`machine`] | [`BftMachine`]: events in, actions out, no I/O |
//! | [`engine`] | [`BftEngine`]: the [`ConsensusEngine`](crate::ConsensusEngine) face |
//!
//! # The rules (CONTRACT 6.5, SPEC 9.2)
//!
//! - The validator set is fixed in `ChainParams::bft_validators`, x-only BIP-340
//!   keys, `n >= 4`, `f = (n - 1) / 3`, quorum `2f + 1`, and `2(2f + 1) > n`.
//!   That last clause is quorum intersection, and it is the whole reason a
//!   `2f+1` certificate means anything; it excludes exactly `n = 6`, which
//!   [`ValidatorSet::new`](validators::ValidatorSet::new) refuses at startup.
//! - Round: propose, prevote, precommit, commit, with round-robin proposer
//!   `validators[(height + round) % n]`.
//! - Timeouts double each round: `base * 2^round`.
//! - **Locking:** a validator that precommits a block in round `r` is locked on
//!   it and may only prevote a different block after seeing a `2f+1` polka for
//!   that block at a round greater than `r`. This is the rule that makes safety
//!   hold under asynchrony, and it is the rule most often omitted from
//!   simplified implementations. It lives in
//!   [`BftMachine::step`](machine::BftMachine::step), and there are tests for
//!   both halves of it.
//! - Signed message:
//!   `tagged_hash(TAG_BFT_PRECOMMIT, borsh(VoteMsg{chain_id, height, round, block_hash}))`,
//!   and the prevote is the same preimage under `TAG_BFT_PREVOTE`. A proposal
//!   signs `tagged_hash(TAG_BFT_PROPOSAL, borsh(VoteMsg) || borsh(pol_round))`:
//!   `pol_round` picks which prevote rule a receiver runs, so leaving it out of
//!   the preimage would hand that choice to whoever relays the message.
//!
//! # Safety over liveness, deliberately
//!
//! With `n = 4`, killing one validator continues; killing two **halts**.
//! Halting is the correct behaviour: a BFT chain that kept producing blocks
//! without a quorum would be forking, which is strictly worse than stopping.
//! `RUNNING.md` states the operational commitment plainly — *this chain may
//! halt for up to 24 hours; it will never fork* — and the four-validator
//! harness in `bft::tests::harness` asserts both halves of it.
//!
//! # No I/O, by construction
//!
//! The round machine is pure: it takes events and returns actions. It cannot
//! open a socket, read a clock or touch the block store, because
//! `ferrum-consensus` depends on `ferrum-types` and `ferrum-crypto` and nothing
//! else (CONTRACT 0.6). The node supplies the network and the timers. That is
//! also what makes a four-validator consensus run a unit test.

use core::time::Duration;

pub mod engine;
pub mod event;
pub mod machine;
pub mod state;
pub mod validators;
pub mod vote;

pub use crate::bft::engine::BftEngine;
pub use crate::bft::event::{BftAction, BftEvent, BftMessage};
pub use crate::bft::machine::{BftMachine, MAX_ROUND_LOOKAHEAD};
pub use crate::bft::state::{
    RoundState, RoundVotes, Step, Timeout, TimeoutConfig, TimeoutKind, VoteOutcome, VoteTally,
    timeout_for_round,
};
pub use crate::bft::validators::{MIN_VALIDATORS, ValidatorSet};
pub use crate::bft::vote::{
    BftCommit, NIL_BLOCK, Proposal, SignedVote, VOTE_MSG_SIZE, VoteKind, VoteMsg, precommit_digest,
    prevote_digest, proposal_digest,
};

/// Default propose timeout at round 0.
pub const DEFAULT_PROPOSE_TIMEOUT: Duration = Duration::from_millis(3_000);
/// Default prevote timeout at round 0.
pub const DEFAULT_PREVOTE_TIMEOUT: Duration = Duration::from_millis(1_000);
/// Default precommit timeout at round 0.
pub const DEFAULT_PRECOMMIT_TIMEOUT: Duration = Duration::from_millis(1_000);

/// Deterministic validator keys for tests in this crate.
#[cfg(test)]
pub(crate) mod tests_support {
    use ferrum_crypto::SecretKey;
    use ferrum_types::ValidatorId;

    /// The `i`-th test validator's secret key: seed `[i+1; 32]`.
    pub(crate) fn validator_key(i: usize) -> SecretKey {
        let seed = [u8::try_from(i.wrapping_add(1)).unwrap_or(1); 32];
        SecretKey::from_bytes(&seed).expect("a non-zero 32-byte seed is a valid secret key")
    }

    /// `n` distinct, valid x-only validator ids.
    pub(crate) fn validator_ids(n: usize) -> Vec<ValidatorId> {
        (0..n).map(|i| ValidatorId::from(validator_key(i).public_key())).collect()
    }
}

#[cfg(test)]
mod tests;
