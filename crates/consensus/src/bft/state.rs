//! The round state a validator keeps for one height: step, locks, and the
//! vote store.
//!
//! Everything here is a plain data structure with no I/O and no clock. The
//! machine in [`crate::bft::machine`] is the only thing that mutates it, and
//! the node drives that. Every collection is a `BTreeMap`/`BTreeSet`: vote
//! tallies are consensus state, so iteration order must be identical on every
//! node (CONTRACT 0.2).

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use ferrum_crypto::Signature;
use ferrum_types::BlockHash;

use crate::bft::vote::{NIL_BLOCK, VoteKind};

/// Where a validator is inside one round.
///
/// The order matters: several Tendermint rules are written as "while
/// `step >= prevote`", so the derived `Ord` is part of the algorithm rather
/// than a convenience.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    /// Waiting for the proposal from this round's proposer.
    #[default]
    Propose,
    /// Prevote cast; collecting prevotes.
    Prevote,
    /// Precommit cast; collecting precommits.
    Precommit,
    /// A block was decided at this height. Terminal.
    Commit,
}

impl Step {
    /// Short name, for logs and test failure messages.
    pub fn name(self) -> &'static str {
        match self {
            Step::Propose => "propose",
            Step::Prevote => "prevote",
            Step::Precommit => "precommit",
            Step::Commit => "commit",
        }
    }
}

/// Which timer fired, or is being armed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TimeoutKind {
    /// No proposal arrived in time.
    Propose,
    /// A quorum of prevotes arrived but did not agree.
    Prevote,
    /// A quorum of precommits arrived but did not agree.
    Precommit,
}

impl TimeoutKind {
    /// Short name, for logs.
    pub fn name(self) -> &'static str {
        match self {
            TimeoutKind::Propose => "propose",
            TimeoutKind::Prevote => "prevote",
            TimeoutKind::Precommit => "precommit",
        }
    }
}

/// A timer the driver must arm and hand back when it expires.
///
/// It carries `(height, round)` so that a timer armed two rounds ago and
/// delivered late is recognised as stale and dropped, instead of skipping a
/// round the machine is currently making progress in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timeout {
    /// Height the timer belongs to.
    pub height: u64,
    /// Round the timer belongs to.
    pub round: u32,
    /// Which step it guards.
    pub kind: TimeoutKind,
}

impl Timeout {
    /// Build a timeout descriptor.
    pub fn new(height: u64, round: u32, kind: TimeoutKind) -> Self {
        Timeout { height, round, kind }
    }
}

/// The delay for `round`: `base * 2^round`, saturating.
///
/// Doubling is what lets an asynchronous network eventually agree: rounds keep
/// widening until the timeout exceeds the real message delay.
///
/// It saturates at `u64::MAX` milliseconds rather than wrapping. A wrapped
/// shift would produce a *zero* timeout at high round numbers, which spins the
/// round machine at full speed exactly when the network is already in trouble.
pub fn timeout_for_round(base: Duration, round: u32) -> Duration {
    let millis = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
    if millis == 0 {
        return Duration::ZERO;
    }
    // The shift overflows precisely when it would push a set bit past 64.
    if round > millis.leading_zeros() {
        return Duration::from_millis(u64::MAX);
    }
    Duration::from_millis(millis.checked_shl(round).unwrap_or(u64::MAX))
}

/// Round-zero timeouts for the three steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeoutConfig {
    /// How long to wait for a proposal at round 0.
    pub propose: Duration,
    /// How long to wait for prevotes to agree at round 0.
    pub prevote: Duration,
    /// How long to wait for precommits to agree at round 0.
    pub precommit: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        TimeoutConfig {
            propose: super::DEFAULT_PROPOSE_TIMEOUT,
            prevote: super::DEFAULT_PREVOTE_TIMEOUT,
            precommit: super::DEFAULT_PRECOMMIT_TIMEOUT,
        }
    }
}

impl TimeoutConfig {
    /// The round-zero base for one step.
    pub fn base(&self, kind: TimeoutKind) -> Duration {
        match kind {
            TimeoutKind::Propose => self.propose,
            TimeoutKind::Prevote => self.prevote,
            TimeoutKind::Precommit => self.precommit,
        }
    }

    /// The delay for one step at `round`.
    pub fn delay(&self, kind: TimeoutKind, round: u32) -> Duration {
        timeout_for_round(self.base(kind), round)
    }
}

/// What happened when a vote was added to the tally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VoteOutcome {
    /// A new vote from a validator that had not voted in this round and step.
    Accepted,
    /// The same validator voting for the same block again. Ignored.
    Duplicate,
    /// The same validator voting for a *different* block in the same round and
    /// step. The first vote stands and the validator is flagged.
    Equivocation,
}

/// Every vote cast in one round, for one step.
///
/// The first vote from a validator is the one that counts. A second, different
/// vote is recorded as evidence but never replaces the first — if it did, one
/// equivocating validator could move a block from below quorum to above it,
/// which is exactly the attack the tally exists to stop.
#[derive(Clone, Debug, Default)]
pub struct RoundVotes {
    by_validator: BTreeMap<u16, (BlockHash, Signature)>,
    by_block: BTreeMap<BlockHash, BTreeSet<u16>>,
    equivocators: BTreeSet<u16>,
}

impl RoundVotes {
    /// Add a vote, reporting whether it was new, a duplicate, or equivocation.
    pub fn add(&mut self, validator: u16, block: BlockHash, signature: Signature) -> VoteOutcome {
        match self.by_validator.get(&validator) {
            // A second signature over the *same* vote is not equivocation:
            // BIP-340 admits many valid signatures per message because the
            // auxiliary randomness is the signer's choice. Keep the first.
            Some((seen, _)) if *seen == block => VoteOutcome::Duplicate,
            Some(_) => {
                self.equivocators.insert(validator);
                VoteOutcome::Equivocation
            }
            None => {
                self.by_validator.insert(validator, (block, signature));
                self.by_block.entry(block).or_default().insert(validator);
                VoteOutcome::Accepted
            }
        }
    }

    /// How many distinct validators voted for `block`.
    pub fn count_for(&self, block: &BlockHash) -> usize {
        self.by_block.get(block).map_or(0, BTreeSet::len)
    }

    /// How many distinct validators voted at all.
    pub fn total(&self) -> usize {
        self.by_validator.len()
    }

    /// True when nobody has voted in this round and step.
    pub fn is_empty(&self) -> bool {
        self.by_validator.is_empty()
    }

    /// The validators that voted for `block`, ascending.
    pub fn voters_for(&self, block: &BlockHash) -> BTreeSet<u16> {
        self.by_block.get(block).cloned().unwrap_or_default()
    }

    /// The validators that voted at all, ascending.
    pub fn voters(&self) -> BTreeSet<u16> {
        self.by_validator.keys().copied().collect()
    }

    /// The `(index, signature)` pairs backing `block`, strictly ascending by
    /// index — exactly the shape a [`BftCommit`](crate::BftCommit) needs.
    pub fn signatures_for(&self, block: &BlockHash) -> Vec<(u16, Signature)> {
        self.by_validator
            .iter()
            .filter(|(_, (voted, _))| voted == block)
            .map(|(index, (_, signature))| (*index, *signature))
            .collect()
    }

    /// The first non-nil block that reached `quorum` votes, if any.
    ///
    /// At most one block can reach a quorum in a round when fewer than `f+1`
    /// validators equivocate, so "first" is "the only one" in practice; the
    /// deterministic `BTreeMap` order makes the degenerate case identical on
    /// every node instead of a fork.
    pub fn quorum_block(&self, quorum: usize) -> Option<BlockHash> {
        self.by_block
            .iter()
            .find(|(block, voters)| !block.is_zero() && voters.len() >= quorum)
            .map(|(block, _)| *block)
    }

    /// True when `quorum` validators voted nil in this round and step.
    pub fn has_nil_quorum(&self, quorum: usize) -> bool {
        self.count_for(&NIL_BLOCK) >= quorum
    }

    /// Validators caught voting two ways in this round and step.
    pub fn equivocators(&self) -> &BTreeSet<u16> {
        &self.equivocators
    }
}

/// Every prevote and precommit seen at the current height, indexed by round.
#[derive(Clone, Debug, Default)]
pub struct VoteTally {
    prevotes: BTreeMap<u32, RoundVotes>,
    precommits: BTreeMap<u32, RoundVotes>,
}

impl VoteTally {
    /// An empty tally.
    pub fn new() -> Self {
        VoteTally::default()
    }

    fn bucket_mut(&mut self, kind: VoteKind) -> &mut BTreeMap<u32, RoundVotes> {
        match kind {
            VoteKind::Prevote => &mut self.prevotes,
            VoteKind::Precommit => &mut self.precommits,
        }
    }

    fn bucket(&self, kind: VoteKind) -> &BTreeMap<u32, RoundVotes> {
        match kind {
            VoteKind::Prevote => &self.prevotes,
            VoteKind::Precommit => &self.precommits,
        }
    }

    /// Record a vote.
    pub fn add(
        &mut self,
        kind: VoteKind,
        round: u32,
        validator: u16,
        block: BlockHash,
        signature: Signature,
    ) -> VoteOutcome {
        self.bucket_mut(kind).entry(round).or_default().add(validator, block, signature)
    }

    /// The votes of one kind in one round.
    pub fn at(&self, kind: VoteKind, round: u32) -> Option<&RoundVotes> {
        self.bucket(kind).get(&round)
    }

    /// How many validators cast a vote of this kind in this round.
    pub fn total(&self, kind: VoteKind, round: u32) -> usize {
        self.at(kind, round).map_or(0, RoundVotes::total)
    }

    /// How many validators voted for `block`.
    pub fn count(&self, kind: VoteKind, round: u32, block: &BlockHash) -> usize {
        self.at(kind, round).map_or(0, |votes| votes.count_for(block))
    }

    /// The block that reached a prevote quorum ("polka") in `round`.
    pub fn polka(&self, round: u32, quorum: usize) -> Option<BlockHash> {
        self.at(VoteKind::Prevote, round)?.quorum_block(quorum)
    }

    /// True when a quorum prevoted nil in `round`.
    pub fn nil_polka(&self, round: u32, quorum: usize) -> bool {
        self.at(VoteKind::Prevote, round).is_some_and(|votes| votes.has_nil_quorum(quorum))
    }

    /// The lowest round at which a quorum precommitted the same non-nil block,
    /// with that block. This is the decision rule.
    ///
    /// Scanning every round, not only the current one, is deliberate: a
    /// validator that fell behind can be handed the precommits of a round it
    /// never entered and must still decide the same block as everyone else.
    pub fn decided(&self, quorum: usize) -> Option<(u32, BlockHash)> {
        self.precommits
            .iter()
            .find_map(|(round, votes)| votes.quorum_block(quorum).map(|block| (*round, block)))
    }

    /// The `(index, signature)` pairs for a decision, ascending by index.
    pub fn signatures_for(
        &self,
        kind: VoteKind,
        round: u32,
        block: &BlockHash,
    ) -> Vec<(u16, Signature)> {
        self.at(kind, round).map(|votes| votes.signatures_for(block)).unwrap_or_default()
    }

    /// The lowest round strictly above `current` in which at least `threshold`
    /// distinct validators have been heard from, of either kind.
    ///
    /// With `threshold = f + 1`, at least one of them is honest, so the round
    /// really is in progress and this validator is behind. Catching up is what
    /// stops a slow node from stalling a height it has already been overtaken
    /// in.
    pub fn skip_round(&self, current: u32, threshold: usize) -> Option<u32> {
        let mut rounds: BTreeSet<u32> = BTreeSet::new();
        rounds.extend(self.prevotes.keys().copied().filter(|r| *r > current));
        rounds.extend(self.precommits.keys().copied().filter(|r| *r > current));
        rounds.into_iter().find(|round| {
            let mut seen: BTreeSet<u16> = BTreeSet::new();
            if let Some(votes) = self.prevotes.get(round) {
                seen.extend(votes.voters());
            }
            if let Some(votes) = self.precommits.get(round) {
                seen.extend(votes.voters());
            }
            seen.len() >= threshold
        })
    }

    /// Every validator caught equivocating at this height, in any round or
    /// step.
    pub fn equivocators(&self) -> BTreeSet<u16> {
        let mut out = BTreeSet::new();
        for votes in self.prevotes.values().chain(self.precommits.values()) {
            out.extend(votes.equivocators().iter().copied());
        }
        out
    }

    /// Forget everything. Called when the machine moves to a new height.
    pub fn clear(&mut self) {
        self.prevotes.clear();
        self.precommits.clear();
    }
}

/// One validator's view of one height (CONTRACT 6.5).
///
/// `locked_*` is the safety rule: a validator that precommits a block at round
/// `r` is locked on it and may only prevote a different block after seeing a
/// `2f+1` polka for that block at a round **strictly greater** than `r`.
///
/// `valid_*` is the liveness half of the same coin: the newest block this
/// validator has seen a polka for, which is what a proposer re-proposes so a
/// value that already convinced a quorum is not lost when the round changes.
#[derive(Clone, Debug, Default)]
pub struct RoundState {
    /// The height being decided.
    pub height: u64,
    /// The round being decided.
    pub round: u32,
    /// Where in the round this validator is.
    pub step: Step,
    /// The block this validator is locked on.
    pub locked_block: Option<BlockHash>,
    /// The round the lock was taken in.
    pub locked_round: Option<u32>,
    /// The newest block a polka was seen for.
    pub valid_block: Option<BlockHash>,
    /// The round that polka was seen in.
    pub valid_round: Option<u32>,
    /// Every prevote and precommit seen at this height.
    pub votes: VoteTally,
}

impl RoundState {
    /// A fresh state at `height`, round 0, step propose.
    pub fn new(height: u64) -> Self {
        RoundState { height, ..RoundState::default() }
    }

    /// Start a new height: locks, valid values and votes are all dropped.
    ///
    /// Locks are per-height. Carrying one across a height would lock a
    /// validator onto a block that has already been committed and superseded.
    pub fn reset_to_height(&mut self, height: u64) {
        self.height = height;
        self.round = 0;
        self.step = Step::Propose;
        self.locked_block = None;
        self.locked_round = None;
        self.valid_block = None;
        self.valid_round = None;
        self.votes.clear();
    }

    /// Enter `round` at step propose. Locks and valid values survive, because
    /// they are what a later round is judged against.
    pub fn enter_round(&mut self, round: u32) {
        self.round = round;
        self.step = Step::Propose;
    }

    /// The `(round, block)` this validator is locked on, if any.
    pub fn locked(&self) -> Option<(u32, BlockHash)> {
        self.locked_round.zip(self.locked_block)
    }

    /// The `(round, block)` this validator last saw a polka for, if any.
    pub fn valid(&self) -> Option<(u32, BlockHash)> {
        self.valid_round.zip(self.valid_block)
    }
}
