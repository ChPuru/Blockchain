//! The Tendermint-shaped round machine, as a **pure state machine**.
//!
//! [`BftMachine::step`] takes one [`BftEvent`] and returns the [`BftAction`]s
//! the driver must perform. It never touches the network, the clock, the
//! filesystem or the block store: `ferrum-consensus` may depend on
//! `ferrum-types` and `ferrum-crypto` and nothing else (CONTRACT 0.6), and a
//! machine with no I/O is a machine that can be tested without a network.
//!
//! # The contract with the driver
//!
//! 1. Every [`BftAction::Broadcast`] must be delivered to **every** validator,
//!    including this one. The machine does not add its own vote to its own
//!    tally; looping it back is what keeps one code path for "a vote arrived".
//! 2. Every [`BftAction::ScheduleTimeout`] must be armed and, on expiry,
//!    handed back as [`BftEvent::Timeout`]. A late timer is safe: the machine
//!    drops any timeout that does not name its current `(height, round)`.
//! 3. [`BftAction::Decide`] means "this block is committed at this height".
//!    The driver stores the block, then sends [`BftEvent::NewHeight`].
//! 4. The candidate block for a height is supplied with
//!    [`BftMachine::set_candidate`]; the machine cannot build one, because
//!    building one needs the mempool and the mempool is above this seam.
//!
//! # The rules
//!
//! Every rule below carries its number from the Tendermint paper, so a reader
//! can diff this module against the published pseudo-code: `start_round`, then
//! rules 2 and 3 in `try_prevote_on_proposal`, rule 5 in `try_lock_on_polka`,
//! rules 4, 6, 9, 11 and 12 in `advance_once`, rules 7, 8 and 10 in
//! `on_timeout`.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

use ferrum_crypto::SecretKey;
use ferrum_types::{BlockHash, ChainId, ValidatorId};

use crate::bft::event::{BftAction, BftEvent, BftMessage};
use crate::bft::state::{RoundState, Step, Timeout, TimeoutConfig, TimeoutKind, VoteOutcome};
use crate::bft::validators::ValidatorSet;
use crate::bft::vote::{BftCommit, NIL_BLOCK, Proposal, SignedVote, VoteKind, VoteMsg};

/// How many times [`BftMachine::advance_once`] may fire per event.
///
/// Every pass either changes the step (four values, monotone within a round) or
/// enters a higher round, so a handful of passes covers any real sequence:
/// catch up to a later round, prevote, lock, decide. The bound exists so that a
/// crafted message sequence can never spin here — a consensus engine that
/// livelocks inside one event handler is a denial of service.
const MAX_ADVANCE_PASSES: usize = 16;

/// One validator's Tendermint round machine.
#[derive(Debug)]
pub struct BftMachine {
    chain_id: ChainId,
    validators: ValidatorSet,
    me: Option<u16>,
    signing_key: Option<SecretKey>,
    timeouts: TimeoutConfig,
    state: RoundState,
    started: bool,
    /// The block this node would propose, and the height it was built for.
    candidate: Option<(u64, BlockHash)>,
    /// Proposals seen at this height, by round. The first one from a round
    /// wins; a second, different one is proposer equivocation.
    proposals: BTreeMap<u32, Proposal>,
    proposal_equivocators: BTreeSet<u16>,
    /// Timers already armed, so each is armed exactly once.
    scheduled: BTreeSet<Timeout>,
    /// Rounds whose polka has already been applied, so rule 5 fires once.
    polka_applied: BTreeSet<u32>,
    decision: Option<BftCommit>,
    ignored: u64,
}

impl BftMachine {
    /// Build a machine for one validator.
    ///
    /// `signing_key` is `None` for a full node that follows consensus without
    /// voting: it tallies everything and decides with everyone else, but emits
    /// no [`BftAction::Broadcast`].
    pub fn new(
        chain_id: ChainId,
        validators: ValidatorSet,
        signing_key: Option<SecretKey>,
        timeouts: TimeoutConfig,
    ) -> Self {
        let me = signing_key
            .as_ref()
            .and_then(|key| validators.index_of(&ValidatorId::from(key.public_key())));
        BftMachine {
            chain_id,
            validators,
            me,
            signing_key,
            timeouts,
            state: RoundState::new(0),
            started: false,
            candidate: None,
            proposals: BTreeMap::new(),
            proposal_equivocators: BTreeSet::new(),
            scheduled: BTreeSet::new(),
            polka_applied: BTreeSet::new(),
            decision: None,
            ignored: 0,
        }
    }

    // ---------------------------------------------------------------- reads

    /// The current round state.
    pub fn state(&self) -> &RoundState {
        &self.state
    }

    /// The active validator set.
    pub fn validators(&self) -> &ValidatorSet {
        &self.validators
    }

    /// The quorum size, `2f + 1`.
    pub fn quorum(&self) -> usize {
        self.validators.quorum()
    }

    /// The Byzantine tolerance, `f`.
    pub fn fault_tolerance(&self) -> usize {
        self.validators.fault_tolerance()
    }

    /// This node's validator index, when it holds a key that is in the set.
    pub fn own_index(&self) -> Option<u16> {
        self.me
    }

    /// The commit certificate for the decided block, once one exists.
    pub fn decision(&self) -> Option<&BftCommit> {
        self.decision.as_ref()
    }

    /// True once [`BftEvent::NewHeight`] has started a height.
    pub fn is_started(&self) -> bool {
        self.started
    }

    /// Every validator caught contradicting itself at this height: two
    /// different prevotes or precommits in one round, or two different
    /// proposals in one round.
    ///
    /// Equivocation is evidence, not an error. Agreement is unaffected because
    /// the tally keeps the first vote, so an equivocator cannot move a block
    /// across the quorum line; the driver may gossip or punish this set.
    pub fn equivocators(&self) -> BTreeSet<u16> {
        let mut out = self.state.votes.equivocators();
        out.extend(self.proposal_equivocators.iter().copied());
        out
    }

    /// How many messages were dropped as stale, unsigned or out of range.
    pub fn ignored(&self) -> u64 {
        self.ignored
    }

    /// True when this node proposes `(height, round)`.
    pub fn is_proposer(&self, height: u64, round: u32) -> bool {
        self.me == Some(self.validators.proposer_index(height, round))
    }

    /// The block this node would propose at `height`, if one was supplied.
    pub fn candidate(&self, height: u64) -> Option<BlockHash> {
        self.candidate.filter(|(h, _)| *h == height).map(|(_, hash)| hash)
    }

    // --------------------------------------------------------------- writes

    /// Supply the block this node proposes at `height`.
    ///
    /// The machine cannot build a block: that needs the mempool, which lives
    /// above this seam. The driver builds a template, hashes it and hands the
    /// hash here. Tagging it with a height means a stale candidate from the
    /// previous height is never proposed.
    pub fn set_candidate(&mut self, height: u64, block_hash: BlockHash) {
        self.candidate = Some((height, block_hash));
    }

    /// Feed one event in, get the actions to perform out.
    pub fn step(&mut self, event: BftEvent) -> Vec<BftAction> {
        let mut out = Vec::new();
        match event {
            BftEvent::NewHeight(height) => self.on_new_height(height, &mut out),
            BftEvent::Proposal(proposal) => self.on_proposal(proposal, &mut out),
            BftEvent::Prevote(vote) => self.on_vote(VoteKind::Prevote, vote, &mut out),
            BftEvent::Precommit(vote) => self.on_vote(VoteKind::Precommit, vote, &mut out),
            BftEvent::Timeout(timeout) => self.on_timeout(timeout, &mut out),
        }
        out
    }

    // ------------------------------------------------------------- handlers

    fn on_new_height(&mut self, height: u64, out: &mut Vec<BftAction>) {
        if self.started && height <= self.state.height {
            // Heights only go forward. Re-entering one already decided would
            // discard the lock that makes the decision safe.
            self.ignored = self.ignored.saturating_add(1);
            return;
        }
        self.started = true;
        self.state.reset_to_height(height);
        self.proposals.clear();
        self.proposal_equivocators.clear();
        self.scheduled.clear();
        self.polka_applied.clear();
        self.decision = None;
        self.start_round(0, out);
        self.advance(out);
    }

    fn on_proposal(&mut self, proposal: Proposal, out: &mut Vec<BftAction>) {
        if !self.started || proposal.height != self.state.height {
            self.ignored = self.ignored.saturating_add(1);
            return;
        }
        // Nil is a vote, never a proposal: proposing "no block" is meaningless
        // and would let a proposer manufacture a polka for nothing.
        if proposal.block_hash.is_zero() {
            self.ignored = self.ignored.saturating_add(1);
            return;
        }
        if proposal.proposer != self.validators.proposer_index(proposal.height, proposal.round) {
            self.ignored = self.ignored.saturating_add(1);
            return;
        }
        if proposal.verify(self.chain_id, &self.validators).is_err() {
            self.ignored = self.ignored.saturating_add(1);
            return;
        }

        match self.proposals.entry(proposal.round) {
            Entry::Occupied(entry) => {
                if entry.get().block_hash != proposal.block_hash {
                    // Two different proposals in one round from one proposer.
                    // Keep the first: a proposer must not be able to move a
                    // round by re-proposing after validators have prevoted.
                    self.proposal_equivocators.insert(proposal.proposer);
                }
                self.ignored = self.ignored.saturating_add(1);
                return;
            }
            Entry::Vacant(entry) => {
                entry.insert(proposal);
            }
        }
        self.advance(out);
    }

    fn on_vote(&mut self, kind: VoteKind, signed: SignedVote, out: &mut Vec<BftAction>) {
        if !self.started
            || signed.vote.chain_id != self.chain_id
            || signed.vote.height != self.state.height
        {
            self.ignored = self.ignored.saturating_add(1);
            return;
        }
        if signed.verify(kind, &self.validators).is_err() {
            self.ignored = self.ignored.saturating_add(1);
            return;
        }

        let outcome = self.state.votes.add(
            kind,
            signed.vote.round,
            signed.validator,
            signed.vote.block_hash,
            signed.signature,
        );
        match outcome {
            // Neither changes the tally, so neither can unblock a rule.
            VoteOutcome::Duplicate | VoteOutcome::Equivocation => {
                self.ignored = self.ignored.saturating_add(1);
            }
            VoteOutcome::Accepted => self.advance(out),
        }
    }

    fn on_timeout(&mut self, timeout: Timeout, out: &mut Vec<BftAction>) {
        if !self.started || timeout.height != self.state.height || timeout.round != self.state.round
        {
            // A timer armed in an earlier round, delivered late.
            self.ignored = self.ignored.saturating_add(1);
            return;
        }
        match timeout.kind {
            // Rule 7: no proposal arrived, so there is nothing to prevote for.
            TimeoutKind::Propose if self.state.step == Step::Propose => {
                self.broadcast_vote(VoteKind::Prevote, timeout.round, NIL_BLOCK, out);
                self.state.step = Step::Prevote;
            }
            // Rule 8: prevotes arrived but did not agree.
            TimeoutKind::Prevote if self.state.step == Step::Prevote => {
                self.broadcast_vote(VoteKind::Precommit, timeout.round, NIL_BLOCK, out);
                self.state.step = Step::Precommit;
            }
            // Rule 10: precommits arrived but did not agree; try a new round
            // with a new proposer and a longer timeout.
            TimeoutKind::Precommit if self.state.step != Step::Commit => {
                self.start_round(timeout.round.saturating_add(1), out);
            }
            _ => {
                self.ignored = self.ignored.saturating_add(1);
                return;
            }
        }
        self.advance(out);
    }

    // ---------------------------------------------------------------- rules

    /// Enter `round`: propose if it is our turn, and arm the propose timer.
    ///
    /// The timer is armed even for the proposer. A proposer whose own broadcast
    /// never comes back to it would otherwise sit in `Propose` for ever, and a
    /// stalled proposer is exactly the case the round machine exists to escape.
    fn start_round(&mut self, round: u32, out: &mut Vec<BftAction>) {
        self.state.enter_round(round);
        let height = self.state.height;

        if self.is_proposer(height, round) {
            // Re-propose the value we last saw a polka for, so a block that
            // already convinced a quorum survives a round change; otherwise
            // propose whatever the driver built for us.
            let value = self.state.valid_block.or_else(|| self.candidate(height));
            if let Some(block_hash) = value
                && let Some(proposal) =
                    self.sign_proposal(height, round, block_hash, self.state.valid_round)
            {
                out.push(BftAction::Broadcast(BftMessage::Proposal(proposal)));
            }
        }
        self.schedule(Timeout::new(height, round, TimeoutKind::Propose), out);
    }

    /// Run the "upon" rules until nothing more fires.
    fn advance(&mut self, out: &mut Vec<BftAction>) {
        for _ in 0..MAX_ADVANCE_PASSES {
            if !self.advance_once(out) {
                return;
            }
        }
        tracing::warn!(
            height = self.state.height,
            round = self.state.round,
            "BFT round machine hit its per-event rule budget"
        );
    }

    /// One pass over the rules. Returns whether anything changed.
    fn advance_once(&mut self, out: &mut Vec<BftAction>) -> bool {
        if self.state.step == Step::Commit {
            return false;
        }
        let quorum = self.validators.quorum();
        let height = self.state.height;

        // Rule 11: a quorum of precommits for one block decides it, whatever
        // round it happened in and whatever step we are in.
        if let Some((round, block)) = self.state.votes.decided(quorum) {
            self.decide(round, block, out);
            return true;
        }

        // Rule 12: f+1 validators are already in a later round, so at least one
        // honest node has moved on and this one is behind.
        let threshold = self.validators.fault_tolerance().saturating_add(1);
        if let Some(round) = self.state.votes.skip_round(self.state.round, threshold) {
            self.start_round(round, out);
            return true;
        }

        // Rules 2 and 3.
        if self.try_prevote_on_proposal(out) {
            return true;
        }

        // Rule 5.
        if self.try_lock_on_polka(out) {
            return true;
        }

        // Rule 6: a quorum prevoted nil, so there is nothing to lock on.
        if self.state.step == Step::Prevote && self.state.votes.nil_polka(self.state.round, quorum)
        {
            self.broadcast_vote(VoteKind::Precommit, self.state.round, NIL_BLOCK, out);
            self.state.step = Step::Precommit;
            return true;
        }

        // Rule 4: a quorum of prevotes that did not agree. Give the stragglers
        // one timeout before precommitting nil.
        if self.state.step == Step::Prevote
            && self.state.votes.total(VoteKind::Prevote, self.state.round) >= quorum
            && self.schedule(Timeout::new(height, self.state.round, TimeoutKind::Prevote), out)
        {
            return true;
        }

        // Rule 9: a quorum of precommits that did not agree. Time-box the round.
        if self.state.votes.total(VoteKind::Precommit, self.state.round) >= quorum
            && self.schedule(Timeout::new(height, self.state.round, TimeoutKind::Precommit), out)
        {
            return true;
        }

        false
    }

    /// Rules 2 and 3: prevote once this round's proposal is usable.
    ///
    /// This is where **locking** is enforced, and it is the rule most often
    /// omitted. A validator locked on `A` at round `r` prevotes `nil` for a
    /// competing `B`, and changes its mind only when it has itself counted a
    /// `2f+1` polka for `B` at a round strictly greater than `r`.
    ///
    /// The Tendermint pseudo-code writes that test as `lockedRound <= vr`;
    /// Ferrum uses `lockedRound < vr` because CONTRACT 6.5 and SPEC 9.2 both
    /// say "a round **greater** than r". The two differ only when a polka
    /// exists in the very round this validator precommitted a different value,
    /// which already requires a quorum member to have equivocated, and taking
    /// the stricter reading costs nothing.
    fn try_prevote_on_proposal(&mut self, out: &mut Vec<BftAction>) -> bool {
        if self.state.step != Step::Propose {
            return false;
        }
        let round = self.state.round;
        let Some(proposal) = self.proposals.get(&round).copied() else {
            return false;
        };
        let quorum = self.validators.quorum();

        let target = match proposal.pol_round {
            // Rule 2: a fresh proposal, no proof of lock offered.
            None => {
                if self.state.locked_block.is_none_or(|locked| locked == proposal.block_hash) {
                    proposal.block_hash
                } else {
                    NIL_BLOCK
                }
            }
            // Rule 3: the proposer claims a polka at `vr`. The claim itself is
            // worthless; only a polka this validator has counted counts.
            Some(vr) => {
                if vr >= round {
                    self.ignored = self.ignored.saturating_add(1);
                    return false;
                }
                if self.state.votes.polka(vr, quorum) != Some(proposal.block_hash) {
                    // The polka may still arrive; this rule is retried on every
                    // later event while the step is still `Propose`.
                    return false;
                }
                let unlocked = self.state.locked_round.is_none_or(|locked| locked < vr)
                    || self.state.locked_block == Some(proposal.block_hash);
                if unlocked { proposal.block_hash } else { NIL_BLOCK }
            }
        };

        self.broadcast_vote(VoteKind::Prevote, round, target, out);
        self.state.step = Step::Prevote;
        true
    }

    /// Rule 5: a polka for this round's proposal locks it and precommits it.
    fn try_lock_on_polka(&mut self, out: &mut Vec<BftAction>) -> bool {
        let round = self.state.round;
        if self.state.step < Step::Prevote || self.polka_applied.contains(&round) {
            return false;
        }
        let Some(block) = self.state.votes.polka(round, self.validators.quorum()) else {
            return false;
        };
        // A polka names a hash; locking on a block we have never seen proposed
        // would let a quorum of liars lock this node onto nothing.
        if self.proposals.get(&round).map(|p| p.block_hash) != Some(block) {
            return false;
        }

        self.polka_applied.insert(round);
        self.state.valid_block = Some(block);
        self.state.valid_round = Some(round);
        if self.state.step == Step::Prevote {
            self.state.locked_block = Some(block);
            self.state.locked_round = Some(round);
            self.broadcast_vote(VoteKind::Precommit, round, block, out);
            self.state.step = Step::Precommit;
        }
        true
    }

    /// Rule 11: turn a quorum of precommits into a commit certificate.
    fn decide(&mut self, round: u32, block: BlockHash, out: &mut Vec<BftAction>) {
        let signatures = self.state.votes.signatures_for(VoteKind::Precommit, round, &block);
        self.decision = Some(BftCommit::new(self.state.height, round, block, signatures));
        self.state.step = Step::Commit;
        out.push(BftAction::Decide(block));
    }

    // -------------------------------------------------------------- helpers

    /// Arm a timer once. Returns whether it was newly armed.
    fn schedule(&mut self, timeout: Timeout, out: &mut Vec<BftAction>) -> bool {
        if !self.scheduled.insert(timeout) {
            return false;
        }
        out.push(BftAction::ScheduleTimeout(
            timeout,
            self.timeouts.delay(timeout.kind, timeout.round),
        ));
        true
    }

    /// Emit a signed vote, if this node is a validator with a key.
    ///
    /// The vote is **not** added to the local tally here. The driver delivers
    /// every broadcast to every validator, this one included, so a vote is
    /// counted through exactly one path.
    fn broadcast_vote(
        &mut self,
        kind: VoteKind,
        round: u32,
        block: BlockHash,
        out: &mut Vec<BftAction>,
    ) {
        let Some(index) = self.me else {
            return;
        };
        let Some(key) = self.signing_key.as_ref() else {
            return;
        };
        let vote = VoteMsg::new(self.chain_id, self.state.height, round, block);
        let signed = SignedVote::sign(key, index, kind, vote);
        out.push(BftAction::Broadcast(match kind {
            VoteKind::Prevote => BftMessage::Prevote(signed),
            VoteKind::Precommit => BftMessage::Precommit(signed),
        }));
    }

    fn sign_proposal(
        &self,
        height: u64,
        round: u32,
        block_hash: BlockHash,
        pol_round: Option<u32>,
    ) -> Option<Proposal> {
        let index = self.me?;
        let key = self.signing_key.as_ref()?;
        Some(Proposal::sign(key, self.chain_id, index, height, round, block_hash, pol_round))
    }
}
