//! A deterministic in-memory network of four validators.
//!
//! There is no clock, no scheduler and no I/O: broadcasts go into a FIFO,
//! timers are delivered explicitly, and every run is bit-for-bit reproducible.
//! That is what modelling the round machine as a pure state machine buys —
//! a four-node consensus run is an ordinary unit test.

use std::collections::{BTreeSet, VecDeque};

use ferrum_types::{Block, BlockHash, BlockHeader, ChainParams, Hash32};

use super::*;
use crate::engine::{ConsensusEngine, block_hash};
use crate::testview::TestView;

/// Upper bound on message deliveries per `pump`, so a broken machine fails the
/// test instead of hanging it.
const MAX_DELIVERIES: usize = 20_000;

/// A set of validator machines wired to each other through one queue.
#[derive(Debug)]
struct Harness {
    machines: Vec<BftMachine>,
    live: Vec<bool>,
    timers: Vec<BTreeSet<Timeout>>,
    decided: Vec<Option<BlockHash>>,
    decides: usize,
    inbox: VecDeque<(usize, BftEvent)>,
}

impl Harness {
    /// `n` validators, with `live[i]` false for the ones that are switched off.
    fn new(n: usize, live: Vec<bool>) -> Self {
        assert_eq!(live.len(), n);
        Harness {
            machines: (0..n).map(|i| machine_for(i, n)).collect(),
            live,
            timers: vec![BTreeSet::new(); n],
            decided: vec![None; n],
            decides: 0,
            inbox: VecDeque::new(),
        }
    }

    fn count(&self) -> usize {
        self.machines.len()
    }

    /// Hand every live machine the candidate and a new height, without
    /// delivering anything yet.
    fn seed(&mut self, height: u64, candidate: BlockHash) {
        for i in 0..self.count() {
            if !self.live[i] {
                continue;
            }
            self.machines[i].set_candidate(height, candidate);
            let actions = self.machines[i].step(BftEvent::NewHeight(height));
            self.apply(i, actions);
        }
    }

    /// Start a height and run the network to quiescence.
    fn start(&mut self, height: u64, candidate: BlockHash) {
        self.seed(height, candidate);
        self.pump();
    }

    /// Deliver queued messages until the queue drains.
    fn pump(&mut self) {
        for _ in 0..MAX_DELIVERIES {
            let Some((index, event)) = self.inbox.pop_front() else {
                return;
            };
            if !self.live[index] {
                continue;
            }
            let actions = self.machines[index].step(event);
            self.apply(index, actions);
        }
        panic!("the harness did not settle: the round machine is looping");
    }

    fn apply(&mut self, index: usize, actions: Vec<BftAction>) {
        for action in actions {
            match action {
                BftAction::Broadcast(message) => {
                    let event = message.into_event();
                    for j in 0..self.count() {
                        if self.live[j] {
                            self.inbox.push_back((j, event));
                        }
                    }
                }
                BftAction::ScheduleTimeout(timeout, _) => {
                    self.timers[index].insert(timeout);
                }
                BftAction::Decide(hash) => {
                    self.decided[index] = Some(hash);
                    self.decides = self.decides.saturating_add(1);
                }
            }
        }
    }

    /// Put an event at the head of every live machine's queue.
    fn inject_front(&mut self, event: BftEvent) {
        for j in (0..self.count()).rev() {
            if self.live[j] {
                self.inbox.push_front((j, event));
            }
        }
    }

    /// Fire every armed timer of `kind` that still names a machine's current
    /// round.
    fn fire(&mut self, kind: TimeoutKind) {
        for i in 0..self.count() {
            if !self.live[i] {
                continue;
            }
            let height = self.machines[i].state().height;
            let round = self.machines[i].state().round;
            let due: Vec<Timeout> = self.timers[i]
                .iter()
                .copied()
                .filter(|t| t.kind == kind && t.height == height && t.round == round)
                .collect();
            for timeout in due {
                self.timers[i].remove(&timeout);
                let actions = self.machines[i].step(BftEvent::Timeout(timeout));
                self.apply(i, actions);
            }
        }
        self.pump();
    }

    /// Hand every live machine all three timeouts for its current round, armed
    /// or not. This is the most generous possible schedule: if the network
    /// still fails to decide under it, it is not a timing problem.
    fn force_round(&mut self) {
        for kind in [TimeoutKind::Propose, TimeoutKind::Prevote, TimeoutKind::Precommit] {
            for i in 0..self.count() {
                if !self.live[i] {
                    continue;
                }
                let height = self.machines[i].state().height;
                let round = self.machines[i].state().round;
                let actions =
                    self.machines[i].step(BftEvent::Timeout(Timeout::new(height, round, kind)));
                self.apply(i, actions);
            }
            self.pump();
        }
    }

    fn reset_decisions(&mut self) {
        self.decided = vec![None; self.count()];
        self.decides = 0;
    }
}

/// A real header, so the decided hash is a block hash the engine can check.
fn header(timestamp_ms: u64) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_hash: BlockHash::ZERO,
        merkle_root: Hash32::ZERO,
        timestamp_ms,
        bits: ChainParams::devnet().genesis_bits,
        nonce: 0,
    }
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn four_validators_commit_in_one_round() {
    let candidate = block_hash(&header(1_000));
    let mut net = Harness::new(4, vec![true; 4]);
    net.start(0, candidate);

    assert_eq!(net.decides, 4, "every validator decides exactly once");
    for i in 0..4 {
        assert_eq!(net.decided[i], Some(candidate), "validator {i}");
        assert_eq!(net.machines[i].state().step, Step::Commit);
        assert_eq!(net.machines[i].state().round, 0, "one round was enough");
    }
}

#[test]
fn every_certificate_carries_a_quorum_and_verifies() {
    let candidate = block_hash(&header(1_000));
    let mut net = Harness::new(4, vec![true; 4]);
    net.start(0, candidate);

    let engine = engine(4);
    for i in 0..4 {
        let commit = net.machines[i].decision().unwrap().clone();
        assert_eq!(commit.height, 0);
        assert_eq!(commit.block_hash, candidate);
        assert!(commit.signatures.len() >= engine.quorum(), "validator {i} is short of quorum");
        assert_eq!(engine.verify_commit(&commit, &candidate, 0), Ok(()));
    }
}

#[test]
fn the_committed_certificate_passes_validate_seal() {
    // The full path the chain layer takes: agree on a header hash, seal the
    // block with the certificate, and validate it as any peer would.
    let head = header(1_000);
    let mut net = Harness::new(4, vec![true; 4]);
    net.start(0, block_hash(&head));

    let commit = net.machines[0].decision().unwrap().clone();
    let block = Block::new(head, Vec::new(), commit.to_seal());
    assert_eq!(engine(4).validate_seal(&block, &TestView::devnet()), Ok(()));
}

#[test]
fn consecutive_heights_commit() {
    let first = block_hash(&header(1_000));
    let second = block_hash(&header(2_000));
    let mut net = Harness::new(4, vec![true; 4]);

    net.start(0, first);
    assert_eq!(net.decides, 4);
    net.reset_decisions();

    net.start(1, second);
    assert_eq!(net.decides, 4);
    for i in 0..4 {
        assert_eq!(net.decided[i], Some(second));
        assert_eq!(net.machines[i].decision().unwrap().height, 1);
        // The proposer rotates with the height: validator 1 proposes height 1.
        assert_eq!(net.machines[i].state().height, 1);
    }
}

// ---------------------------------------------------------------------------
// One validator offline: 3 of 4 is still 2f+1
// ---------------------------------------------------------------------------

#[test]
fn three_of_four_still_commit_when_one_is_offline() {
    let candidate = block_hash(&header(1_000));
    let mut net = Harness::new(4, vec![true, true, true, false]);
    net.start(0, candidate);

    assert_eq!(net.decides, 3);
    for i in 0..3 {
        assert_eq!(net.decided[i], Some(candidate), "validator {i}");
    }
    assert_eq!(net.decided[3], None, "the dead validator decides nothing");
    let commit = net.machines[0].decision().unwrap().clone();
    assert_eq!(commit.signatures.len(), 3, "exactly 2f+1 signatures");
    assert_eq!(engine(4).verify_commit(&commit, &candidate, 0), Ok(()));
}

#[test]
fn a_dead_proposer_is_stepped_over_by_the_next_round() {
    // Validator 0 proposes round 0 and is offline, so round 0 cannot produce a
    // proposal. Round 1 belongs to validator 1, which is alive.
    let candidate = block_hash(&header(1_000));
    let mut net = Harness::new(4, vec![false, true, true, true]);
    net.start(0, candidate);
    assert_eq!(net.decides, 0, "no proposal, no decision");

    net.fire(TimeoutKind::Propose);
    net.fire(TimeoutKind::Prevote);
    net.fire(TimeoutKind::Precommit);

    assert_eq!(net.decides, 3, "round 1 commits with the three live validators");
    for i in 1..4 {
        assert_eq!(net.decided[i], Some(candidate));
        assert_eq!(net.machines[i].decision().unwrap().round, 1);
    }
}

// ---------------------------------------------------------------------------
// Two validators offline: the machine halts, and that is correct
// ---------------------------------------------------------------------------

#[test]
fn two_of_four_halt_and_never_decide() {
    // Halting is the correct behaviour, not a bug to be worked around. With
    // n = 4 the quorum is 3; two validators can only ever muster 2 signatures,
    // and a BFT chain that produced blocks without a quorum would be forking —
    // two disjoint groups could each commit a different block at this height.
    // Forking is strictly worse than stopping: a halted chain loses liveness
    // for as long as the operators take to restore a validator, while a forked
    // chain loses the one property the whole design exists to provide.
    let candidate = block_hash(&header(1_000));
    let mut net = Harness::new(4, vec![true, true, false, false]);
    net.start(0, candidate);

    assert_eq!(net.decides, 0, "no Decide action may ever be produced");
    for i in 0..4 {
        assert_eq!(net.decided[i], None, "validator {i} must not decide");
        assert!(net.machines[i].decision().is_none());
    }
    // The two live validators prevoted the proposal and are stuck there: with
    // only two prevotes there is no polka, and Tendermint does not even arm the
    // prevote timeout below a quorum.
    for i in 0..2 {
        assert_eq!(net.machines[i].state().step, Step::Prevote);
        assert_eq!(net.machines[i].state().round, 0);
    }
}

#[test]
fn a_halted_network_keeps_trying_rounds_and_still_never_decides() {
    // Even handed every timeout for every round, the two survivors rotate
    // through proposers for ever without ever reaching 2f+1.
    let candidate = block_hash(&header(1_000));
    let mut net = Harness::new(4, vec![true, true, false, false]);
    net.start(0, candidate);

    for _ in 0..12 {
        net.force_round();
        assert_eq!(net.decides, 0, "a quorum of two out of four does not exist");
    }
    assert!(net.machines[0].state().round >= 12, "rounds advanced; only agreement did not");
    for i in 0..4 {
        assert_eq!(net.decided[i], None);
    }
}

#[test]
fn a_halted_network_recovers_when_a_validator_returns() {
    // The other half of the promise: the halt is not a wedge. Bring one back
    // and the very next round commits.
    let candidate = block_hash(&header(1_000));
    let mut net = Harness::new(4, vec![true, true, false, false]);
    net.start(0, candidate);
    assert_eq!(net.decides, 0);

    net.live[2] = true;
    net.machines[2].set_candidate(0, candidate);
    let actions = net.machines[2].step(BftEvent::NewHeight(0));
    net.apply(2, actions);
    net.pump();
    net.force_round();

    assert!(net.decides >= 3, "a restored quorum commits");
    assert_eq!(net.decided[0], Some(candidate));
    assert_eq!(net.decided[1], Some(candidate));
}

// ---------------------------------------------------------------------------
// Equivocation
// ---------------------------------------------------------------------------

#[test]
fn an_equivocating_validator_does_not_break_agreement() {
    // Validator 3 prevotes a block nobody proposed, and then prevotes the
    // proposal like everybody else. The tally keeps its first vote, so the
    // honest three still form the polka and the network commits the proposal.
    let candidate = block_hash(&header(1_000));
    let mut net = Harness::new(4, vec![true; 4]);
    net.seed(0, candidate);
    net.inject_front(BftEvent::Prevote(prevote(3, 0, 0, hash(0xee))));
    net.pump();

    assert_eq!(net.decides, 4);
    for i in 0..4 {
        assert_eq!(net.decided[i], Some(candidate), "validator {i} follows the honest majority");
        assert!(net.machines[i].equivocators().contains(&3), "validator {i} saw the evidence");
    }
    // The block the equivocator invented never reached a quorum.
    for i in 0..4 {
        assert_eq!(net.machines[i].state().votes.count(VoteKind::Prevote, 0, &hash(0xee)), 1);
    }
}

#[test]
fn an_equivocating_proposer_cannot_split_the_network() {
    // A second, different proposal in one round is dropped: the first stands,
    // so every validator prevotes the same block.
    let candidate = block_hash(&header(1_000));
    let mut net = Harness::new(4, vec![true; 4]);
    net.seed(0, candidate);
    net.inbox.push_back((1, BftEvent::Proposal(proposal(0, 0, 0, hash(0xdd), None))));
    net.inbox.push_back((2, BftEvent::Proposal(proposal(0, 0, 0, hash(0xdd), None))));
    net.pump();

    assert_eq!(net.decides, 4);
    for i in 0..4 {
        assert_eq!(net.decided[i], Some(candidate));
    }
    assert!(net.machines[1].equivocators().contains(&0));
    assert!(net.machines[2].equivocators().contains(&0));
}

// ---------------------------------------------------------------------------
// Round advance
// ---------------------------------------------------------------------------

#[test]
fn a_round_that_times_out_advances_every_validator_together() {
    // No proposer candidate anywhere: nothing to prevote, so every validator
    // walks the same timeout path and lands in round 1 together.
    let mut net = Harness::new(4, vec![true; 4]);
    for i in 0..4 {
        let actions = net.machines[i].step(BftEvent::NewHeight(0));
        net.apply(i, actions);
    }
    net.pump();

    net.fire(TimeoutKind::Propose);
    for i in 0..4 {
        assert_eq!(net.machines[i].state().step, Step::Precommit, "nil polka precommits nil");
    }
    net.fire(TimeoutKind::Precommit);
    for i in 0..4 {
        assert_eq!(net.machines[i].state().round, 1, "validator {i} advanced");
    }
    assert_eq!(net.decides, 0, "a nil round decides nothing");
}
