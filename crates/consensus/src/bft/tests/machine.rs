//! The round machine, one validator at a time.
//!
//! Every test here drives a single [`BftMachine`] by hand, which is the point
//! of modelling consensus as a pure state machine: the rules are testable
//! without a network, a clock or a block store.

use core::time::Duration;

use ferrum_crypto::Signature;
use ferrum_types::ChainId;

use super::*;
use crate::bft::vote::VoteKind;

/// A block, and a competing one.
fn a() -> BlockHash {
    hash(0xa1)
}
fn b() -> BlockHash {
    hash(0xb2)
}

/// Drive `m` to `(height 0, round 0)` with a lock on [`a`], taken at round 0.
///
/// Validator 3 is the machine under test; validator 0 proposes at round 0.
fn locked_on_a() -> BftMachine {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    m.step(BftEvent::Proposal(proposal(0, 0, 0, a(), None)));
    m.step(BftEvent::Prevote(prevote(0, 0, 0, a())));
    m.step(BftEvent::Prevote(prevote(1, 0, 0, a())));
    m.step(BftEvent::Prevote(prevote(2, 0, 0, a())));
    assert_eq!(m.state().locked(), Some((0, a())), "the harness must reach the lock");
    m
}

// ---------------------------------------------------------------------------
// Starting a height and a round
// ---------------------------------------------------------------------------

#[test]
fn a_new_height_starts_at_round_zero_and_arms_the_propose_timer() {
    let mut m = machine_for(1, 4);
    assert!(!m.is_started());
    let actions = m.step(BftEvent::NewHeight(9));
    assert!(m.is_started());
    assert_eq!(m.state().height, 9);
    assert_eq!(m.state().round, 0);
    assert_eq!(m.state().step, Step::Propose);

    let armed = timeouts_in(&actions);
    assert_eq!(armed.len(), 1);
    assert_eq!(armed[0].0, Timeout::new(9, 0, TimeoutKind::Propose));
    assert_eq!(armed[0].1, DEFAULT_PROPOSE_TIMEOUT);
}

#[test]
fn the_proposer_broadcasts_its_candidate() {
    let mut m = machine_for(0, 4);
    m.set_candidate(0, a());
    assert!(m.is_proposer(0, 0));
    assert_eq!(m.candidate(0), Some(a()));
    assert_eq!(m.candidate(1), None, "a candidate is tied to the height it was built for");

    let actions = m.step(BftEvent::NewHeight(0));
    let proposals = proposals_in(&actions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].proposer, 0);
    assert_eq!(proposals[0].round, 0);
    assert_eq!(proposals[0].block_hash, a());
    assert_eq!(proposals[0].pol_round, None, "no polka has been seen yet");
    assert_eq!(proposals[0].verify(ChainId::DEVNET, &set(4)), Ok(()));
}

#[test]
fn a_non_proposer_does_not_propose() {
    let mut m = machine_for(1, 4);
    m.set_candidate(0, a());
    assert!(!m.is_proposer(0, 0));
    assert!(proposals_in(&m.step(BftEvent::NewHeight(0))).is_empty());
}

#[test]
fn a_proposer_without_a_candidate_stays_quiet_but_still_arms_the_timer() {
    // The machine cannot build a block: that needs the mempool, which is above
    // this seam. With no candidate it simply lets the round time out.
    let mut m = machine_for(0, 4);
    let actions = m.step(BftEvent::NewHeight(0));
    assert!(proposals_in(&actions).is_empty());
    assert_eq!(timeouts_in(&actions).len(), 1);
}

#[test]
fn events_before_the_first_height_are_ignored() {
    let mut m = machine_for(1, 4);
    assert!(m.step(BftEvent::Proposal(proposal(0, 0, 0, a(), None))).is_empty());
    assert!(m.step(BftEvent::Prevote(prevote(0, 0, 0, a()))).is_empty());
    assert!(m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Propose))).is_empty());
    assert_eq!(m.ignored(), 3);
}

#[test]
fn a_height_never_goes_backwards() {
    let mut m = machine_for(1, 4);
    m.step(BftEvent::NewHeight(5));
    assert!(m.step(BftEvent::NewHeight(5)).is_empty());
    assert!(m.step(BftEvent::NewHeight(4)).is_empty());
    assert_eq!(m.state().height, 5);
    assert_eq!(m.ignored(), 2);
}

// ---------------------------------------------------------------------------
// Proposals
// ---------------------------------------------------------------------------

#[test]
fn the_machine_prevotes_the_proposal_it_receives() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    let actions = m.step(BftEvent::Proposal(proposal(0, 0, 0, a(), None)));
    let votes = prevotes_in(&actions);
    assert_eq!(votes.len(), 1);
    assert_eq!(votes[0].validator, 3);
    assert_eq!(votes[0].vote.block_hash, a());
    assert_eq!(votes[0].verify(VoteKind::Prevote, &set(4)), Ok(()));
    assert_eq!(m.state().step, Step::Prevote);
}

#[test]
fn a_proposal_from_the_wrong_validator_is_ignored() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    // Validator 1 is not the proposer for (0, 0); validator 0 is.
    let actions = m.step(BftEvent::Proposal(proposal(1, 0, 0, a(), None)));
    assert!(actions.is_empty());
    assert_eq!(m.state().step, Step::Propose);
    assert_eq!(m.ignored(), 1);
}

#[test]
fn a_proposal_with_a_bad_signature_is_ignored() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    let mut forged = proposal(0, 0, 0, a(), None);
    forged.signature = Signature::from_bytes([0x33; 64]);
    assert!(m.step(BftEvent::Proposal(forged)).is_empty());
    assert_eq!(m.state().step, Step::Propose);
    assert_eq!(m.ignored(), 1);
}

#[test]
fn a_nil_proposal_is_ignored() {
    // Proposing "no block" would let a proposer manufacture a polka for
    // nothing, which is a free way to stall a height.
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    assert!(m.step(BftEvent::Proposal(proposal(0, 0, 0, NIL_BLOCK, None))).is_empty());
    assert_eq!(m.ignored(), 1);
}

#[test]
fn a_second_different_proposal_in_one_round_is_equivocation() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    m.step(BftEvent::Proposal(proposal(0, 0, 0, a(), None)));
    assert!(m.step(BftEvent::Proposal(proposal(0, 0, 0, b(), None))).is_empty());
    assert!(m.equivocators().contains(&0));
    // The first proposal is the one that stands.
    assert_eq!(m.state().step, Step::Prevote);
}

// ---------------------------------------------------------------------------
// Prevotes, polkas and locking
// ---------------------------------------------------------------------------

#[test]
fn a_polka_locks_and_precommits() {
    let m = locked_on_a();
    assert_eq!(m.state().locked_block, Some(a()));
    assert_eq!(m.state().locked_round, Some(0));
    assert_eq!(m.state().valid(), Some((0, a())));
    assert_eq!(m.state().step, Step::Precommit);
}

#[test]
fn a_polka_without_the_matching_proposal_does_not_lock() {
    // A polka names a hash. Locking on a block this node has never seen
    // proposed would let a lying quorum lock it onto nothing.
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Propose)));
    m.step(BftEvent::Prevote(prevote(0, 0, 0, b())));
    m.step(BftEvent::Prevote(prevote(1, 0, 0, b())));
    let actions = m.step(BftEvent::Prevote(prevote(2, 0, 0, b())));
    assert!(precommits_in(&actions).is_empty());
    assert_eq!(m.state().locked(), None);
}

#[test]
fn a_nil_polka_precommits_nil() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Propose)));
    m.step(BftEvent::Prevote(prevote(0, 0, 0, NIL_BLOCK)));
    m.step(BftEvent::Prevote(prevote(1, 0, 0, NIL_BLOCK)));
    let actions = m.step(BftEvent::Prevote(prevote(2, 0, 0, NIL_BLOCK)));
    let votes = precommits_in(&actions);
    assert_eq!(votes.len(), 1);
    assert!(votes[0].is_nil());
    assert_eq!(m.state().step, Step::Precommit);
    assert_eq!(m.state().locked(), None, "nil is never locked on");
}

#[test]
fn a_locked_validator_prevotes_nil_for_a_competing_block() {
    // THE locking rule. Without it, a validator that already precommitted `a`
    // could prevote `b` in the next round, and two quorums could form for two
    // different blocks at one height — a fork.
    let mut m = locked_on_a();
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Precommit)));
    assert_eq!(m.state().round, 1);

    let actions = m.step(BftEvent::Proposal(proposal(1, 0, 1, b(), None)));
    let votes = prevotes_in(&actions);
    assert_eq!(votes.len(), 1);
    assert!(votes[0].is_nil(), "a locked validator refuses a competing block");
    assert_eq!(m.state().locked(), Some((0, a())), "and stays locked");
}

#[test]
fn a_locked_validator_reprevotes_the_block_it_is_locked_on() {
    let mut m = locked_on_a();
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Precommit)));
    let actions = m.step(BftEvent::Proposal(proposal(1, 0, 1, a(), None)));
    let votes = prevotes_in(&actions);
    assert_eq!(votes.len(), 1);
    assert_eq!(votes[0].vote.block_hash, a());
}

#[test]
fn a_higher_round_polka_unlocks_the_validator() {
    // The other half of the rule: the lock is not permanent. A `2f+1` polka
    // for `b` at a round strictly greater than the locking round is proof that
    // a quorum moved on, so it is safe to follow.
    let mut m = locked_on_a();
    // Walk to round 2 the ordinary way.
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Precommit)));
    m.step(BftEvent::Timeout(Timeout::new(0, 1, TimeoutKind::Propose)));
    m.step(BftEvent::Timeout(Timeout::new(0, 1, TimeoutKind::Prevote)));
    m.step(BftEvent::Timeout(Timeout::new(0, 1, TimeoutKind::Precommit)));
    assert_eq!(m.state().round, 2);
    assert_eq!(m.state().locked(), Some((0, a())));

    // A genuine polka for `b`, at round 1 > the locking round 0.
    m.step(BftEvent::Prevote(prevote(0, 0, 1, b())));
    m.step(BftEvent::Prevote(prevote(1, 0, 1, b())));
    m.step(BftEvent::Prevote(prevote(2, 0, 1, b())));
    assert_eq!(m.state().locked(), Some((0, a())), "still locked until it prevotes");

    let actions = m.step(BftEvent::Proposal(proposal(2, 0, 2, b(), Some(1))));
    let votes = prevotes_in(&actions);
    assert_eq!(votes.len(), 1);
    assert_eq!(votes[0].vote.block_hash, b(), "the higher-round polka unlocks");
}

#[test]
fn a_proposal_claiming_a_polka_it_cannot_show_is_not_acted_on() {
    // `pol_round` is an unsigned hint. A receiver acts only on a polka it has
    // counted itself, so lying about it achieves nothing.
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Propose)));
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Prevote)));
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Precommit)));
    assert_eq!(m.state().round, 1);

    let actions = m.step(BftEvent::Proposal(proposal(1, 0, 1, b(), Some(0))));
    assert!(prevotes_in(&actions).is_empty(), "no polka at round 0 was ever counted");
    assert_eq!(m.state().step, Step::Propose, "the machine waits rather than guessing");
}

#[test]
fn a_proposal_claiming_a_polka_from_its_own_round_is_rejected() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Propose)));
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Prevote)));
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Precommit)));

    let before = m.ignored();
    let actions = m.step(BftEvent::Proposal(proposal(1, 0, 1, b(), Some(1))));
    assert!(prevotes_in(&actions).is_empty());
    assert!(m.ignored() > before, "a proof of lock from the current round is nonsense");
}

#[test]
fn an_equivocating_prevote_is_detected_and_the_first_vote_stands() {
    // Agreement is unaffected because the tally keeps the first vote: an
    // equivocator cannot move a block across the quorum line, it can only
    // withhold its own weight.
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    m.step(BftEvent::Proposal(proposal(0, 0, 0, a(), None)));
    m.step(BftEvent::Prevote(prevote(0, 0, 0, a())));
    m.step(BftEvent::Prevote(prevote(1, 0, 0, b())));

    let actions = m.step(BftEvent::Prevote(prevote(1, 0, 0, a())));
    assert!(actions.is_empty(), "the second vote changes nothing");
    assert!(m.equivocators().contains(&1));
    assert_eq!(m.state().votes.count(VoteKind::Prevote, 0, &b()), 1);
    assert_eq!(m.state().votes.count(VoteKind::Prevote, 0, &a()), 1);

    // Two honest votes are still not a quorum of three.
    m.step(BftEvent::Prevote(prevote(2, 0, 0, a())));
    assert_eq!(m.state().locked(), None);

    // The machine's own prevote, looped back by the driver, completes it.
    let actions = m.step(BftEvent::Prevote(prevote(3, 0, 0, a())));
    assert_eq!(precommits_in(&actions).len(), 1);
    assert_eq!(m.state().locked(), Some((0, a())));
}

#[test]
fn a_duplicate_vote_produces_no_actions() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    m.step(BftEvent::Prevote(prevote(0, 0, 0, a())));
    let before = m.ignored();
    assert!(m.step(BftEvent::Prevote(prevote(0, 0, 0, a()))).is_empty());
    assert!(m.ignored() > before);
    assert!(m.equivocators().is_empty(), "a repeat is not equivocation");
}

#[test]
fn a_vote_from_another_chain_is_ignored() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    let foreign = VoteMsg::new(ChainId::MAINNET, 0, 0, a());
    let signed = SignedVote::sign(&validator_key(0), 0, VoteKind::Prevote, foreign);
    assert!(m.step(BftEvent::Prevote(signed)).is_empty());
    assert_eq!(m.state().votes.total(VoteKind::Prevote, 0), 0);
    assert_eq!(m.ignored(), 1);
}

#[test]
fn a_vote_for_another_height_is_ignored() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    assert!(m.step(BftEvent::Prevote(prevote(0, 1, 0, a()))).is_empty());
    assert_eq!(m.ignored(), 1);
}

#[test]
fn a_vote_with_a_forged_signature_is_ignored() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    let mut forged = prevote(0, 0, 0, a());
    forged.signature = Signature::from_bytes([0x44; 64]);
    assert!(m.step(BftEvent::Prevote(forged)).is_empty());
    assert_eq!(m.state().votes.total(VoteKind::Prevote, 0), 0);
}

// ---------------------------------------------------------------------------
// Precommits and the decision
// ---------------------------------------------------------------------------

#[test]
fn a_quorum_of_precommits_decides() {
    // Deciding needs the certificate, not the block: the driver fetches the
    // block by hash, and `validate_seal` re-checks the quorum independently.
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    m.step(BftEvent::Precommit(precommit(0, 0, 0, a())));
    m.step(BftEvent::Precommit(precommit(1, 0, 0, a())));
    let actions = m.step(BftEvent::Precommit(precommit(2, 0, 0, a())));

    assert_eq!(decisions_in(&actions), vec![a()]);
    assert_eq!(m.state().step, Step::Commit);
}

#[test]
fn the_decision_certificate_is_ascending_and_verifies() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    for index in [2u16, 0, 1] {
        m.step(BftEvent::Precommit(precommit(index, 0, 0, a())));
    }
    let commit = m.decision().unwrap().clone();
    assert_eq!(commit.height, 0);
    assert_eq!(commit.round, 0);
    assert_eq!(commit.block_hash, a());
    assert_eq!(commit.signatures.len(), 3);
    let indices: Vec<u16> = commit.signatures.iter().map(|(i, _)| *i).collect();
    assert_eq!(indices, vec![0, 1, 2], "canonical order regardless of arrival order");
    assert_eq!(engine(4).verify_commit(&commit, &a(), 0), Ok(()));
}

#[test]
fn nil_precommits_never_decide() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    for index in 0..3u16 {
        let actions = m.step(BftEvent::Precommit(precommit(index, 0, 0, NIL_BLOCK)));
        assert!(decisions_in(&actions).is_empty());
    }
    assert!(m.decision().is_none());
    assert_ne!(m.state().step, Step::Commit);
}

#[test]
fn a_decided_machine_ignores_further_timeouts() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    for index in 0..3u16 {
        m.step(BftEvent::Precommit(precommit(index, 0, 0, a())));
    }
    assert_eq!(m.state().step, Step::Commit);
    let actions = m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Precommit)));
    assert!(actions.is_empty());
    assert_eq!(m.state().round, 0, "a decided height does not start another round");
}

// ---------------------------------------------------------------------------
// Timeouts and round advance
// ---------------------------------------------------------------------------

#[test]
fn the_propose_timeout_prevotes_nil() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    let actions = m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Propose)));
    let votes = prevotes_in(&actions);
    assert_eq!(votes.len(), 1);
    assert!(votes[0].is_nil());
    assert_eq!(m.state().step, Step::Prevote);
}

#[test]
fn the_prevote_timeout_precommits_nil() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Propose)));
    let actions = m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Prevote)));
    let votes = precommits_in(&actions);
    assert_eq!(votes.len(), 1);
    assert!(votes[0].is_nil());
    assert_eq!(m.state().step, Step::Precommit);
}

#[test]
fn the_precommit_timeout_advances_the_round_and_rotates_the_proposer() {
    let mut m = machine_for(1, 4);
    m.set_candidate(0, a());
    let actions = m.step(BftEvent::NewHeight(0));
    assert!(proposals_in(&actions).is_empty(), "validator 0 proposes round 0");

    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Propose)));
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Prevote)));
    let actions = m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Precommit)));

    assert_eq!(m.state().round, 1);
    assert_eq!(m.state().step, Step::Propose);
    let proposals = proposals_in(&actions);
    assert_eq!(proposals.len(), 1, "validator 1 proposes round 1");
    assert_eq!(proposals[0].proposer, 1);
    assert_eq!(proposals[0].round, 1);
}

#[test]
fn timeout_delays_double_with_the_round() {
    let mut m = machine_for(3, 4);
    let actions = m.step(BftEvent::NewHeight(0));
    assert_eq!(timeouts_in(&actions)[0].1, DEFAULT_PROPOSE_TIMEOUT);

    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Propose)));
    m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Prevote)));
    let actions = m.step(BftEvent::Timeout(Timeout::new(0, 0, TimeoutKind::Precommit)));
    let armed = timeouts_in(&actions);
    assert_eq!(armed.len(), 1);
    assert_eq!(armed[0].0.round, 1);
    assert_eq!(armed[0].1, DEFAULT_PROPOSE_TIMEOUT * 2);
    assert_eq!(armed[0].1, Duration::from_millis(6_000));
}

#[test]
fn a_stale_timeout_is_ignored() {
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    assert!(m.step(BftEvent::Timeout(Timeout::new(0, 7, TimeoutKind::Propose))).is_empty());
    assert!(m.step(BftEvent::Timeout(Timeout::new(3, 0, TimeoutKind::Propose))).is_empty());
    assert_eq!(m.state().step, Step::Propose);
    assert_eq!(m.ignored(), 2);
}

#[test]
fn f_plus_one_votes_from_a_later_round_skip_ahead() {
    // One of `f+1` validators is honest, so the later round is real and this
    // node is behind. Catching up is what stops a slow node from stalling.
    let mut m = machine_for(0, 4);
    m.step(BftEvent::NewHeight(0));
    m.step(BftEvent::Prevote(prevote(1, 0, 3, b())));
    assert_eq!(m.state().round, 0, "one message is not evidence");

    let actions = m.step(BftEvent::Prevote(prevote(2, 0, 3, b())));
    assert_eq!(m.state().round, 3, "f + 1 = 2 validators are already at round 3");
    let armed = timeouts_in(&actions);
    assert_eq!(armed[0].0, Timeout::new(0, 3, TimeoutKind::Propose));
    assert_eq!(armed[0].1, DEFAULT_PROPOSE_TIMEOUT * 8);
}

#[test]
fn a_new_height_clears_the_lock() {
    // Locks are per height. Carrying one forward would lock a validator onto a
    // block that has already been committed and superseded.
    let mut m = locked_on_a();
    m.step(BftEvent::NewHeight(1));
    assert_eq!(m.state().height, 1);
    assert_eq!(m.state().round, 0);
    assert_eq!(m.state().step, Step::Propose);
    assert_eq!(m.state().locked(), None);
    assert_eq!(m.state().valid(), None);
    assert_eq!(m.state().votes.total(VoteKind::Prevote, 0), 0);
    assert!(m.decision().is_none());
}

#[test]
fn an_observer_without_a_key_tallies_but_never_broadcasts() {
    // A full node follows consensus without voting: it decides with everyone
    // else and emits nothing.
    let mut m = BftMachine::new(ChainId::DEVNET, set(4), None, TimeoutConfig::default());
    assert_eq!(m.own_index(), None);
    assert!(!m.is_proposer(0, 0));

    let actions = m.step(BftEvent::NewHeight(0));
    assert!(proposals_in(&actions).is_empty());
    m.step(BftEvent::Proposal(proposal(0, 0, 0, a(), None)));
    assert_eq!(m.state().step, Step::Prevote, "it still follows the round");
    assert!(prevotes_in(&m.step(BftEvent::Prevote(prevote(0, 0, 0, a())))).is_empty());

    for index in 0..3u16 {
        m.step(BftEvent::Precommit(precommit(index, 0, 0, a())));
    }
    assert_eq!(m.decision().map(|c| c.block_hash), Some(a()));
}

#[test]
fn quorum_and_fault_tolerance_are_visible_on_the_machine() {
    let m = machine_for(0, 7);
    assert_eq!(m.quorum(), 5);
    assert_eq!(m.fault_tolerance(), 2);
    assert_eq!(m.validators().len(), 7);
    assert_eq!(m.own_index(), Some(0));
}

// ---------------------------------------------------------------------------
// `pol_round` is a signed control input, not a hint
// ---------------------------------------------------------------------------

#[test]
fn a_relayed_proposal_with_a_mutated_pol_round_is_rejected() {
    // `pol_round` selects which of rules 2 and 3 runs, so it is a control
    // input, not a hint. If it is outside the signed preimage, any relay
    // holding no validator key at all can flip it on a genuine proposal, and
    // the poisoned copy still verifies. `on_proposal` keeps the first copy it
    // sees for a round for ever, so the poisoned one is the one every rule is
    // evaluated against — and `vr >= round` makes the node prevote nothing at
    // all. Repeated every round, that halts the chain with zero keys.
    let genuine = proposal(0, 0, 0, a(), None);
    assert_eq!(genuine.verify(ChainId::DEVNET, &set(4)), Ok(()));

    let mut poisoned = genuine;
    poisoned.pol_round = Some(0);
    assert!(
        poisoned.verify(ChainId::DEVNET, &set(4)).is_err(),
        "a proposal signature must cover pol_round"
    );

    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));
    let before = m.ignored();
    assert!(m.step(BftEvent::Proposal(poisoned)).is_empty(), "the forgery must not be acted on");
    assert!(m.ignored() > before);
    assert_eq!(m.state().step, Step::Propose);

    // And it must not have squatted the round's proposal slot: the genuine
    // copy arriving second is still the one prevoted.
    let actions = m.step(BftEvent::Proposal(genuine));
    let votes = prevotes_in(&actions);
    assert_eq!(votes.len(), 1);
    assert_eq!(votes[0].vote.block_hash, a(), "the genuine proposal still wins the round");
}

#[test]
fn a_stripped_pol_round_cannot_downgrade_a_reproposal() {
    // The same primitive in the other direction: strip `Some(vr)` to `None` on
    // a re-proposal and every locked validator takes the rule-2 branch and
    // prevotes nil for a block it would otherwise have unlocked onto.
    let genuine = proposal(2, 0, 2, b(), Some(1));
    assert_eq!(genuine.verify(ChainId::DEVNET, &set(4)), Ok(()));

    let mut downgraded = genuine;
    downgraded.pol_round = None;
    assert!(
        downgraded.verify(ChainId::DEVNET, &set(4)).is_err(),
        "stripping the proof-of-lock round must break the signature"
    );
}

// ---------------------------------------------------------------------------
// The round window
// ---------------------------------------------------------------------------

#[test]
fn votes_for_a_far_future_round_are_ignored() {
    // A vote's round is unconstrained attacker input, and every accepted round
    // becomes a live `RoundVotes` bucket that `decided()` and `skip_round()`
    // rescan on every later event. One Byzantine validator signing a nil
    // precommit at each of a hundred thousand rounds is ~11 MB of perfectly
    // valid traffic that costs every honest node quadratic CPU and unbounded
    // memory. Rule 12 only ever advances to the *lowest* qualifying round, so
    // a bounded window above the current round is all it needs.
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));

    let before = m.ignored();
    assert!(m.step(BftEvent::Prevote(prevote(0, 0, 100_000, a()))).is_empty());
    assert!(m.step(BftEvent::Precommit(precommit(0, 0, u32::MAX, a()))).is_empty());
    assert_eq!(m.ignored(), before + 2, "both are dropped, not buffered");
    assert_eq!(m.state().votes.total(VoteKind::Prevote, 100_000), 0);
    assert_eq!(m.state().votes.total(VoteKind::Precommit, u32::MAX), 0);
}

#[test]
fn a_proposal_for_a_far_future_round_is_ignored() {
    // Same bucket-seeding attack through `self.proposals`, which is keyed by
    // round and equally unbounded.
    let mut m = machine_for(3, 4);
    m.step(BftEvent::NewHeight(0));

    let far = 100_000u32;
    let proposer = set(4).proposer_index(0, far);
    let before = m.ignored();
    assert!(m.step(BftEvent::Proposal(proposal(proposer, 0, far, a(), None))).is_empty());
    assert_eq!(m.ignored(), before + 1, "an unreachable round is not cached");
}

#[test]
fn the_round_window_still_lets_a_behind_node_catch_up() {
    // The bound must not cost liveness. Rule 12 only ever jumps to the lowest
    // round above the current one that `f+1` validators are in, so the window
    // has to be wide enough to see them — and it moves forward with the round,
    // so a node caught up to the edge can immediately see the next window.
    let mut m = machine_for(0, 4);
    m.step(BftEvent::NewHeight(0));

    let edge = MAX_ROUND_LOOKAHEAD;
    m.step(BftEvent::Prevote(prevote(1, 0, edge, b())));
    assert_eq!(m.state().votes.total(VoteKind::Prevote, edge), 1, "the far edge is admissible");
    m.step(BftEvent::Prevote(prevote(2, 0, edge, b())));
    assert_eq!(m.state().round, edge, "f + 1 validators at the edge still pull us over");

    let next_edge = edge.saturating_mul(2);
    m.step(BftEvent::Prevote(prevote(1, 0, next_edge, b())));
    assert_eq!(
        m.state().votes.total(VoteKind::Prevote, next_edge),
        1,
        "the window travels with the round"
    );
}

#[test]
fn skip_round_merges_both_vote_kinds_and_takes_the_lowest() {
    // Rule 12 needs the *lowest* round above the current one that `f+1`
    // distinct validators are in, counting a validator once even when it is
    // heard in both steps. This walks the prevote and precommit maps together
    // rather than collecting every round into a fresh set on each call, so it
    // is worth pinning every branch of the merge.
    let mut t = VoteTally::new();
    let sig = Signature::from_bytes([0x01; 64]);

    t.add(VoteKind::Prevote, 9, 0, hash(1), sig);
    t.add(VoteKind::Precommit, 9, 1, hash(1), sig);
    assert_eq!(t.skip_round(0, 2), Some(9), "two validators, split across the steps");

    t.add(VoteKind::Prevote, 5, 2, hash(1), sig);
    t.add(VoteKind::Precommit, 5, 2, hash(1), sig);
    assert_eq!(t.skip_round(0, 2), Some(9), "one validator in two steps is one voter");

    t.add(VoteKind::Precommit, 5, 3, hash(1), sig);
    assert_eq!(t.skip_round(0, 2), Some(5), "and 5 is lower than 9");

    assert_eq!(t.skip_round(5, 2), Some(9), "`current` is exclusive");
    assert_eq!(t.skip_round(9, 2), None, "nothing above the highest round");
    assert_eq!(t.skip_round(0, 3), None, "no round reaches a threshold of three");

    // A round present in only one of the two maps is still found.
    t.add(VoteKind::Prevote, 7, 0, hash(1), sig);
    t.add(VoteKind::Prevote, 7, 1, hash(1), sig);
    assert_eq!(t.skip_round(5, 2), Some(7));

    t.add(VoteKind::Prevote, 11, 0, hash(1), sig);
    t.add(VoteKind::Prevote, 11, 1, hash(1), sig);
    assert_eq!(t.skip_round(9, 2), Some(11), "prevotes past the last precommit round");

    t.add(VoteKind::Precommit, 13, 0, hash(1), sig);
    t.add(VoteKind::Precommit, 13, 1, hash(1), sig);
    assert_eq!(t.skip_round(11, 2), Some(13), "precommits past the last prevote round");
}
