#![allow(clippy::unwrap_used)]

use ferrum_consensus::ConsensusError;
use ferrum_script::ScriptError;
use ferrum_storage::StorageError;
use ferrum_types::{Amount, OutPoint};

use super::*;

fn hash(b: u8) -> BlockHash {
    BlockHash(ferrum_types::Hash32::from_bytes([b; 32]))
}

#[test]
fn verdicts_map_onto_the_libp2p_values() {
    assert!(matches!(GossipVerdict::Accept.acceptance(), MessageAcceptance::Accept));
    assert!(matches!(GossipVerdict::Reject.acceptance(), MessageAcceptance::Reject));
    assert!(matches!(GossipVerdict::Ignore.acceptance(), MessageAcceptance::Ignore));
    assert_eq!(GossipVerdict::Reject.name(), "reject");
}

#[test]
fn a_block_that_joined_the_chain_is_accepted() {
    for outcome in [
        AcceptOutcome::Extended(hash(1)),
        AcceptOutcome::SideChain(hash(2)),
        AcceptOutcome::Reorged {
            from: hash(1),
            to: hash(2),
            disconnected: vec![hash(1)],
            connected: vec![hash(2)],
        },
    ] {
        assert_eq!(block_verdict(&Ok(outcome)), GossipVerdict::Accept);
    }
}

#[test]
fn a_duplicate_or_an_orphan_is_ignored_never_rejected() {
    // Neither says anything about the sender.
    assert_eq!(block_verdict(&Ok(AcceptOutcome::Duplicate)), GossipVerdict::Ignore);
    assert_eq!(block_verdict(&Ok(AcceptOutcome::Orphan)), GossipVerdict::Ignore);
}

#[test]
fn a_consensus_invalid_block_is_rejected_so_the_sender_is_scored() {
    let invalid: Result<AcceptOutcome, ChainError> =
        Err(ChainError::Consensus(ConsensusError::ZeroTarget));
    assert_eq!(block_verdict(&invalid), GossipVerdict::Reject);
    assert_eq!(
        block_rejection(&ChainError::Consensus(ConsensusError::ZeroTarget)),
        BlockRejection::Invalid
    );

    let known: Result<AcceptOutcome, ChainError> = Err(ChainError::KnownInvalid(hash(3)));
    assert_eq!(block_verdict(&known), GossipVerdict::Reject);
}

#[test]
fn our_own_storage_failure_never_scores_the_sender() {
    let ours: Result<AcceptOutcome, ChainError> = Err(ChainError::NoTip);
    assert_eq!(block_verdict(&ours), GossipVerdict::Ignore);
    assert_eq!(block_rejection(&ChainError::NoTip), BlockRejection::Transient);

    let disk: Result<AcceptOutcome, ChainError> = Err(ChainError::Storage(StorageError::NoTip));
    assert_eq!(block_verdict(&disk), GossipVerdict::Ignore);
}

#[test]
fn a_reorg_the_engine_refuses_is_not_the_senders_fault() {
    let e = ChainError::ReorgBelowFinalized { fork_height: 5, finalized_height: 9 };
    assert_eq!(block_rejection(&e), BlockRejection::Transient);
    assert_eq!(block_verdict(&Err(e)), GossipVerdict::Ignore);
}

#[test]
fn an_accepted_transaction_is_accepted() {
    let ok = Ok(AcceptResult::Accepted {
        txid: Txid(ferrum_types::Hash32::ZERO),
        fee: Amount::ZERO,
        fee_rate: 0,
        size: 1,
        promoted: Vec::new(),
        evicted: Vec::new(),
    });
    assert_eq!(tx_verdict(&ok), GossipVerdict::Accept);
}

#[test]
fn a_held_or_duplicate_transaction_is_ignored() {
    let id = Txid(ferrum_types::Hash32::ZERO);
    assert_eq!(tx_verdict(&Ok(AcceptResult::AlreadyInPool { txid: id })), GossipVerdict::Ignore);
    assert_eq!(
        tx_verdict(&Ok(AcceptResult::Orphan { txid: id, missing: Vec::new() })),
        GossipVerdict::Ignore
    );
}

#[test]
fn a_policy_refusal_never_lowers_a_peers_score() {
    // SPEC 10: a block containing a transaction our mempool refused is
    // still valid, so the peer that relayed it did nothing wrong.
    for e in [
        MempoolError::FeeTooLow { fee_rate: 1, min: 1_000 },
        MempoolError::NonStandardOutput { vout: 0 },
        MempoolError::TooLarge { size: 200_000, max: 100_000 },
        MempoolError::PoolFull { size_bytes: 10, max_bytes: 10 },
        MempoolError::Conflict {
            out_point: OutPoint::NULL,
            existing: Txid(ferrum_types::Hash32::ZERO),
        },
        MempoolError::NonFinal { lock_time: 500, height: 1 },
        MempoolError::View { detail: "disk".to_owned() },
    ] {
        assert!(!is_consensus_invalid(&e), "{e} is policy, not consensus");
        assert_eq!(tx_verdict(&Err(e)), GossipVerdict::Ignore);
    }
}

#[test]
fn a_transaction_nobody_can_mine_is_rejected() {
    for e in [
        MempoolError::Coinbase,
        MempoolError::NonPushOnlyScriptSig { input_index: 0 },
        MempoolError::ScriptVerification {
            input_index: 0,
            source: ScriptError::CleanStack { size: 2 },
        },
        MempoolError::InputSumOverflow,
        MempoolError::InsufficientInputValue {
            inputs: Amount::ZERO,
            outputs: Amount::from_grains(1),
        },
    ] {
        assert!(is_consensus_invalid(&e), "{e} can never be mined");
        assert_eq!(tx_verdict(&Err(e)), GossipVerdict::Reject);
    }
}

#[test]
fn a_transient_mempool_failure_is_ignored() {
    let e = MempoolError::view(&StorageError::NoTip);
    assert!(e.is_transient());
    assert_eq!(tx_verdict(&Err(e)), GossipVerdict::Ignore);
}

#[test]
fn the_fixed_clock_moves_when_told_to() {
    let c = FixedClock::new(1_000);
    assert_eq!(c.now_ms(), 1_000);
    c.set(2_000);
    assert_eq!(c.now_ms(), 2_000);
}

#[test]
fn the_system_clock_is_after_2020() {
    assert!(SystemClock.now_ms() > 1_577_836_800_000);
}
