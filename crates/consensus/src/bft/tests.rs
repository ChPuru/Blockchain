//! Tests for the BFT engine, its commit certificates and its signing
//! digests.
//!
//! Split out of `mod.rs` so that the production module stays readable; the
//! `#![allow]`s below are the usual test-only relaxations.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use super::tests_support::{validator_ids, validator_key};
use super::*;
use crate::engine::block_hash;
use crate::testview::TestView;

fn params(n: usize) -> ChainParams {
    let mut p = ChainParams::devnet();
    p.bft_activation_height = Some(0);
    p.bft_validators = validator_ids(n);
    p
}

fn engine(n: usize) -> BftEngine {
    BftEngine::new(params(n), None).unwrap()
}

fn vote(n: usize) -> VoteMsg {
    VoteMsg::new(params(n).chain_id, 7, 2, BlockHash::from_bytes([9; 32]))
}

/// A commit signed by validators `indices`, over `(height, round, hash)`.
fn commit_signed_by(
    p: &ChainParams,
    indices: &[u16],
    height: u64,
    round: u32,
    hash: BlockHash,
) -> BftCommit {
    let v = VoteMsg::new(p.chain_id, height, round, hash);
    let digest = precommit_digest(&v);
    let signatures = indices
        .iter()
        .map(|i| (*i, validator_key(usize::from(*i)).sign_deterministic(&digest)))
        .collect();
    BftCommit::new(height, round, hash, signatures)
}

#[test]
fn vote_encoding_is_forty_eight_frozen_bytes() {
    let v = VoteMsg::new(
        ChainId(3),
        0x0102_0304_0506_0708,
        0x0a0b_0c0d,
        BlockHash::from_bytes([0xee; 32]),
    );
    let bytes = v.signing_bytes();
    assert_eq!(bytes.len(), VOTE_MSG_SIZE);
    assert_eq!(&bytes[0..4], &3u32.to_le_bytes(), "chain_id first, little-endian");
    assert_eq!(&bytes[4..12], &0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(&bytes[12..16], &0x0a0b_0c0du32.to_le_bytes());
    assert_eq!(&bytes[16..48], &[0xee; 32]);
    assert_eq!(borsh::from_slice::<VoteMsg>(&bytes).unwrap(), v);
}

#[test]
fn the_three_vote_digests_are_domain_separated() {
    let v = vote(4);
    let p = proposal_digest(&v);
    let pre = prevote_digest(&v);
    let com = precommit_digest(&v);
    assert_ne!(p, pre);
    assert_ne!(pre, com);
    assert_ne!(p, com);
    // The precommit digest is exactly what the contract specifies.
    assert_eq!(com, tagged_hash(TAG_BFT_PRECOMMIT, &borsh::to_vec(&v).unwrap()));
}

#[test]
fn the_chain_id_is_inside_every_digest() {
    let a = VoteMsg::new(ChainId(1), 5, 0, BlockHash::from_bytes([1; 32]));
    let b = VoteMsg::new(ChainId(2), 5, 0, BlockHash::from_bytes([1; 32]));
    assert_ne!(precommit_digest(&a), precommit_digest(&b), "cross-chain replay must be impossible");
}

#[test]
fn the_round_is_inside_every_digest() {
    let a = VoteMsg::new(ChainId(3), 5, 0, BlockHash::from_bytes([1; 32]));
    let b = VoteMsg::new(ChainId(3), 5, 1, BlockHash::from_bytes([1; 32]));
    assert_ne!(
        precommit_digest(&a),
        precommit_digest(&b),
        "a vote must not be replayable across rounds"
    );
}

#[test]
fn a_commit_round_trips_through_its_seal() {
    let p = params(4);
    let c = commit_signed_by(&p, &[0, 1, 2], 7, 1, BlockHash::from_bytes([4; 32]));
    let seal = c.to_seal();
    assert_eq!(seal.engine, BlockSeal::ENGINE_BFT);
    assert_eq!(BftCommit::decode(&seal.data).unwrap(), c);
    assert_eq!(c.vote(p.chain_id), VoteMsg::new(p.chain_id, 7, 1, c.block_hash));
}

#[test]
fn a_commit_with_trailing_bytes_is_rejected() {
    let p = params(4);
    let c = commit_signed_by(&p, &[0, 1, 2], 7, 1, BlockHash::from_bytes([4; 32]));
    let mut bytes = c.encode();
    bytes.push(0);
    assert!(matches!(BftCommit::decode(&bytes), Err(ConsensusError::MalformedSeal(_))));
    assert!(matches!(BftCommit::decode(&[]), Err(ConsensusError::MalformedSeal(_))));
}

#[test]
fn quorum_arithmetic_matches_the_contract() {
    for (n, f, q) in
        [(4usize, 1usize, 3usize), (5, 1, 3), (6, 1, 3), (7, 2, 5), (10, 3, 7), (64, 21, 43)]
    {
        let e = engine(n);
        assert_eq!(e.validator_count(), n);
        assert_eq!(e.fault_tolerance(), f, "n = {n}");
        assert_eq!(e.quorum(), q, "n = {n}");
        // A quorum always contains more honest members than faulty ones,
        // even when every faulty member is inside it.
        assert!(q.saturating_sub(f) > f, "n = {n}: honest quorum must outweigh f");
    }
}

#[test]
fn quorum_intersection_holds_for_every_set_size_except_six() {
    // Two quorums must overlap, or two conflicting commits could both be
    // valid at one height. With f = (n-1)/3 that holds everywhere except
    // n = 6, which is why the contract's `n = 3f + 1` shape matters.
    for n in MIN_VALIDATORS..=32 {
        let e = engine(n);
        if n == 6 {
            assert!(!e.has_quorum_intersection(), "n = 6 is the known degenerate case");
            assert_eq!(e.quorum().saturating_mul(2), n);
        } else {
            assert!(e.has_quorum_intersection(), "n = {n} must have quorum intersection");
        }
    }
    for n in [4usize, 7, 10, 13, 16] {
        let e = engine(n);
        assert_eq!(e.validator_count(), e.fault_tolerance().saturating_mul(3).saturating_add(1));
        assert!(e.has_quorum_intersection());
    }
}

#[test]
fn a_set_below_four_is_refused() {
    for n in 0..MIN_VALIDATORS {
        let mut p = ChainParams::devnet();
        p.bft_validators = validator_ids(n);
        assert_eq!(
            BftEngine::new(p, None).err(),
            Some(ConsensusError::ValidatorSetTooSmall { actual: n, minimum: 4 })
        );
    }
}

#[test]
fn a_duplicated_validator_is_refused() {
    let mut p = ChainParams::devnet();
    let mut set = validator_ids(4);
    set[3] = set[0];
    p.bft_validators = set.clone();
    assert_eq!(
        BftEngine::new(p, None).err(),
        Some(ConsensusError::DuplicateValidator(set[0].to_hex()))
    );
}

#[test]
fn an_off_curve_validator_key_is_refused() {
    let mut p = ChainParams::devnet();
    let mut set = validator_ids(4);
    // The field modulus itself is not a valid x coordinate.
    set[2] = ValidatorId::from_bytes([0xff; 32]);
    p.bft_validators = set;
    match BftEngine::new(p, None) {
        Err(ConsensusError::InvalidValidatorKey { index, .. }) => assert_eq!(index, 2),
        other => panic!("expected InvalidValidatorKey, got {other:?}"),
    }
}

#[test]
fn the_proposer_schedule_is_round_robin_over_height_and_round() {
    let e = engine(4);
    let v = e.validators().to_vec();
    assert_eq!(e.proposer(0, 0), v[0]);
    assert_eq!(e.proposer(1, 0), v[1]);
    assert_eq!(e.proposer(2, 0), v[2]);
    assert_eq!(e.proposer(3, 0), v[3]);
    assert_eq!(e.proposer(4, 0), v[0], "wraps at n");
    assert_eq!(e.proposer(0, 1), v[1], "a new round steps over the last proposer");
    assert_eq!(e.proposer(0, 4), v[0]);
    assert_eq!(
        e.proposer(u64::MAX, u32::MAX),
        v[(u128::from(u64::MAX) + u128::from(u32::MAX)) as usize % 4]
    );
}

#[test]
fn every_validator_proposes_equally_often() {
    let e = engine(7);
    let mut counts = [0usize; 7];
    for height in 0..7_000u64 {
        let p = e.proposer(height, 0);
        let idx = usize::from(e.validator_index(&p).unwrap());
        counts[idx] += 1;
    }
    assert_eq!(counts, [1_000; 7]);
}

#[test]
fn timeouts_double_each_round() {
    let base = Duration::from_millis(1_000);
    assert_eq!(BftEngine::timeout_for_round(base, 0), Duration::from_millis(1_000));
    assert_eq!(BftEngine::timeout_for_round(base, 1), Duration::from_millis(2_000));
    assert_eq!(BftEngine::timeout_for_round(base, 2), Duration::from_millis(4_000));
    assert_eq!(BftEngine::timeout_for_round(base, 10), Duration::from_millis(1_024_000));
    // And they saturate instead of wrapping to a zero timeout, which would
    // spin the round machine at full speed.
    assert_eq!(BftEngine::timeout_for_round(base, u32::MAX), Duration::from_millis(u64::MAX));
    assert_eq!(BftEngine::timeout_for_round(Duration::ZERO, 5), Duration::ZERO);
}

#[test]
fn default_timeouts_are_present() {
    assert_eq!(DEFAULT_PROPOSE_TIMEOUT, Duration::from_millis(3_000));
    assert_eq!(DEFAULT_PREVOTE_TIMEOUT, Duration::from_millis(1_000));
    assert_eq!(DEFAULT_PRECOMMIT_TIMEOUT, Duration::from_millis(1_000));
}

#[test]
fn a_quorum_of_valid_signatures_verifies() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let hash = BlockHash::from_bytes([0x11; 32]);
    let c = commit_signed_by(&p, &[0, 1, 2], 12, 0, hash);
    assert_eq!(e.verify_commit(&c, &hash, 12), Ok(()));
}

#[test]
fn all_four_signatures_also_verify() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let hash = BlockHash::from_bytes([0x11; 32]);
    let c = commit_signed_by(&p, &[0, 1, 2, 3], 12, 0, hash);
    assert_eq!(e.verify_commit(&c, &hash, 12), Ok(()));
}

#[test]
fn one_signature_short_of_quorum_is_refused() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let hash = BlockHash::from_bytes([0x11; 32]);
    let c = commit_signed_by(&p, &[0, 1], 12, 0, hash);
    assert_eq!(
        e.verify_commit(&c, &hash, 12),
        Err(ConsensusError::QuorumNotReached { have: 2, need: 3 })
    );
}

#[test]
fn killing_one_of_four_validators_still_reaches_quorum_but_two_halts() {
    // This is the operational promise in RUNNING.md, asserted.
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let hash = BlockHash::from_bytes([0x22; 32]);
    assert_eq!(e.verify_commit(&commit_signed_by(&p, &[0, 1, 2], 1, 0, hash), &hash, 1), Ok(()));
    assert!(e.verify_commit(&commit_signed_by(&p, &[0, 1], 1, 0, hash), &hash, 1).is_err());
}

#[test]
fn a_duplicated_validator_index_cannot_fill_a_quorum() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let hash = BlockHash::from_bytes([0x11; 32]);
    let mut c = commit_signed_by(&p, &[0], 12, 0, hash);
    let sig = c.signatures[0].1;
    c.signatures = vec![(0, sig), (0, sig), (0, sig)];
    assert_eq!(e.verify_commit(&c, &hash, 12), Err(ConsensusError::UnorderedCommitSignatures(1)));
}

#[test]
fn out_of_order_signatures_are_refused() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let hash = BlockHash::from_bytes([0x11; 32]);
    let mut c = commit_signed_by(&p, &[0, 1, 2], 12, 0, hash);
    c.signatures.swap(0, 1);
    assert_eq!(e.verify_commit(&c, &hash, 12), Err(ConsensusError::UnorderedCommitSignatures(1)));
}

#[test]
fn a_validator_index_outside_the_set_is_refused() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let hash = BlockHash::from_bytes([0x11; 32]);
    let mut c = commit_signed_by(&p, &[0, 1, 2], 12, 0, hash);
    c.signatures[2].0 = 9;
    assert_eq!(
        e.verify_commit(&c, &hash, 12),
        Err(ConsensusError::ValidatorIndexOutOfRange { index: 9, size: 4 })
    );
}

#[test]
fn a_forged_signature_is_refused() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let hash = BlockHash::from_bytes([0x11; 32]);
    let mut c = commit_signed_by(&p, &[0, 1, 2], 12, 0, hash);
    c.signatures[1].1 = Signature::from_bytes([0x77; 64]);
    match e.verify_commit(&c, &hash, 12) {
        Err(ConsensusError::BadCommitSignature { index, .. }) => assert_eq!(index, 1),
        other => panic!("expected BadCommitSignature, got {other:?}"),
    }
}

#[test]
fn a_signature_by_the_wrong_validator_is_refused() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let hash = BlockHash::from_bytes([0x11; 32]);
    let mut c = commit_signed_by(&p, &[0, 1, 2], 12, 0, hash);
    // Validator 3's signature filed under index 2.
    let digest = precommit_digest(&c.vote(p.chain_id));
    c.signatures[2].1 = validator_key(3).sign_deterministic(&digest);
    match e.verify_commit(&c, &hash, 12) {
        Err(ConsensusError::BadCommitSignature { index, .. }) => assert_eq!(index, 2),
        other => panic!("expected BadCommitSignature, got {other:?}"),
    }
}

#[test]
fn a_commit_for_another_block_or_height_is_refused() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let hash = BlockHash::from_bytes([0x11; 32]);
    let other = BlockHash::from_bytes([0x12; 32]);
    let c = commit_signed_by(&p, &[0, 1, 2], 12, 0, hash);

    assert_eq!(
        e.verify_commit(&c, &other, 12),
        Err(ConsensusError::CommitMismatch {
            actual: hash,
            actual_height: 12,
            expected: other,
            expected_height: 12,
        })
    );
    assert!(matches!(e.verify_commit(&c, &hash, 13), Err(ConsensusError::CommitMismatch { .. })));
}

#[test]
fn a_commit_from_another_chain_is_refused() {
    let mut testnet = params(4);
    testnet.chain_id = ChainId::TESTNET;
    let hash = BlockHash::from_bytes([0x11; 32]);
    let c = commit_signed_by(&testnet, &[0, 1, 2], 12, 0, hash);

    // Same signatures, same block, replayed on devnet.
    let devnet = BftEngine::new(params(4), None).unwrap();
    match devnet.verify_commit(&c, &hash, 12) {
        Err(ConsensusError::BadCommitSignature { index, .. }) => assert_eq!(index, 0),
        other => panic!("expected a cross-chain replay to fail, got {other:?}"),
    }
}

#[test]
fn a_commit_from_another_round_is_refused() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let hash = BlockHash::from_bytes([0x11; 32]);
    let mut c = commit_signed_by(&p, &[0, 1, 2], 12, 0, hash);
    c.round = 1; // signatures still cover round 0
    match e.verify_commit(&c, &hash, 12) {
        Err(ConsensusError::BadCommitSignature { index, .. }) => assert_eq!(index, 0),
        other => panic!("expected a cross-round replay to fail, got {other:?}"),
    }
}

#[test]
fn an_empty_commit_is_refused_as_a_short_quorum() {
    let p = params(4);
    let e = BftEngine::new(p, None).unwrap();
    let hash = BlockHash::from_bytes([0x11; 32]);
    let c = BftCommit::new(12, 0, hash, Vec::new());
    assert_eq!(
        e.verify_commit(&c, &hash, 12),
        Err(ConsensusError::QuorumNotReached { have: 0, need: 3 })
    );
}

#[test]
fn signing_needs_a_validator_key() {
    let e = engine(4);
    assert_eq!(e.sign_precommit(&vote(4)), Err(ConsensusError::EngineUnavailable));
    assert_eq!(e.own_index(), None);
    assert!(!e.is_proposer(0, 0));

    let signer = BftEngine::new(params(4), Some(validator_key(2))).unwrap();
    assert_eq!(signer.own_index(), Some(2));
    assert!(signer.is_proposer(2, 0));
    assert!(!signer.is_proposer(3, 0));
    let sig = signer.sign_precommit(&vote(4)).unwrap();
    let key = validator_key(2).public_key();
    assert!(key.verify(&precommit_digest(&vote(4)), &sig).is_ok());
}

#[test]
fn a_node_signing_with_a_key_outside_the_set_has_no_index() {
    let outsider = validator_key(50);
    let e = BftEngine::new(params(4), Some(outsider)).unwrap();
    assert_eq!(e.own_index(), None);
    assert!(!e.is_proposer(0, 0));
}

#[test]
fn engine_identity_matches_the_contract() {
    let e = engine(4);
    assert_eq!(e.name(), "bft");
    assert_eq!(e.engine_id(), BlockSeal::ENGINE_BFT);
    assert_eq!(e.params().chain_id, ChainParams::devnet().chain_id);
    assert_eq!(e.validators().len(), 4);
}

#[test]
fn every_block_contributes_exactly_one_unit_of_work() {
    let e = engine(4);
    assert_eq!(e.work(&BlockHeader::default()), Work::ONE);
    assert_eq!(
        e.work(&BlockHeader { bits: CompactTarget(0x1d00_ffff), ..BlockHeader::default() }),
        Work::ONE
    );
}

#[test]
fn the_round_machine_reports_itself_unavailable_rather_than_accepting() {
    let e = engine(4);
    let view = TestView::devnet();
    let header = BlockHeader::default();
    let block = Block::new(header, Vec::new(), BlockSeal::bft(Vec::new()));

    assert_eq!(e.validate_header(&header, &header, &view), Err(ConsensusError::EngineUnavailable));
    assert_eq!(e.validate_seal(&block, &view), Err(ConsensusError::EngineUnavailable));
    assert_eq!(e.next_bits(&header, &view), Err(ConsensusError::EngineUnavailable));
    assert_eq!(
        e.seal(BlockTemplate::new(header, Vec::new(), 1), &AtomicBool::new(false)),
        Err(ConsensusError::EngineUnavailable)
    );
}

#[test]
fn finality_follows_the_last_recorded_commit() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let view = TestView::devnet();
    assert_eq!(e.finalized_height(&view), None, "nothing is final before the first commit");
    assert_eq!(e.locked_on(), None);
    assert_eq!(e.last_commit(), None);

    let hash = BlockHash::from_bytes([0x33; 32]);
    let c = commit_signed_by(&p, &[0, 1, 2], 41, 3, hash);
    e.record_commit(c.clone());
    assert_eq!(e.finalized_height(&view), Some(41));
    assert_eq!(e.locked_on(), Some((3, hash)));
    assert_eq!(e.last_commit(), Some(c));
}

#[test]
fn a_commit_seal_carries_a_verifiable_certificate_end_to_end() {
    // The full path the chain layer will take: hash a header, build a
    // commit over it, put it in the seal, read it back, verify it.
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let header = BlockHeader { version: 1, timestamp_ms: 5_000, ..BlockHeader::default() };
    let hash = block_hash(&header);
    let commit = commit_signed_by(&p, &[1, 2, 3], 99, 0, hash);
    let block = Block::new(header, Vec::new(), commit.to_seal());

    assert_eq!(block.seal.engine, BlockSeal::ENGINE_BFT);
    let decoded = BftCommit::decode(&block.seal.data).unwrap();
    assert_eq!(decoded, commit);
    assert_eq!(e.verify_commit(&decoded, &block_hash(&block.header), 99), Ok(()));
}
