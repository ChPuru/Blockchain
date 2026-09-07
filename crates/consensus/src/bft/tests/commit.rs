//! The vote preimage, the three signing digests, the validator set and
//! `2f+1` commit-certificate verification.

use core::time::Duration;

use ferrum_crypto::{Signature, TAG_BFT_PRECOMMIT, TAG_BFT_PROPOSAL, tagged_hash};
use ferrum_types::{BlockSeal, ChainId, ChainParams, ValidatorId};

use super::*;
use crate::bft::vote::VoteKind;
use crate::error::ConsensusError;

fn vote(n: usize) -> VoteMsg {
    VoteMsg::new(params(n).chain_id, 7, 2, hash(9))
}

// ---------------------------------------------------------------------------
// The frozen preimage
// ---------------------------------------------------------------------------

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
    let p = proposal_digest(&v, None);
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
    let a = VoteMsg::new(ChainId(1), 5, 0, hash(1));
    let b = VoteMsg::new(ChainId(2), 5, 0, hash(1));
    assert_ne!(precommit_digest(&a), precommit_digest(&b), "cross-chain replay must be impossible");
    assert_ne!(prevote_digest(&a), prevote_digest(&b));
    assert_ne!(proposal_digest(&a, None), proposal_digest(&b, None));
    assert_ne!(proposal_digest(&a, Some(2)), proposal_digest(&b, Some(2)));
}

#[test]
fn the_proposal_digest_commits_to_pol_round() {
    // `pol_round` decides which of rules 2 and 3 a receiver runs, so it is a
    // control input. Outside the signed preimage it would be a control input
    // owned by whoever relays the message rather than by the proposer.
    let v = VoteMsg::new(ChainId(3), 5, 7, hash(1));
    assert_ne!(proposal_digest(&v, None), proposal_digest(&v, Some(0)));
    assert_ne!(proposal_digest(&v, Some(0)), proposal_digest(&v, Some(1)));
    assert_ne!(proposal_digest(&v, Some(6)), proposal_digest(&v, None));
    assert_eq!(proposal_digest(&v, Some(6)), proposal_digest(&v, Some(6)), "and is a function");

    // The preimage is the frozen 48-byte vote followed by borsh(Option<u32>),
    // so the vote itself is unchanged and none of the three encodings is a
    // prefix of another.
    let mut none = v.signing_bytes();
    none.push(0);
    assert_eq!(proposal_digest(&v, None), tagged_hash(TAG_BFT_PROPOSAL, &none));
    let mut some = v.signing_bytes();
    some.push(1);
    some.extend_from_slice(&6u32.to_le_bytes());
    assert_eq!(proposal_digest(&v, Some(6)), tagged_hash(TAG_BFT_PROPOSAL, &some));
}

#[test]
fn the_round_is_inside_every_digest() {
    let a = VoteMsg::new(ChainId(3), 5, 0, hash(1));
    let b = VoteMsg::new(ChainId(3), 5, 1, hash(1));
    assert_ne!(
        precommit_digest(&a),
        precommit_digest(&b),
        "a vote must not be replayable across rounds"
    );
}

#[test]
fn the_block_hash_is_inside_every_digest() {
    let a = VoteMsg::new(ChainId(3), 5, 0, hash(1));
    let b = VoteMsg::new(ChainId(3), 5, 0, hash(2));
    assert_ne!(precommit_digest(&a), precommit_digest(&b));
    assert_ne!(prevote_digest(&a), prevote_digest(&b));
}

#[test]
fn a_nil_vote_is_the_zero_block_hash() {
    let v = VoteMsg::nil(ChainId(3), 5, 1);
    assert!(v.is_nil());
    assert_eq!(v.block_hash, NIL_BLOCK);
    assert!(NIL_BLOCK.is_zero());
    assert!(!VoteMsg::new(ChainId(3), 5, 1, hash(1)).is_nil());
}

#[test]
fn a_signed_vote_verifies_only_under_its_own_kind() {
    let set = set(4);
    let v = VoteMsg::new(params(4).chain_id, 3, 0, hash(7));
    let signed = SignedVote::sign(&validator_key(1), 1, VoteKind::Prevote, v);
    assert_eq!(signed.verify(VoteKind::Prevote, &set), Ok(()));
    // The tag is what stops a prevote being counted as a precommit — and a
    // precommit is the only thing a commit certificate may be built from.
    assert!(signed.verify(VoteKind::Precommit, &set).is_err());
    assert!(!signed.is_nil());
}

#[test]
fn a_proposal_signature_is_checked() {
    let set = set(4);
    let p = proposal(0, 4, 1, hash(3), Some(0));
    assert_eq!(p.verify(params(4).chain_id, &set), Ok(()));
    assert_eq!(p.vote(params(4).chain_id), VoteMsg::new(params(4).chain_id, 4, 1, hash(3)));

    let mut forged = p;
    forged.block_hash = hash(4);
    assert!(forged.verify(params(4).chain_id, &set).is_err());

    let mut wrong_signer = p;
    wrong_signer.proposer = 1;
    assert!(wrong_signer.verify(params(4).chain_id, &set).is_err());
}

// ---------------------------------------------------------------------------
// The validator set
// ---------------------------------------------------------------------------

#[test]
fn quorum_arithmetic_matches_the_contract() {
    // `f = (n - 1) / 3`, quorum `2f + 1`, unchanged (CONTRACT 6.5). n = 6 is
    // absent because it is no longer an admissible set size, not because the
    // formula differs there — `a_six_validator_set_is_refused` pins the f and
    // quorum it would have produced, and why that is fatal.
    for (n, f, q) in [(4usize, 1usize, 3usize), (5, 1, 3), (7, 2, 5), (10, 3, 7), (64, 21, 43)] {
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
fn quorum_intersection_holds_for_every_admissible_set_size() {
    // Two quorums must overlap, or two conflicting commits could both be
    // valid at one height. With f = (n-1)/3 that holds everywhere except
    // n = 6, which is why the contract's `n = 3f + 1` shape matters — and
    // n = 6 is now refused by the constructor rather than merely noticed, so
    // every set that exists has the property.
    for n in MIN_VALIDATORS..=32 {
        match ValidatorSet::new(validator_ids(n)) {
            Ok(set) => {
                assert_ne!(n, 6, "n = 6 must never be constructible");
                assert!(set.has_quorum_intersection(), "n = {n} must have quorum intersection");
                assert!(engine(n).has_quorum_intersection(), "n = {n} through the engine");
            }
            Err(ConsensusError::NoQuorumIntersection { validators, quorum }) => {
                assert_eq!(n, 6, "n = 6 is the one degenerate size");
                assert_eq!((validators, quorum), (6, 3));
                assert_eq!(quorum.saturating_mul(2), n, "two quorums of 3 exactly fill the set");
            }
            Err(other) => panic!("n = {n} was refused for the wrong reason: {other:?}"),
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
        assert_eq!(
            ValidatorSet::new(validator_ids(n)).err(),
            Some(ConsensusError::ValidatorSetTooSmall { actual: n, minimum: 4 })
        );
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
    let mut ids = validator_ids(4);
    ids[3] = ids[0];
    assert_eq!(
        ValidatorSet::new(ids.clone()).err(),
        Some(ConsensusError::DuplicateValidator(ids[0].to_hex()))
    );
}

#[test]
fn an_off_curve_validator_key_is_refused() {
    let mut ids = validator_ids(4);
    // The field modulus itself is not a valid x coordinate.
    ids[2] = ValidatorId::from_bytes([0xff; 32]);
    match ValidatorSet::new(ids) {
        Err(ConsensusError::InvalidValidatorKey { index, .. }) => assert_eq!(index, 2),
        other => panic!("expected InvalidValidatorKey, got {other:?}"),
    }
}

#[test]
fn a_validator_set_maps_ids_to_indices_and_back() {
    let s = set(4);
    assert_eq!(s.len(), 4);
    assert!(!s.is_empty());
    for (i, id) in s.ids().iter().enumerate() {
        assert_eq!(s.index_of(id), u16::try_from(i).ok());
        assert!(s.key(u16::try_from(i).unwrap()).is_ok());
    }
    assert_eq!(s.index_of(&ValidatorId::from_bytes([1; 32])), None);
    assert_eq!(
        s.key(4).err(),
        Some(ConsensusError::ValidatorIndexOutOfRange { index: 4, size: 4 })
    );
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
        v[((u128::from(u64::MAX) + u128::from(u32::MAX)) % 4) as usize]
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
    assert_eq!(timeout_for_round(base, 3), Duration::from_millis(8_000));
}

#[test]
fn default_timeouts_are_present() {
    assert_eq!(DEFAULT_PROPOSE_TIMEOUT, Duration::from_millis(3_000));
    assert_eq!(DEFAULT_PREVOTE_TIMEOUT, Duration::from_millis(1_000));
    assert_eq!(DEFAULT_PRECOMMIT_TIMEOUT, Duration::from_millis(1_000));

    let cfg = TimeoutConfig::default();
    assert_eq!(cfg.base(TimeoutKind::Propose), DEFAULT_PROPOSE_TIMEOUT);
    assert_eq!(cfg.base(TimeoutKind::Prevote), DEFAULT_PREVOTE_TIMEOUT);
    assert_eq!(cfg.base(TimeoutKind::Precommit), DEFAULT_PRECOMMIT_TIMEOUT);
    assert_eq!(cfg.delay(TimeoutKind::Propose, 2), Duration::from_millis(12_000));
}

// ---------------------------------------------------------------------------
// Commit certificates
// ---------------------------------------------------------------------------

#[test]
fn a_commit_round_trips_through_its_seal() {
    let p = params(4);
    let c = commit_signed_by(&p, &[0, 1, 2], 7, 1, hash(4));
    let seal = c.to_seal();
    assert_eq!(seal.engine, BlockSeal::ENGINE_BFT);
    assert_eq!(BftCommit::decode(&seal.data).unwrap(), c);
    assert_eq!(c.vote(p.chain_id), VoteMsg::new(p.chain_id, 7, 1, c.block_hash));
}

#[test]
fn a_commit_with_trailing_bytes_is_rejected() {
    let p = params(4);
    let c = commit_signed_by(&p, &[0, 1, 2], 7, 1, hash(4));
    let mut bytes = c.encode();
    bytes.push(0);
    assert!(matches!(BftCommit::decode(&bytes), Err(ConsensusError::MalformedSeal(_))));
    assert!(matches!(BftCommit::decode(&[]), Err(ConsensusError::MalformedSeal(_))));
}

#[test]
fn a_quorum_of_valid_signatures_verifies() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let h = hash(0x11);
    let c = commit_signed_by(&p, &[0, 1, 2], 12, 0, h);
    assert_eq!(e.verify_commit(&c, &h, 12), Ok(()));
}

#[test]
fn all_four_signatures_also_verify() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let h = hash(0x11);
    let c = commit_signed_by(&p, &[0, 1, 2, 3], 12, 0, h);
    assert_eq!(e.verify_commit(&c, &h, 12), Ok(()));
}

#[test]
fn one_signature_short_of_quorum_is_refused() {
    // 2f signatures with f = 1: exactly the certificate an attacker can build
    // from one honest validator and one Byzantine one.
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let h = hash(0x11);
    let c = commit_signed_by(&p, &[0, 1], 12, 0, h);
    assert_eq!(
        e.verify_commit(&c, &h, 12),
        Err(ConsensusError::QuorumNotReached { have: 2, need: 3 })
    );
}

#[test]
fn a_larger_set_also_rejects_two_f_signatures() {
    // n = 7, f = 2, quorum 5: four signatures is 2f and must be refused.
    let p = params(7);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let h = hash(0x11);
    assert_eq!(
        e.verify_commit(&commit_signed_by(&p, &[0, 1, 2, 3], 3, 0, h), &h, 3),
        Err(ConsensusError::QuorumNotReached { have: 4, need: 5 })
    );
    assert_eq!(e.verify_commit(&commit_signed_by(&p, &[0, 1, 2, 3, 4], 3, 0, h), &h, 3), Ok(()));
}

#[test]
fn killing_one_of_four_validators_still_reaches_quorum_but_two_halts() {
    // This is the operational promise in RUNNING.md, asserted.
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let h = hash(0x22);
    assert_eq!(e.verify_commit(&commit_signed_by(&p, &[0, 1, 2], 1, 0, h), &h, 1), Ok(()));
    assert!(e.verify_commit(&commit_signed_by(&p, &[0, 1], 1, 0, h), &h, 1).is_err());
}

#[test]
fn a_duplicated_validator_index_cannot_fill_a_quorum() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let h = hash(0x11);
    let mut c = commit_signed_by(&p, &[0], 12, 0, h);
    let sig = c.signatures[0].1;
    c.signatures = vec![(0, sig), (0, sig), (0, sig)];
    assert_eq!(e.verify_commit(&c, &h, 12), Err(ConsensusError::UnorderedCommitSignatures(1)));
}

#[test]
fn out_of_order_signatures_are_refused() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let h = hash(0x11);
    let mut c = commit_signed_by(&p, &[0, 1, 2], 12, 0, h);
    c.signatures.swap(0, 1);
    assert_eq!(e.verify_commit(&c, &h, 12), Err(ConsensusError::UnorderedCommitSignatures(1)));
}

#[test]
fn a_validator_index_outside_the_set_is_refused() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let h = hash(0x11);
    let mut c = commit_signed_by(&p, &[0, 1, 2], 12, 0, h);
    c.signatures[2].0 = 9;
    assert_eq!(
        e.verify_commit(&c, &h, 12),
        Err(ConsensusError::ValidatorIndexOutOfRange { index: 9, size: 4 })
    );
}

#[test]
fn a_forged_signature_is_refused() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let h = hash(0x11);
    let mut c = commit_signed_by(&p, &[0, 1, 2], 12, 0, h);
    c.signatures[1].1 = Signature::from_bytes([0x77; 64]);
    match e.verify_commit(&c, &h, 12) {
        Err(ConsensusError::BadCommitSignature { index, .. }) => assert_eq!(index, 1),
        other => panic!("expected BadCommitSignature, got {other:?}"),
    }
}

#[test]
fn a_signature_by_the_wrong_validator_is_refused() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let h = hash(0x11);
    let mut c = commit_signed_by(&p, &[0, 1, 2], 12, 0, h);
    // Validator 3's signature filed under index 2.
    let digest = precommit_digest(&c.vote(p.chain_id));
    c.signatures[2].1 = validator_key(3).sign_deterministic(&digest);
    match e.verify_commit(&c, &h, 12) {
        Err(ConsensusError::BadCommitSignature { index, .. }) => assert_eq!(index, 2),
        other => panic!("expected BadCommitSignature, got {other:?}"),
    }
}

#[test]
fn a_commit_for_another_block_or_height_is_refused() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let h = hash(0x11);
    let other = hash(0x12);
    let c = commit_signed_by(&p, &[0, 1, 2], 12, 0, h);

    assert_eq!(
        e.verify_commit(&c, &other, 12),
        Err(ConsensusError::CommitMismatch {
            actual: h,
            actual_height: 12,
            expected: other,
            expected_height: 12,
        })
    );
    assert!(matches!(e.verify_commit(&c, &h, 13), Err(ConsensusError::CommitMismatch { .. })));
}

#[test]
fn signatures_over_a_different_hash_are_refused() {
    // The certificate claims our block, but every signature covers another
    // one. This is the attack `CommitMismatch` alone would not catch.
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let ours = hash(0x11);
    let theirs = hash(0x12);
    let mut c = commit_signed_by(&p, &[0, 1, 2], 12, 0, theirs);
    c.block_hash = ours;
    match e.verify_commit(&c, &ours, 12) {
        Err(ConsensusError::BadCommitSignature { index, .. }) => assert_eq!(index, 0),
        other => panic!("expected BadCommitSignature, got {other:?}"),
    }
}

#[test]
fn a_commit_from_another_chain_is_refused() {
    let mut testnet = params(4);
    testnet.chain_id = ChainId::TESTNET;
    let h = hash(0x11);
    let c = commit_signed_by(&testnet, &[0, 1, 2], 12, 0, h);

    // Same signatures, same block, replayed on devnet.
    let devnet = BftEngine::new(params(4), None).unwrap();
    match devnet.verify_commit(&c, &h, 12) {
        Err(ConsensusError::BadCommitSignature { index, .. }) => assert_eq!(index, 0),
        other => panic!("expected a cross-chain replay to fail, got {other:?}"),
    }
}

#[test]
fn a_commit_from_another_round_is_refused() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let h = hash(0x11);
    let mut c = commit_signed_by(&p, &[0, 1, 2], 12, 0, h);
    c.round = 1; // signatures still cover round 0
    match e.verify_commit(&c, &h, 12) {
        Err(ConsensusError::BadCommitSignature { index, .. }) => assert_eq!(index, 0),
        other => panic!("expected a cross-round replay to fail, got {other:?}"),
    }
}

#[test]
fn an_empty_commit_is_refused_as_a_short_quorum() {
    let e = engine(4);
    let h = hash(0x11);
    let c = BftCommit::new(12, 0, h, Vec::new());
    assert_eq!(
        e.verify_commit(&c, &h, 12),
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
fn a_six_validator_set_is_refused() {
    // n = 6 gives f = 1 and quorum 3, and 3 + 3 = 6 is not > 6: two disjoint
    // quorums exist. One Byzantine proposer then splits the honest five into
    // {0,1,2} and {3,4}, joins the second, and both groups reach 2f+1 on
    // different blocks at one height. Both certificates pass `verify_commit`
    // and therefore `validate_seal` — a hard fork from a single fault, which
    // is exactly what the whole design promises cannot happen. It is a boot
    // failure, not a log line.
    assert_eq!(
        ValidatorSet::new(validator_ids(6)).err(),
        Some(ConsensusError::NoQuorumIntersection { validators: 6, quorum: 3 }),
        "a validator set with two disjoint quorums must be refused"
    );
    let mut p = ChainParams::devnet();
    p.bft_validators = validator_ids(6);
    assert_eq!(
        BftEngine::new(p, None).err(),
        Some(ConsensusError::NoQuorumIntersection { validators: 6, quorum: 3 }),
        "and the engine must refuse to start on it"
    );
    // Every other size in the neighbourhood is fine, so the rejection is the
    // degenerate case and not a blanket ban on non-`3f+1` sets.
    for n in [4usize, 5, 7, 8, 9] {
        assert!(ValidatorSet::new(validator_ids(n)).is_ok(), "n = {n} must still be accepted");
    }
}
