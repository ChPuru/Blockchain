//! The engine face of the BFT subtree, and the PoW to BFT fork boundary.

use core::sync::atomic::AtomicBool;

use ferrum_crypto::Signature;
use ferrum_types::{Block, BlockHash, BlockHeader, BlockSeal, ChainParams, CompactTarget, Hash32};

use super::*;
use crate::engine::{BlockTemplate, ConsensusEngine, EngineRouter, block_hash};
use crate::error::ConsensusError;
use crate::pow::PowEngine;
use crate::target::Work;
use crate::testview::TestView;

/// A view holding only the devnet genesis header, and that header.
fn view_with_genesis() -> (TestView, BlockHeader) {
    let mut view = TestView::with_params(params(4));
    let genesis = view.push_genesis();
    (view, genesis)
}

/// A well-formed BFT child of `parent`.
fn bft_child(parent: &BlockHeader) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_hash: block_hash(parent),
        merkle_root: Hash32::ZERO,
        timestamp_ms: parent.timestamp_ms.saturating_add(120_000),
        bits: parent.bits,
        nonce: 0,
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

#[test]
fn engine_identity_matches_the_contract() {
    let e = engine(4);
    assert_eq!(e.name(), "bft");
    assert_eq!(e.engine_id(), BlockSeal::ENGINE_BFT);
    assert_eq!(e.params().chain_id, ChainParams::devnet().chain_id);
    assert_eq!(e.validators().len(), 4);
    assert_eq!(e.validator_set().len(), 4);
}

#[test]
fn every_block_contributes_exactly_one_unit_of_work() {
    // Under BFT fork choice below finality is by height, and a constant weight
    // per block says exactly that in the currency proof of work already uses.
    let e = engine(4);
    assert_eq!(e.work(&BlockHeader::default()), Work::ONE);
    assert_eq!(
        e.work(&BlockHeader { bits: CompactTarget(0x1d00_ffff), ..BlockHeader::default() }),
        Work::ONE
    );
}

#[test]
fn next_bits_freezes_the_parent_target() {
    // There is no difficulty under BFT; the field survives the fork because
    // SPEC 9.3 promises the serialised structure does not change.
    let (view, genesis) = view_with_genesis();
    let e = engine(4);
    assert_eq!(e.next_bits(&genesis, &view), Ok(genesis.bits));

    let odd = BlockHeader { bits: CompactTarget(0x1d00_ffff), ..genesis };
    assert_eq!(e.next_bits(&odd, &view), Ok(CompactTarget(0x1d00_ffff)));
}

// ---------------------------------------------------------------------------
// Header validation
// ---------------------------------------------------------------------------

#[test]
fn a_valid_bft_header_is_accepted() {
    let (view, genesis) = view_with_genesis();
    let e = engine(4);
    assert_eq!(e.validate_header(&bft_child(&genesis), &genesis, &view), Ok(()));
}

#[test]
fn a_bft_header_below_the_minimum_version_is_rejected() {
    let (view, genesis) = view_with_genesis();
    let header = BlockHeader { version: 0, ..bft_child(&genesis) };
    assert_eq!(
        engine(4).validate_header(&header, &genesis, &view),
        Err(ConsensusError::BadVersion(0))
    );
}

#[test]
fn a_bft_header_naming_another_parent_is_rejected() {
    let (view, genesis) = view_with_genesis();
    let header = BlockHeader { prev_hash: hash(0x99), ..bft_child(&genesis) };
    assert_eq!(
        engine(4).validate_header(&header, &genesis, &view),
        Err(ConsensusError::WrongParent { expected: block_hash(&genesis), actual: hash(0x99) })
    );
}

#[test]
fn a_bft_header_changing_bits_is_rejected() {
    let (view, genesis) = view_with_genesis();
    let header = BlockHeader { bits: CompactTarget(0x1d00_ffff), ..bft_child(&genesis) };
    assert_eq!(
        engine(4).validate_header(&header, &genesis, &view),
        Err(ConsensusError::BadDifficultyTransition {
            expected: genesis.bits,
            actual: CompactTarget(0x1d00_ffff),
        })
    );
}

#[test]
fn a_bft_header_with_a_non_zero_nonce_is_rejected() {
    // Nothing grinds a nonce under BFT, so a free 64-bit field would let a
    // proposer offer the same content under many block hashes.
    let (view, genesis) = view_with_genesis();
    let header = BlockHeader { nonce: 1, ..bft_child(&genesis) };
    assert_eq!(
        engine(4).validate_header(&header, &genesis, &view),
        Err(ConsensusError::NonZeroBftNonce(1))
    );
}

#[test]
fn a_bft_header_at_or_before_median_time_past_is_rejected() {
    let (view, genesis) = view_with_genesis();
    let e = engine(4);
    let mtp_ms = genesis.timestamp_ms;
    for timestamp_ms in [mtp_ms, mtp_ms.saturating_sub(1), 0] {
        let header = BlockHeader { timestamp_ms, ..bft_child(&genesis) };
        assert_eq!(
            e.validate_header(&header, &genesis, &view),
            Err(ConsensusError::TimestampTooOld { timestamp_ms, median_time_past_ms: mtp_ms })
        );
    }
}

#[test]
fn a_bft_header_without_median_time_past_is_missing_context() {
    let mut view = TestView::with_params(params(4));
    let genesis = view.push_genesis();
    view.suppress_median_time_past();
    let error = engine(4).validate_header(&bft_child(&genesis), &genesis, &view).unwrap_err();
    assert_eq!(error, ConsensusError::MedianTimePastUnavailable(block_hash(&genesis)));
    assert!(error.is_missing_context(), "a syncing node holds this, it does not ban the peer");
}

// ---------------------------------------------------------------------------
// Seal validation
// ---------------------------------------------------------------------------

#[test]
fn a_proof_of_work_seal_on_a_bft_block_is_rejected() {
    let block = Block::new(BlockHeader::default(), Vec::new(), BlockSeal::POW);
    assert_eq!(
        engine(4).validate_seal(&block, &TestView::devnet()),
        Err(ConsensusError::WrongEngine { expected: BlockSeal::ENGINE_BFT, actual: 0 })
    );
}

#[test]
fn a_malformed_bft_seal_is_rejected() {
    let block = Block::new(BlockHeader::default(), Vec::new(), BlockSeal::bft(vec![0xff; 3]));
    assert!(matches!(
        engine(4).validate_seal(&block, &TestView::devnet()),
        Err(ConsensusError::MalformedSeal(_))
    ));
}

#[test]
fn a_seal_certifying_another_block_is_rejected() {
    let p = params(4);
    let header = BlockHeader { timestamp_ms: 5_000, ..BlockHeader::default() };
    let commit = commit_signed_by(&p, &[0, 1, 2], 0, 0, hash(0x5a));
    let block = Block::new(header, Vec::new(), commit.to_seal());
    assert!(matches!(
        engine(4).validate_seal(&block, &TestView::devnet()),
        Err(ConsensusError::CommitMismatch { .. })
    ));
}

#[test]
fn a_seal_short_of_quorum_is_rejected() {
    let p = params(4);
    let header = BlockHeader { timestamp_ms: 5_000, ..BlockHeader::default() };
    let commit = commit_signed_by(&p, &[0, 1], 0, 0, block_hash(&header));
    let block = Block::new(header, Vec::new(), commit.to_seal());
    assert_eq!(
        engine(4).validate_seal(&block, &TestView::devnet()),
        Err(ConsensusError::QuorumNotReached { have: 2, need: 3 })
    );
}

#[test]
fn a_seal_whose_parent_is_unknown_is_missing_context() {
    let p = params(4);
    let header =
        BlockHeader { prev_hash: hash(0x77), timestamp_ms: 5_000, ..BlockHeader::default() };
    let commit = commit_signed_by(&p, &[0, 1, 2], 0, 0, block_hash(&header));
    let block = Block::new(header, Vec::new(), commit.to_seal());
    assert_eq!(
        engine(4).validate_seal(&block, &TestView::devnet()),
        Err(ConsensusError::UnknownParent(hash(0x77)))
    );
}

#[test]
fn a_seal_is_checked_against_the_height_the_view_gives_it() {
    // The height is derived from the chain, never from the certificate, so a
    // commit for height 9 cannot be pasted onto the block at height 1.
    let (mut view, genesis) = view_with_genesis();
    let child = bft_child(&genesis);
    let p = params(4);
    let commit = commit_signed_by(&p, &[0, 1, 2], 9, 0, block_hash(&child));
    let block = Block::new(child, Vec::new(), commit.to_seal());
    assert!(matches!(
        engine(4).validate_seal(&block, &view),
        Err(ConsensusError::CommitMismatch { expected_height: 1, actual_height: 9, .. })
    ));

    let good = commit_signed_by(&p, &[0, 1, 2], 1, 0, block_hash(&block.header));
    let block = Block::new(block.header, Vec::new(), good.to_seal());
    assert_eq!(engine(4).validate_seal(&block, &view), Ok(()));
    // And it still validates once the block itself is in the view.
    view.push_header(block.header);
    assert_eq!(engine(4).validate_seal(&block, &view), Ok(()));
}

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

/// A header at height 0 that a template can be built from.
fn sealable_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_hash: BlockHash::ZERO,
        merkle_root: Hash32::ZERO,
        timestamp_ms: 5_000,
        bits: ChainParams::devnet().genesis_bits,
        nonce: 0,
    }
}

#[test]
fn seal_returns_none_until_the_round_decides() {
    let e = engine(4);
    let template = BlockTemplate::new(sealable_header(), Vec::new(), 0);
    assert_eq!(e.seal(template, &AtomicBool::new(false)), Ok(None));
}

#[test]
fn seal_returns_none_when_cancelled() {
    let e = engine(4);
    let template = BlockTemplate::new(sealable_header(), Vec::new(), 0);
    assert_eq!(e.seal(template, &AtomicBool::new(true)), Ok(None));
}

#[test]
fn a_decided_round_seals_a_block_whose_certificate_validates() {
    let header = sealable_header();
    let decided = block_hash(&header);
    let e = engine(4);
    e.submit(BftEvent::NewHeight(0));
    for index in 0..3u16 {
        e.submit(BftEvent::Precommit(precommit(index, 0, 0, decided)));
    }
    assert_eq!(e.decision().map(|c| c.block_hash), Some(decided));

    let template = BlockTemplate::new(header, Vec::new(), 0);
    let block = e.seal(template, &AtomicBool::new(false)).unwrap().unwrap();
    assert_eq!(block.seal.engine, BlockSeal::ENGINE_BFT);
    assert_eq!(block_hash(&block.header), decided);
    assert_eq!(e.validate_seal(&block, &TestView::devnet()), Ok(()));
    assert_eq!(BftCommit::decode(&block.seal.data).unwrap().signatures.len(), 3);
}

#[test]
fn seal_refuses_a_template_the_round_did_not_decide() {
    let e = engine(4);
    e.submit(BftEvent::NewHeight(0));
    for index in 0..3u16 {
        e.submit(BftEvent::Precommit(precommit(index, 0, 0, hash(0x01))));
    }
    // The round decided some other block, so this template is not sealable.
    let template = BlockTemplate::new(sealable_header(), Vec::new(), 0);
    assert_eq!(e.seal(template, &AtomicBool::new(false)), Ok(None));
}

#[test]
fn sealing_normalises_the_nonce() {
    // A template that arrives with a stale nonce is normalised, so the hash the
    // round agreed on is the hash the network will accept.
    let header = sealable_header();
    let decided = block_hash(&header);
    let e = engine(4);
    e.submit(BftEvent::NewHeight(0));
    for index in 0..3u16 {
        e.submit(BftEvent::Precommit(precommit(index, 0, 0, decided)));
    }
    let template = BlockTemplate::new(BlockHeader { nonce: 42, ..header }, Vec::new(), 0);
    let block = e.seal(template, &AtomicBool::new(false)).unwrap().unwrap();
    assert_eq!(block.header.nonce, 0);
    assert_eq!(block_hash(&block.header), decided);
}

// ---------------------------------------------------------------------------
// Finality and reorgs
// ---------------------------------------------------------------------------

#[test]
fn nothing_is_final_before_the_first_commit() {
    let e = engine(4);
    assert_eq!(e.finalized_height(&TestView::devnet()), None);
    assert_eq!(e.last_commit(), None);
    assert_eq!(e.locked_on(), None);
    assert_eq!(e.round_state().height, 0);
}

#[test]
fn finality_follows_the_last_recorded_commit() {
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let commit = commit_signed_by(&p, &[0, 1, 2], 41, 3, hash(0x33));
    e.record_commit(commit.clone()).unwrap();
    assert_eq!(e.finalized_height(&TestView::devnet()), Some(41));
    assert_eq!(e.last_commit(), Some(commit));
}

#[test]
fn recorded_finality_only_moves_forward() {
    // A stale commit arriving late must never lower the finalized height; that
    // would reopen a reorg the chain has already refused.
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    e.record_commit(commit_signed_by(&p, &[0, 1, 2], 41, 0, hash(0x33))).unwrap();
    e.record_commit(commit_signed_by(&p, &[0, 1, 2], 7, 0, hash(0x34))).unwrap();
    assert_eq!(e.finalized_height(&TestView::devnet()), Some(41));
}

#[test]
fn every_bft_block_on_the_active_chain_is_final() {
    // A block only reaches the active chain after `validate_seal` verified a
    // 2f+1 certificate over it, so the tip is the finalized height even before
    // any driver bookkeeping.
    let mut view = TestView::with_params(params(4));
    view.push_genesis();
    let e = engine(4);
    assert_eq!(e.finalized_height(&view), Some(0));
    view.push_child(120_000);
    assert_eq!(e.finalized_height(&view), Some(1));
}

#[test]
fn a_lock_is_visible_through_the_engine() {
    let e = BftEngine::new(params(4), Some(validator_key(3))).unwrap();
    e.submit(BftEvent::NewHeight(0));
    e.submit(BftEvent::Proposal(proposal(0, 0, 0, hash(0xa1), None)));
    for index in 0..3u16 {
        e.submit(BftEvent::Prevote(prevote(index, 0, 0, hash(0xa1))));
    }
    assert_eq!(e.locked_on(), Some((0, hash(0xa1))));
    assert_eq!(e.round_state().step, Step::Precommit);
}

#[test]
fn the_router_refuses_a_reorg_below_finality() {
    let mut p = ChainParams::devnet();
    p.bft_activation_height = Some(0);
    p.bft_validators = validator_ids(4);
    let router = EngineRouter::new(p.clone()).unwrap();

    let mut view = TestView::with_params(p);
    view.push_genesis();
    view.push_child(120_000);
    view.push_child(120_000);

    assert_eq!(router.finalized_height(&view), Some(2));
    assert_eq!(
        router.check_reorg(0, &view),
        Err(ConsensusError::ReorgBelowFinalized { fork_height: 0, finalized_height: 2 })
    );
    assert_eq!(
        router.check_reorg(1, &view),
        Err(ConsensusError::ReorgBelowFinalized { fork_height: 1, finalized_height: 2 })
    );
    assert_eq!(router.check_reorg(2, &view), Ok(()), "the tip itself is not below finality");
    assert_eq!(router.check_reorg(9, &view), Ok(()));
}

#[test]
fn proof_of_work_never_finalises_so_every_reorg_is_allowed() {
    let router = EngineRouter::new(ChainParams::devnet()).unwrap();
    let mut view = TestView::devnet();
    view.push_genesis();
    view.push_child(120_000);
    assert_eq!(router.finalized_height(&view), None);
    assert_eq!(router.check_reorg(0, &view), Ok(()));
}

// ---------------------------------------------------------------------------
// The fork boundary
// ---------------------------------------------------------------------------

#[test]
fn the_activation_boundary_is_exact() {
    let mut p = ChainParams::devnet();
    p.bft_activation_height = Some(2);
    p.bft_validators = validator_ids(4);
    let router = EngineRouter::new(p).unwrap();

    assert_eq!(router.engine_for_height(0).engine_id(), BlockSeal::ENGINE_POW);
    assert_eq!(router.engine_for_height(1).engine_id(), BlockSeal::ENGINE_POW, "h-1 is PoW");
    assert_eq!(router.engine_for_height(2).engine_id(), BlockSeal::ENGINE_BFT, "h is BFT");
    assert_eq!(router.engine_for_height(3).engine_id(), BlockSeal::ENGINE_BFT);
    assert_eq!(router.engine_for_height(1).name(), "pow");
    assert_eq!(router.engine_for_height(2).name(), "bft");
}

#[test]
fn a_block_validated_under_one_engine_stays_valid_across_the_fork() {
    // This is the whole of the M10 hard fork: history stays valid because each
    // block is validated by the engine that was active at its height.
    let mut p = ChainParams::devnet();
    p.bft_activation_height = Some(2);
    p.bft_validators = validator_ids(4);
    let router = EngineRouter::new(p.clone()).unwrap();

    let mut view = TestView::with_params(p.clone());
    let genesis = view.push_genesis();
    let pow = PowEngine::new(p.clone());
    let candidate = BlockHeader {
        version: 1,
        prev_hash: block_hash(&genesis),
        merkle_root: Hash32::ZERO,
        timestamp_ms: genesis.timestamp_ms.saturating_add(120_000),
        // The ASERT anchor is genesis, so height 1 is on the schedule like
        // every other block; its target is no longer simply `genesis_bits`.
        bits: pow.next_bits(&genesis, &view).unwrap(),
        nonce: 0,
    };
    let block = pow
        .seal(BlockTemplate::new(candidate, Vec::new(), 1), &AtomicBool::new(false))
        .unwrap()
        .unwrap();

    // Height 1 is proof of work, before and after the fork height is crossed.
    let engine_at_1 = router.engine_for_height(1);
    assert_eq!(engine_at_1.name(), "pow");
    assert_eq!(engine_at_1.validate_header(&block.header, &genesis, &view), Ok(()));
    assert_eq!(engine_at_1.validate_seal(&block, &view), Ok(()));

    view.push_header(block.header);
    assert_eq!(router.engine_for_height(2).name(), "bft");
    assert_eq!(
        router.engine_for_height(1).validate_seal(&block, &view),
        Ok(()),
        "the pre-fork block is still valid once BFT is live"
    );

    // And the BFT engine would refuse it, which is exactly why the router must
    // dispatch by height rather than by tip.
    assert_eq!(
        router.bft().unwrap().validate_seal(&block, &view),
        Err(ConsensusError::WrongEngine { expected: BlockSeal::ENGINE_BFT, actual: 0 })
    );
}

// ---------------------------------------------------------------------------
// Finality is only ever raised by something that was checked
// ---------------------------------------------------------------------------

#[test]
fn record_commit_refuses_an_unverified_certificate() {
    // `record_commit` is public, self-describing and takes a certificate
    // straight from its caller. Raising `finalized` from one that was never
    // verified is irreversible — there is no API that lowers it — so a single
    // garbage certificate claiming height u64::MAX makes `check_reorg` refuse
    // every reorg at every depth for the life of the process. `seal` already
    // runs `verify_commit` before touching the same two fields; so must this.
    let p = params(4);
    let e = BftEngine::new(p, None).unwrap();
    let bogus = BftCommit::new(
        u64::MAX,
        0,
        hash(0x99),
        vec![
            (0, Signature::from_bytes([0x11; 64])),
            (1, Signature::from_bytes([0x22; 64])),
            (2, Signature::from_bytes([0x33; 64])),
        ],
    );

    assert!(matches!(
        e.record_commit(bogus),
        Err(ConsensusError::BadCommitSignature { index: 0, .. })
    ));
    assert_eq!(
        e.finalized_height(&TestView::devnet()),
        None,
        "an unverified certificate must not move finality"
    );
    assert_eq!(e.last_commit(), None, "nor become the last commit");
}

/// A view whose tip is real but whose header table cannot be read.
///
/// This is what a transient storage error looks like through [`HeaderView`],
/// which has nowhere to report one: `StoreHeaderView` logs it and returns
/// `None`. Failing closed is right for the difficulty rule, where "unknown"
/// means "reject"; for finality the polarity is inverted, and a missing answer
/// silently removes the guard that stops a committed prefix being unwound.
#[derive(Debug)]
struct TornView {
    params: ChainParams,
    tip: (BlockHash, u64),
}

impl crate::engine::HeaderView for TornView {
    fn params(&self) -> &ChainParams {
        &self.params
    }
    fn header_by_hash(&self, _: &BlockHash) -> Option<BlockHeader> {
        None
    }
    fn header_at_height(&self, _: u64) -> Option<BlockHeader> {
        None
    }
    fn height_of(&self, _: &BlockHash) -> Option<u64> {
        None
    }
    fn tip(&self) -> (BlockHash, u64) {
        self.tip
    }
    fn median_time_past(&self, _: &BlockHash) -> Option<u64> {
        None
    }
}

#[test]
fn an_unreadable_tip_header_does_not_erase_finality() {
    let e = engine(4);
    let torn = TornView { params: params(4), tip: (hash(0x77), 150) };
    assert_eq!(
        e.finalized_height(&torn),
        Some(150),
        "a header read that failed must not read as 'nothing is final'"
    );
}

#[test]
fn a_genuinely_empty_view_finalises_nothing() {
    // The other half: a zero tip hash really is an empty chain, and claiming
    // finality over it would be a lie in the other direction.
    let e = engine(4);
    let empty = TornView { params: params(4), tip: (BlockHash::ZERO, 0) };
    assert_eq!(e.finalized_height(&empty), None);
}

#[test]
fn record_commit_refuses_a_short_quorum() {
    // Two genuine signatures out of four is not 2f+1. Accepting it would
    // finalise a height that no quorum ever agreed on.
    let p = params(4);
    let e = BftEngine::new(p.clone(), None).unwrap();
    let short = commit_signed_by(&p, &[0, 1], 12, 0, hash(0x55));
    assert_eq!(e.record_commit(short), Err(ConsensusError::QuorumNotReached { have: 2, need: 3 }));
    assert_eq!(e.finalized_height(&TestView::devnet()), None);
    assert_eq!(e.last_commit(), None);
}
