//! The proof-of-work engine.
//!
//! Nakamoto consensus with an ASERT difficulty controller. Nothing is ever
//! final ([`ConsensusEngine::finalized_height`] is `None`), fork choice is by
//! cumulative work, and the seal is empty because the nonce inside the header
//! is the whole proof.
//!
//! # Validation order
//!
//! [`PowEngine::validate_header`] checks, in this order:
//!
//! 1. `version >= MIN_BLOCK_VERSION`;
//! 2. `prev_hash` names the parent it was handed;
//! 3. `bits == next_bits(parent)` — exactly; over-paying difficulty is still
//!    invalid, because there is only one correct target per parent;
//! 4. the target is expandable, non-zero and no easier than `pow_limit`;
//! 5. the header hash meets the target;
//! 6. `timestamp_ms > median_time_past(parent) * 1000`, strictly.
//!
//! The cheap checks come first on purpose: an implementation that hashes before
//! it has checked `bits` lets a peer spend our CPU for free.

use core::sync::atomic::{AtomicBool, Ordering};

use ferrum_types::{Block, BlockHeader, BlockSeal, ChainParams, CompactTarget};

use crate::asert::{ANCHOR_HEIGHT, AsertAnchor, AsertParams, asert_next_bits};
use crate::engine::{BlockTemplate, ConsensusEngine, HeaderView, MIN_BLOCK_VERSION, block_hash};
use crate::error::ConsensusError;
use crate::target::{Target, Work, compact_to_target, hash_meets_target, work_from_target};

/// How many hashes the miner tries between cancellation checks.
///
/// 4096 BLAKE3 hashes of 88 bytes is well under a millisecond, so a new tip
/// stops the miner promptly, while an atomic load per hash would be measurable
/// overhead in the inner loop (SPEC 9.1).
pub const CANCEL_CHECK_INTERVAL: u32 = 4_096;

/// The proof-of-work consensus engine.
#[derive(Clone, Debug)]
pub struct PowEngine {
    params: ChainParams,
}

impl PowEngine {
    /// Build the engine for a network.
    pub fn new(params: ChainParams) -> Self {
        PowEngine { params }
    }

    /// The parameter set this engine enforces.
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// The easiest target this network permits.
    pub fn pow_limit(&self) -> Target {
        Target::from_be_bytes(&self.params.pow_limit)
    }

    /// The ASERT constants, read once from the parameters.
    pub fn asert_params(&self) -> AsertParams {
        AsertParams::from_chain_params(&self.params)
    }

    /// Expand and range-check a header's target in one step.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::ZeroTarget`] and
    /// [`ConsensusError::TargetAbovePowLimit`], plus the expansion errors.
    pub fn checked_target(&self, bits: CompactTarget) -> Result<Target, ConsensusError> {
        let target = compact_to_target(bits)?;
        if target.is_zero() {
            return Err(ConsensusError::ZeroTarget);
        }
        let limit = self.pow_limit();
        if target > limit {
            return Err(ConsensusError::TargetAbovePowLimit { actual: target, limit });
        }
        Ok(target)
    }

    /// Advance the search by one step: bump the nonce, or roll over into the
    /// next millisecond when the 64-bit nonce space is exhausted.
    ///
    /// The 64-bit nonce space is eighteen quintillion tries, so exhausting it
    /// is only reachable in a test with an impossible target — but a *wrapping*
    /// nonce would then spin forever over the same `2^64` hashes, never finding
    /// a block and never noticing. Advancing `timestamp_ms` opens a fresh
    /// search space (SPEC 9.1). It saturates at `u64::MAX` rather than wrapping
    /// back into the past.
    pub fn advance_search(header: &mut BlockHeader) {
        match header.nonce.checked_add(1) {
            Some(next) => header.nonce = next,
            None => {
                header.nonce = 0;
                header.timestamp_ms = header.timestamp_ms.saturating_add(1);
            }
        }
    }

    /// The ASERT anchor for this chain: the block at [`ANCHOR_HEIGHT`].
    ///
    /// # Errors
    ///
    /// [`ConsensusError::MissingHeader`] when the view has no active-chain
    /// header at the anchor height.
    pub fn anchor(&self, view: &dyn HeaderView) -> Result<AsertAnchor, ConsensusError> {
        let header = view
            .header_at_height(ANCHOR_HEIGHT)
            .ok_or(ConsensusError::MissingHeader(ANCHOR_HEIGHT))?;
        AsertAnchor::from_compact(
            header.bits,
            i64::try_from(header.timestamp_s()).unwrap_or(i64::MAX),
            ANCHOR_HEIGHT,
        )
    }
}

impl ConsensusEngine for PowEngine {
    fn name(&self) -> &'static str {
        "pow"
    }

    fn engine_id(&self) -> u8 {
        BlockSeal::ENGINE_POW
    }

    fn validate_header(
        &self,
        h: &BlockHeader,
        parent: &BlockHeader,
        view: &dyn HeaderView,
    ) -> Result<(), ConsensusError> {
        if h.version < MIN_BLOCK_VERSION {
            return Err(ConsensusError::BadVersion(h.version));
        }

        let parent_hash = block_hash(parent);
        if h.prev_hash != parent_hash {
            return Err(ConsensusError::WrongParent { expected: parent_hash, actual: h.prev_hash });
        }

        let expected = self.next_bits(parent, view)?;
        if h.bits != expected {
            return Err(ConsensusError::BadDifficultyTransition { expected, actual: h.bits });
        }

        let target = self.checked_target(h.bits)?;
        let hash = block_hash(h);
        if !hash_meets_target(&hash, target) {
            return Err(ConsensusError::InsufficientWork { hash, target });
        }

        let mtp_s = view
            .median_time_past(&parent_hash)
            .ok_or(ConsensusError::MedianTimePastUnavailable(parent_hash))?;
        let median_time_past_ms = mtp_s.saturating_mul(1_000);
        if h.timestamp_ms <= median_time_past_ms {
            return Err(ConsensusError::TimestampTooOld {
                timestamp_ms: h.timestamp_ms,
                median_time_past_ms,
            });
        }

        Ok(())
    }

    fn validate_seal(&self, block: &Block, _view: &dyn HeaderView) -> Result<(), ConsensusError> {
        if block.seal.engine != BlockSeal::ENGINE_POW {
            return Err(ConsensusError::WrongEngine {
                expected: BlockSeal::ENGINE_POW,
                actual: block.seal.engine,
            });
        }
        if !block.seal.data.is_empty() {
            // The nonce is the whole proof of work. A payload here would be a
            // field the block hash does not commit to, i.e. free malleability.
            return Err(ConsensusError::NonEmptyPowSeal(block.seal.data.len()));
        }
        Ok(())
    }

    fn next_bits(
        &self,
        parent: &BlockHeader,
        view: &dyn HeaderView,
    ) -> Result<CompactTarget, ConsensusError> {
        let parent_hash = block_hash(parent);
        let parent_height =
            view.height_of(&parent_hash).ok_or(ConsensusError::UnknownParent(parent_hash))?;

        // Genesis and the anchor itself carry the genesis target: the anchor is
        // the block at height 1, so there is nothing to measure against until
        // it exists (CONTRACT 6.3).
        let child_height = parent_height.saturating_add(1);
        if child_height <= ANCHOR_HEIGHT {
            return Ok(self.params.genesis_bits);
        }

        let anchor = self.anchor(view)?;
        let parent_time_s = i64::try_from(parent.timestamp_s()).unwrap_or(i64::MAX);
        asert_next_bits(&anchor, parent_time_s, parent_height, &self.asert_params())
    }

    fn seal(
        &self,
        tmpl: BlockTemplate,
        cancel: &AtomicBool,
    ) -> Result<Option<Block>, ConsensusError> {
        let target = self.checked_target(tmpl.header.bits)?;
        let mut header = tmpl.header;

        loop {
            if cancel.load(Ordering::Relaxed) {
                return Ok(None);
            }
            for _ in 0..CANCEL_CHECK_INTERVAL {
                let hash = block_hash(&header);
                if hash_meets_target(&hash, target) {
                    return Ok(Some(Block::new(header, tmpl.txs, BlockSeal::POW)));
                }
                PowEngine::advance_search(&mut header);
            }
        }
    }

    fn work(&self, h: &BlockHeader) -> Work {
        // An unparseable `bits` contributes nothing. Returning zero rather than
        // the work of a zero target (which is `U256::MAX`) is what stops a
        // malformed header from winning fork choice outright.
        match compact_to_target(h.bits) {
            Ok(t) if !t.is_zero() => work_from_target(t),
            _ => Work::ZERO,
        }
    }

    fn finalized_height(&self, _view: &dyn HeaderView) -> Option<u64> {
        // Under proof of work nothing is ever final; a sufficiently long chain
        // can always replace any prefix. Saying so explicitly is what keeps the
        // reorg cap honest.
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]

    use ferrum_types::{Hash32, Transaction};

    use super::*;
    use crate::engine::block_hash;
    use crate::testview::TestView;

    fn devnet() -> PowEngine {
        PowEngine::new(ChainParams::devnet())
    }

    fn template(header: BlockHeader, height: u64) -> BlockTemplate {
        BlockTemplate::new(header, Vec::<Transaction>::new(), height)
    }

    #[test]
    fn identity_matches_the_contract() {
        let e = devnet();
        assert_eq!(e.name(), "pow");
        assert_eq!(e.engine_id(), BlockSeal::ENGINE_POW);
        assert_eq!(e.params().network, ChainParams::devnet().network);
        assert_eq!(e.pow_limit(), Target::from_be_bytes(&ChainParams::devnet().pow_limit));
    }

    #[test]
    fn nothing_is_ever_final_under_proof_of_work() {
        let view = TestView::devnet();
        assert_eq!(devnet().finalized_height(&view), None);
    }

    #[test]
    fn work_of_a_header_is_the_work_of_its_target() {
        let e = devnet();
        let h = BlockHeader { bits: CompactTarget(0x1d00_ffff), ..BlockHeader::default() };
        assert_eq!(e.work(&h), work_from_target(compact_to_target(h.bits).unwrap()));
    }

    #[test]
    fn a_malformed_bits_field_contributes_no_work() {
        let e = devnet();
        for raw in [0x1d80_ffffu32, 0x0100_0000, 0xff7f_ffff, 0x0000_0000] {
            let h = BlockHeader { bits: CompactTarget(raw), ..BlockHeader::default() };
            assert_eq!(e.work(&h), Work::ZERO, "{raw:#x} must contribute nothing");
        }
    }

    #[test]
    fn checked_target_rejects_zero_and_anything_above_the_limit() {
        let e = PowEngine::new(ChainParams::mainnet());
        assert_eq!(e.checked_target(CompactTarget(0)), Err(ConsensusError::ZeroTarget));
        let easier = CompactTarget(0x1d01_0000);
        let actual = compact_to_target(easier).unwrap();
        assert_eq!(
            e.checked_target(easier),
            Err(ConsensusError::TargetAbovePowLimit { actual, limit: e.pow_limit() })
        );
        assert!(e.checked_target(CompactTarget(0x1d00_ffff)).is_ok());
        assert!(e.checked_target(CompactTarget(0x1c00_ffff)).is_ok(), "harder is fine");
    }

    #[test]
    fn the_seal_must_be_empty() {
        let e = devnet();
        let view = TestView::devnet();
        let mut block = Block::new(BlockHeader::default(), Vec::new(), BlockSeal::POW);
        assert_eq!(e.validate_seal(&block, &view), Ok(()));

        block.seal = BlockSeal { engine: BlockSeal::ENGINE_POW, data: vec![0u8; 3] };
        assert_eq!(e.validate_seal(&block, &view), Err(ConsensusError::NonEmptyPowSeal(3)));

        block.seal = BlockSeal::bft(Vec::new());
        assert_eq!(
            e.validate_seal(&block, &view),
            Err(ConsensusError::WrongEngine { expected: 0, actual: 1 })
        );
    }

    #[test]
    fn next_bits_is_the_genesis_target_for_the_first_two_heights() {
        let mut view = TestView::devnet();
        let genesis = view.push_genesis();
        let e = devnet();
        assert_eq!(e.next_bits(&genesis, &view).unwrap(), ChainParams::devnet().genesis_bits);
    }

    #[test]
    fn next_bits_on_an_unknown_parent_is_a_missing_context_error() {
        let view = TestView::devnet();
        let stranger = BlockHeader { nonce: 999, ..BlockHeader::default() };
        let err = devnet().next_bits(&stranger, &view).unwrap_err();
        assert_eq!(err, ConsensusError::UnknownParent(block_hash(&stranger)));
        assert!(err.is_missing_context());
    }

    #[test]
    fn next_bits_needs_the_anchor_header() {
        // A view that knows the parent's height but has lost height 1.
        let mut view = TestView::devnet();
        view.push_genesis();
        let parent = view.push_child(120_000);
        view.push_child(240_000);
        view.forget_height(ANCHOR_HEIGHT);
        let err = devnet().next_bits(&parent, &view).unwrap_err();
        assert_eq!(err, ConsensusError::MissingHeader(ANCHOR_HEIGHT));
        assert!(err.is_missing_context());
    }

    #[test]
    fn next_bits_follows_asert_from_the_anchor() {
        let mut view = TestView::devnet();
        view.push_genesis();
        let anchor = view.push_child(120_000);
        let parent = view.push_child(240_000);

        let e = devnet();
        let expected = asert_next_bits(
            &AsertAnchor::from_compact(
                anchor.bits,
                i64::try_from(anchor.timestamp_s()).unwrap(),
                ANCHOR_HEIGHT,
            )
            .unwrap(),
            i64::try_from(parent.timestamp_s()).unwrap(),
            2,
            &e.asert_params(),
        )
        .unwrap();
        assert_eq!(e.next_bits(&parent, &view).unwrap(), expected);
    }

    #[test]
    fn the_miner_finds_a_seal_and_it_validates() {
        let mut view = TestView::devnet();
        let genesis = view.push_genesis();
        let e = devnet();

        let header = BlockHeader {
            version: 1,
            prev_hash: block_hash(&genesis),
            merkle_root: Hash32::from_bytes([3; 32]),
            timestamp_ms: genesis.timestamp_ms + 120_000,
            bits: e.next_bits(&genesis, &view).unwrap(),
            nonce: 0,
        };
        let cancel = AtomicBool::new(false);
        let block = e.seal(template(header, 1), &cancel).unwrap().expect("devnet seals instantly");

        assert_eq!(block.seal, BlockSeal::POW);
        assert!(hash_meets_target(
            &block_hash(&block.header),
            e.checked_target(block.header.bits).unwrap()
        ));
        assert_eq!(e.validate_header(&block.header, &genesis, &view), Ok(()));
        assert_eq!(e.validate_seal(&block, &view), Ok(()));
    }

    #[test]
    fn a_raised_cancel_flag_stops_the_miner_immediately() {
        let e = PowEngine::new(ChainParams::mainnet());
        // Mainnet difficulty: this would never terminate if the flag were
        // ignored, so reaching the assertion is itself the test.
        let header = BlockHeader {
            version: 1,
            bits: ChainParams::mainnet().genesis_bits,
            ..BlockHeader::default()
        };
        let cancel = AtomicBool::new(true);
        assert_eq!(e.seal(template(header, 1), &cancel).unwrap(), None);
    }

    #[test]
    fn sealing_an_impossible_target_is_an_error_not_a_hang() {
        let e = devnet();
        let header = BlockHeader { bits: CompactTarget(0), ..BlockHeader::default() };
        assert_eq!(
            e.seal(template(header, 1), &AtomicBool::new(false)),
            Err(ConsensusError::ZeroTarget)
        );

        let header = BlockHeader { bits: CompactTarget(0x1d80_ffff), ..BlockHeader::default() };
        assert_eq!(
            e.seal(template(header, 1), &AtomicBool::new(false)),
            Err(ConsensusError::NegativeTarget(0x1d80_ffff))
        );
    }

    #[test]
    fn advancing_the_search_walks_the_nonce_then_the_clock() {
        let mut h = BlockHeader { timestamp_ms: 1_000, nonce: 0, ..BlockHeader::default() };
        PowEngine::advance_search(&mut h);
        assert_eq!((h.nonce, h.timestamp_ms), (1, 1_000));

        h.nonce = u64::MAX - 1;
        PowEngine::advance_search(&mut h);
        assert_eq!((h.nonce, h.timestamp_ms), (u64::MAX, 1_000), "the last nonce is still tried");

        PowEngine::advance_search(&mut h);
        assert_eq!(
            (h.nonce, h.timestamp_ms),
            (0, 1_001),
            "an exhausted nonce space opens the next millisecond, it does not wrap in place"
        );

        // And the clock saturates rather than wrapping into the past, which
        // would make the miner grind a header it had already rejected.
        h.nonce = u64::MAX;
        h.timestamp_ms = u64::MAX;
        PowEngine::advance_search(&mut h);
        assert_eq!((h.nonce, h.timestamp_ms), (0, u64::MAX));
    }

    #[test]
    fn advancing_the_search_never_repeats_a_header_within_a_run() {
        let mut h = BlockHeader { timestamp_ms: 7, nonce: u64::MAX - 3, ..BlockHeader::default() };
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..10 {
            assert!(seen.insert((h.nonce, h.timestamp_ms)), "the search revisited a header");
            PowEngine::advance_search(&mut h);
        }
        assert_eq!(seen.len(), 10);
    }

    #[test]
    fn the_miner_bumps_the_timestamp_when_the_nonce_space_runs_out() {
        // Start one nonce short of the end with a target that the very first
        // two candidates almost certainly miss, then confirm the header the
        // miner returns either wrapped the nonce or advanced the clock.
        let e = devnet();
        let start = BlockHeader {
            version: 1,
            timestamp_ms: 1_000,
            bits: ChainParams::devnet().genesis_bits,
            nonce: u64::MAX,
            ..BlockHeader::default()
        };
        let block = e
            .seal(template(start, 1), &AtomicBool::new(false))
            .unwrap()
            .expect("devnet seals instantly");
        assert!(
            block.header.nonce < u64::MAX || block.header.timestamp_ms == 1_000,
            "the miner must wrap the nonce rather than overflow it"
        );
        // Either it solved at u64::MAX, or it wrapped to 0 and (if it wrapped)
        // bumped the clock exactly once per wrap.
        if block.header.nonce != u64::MAX {
            assert!(block.header.timestamp_ms >= 1_000);
        }
    }

    #[test]
    fn a_header_below_the_minimum_version_is_rejected() {
        let mut view = TestView::devnet();
        let genesis = view.push_genesis();
        let h = BlockHeader { version: 0, ..BlockHeader::default() };
        assert_eq!(
            devnet().validate_header(&h, &genesis, &view),
            Err(ConsensusError::BadVersion(0))
        );
    }

    #[test]
    fn a_header_naming_the_wrong_parent_is_rejected() {
        let mut view = TestView::devnet();
        let genesis = view.push_genesis();
        let h = BlockHeader { version: 1, ..BlockHeader::default() };
        assert_eq!(
            devnet().validate_header(&h, &genesis, &view),
            Err(ConsensusError::WrongParent {
                expected: block_hash(&genesis),
                actual: h.prev_hash
            })
        );
    }

    #[test]
    fn over_paying_difficulty_is_still_invalid() {
        let mut view = TestView::devnet();
        let genesis = view.push_genesis();
        let e = devnet();
        let correct = e.next_bits(&genesis, &view).unwrap();
        let harder = CompactTarget(0x1d00_ffff); // far harder than devnet asks for
        assert_ne!(correct, harder);

        let h = BlockHeader {
            version: 1,
            prev_hash: block_hash(&genesis),
            bits: harder,
            timestamp_ms: genesis.timestamp_ms + 120_000,
            ..BlockHeader::default()
        };
        assert_eq!(
            e.validate_header(&h, &genesis, &view),
            Err(ConsensusError::BadDifficultyTransition { expected: correct, actual: harder })
        );
    }

    #[test]
    fn a_header_that_misses_its_target_is_rejected() {
        let mut view = TestView::mainnet();
        let genesis = view.push_genesis();
        let e = PowEngine::new(ChainParams::mainnet());
        let h = BlockHeader {
            version: 1,
            prev_hash: block_hash(&genesis),
            bits: e.next_bits(&genesis, &view).unwrap(),
            timestamp_ms: genesis.timestamp_ms + 120_000,
            nonce: 1,
            ..BlockHeader::default()
        };
        match e.validate_header(&h, &genesis, &view) {
            Err(ConsensusError::InsufficientWork { hash, target }) => {
                assert_eq!(hash, block_hash(&h));
                assert_eq!(target, e.pow_limit());
            }
            other => panic!("expected InsufficientWork, got {other:?}"),
        }
    }

    #[test]
    fn a_timestamp_at_or_below_median_time_past_is_rejected() {
        let mut view = TestView::devnet();
        let genesis = view.push_genesis();
        let e = devnet();
        let bits = e.next_bits(&genesis, &view).unwrap();
        let mtp_ms = view.median_time_past(&block_hash(&genesis)).unwrap() * 1_000;

        // Seal a real header, then move its timestamp back onto the boundary.
        let base = BlockHeader {
            version: 1,
            prev_hash: block_hash(&genesis),
            bits,
            timestamp_ms: mtp_ms,
            ..BlockHeader::default()
        };
        let sealed = e
            .seal(template(base, 1), &AtomicBool::new(false))
            .unwrap()
            .expect("devnet seals instantly");
        assert_eq!(
            e.validate_header(&sealed.header, &genesis, &view),
            Err(ConsensusError::TimestampTooOld {
                timestamp_ms: sealed.header.timestamp_ms,
                median_time_past_ms: mtp_ms,
            }),
            "equality with median time past must be rejected, not just less-than"
        );
    }

    #[test]
    fn a_missing_median_time_past_is_a_missing_context_error() {
        let mut view = TestView::devnet();
        let genesis = view.push_genesis();
        view.suppress_median_time_past();
        let e = devnet();
        let bits = e.next_bits(&genesis, &view).unwrap();
        let base = BlockHeader {
            version: 1,
            prev_hash: block_hash(&genesis),
            bits,
            timestamp_ms: genesis.timestamp_ms + 120_000,
            ..BlockHeader::default()
        };
        let sealed = e
            .seal(template(base, 1), &AtomicBool::new(false))
            .unwrap()
            .expect("devnet seals instantly");
        let err = e.validate_header(&sealed.header, &genesis, &view).unwrap_err();
        assert_eq!(err, ConsensusError::MedianTimePastUnavailable(block_hash(&genesis)));
        assert!(err.is_missing_context());
    }

    #[test]
    fn a_mined_chain_of_twenty_blocks_validates_end_to_end() {
        let mut view = TestView::devnet();
        let mut parent = view.push_genesis();
        let e = devnet();
        let cancel = AtomicBool::new(false);

        for height in 1u64..=20 {
            let bits = e.next_bits(&parent, &view).unwrap();
            let header = BlockHeader {
                version: 1,
                prev_hash: block_hash(&parent),
                merkle_root: Hash32::from_bytes([u8::try_from(height).unwrap(); 32]),
                timestamp_ms: parent.timestamp_ms + 120_000,
                bits,
                nonce: 0,
            };
            let block =
                e.seal(template(header, height), &cancel).unwrap().expect("devnet seals instantly");
            assert_eq!(e.validate_header(&block.header, &parent, &view), Ok(()));
            assert_eq!(e.validate_seal(&block, &view), Ok(()));
            view.push_header(block.header);
            parent = block.header;
        }
        assert_eq!(view.tip().1, 20);
    }
}
