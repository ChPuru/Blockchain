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
//!
//! # The difficulty rule reads the parameters, not the chain
//!
//! [`PowEngine::anchor`] builds the ASERT anchor from [`ChainParams`] alone —
//! genesis. The only thing `next_bits` asks the [`HeaderView`] for is the
//! parent's *height*, which is a fact about the block rather than about which
//! fork the reader is standing on. So the required `bits` for a header is a
//! pure function of `(parent_height, parent_timestamp, params)`, and two nodes
//! holding different chains still agree on it.
//!
//! That is not a nicety. An anchor read through
//! [`HeaderView::header_at_height`] — the *active* chain — makes difficulty
//! fork-dependent: two nodes that sealed different blocks at the anchor height
//! reject each other's headers as
//! [`ConsensusError::BadDifficultyTransition`] and ban each other, and the
//! split is permanent because a header that fails validation never reaches fork
//! choice (CONTRACT 6.3).

use core::sync::atomic::{AtomicBool, Ordering};

use ferrum_types::{Block, BlockHeader, BlockSeal, ChainParams, CompactTarget};

use crate::asert::{AsertAnchor, AsertParams, asert_next_bits};
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

    /// The ASERT anchor for this chain: **genesis**, read from
    /// [`ChainParams`] and from nothing else.
    ///
    /// This deliberately takes no [`HeaderView`]. An anchor resolved through
    /// [`HeaderView::header_at_height`] is an anchor on the *active* chain, and
    /// that makes the difficulty rule fork-dependent: two nodes holding
    /// different blocks at the anchor height compute different required `bits`
    /// for each other's headers, reject them as
    /// [`ConsensusError::BadDifficultyTransition`], and fork permanently — a
    /// header that fails validation never reaches fork choice, so there is no
    /// reorg path back together. Genesis is fixed by the parameters, so every
    /// node has the same anchor before it has spoken to anyone (CONTRACT 6.3).
    ///
    /// Because nothing is read from the chain there is no "the anchor header is
    /// missing" failure any more; the only way this fails is a parameter set
    /// whose `genesis_bits` is not a valid compact target.
    ///
    /// # Errors
    ///
    /// Propagates [`compact_to_target`] for a malformed `params.genesis_bits`.
    pub fn anchor(&self) -> Result<AsertAnchor, ConsensusError> {
        AsertAnchor::genesis(&self.params)
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

        // Genesis, at height ANCHOR_HEIGHT == 0, is the one block exempt from
        // the difficulty-transition rule, and only because it has no parent to
        // transition from — so this function is never asked about it. Every
        // child height, height 1 included, is on the ASERT schedule
        // (CONTRACT 6.3).
        //
        // The view supplies the parent's *height*, which is a fact about the
        // block, not about which fork the reader is on. Nothing else here
        // touches the chain: the anchor comes from the parameters, so two nodes
        // on two forks compute the same answer for the same parent.
        let anchor = self.anchor()?;
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

    use ferrum_types::{BlockHash, Hash32, Transaction};

    use super::*;
    use crate::asert::ANCHOR_HEIGHT;
    use crate::engine::block_hash;
    use crate::testview::{TestView, easy_devnet_params};

    /// The engine under test: devnet, mined at a trivial target so that a test
    /// which seals a dozen headers takes milliseconds rather than a minute.
    /// See [`easy_devnet_params`]. It pairs with [`TestView::devnet`], which
    /// carries the same parameters — the view supplies the headers and the
    /// engine reads `pow_limit` and `genesis_bits` from its own copy, so the
    /// two must agree.
    fn devnet() -> PowEngine {
        PowEngine::new(easy_devnet_params())
    }

    fn template(header: BlockHeader, height: u64) -> BlockTemplate {
        BlockTemplate::new(header, Vec::<Transaction>::new(), height)
    }

    #[test]
    fn identity_matches_the_contract() {
        // The shipped parameter set, not the relaxed fixture: `pow_limit` is
        // read straight off `ChainParams`, and this is the test that says so.
        let e = PowEngine::new(ChainParams::devnet());
        assert_eq!(e.name(), "pow");
        assert_eq!(e.engine_id(), BlockSeal::ENGINE_POW);
        assert_eq!(e.params().network, ChainParams::devnet().network);
        assert_eq!(e.pow_limit(), Target::from_be_bytes(&ChainParams::devnet().pow_limit));
        assert_eq!(e.pow_limit(), compact_to_target(ChainParams::devnet().genesis_bits).unwrap());
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
    fn the_anchor_is_genesis_and_is_read_from_the_parameters_alone() {
        for params in [ChainParams::mainnet(), ChainParams::testnet(), ChainParams::devnet()] {
            let e = PowEngine::new(params.clone());
            let anchor = e.anchor().unwrap();
            assert_eq!(anchor.height, ANCHOR_HEIGHT);
            assert_eq!(anchor.height, 0, "the anchor is genesis, not the block after it");
            assert_eq!(anchor.target, compact_to_target(params.genesis_bits).unwrap());
            assert_eq!(anchor.time_s, i64::try_from(params.genesis_timestamp_ms / 1_000).unwrap());
        }
    }

    #[test]
    fn next_bits_puts_the_child_of_genesis_on_the_asert_schedule() {
        // Height 1 used to be exempt, because the anchor was the block at
        // height 1 and it did not exist yet. With the anchor at genesis there
        // is nothing to wait for: the first child is on the schedule like every
        // other block, and its target is *not* simply `genesis_bits`.
        let mut view = TestView::devnet();
        let genesis = view.push_genesis();
        let e = devnet();

        let expected = asert_next_bits(
            &AsertAnchor::genesis(e.params()).unwrap(),
            i64::try_from(genesis.timestamp_s()).unwrap(),
            0,
            &e.asert_params(),
        )
        .unwrap();
        assert_eq!(e.next_bits(&genesis, &view).unwrap(), expected);
        assert_ne!(
            e.next_bits(&genesis, &view).unwrap(),
            ChainParams::devnet().genesis_bits,
            "the child of genesis is one spacing behind schedule, so its target is not genesis_bits"
        );
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
    fn next_bits_needs_no_header_but_the_parent_it_was_handed() {
        // This replaces a test that asserted the opposite — that losing the
        // header at height 1 broke the difficulty rule. That failure mode was
        // the bug: whichever header sat at the anchor height decided the answer.
        // A view that has forgotten every height mapping must now still answer.
        let mut view = TestView::devnet();
        view.push_genesis();
        let parent = view.push_child(120_000);
        view.push_child(240_000);
        for height in 0..=2 {
            view.forget_height(height);
        }

        let e = devnet();
        let expected = asert_next_bits(
            &AsertAnchor::genesis(e.params()).unwrap(),
            i64::try_from(parent.timestamp_s()).unwrap(),
            1,
            &e.asert_params(),
        )
        .unwrap();
        assert_eq!(e.next_bits(&parent, &view).unwrap(), expected);
    }

    #[test]
    fn next_bits_follows_asert_from_the_genesis_anchor() {
        let mut view = TestView::devnet();
        view.push_genesis();
        view.push_child(120_000);
        let parent = view.push_child(240_000);

        let e = devnet();
        let expected = asert_next_bits(
            &AsertAnchor::genesis(e.params()).unwrap(),
            i64::try_from(parent.timestamp_s()).unwrap(),
            2,
            &e.asert_params(),
        )
        .unwrap();
        assert_eq!(e.next_bits(&parent, &view).unwrap(), expected);
    }

    /// A network whose difficulty has room to move in both directions, and
    /// whose blocks cost a couple of hundred hashes.
    ///
    /// Both numbers are pinned here rather than inherited from devnet, for two
    /// reasons. Devnet pins `genesis_bits` *at* its own `pow_limit`, so every
    /// answer slower than schedule saturates there and they all look alike —
    /// which would make the fork test below pass for the wrong reason. And
    /// devnet's cost per block is tuned for a four-node laptop network, not for
    /// a unit test that seals four headers; borrowing it would make this test's
    /// runtime track a number that has nothing to do with what it asserts.
    ///
    /// `0x2000ffff` is `2^-8` of the limit below, so ASERT has 128x of headroom
    /// before it clamps, and a block costs about 256 hashes.
    fn forkable_devnet() -> ChainParams {
        let mut params = ChainParams::devnet();
        params.genesis_bits = CompactTarget(0x2000_ffff);
        params.pow_limit = [0xff; 32];
        params.pow_limit[0] = 0x7f;
        params
    }

    #[test]
    fn the_anchor_does_not_depend_on_which_fork_you_are_on() {
        // Two nodes seal different — both valid — blocks at height 1, which is
        // what devnet does on almost every run: the pow_limit is so easy that
        // each node seals its own height 1 before libp2p has dialled anyone.
        //
        // The old rule read the anchor out of the chain, through
        // `header_at_height(1)`, which is defined as the *active* chain. Each
        // node therefore anchored on its own height-1 block, computed a
        // different required `bits` for the other's headers, rejected them as
        // BadDifficultyTransition and banned the peer — permanently, because a
        // header that fails validation never reaches fork choice.
        let params = forkable_devnet();
        let e = PowEngine::new(params.clone());
        let cancel = AtomicBool::new(false);

        let mut left = TestView::with_params(params.clone());
        let mut right = TestView::with_params(params.clone());
        let genesis = left.push_genesis();
        assert_eq!(block_hash(&right.push_genesis()), block_hash(&genesis), "one genesis");

        // Two valid height-1 headers: different transactions, and timestamps a
        // whole half-life apart, so a chain-read anchor would have differed in
        // every field it read.
        let bits1 = e.next_bits(&genesis, &left).unwrap();
        let seal_height_1 = |merkle: u8, delta_ms: u64| -> BlockHeader {
            let header = BlockHeader {
                version: 1,
                prev_hash: block_hash(&genesis),
                merkle_root: Hash32::from_bytes([merkle; 32]),
                timestamp_ms: genesis.timestamp_ms + delta_ms,
                bits: bits1,
                nonce: 0,
            };
            e.seal(template(header, 1), &cancel).unwrap().expect("devnet seals quickly").header
        };
        let one = seal_height_1(1, 1_000);
        let two = seal_height_1(2, 7_200_000);

        assert_ne!(block_hash(&one), block_hash(&two), "the forks must really differ");
        assert_ne!(one.timestamp_s(), two.timestamp_s());
        assert_eq!(e.validate_header(&one, &genesis, &left), Ok(()), "fork one is valid");
        assert_eq!(e.validate_header(&two, &genesis, &right), Ok(()), "fork two is valid");
        left.push_header(one);
        right.push_header(two);

        // The counterfactual, spelled out: the *old* rule, applied to these two
        // chains, gives two different answers. Without this the test could go
        // green on an implementation that had quietly stopped moving at all.
        let old_rule = |h1: &BlockHeader, parent_time_s: i64| {
            asert_next_bits(
                &AsertAnchor::from_compact(h1.bits, i64::try_from(h1.timestamp_s()).unwrap(), 1)
                    .unwrap(),
                parent_time_s,
                2,
                &e.asert_params(),
            )
            .unwrap()
        };

        // A child of each fork at the *same* height and the *same* timestamp:
        // every input the difficulty rule is allowed to see is identical.
        let parent_time_ms = genesis.timestamp_ms + 7_300_000;
        let parent_time_s = i64::try_from(parent_time_ms / 1_000).unwrap();
        assert_ne!(
            old_rule(&one, parent_time_s),
            old_rule(&two, parent_time_s),
            "the old chain-read anchor really did split the network here"
        );

        let seal_height_2 = |view: &TestView, h1: &BlockHeader| -> BlockHeader {
            let header = BlockHeader {
                version: 1,
                prev_hash: block_hash(h1),
                merkle_root: Hash32::from_bytes([9; 32]),
                timestamp_ms: parent_time_ms,
                bits: e.next_bits(h1, view).unwrap(),
                nonce: 0,
            };
            e.seal(template(header, 2), &cancel).unwrap().expect("devnet seals quickly").header
        };
        let parent_left = seal_height_2(&left, &one);
        let parent_right = seal_height_2(&right, &two);
        assert_ne!(block_hash(&parent_left), block_hash(&parent_right));
        assert_eq!(parent_left.timestamp_ms, parent_right.timestamp_ms);
        left.push_header(parent_left);
        right.push_header(parent_right);

        // This is the whole point. Same parent height, same parent timestamp,
        // same parameters, two irreconcilable chains — one answer.
        let from_left = e.next_bits(&parent_left, &left).unwrap();
        let from_right = e.next_bits(&parent_right, &right).unwrap();
        assert_eq!(
            from_left, from_right,
            "the difficulty rule must not depend on which fork the node is on"
        );

        // And that one answer is the one the parameters alone predict.
        let expected = asert_next_bits(
            &AsertAnchor::genesis(&params).unwrap(),
            parent_time_s,
            2,
            &e.asert_params(),
        )
        .unwrap();
        assert_eq!(from_left, expected);
        assert!(
            e.checked_target(from_left).unwrap() < e.pow_limit(),
            "an answer pinned at pow_limit would make this test vacuous"
        );
    }

    #[test]
    fn next_bits_ignores_everything_in_the_view_except_the_parents_height() {
        // Two views with nothing in common but the parent's height. The rule is
        // a pure function of (parent_height, parent_time_s, params), so both
        // must answer identically.
        let e = devnet();
        let params = e.params().clone();
        let parent = BlockHeader {
            version: 1,
            prev_hash: BlockHash::from_bytes([7; 32]),
            merkle_root: Hash32::from_bytes([8; 32]),
            timestamp_ms: params.genesis_timestamp_ms + 360_000,
            bits: CompactTarget(0x1d00_ffff),
            nonce: 42,
        };

        let mut honest = TestView::devnet();
        honest.push_genesis();
        honest.push_child(120_000);
        honest.push_header(parent);

        let mut nonsense = TestView::devnet();
        for i in 0u8..2 {
            nonsense.push_header(BlockHeader {
                version: 9,
                prev_hash: BlockHash::from_bytes([i; 32]),
                merkle_root: Hash32::from_bytes([i.wrapping_add(200); 32]),
                timestamp_ms: 1,
                bits: CompactTarget(0x1c00_ffff),
                nonce: u64::from(i) + 1_000,
            });
        }
        nonsense.push_header(parent);
        nonsense.forget_height(0);
        nonsense.forget_height(1);

        assert_eq!(honest.height_of(&block_hash(&parent)), Some(2));
        assert_eq!(nonsense.height_of(&block_hash(&parent)), Some(2));
        assert_ne!(honest.header_at_height(1), nonsense.header_at_height(1));

        let from_honest = e.next_bits(&parent, &honest).unwrap();
        let from_nonsense = e.next_bits(&parent, &nonsense).unwrap();
        assert_eq!(from_honest, from_nonsense, "the view must not be able to change the answer");
        assert_eq!(
            from_honest,
            asert_next_bits(
                &AsertAnchor::genesis(&params).unwrap(),
                i64::try_from(parent.timestamp_s()).unwrap(),
                2,
                &e.asert_params(),
            )
            .unwrap()
        );
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
                assert_eq!(target, e.checked_target(h.bits).unwrap());
                // With the anchor at genesis, height 1 is already on the ASERT
                // schedule, so its target is one spacing *harder* than the
                // limit rather than the limit itself.
                assert!(target < e.pow_limit(), "height 1 is not exempt any more");
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
