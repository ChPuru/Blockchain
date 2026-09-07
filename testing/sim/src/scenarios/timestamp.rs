//! **Attack:** move block timestamps to steer the difficulty controller.
//!
//! A miner writes its own header, so it writes its own timestamp. On a chain
//! that retargets from recent history that is leverage: report late timestamps
//! and the next target gets easier; alternate late and early ones and a naive
//! controller oscillates. Several small chains have been mined into the ground
//! this way.
//!
//! Ferrum's defence is three rules that interlock:
//!
//! 1. **`timestamp_ms > median_time_past(parent) * 1000`, strictly.** The
//!    median of the last eleven headers cannot be moved by a minority miner,
//!    and equality is rejected so the clock cannot be frozen across a whole
//!    window ([`ferrum_consensus::ConsensusError::TimestampTooOld`]).
//! 2. **`bits == next_bits(parent)`, exactly.** There is one correct target per
//!    parent; a block that *over*-pays difficulty is just as invalid as one
//!    that under-pays ([`ferrum_consensus::ConsensusError::BadDifficultyTransition`]). This rule
//!    needs the header chain, so it lives in the engine rather than inside the
//!    pure state-transition seam.
//! 3. **ASERT is stateless with respect to recent history.** `next_bits`
//!    depends only on a fixed anchor and the parent's height and timestamp, so
//!    a manipulated timestamp affects exactly one block and is then forgotten.
//!    A controller that averaged an epoch would carry the manipulation forward
//!    and could be driven by alternating stamps.
//!
//! **Red:** a frozen timestamp and a self-chosen target are both rejected by
//! name.
//! **Green:** the controller responds in the right direction to a fast and a
//! slow chain, and a single manipulated timestamp moves one target and *no
//! others* — two chains that differ only in one intermediate stamp compute the
//! same target for the block after, bit for bit.

use ferrum_consensus::{ConsensusEngine, PowEngine, Target, compact_to_target};
use ferrum_types::{BlockHeader, ChainParams, CompactTarget};

use crate::chain_builder::{BlockPlan, ChainBuilder};
use crate::error::SimError;
use crate::scenarios::{Verdict, judge};

/// Devnet with a starting target well below `pow_limit`.
///
/// On any shipped network the genesis target *is* the `pow_limit`, so ASERT has
/// nowhere to go when a chain runs slow: every easier target clamps back to the
/// limit and the controller looks inert. These parameters keep the trivial
/// `sim_params` limit but start the chain 128x below it, leaving headroom above
/// and unlimited room below, while still costing about 256 hashes per block —
/// so difficulty is observable without making the fixtures slow.
#[must_use]
pub fn retarget_params() -> ChainParams {
    let mut params = crate::sim_params();
    params.genesis_bits = CompactTarget(0x2000_ffff);
    params
}

/// Judge a block whose header carries `timestamp_ms`.
///
/// # Errors
///
/// [`SimError`] if the block cannot be built or the executors disagree.
pub fn block_stamped(chain: &mut ChainBuilder, timestamp_ms: u64) -> Result<Verdict, SimError> {
    let ctx = chain.next_ctx()?;
    let pre = chain.state_view();
    let block = chain
        .build_block(&BlockPlan { timestamp_ms: Some(timestamp_ms), ..BlockPlan::default() })?;
    judge(&pre, &block, &ctx)
}

/// The target the difficulty rule requires for the next block.
///
/// # Errors
///
/// [`SimError::Consensus`] when ASERT cannot produce a target.
pub fn next_target(chain: &ChainBuilder) -> Result<Target, SimError> {
    Ok(compact_to_target(chain.next_bits()?)?)
}

/// Run the engine's header check over `header`.
///
/// The difficulty transition lives here rather than in `apply_block`: it needs
/// the header chain, and the state-transition seam is kept free of anything it
/// cannot compute from its three arguments.
///
/// # Errors
///
/// [`SimError::Consensus`] with the engine's verdict, and
/// [`SimError::Fixture`] when the chain has no tip.
pub fn engine_header_verdict(chain: &ChainBuilder, header: &BlockHeader) -> Result<(), SimError> {
    let engine = PowEngine::new(chain.params().clone());
    let parent = chain.tip_header()?;
    engine.validate_header(header, &parent, &chain.header_view())?;
    Ok(())
}

/// Build a chain of `height` blocks whose block `at` is stamped `late_ms`
/// later than the schedule; every other block is exactly on schedule.
///
/// `at == 0` means "no manipulation", which is the control chain.
///
/// # Errors
///
/// [`SimError`] if a block cannot be built.
pub fn chain_with_one_late_stamp(
    params: ChainParams,
    seed: u64,
    height: u64,
    at: u64,
    late_ms: u64,
) -> Result<ChainBuilder, SimError> {
    let mut chain = ChainBuilder::new(params, seed)?;
    let spacing = chain.params().target_spacing_ms;
    let genesis_ms = chain.params().genesis_timestamp_ms;
    for h in 1..=height {
        let mut stamp = genesis_ms.saturating_add(spacing.saturating_mul(h));
        if h == at {
            stamp = stamp.saturating_add(late_ms);
        }
        let block =
            chain.build_block(&BlockPlan { timestamp_ms: Some(stamp), ..BlockPlan::default() })?;
        chain.connect(&block);
    }
    Ok(chain)
}

/// Build a chain running `speedup` times faster than the target spacing.
///
/// # Errors
///
/// [`SimError`] if a block cannot be built.
pub fn fast_chain(
    params: ChainParams,
    seed: u64,
    height: u64,
    speedup: u64,
) -> Result<ChainBuilder, SimError> {
    let mut chain = ChainBuilder::new(params, seed)?;
    let spacing = chain.params().target_spacing_ms;
    let genesis_ms = chain.params().genesis_timestamp_ms;
    let step = spacing.checked_div(speedup.max(1)).unwrap_or(spacing);
    for h in 1..=height {
        let stamp = genesis_ms.saturating_add(step.saturating_mul(h));
        let block =
            chain.build_block(&BlockPlan { timestamp_ms: Some(stamp), ..BlockPlan::default() })?;
        chain.connect(&block);
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_chain::ValidationError;
    use ferrum_consensus::{AsertAnchor, ConsensusError, U256, asert_next_bits};

    use super::*;
    use crate::prng::XorShift64;

    const TWO_HOURS_MS: u64 = 7_200_000;
    const RETARGET_HEIGHT: u64 = 24;

    fn devnet_chain(n: usize) -> ChainBuilder {
        let mut c = ChainBuilder::devnet(XorShift64::SCENARIO_SEED).unwrap();
        c.advance(n).unwrap();
        c
    }

    fn on_schedule(seed: u64) -> ChainBuilder {
        chain_with_one_late_stamp(retarget_params(), seed, RETARGET_HEIGHT, 0, 0).unwrap()
    }

    // ---- red -----------------------------------------------------------

    #[test]
    fn a_timestamp_equal_to_median_time_past_is_rejected() {
        let mut c = devnet_chain(15);
        let mtp_ms = c.median_time_past(c.height()) * 1_000;
        match block_stamped(&mut c, mtp_ms).unwrap().rejection() {
            Some(ValidationError::Header(ConsensusError::TimestampTooOld {
                timestamp_ms,
                median_time_past_ms,
            })) => {
                assert_eq!(*timestamp_ms, mtp_ms);
                assert_eq!(*median_time_past_ms, mtp_ms);
            }
            other => panic!("expected TimestampTooOld, got {other:?}"),
        }
    }

    #[test]
    fn a_timestamp_before_median_time_past_is_rejected() {
        let mut c = devnet_chain(15);
        let mtp_ms = c.median_time_past(c.height()) * 1_000;
        assert!(matches!(
            block_stamped(&mut c, mtp_ms.saturating_sub(1)).unwrap().rejection(),
            Some(ValidationError::Header(ConsensusError::TimestampTooOld { .. }))
        ));
    }

    #[test]
    fn a_self_chosen_easier_target_is_rejected_by_the_engine() {
        let mut chain = on_schedule(101);
        let required = chain.next_bits().unwrap();
        let easier = chain.params().genesis_bits;
        assert_ne!(easier, required, "the fixture must actually differ from the rule");
        let candidate =
            chain.build_block(&BlockPlan { bits: Some(easier), ..BlockPlan::default() }).unwrap();
        match engine_header_verdict(&chain, &candidate.header).unwrap_err() {
            SimError::Consensus(ConsensusError::BadDifficultyTransition { expected, actual }) => {
                assert_eq!(expected, required);
                assert_eq!(actual, easier);
            }
            other => panic!("expected BadDifficultyTransition, got {other}"),
        }
    }

    #[test]
    fn a_self_chosen_harder_target_is_rejected_too() {
        // Over-paying difficulty is not generosity: there is exactly one
        // correct target per parent, and accepting a harder one would let a
        // miner fork the chain by choosing a different rule.
        let mut chain = on_schedule(102);
        let required = chain.next_bits().unwrap();
        let harder = CompactTarget(required.to_u32().saturating_sub(1));
        let candidate =
            chain.build_block(&BlockPlan { bits: Some(harder), ..BlockPlan::default() }).unwrap();
        assert!(matches!(
            engine_header_verdict(&chain, &candidate.header).unwrap_err(),
            SimError::Consensus(ConsensusError::BadDifficultyTransition { .. })
        ));
    }

    #[test]
    fn a_minority_miner_cannot_drag_the_median_backwards() {
        // Median time past is the median of eleven headers, so a run of blocks
        // stamped as early as the rule allows still cannot move it backwards.
        let mut honest = devnet_chain(20);
        let base = honest.median_time_past(honest.height());
        for _ in 0..5 {
            let mtp_ms = honest.median_time_past(honest.height()) * 1_000;
            let block = honest
                .build_block(&BlockPlan {
                    timestamp_ms: Some(mtp_ms.saturating_add(1)),
                    ..BlockPlan::default()
                })
                .unwrap();
            honest.connect(&block);
        }
        let after = honest.median_time_past(honest.height());
        assert!(after >= base, "the median never moves backwards: {base} -> {after}");
    }

    // ---- green ---------------------------------------------------------

    #[test]
    fn one_more_millisecond_than_median_time_past_is_accepted() {
        let mut c = devnet_chain(15);
        let mtp_ms = c.median_time_past(c.height()) * 1_000;
        assert!(block_stamped(&mut c, mtp_ms.saturating_add(1)).unwrap().is_accepted());
    }

    #[test]
    fn a_late_parent_makes_the_next_target_easier() {
        let control = on_schedule(11);
        let late = chain_with_one_late_stamp(
            retarget_params(),
            11,
            RETARGET_HEIGHT,
            RETARGET_HEIGHT,
            TWO_HOURS_MS,
        )
        .unwrap();
        assert!(
            next_target(&late).unwrap() > next_target(&control).unwrap(),
            "a chain running behind schedule must get an easier target"
        );
    }

    #[test]
    fn a_ten_times_faster_chain_gets_a_harder_target() {
        let control = on_schedule(12);
        let fast = fast_chain(retarget_params(), 12, RETARGET_HEIGHT, 10).unwrap();
        assert!(
            next_target(&fast).unwrap() < next_target(&control).unwrap(),
            "a chain running ahead of schedule must get a harder target"
        );
    }

    #[test]
    fn a_manipulated_timestamp_is_forgotten_by_the_next_block() {
        // The heart of the scenario. Two chains identical except that block
        // `RETARGET_HEIGHT - 1` of one is stamped two hours late. The final
        // block carries the same timestamp in both. ASERT depends only on the
        // anchor and the parent, so the target for the next block must be
        // *bit for bit* the same: the manipulation has no memory.
        let honest = on_schedule(13);
        let manipulated = chain_with_one_late_stamp(
            retarget_params(),
            13,
            RETARGET_HEIGHT,
            RETARGET_HEIGHT - 1,
            TWO_HOURS_MS,
        )
        .unwrap();

        assert_eq!(honest.height(), RETARGET_HEIGHT);
        assert_eq!(manipulated.height(), RETARGET_HEIGHT);
        let last = usize::try_from(RETARGET_HEIGHT).unwrap();
        assert_eq!(
            honest.headers()[last].timestamp_ms,
            manipulated.headers()[last].timestamp_ms,
            "the final block carries the same timestamp in both chains"
        );
        assert_ne!(
            honest.headers()[last - 1].timestamp_ms,
            manipulated.headers()[last - 1].timestamp_ms,
            "the block before is where they differ"
        );
        assert_eq!(
            honest.next_bits().unwrap(),
            manipulated.next_bits().unwrap(),
            "an absolute-schedule controller has no memory of a manipulated stamp"
        );
    }

    #[test]
    fn the_first_block_is_on_the_asert_schedule_like_every_other() {
        // The anchor is genesis itself (CONTRACT §6.3), so height 1 is not
        // exempt from the controller the way it used to be: its target is what
        // ASERT says for a parent at height 0, not `genesis_bits` copied
        // forward. Asserting against the controller rather than against a
        // literal keeps this honest whether or not the answer meets the
        // `pow_limit` clamp on the way out.
        let c = ChainBuilder::new(retarget_params(), 14).unwrap();
        let params = c.params().clone();
        let engine = PowEngine::new(params.clone());
        let anchor = AsertAnchor::genesis(&params).unwrap();
        let expected = asert_next_bits(
            &anchor,
            i64::try_from(params.genesis_timestamp_ms / 1_000).unwrap(),
            0,
            &engine.asert_params(),
        )
        .unwrap();
        assert_eq!(c.next_bits().unwrap(), expected);
    }

    #[test]
    fn an_on_schedule_chain_holds_its_difficulty_within_a_few_percent() {
        // "Steady" is a numeric claim, not a direction: over two dozen blocks
        // on schedule the target must stay within a few percent of the anchor.
        let c = on_schedule(15);
        let anchor = compact_to_target(c.params().genesis_bits).unwrap();
        let actual = next_target(&c).unwrap();
        let low = Target(anchor.0 / U256::from(100u32) * U256::from(95u32));
        let high = Target(anchor.0 / U256::from(100u32) * U256::from(105u32));
        assert!(actual >= low && actual <= high, "target drifted: {actual} vs anchor {anchor}");
    }

    #[test]
    fn the_manipulated_block_itself_is_still_a_valid_block() {
        // The attack is rejected by the difficulty rule, not by pretending the
        // late block never existed: a two-hour-late stamp is legal, it just
        // buys nothing.
        let mut chain =
            chain_with_one_late_stamp(retarget_params(), 16, 12, 12, TWO_HOURS_MS).unwrap();
        assert_eq!(chain.height(), 12);
        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        let block = chain.build_block(&BlockPlan::default()).unwrap();
        assert!(judge(&pre, &block, &ctx).unwrap().is_accepted());
    }
}
