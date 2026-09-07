//! ASERT (`aserti3-2d`) — the difficulty controller, integer only.
//!
//! # Why ASERT rather than Bitcoin's retarget (SPEC 6.1)
//!
//! Bitcoin adjusts every 2016 blocks with a 4x clamp. On a chain with no
//! security budget that is fatal: rented hashrate mines an epoch cheaply,
//! leaves, and the honest remainder faces a clamped difficulty for weeks with
//! no mechanism to escape.
//!
//! ASERT is an *absolute-schedule* exponential controller. The next target
//! depends only on a fixed **anchor** block and the parent's height and
//! timestamp — never on recent history — so it has no oscillation mode, cannot
//! be driven by an alternating-timestamp attack, and self-corrects after a
//! manipulated timestamp instead of amplifying it.
//!
//! # The anchor is genesis, and it is read from `ChainParams` (CONTRACT 6.3)
//!
//! [`ANCHOR_HEIGHT`] is `0`. [`AsertAnchor::genesis`] builds the anchor from
//! [`ChainParams::genesis_bits`] and [`ChainParams::genesis_timestamp_ms`], so
//! every node on a network has byte-identical anchor values by construction and
//! the required `bits` for a header is a pure function of
//! `(parent_height, parent_time_s, params)`.
//!
//! **The anchor must never be read out of the chain.** This was originally
//! specified and implemented as "the block at height 1, via
//! `HeaderView::header_at_height`", and that is a consensus bug: that method is
//! defined as the *active* chain, so two nodes that sealed different height-1
//! blocks compute different required `bits` for each other's headers, reject
//! them as [`ConsensusError::BadDifficultyTransition`], and ban each other. The
//! resulting fork is permanent and unrecoverable, because a header that fails
//! validation never reaches fork choice at all — there is no reorg path out.
//! It is not a small-network artefact either: *any* two nodes that disagree
//! about the anchor disagree about difficulty forever. Bitcoin Cash's
//! `aserti3-2d` pins a fixed anchor for exactly this reason.
//!
//! Genesis is the only block every node is guaranteed to agree on before it has
//! spoken to anybody, which is what makes it the one safe anchor.
//!
//! # The algorithm (CONTRACT 6.3, SPEC 6.2)
//!
//! ```text
//! time_diff   = parent_time_s - anchor_time_s
//! height_diff = parent_height - anchor_height
//! exponent    = ((time_diff - target_spacing_s * (height_diff + 1)) * 65536) / halflife_s
//!
//! shifts      = exponent >> 16            // arithmetic shift: floor division
//! frac        = exponent & 0xffff         // always in [0, 65536)
//!
//! factor      = 65536 + ((195_766_423_245_049 * frac
//!                       +     971_821_376 * frac^2
//!                       +           5_127 * frac^3
//!                       + (1 << 47)) >> 48)
//!
//! next_target = anchor_target * factor
//! next_target = shifts < 0 ? next_target >> -shifts : next_target << shifts
//! next_target = next_target >> 16
//!
//! if next_target == 0        -> 1
//! if next_target > pow_limit -> pow_limit
//! ```
//!
//! Three details are load-bearing:
//!
//! 1. **The division producing `exponent` truncates toward zero**, and the
//!    split into `shifts`/`frac` then uses a *floor* division so that `frac`
//!    stays in `[0, 65536)` even when `exponent` is negative. A truncating
//!    division in the split is a real and easy bug: it makes difficulty drift
//!    asymmetrically between speed-ups and slow-downs. This implementation uses
//!    [`i64::div_euclid`] and [`i64::rem_euclid`], which are floor division and
//!    a non-negative remainder for a positive divisor — exactly `>> 16` and
//!    `& 0xffff` on a two's-complement machine, expressed without a raw shift.
//! 2. **Every intermediate is `u128` or `U256`/`U512`.** The product
//!    `anchor_target * factor` is computed as a widening 512-bit multiply, so
//!    the `>> 16` that follows loses nothing. A left shift whose result would
//!    exceed 256 bits saturates to `pow_limit`.
//! 3. **No floats.** A float here produces platform-dependent rounding, two
//!    nodes compute different targets from the same inputs, and the chain
//!    splits along CPU architecture lines.
//!
//! # The exponent clamp
//!
//! `exponent` is clamped to [`EXPONENT_CLAMP`] before the split. This is not an
//! approximation: `shifts >= +512` always overflows 256 bits (the product is at
//! least `65536`, so `bits >= 17`), and `shifts <= -512` always shifts the
//! at-most-273-bit product to zero. Both ends therefore already saturate, so
//! clamping cannot change an answer — it only keeps the arithmetic inside
//! `i64` and keeps the Python reference from allocating a gigabit integer.
//!
//! # Cross-checking
//!
//! `testing/reference/asert.py` is an independent implementation written from
//! the paragraph above, and `testing/reference/asert_vectors.json` holds the
//! cases both must agree on exactly. `tests/asert_vectors.rs` is the Rust half
//! of that gate.

use ferrum_types::{ChainParams, CompactTarget};
use primitive_types::U256;

use crate::error::ConsensusError;
use crate::target::{Target, shl_u512, shr_u512, target_to_compact, widening_mul};

/// The height ASERT measures everything from: **genesis**.
///
/// Genesis is fixed by [`ChainParams`], identical on every node before any of
/// them has seen a peer, and can never be reorged away. Anchoring anywhere else
/// — including height 1 — makes the difficulty rule fork-dependent and splits
/// the network permanently; see the module docs.
///
/// Genesis itself is the only block exempt from the difficulty-transition rule,
/// and only because it has no parent to transition from. Its child, at height
/// 1, gets an ASERT target like every other block.
pub const ANCHOR_HEIGHT: u64 = 0;

/// Fixed-point radix: the exponent is in units of `1 / 65536` half-lives.
pub const RADIX: i64 = 65_536;

/// Bound applied to `exponent` before it is split into `shifts` and `frac`.
///
/// `2^25` corresponds to `shifts = +-512`, both of which already saturate. See
/// the module docs for why clamping here is exact rather than approximate.
pub const EXPONENT_CLAMP: i64 = 1 << 25;

/// Linear coefficient of the cubic approximation of `2^(frac/65536)`.
pub const CUBIC_C1: u128 = 195_766_423_245_049;
/// Quadratic coefficient of the cubic approximation.
pub const CUBIC_C2: u128 = 971_821_376;
/// Cubic coefficient of the cubic approximation.
pub const CUBIC_C3: u128 = 5_127;
/// Rounding term added before the final shift: `1 << 47`, i.e. one half ulp.
pub const CUBIC_ROUND: u128 = 1 << 47;
/// Final right shift of the cubic approximation.
pub const CUBIC_SHIFT: u32 = 48;

/// The largest `shifts` magnitude reachable after the clamp.
const MAX_SHIFTS: u32 = 512;

/// Width, in bits, that the 512-bit accumulator may occupy and still leave a
/// 256-bit result after the closing `>> 16`.
const MAX_ACCUMULATOR_BITS: u32 = 272;

/// The anchor block: the fixed point the whole difficulty schedule hangs from.
///
/// On a live chain it is genesis — [`AsertAnchor::genesis`] — carrying the
/// `bits` and timestamp that [`ChainParams`] states. Nothing about it is
/// recomputed as the chain grows and nothing about it is read from a
/// [`HeaderView`](crate::HeaderView), which is what makes ASERT both stateless
/// with respect to recent history and independent of which fork the reader is
/// on.
///
/// The fields stay public and [`AsertAnchor::from_compact`] stays general so
/// that the cross-check vectors can drive the algorithm from an arbitrary
/// anchor; consensus itself only ever uses [`AsertAnchor::genesis`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsertAnchor {
    /// The anchor block's expanded target.
    pub target: Target,
    /// The anchor block's timestamp, in **seconds**.
    pub time_s: i64,
    /// The anchor block's height, [`ANCHOR_HEIGHT`] on a live chain.
    pub height: u64,
}

impl AsertAnchor {
    /// Build an anchor from a compact target.
    ///
    /// # Errors
    ///
    /// Propagates [`compact_to_target`](crate::compact_to_target) failures.
    pub fn from_compact(
        bits: CompactTarget,
        time_s: i64,
        height: u64,
    ) -> Result<Self, ConsensusError> {
        Ok(AsertAnchor { target: crate::target::compact_to_target(bits)?, time_s, height })
    }

    /// The one anchor consensus uses: genesis, straight out of [`ChainParams`].
    ///
    /// `target = compact_to_target(params.genesis_bits)`,
    /// `time_s = params.genesis_timestamp_ms / 1000`, `height =`
    /// [`ANCHOR_HEIGHT`]. No chain is read, so this cannot fail for a missing
    /// header and cannot return two different answers to two nodes holding
    /// different forks. That is the whole point (CONTRACT 6.3).
    ///
    /// # Errors
    ///
    /// [`ConsensusError`] variants from
    /// [`compact_to_target`](crate::compact_to_target) when `genesis_bits` is
    /// not a valid compact target — a malformed parameter set, never a
    /// chain-state condition.
    pub fn genesis(params: &ChainParams) -> Result<Self, ConsensusError> {
        // Milliseconds to seconds, truncating, matching `BlockHeader::timestamp_s`.
        let time_s = params.genesis_timestamp_ms.checked_div(1_000).unwrap_or(0);
        // A genesis timestamp beyond i64 seconds is 292 billion years out; the
        // saturation keeps the ordering rather than wrapping into the past.
        AsertAnchor::from_compact(
            params.genesis_bits,
            i64::try_from(time_s).unwrap_or(i64::MAX),
            ANCHOR_HEIGHT,
        )
    }
}

/// The network constants ASERT needs, extracted once from [`ChainParams`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsertParams {
    /// Target time between blocks, in **seconds**.
    pub target_spacing_s: i64,
    /// Half-life of the exponential controller, in seconds.
    pub halflife_s: i64,
    /// The easiest target this network permits.
    pub pow_limit: Target,
}

impl AsertParams {
    /// Read the ASERT constants out of a full parameter set.
    pub fn from_chain_params(p: &ChainParams) -> Self {
        AsertParams {
            target_spacing_s: i64::try_from(p.target_spacing_s()).unwrap_or(i64::MAX),
            halflife_s: p.asert_halflife_s,
            pow_limit: Target::from_be_bytes(&p.pow_limit),
        }
    }

    /// Reject a parameter set that would make the controller meaningless.
    fn validate(&self) -> Result<(), ConsensusError> {
        if self.halflife_s <= 0 {
            return Err(ConsensusError::InvalidAsertParams("halflife_s must be positive"));
        }
        if self.target_spacing_s <= 0 {
            return Err(ConsensusError::InvalidAsertParams("target_spacing_s must be positive"));
        }
        if self.pow_limit.is_zero() {
            return Err(ConsensusError::InvalidAsertParams("pow_limit must be non-zero"));
        }
        Ok(())
    }
}

/// The fixed-point exponent: how many `1/65536`-ths of a half-life the chain is
/// ahead of (positive) or behind (negative) its absolute schedule.
///
/// The division truncates toward zero, per CONTRACT 6.3. The result is clamped
/// to `+-`[`EXPONENT_CLAMP`]; see the module docs for why that is exact.
///
/// # Errors
///
/// [`ConsensusError::InvalidAsertParams`] when the spacing or half-life is not
/// positive.
pub fn asert_exponent(
    anchor: &AsertAnchor,
    parent_time_s: i64,
    parent_height: u64,
    params: &AsertParams,
) -> Result<i64, ConsensusError> {
    params.validate()?;

    let time_diff = i128::from(parent_time_s).saturating_sub(i128::from(anchor.time_s));
    let height_diff = i128::from(parent_height).saturating_sub(i128::from(anchor.height));

    // Saturating rather than checked: saturation can only happen at magnitudes
    // far beyond EXPONENT_CLAMP, where the clamp below discards the value
    // anyway, and it keeps the sign — which is the only thing that survives.
    let scheduled =
        i128::from(params.target_spacing_s).saturating_mul(height_diff.saturating_add(1));
    let drift = time_diff.saturating_sub(scheduled);
    let scaled = drift.saturating_mul(i128::from(RADIX));

    // Rust's `/` on integers truncates toward zero, which is what 6.3 asks for.
    let exponent = scaled
        .checked_div(i128::from(params.halflife_s))
        .ok_or(ConsensusError::Arithmetic("asert exponent"))?;

    let upper = i128::from(EXPONENT_CLAMP);
    // `EXPONENT_CLAMP` is a positive power of two, so negating it in `i128`
    // cannot overflow; `checked_neg` states that rather than assuming it.
    let lower = upper.checked_neg().ok_or(ConsensusError::Arithmetic("asert exponent clamp"))?;
    i64::try_from(exponent.clamp(lower, upper))
        .map_err(|_| ConsensusError::Arithmetic("asert exponent"))
}

/// Split a clamped exponent into the integer shift and the 16-bit fraction.
///
/// `div_euclid`/`rem_euclid` are floor division and a non-negative remainder,
/// so `frac` is in `[0, 65536)` for negative exponents too. This is the
/// correction CONTRACT 6.3 calls for, written without a raw shift.
pub fn split_exponent(exponent: i64) -> (i64, u64) {
    let shifts = exponent.div_euclid(RADIX);
    let frac = exponent.rem_euclid(RADIX);
    // `rem_euclid` with a positive divisor is non-negative by definition.
    (shifts, u64::try_from(frac).unwrap_or(0))
}

/// The cubic approximation of `65536 * 2^(frac/65536)`.
///
/// Relative error below 0.013 %. `frac` must be in `[0, 65536)`; the result is
/// then in `[65536, 131072]`.
///
/// The largest term is `195_766_423_245_049 * 65535`, about `2^63.5`, and
/// `5_127 * 65535^3` is about `2^60.3`, so the sum cannot come close to
/// overflowing `u128`. The saturating operators are belt and braces for a caller
/// that ignores the range contract.
pub fn asert_factor(frac: u64) -> u64 {
    debug_assert!(frac < 65_536, "frac must be in [0, 65536)");
    let f = u128::from(frac);
    let f2 = f.saturating_mul(f);
    let f3 = f2.saturating_mul(f);

    let poly = CUBIC_C1
        .saturating_mul(f)
        .saturating_add(CUBIC_C2.saturating_mul(f2))
        .saturating_add(CUBIC_C3.saturating_mul(f3))
        .saturating_add(CUBIC_ROUND);

    let scaled = poly.checked_shr(CUBIC_SHIFT).unwrap_or(0);
    let factor = scaled.saturating_add(u128::from(RADIX.unsigned_abs()));
    u64::try_from(factor).unwrap_or(u64::MAX)
}

/// The target for the child of `parent`, given the anchor.
///
/// This is the whole of CONTRACT 6.3. `parent_time_s` and `parent_height`
/// describe the *parent* of the block being created; the `+ 1` inside the
/// exponent is what accounts for the child.
///
/// # Errors
///
/// [`ConsensusError::InvalidAsertParams`] for a non-positive spacing or
/// half-life, or a zero `pow_limit`.
pub fn asert_next_target(
    anchor: &AsertAnchor,
    parent_time_s: i64,
    parent_height: u64,
    params: &AsertParams,
) -> Result<Target, ConsensusError> {
    params.validate()?;

    let exponent = asert_exponent(anchor, parent_time_s, parent_height, params)?;
    let (shifts, frac) = split_exponent(exponent);
    let factor = asert_factor(frac);

    // 256 x 64 -> 512 bits, so the closing `>> 16` truncates nothing that the
    // multiply itself introduced.
    let product = widening_mul(anchor.target.0, factor);

    let next = if product.is_zero() {
        // An anchor target of zero stays zero, and is lifted to 1 below.
        U256::zero()
    } else {
        let shifted = if shifts < 0 {
            shr_u512(product, shift_magnitude(shifts))
        } else {
            let magnitude = shift_magnitude(shifts);
            let bits = u32::try_from(product.bits()).unwrap_or(u32::MAX);
            if bits.saturating_add(magnitude) > MAX_ACCUMULATOR_BITS {
                // The result would need more than 256 bits after `>> 16`, so it
                // is certainly above any representable pow_limit.
                return Ok(params.pow_limit);
            }
            shl_u512(product, magnitude)
        };
        let narrowed = shr_u512(shifted, 16);
        // The width check above guarantees this conversion cannot fail.
        U256::try_from(narrowed).unwrap_or(params.pow_limit.0)
    };

    let mut target = next;
    if target.is_zero() {
        target = U256::one();
    }
    if target > params.pow_limit.0 {
        target = params.pow_limit.0;
    }
    Ok(Target(target))
}

/// [`asert_next_target`], compressed to the canonical compact form a header
/// carries.
///
/// # Errors
///
/// Propagates [`asert_next_target`].
pub fn asert_next_bits(
    anchor: &AsertAnchor,
    parent_time_s: i64,
    parent_height: u64,
    params: &AsertParams,
) -> Result<CompactTarget, ConsensusError> {
    asert_next_target(anchor, parent_time_s, parent_height, params).map(target_to_compact)
}

/// `|shifts|` as a shift amount, capped at [`MAX_SHIFTS`].
///
/// `shifts` is already in `[-512, 512]` after the exponent clamp; the cap is
/// what makes that a type-level guarantee for the shift helpers.
fn shift_magnitude(shifts: i64) -> u32 {
    u32::try_from(shifts.unsigned_abs()).unwrap_or(MAX_SHIFTS).min(MAX_SHIFTS)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]

    use proptest::prelude::*;

    use super::*;
    use crate::target::compact_to_target;

    const SPACING: i64 = 120;
    const HALFLIFE: i64 = 7_200;
    const ANCHOR_TIME: i64 = 1_735_689_600;

    /// A mid-range anchor: 2^32 times harder than the mainnet `pow_limit`, so
    /// the controller has room to move in both directions without meeting the
    /// clamp. Tests that want the clamp use `0x1d00ffff`, the limit itself.
    const MID_BITS: u32 = 0x1900_ffff;

    fn mainnet_params() -> AsertParams {
        AsertParams::from_chain_params(&ChainParams::mainnet())
    }

    fn anchor(bits: u32) -> AsertAnchor {
        AsertAnchor::from_compact(CompactTarget(bits), ANCHOR_TIME, ANCHOR_HEIGHT).unwrap()
    }

    /// Difficulty as a ratio to the anchor, expressed as parts per million so
    /// the assertions stay integer-only.
    fn ratio_ppm(a: Target, b: Target) -> u128 {
        // (a / b) * 1e6, computed as (a * 1e6) / b with a 512-bit numerator.
        let num = crate::target::widening_mul(a.0, 1_000_000);
        let den = primitive_types::U512::from(b.0);
        (num / den).low_u128()
    }

    #[test]
    fn split_is_floor_division_with_a_non_negative_fraction() {
        assert_eq!(split_exponent(0), (0, 0));
        assert_eq!(split_exponent(65_536), (1, 0));
        assert_eq!(split_exponent(65_537), (1, 1));
        assert_eq!(split_exponent(-1), (-1, 65_535));
        assert_eq!(split_exponent(-65_536), (-1, 0));
        assert_eq!(split_exponent(-65_537), (-2, 65_535));
        assert_eq!(split_exponent(-1_092), (-1, 64_444));
    }

    #[test]
    fn split_matches_a_two_complement_shift_for_every_sampled_exponent() {
        for e in [-1_000_000i64, -70_000, -65_536, -1, 0, 1, 65_535, 70_000, 1_000_000] {
            let (shifts, frac) = split_exponent(e);
            assert_eq!(shifts, e >> 16, "arithmetic shift disagreement at {e}");
            assert_eq!(frac, (e & 0xffff) as u64, "mask disagreement at {e}");
            assert!(frac < 65_536);
        }
    }

    #[test]
    fn factor_endpoints_are_exact() {
        // 2^0 = 1 exactly.
        assert_eq!(asert_factor(0), 65_536);
        // 2^(65535/65536) is just under 2; the cubic must not reach 131_072.
        let top = asert_factor(65_535);
        assert!(top > 131_060 && top <= 131_072, "factor(65535) = {top}");
    }

    #[test]
    fn factor_is_monotonic_and_within_thirteen_thousandths_of_a_percent() {
        let mut prev = 0u64;
        for i in 0..=64u64 {
            let frac = i * 1_024;
            let frac = frac.min(65_535);
            let f = asert_factor(frac);
            assert!(f >= prev, "factor must not decrease");
            prev = f;
            assert!((65_536..=131_072).contains(&f));
        }
    }

    #[test]
    fn factor_at_a_half_is_the_square_root_of_two() {
        // 65536 * sqrt(2) = 92681.9…; the cubic must land within 0.013 %.
        let f = asert_factor(32_768);
        assert!(f.abs_diff(92_682) <= 12, "factor(32768) = {f}");
    }

    #[test]
    fn on_schedule_timestamps_hold_bits_perfectly_stable() {
        let a = anchor(0x1d00_ffff);
        let p = mainnet_params();
        let first = asert_next_bits(&a, ANCHOR_TIME, ANCHOR_HEIGHT, &p).unwrap();
        for h in 1u64..500 {
            let parent_height = ANCHOR_HEIGHT + h;
            let parent_time = ANCHOR_TIME + i64::try_from(h).unwrap() * SPACING;
            let bits = asert_next_bits(&a, parent_time, parent_height, &p).unwrap();
            assert_eq!(bits, first, "bits drifted at parent height {parent_height}");
        }
    }

    #[test]
    fn on_schedule_difficulty_stays_within_two_percent_of_the_anchor() {
        let a = anchor(MID_BITS);
        let p = mainnet_params();
        let t = asert_next_target(&a, ANCHOR_TIME + 10 * SPACING, ANCHOR_HEIGHT + 10, &p).unwrap();
        let ppm = ratio_ppm(t, a.target);
        // One spacing of built-in offset: 2^(-120/7200) = 0.98851.
        assert!((985_000..=990_000).contains(&ppm), "ratio {ppm} ppm");
    }

    #[test]
    fn one_halflife_ahead_of_schedule_halves_the_target() {
        let a = anchor(MID_BITS);
        let p = mainnet_params();
        // Parent is at height anchor+n but its clock is a half-life *behind*
        // the schedule, i.e. blocks were slow: the target must double.
        let n = 100i64;
        let parent_time = ANCHOR_TIME + SPACING * (n + 1) + HALFLIFE;
        let t = asert_next_target(&a, parent_time, ANCHOR_HEIGHT + 100, &p).unwrap();
        let ppm = ratio_ppm(t, a.target);
        assert!((1_999_000..=2_001_000).contains(&ppm), "expected 2x, got {ppm} ppm");
    }

    #[test]
    fn one_halflife_behind_schedule_doubles_the_difficulty() {
        let a = anchor(MID_BITS);
        let p = mainnet_params();
        let n = 100i64;
        let parent_time = ANCHOR_TIME + SPACING * (n + 1) - HALFLIFE;
        let t = asert_next_target(&a, parent_time, ANCHOR_HEIGHT + 100, &p).unwrap();
        let ppm = ratio_ppm(t, a.target);
        assert!((499_500..=500_500).contains(&ppm), "expected 0.5x, got {ppm} ppm");
    }

    #[test]
    fn n_halflives_are_exponential_not_linear() {
        let a = anchor(MID_BITS);
        let p = mainnet_params();
        let n = 1_000i64;
        for (halflives, expected_ppm) in
            [(1i64, 2_000_000u128), (2, 4_000_000), (3, 8_000_000), (4, 16_000_000)]
        {
            let parent_time = ANCHOR_TIME + SPACING * (n + 1) + HALFLIFE * halflives;
            let t = asert_next_target(&a, parent_time, ANCHOR_HEIGHT + 1_000, &p).unwrap();
            let ppm = ratio_ppm(t, a.target);
            let tolerance = expected_ppm / 500; // 0.2 %
            assert!(
                ppm.abs_diff(expected_ppm) <= tolerance,
                "{halflives} half-lives: expected {expected_ppm} ppm, got {ppm}"
            );
        }
    }

    #[test]
    fn the_target_never_exceeds_the_pow_limit() {
        let a = anchor(0x1d00_ffff);
        let p = mainnet_params();
        // A gap of a thousand years with no blocks.
        let t = asert_next_target(&a, ANCHOR_TIME + 31_536_000_000, ANCHOR_HEIGHT + 1, &p).unwrap();
        assert_eq!(t, p.pow_limit);
    }

    #[test]
    fn the_target_never_reaches_zero() {
        let a = anchor(0x1d00_ffff);
        let p = mainnet_params();
        // A parent claiming to be a thousand years *before* the anchor.
        let t = asert_next_target(&a, ANCHOR_TIME - 31_536_000_000, ANCHOR_HEIGHT + 1, &p).unwrap();
        assert_eq!(t, Target(U256::one()), "the floor is 1, never 0");
        assert!(!t.is_zero());
    }

    #[test]
    fn the_clamp_boundary_saturates_on_both_sides() {
        let a = anchor(0x1d00_ffff);
        let p = mainnet_params();
        // Exponents at and beyond the clamp must give identical answers.
        let far_future = asert_next_target(&a, i64::MAX / 2, ANCHOR_HEIGHT + 1, &p).unwrap();
        let further = asert_next_target(&a, i64::MAX, ANCHOR_HEIGHT + 1, &p).unwrap();
        assert_eq!(far_future, further);
        assert_eq!(far_future, p.pow_limit);

        let far_past = asert_next_target(&a, i64::MIN / 2, ANCHOR_HEIGHT + 1, &p).unwrap();
        let further_past = asert_next_target(&a, i64::MIN, ANCHOR_HEIGHT + 1, &p).unwrap();
        assert_eq!(far_past, further_past);
        assert_eq!(far_past, Target(U256::one()));
    }

    #[test]
    fn a_devnet_anchor_at_the_pow_limit_cannot_get_easier() {
        let p = AsertParams::from_chain_params(&ChainParams::devnet());
        let a = anchor(0x207f_ffff);
        for gap in [0i64, 1, 100, 10_000, 1_000_000] {
            let t = asert_next_target(&a, ANCHOR_TIME + gap, ANCHOR_HEIGHT + 1, &p).unwrap();
            assert!(t <= p.pow_limit, "gap {gap} produced a target above pow_limit");
        }
    }

    #[test]
    fn a_single_manipulated_timestamp_moves_difficulty_by_no_more_than_the_halflife_permits() {
        let a = anchor(MID_BITS);
        let p = mainnet_params();
        let n = 500i64;
        let honest_time = ANCHOR_TIME + SPACING * n;
        let honest = asert_next_target(&a, honest_time, ANCHOR_HEIGHT + 500, &p).unwrap();

        // A miner lies by the whole two-hour future allowance, which happens to
        // be exactly one half-life. The most that can do is halve the
        // difficulty, for one block.
        let lied = asert_next_target(&a, honest_time + HALFLIFE, ANCHOR_HEIGHT + 500, &p).unwrap();
        let ppm = ratio_ppm(lied, honest);
        assert!(ppm <= 2_001_000, "one lie moved difficulty by {ppm} ppm, past one half-life");
        assert!(ppm >= 1_999_000, "one lie should move difficulty a full half-life: {ppm} ppm");

        // And the lie does not compound: ASERT reads only the parent, against an
        // absolute schedule, so the next on-schedule block is identical to the
        // one a chain that never saw the lie would have produced.
        let after = asert_next_target(&a, honest_time + SPACING, ANCHOR_HEIGHT + 501, &p).unwrap();
        assert_eq!(after, honest, "ASERT must not carry the lie forward");

        // Even lying by the full two hours on every single block cannot ratchet:
        // the target stays pinned one half-life easier, it does not run away.
        for k in 1i64..50 {
            let t = asert_next_target(
                &a,
                ANCHOR_TIME + SPACING * (500 + k) + HALFLIFE,
                ANCHOR_HEIGHT + u64::try_from(500 + k).unwrap(),
                &p,
            )
            .unwrap();
            let ppm = ratio_ppm(t, honest);
            assert!(ppm <= 2_001_000, "sustained lying compounded to {ppm} ppm at k = {k}");
        }
    }

    #[test]
    fn alternating_timestamp_manipulation_cannot_ratchet_difficulty_down() {
        let a = anchor(MID_BITS);
        let p = mainnet_params();
        let mut worst = Target::ZERO;
        for i in 0..200i64 {
            // Alternate +1 hour / -1 hour around the schedule.
            let skew = if i % 2 == 0 { 3_600 } else { -3_600 };
            let parent_time = ANCHOR_TIME + SPACING * i + skew;
            let t =
                asert_next_target(&a, parent_time, ANCHOR_HEIGHT + u64::try_from(i).unwrap(), &p)
                    .unwrap();
            if t > worst {
                worst = t;
            }
        }
        // The excursion is bounded by 2^(3600/7200) = sqrt(2), not compounded.
        let ppm = ratio_ppm(worst, a.target);
        assert!(ppm < 1_450_000, "alternating skew reached {ppm} ppm of the anchor");
    }

    /// Deterministic hashrate simulator: with `hashrate_x1000` thousandths of
    /// the nominal hashrate, a block at `target` takes
    /// `spacing * anchor_target / target * 1000 / hashrate_x1000` seconds.
    fn block_interval_s(anchor_target: Target, target: Target, hashrate_x1000: u64) -> i64 {
        let num = crate::target::widening_mul(anchor_target.0, 1_000);
        let num = num * primitive_types::U512::from(u64::try_from(SPACING).unwrap());
        let den =
            primitive_types::U512::from(target.0) * primitive_types::U512::from(hashrate_x1000);
        let dt = (num / den).low_u128();
        i64::try_from(dt.max(1)).unwrap_or(i64::MAX)
    }

    /// Run the controller against a constant hashrate for `seconds` of
    /// simulated wall-clock time, returning the last block interval and the
    /// target in force at the end.
    fn simulate_for(anchor_bits: u32, hashrate_x1000: u64, seconds: i64) -> (i64, Target) {
        let a = anchor(anchor_bits);
        let p = mainnet_params();
        let deadline = ANCHOR_TIME.saturating_add(seconds);
        let mut height = ANCHOR_HEIGHT;
        let mut time = ANCHOR_TIME;
        let mut last_dt = SPACING;
        let mut target = a.target;
        let mut blocks = 0u32;
        while time < deadline && blocks < 1_000_000 {
            target = asert_next_target(&a, time, height, &p).unwrap();
            last_dt = block_interval_s(a.target, target, hashrate_x1000);
            time = time.saturating_add(last_dt);
            height = height.saturating_add(1);
            blocks = blocks.saturating_add(1);
        }
        (last_dt, target)
    }

    /// Simulated seconds until the block interval first lands within 2x of the
    /// target spacing, or `None` if it never does.
    fn seconds_to_settle(anchor_bits: u32, hashrate_x1000: u64) -> Option<i64> {
        let a = anchor(anchor_bits);
        let p = mainnet_params();
        let mut height = ANCHOR_HEIGHT;
        let mut time = ANCHOR_TIME;
        for _ in 0..1_000_000u32 {
            let target = asert_next_target(&a, time, height, &p).unwrap();
            let dt = block_interval_s(a.target, target, hashrate_x1000);
            if (SPACING / 2..=SPACING * 2).contains(&dt) {
                return Some(time - ANCHOR_TIME);
            }
            time = time.saturating_add(dt);
            height = height.saturating_add(1);
        }
        None
    }

    #[test]
    fn a_ten_times_hashrate_spike_returns_block_time_to_target_within_two_halflives() {
        let settled = seconds_to_settle(MID_BITS, 10_000).expect("the controller must settle");
        assert!(settled <= 2 * HALFLIFE, "a 10x spike took {settled} s, over two half-lives");

        let (dt, _) = simulate_for(MID_BITS, 10_000, 2 * HALFLIFE);
        assert!(
            (SPACING / 2..=SPACING * 2).contains(&dt),
            "after two half-lives at 10x the interval was {dt} s, outside 60..240"
        );

        // Left alone, the controller lands on a tenfold difficulty increase:
        // the target ends at about a tenth of the anchor, which is what a
        // tenfold hashrate increase should cost.
        let (dt, target) = simulate_for(MID_BITS, 10_000, 20 * HALFLIFE);
        assert!((SPACING / 2..=SPACING * 2).contains(&dt), "steady state was {dt} s");
        let ppm = ratio_ppm(anchor(MID_BITS).target, target);
        assert!(
            (9_500_000..=10_500_000).contains(&ppm),
            "difficulty settled at {ppm} ppm, not 10x"
        );
    }

    #[test]
    fn a_ten_times_hashrate_collapse_returns_block_time_to_target_within_four_halflives() {
        // A collapse is intrinsically slower in wall-clock terms than a spike:
        // the controller learns only from elapsed time, and at a tenth of the
        // hashrate a tenth as many blocks arrive to carry that information. The
        // response is the same two half-lives of *drift*; accumulating that
        // drift takes longer than two half-lives of clock.
        let settled = seconds_to_settle(MID_BITS, 100).expect("the controller must settle");
        assert!(settled <= 4 * HALFLIFE, "a 10x collapse took {settled} s, over four half-lives");
        assert!(settled > HALFLIFE, "the asymmetry is real; assert it rather than hide it");

        let (dt, target) = simulate_for(MID_BITS, 100, 6 * HALFLIFE);
        assert!(
            (SPACING / 2..=SPACING * 2).contains(&dt),
            "after six half-lives at 0.1x the interval was {dt} s, outside 60..240"
        );
        let ppm = ratio_ppm(target, anchor(MID_BITS).target);
        assert!((8_000_000..=12_500_000).contains(&ppm), "difficulty moved {ppm} ppm, not ~10x");
    }

    #[test]
    fn the_controller_converges_at_the_nominal_hashrate() {
        let (dt, target) = simulate_for(MID_BITS, 1_000, 20 * HALFLIFE);
        assert!((110..=130).contains(&dt), "steady state settled at {dt} s");
        let ppm = ratio_ppm(target, anchor(MID_BITS).target);
        assert!((980_000..=1_020_000).contains(&ppm), "steady-state target drifted to {ppm} ppm");
    }

    #[test]
    fn a_hundredfold_spike_still_settles() {
        let settled = seconds_to_settle(MID_BITS, 100_000).expect("the controller must settle");
        assert!(settled <= 3 * HALFLIFE, "a 100x spike took {settled} s to settle");
        let (dt, _) = simulate_for(MID_BITS, 100_000, 3 * HALFLIFE);
        assert!((SPACING / 2..=SPACING * 2).contains(&dt), "100x spike settled at {dt} s");
    }

    #[test]
    fn invalid_parameters_are_rejected_rather_than_dividing_by_zero() {
        let a = anchor(0x1d00_ffff);
        let mut p = mainnet_params();
        p.halflife_s = 0;
        assert_eq!(
            asert_next_target(&a, ANCHOR_TIME, ANCHOR_HEIGHT, &p),
            Err(ConsensusError::InvalidAsertParams("halflife_s must be positive"))
        );
        p.halflife_s = -1;
        assert!(asert_next_target(&a, ANCHOR_TIME, ANCHOR_HEIGHT, &p).is_err());

        let mut p = mainnet_params();
        p.target_spacing_s = 0;
        assert_eq!(
            asert_exponent(&a, ANCHOR_TIME, ANCHOR_HEIGHT, &p),
            Err(ConsensusError::InvalidAsertParams("target_spacing_s must be positive"))
        );

        let mut p = mainnet_params();
        p.pow_limit = Target::ZERO;
        assert_eq!(
            asert_next_bits(&a, ANCHOR_TIME, ANCHOR_HEIGHT, &p),
            Err(ConsensusError::InvalidAsertParams("pow_limit must be non-zero"))
        );
    }

    #[test]
    fn an_anchor_target_of_zero_floors_at_one() {
        let p = mainnet_params();
        let a = AsertAnchor { target: Target::ZERO, time_s: ANCHOR_TIME, height: ANCHOR_HEIGHT };
        assert_eq!(
            asert_next_target(&a, ANCHOR_TIME, ANCHOR_HEIGHT, &p).unwrap(),
            Target(U256::one())
        );
    }

    #[test]
    fn exponent_matches_the_contract_formula_on_worked_examples() {
        let a = anchor(0x1d00_ffff);
        let p = mainnet_params();

        // Parent is the anchor itself: drift is exactly -1 spacing.
        let e = asert_exponent(&a, ANCHOR_TIME, ANCHOR_HEIGHT, &p).unwrap();
        assert_eq!(e, (-SPACING * RADIX) / HALFLIFE);
        assert_eq!(e, -1_092);

        // On schedule, 10 blocks on: still exactly -1 spacing.
        assert_eq!(
            asert_exponent(&a, ANCHOR_TIME + 10 * SPACING, ANCHOR_HEIGHT + 10, &p).unwrap(),
            -1_092
        );

        // Exactly one half-life ahead of schedule.
        let e = asert_exponent(&a, ANCHOR_TIME + SPACING * 11 + HALFLIFE, ANCHOR_HEIGHT + 10, &p)
            .unwrap();
        assert_eq!(e, RADIX);
    }

    #[test]
    fn the_division_producing_the_exponent_truncates_toward_zero() {
        let a = anchor(0x1d00_ffff);
        let p = AsertParams {
            target_spacing_s: 1,
            halflife_s: 7,
            pow_limit: mainnet_params().pow_limit,
        };
        // drift = +3 s -> (3 * 65536) / 7 = 28086.85… -> 28086
        let e = asert_exponent(&a, ANCHOR_TIME + 4, ANCHOR_HEIGHT, &p).unwrap();
        assert_eq!(e, (3 * RADIX) / 7);
        assert_eq!(e, 28_086);
        // drift = -3 s -> -28086.85… -> -28086, not -28087.
        let e = asert_exponent(&a, ANCHOR_TIME - 2, ANCHOR_HEIGHT, &p).unwrap();
        assert_eq!(e, -28_086);
    }

    #[test]
    fn anchor_from_compact_rejects_an_invalid_target() {
        assert_eq!(
            AsertAnchor::from_compact(CompactTarget(0x1d80_ffff), 0, 1),
            Err(ConsensusError::NegativeTarget(0x1d80_ffff))
        );
    }

    #[test]
    fn asert_params_are_read_from_chain_params() {
        let p = AsertParams::from_chain_params(&ChainParams::mainnet());
        assert_eq!(p.target_spacing_s, 120);
        assert_eq!(p.halflife_s, 7_200);
        assert_eq!(p.pow_limit, compact_to_target(CompactTarget(0x1d00_ffff)).unwrap());

        let d = AsertParams::from_chain_params(&ChainParams::devnet());
        assert_eq!(d.pow_limit, Target::from_be_bytes(&ChainParams::devnet().pow_limit));
        // Read the devnet limit off the parameters rather than pinning a
        // literal: which compact value devnet uses is that crate's business,
        // and the only thing ASERT cares about is that it is far easier than
        // mainnet's.
        assert_eq!(d.pow_limit, compact_to_target(ChainParams::devnet().genesis_bits).unwrap());
        assert!(d.pow_limit > p.pow_limit, "devnet must be far easier to mine than mainnet");
    }

    #[test]
    fn the_anchor_is_genesis_and_is_built_only_from_chain_params() {
        for params in [ChainParams::mainnet(), ChainParams::testnet(), ChainParams::devnet()] {
            let a = AsertAnchor::genesis(&params).unwrap();
            assert_eq!(a.height, 0, "the anchor is genesis, not the block after it");
            assert_eq!(a.height, ANCHOR_HEIGHT);
            assert_eq!(a.target, compact_to_target(params.genesis_bits).unwrap());
            assert_eq!(a.time_s, i64::try_from(params.genesis_timestamp_ms / 1_000).unwrap());
            // The anchor is a pure function of the parameters: same params in,
            // same anchor out, every time, on every node.
            assert_eq!(a, AsertAnchor::genesis(&params).unwrap());
        }
    }

    #[test]
    fn a_different_genesis_moves_the_anchor_and_nothing_else_does() {
        let mut params = ChainParams::devnet();
        let base = AsertAnchor::genesis(&params).unwrap();

        params.genesis_timestamp_ms += 60_000;
        let later = AsertAnchor::genesis(&params).unwrap();
        assert_eq!(later.time_s, base.time_s + 60);
        assert_eq!(later.target, base.target);
        assert_eq!(later.height, ANCHOR_HEIGHT);

        params.genesis_bits = CompactTarget(0x1d00_ffff);
        let harder = AsertAnchor::genesis(&params).unwrap();
        assert_eq!(harder.target, compact_to_target(CompactTarget(0x1d00_ffff)).unwrap());
        assert!(harder.target < base.target);
    }

    #[test]
    fn a_genesis_timestamp_truncates_to_whole_seconds() {
        let mut params = ChainParams::devnet();
        params.genesis_timestamp_ms = 1_735_689_600_999;
        assert_eq!(AsertAnchor::genesis(&params).unwrap().time_s, 1_735_689_600);
    }

    #[test]
    fn an_unexpandable_genesis_bits_is_a_parameter_error_not_a_chain_error() {
        let mut params = ChainParams::devnet();
        params.genesis_bits = CompactTarget(0x1d80_ffff);
        assert_eq!(
            AsertAnchor::genesis(&params),
            Err(ConsensusError::NegativeTarget(0x1d80_ffff))
        );
    }

    #[test]
    fn the_child_of_genesis_is_on_the_asert_schedule_like_every_other_block() {
        // Height 1 is *not* exempt: the anchor is genesis itself, so the very
        // first child already carries one spacing of built-in offset — the same
        // -1092 exponent every on-schedule block has.
        let params = ChainParams::mainnet();
        let a = AsertAnchor::genesis(&params).unwrap();
        let p = mainnet_params();
        let anchor_time = i64::try_from(params.genesis_timestamp_ms / 1_000).unwrap();

        let e = asert_exponent(&a, anchor_time, 0, &p).unwrap();
        assert_eq!(e, -1_092, "the child of genesis is one spacing behind the schedule");

        let child_of_genesis = asert_next_bits(&a, anchor_time, 0, &p).unwrap();
        let tenth_block = asert_next_bits(&a, anchor_time + 9 * SPACING, 9, &p).unwrap();
        assert_eq!(
            child_of_genesis, tenth_block,
            "an on-schedule height 1 must land on the same target as any other on-schedule block"
        );
    }

    proptest! {
        /// The controller never panics, never returns zero and never exceeds
        /// the limit, for any parent time and height at all.
        #[test]
        fn asert_is_total_and_bounded(
            parent_time in any::<i64>(),
            parent_height in any::<u64>(),
        ) {
            let a = anchor(0x1d00_ffff);
            let p = mainnet_params();
            let t = asert_next_target(&a, parent_time, parent_height, &p).unwrap();
            prop_assert!(!t.is_zero());
            prop_assert!(t <= p.pow_limit);
            let bits = asert_next_bits(&a, parent_time, parent_height, &p).unwrap();
            prop_assert!(compact_to_target(bits).unwrap() <= p.pow_limit);
        }

        /// Later parent timestamps at the same height can only make the target
        /// easier: the controller is monotone in time.
        #[test]
        fn target_is_monotone_in_parent_time(
            base in -1_000_000_000i64..1_000_000_000i64,
            delta in 0i64..1_000_000i64,
            height_offset in 0u64..100_000,
        ) {
            let a = anchor(0x1d00_ffff);
            let p = mainnet_params();
            let h = ANCHOR_HEIGHT + height_offset;
            let t0 = asert_next_target(&a, ANCHOR_TIME + base, h, &p).unwrap();
            let t1 = asert_next_target(&a, ANCHOR_TIME + base + delta, h, &p).unwrap();
            prop_assert!(t1 >= t0);
        }

        /// More blocks at the same timestamp can only make the target harder.
        #[test]
        fn target_is_antitone_in_parent_height(
            base in -100_000i64..100_000i64,
            height in 1u64..1_000_000,
            extra in 0u64..1_000,
        ) {
            let a = anchor(0x1d00_ffff);
            let p = mainnet_params();
            let t0 = asert_next_target(&a, ANCHOR_TIME + base, height, &p).unwrap();
            let t1 = asert_next_target(&a, ANCHOR_TIME + base, height + extra, &p).unwrap();
            prop_assert!(t1 <= t0);
        }

        /// `frac` is always in range, whatever the exponent.
        #[test]
        fn frac_is_always_in_range(e in any::<i64>()) {
            let (_, frac) = split_exponent(e);
            prop_assert!(frac < 65_536);
        }

        /// The factor is always inside `[65536, 131072]`.
        #[test]
        fn factor_is_always_in_range(frac in 0u64..65_536) {
            let f = asert_factor(frac);
            prop_assert!((65_536..=131_072).contains(&f));
        }
    }
}
