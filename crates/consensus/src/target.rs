//! Difficulty targets, the compact ("bits") encoding, and accumulated work.
//!
//! # The compact encoding (CONTRACT 6.1)
//!
//! `bits` is Bitcoin's float-free 32-bit encoding of a 256-bit number:
//! `0xEEMMMMMM`, where `EE` is the size of the number in bytes and `MMMMMM` is
//! a 24-bit mantissa. It is a base-256 floating point format with a sign bit
//! that nobody has ever had a use for.
//!
//! Three spellings are rejected outright rather than normalised:
//!
//! 1. the **negative form** — mantissa bit `0x00800000` set;
//! 2. a **zero mantissa with a non-zero exponent** — a non-canonical zero;
//! 3. any value whose expansion needs **more than 256 bits**.
//!
//! [`target_to_compact`] always emits the canonical form, so
//! `target_to_compact(compact_to_target(c)) == c` for every canonical `c`. That
//! round trip is proptested, and [`is_canonical_compact`] is the predicate.
//!
//! # Work (CONTRACT 6.2)
//!
//! `work(t) = (!t / (t + 1)) + 1`, in 256-bit integers. This is the expected
//! number of hashes needed to find a block at target `t`. Fork choice sums it;
//! it never compares heights, because a hundred easy blocks can be worth less
//! than ten hard ones.
//!
//! # Byte order
//!
//! A block hash is compared against a target by reading its 32 bytes as a
//! **big-endian** integer. Ferrum displays hashes in natural byte order
//! (CONTRACT 2.4), so a "small" hash is one with leading zero bytes exactly as
//! it prints. Bitcoin's little-endian reading is an artefact of its display
//! reversal and is not reproduced here.

use core::fmt;

use ferrum_types::{BlockHash, CompactTarget, HASH_LEN, Hash32};
use primitive_types::{U256, U512};

use crate::error::ConsensusError;

/// Mask of the 24-bit mantissa inside a compact target.
pub const COMPACT_MANTISSA_MASK: u32 = 0x00ff_ffff;

/// The mantissa's sign bit. Setting it makes the compact form negative, which
/// Ferrum rejects.
pub const COMPACT_SIGN_BIT: u32 = 0x0080_0000;

/// Number of bits in a target.
pub const TARGET_BITS: u32 = 256;

/// A 256-bit difficulty target: a header hash is valid when, read big-endian,
/// it is less than or equal to this value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Target(pub U256);

impl Target {
    /// The unsatisfiable target. No hash is ever `<= 0`… except the zero hash,
    /// which is why a zero target is rejected before it is ever compared.
    pub const ZERO: Target = Target(U256::zero());

    /// The easiest possible 256-bit target: every hash meets it.
    pub const MAX: Target = Target(U256::max_value());

    /// Read a target from 32 big-endian bytes, the form `ChainParams::pow_limit`
    /// is stored in.
    pub fn from_be_bytes(b: &[u8; HASH_LEN]) -> Self {
        Target(U256::from_big_endian(b))
    }

    /// Write the target as 32 big-endian bytes.
    pub fn to_be_bytes(self) -> [u8; HASH_LEN] {
        self.0.to_big_endian()
    }

    /// True when the target is zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// The canonical compact encoding of this target.
    pub fn to_compact(self) -> CompactTarget {
        target_to_compact(self)
    }

    /// Expand a compact target, rejecting all three invalid spellings.
    pub fn from_compact(c: CompactTarget) -> Result<Self, ConsensusError> {
        compact_to_target(c)
    }

    /// The work a block at this target contributes to fork choice.
    pub fn work(self) -> Work {
        work_from_target(self)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_be_bytes()))
    }
}

impl From<U256> for Target {
    fn from(v: U256) -> Self {
        Target(v)
    }
}

/// Accumulated proof-of-work, in expected hashes.
///
/// Fork choice is by cumulative `Work`, never by height (SPEC 7.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Work(pub U256);

impl Work {
    /// No work at all — what an unparseable header contributes.
    pub const ZERO: Work = Work(U256::zero());

    /// One unit of work. The BFT engine gives every block exactly this.
    pub const ONE: Work = Work(U256::one());

    /// Read work from 32 big-endian bytes, the form `BlockIndexEntry` stores.
    pub fn from_be_bytes(b: &[u8; HASH_LEN]) -> Self {
        Work(U256::from_big_endian(b))
    }

    /// Write work as 32 big-endian bytes, so that bytewise lexicographic
    /// ordering equals numeric ordering in a database key.
    pub fn to_be_bytes(self) -> [u8; HASH_LEN] {
        self.0.to_big_endian()
    }

    /// True when this is zero work.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Sum two work values, `None` on 256-bit overflow.
    pub fn checked_add(self, other: Work) -> Option<Work> {
        self.0.checked_add(other.0).map(Work)
    }

    /// Sum two work values, saturating at 256 bits.
    ///
    /// Saturation is unreachable on any real chain: `U256::MAX` work is more
    /// hashes than there are Planck times in the age of the universe.
    pub fn saturating_add(self, other: Work) -> Work {
        Work(self.0.saturating_add(other.0))
    }
}

impl fmt::Display for Work {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_be_bytes()))
    }
}

/// Right-shift a `U256`, yielding zero once the shift reaches the width.
///
/// Wrapped once, with the bound stated, so that the rest of the crate can stay
/// under `clippy::arithmetic_side_effects` without an annotation per call site.
#[allow(clippy::arithmetic_side_effects)] // `n` is bounded to < 256 on the shifting path
pub(crate) fn shr_u256(v: U256, n: u32) -> U256 {
    if n >= TARGET_BITS { U256::zero() } else { v >> n }
}

/// Left-shift a `U256`, returning `None` when the result would need more than
/// 256 bits. The width is checked *before* the shift, so nothing is truncated.
#[allow(clippy::arithmetic_side_effects)] // width checked immediately above the shift
pub(crate) fn shl_u256_checked(v: U256, n: u32) -> Option<U256> {
    if v.is_zero() {
        return Some(U256::zero());
    }
    let bits = u32::try_from(v.bits()).ok()?;
    if bits.checked_add(n)? > TARGET_BITS {
        return None;
    }
    Some(v << n)
}

/// Right-shift a `U512`, yielding zero once the shift reaches the width.
#[allow(clippy::arithmetic_side_effects)] // `n` is bounded to < 512 by the guard
pub(crate) fn shr_u512(v: U512, n: u32) -> U512 {
    if n >= 512 { U512::zero() } else { v >> n }
}

/// Left-shift a `U512`. The caller must already have proved the result fits;
/// `debug_assert` states the contract and the release path saturates to zero
/// rather than producing a silently wrapped value.
#[allow(clippy::arithmetic_side_effects)] // caller-proved width, asserted in debug
pub(crate) fn shl_u512(v: U512, n: u32) -> U512 {
    debug_assert!(
        v.is_zero() || u32::try_from(v.bits()).unwrap_or(u32::MAX).saturating_add(n) <= 512,
        "shl_u512 called with a shift that would overflow"
    );
    if n >= 512 { U512::zero() } else { v << n }
}

/// Expand a compact target into a full 256-bit target.
///
/// # Errors
///
/// - [`ConsensusError::NegativeTarget`] when mantissa bit `0x00800000` is set.
/// - [`ConsensusError::ZeroMantissaTarget`] when the mantissa is zero but the
///   exponent is not — a non-canonical spelling of zero.
/// - [`ConsensusError::TargetOverflow`] when the expansion needs over 256 bits.
///
/// `CompactTarget(0)` is the one legitimate zero: it is what
/// [`target_to_compact`] emits for a zero target, so accepting it keeps the
/// round trip total.
pub fn compact_to_target(c: CompactTarget) -> Result<Target, ConsensusError> {
    let raw = c.to_u32();
    // Split without shifting: the compact form is literally
    // `size || mantissa[2] || mantissa[1] || mantissa[0]` in big-endian bytes.
    let b = raw.to_be_bytes();
    let size = u32::from(b[0]);
    let mantissa = u32::from_be_bytes([0, b[1], b[2], b[3]]) & COMPACT_MANTISSA_MASK;

    if mantissa & COMPACT_SIGN_BIT != 0 {
        return Err(ConsensusError::NegativeTarget(raw));
    }
    if mantissa == 0 {
        if size != 0 {
            return Err(ConsensusError::ZeroMantissaTarget(raw));
        }
        return Ok(Target::ZERO);
    }

    if size <= 3 {
        // The mantissa's low bytes fall off the bottom; nothing can overflow.
        let shift = 8u32.saturating_mul(3u32.saturating_sub(size));
        Ok(Target(U256::from(mantissa.checked_shr(shift).unwrap_or(0))))
    } else {
        let shift = 8u32.saturating_mul(size.saturating_sub(3));
        shl_u256_checked(U256::from(mantissa), shift)
            .map(Target)
            .ok_or(ConsensusError::TargetOverflow(raw))
    }
}

/// Compress a target into its canonical compact form.
///
/// Always produces the non-negative, normalised spelling: the mantissa's top
/// bit is never set, and the exponent is the smallest that represents the
/// value. Low bits below the 24-bit mantissa are truncated, so the compact form
/// is always less than or equal to the target it came from — never easier.
pub fn target_to_compact(t: Target) -> CompactTarget {
    let v = t.0;
    if v.is_zero() {
        return CompactTarget(0);
    }

    // `bits()` is at most 256, so `size` is at most 32 and every step below
    // stays inside `u32`.
    let bit_len = u32::try_from(v.bits()).unwrap_or(TARGET_BITS);
    let mut size = bit_len.saturating_add(7) / 8;
    let mut mantissa: u64 = if size <= 3 {
        let shift = 8u32.saturating_mul(3u32.saturating_sub(size));
        v.low_u64().checked_shl(shift).unwrap_or(0)
    } else {
        let shift = 8u32.saturating_mul(size.saturating_sub(3));
        shr_u256(v, shift).low_u64()
    };

    // The top bit of the mantissa is the sign bit. If normalising set it, shed
    // a byte and grow the exponent instead of emitting the negative form.
    if mantissa & u64::from(COMPACT_SIGN_BIT) != 0 {
        mantissa = mantissa.checked_shr(8).unwrap_or(0);
        size = size.saturating_add(1);
    }

    let m = u32::try_from(mantissa).unwrap_or(0) & COMPACT_MANTISSA_MASK;
    let mb = m.to_be_bytes();
    let size_byte = u8::try_from(size).unwrap_or(u8::MAX);
    CompactTarget(u32::from_be_bytes([size_byte, mb[1], mb[2], mb[3]]))
}

/// True when `c` is the canonical spelling of the target it expands to.
///
/// The `target_to_compact(compact_to_target(c)) == c` round trip holds for
/// exactly the values this returns `true` for.
pub fn is_canonical_compact(c: CompactTarget) -> bool {
    match compact_to_target(c) {
        Ok(t) => target_to_compact(t) == c,
        Err(_) => false,
    }
}

/// The fork-choice weight of one block at target `t`.
///
/// `work(t) = (!t / (t + 1)) + 1`, in 256-bit integers — the expected number of
/// hashes needed to find a header at that target.
///
/// Both saturating edges are unreachable through [`compact_to_target`], whose
/// output is at most `0x7fffff * 2^232`, but `Target` is a public tuple struct:
///
/// - `t = 0` is unsatisfiable, so its true work is infinite; it saturates to
///   `U256::MAX`, the largest representable answer.
/// - `t = U256::MAX` would make `t + 1` wrap to zero; the saturating add keeps
///   the denominator at `MAX` and the result is `1`, which is also the correct
///   answer for a target that every hash meets.
pub fn work_from_target(t: Target) -> Work {
    let denominator = t.0.saturating_add(U256::one());
    let quotient = (!t.0).checked_div(denominator).unwrap_or(U256::zero());
    Work(quotient.saturating_add(U256::one()))
}

/// Difficulty relative to `pow_limit`, in **thousandths**.
///
/// `difficulty = pow_limit / target`, the number every explorer prints. Bitcoin
/// reports it as a float; floats are denied workspace-wide because a float in
/// consensus arithmetic splits the chain along CPU architecture lines, and a
/// number this visible should not be the one exception. Callers that want
/// "1234.567" format `x / 1000` and `x % 1000` themselves.
///
/// Returns 0 for a zero `target` (unsatisfiable, so difficulty is unbounded and
/// there is no honest answer) and saturates at `u128::MAX`.
pub fn difficulty_x1000(target: Target, pow_limit: Target) -> u128 {
    if target.is_zero() {
        return 0;
    }
    let numerator = widening_mul(pow_limit.0, 1_000);
    let quotient = numerator.checked_div(U512::from(target.0)).unwrap_or_else(U512::zero);
    if quotient > U512::from(u128::MAX) { u128::MAX } else { quotient.low_u128() }
}

/// Read a 32-byte digest as a big-endian 256-bit integer, the numeric value a
/// proof-of-work check compares against a target.
pub fn hash_to_u256(h: &Hash32) -> U256 {
    U256::from_big_endian(h.as_bytes())
}

/// True when `hash <= target`, i.e. the header satisfies its proof of work.
pub fn hash_meets_target(hash: &BlockHash, target: Target) -> bool {
    hash_to_u256(&hash.0) <= target.0
}

/// Multiply a target by a small factor without losing bits: the 512-bit product
/// is what ASERT then shifts.
pub(crate) fn widening_mul(t: U256, factor: u64) -> U512 {
    t.full_mul(U256::from(factor))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]

    use proptest::prelude::*;

    use super::*;

    /// Mainnet `pow_limit`, compact `0x1d00ffff`.
    fn mainnet_limit() -> Target {
        let mut l = [0u8; 32];
        l[4] = 0xff;
        l[5] = 0xff;
        Target::from_be_bytes(&l)
    }

    #[test]
    fn fixed_vector_1d00ffff_is_the_bitcoin_genesis_target() {
        let t = compact_to_target(CompactTarget(0x1d00_ffff)).unwrap();
        assert_eq!(t, mainnet_limit());
        assert_eq!(
            t.to_string(),
            "00000000ffff0000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(target_to_compact(t), CompactTarget(0x1d00_ffff));
    }

    #[test]
    fn fixed_vector_1b0404cb() {
        // Bitcoin block 100_800's bits; the canonical expansion is
        // 0x0404cb * 2^(8 * (0x1b - 3)).
        let t = compact_to_target(CompactTarget(0x1b04_04cb)).unwrap();
        assert_eq!(
            t.to_string(),
            "00000000000404cb000000000000000000000000000000000000000000000000"
        );
        assert_eq!(target_to_compact(t), CompactTarget(0x1b04_04cb));
    }

    #[test]
    fn fixed_vector_207fffff_is_the_devnet_genesis_target() {
        // The largest value the compact form can hold: a 23-bit mantissa at
        // exponent 32, i.e. 0x7fffff * 2^232. Note this is *not* the devnet
        // `pow_limit` array (0x7fff..ff): the compact encoding truncates, so
        // the genesis target is slightly harder than the limit.
        let t = compact_to_target(CompactTarget(0x207f_ffff)).unwrap();
        assert_eq!(
            t.to_string(),
            "7fffff0000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(target_to_compact(t), CompactTarget(0x207f_ffff));

        let mut limit = [0xffu8; 32];
        limit[0] = 0x7f;
        assert!(t < Target::from_be_bytes(&limit), "the compact form rounds down");
    }

    #[test]
    fn negative_form_is_rejected() {
        // 0x1d80ffff has the sign bit set inside the mantissa.
        assert_eq!(
            compact_to_target(CompactTarget(0x1d80_ffff)),
            Err(ConsensusError::NegativeTarget(0x1d80_ffff))
        );
        assert_eq!(
            compact_to_target(CompactTarget(0x0180_0000)),
            Err(ConsensusError::NegativeTarget(0x0180_0000))
        );
        assert!(!is_canonical_compact(CompactTarget(0x1d80_ffff)));
    }

    #[test]
    fn zero_mantissa_with_a_nonzero_exponent_is_rejected() {
        for size in 1u32..=0xff {
            let c = CompactTarget(u32::from_be_bytes([u8::try_from(size).unwrap(), 0, 0, 0]));
            assert_eq!(
                compact_to_target(c),
                Err(ConsensusError::ZeroMantissaTarget(c.to_u32())),
                "size {size} must be rejected"
            );
        }
    }

    #[test]
    fn a_wholly_zero_compact_is_the_canonical_zero() {
        assert_eq!(compact_to_target(CompactTarget(0)).unwrap(), Target::ZERO);
        assert_eq!(target_to_compact(Target::ZERO), CompactTarget(0));
        assert!(is_canonical_compact(CompactTarget(0)));
    }

    #[test]
    fn expansion_past_256_bits_is_rejected() {
        // size 34 shifts the mantissa up by 8 * 31 = 248 bits, so anything
        // wider than 8 significant bits runs off the end.
        assert_eq!(
            compact_to_target(CompactTarget(0x2200_ffff)),
            Err(ConsensusError::TargetOverflow(0x2200_ffff))
        );
        // … but a one-bit mantissa at the same exponent is exactly 2^248.
        assert_eq!(compact_to_target(CompactTarget(0x2200_0001)).unwrap().0, U256::one() << 248u32);
        assert_eq!(
            compact_to_target(CompactTarget(0xff7f_ffff)),
            Err(ConsensusError::TargetOverflow(0xff7f_ffff))
        );
        // The exact boundary: 0x20 = 32 bytes with a 23-bit mantissa fits …
        assert!(compact_to_target(CompactTarget(0x207f_ffff)).is_ok());
        // … and one byte more does not.
        assert_eq!(
            compact_to_target(CompactTarget(0x217f_ffff)),
            Err(ConsensusError::TargetOverflow(0x217f_ffff))
        );
    }

    #[test]
    fn boundary_of_the_size_three_branch() {
        // size == 3: the mantissa is the value itself.
        assert_eq!(compact_to_target(CompactTarget(0x0300_1234)).unwrap().0, U256::from(0x1234));
        // size == 2: one byte is shed.
        assert_eq!(compact_to_target(CompactTarget(0x0200_1234)).unwrap().0, U256::from(0x12));
        // size == 1: two bytes are shed.
        assert_eq!(compact_to_target(CompactTarget(0x0100_1234)).unwrap().0, U256::zero());
        // size == 4: one byte is added.
        assert_eq!(
            compact_to_target(CompactTarget(0x0400_1234)).unwrap().0,
            U256::from(0x0012_3400u32)
        );
    }

    #[test]
    fn non_canonical_spellings_are_detected() {
        // 0x0100_1234 expands to zero, whose canonical form is 0x00000000.
        assert!(!is_canonical_compact(CompactTarget(0x0100_1234)));
        // A mantissa with a spare leading zero byte is non-canonical.
        assert!(!is_canonical_compact(CompactTarget(0x0400_00ff)));
        // 0x0200_00ff expands to 0xff >> 8 == 0, so it is a spelling of zero.
        assert!(!is_canonical_compact(CompactTarget(0x0200_00ff)));
        // The canonical spelling of 0xff is 0x0200ff00: normalising to size 3
        // would set the sign bit, so the encoder sheds a byte.
        assert_eq!(target_to_compact(Target(U256::from(0xffu64))), CompactTarget(0x0200_ff00));
        assert!(is_canonical_compact(CompactTarget(0x0200_ff00)));
    }

    #[test]
    fn normalisation_sheds_a_byte_rather_than_emitting_the_sign_bit() {
        // 0x00800000 as a raw value: bits() == 24, size == 3, mantissa
        // 0x800000 would set the sign bit, so the encoder must emit size 4.
        let t = Target(U256::from(0x0080_0000u32));
        let c = target_to_compact(t);
        assert_eq!(c, CompactTarget(0x0400_8000));
        assert_eq!(compact_to_target(c).unwrap(), t);
        assert!(is_canonical_compact(c));
    }

    #[test]
    fn compact_encoding_never_rounds_a_target_easier() {
        for raw in [0x1d00_ffffu32, 0x1b04_04cb, 0x207f_ffff, 0x0300_1234] {
            let t = compact_to_target(CompactTarget(raw)).unwrap();
            let back = compact_to_target(target_to_compact(t)).unwrap();
            assert!(back <= t, "{raw:#x} rounded up");
        }
    }

    #[test]
    fn work_of_the_mainnet_limit_matches_the_closed_form() {
        // (!t / (t+1)) + 1 with t = 0xffff * 2^208 is 2^256 / (2^208 * 0x10000)
        // rounded down, i.e. 0x100010001 (Bitcoin's difficulty-1 chainwork).
        let w = work_from_target(mainnet_limit());
        assert_eq!(w.0, U256::from(0x0001_0001_0001u64));
    }

    #[test]
    fn work_edges_are_defined() {
        // t = 0 is unsatisfiable, so its work saturates at the maximum.
        assert_eq!(work_from_target(Target::ZERO), Work(U256::max_value()));
        // t = MAX is met by every hash, so one hash is enough.
        assert_eq!(work_from_target(Target::MAX), Work::ONE);
        // t = 1: (!1 / 2) + 1 = (2^256 - 2)/2 + 1 = 2^255.
        assert_eq!(work_from_target(Target(U256::one())), Work(U256::one() << 255u32));
    }

    #[test]
    fn halving_the_target_doubles_the_work() {
        let t = mainnet_limit();
        let half = Target(shr_u256(t.0, 1));
        let w1 = work_from_target(t).0;
        let w2 = work_from_target(half).0;
        // Exactly double, up to the +1 rounding term in each.
        assert!(w2 >= w1 * U256::from(2u64) - U256::from(2u64));
        assert!(w2 <= w1 * U256::from(2u64) + U256::from(2u64));
    }

    #[test]
    fn work_is_strictly_monotonic_in_difficulty() {
        let mut prev = Work::ZERO;
        for shift in [0u32, 8, 16, 32, 64, 128, 200] {
            let t = Target(shr_u256(U256::max_value(), shift));
            let w = work_from_target(t);
            assert!(w > prev, "work must grow as the target shrinks");
            prev = w;
        }
    }

    #[test]
    fn work_round_trips_through_big_endian_bytes() {
        let w = work_from_target(mainnet_limit());
        assert_eq!(Work::from_be_bytes(&w.to_be_bytes()), w);
        assert_eq!(Work::ZERO.to_be_bytes(), [0u8; 32]);
        assert!(Work::ZERO.is_zero());
        assert!(!Work::ONE.is_zero());
    }

    #[test]
    fn work_addition_is_checked() {
        let a = Work(U256::max_value());
        assert_eq!(a.checked_add(Work::ONE), None);
        assert_eq!(a.saturating_add(Work::ONE), a);
        assert_eq!(Work::ONE.checked_add(Work::ONE), Some(Work(U256::from(2u64))));
    }

    #[test]
    fn hashes_are_compared_big_endian() {
        let target = compact_to_target(CompactTarget(0x1d00_ffff)).unwrap();

        // Four leading zero bytes then 0x0000ffff… : exactly the limit.
        let mut at_limit = [0u8; 32];
        at_limit[4] = 0xff;
        at_limit[5] = 0xff;
        assert!(hash_meets_target(&BlockHash::from_bytes(at_limit), target));

        // One more in the last byte and it is over.
        let mut over = at_limit;
        over[31] = 0x01;
        assert!(!hash_meets_target(&BlockHash::from_bytes(over), target));

        // A hash with a high leading byte fails, even though its *last* bytes
        // are zero — this is the test that catches a little-endian reading.
        let mut leading = [0u8; 32];
        leading[0] = 0x01;
        assert!(!hash_meets_target(&BlockHash::from_bytes(leading), target));

        assert!(hash_meets_target(&BlockHash::from_bytes([0u8; 32]), target));
    }

    #[test]
    fn difficulty_is_reported_in_thousandths_without_a_float() {
        let limit = mainnet_limit();
        assert_eq!(difficulty_x1000(limit, limit), 1_000, "the limit itself is difficulty 1");

        // Halving the target doubles the difficulty, exactly.
        let harder = Target(shr_u256(limit.0, 1));
        assert_eq!(difficulty_x1000(harder, limit), 2_000);
        assert_eq!(difficulty_x1000(Target(shr_u256(limit.0, 10)), limit), 1_024_000);

        // An easier target lands below 1, with three decimal places of detail.
        let easier = Target(limit.0 * U256::from(4u64));
        assert_eq!(difficulty_x1000(easier, limit), 250);

        // Edges: a zero target has no honest answer, and the arithmetic
        // saturates rather than wrapping.
        assert_eq!(difficulty_x1000(Target::ZERO, limit), 0);
        assert_eq!(difficulty_x1000(Target(U256::one()), Target::MAX), u128::MAX);
        assert_eq!(difficulty_x1000(Target::MAX, Target::MAX), 1_000);
    }

    #[test]
    fn difficulty_is_antitone_in_the_target() {
        let limit = mainnet_limit();
        let mut previous = u128::MAX;
        for shift in [0u32, 1, 2, 4, 8, 16] {
            let d = difficulty_x1000(Target(shr_u256(limit.0, 16 - shift)), limit);
            assert!(d <= previous, "difficulty must fall as the target grows");
            previous = d;
        }
    }

    #[test]
    fn display_is_sixty_four_hex_characters() {
        let t = compact_to_target(CompactTarget(0x1d00_ffff)).unwrap();
        assert_eq!(t.to_string().len(), 64);
        assert_eq!(work_from_target(t).to_string().len(), 64);
    }

    #[test]
    fn target_helpers_agree_with_the_free_functions() {
        let c = CompactTarget(0x1d00_ffff);
        let t = Target::from_compact(c).unwrap();
        assert_eq!(t.to_compact(), c);
        assert_eq!(t.work(), work_from_target(t));
        assert!(!t.is_zero());
        assert!(Target::ZERO.is_zero());
        assert_eq!(Target::from(U256::one()), Target(U256::one()));
        assert_eq!(Target::MAX.0, U256::max_value());
    }

    #[test]
    fn shift_helpers_saturate_instead_of_panicking() {
        assert_eq!(shr_u256(U256::max_value(), 256), U256::zero());
        assert_eq!(shr_u256(U256::max_value(), u32::MAX), U256::zero());
        assert_eq!(shl_u256_checked(U256::zero(), u32::MAX), Some(U256::zero()));
        assert_eq!(shl_u256_checked(U256::one(), 255), Some(U256::one() << 255u32));
        assert_eq!(shl_u256_checked(U256::one(), 256), None);
        assert_eq!(shr_u512(U512::max_value(), 512), U512::zero());
        assert_eq!(shr_u512(U512::max_value(), u32::MAX), U512::zero());
        assert_eq!(shl_u512(U512::one(), 100), U512::one() << 100u32);
        assert_eq!(shl_u512(U512::zero(), 511), U512::zero());
    }

    proptest! {
        /// The contract's headline round trip, over every canonical `c`.
        #[test]
        fn canonical_compact_round_trips(raw in any::<u32>()) {
            let c = CompactTarget(raw);
            if is_canonical_compact(c) {
                let t = compact_to_target(c).unwrap();
                prop_assert_eq!(target_to_compact(t), c);
            }
        }

        /// Every target compresses to a compact form that expands to something
        /// no greater than it, and compressing again is idempotent.
        #[test]
        fn compact_is_idempotent_and_never_rounds_up(bytes in any::<[u8; 32]>()) {
            let t = Target::from_be_bytes(&bytes);
            let c = target_to_compact(t);
            let back = compact_to_target(c).unwrap();
            prop_assert!(back <= t);
            prop_assert_eq!(target_to_compact(back), c);
            prop_assert!(is_canonical_compact(c));
        }

        /// `compact_to_target` never panics and never returns a negative or
        /// oversized value.
        #[test]
        fn compact_to_target_is_total(raw in any::<u32>()) {
            match compact_to_target(CompactTarget(raw)) {
                Ok(t) => {
                    prop_assert!(t.0.bits() <= 256);
                    prop_assert_eq!(raw & COMPACT_SIGN_BIT, 0);
                }
                Err(e) => {
                    prop_assert!(matches!(
                        e,
                        ConsensusError::NegativeTarget(_)
                            | ConsensusError::ZeroMantissaTarget(_)
                            | ConsensusError::TargetOverflow(_)
                    ));
                }
            }
        }

        /// Work is monotonically non-increasing in the target.
        #[test]
        fn work_is_monotonic(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
            let (ta, tb) = (Target::from_be_bytes(&a), Target::from_be_bytes(&b));
            if ta <= tb {
                prop_assert!(work_from_target(ta) >= work_from_target(tb));
            } else {
                prop_assert!(work_from_target(ta) <= work_from_target(tb));
            }
        }

        /// Work is never zero: even the easiest target costs one hash.
        #[test]
        fn work_is_never_zero(bytes in any::<[u8; 32]>()) {
            prop_assert!(!work_from_target(Target::from_be_bytes(&bytes)).is_zero());
        }

        /// A hash meets a target exactly when its big-endian value is not
        /// greater — stated independently of the implementation.
        #[test]
        fn hash_comparison_is_big_endian(h in any::<[u8; 32]>(), t in any::<[u8; 32]>()) {
            let expected = h <= t; // arrays compare lexicographically = big-endian
            prop_assert_eq!(
                hash_meets_target(&BlockHash::from_bytes(h), Target::from_be_bytes(&t)),
                expected
            );
        }
    }
}
