//! Script numbers and booleans (CONTRACT §5.3).
//!
//! Numbers are minimally-encoded, sign-magnitude little-endian byte strings —
//! Bitcoin's `CScriptNum` rules, kept because they are well understood and
//! because a byte-compatible encoding costs nothing.
//!
//! Two asymmetries matter and are deliberate:
//!
//! - **Reading is limited, writing is not.** An arithmetic opcode reads at most
//!   [`ScriptLimits::max_num_size`] bytes (4), which pins operands to the `i32`
//!   range. A *result* is held in an `i64` and may serialise to five bytes; a
//!   later opcode that tries to read it back fails with
//!   [`ScriptError::NumTooLarge`]. That is exactly Bitcoin's contract, and it
//!   is what makes `OP_ADD` on two four-byte operands total rather than
//!   truncating.
//! - **Minimality is enforced where a value is read**, not where it is written.
//!   `0x00 0x00 0x01` and `0x01` denote the same number; only the second is
//!   accepted, so a witness cannot be mutated without changing the txid.
//!
//! Booleans are separate: the empty string, `0x00`, `0x80` and any all-zero
//! string with only the sign bit set are false; everything else is true. Note
//! `0x80` is *negative zero*, which is why it is false despite being non-empty.
//!
//! [`ScriptLimits::max_num_size`]: crate::limits::ScriptLimits::max_num_size

use crate::error::ScriptError;
use crate::limits::NUM_BUFFER_SIZE;

/// A number as the VM sees it: an `i64` that came from, or is going to, a
/// minimally-encoded sign-magnitude byte string.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScriptNum(i64);

impl ScriptNum {
    /// Zero, which encodes as the empty byte string.
    pub const ZERO: ScriptNum = ScriptNum(0);
    /// One.
    pub const ONE: ScriptNum = ScriptNum(1);
    /// Minus one, which `OP_1NEGATE` pushes.
    pub const NEGATIVE_ONE: ScriptNum = ScriptNum(-1);

    /// The largest value a four-byte operand can hold.
    pub const MAX_4_BYTE: i64 = 0x7fff_ffff;
    /// The smallest value a four-byte operand can hold. Sign-magnitude has no
    /// `i32::MIN`: `0x80000000` is negative zero, not `-2^31`.
    pub const MIN_4_BYTE: i64 = -0x7fff_ffff;

    /// Wrap a raw value. Used for results of arithmetic, which are not
    /// range-checked on the way out.
    pub const fn new(v: i64) -> Self {
        ScriptNum(v)
    }

    /// The underlying value.
    pub const fn value(self) -> i64 {
        self.0
    }

    /// Decode a stack element as a number.
    ///
    /// `max_size` is the widest encoding the calling opcode accepts — 4 for
    /// arithmetic, 5 for `OP_CHECKLOCKTIMEVERIFY` and
    /// `OP_CHECKSEQUENCEVERIFY`. `require_minimal` is always true in consensus;
    /// the parameter exists so the minimality rule itself can be tested from
    /// both sides.
    pub fn from_slice(
        bytes: &[u8],
        max_size: usize,
        require_minimal: bool,
    ) -> Result<Self, ScriptError> {
        let cap = if max_size > NUM_BUFFER_SIZE { NUM_BUFFER_SIZE } else { max_size };
        if bytes.len() > cap {
            return Err(ScriptError::NumTooLarge { len: bytes.len(), max: cap });
        }
        if bytes.is_empty() {
            return Ok(ScriptNum::ZERO);
        }
        if require_minimal && !is_minimally_encoded(bytes) {
            return Err(ScriptError::NonMinimalNum);
        }

        // Copy into a fixed buffer so the sign bit can be cleared without
        // mutating the caller's stack element.
        let mut buf = [0u8; NUM_BUFFER_SIZE];
        let head = buf.get_mut(..bytes.len()).ok_or(ScriptError::NumericOverflow)?;
        head.copy_from_slice(bytes);
        let last = bytes.len().checked_sub(1).ok_or(ScriptError::NumericOverflow)?;
        let top = buf.get_mut(last).ok_or(ScriptError::NumericOverflow)?;
        let negative = *top & 0x80 != 0;
        *top &= 0x7f;

        let mut magnitude: u64 = 0;
        let body = buf.get(..bytes.len()).ok_or(ScriptError::NumericOverflow)?;
        for &b in body.iter().rev() {
            magnitude =
                magnitude.checked_shl(8).ok_or(ScriptError::NumericOverflow)? | u64::from(b);
        }

        let value = i64::try_from(magnitude).map_err(|_| ScriptError::NumericOverflow)?;
        let signed =
            if negative { value.checked_neg().ok_or(ScriptError::NumericOverflow)? } else { value };
        Ok(ScriptNum(signed))
    }

    /// Decode a stack element as an arithmetic operand: at most `max_size`
    /// bytes, minimally encoded.
    pub fn arithmetic(bytes: &[u8], max_size: usize) -> Result<Self, ScriptError> {
        ScriptNum::from_slice(bytes, max_size, true)
    }

    /// The minimal sign-magnitude little-endian encoding.
    ///
    /// Zero is the empty byte string, which is also what `OP_0` pushes and what
    /// the boolean `false` is.
    pub fn to_vec(self) -> Vec<u8> {
        if self.0 == 0 {
            return Vec::new();
        }
        let negative = self.0 < 0;
        // `unsigned_abs` is total: it handles `i64::MIN`, which plain negation
        // does not.
        let mut magnitude = self.0.unsigned_abs();
        let mut out = Vec::with_capacity(9);
        while magnitude > 0 {
            out.push((magnitude & 0xff) as u8);
            magnitude = magnitude.wrapping_shr(8);
        }
        // The top byte's high bit is the sign, so a magnitude that already uses
        // it needs one more byte to carry the sign.
        if out.last().copied().unwrap_or(0) & 0x80 != 0 {
            out.push(if negative { 0x80 } else { 0x00 });
        } else if negative && let Some(top) = out.last_mut() {
            *top |= 0x80;
        }
        out
    }

    /// True when the value is non-zero — the boolean reading of a number.
    pub const fn to_bool(self) -> bool {
        self.0 != 0
    }
}

impl From<i64> for ScriptNum {
    fn from(v: i64) -> Self {
        ScriptNum(v)
    }
}

impl From<ScriptNum> for i64 {
    fn from(v: ScriptNum) -> Self {
        v.0
    }
}

impl std::fmt::Display for ScriptNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// True when `bytes` is the shortest sign-magnitude encoding of its value.
///
/// The rule: the most significant byte must carry information. It may be
/// `0x00` or `0x80` only when the byte below it already has its high bit set,
/// because in that case the extra byte exists solely to hold the sign.
pub fn is_minimally_encoded(bytes: &[u8]) -> bool {
    let Some((&last, rest)) = bytes.split_last() else {
        // The empty string is the canonical zero.
        return true;
    };
    if last & 0x7f != 0 {
        return true;
    }
    // `last` is 0x00 or 0x80: only legitimate as a sign byte.
    matches!(rest.last(), Some(&prev) if prev & 0x80 != 0)
}

/// The boolean reading of a stack element.
///
/// False for the empty string and for any string whose bytes are all zero
/// except possibly a sign bit in the final byte — `0x80` is negative zero.
pub fn cast_to_bool(bytes: &[u8]) -> bool {
    let last_index = bytes.len().saturating_sub(1);
    for (i, &b) in bytes.iter().enumerate() {
        if b != 0 {
            return !(i == last_index && b == 0x80);
        }
    }
    false
}

/// The canonical stack encoding of a boolean: `{0x01}` for true, `{}` for
/// false.
pub fn bool_to_vec(v: bool) -> Vec<u8> {
    if v { vec![1u8] } else { Vec::new() }
}

/// True when `bytes` is exactly `{}` or `{0x01}`.
///
/// `OP_IF` and `OP_NOTIF` demand this. Bitcoin accepts any truthy value there
/// and had to add `MINIMALIF` as a policy patch; making it consensus from the
/// start removes a witness-malleability vector — with any-truthy conditions an
/// attacker can rewrite `0x02` to `0x03` and change a transaction's id without
/// invalidating it.
pub fn is_minimal_bool(bytes: &[u8]) -> bool {
    bytes.is_empty() || bytes == [1u8]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use proptest::prelude::*;

    fn dec(b: &[u8]) -> Result<i64, ScriptError> {
        ScriptNum::from_slice(b, 4, true).map(ScriptNum::value)
    }

    #[test]
    fn zero_is_the_empty_string() {
        assert_eq!(dec(&[]).unwrap(), 0);
        assert_eq!(ScriptNum::new(0).to_vec(), Vec::<u8>::new());
    }

    #[test]
    fn known_encodings() {
        let cases: &[(i64, &[u8])] = &[
            (1, &[0x01]),
            (-1, &[0x81]),
            (16, &[0x10]),
            (127, &[0x7f]),
            (128, &[0x80, 0x00]),
            (-128, &[0x80, 0x80]),
            (255, &[0xff, 0x00]),
            (256, &[0x00, 0x01]),
            (-256, &[0x00, 0x81]),
            (0x7fff_ffff, &[0xff, 0xff, 0xff, 0x7f]),
            (-0x7fff_ffff, &[0xff, 0xff, 0xff, 0xff]),
        ];
        for (v, bytes) in cases {
            assert_eq!(&ScriptNum::new(*v).to_vec()[..], *bytes, "encoding {v}");
            assert_eq!(dec(bytes).unwrap(), *v, "decoding {bytes:?}");
        }
    }

    #[test]
    fn negative_zero_decodes_as_zero_but_is_not_minimal() {
        assert_eq!(dec(&[0x80]), Err(ScriptError::NonMinimalNum));
        assert_eq!(ScriptNum::from_slice(&[0x80], 4, false).unwrap().value(), 0);
        assert!(!cast_to_bool(&[0x80]));
    }

    #[test]
    fn non_minimal_encodings_are_rejected() {
        for b in [&[0x00][..], &[0x01, 0x00], &[0x00, 0x00], &[0xff, 0x00, 0x00]] {
            assert_eq!(dec(b), Err(ScriptError::NonMinimalNum), "{b:?}");
            assert!(!is_minimally_encoded(b), "{b:?}");
        }
    }

    #[test]
    fn a_sign_byte_is_minimal_when_it_is_needed() {
        assert!(is_minimally_encoded(&[0x80, 0x00]));
        assert!(is_minimally_encoded(&[0xff, 0x80]));
        assert!(is_minimally_encoded(&[]));
        assert!(is_minimally_encoded(&[0x01]));
    }

    #[test]
    fn operands_wider_than_the_limit_are_rejected() {
        assert_eq!(
            dec(&[0x01, 0x02, 0x03, 0x04, 0x05]),
            Err(ScriptError::NumTooLarge { len: 5, max: 4 })
        );
        // Five bytes are fine for a locktime operand.
        assert_eq!(
            ScriptNum::from_slice(&[0xff, 0xff, 0xff, 0xff, 0x00], 5, true).unwrap().value(),
            0xffff_ffff
        );
    }

    #[test]
    fn a_request_wider_than_the_buffer_is_clamped() {
        let too_wide = vec![0x01u8; 9];
        assert_eq!(
            ScriptNum::from_slice(&too_wide, 64, true),
            Err(ScriptError::NumTooLarge { len: 9, max: NUM_BUFFER_SIZE })
        );
    }

    #[test]
    fn booleans_follow_the_negative_zero_rule() {
        assert!(!cast_to_bool(&[]));
        assert!(!cast_to_bool(&[0x00]));
        assert!(!cast_to_bool(&[0x00, 0x00]));
        assert!(!cast_to_bool(&[0x00, 0x80]));
        assert!(cast_to_bool(&[0x01]));
        assert!(cast_to_bool(&[0x80, 0x00]));
        assert!(cast_to_bool(&[0x00, 0x01]));
        assert!(cast_to_bool(&[0x80, 0x80]));
    }

    #[test]
    fn minimal_bool_is_exactly_two_strings() {
        assert!(is_minimal_bool(&[]));
        assert!(is_minimal_bool(&[0x01]));
        assert!(!is_minimal_bool(&[0x00]));
        assert!(!is_minimal_bool(&[0x02]));
        assert!(!is_minimal_bool(&[0x01, 0x00]));
        assert_eq!(bool_to_vec(true), vec![1u8]);
        assert_eq!(bool_to_vec(false), Vec::<u8>::new());
    }

    #[test]
    fn conversions_are_transparent() {
        assert_eq!(i64::from(ScriptNum::from(-7i64)), -7);
        assert_eq!(ScriptNum::new(42).to_string(), "42");
        assert!(ScriptNum::ONE.to_bool());
        assert!(!ScriptNum::ZERO.to_bool());
        assert!(ScriptNum::NEGATIVE_ONE.to_bool());
    }

    proptest! {
        #[test]
        fn encode_then_decode_round_trips(v in ScriptNum::MIN_4_BYTE..=ScriptNum::MAX_4_BYTE) {
            let bytes = ScriptNum::new(v).to_vec();
            prop_assert!(bytes.len() <= 4);
            prop_assert!(is_minimally_encoded(&bytes));
            prop_assert_eq!(dec(&bytes).unwrap(), v);
        }

        #[test]
        fn wide_results_round_trip_at_five_bytes(v in -0xffff_ffffi64..=0xffff_ffffi64) {
            let bytes = ScriptNum::new(v).to_vec();
            prop_assert!(bytes.len() <= 5);
            prop_assert_eq!(ScriptNum::from_slice(&bytes, 5, true).unwrap().value(), v);
        }

        #[test]
        fn decoding_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..12)) {
            let _ = ScriptNum::from_slice(&bytes, 4, true);
            let _ = ScriptNum::from_slice(&bytes, 5, false);
            let _ = ScriptNum::from_slice(&bytes, 64, true);
            let _ = cast_to_bool(&bytes);
            let _ = is_minimally_encoded(&bytes);
        }

        #[test]
        fn every_accepted_encoding_is_the_canonical_one(
            bytes in proptest::collection::vec(any::<u8>(), 0..5)
        ) {
            if let Ok(n) = ScriptNum::from_slice(&bytes, 4, true) {
                prop_assert_eq!(n.to_vec(), bytes);
            }
        }
    }
}
