//! Monetary amounts, denominated in grains.
//!
//! `1 FRM = 100_000_000 grain`, the same 8 decimal places Bitcoin uses, so the
//! whole money supply fits comfortably in a `u64`.
//!
//! [`Amount`] deliberately has **no** `Add`/`Sub`/`Mul` impls (CONTRACT §3,
//! DECISIONS D7). Every monetary operation is a `checked_*` call whose `None`
//! becomes a typed error at the call site. Writing an inflation bug therefore
//! has to be deliberate: it requires calling `.to_grains()` first, which is
//! greppable in review.

use std::fmt;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::error::TypeError;

/// Grains in one FRM.
pub const COIN: u64 = 100_000_000;

/// Fractional digits in the textual FRM form, as a `usize` for slicing.
const FRAC_DIGITS: usize = 8;

/// The total money supply, in grains: 21 million FRM.
///
/// Re-exported at the crate root as a convenience; [`Amount::MAX_MONEY`] is
/// the canonical spelling named by the contract.
pub const MAX_MONEY: Amount = Amount::MAX_MONEY;

/// A monetary amount, in grains.
///
/// Borsh and serde both encode it as the bare `u64` grain count: a JSON amount
/// is an integer, never a decimal string, so no consumer can reintroduce a
/// float at the edge.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct Amount(u64);

impl Amount {
    /// Zero grains.
    pub const ZERO: Amount = Amount(0);

    /// One grain — the smallest representable amount.
    pub const ONE_GRAIN: Amount = Amount(1);

    /// One FRM.
    pub const ONE_FRM: Amount = Amount(COIN);

    /// The total money supply: `21_000_000 * COIN` grains.
    pub const MAX_MONEY: Amount = Amount(21_000_000 * COIN);

    /// Number of decimal places in the textual FRM form.
    pub const DECIMALS: u32 = 8;

    /// Wrap a raw grain count.
    ///
    /// No range check: the value may exceed [`Amount::MAX_MONEY`], which is
    /// exactly what makes [`Amount::is_valid_money`] a meaningful check on
    /// decoded, attacker-supplied data.
    pub const fn from_grains(v: u64) -> Self {
        Amount(v)
    }

    /// The raw grain count.
    pub const fn to_grains(self) -> u64 {
        self.0
    }

    /// Parse a decimal FRM string such as `"12.34567890"`.
    ///
    /// This is an exact integer parser — no float ever touches the value.
    /// Accepted: an optional integer part of ASCII digits, optionally followed
    /// by `.` and 1..=8 ASCII digits. Rejected: the empty string, a leading
    /// sign, whitespace, a bare `.5` or `1.`, more than one `.`, more than 8
    /// decimal places, anything that overflows `u64`, and anything above
    /// [`Amount::MAX_MONEY`].
    pub fn from_frm_str(s: &str) -> Result<Self, TypeError> {
        if s.is_empty() {
            return Err(TypeError::EmptyAmount);
        }
        let invalid = || TypeError::InvalidAmount(s.to_owned());

        let (int_part, frac_part, has_dot) = match s.split_once('.') {
            Some((i, f)) => (i, f, true),
            None => (s, "", false),
        };
        // A second dot lands in `frac_part`; ".5" and "1." are both malformed.
        if frac_part.contains('.') || int_part.is_empty() || (has_dot && frac_part.is_empty()) {
            return Err(invalid());
        }
        if !int_part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        if !frac_part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        if frac_part.len() > FRAC_DIGITS {
            return Err(TypeError::TooManyDecimals { max: Self::DECIMALS });
        }

        // `int_part` is all digits, so the only parse failure is overflow.
        let whole: u64 = int_part.parse().map_err(|_| TypeError::AmountOverflow)?;

        // Right-pad the fraction to 8 digits: "5" means 0.5 FRM, not 5 grains.
        let mut frac: u64 = 0;
        let bytes = frac_part.as_bytes();
        for i in 0..FRAC_DIGITS {
            let digit = match bytes.get(i) {
                Some(b) => u64::from(b.wrapping_sub(b'0')),
                None => 0,
            };
            // Bounded by 99_999_999, so this cannot overflow.
            frac = frac.saturating_mul(10).saturating_add(digit);
        }

        let grains = whole
            .checked_mul(COIN)
            .and_then(|w| w.checked_add(frac))
            .ok_or(TypeError::AmountOverflow)?;
        let amount = Amount(grains);
        if !amount.is_valid_money() {
            return Err(TypeError::AmountOutOfRange(grains));
        }
        Ok(amount)
    }

    /// Render as a decimal FRM string with all 8 decimal places, e.g.
    /// `"12.34567890"`. Trailing zeros are kept so the width is constant and
    /// the string round-trips through [`Amount::from_frm_str`].
    pub fn to_frm_string(self) -> String {
        let whole = self.0 / COIN;
        let frac = self.0 % COIN;
        format!("{whole}.{frac:08}")
    }

    /// Checked addition; `None` on `u64` overflow.
    ///
    /// Note this is *only* an overflow check: the caller decides whether the
    /// result also has to satisfy [`Amount::is_valid_money`].
    pub const fn checked_add(self, o: Amount) -> Option<Amount> {
        match self.0.checked_add(o.0) {
            Some(v) => Some(Amount(v)),
            None => None,
        }
    }

    /// Checked subtraction; `None` when the result would be negative.
    pub const fn checked_sub(self, o: Amount) -> Option<Amount> {
        match self.0.checked_sub(o.0) {
            Some(v) => Some(Amount(v)),
            None => None,
        }
    }

    /// Checked multiplication by a scalar; `None` on `u64` overflow.
    pub const fn checked_mul_u64(self, k: u64) -> Option<Amount> {
        match self.0.checked_mul(k) {
            Some(v) => Some(Amount(v)),
            None => None,
        }
    }

    /// Checked division by a scalar; `None` when `k == 0`.
    ///
    /// Used by fee-rate arithmetic in the mempool and wallet, which must never
    /// panic on a caller-supplied divisor.
    pub const fn checked_div_u64(self, k: u64) -> Option<Amount> {
        match self.0.checked_div(k) {
            Some(v) => Some(Amount(v)),
            None => None,
        }
    }

    /// Saturating addition, clamped at `u64::MAX`.
    pub const fn saturating_add(self, o: Amount) -> Amount {
        Amount(self.0.saturating_add(o.0))
    }

    /// Saturating subtraction, clamped at zero.
    pub const fn saturating_sub(self, o: Amount) -> Amount {
        Amount(self.0.saturating_sub(o.0))
    }

    /// `0 <= v <= MAX_MONEY` — the consensus range check.
    pub const fn is_valid_money(self) -> bool {
        self.0 <= Self::MAX_MONEY.0
    }

    /// True when the amount is exactly zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Amount {
    /// The plain decimal FRM form, without a ticker suffix.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_frm_string())
    }
}

impl FromStr for Amount {
    type Err = TypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Amount::from_frm_str(s)
    }
}

impl From<Amount> for u64 {
    fn from(a: Amount) -> u64 {
        a.0
    }
}

impl From<u64> for Amount {
    fn from(v: u64) -> Amount {
        Amount(v)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn constants_match_the_contract() {
        assert_eq!(COIN, 100_000_000);
        assert_eq!(Amount::MAX_MONEY.to_grains(), 21_000_000 * 100_000_000);
        assert_eq!(Amount::MAX_MONEY.to_grains(), 2_100_000_000_000_000);
        assert_eq!(MAX_MONEY, Amount::MAX_MONEY);
        assert_eq!(Amount::ZERO.to_grains(), 0);
        assert_eq!(Amount::ONE_GRAIN.to_grains(), 1);
        assert_eq!(Amount::ONE_FRM.to_grains(), COIN);
        assert_eq!(Amount::DECIMALS, 8);
        assert_eq!(Amount::default(), Amount::ZERO);
        assert!(Amount::ZERO.is_zero());
        assert!(!Amount::ONE_GRAIN.is_zero());
    }

    #[test]
    fn grain_conversions_are_lossless() {
        assert_eq!(Amount::from_grains(12_345).to_grains(), 12_345);
        assert_eq!(u64::from(Amount::from_grains(7)), 7);
        assert_eq!(Amount::from(7u64), Amount::from_grains(7));
    }

    #[test]
    fn checked_add_returns_none_on_true_u64_overflow() {
        let max = Amount::from_grains(u64::MAX);
        assert_eq!(max.checked_add(Amount::ZERO), Some(max));
        assert_eq!(max.checked_add(Amount::ONE_GRAIN), None);
        assert_eq!(
            Amount::from_grains(3).checked_add(Amount::from_grains(4)),
            Some(Amount::from_grains(7))
        );
    }

    #[test]
    fn checked_sub_returns_none_below_zero() {
        assert_eq!(Amount::ZERO.checked_sub(Amount::ONE_GRAIN), None);
        assert_eq!(
            Amount::from_grains(10).checked_sub(Amount::from_grains(4)),
            Some(Amount::from_grains(6))
        );
        assert_eq!(Amount::ONE_GRAIN.checked_sub(Amount::ONE_GRAIN), Some(Amount::ZERO));
    }

    #[test]
    fn checked_mul_and_div() {
        assert_eq!(Amount::from_grains(21).checked_mul_u64(2), Some(Amount::from_grains(42)));
        assert_eq!(Amount::from_grains(u64::MAX).checked_mul_u64(2), None);
        assert_eq!(Amount::from_grains(0).checked_mul_u64(u64::MAX), Some(Amount::ZERO));
        assert_eq!(Amount::from_grains(42).checked_div_u64(2), Some(Amount::from_grains(21)));
        assert_eq!(Amount::from_grains(42).checked_div_u64(0), None);
    }

    #[test]
    fn saturating_helpers_clamp() {
        let max = Amount::from_grains(u64::MAX);
        assert_eq!(max.saturating_add(Amount::ONE_GRAIN), max);
        assert_eq!(Amount::ZERO.saturating_sub(Amount::ONE_GRAIN), Amount::ZERO);
        assert_eq!(
            Amount::from_grains(5).saturating_add(Amount::from_grains(5)),
            Amount::from_grains(10)
        );
    }

    #[test]
    fn is_valid_money_boundaries() {
        assert!(Amount::ZERO.is_valid_money());
        assert!(Amount::MAX_MONEY.is_valid_money());
        assert!(!Amount::from_grains(Amount::MAX_MONEY.to_grains() + 1).is_valid_money());
        assert!(!Amount::from_grains(u64::MAX).is_valid_money());
    }

    #[test]
    fn from_frm_str_accepts_a_bare_integer() {
        assert_eq!(Amount::from_frm_str("1").unwrap(), Amount::from_grains(COIN));
        assert_eq!(Amount::from_frm_str("0").unwrap(), Amount::ZERO);
        assert_eq!(Amount::from_frm_str("50").unwrap(), Amount::from_grains(50 * COIN));
        assert_eq!(Amount::from_frm_str("007").unwrap(), Amount::from_grains(7 * COIN));
    }

    #[test]
    fn from_frm_str_accepts_fractions() {
        assert_eq!(Amount::from_frm_str("0.5").unwrap(), Amount::from_grains(50_000_000));
        assert_eq!(Amount::from_frm_str("0.00000001").unwrap(), Amount::ONE_GRAIN);
        assert_eq!(
            Amount::from_frm_str("12.34567890").unwrap(),
            Amount::from_grains(12 * COIN + 34_567_890)
        );
        assert_eq!(Amount::from_frm_str("0.00000000").unwrap(), Amount::ZERO);
    }

    #[test]
    fn from_frm_str_rejects_a_missing_integer_part() {
        // ".5" is rejected: an amount always has an explicit integer part.
        assert_eq!(Amount::from_frm_str(".5"), Err(TypeError::InvalidAmount(".5".to_owned())));
    }

    #[test]
    fn from_frm_str_rejects_a_missing_fraction() {
        assert_eq!(Amount::from_frm_str("1."), Err(TypeError::InvalidAmount("1.".to_owned())));
    }

    #[test]
    fn from_frm_str_rejects_the_empty_string() {
        assert_eq!(Amount::from_frm_str(""), Err(TypeError::EmptyAmount));
    }

    #[test]
    fn from_frm_str_rejects_multiple_dots() {
        assert_eq!(
            Amount::from_frm_str("1.2.3"),
            Err(TypeError::InvalidAmount("1.2.3".to_owned()))
        );
        assert!(Amount::from_frm_str("..").is_err());
        assert!(Amount::from_frm_str(".").is_err());
    }

    #[test]
    fn from_frm_str_rejects_more_than_eight_decimals() {
        assert_eq!(Amount::from_frm_str("1.000000001"), Err(TypeError::TooManyDecimals { max: 8 }));
        assert!(Amount::from_frm_str("0.123456789").is_err());
        // Exactly eight is fine.
        assert!(Amount::from_frm_str("0.12345678").is_ok());
    }

    #[test]
    fn from_frm_str_rejects_signs_whitespace_and_junk() {
        for bad in ["-1", "+1", " 1", "1 ", "1_000", "abc", "1e8", "0x10", "1,5", "\u{661}"] {
            assert!(
                matches!(Amount::from_frm_str(bad), Err(TypeError::InvalidAmount(_))),
                "{bad:?} should be rejected as malformed"
            );
        }
    }

    #[test]
    fn from_frm_str_rejects_u64_overflow() {
        // 2^64 grains is ~184_467_440_737.09551616 FRM.
        assert_eq!(Amount::from_frm_str("184467440737.09551616"), Err(TypeError::AmountOverflow));
        assert_eq!(
            Amount::from_frm_str("99999999999999999999999999"),
            Err(TypeError::AmountOverflow)
        );
    }

    #[test]
    fn from_frm_str_rejects_above_max_money() {
        assert!(Amount::from_frm_str("21000000").is_ok());
        assert_eq!(
            Amount::from_frm_str("21000000.00000001"),
            Err(TypeError::AmountOutOfRange(Amount::MAX_MONEY.to_grains() + 1))
        );
        assert!(matches!(Amount::from_frm_str("21000001"), Err(TypeError::AmountOutOfRange(_))));
    }

    #[test]
    fn to_frm_string_always_has_eight_decimals() {
        assert_eq!(Amount::ZERO.to_frm_string(), "0.00000000");
        assert_eq!(Amount::ONE_GRAIN.to_frm_string(), "0.00000001");
        assert_eq!(Amount::from_grains(COIN).to_frm_string(), "1.00000000");
        assert_eq!(Amount::from_grains(12 * COIN + 34_567_890).to_frm_string(), "12.34567890");
        assert_eq!(Amount::MAX_MONEY.to_frm_string(), "21000000.00000000");
        assert_eq!(Amount::from_grains(50 * COIN).to_string(), "50.00000000");
    }

    #[test]
    fn display_and_from_str_agree() {
        let a = Amount::from_grains(1_234_567_890);
        assert_eq!(a.to_string().parse::<Amount>().unwrap(), a);
    }

    #[test]
    fn serde_is_a_bare_grain_count() {
        let a = Amount::from_grains(5_000_000_000);
        assert_eq!(serde_json::to_string(&a).unwrap(), "5000000000");
        let back: Amount = serde_json::from_str("5000000000").unwrap();
        assert_eq!(back, a);
        // Never a float, never a string.
        assert!(serde_json::from_str::<Amount>("\"1.0\"").is_err());
    }

    #[test]
    fn borsh_is_eight_little_endian_bytes() {
        let a = Amount::from_grains(1);
        let b = borsh::to_vec(&a).unwrap();
        assert_eq!(b, vec![1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(borsh::from_slice::<Amount>(&b).unwrap(), a);
    }

    #[test]
    fn ordering_is_numeric() {
        assert!(Amount::ZERO < Amount::ONE_GRAIN);
        assert!(Amount::ONE_GRAIN < Amount::ONE_FRM);
        let mut v = [Amount::from_grains(3), Amount::ZERO, Amount::from_grains(2)];
        v.sort();
        assert_eq!(v, [Amount::ZERO, Amount::from_grains(2), Amount::from_grains(3)]);
    }

    proptest! {
        #[test]
        fn frm_string_round_trips(g in 0u64..=Amount::MAX_MONEY.to_grains()) {
            let a = Amount::from_grains(g);
            prop_assert_eq!(Amount::from_frm_str(&a.to_frm_string()).unwrap(), a);
        }

        #[test]
        fn frm_string_has_a_stable_shape(g in 0u64..=Amount::MAX_MONEY.to_grains()) {
            let s = Amount::from_grains(g).to_frm_string();
            let (int_part, frac) = s.split_once('.').unwrap();
            prop_assert_eq!(frac.len(), 8);
            prop_assert!(!int_part.is_empty());
            prop_assert!(s.bytes().all(|b| b.is_ascii_digit() || b == b'.'));
        }

        #[test]
        fn checked_add_never_wraps(a in any::<u64>(), b in any::<u64>()) {
            let sum = Amount::from_grains(a).checked_add(Amount::from_grains(b));
            match a.checked_add(b) {
                Some(v) => prop_assert_eq!(sum, Some(Amount::from_grains(v))),
                None => prop_assert_eq!(sum, None),
            }
        }

        #[test]
        fn checked_sub_is_the_inverse_of_checked_add(a in any::<u64>(), b in any::<u64>()) {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            let diff = Amount::from_grains(hi).checked_sub(Amount::from_grains(lo)).unwrap();
            prop_assert_eq!(diff.checked_add(Amount::from_grains(lo)),
                            Some(Amount::from_grains(hi)));
        }

        #[test]
        fn parsing_never_panics(s in ".{0,24}") {
            let _ = Amount::from_frm_str(&s);
        }

        #[test]
        fn is_valid_money_is_exactly_the_range(g in any::<u64>()) {
            prop_assert_eq!(
                Amount::from_grains(g).is_valid_money(),
                g <= 21_000_000 * COIN
            );
        }
    }
}
