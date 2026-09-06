//! The error type returned by every fallible operation in `ferrum-types`.
//!
//! Everything in this crate is pure parsing, decoding and conversion, so one
//! flat enum is enough. Variants carry `String` rather than a `source` error
//! because `borsh` surfaces failures as `std::io::Error`, which is neither
//! `Clone` nor `PartialEq`; tests want to compare a returned error by value,
//! and that is worth more here than a preserved error chain.

use thiserror::Error;

/// Every way a Ferrum core type can fail to parse, decode or convert.
///
/// The enum is intentionally *not* `#[non_exhaustive]`: downstream crates map
/// these into their own error types with exhaustive `match`es, and the compiler
/// telling them about a new variant is the point.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TypeError {
    /// A hex string contained a non-hex character, or had an odd length.
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// A hash literal was not exactly 64 hex characters (after any `0x`).
    #[error("invalid hash: expected 64 hex characters, got {0}")]
    InvalidHashLength(usize),

    /// An amount was parsed from an empty string.
    #[error("empty amount string")]
    EmptyAmount,

    /// An amount string was malformed: a sign, whitespace, a second `.`, a
    /// missing integer part (`.5`), a missing fraction (`1.`) or a non-digit.
    #[error("invalid amount string {0:?}")]
    InvalidAmount(String),

    /// An amount carried more fractional digits than a grain can represent.
    #[error("amount has more than {max} decimal places")]
    TooManyDecimals {
        /// The number of decimal places the base unit actually has (8).
        max: u32,
    },

    /// An amount does not fit in the `u64` grain count.
    #[error("amount overflows the u64 grain count")]
    AmountOverflow,

    /// An amount is representable but above `Amount::MAX_MONEY`.
    #[error("amount {0} grains is above MAX_MONEY")]
    AmountOutOfRange(u64),

    /// A transaction envelope had no type byte at all.
    #[error("transaction envelope is empty")]
    EmptyEnvelope,

    /// The type byte is in the valid range `0x00..=0x7f` but is not a type this
    /// version knows how to decode.
    #[error("unknown transaction type byte {0:#04x}")]
    UnknownTxType(u8),

    /// The type byte is in the reserved range `0x80..=0xff` and must never be
    /// accepted by a v1 node.
    #[error("reserved transaction type byte {0:#04x}")]
    ReservedTxType(u8),

    /// Borsh refused the bytes: truncated, malformed, or with a trailing
    /// suffix (which is a txid-malleability bug, so it is always an error).
    #[error("borsh decode failed: {0}")]
    Decode(String),

    /// `ChainParams::by_name` was handed a name that is not a known network.
    #[error("unknown network {0:?}")]
    UnknownNetwork(String),
}

impl TypeError {
    /// Wrap a `borsh`/`io` failure.
    pub(crate) fn decode(e: std::io::Error) -> Self {
        TypeError::Decode(e.to_string())
    }

    /// Wrap a `hex` failure.
    pub(crate) fn hex(e: hex::FromHexError) -> Self {
        TypeError::InvalidHex(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn display_messages_are_stable() {
        assert_eq!(TypeError::EmptyAmount.to_string(), "empty amount string");
        assert_eq!(
            TypeError::UnknownTxType(0x01).to_string(),
            "unknown transaction type byte 0x01"
        );
        assert_eq!(
            TypeError::ReservedTxType(0xff).to_string(),
            "reserved transaction type byte 0xff"
        );
        assert_eq!(
            TypeError::TooManyDecimals { max: 8 }.to_string(),
            "amount has more than 8 decimal places"
        );
    }

    #[test]
    fn errors_compare_by_value() {
        assert_eq!(TypeError::AmountOutOfRange(7), TypeError::AmountOutOfRange(7));
        assert_ne!(TypeError::AmountOutOfRange(7), TypeError::AmountOutOfRange(8));
    }

    #[test]
    fn wrappers_preserve_a_message() {
        let e = TypeError::decode(std::io::Error::other("boom"));
        assert_eq!(e, TypeError::Decode("boom".to_owned()));
        let h = TypeError::hex(hex::FromHexError::OddLength);
        assert!(matches!(h, TypeError::InvalidHex(_)));
    }
}
