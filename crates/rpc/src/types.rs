//! Serde data-transfer objects for both surfaces.
//!
//! These types are **not** the consensus types. Nothing in `ferrum-types`
//! derives the JSON shape that goes over the wire, because a `#[derive(Serialize)]`
//! on a consensus struct makes every internal field rename a breaking change
//! for every client, and makes every JSON quirk a permanent one.
//!
//! # Amounts are never JSON numbers
//!
//! An [`Amount`] is a `u64` of grains. Every JavaScript client parses a JSON
//! number into an IEEE-754 double, which represents integers exactly only up to
//! `2^53` (9 007 199 254 740 992) — a quarter of the `u64` range. The whole
//! money supply, 2 100 000 000 000 000 grains, sits below that line, but
//! nothing else does: a sum across many outputs, a fee-rate product, a value
//! read out of a hostile transaction that never passed validation, or any
//! future unit all can. `JSON.parse` rounds such a number silently and the
//! client's arithmetic is then wrong with no error anywhere.
//!
//! Every amount on both surfaces is therefore an **integer count of grains
//! carried as a decimal string** ([`Grains`]), and signed deltas likewise
//! ([`SignedGrains`]). `explorer/index.html` formats them with string
//! arithmetic and carries a matching comment; the two must stay consistent.
//!
//! Block heights, timestamps in milliseconds and `bits` stay JSON numbers: the
//! explorer does arithmetic on heights (`b.height - 1`) and bit-twiddling on
//! `bits` (`(h.bits >>> 0).toString(16)`), and none of the three can approach
//! `2^53` on any chain that exists. The block `nonce` is a `u64` that a miner
//! genuinely can drive past `2^53`, so it is a string too.

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;

use ferrum_types::Amount;

pub mod explorer;
pub mod rpc;

pub use self::explorer::{
    AddressResponse, AddressTx, BlockResponse, BlockTxSummary, FaucetRequest, FaucetResponse,
    RecentBlock, RecentTx, SearchResponse, StatsResponse, TxInputView, TxOutputView, TxResponse,
};
pub use self::rpc::{
    AddressBalance, BlockHeaderInfo, BlockHeaderJson, BlockJson, BlockTxList, BlockchainInfo,
    CoinJson, GetBlockResult, GetRawTransactionResult, MempoolEntryJson, MempoolInfo,
    NetworkInfoJson, PeerJson, RawMempoolResult, SubmitBlockResult, TemplateJson, TransactionJson,
    TxInJson, TxOutJson, UnspentJson,
};

/// An unsigned monetary amount on the wire: the grain count, as a string.
///
/// Serialises as `"5000000000"`, never as `5000000000`. Deserialises from
/// either a string or a JSON integer, because being strict about what you emit
/// and liberal about what you accept costs nothing here and saves every
/// hand-written client one bug.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Grains(pub Amount);

impl Grains {
    /// Zero.
    pub const ZERO: Grains = Grains(Amount::ZERO);

    /// The amount inside.
    #[must_use]
    pub const fn amount(self) -> Amount {
        self.0
    }

    /// The raw grain count.
    #[must_use]
    pub const fn to_grains(self) -> u64 {
        self.0.to_grains()
    }
}

impl From<Amount> for Grains {
    fn from(a: Amount) -> Self {
        Grains(a)
    }
}

impl From<Grains> for Amount {
    fn from(g: Grains) -> Self {
        g.0
    }
}

impl fmt::Display for Grains {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_grains())
    }
}

impl Serialize for Grains {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_grains().to_string())
    }
}

impl<'de> Deserialize<'de> for Grains {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Grains;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a grain count as a decimal string or an unsigned integer")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Grains, E> {
                v.parse::<u64>()
                    .map(|n| Grains(Amount::from_grains(n)))
                    .map_err(|_| E::custom(format!("{v:?} is not a grain count")))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Grains, E> {
                Ok(Grains(Amount::from_grains(v)))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Grains, E> {
                u64::try_from(v)
                    .map(|n| Grains(Amount::from_grains(n)))
                    .map_err(|_| E::custom("a negative amount"))
            }
        }
        d.deserialize_any(V)
    }
}

/// A signed balance change on the wire: grains, as a string, `-` prefixed when
/// negative.
///
/// Held as `i128` so that the difference of two `u64` grain counts can never
/// wrap. The explorer tests the leading `-` to colour the row, so the textual
/// form is part of the interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignedGrains(pub i128);

impl SignedGrains {
    /// Zero.
    pub const ZERO: SignedGrains = SignedGrains(0);

    /// `received - sent`, in grains, without any possibility of wrapping.
    #[must_use]
    pub fn delta(received: Amount, sent: Amount) -> Self {
        SignedGrains(i128::from(received.to_grains()) - i128::from(sent.to_grains()))
    }
}

impl fmt::Display for SignedGrains {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for SignedGrains {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for SignedGrains {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = SignedGrains;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a signed grain count as a decimal string or an integer")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<SignedGrains, E> {
                v.parse::<i128>()
                    .map(SignedGrains)
                    .map_err(|_| E::custom(format!("{v:?} is not a signed grain count")))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<SignedGrains, E> {
                Ok(SignedGrains(i128::from(v)))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<SignedGrains, E> {
                Ok(SignedGrains(i128::from(v)))
            }
        }
        d.deserialize_any(V)
    }
}

/// A `u64` that is carried as a string because it can legitimately exceed
/// `2^53`.
///
/// Used for the block nonce and for anything else a miner or an attacker can
/// drive to the top of the range. Everything the explorer does arithmetic on
/// stays a number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct U64String(pub u64);

impl fmt::Display for U64String {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for U64String {
    fn from(v: u64) -> Self {
        U64String(v)
    }
}

impl Serialize for U64String {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for U64String {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = U64String;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an unsigned integer as a decimal string or a number")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<U64String, E> {
                v.parse::<u64>().map(U64String).map_err(|_| E::custom("not an unsigned integer"))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<U64String, E> {
                Ok(U64String(v))
            }
        }
        d.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn amounts_serialise_as_strings_not_numbers() {
        let json = serde_json::to_string(&Grains(Amount::from_grains(5_000_000_000))).unwrap();
        assert_eq!(json, "\"5000000000\"");
    }

    #[test]
    fn the_whole_money_supply_survives_a_round_trip() {
        let all = Grains(Amount::MAX_MONEY);
        let json = serde_json::to_string(&all).unwrap();
        assert_eq!(json, "\"2100000000000000\"");
        let back: Grains = serde_json::from_str(&json).unwrap();
        assert_eq!(back, all);
    }

    #[test]
    fn an_amount_above_two_to_the_fifty_three_is_exact() {
        // This is the value a JSON number cannot carry: a double represents
        // integers exactly only to 2^53, and `Amount` is a u64. The string
        // encoding is what makes the round trip lossless.
        let big = Grains(Amount::from_grains((1u64 << 53) + 1));
        let json = serde_json::to_string(&big).unwrap();
        assert_eq!(json, "\"9007199254740993\"");
        assert_eq!(serde_json::from_str::<Grains>(&json).unwrap(), big);
        // Note that `serde_json` itself would carry this fine — it keeps
        // integers as integers. The client that cannot is the browser, whose
        // `JSON.parse` has only doubles, and it is the client this API is
        // written for.
    }

    #[test]
    fn amounts_deserialise_from_a_bare_number_too() {
        let g: Grains = serde_json::from_str("12345").unwrap();
        assert_eq!(g.to_grains(), 12_345);
    }

    #[test]
    fn a_negative_amount_is_refused() {
        assert!(serde_json::from_str::<Grains>("-1").is_err());
        assert!(serde_json::from_str::<Grains>("\"-1\"").is_err());
    }

    #[test]
    fn signed_grains_keep_their_sign_as_text() {
        let minus = SignedGrains::delta(Amount::ZERO, Amount::from_grains(7));
        assert_eq!(serde_json::to_string(&minus).unwrap(), "\"-7\"");
        let plus = SignedGrains::delta(Amount::from_grains(7), Amount::ZERO);
        assert_eq!(serde_json::to_string(&plus).unwrap(), "\"7\"");
    }

    #[test]
    fn a_delta_between_extreme_amounts_does_not_wrap() {
        let d = SignedGrains::delta(Amount::ZERO, Amount::from_grains(u64::MAX));
        assert_eq!(d.0, -i128::from(u64::MAX));
    }

    #[test]
    fn u64_strings_round_trip_past_two_to_the_fifty_three() {
        let n = U64String(u64::MAX);
        let json = serde_json::to_string(&n).unwrap();
        assert_eq!(json, "\"18446744073709551615\"");
        assert_eq!(serde_json::from_str::<U64String>(&json).unwrap(), n);
    }
}
