//! 32-byte hashes, and the two newtypes that give a hash its meaning.
//!
//! # Byte order
//!
//! A [`Hash32`] displays as lowercase hex of its bytes **in natural order**.
//! Ferrum does not reverse hashes for display: Bitcoin's reversal is an
//! accident of its internal little-endian integer representation leaking into
//! RPC output, and reproducing it costs debugging hours forever (CONTRACT
//! §2.4, DECISIONS D5).

use std::fmt;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::TypeError;

/// Number of bytes in every Ferrum hash.
pub const HASH_LEN: usize = 32;

/// Number of hex characters in the textual form of a [`Hash32`].
pub const HASH_HEX_LEN: usize = HASH_LEN * 2;

/// Parse 64 hex characters, with or without a `0x`/`0X` prefix, into 32 bytes.
///
/// Shared by [`Hash32`] and `ValidatorId`, which have the same textual form.
pub(crate) fn parse_hex32(s: &str) -> Result<[u8; HASH_LEN], TypeError> {
    let body = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if body.len() != HASH_HEX_LEN {
        return Err(TypeError::InvalidHashLength(body.len()));
    }
    let mut out = [0u8; HASH_LEN];
    hex::decode_to_slice(body, &mut out).map_err(TypeError::hex)?;
    Ok(out)
}

/// A 32-byte BLAKE3 digest.
///
/// `Copy`, totally ordered by its bytes, and encoded by Borsh as exactly 32
/// raw bytes with no length prefix. Serde renders it as a lowercase hex string
/// so that JSON-RPC output and config files stay readable.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct Hash32([u8; HASH_LEN]);

impl Hash32 {
    /// The all-zero hash. Used as the `prev_hash` of the genesis block and as
    /// the Merkle root of an empty tree.
    pub const ZERO: Hash32 = Hash32([0u8; HASH_LEN]);

    /// Wrap 32 raw bytes.
    pub const fn from_bytes(b: [u8; HASH_LEN]) -> Self {
        Hash32(b)
    }

    /// Borrow the raw bytes, in the order they were hashed.
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Copy out the raw bytes.
    pub const fn to_bytes(self) -> [u8; HASH_LEN] {
        self.0
    }

    /// Lowercase hex of the bytes in natural order: 64 characters, no prefix.
    // `&self` rather than `self` because CONTRACT §3 spells the signature that
    // way, and the contract wins over clippy's naming convention.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse 64 hex characters, case-insensitive, with an optional `0x`.
    pub fn from_hex(s: &str) -> Result<Self, TypeError> {
        parse_hex32(s).map(Hash32)
    }

    /// True when every byte is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; HASH_LEN]
    }
}

impl Default for Hash32 {
    fn default() -> Self {
        Hash32::ZERO
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", self.to_hex())
    }
}

impl fmt::LowerHex for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        f.write_str(&self.to_hex())
    }
}

impl fmt::UpperHex for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0X")?;
        }
        f.write_str(&hex::encode_upper(self.0))
    }
}

impl FromStr for Hash32 {
    type Err = TypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash32::from_hex(s)
    }
}

impl AsRef<[u8]> for Hash32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; HASH_LEN]> for Hash32 {
    fn from(b: [u8; HASH_LEN]) -> Self {
        Hash32(b)
    }
}

impl From<Hash32> for [u8; HASH_LEN] {
    fn from(h: Hash32) -> Self {
        h.0
    }
}

impl Serialize for Hash32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

struct Hash32Visitor;

impl Visitor<'_> for Hash32Visitor {
    type Value = Hash32;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a 64-character hex string")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Hash32, E> {
        Hash32::from_hex(v).map_err(de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(Hash32Visitor)
    }
}

/// Declare a `Hash32` newtype with the full complement of textual and
/// conversion impls. Borsh and serde are *derived*, so the newtype encodes
/// byte-for-byte and character-for-character exactly like the inner hash.
macro_rules! hash_newtype {
    ($(#[$attr:meta])* $name:ident) => {
        $(#[$attr])*
        #[derive(
            Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
            BorshSerialize, BorshDeserialize, Serialize, Deserialize,
        )]
        pub struct $name(pub Hash32);

        impl $name {
            #[doc = "The all-zero value."]
            pub const ZERO: $name = $name(Hash32::ZERO);

            #[doc = "Wrap 32 raw bytes."]
            pub const fn from_bytes(b: [u8; HASH_LEN]) -> Self {
                $name(Hash32::from_bytes(b))
            }

            #[doc = "Borrow the raw bytes, in natural order."]
            pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
                self.0.as_bytes()
            }

            #[doc = "The wrapped [`Hash32`]."]
            pub const fn hash(&self) -> Hash32 {
                self.0
            }

            #[doc = "Lowercase hex, natural byte order, 64 characters."]
            #[allow(clippy::wrong_self_convention)] // signature fixed by CONTRACT §3
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }

            #[doc = "Parse 64 hex characters, case-insensitive, optional `0x`."]
            pub fn from_hex(s: &str) -> Result<Self, TypeError> {
                Hash32::from_hex(s).map($name)
            }

            #[doc = "True when every byte is zero."]
            pub fn is_zero(&self) -> bool {
                self.0.is_zero()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name::ZERO
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0.to_hex())
            }
        }

        impl fmt::LowerHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = TypeError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $name::from_hex(s)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl From<Hash32> for $name {
            fn from(h: Hash32) -> Self {
                $name(h)
            }
        }

        impl From<$name> for Hash32 {
            fn from(v: $name) -> Self {
                v.0
            }
        }
    };
}

hash_newtype! {
    /// The hash of a block header: `tagged_hash(TAG_HEADER, borsh(header))`.
    BlockHash
}

hash_newtype! {
    /// The id of a transaction: `tagged_hash(TAG_TXID, tx_envelope)`.
    ///
    /// The envelope type byte is inside the preimage (CONTRACT §2.1), so a
    /// future transaction type can never collide with a v1 txid.
    Txid
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// `00 01 02 ... 1f` — asymmetric, so a byte reversal cannot be missed.
    fn counting() -> Hash32 {
        let mut b = [0u8; HASH_LEN];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = u8::try_from(i).expect("index below 32 fits in u8");
        }
        Hash32::from_bytes(b)
    }

    const COUNTING_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn zero_is_all_zero_bytes() {
        assert_eq!(Hash32::ZERO.as_bytes(), &[0u8; 32]);
        assert!(Hash32::ZERO.is_zero());
        assert_eq!(Hash32::default(), Hash32::ZERO);
        assert!(!counting().is_zero());
    }

    #[test]
    fn display_uses_natural_byte_order() {
        // The whole point of DECISIONS D5: no reversal, anywhere.
        assert_eq!(counting().to_string(), COUNTING_HEX);
        assert_eq!(counting().to_hex(), COUNTING_HEX);
        assert_eq!(format!("{:x}", counting()), COUNTING_HEX);
        assert_eq!(format!("{:#x}", counting()), format!("0x{COUNTING_HEX}"));
        assert_eq!(format!("{:X}", counting()), COUNTING_HEX.to_uppercase());
    }

    #[test]
    fn debug_is_labelled_hex() {
        assert_eq!(format!("{:?}", counting()), format!("Hash32({COUNTING_HEX})"));
        assert_eq!(format!("{:?}", BlockHash(counting())), format!("BlockHash({COUNTING_HEX})"));
        assert_eq!(format!("{:?}", Txid(counting())), format!("Txid({COUNTING_HEX})"));
    }

    #[test]
    fn from_hex_round_trips() {
        assert_eq!(Hash32::from_hex(COUNTING_HEX).unwrap(), counting());
        assert_eq!(COUNTING_HEX.parse::<Hash32>().unwrap(), counting());
    }

    #[test]
    fn from_hex_accepts_prefix_and_any_case() {
        assert_eq!(Hash32::from_hex(&format!("0x{COUNTING_HEX}")).unwrap(), counting());
        assert_eq!(Hash32::from_hex(&format!("0X{COUNTING_HEX}")).unwrap(), counting());
        assert_eq!(Hash32::from_hex(&COUNTING_HEX.to_uppercase()).unwrap(), counting());
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        assert_eq!(Hash32::from_hex(""), Err(TypeError::InvalidHashLength(0)));
        assert_eq!(Hash32::from_hex("00"), Err(TypeError::InvalidHashLength(2)));
        let long = format!("{COUNTING_HEX}00");
        assert_eq!(Hash32::from_hex(&long), Err(TypeError::InvalidHashLength(66)));
    }

    #[test]
    fn from_hex_rejects_non_hex_characters() {
        let bad = "zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert!(matches!(Hash32::from_hex(bad), Err(TypeError::InvalidHex(_))));
    }

    #[test]
    fn borsh_is_thirty_two_bare_bytes() {
        let b = borsh::to_vec(&counting()).unwrap();
        assert_eq!(b.len(), 32);
        assert_eq!(b, counting().as_bytes().to_vec());
        let back: Hash32 = borsh::from_slice(&b).unwrap();
        assert_eq!(back, counting());
    }

    #[test]
    fn newtypes_encode_exactly_like_the_inner_hash() {
        let h = counting();
        let inner = borsh::to_vec(&h).unwrap();
        assert_eq!(borsh::to_vec(&BlockHash(h)).unwrap(), inner);
        assert_eq!(borsh::to_vec(&Txid(h)).unwrap(), inner);
    }

    #[test]
    fn borsh_rejects_trailing_bytes() {
        let mut b = borsh::to_vec(&counting()).unwrap();
        b.push(0);
        assert!(borsh::from_slice::<Hash32>(&b).is_err());
    }

    #[test]
    fn borsh_rejects_truncated_input() {
        let b = borsh::to_vec(&counting()).unwrap();
        assert!(borsh::from_slice::<Hash32>(&b[..31]).is_err());
    }

    #[test]
    fn serde_json_is_a_hex_string() {
        let j = serde_json::to_string(&counting()).unwrap();
        assert_eq!(j, format!("\"{COUNTING_HEX}\""));
        let back: Hash32 = serde_json::from_str(&j).unwrap();
        assert_eq!(back, counting());

        let j = serde_json::to_string(&BlockHash(counting())).unwrap();
        assert_eq!(j, format!("\"{COUNTING_HEX}\""));
        let back: BlockHash = serde_json::from_str(&j).unwrap();
        assert_eq!(back, BlockHash(counting()));

        let j = serde_json::to_string(&Txid(counting())).unwrap();
        assert_eq!(j, format!("\"{COUNTING_HEX}\""));
        let back: Txid = serde_json::from_str(&j).unwrap();
        assert_eq!(back, Txid(counting()));
    }

    #[test]
    fn serde_rejects_a_bad_hex_string() {
        assert!(serde_json::from_str::<Hash32>("\"deadbeef\"").is_err());
        assert!(serde_json::from_str::<Hash32>("42").is_err());
    }

    #[test]
    fn ordering_is_bytewise_from_the_front() {
        let a = Hash32::ZERO;
        let mut m = [0u8; 32];
        m[0] = 1;
        let b = Hash32::from_bytes(m);
        let mut n = [0u8; 32];
        n[31] = 1;
        let c = Hash32::from_bytes(n);
        assert!(a < c, "a difference in the last byte still orders");
        assert!(c < b, "the first byte dominates");
        assert!(BlockHash(a) < BlockHash(b));
        assert!(Txid(a) < Txid(b));
    }

    #[test]
    fn newtype_conversions_are_lossless() {
        let h = counting();
        assert_eq!(Hash32::from(BlockHash::from(h)), h);
        assert_eq!(Hash32::from(Txid::from(h)), h);
        assert_eq!(BlockHash::from_bytes(h.to_bytes()).hash(), h);
        assert_eq!(Txid::from_bytes(h.to_bytes()).as_bytes(), h.as_bytes());
        assert_eq!(BlockHash::ZERO, BlockHash::default());
        assert!(Txid::ZERO.is_zero());
        assert_eq!(COUNTING_HEX.parse::<BlockHash>().unwrap(), BlockHash(h));
        assert_eq!(COUNTING_HEX.parse::<Txid>().unwrap(), Txid(h));
        assert_eq!(BlockHash(h).to_hex(), COUNTING_HEX);
        assert_eq!(format!("{:x}", Txid(h)), COUNTING_HEX);
        assert_eq!(BlockHash(h).as_ref(), h.as_bytes().as_slice());
        assert_eq!(BlockHash::from_hex(COUNTING_HEX).unwrap(), BlockHash(h));
        assert_eq!(Txid::from_hex(COUNTING_HEX).unwrap(), Txid(h));
    }

    #[test]
    fn array_conversions_are_lossless() {
        let raw = counting().to_bytes();
        assert_eq!(Hash32::from(raw), counting());
        assert_eq!(<[u8; 32]>::from(counting()), raw);
        assert_eq!(counting().as_ref(), &raw[..]);
        assert_eq!(HASH_LEN, 32);
        assert_eq!(HASH_HEX_LEN, 64);
    }
}
