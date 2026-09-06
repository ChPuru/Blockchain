//! Locking and unlocking scripts, as opaque byte strings.
//!
//! `ferrum-types` knows nothing about opcodes — parsing, disassembly and
//! execution all live in `ferrum-script`. Keeping the type here means the
//! transaction model does not depend on the VM, which is what lets the
//! dependency graph stay a DAG.

use std::fmt;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::TypeError;

/// A script: a bare byte string, encoded by Borsh as `u32 LE length || bytes`.
///
/// Serde renders it as a lowercase hex string, matching how every block
/// explorer and JSON-RPC in the world shows a script.
#[derive(
    Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct Script(Vec<u8>);

impl Script {
    /// An empty script. Common: a coinbase output can have one, and
    /// `script_sig` is empty for a bare P2PK spend built by other tooling.
    pub const EMPTY: Script = Script(Vec::new());

    /// Wrap raw script bytes.
    pub fn new(v: Vec<u8>) -> Self {
        Script(v)
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the script and return its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when the script has no bytes at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Lowercase hex of the script bytes.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parse lowercase or uppercase hex, with an optional `0x` prefix.
    ///
    /// An empty string is a valid empty script; an odd number of characters or
    /// a non-hex character is an error.
    pub fn from_hex(s: &str) -> Result<Self, TypeError> {
        let body = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        hex::decode(body).map(Script).map_err(TypeError::hex)
    }
}

impl fmt::Display for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Script({})", self.to_hex())
    }
}

impl fmt::LowerHex for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Script {
    type Err = TypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Script::from_hex(s)
    }
}

impl AsRef<[u8]> for Script {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Script {
    fn from(v: Vec<u8>) -> Self {
        Script(v)
    }
}

impl From<&[u8]> for Script {
    fn from(v: &[u8]) -> Self {
        Script(v.to_vec())
    }
}

impl From<Script> for Vec<u8> {
    fn from(s: Script) -> Self {
        s.0
    }
}

impl Serialize for Script {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

struct ScriptVisitor;

impl Visitor<'_> for ScriptVisitor {
    type Value = Script;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a hex string of script bytes")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Script, E> {
        Script::from_hex(v).map_err(de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for Script {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(ScriptVisitor)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn empty_script_is_empty() {
        assert!(Script::EMPTY.is_empty());
        assert_eq!(Script::EMPTY.len(), 0);
        assert_eq!(Script::default(), Script::EMPTY);
        assert_eq!(Script::EMPTY.to_hex(), "");
    }

    #[test]
    fn new_and_as_bytes_round_trip() {
        let s = Script::new(vec![0x76, 0xa9, 0x14]);
        assert_eq!(s.as_bytes(), &[0x76, 0xa9, 0x14]);
        assert_eq!(s.len(), 3);
        assert!(!s.is_empty());
        assert_eq!(s.clone().into_bytes(), vec![0x76, 0xa9, 0x14]);
        assert_eq!(Vec::<u8>::from(s.clone()), s.as_bytes().to_vec());
        assert_eq!(s.as_ref(), &[0x76u8, 0xa9, 0x14][..]);
    }

    #[test]
    fn hex_round_trips() {
        let s = Script::new(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(s.to_hex(), "deadbeef");
        assert_eq!(Script::from_hex("deadbeef").unwrap(), s);
        assert_eq!(Script::from_hex("DEADBEEF").unwrap(), s);
        assert_eq!(Script::from_hex("0xdeadbeef").unwrap(), s);
        assert_eq!("deadbeef".parse::<Script>().unwrap(), s);
        assert_eq!(Script::from_hex("").unwrap(), Script::EMPTY);
    }

    #[test]
    fn from_hex_rejects_malformed_input() {
        assert!(matches!(Script::from_hex("abc"), Err(TypeError::InvalidHex(_))));
        assert!(matches!(Script::from_hex("zz"), Err(TypeError::InvalidHex(_))));
    }

    #[test]
    fn display_and_debug() {
        let s = Script::new(vec![0x51]);
        assert_eq!(s.to_string(), "51");
        assert_eq!(format!("{s:?}"), "Script(51)");
        assert_eq!(format!("{s:x}"), "51");
        assert_eq!(format!("{s:#x}"), "0x51");
    }

    #[test]
    fn borsh_is_a_u32_length_prefix_then_bytes() {
        let s = Script::new(vec![0xaa, 0xbb]);
        let b = borsh::to_vec(&s).unwrap();
        assert_eq!(b, vec![2, 0, 0, 0, 0xaa, 0xbb]);
        assert_eq!(borsh::from_slice::<Script>(&b).unwrap(), s);

        let e = borsh::to_vec(&Script::EMPTY).unwrap();
        assert_eq!(e, vec![0, 0, 0, 0]);
        assert_eq!(borsh::from_slice::<Script>(&e).unwrap(), Script::EMPTY);
    }

    #[test]
    fn borsh_rejects_trailing_bytes() {
        let mut b = borsh::to_vec(&Script::new(vec![1, 2, 3])).unwrap();
        b.push(0);
        assert!(borsh::from_slice::<Script>(&b).is_err());
    }

    #[test]
    fn serde_is_a_hex_string() {
        let s = Script::new(vec![0x00, 0xff]);
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"00ff\"");
        assert_eq!(serde_json::from_str::<Script>("\"00ff\"").unwrap(), s);
        assert!(serde_json::from_str::<Script>("\"0\"").is_err());
    }

    #[test]
    fn conversions_from_slices_and_vectors() {
        let raw = vec![1u8, 2, 3];
        assert_eq!(Script::from(raw.clone()), Script::new(raw.clone()));
        assert_eq!(Script::from(&raw[..]), Script::new(raw));
    }

    #[test]
    fn ordering_is_lexicographic() {
        let a = Script::new(vec![1]);
        let b = Script::new(vec![1, 0]);
        let c = Script::new(vec![2]);
        assert!(a < b);
        assert!(b < c);
    }
}
