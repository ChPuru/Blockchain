//! Network identity: which chain a node is on, and who is allowed to sign for
//! it under BFT.
//!
//! [`ChainId`] is the first field of every signature preimage (CONTRACT §5.5),
//! which is what stops a testnet signature from being replayed on mainnet.

use std::fmt;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::TypeError;
use crate::hash::{HASH_LEN, parse_hex32};
use crate::params::ChainParams;

/// Which network a node is on.
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
pub enum Network {
    /// The production chain.
    #[default]
    Mainnet,
    /// The public test chain: mainnet rules, valueless coins.
    Testnet,
    /// The local development chain: a trivial proof-of-work limit.
    Devnet,
}

impl Network {
    /// Every network, in chain-id order. Useful for exhaustive tests.
    pub const ALL: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Devnet];

    /// The canonical lowercase name, as accepted by [`Network::from_str`].
    pub const fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Devnet => "devnet",
        }
    }

    /// The chain id mixed into every signature preimage.
    pub const fn chain_id(self) -> ChainId {
        match self {
            Network::Mainnet => ChainId::MAINNET,
            Network::Testnet => ChainId::TESTNET,
            Network::Devnet => ChainId::DEVNET,
        }
    }

    /// The bech32m human-readable prefix for addresses on this network.
    ///
    /// Lives on `Network` as well as on [`ChainParams`] so that `ferrum-crypto`
    /// can encode an address without carrying the whole parameter set.
    pub const fn bech32_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "fer",
            Network::Testnet => "tfer",
            Network::Devnet => "rfer",
        }
    }

    /// The network a chain id belongs to, if any.
    pub const fn from_chain_id(id: ChainId) -> Option<Network> {
        match id.0 {
            1 => Some(Network::Mainnet),
            2 => Some(Network::Testnet),
            3 => Some(Network::Devnet),
            _ => None,
        }
    }

    /// This network's consensus parameters.
    pub fn params(self) -> ChainParams {
        match self {
            Network::Mainnet => ChainParams::mainnet(),
            Network::Testnet => ChainParams::testnet(),
            Network::Devnet => ChainParams::devnet(),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Network {
    type Err = TypeError;

    /// Case-insensitive. `main`, `test`, `dev` and `regtest` are accepted as
    /// aliases because operators type them, and a typo must not silently
    /// select the wrong chain.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mainnet" | "main" => Ok(Network::Mainnet),
            "testnet" | "test" => Ok(Network::Testnet),
            "devnet" | "dev" | "regtest" => Ok(Network::Devnet),
            _ => Err(TypeError::UnknownNetwork(s.to_owned())),
        }
    }
}

/// The chain id: 1 = mainnet, 2 = testnet, 3 = devnet.
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
pub struct ChainId(pub u32);

impl ChainId {
    /// Mainnet.
    pub const MAINNET: ChainId = ChainId(1);
    /// Testnet.
    pub const TESTNET: ChainId = ChainId(2);
    /// Devnet.
    pub const DEVNET: ChainId = ChainId(3);

    /// The raw id.
    pub const fn to_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A BFT validator, identified by its 32-byte x-only BIP-340 public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct ValidatorId(pub [u8; HASH_LEN]);

impl ValidatorId {
    /// Wrap a raw x-only public key.
    pub const fn from_bytes(b: [u8; HASH_LEN]) -> Self {
        ValidatorId(b)
    }

    /// Borrow the raw key bytes.
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Lowercase hex of the key.
    // `&self` to match `Hash32::to_hex`, whose signature CONTRACT §3 fixes.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse 64 hex characters, with an optional `0x`.
    pub fn from_hex(s: &str) -> Result<Self, TypeError> {
        parse_hex32(s).map(ValidatorId)
    }
}

impl fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ValidatorId({})", self.to_hex())
    }
}

impl FromStr for ValidatorId {
    type Err = TypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ValidatorId::from_hex(s)
    }
}

impl Serialize for ValidatorId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

struct ValidatorIdVisitor;

impl Visitor<'_> for ValidatorIdVisitor {
    type Value = ValidatorId;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a 64-character hex x-only public key")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<ValidatorId, E> {
        ValidatorId::from_hex(v).map_err(de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for ValidatorId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(ValidatorIdVisitor)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn network_name_round_trips() {
        for n in Network::ALL {
            assert_eq!(n.name().parse::<Network>().unwrap(), n);
            assert_eq!(n.to_string(), n.name());
            assert_eq!(Network::from_chain_id(n.chain_id()), Some(n));
            assert_eq!(n.params().network, n);
        }
        assert_eq!(Network::from_chain_id(ChainId(99)), None);
        assert_eq!(Network::default(), Network::Mainnet);
    }

    #[test]
    fn network_from_str_accepts_aliases_and_case() {
        assert_eq!("MAINNET".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("main".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!(" test ".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("dev".parse::<Network>().unwrap(), Network::Devnet);
        assert_eq!("regtest".parse::<Network>().unwrap(), Network::Devnet);
        assert_eq!("".parse::<Network>(), Err(TypeError::UnknownNetwork(String::new())));
        assert!("bitcoin".parse::<Network>().is_err());
    }

    #[test]
    fn network_identities_are_distinct() {
        assert_eq!(Network::Mainnet.chain_id(), ChainId(1));
        assert_eq!(Network::Testnet.chain_id(), ChainId(2));
        assert_eq!(Network::Devnet.chain_id(), ChainId(3));
        assert_eq!(Network::Mainnet.bech32_hrp(), "fer");
        assert_eq!(Network::Testnet.bech32_hrp(), "tfer");
        assert_eq!(Network::Devnet.bech32_hrp(), "rfer");
        assert_eq!(ChainId::MAINNET.to_u32(), 1);
        assert_eq!(ChainId::TESTNET.to_string(), "2");
        assert_eq!(ChainId::DEVNET, ChainId(3));
        assert_eq!(ChainId::default(), ChainId(0), "an unset chain id is not a network");
    }

    #[test]
    fn network_borsh_is_a_single_discriminant_byte() {
        assert_eq!(borsh::to_vec(&Network::Mainnet).unwrap(), vec![0]);
        assert_eq!(borsh::to_vec(&Network::Testnet).unwrap(), vec![1]);
        assert_eq!(borsh::to_vec(&Network::Devnet).unwrap(), vec![2]);
        assert_eq!(borsh::from_slice::<Network>(&[2]).unwrap(), Network::Devnet);
        assert!(borsh::from_slice::<Network>(&[3]).is_err(), "unknown variants are rejected");
    }

    #[test]
    fn network_serde_is_the_variant_name() {
        assert_eq!(serde_json::to_string(&Network::Devnet).unwrap(), "\"Devnet\"");
        assert_eq!(serde_json::from_str::<Network>("\"Devnet\"").unwrap(), Network::Devnet);
        assert!(serde_json::from_str::<Network>("\"devnet\"").is_err());
    }

    #[test]
    fn chain_id_serde_and_borsh_are_the_bare_u32() {
        assert_eq!(serde_json::to_string(&ChainId(3)).unwrap(), "3");
        assert_eq!(borsh::to_vec(&ChainId(3)).unwrap(), vec![3, 0, 0, 0]);
    }

    #[test]
    fn validator_id_textual_forms() {
        let v = ValidatorId::from_bytes([0x2a; 32]);
        let hex = "2a".repeat(32);
        assert_eq!(v.to_hex(), hex);
        assert_eq!(v.to_string(), hex);
        assert_eq!(format!("{v:?}"), format!("ValidatorId({hex})"));
        assert_eq!(ValidatorId::from_hex(&hex).unwrap(), v);
        assert_eq!(hex.parse::<ValidatorId>().unwrap(), v);
        assert_eq!(ValidatorId::from_hex(&format!("0x{hex}")).unwrap(), v);
        assert!(ValidatorId::from_hex("00").is_err());
        assert_eq!(v.as_bytes(), &[0x2a; 32]);
    }

    #[test]
    fn validator_id_serde_and_borsh() {
        let v = ValidatorId::from_bytes([0x2a; 32]);
        let hex = "2a".repeat(32);
        assert_eq!(serde_json::to_string(&v).unwrap(), format!("\"{hex}\""));
        assert_eq!(serde_json::from_str::<ValidatorId>(&format!("\"{hex}\"")).unwrap(), v);
        assert!(serde_json::from_str::<ValidatorId>("\"aa\"").is_err());
        let b = borsh::to_vec(&v).unwrap();
        assert_eq!(b.len(), 32, "an x-only key carries no length prefix");
        assert_eq!(borsh::from_slice::<ValidatorId>(&b).unwrap(), v);
    }

    #[test]
    fn validator_ids_order_bytewise() {
        assert!(ValidatorId::from_bytes([0; 32]) < ValidatorId::from_bytes([1; 32]));
    }
}
