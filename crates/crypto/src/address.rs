//! Ferrum addresses: bech32**m** over `version || payload`.
//!
//! ```text
//! address := bech32m(hrp, [version_byte] ++ payload_bytes)
//! hrp     := "fer" (mainnet) | "tfer" (testnet) | "rfer" (devnet)
//! ```
//!
//! | Version | Payload | Locking script |
//! |---|---|---|
//! | 0 | `hash160(x_only_pubkey)`, 20 bytes | `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` |
//! | 1 | `tagged_hash(TAG_SCRIPT, script)`, 32 bytes | `OP_HASH256 <32> OP_EQUAL` |
//!
//! # Why bech32m and not bech32
//!
//! bech32's checksum constant `1` has a known weakness: appending or removing
//! a `q` immediately before the checksum of a string whose data part ends in
//! `p` still checksums. That is exactly why BIP-350 replaced the constant with
//! `0x2bc830a3` for every witness version other than 0. Ferrum has no legacy
//! bech32 addresses to stay compatible with, so it uses bech32m for
//! everything, and [`Address::decode`] rejects a plain-bech32 checksum
//! outright rather than accepting both.
//!
//! # Canonicality
//!
//! 21 bytes do not divide evenly into 5-bit groups, so the encoding carries
//! trailing padding bits. A decoder that ignores them lets two distinct
//! strings name one address. [`Address::decode`] therefore re-encodes what it
//! decoded and demands the original string back.
//!
//! # Why the script bytes are literals here
//!
//! `ferrum-crypto` sits below `ferrum-script` in the dependency graph, so
//! [`Address::script_pubkey`] writes the opcodes as bytes. `ferrum-script`'s
//! `templates` module produces the same bytes; a cross-crate test there should
//! assert the two agree.
//!
//! ```
//! use ferrum_crypto::{Address, SecretKey};
//! use ferrum_types::Network;
//!
//! let pk = SecretKey::from_bytes(&[3u8; 32])?.public_key();
//! let addr = Address::p2pkh(Network::Mainnet, &pk);
//! let text = addr.encode();
//! assert!(text.starts_with("fer1"));
//! assert_eq!(Address::decode(&text)?, addr);
//! # Ok::<(), ferrum_crypto::CryptoError>(())
//! ```

use std::fmt;
use std::str::FromStr;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use ferrum_types::{Network, Script};

use crate::error::CryptoError;
use crate::hashing::{TAG_SCRIPT, hash160, tagged_hash};
use crate::schnorr::PublicKey;

/// Version byte of a pay-to-public-key-hash address.
pub const ADDRESS_VERSION_P2PKH: u8 = 0;
/// Version byte of a pay-to-script-hash address.
pub const ADDRESS_VERSION_P2SH: u8 = 1;

/// Length of a P2PKH payload, in bytes.
pub const P2PKH_PAYLOAD_LEN: usize = 20;
/// Length of a P2SH payload, in bytes.
pub const P2SH_PAYLOAD_LEN: usize = 32;

// Opcode bytes, spelled out because this crate cannot depend on ferrum-script.
const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xa9;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_CHECKSIG: u8 = 0xac;
const OP_HASH256: u8 = 0xaa;
const OP_EQUAL: u8 = 0x87;

/// What an address commits to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressPayload {
    /// `hash160` of an x-only public key: pay to that key.
    PubKeyHash([u8; P2PKH_PAYLOAD_LEN]),
    /// `tagged_hash(TAG_SCRIPT, redeem_script)`: pay to that script.
    ScriptHash([u8; P2SH_PAYLOAD_LEN]),
}

impl AddressPayload {
    /// The version byte that belongs with this payload.
    pub const fn version(&self) -> u8 {
        match self {
            AddressPayload::PubKeyHash(_) => ADDRESS_VERSION_P2PKH,
            AddressPayload::ScriptHash(_) => ADDRESS_VERSION_P2SH,
        }
    }

    /// The payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            AddressPayload::PubKeyHash(h) => h.as_slice(),
            AddressPayload::ScriptHash(h) => h.as_slice(),
        }
    }

    /// Rebuild a payload from a version byte and its bytes.
    pub fn from_parts(version: u8, bytes: &[u8]) -> Result<Self, CryptoError> {
        match version {
            ADDRESS_VERSION_P2PKH => bytes
                .try_into()
                .map(AddressPayload::PubKeyHash)
                .map_err(|_| CryptoError::InvalidPayloadLength { version, len: bytes.len() }),
            ADDRESS_VERSION_P2SH => bytes
                .try_into()
                .map(AddressPayload::ScriptHash)
                .map_err(|_| CryptoError::InvalidPayloadLength { version, len: bytes.len() }),
            other => Err(CryptoError::UnknownAddressVersion(other)),
        }
    }
}

/// A Ferrum address: a network, a version byte and a payload.
///
/// The fields are public because CONTRACT §4 declares them so. Build one with
/// [`Address::p2pkh`], [`Address::p2sh`] or [`Address::new`] and the version
/// will always agree with the payload; if you assemble the struct by hand,
/// [`Address::is_canonical`] tells you whether it will survive a
/// encode/decode round trip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    /// Which chain this address is spendable on.
    pub network: Network,
    /// Version byte: 0 = P2PKH, 1 = P2SH.
    pub version: u8,
    /// The hash this address pays to.
    pub payload: AddressPayload,
}

impl Address {
    /// Build an address whose version matches its payload.
    pub const fn new(network: Network, payload: AddressPayload) -> Self {
        Address { network, version: payload.version(), payload }
    }

    /// Pay to an x-only public key: version 0, `hash160(pk)`.
    pub fn p2pkh(network: Network, pk: &PublicKey) -> Self {
        Address::new(network, AddressPayload::PubKeyHash(hash160(pk.as_bytes())))
    }

    /// Pay to a script: version 1, `tagged_hash(TAG_SCRIPT, script)`.
    pub fn p2sh(network: Network, script: &Script) -> Self {
        let hash = tagged_hash(TAG_SCRIPT, script.as_bytes());
        Address::new(network, AddressPayload::ScriptHash(hash.to_bytes()))
    }

    /// True when `version` agrees with `payload`, which every constructed and
    /// every decoded address satisfies.
    pub const fn is_canonical(&self) -> bool {
        self.version == self.payload.version()
    }

    /// The bech32m string, lowercase.
    pub fn encode(&self) -> String {
        let hrp = Hrp::parse_unchecked(self.network.bech32_hrp());
        let mut data = Vec::with_capacity(1 + self.payload.as_bytes().len());
        data.push(self.version);
        data.extend_from_slice(self.payload.as_bytes());
        // A 21- or 33-byte payload is far below the bech32m length limit, and
        // the HRP is one of three compile-time constants, so this cannot fail.
        bech32::encode::<Bech32m>(hrp, &data)
            .expect("a Ferrum address is always within the bech32m length limit")
    }

    /// Parse a bech32m address.
    ///
    /// Rejects, in order: a checksum that is not bech32m (a plain-bech32
    /// string included), an HRP belonging to no Ferrum network, an empty data
    /// part, a non-canonical bit padding, an unknown version byte, and a
    /// payload of the wrong length for its version.
    pub fn decode(s: &str) -> Result<Self, CryptoError> {
        let checked =
            CheckedHrpstring::new::<Bech32m>(s).map_err(|e| CryptoError::Bech32(e.to_string()))?;

        let hrp = checked.hrp();
        let network = Network::ALL
            .into_iter()
            .find(|n| hrp.as_str().eq_ignore_ascii_case(n.bech32_hrp()))
            .ok_or_else(|| CryptoError::UnknownHrp(hrp.as_str().to_owned()))?;

        let data: Vec<u8> = checked.byte_iter().collect();
        let (version, payload_bytes) =
            data.split_first().ok_or(CryptoError::EmptyAddressPayload)?;

        // The 8-to-5 bit conversion leaves padding bits that the decoder
        // discards without checking. Re-encoding is the cheapest way to insist
        // they were zero, and so that one address has exactly one spelling.
        let canonical = bech32::encode::<Bech32m>(hrp, &data)
            .map_err(|e| CryptoError::Bech32(e.to_string()))?;
        if !canonical.eq_ignore_ascii_case(s) {
            return Err(CryptoError::NonCanonicalAddress);
        }

        let payload = AddressPayload::from_parts(*version, payload_bytes)?;
        Ok(Address { network, version: *version, payload })
    }

    /// The canonical locking script this address pays to.
    ///
    /// Derived from the payload variant, so it is well defined even for a
    /// hand-assembled `Address` whose `version` disagrees.
    pub fn script_pubkey(&self) -> Script {
        match &self.payload {
            AddressPayload::PubKeyHash(h) => {
                // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
                let mut v = Vec::with_capacity(25);
                v.push(OP_DUP);
                v.push(OP_HASH160);
                v.push(0x14);
                v.extend_from_slice(h);
                v.push(OP_EQUALVERIFY);
                v.push(OP_CHECKSIG);
                Script::new(v)
            }
            AddressPayload::ScriptHash(h) => {
                // OP_HASH256 <32 bytes> OP_EQUAL
                let mut v = Vec::with_capacity(35);
                v.push(OP_HASH256);
                v.push(0x20);
                v.extend_from_slice(h);
                v.push(OP_EQUAL);
                Script::new(v)
            }
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

impl FromStr for Address {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::decode(s)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::schnorr::SecretKey;
    use bech32::Bech32;

    fn pubkey(byte: u8) -> PublicKey {
        SecretKey::from_bytes(&[byte; 32]).unwrap().public_key()
    }

    #[test]
    fn p2pkh_round_trips_on_every_network() {
        for network in Network::ALL {
            let addr = Address::p2pkh(network, &pubkey(1));
            let text = addr.encode();
            assert!(text.starts_with(&format!("{}1", network.bech32_hrp())), "{text}");
            assert_eq!(Address::decode(&text).unwrap(), addr);
            assert_eq!(text.parse::<Address>().unwrap(), addr);
            assert_eq!(addr.to_string(), text);
        }
    }

    #[test]
    fn p2sh_round_trips_on_every_network() {
        for network in Network::ALL {
            let addr = Address::p2sh(network, &Script::new(vec![0x51, 0x52, 0x93]));
            assert_eq!(Address::decode(&addr.encode()).unwrap(), addr);
            assert_eq!(addr.version, ADDRESS_VERSION_P2SH);
            assert!(matches!(addr.payload, AddressPayload::ScriptHash(_)));
        }
    }

    #[test]
    fn the_payload_is_the_documented_hash() {
        let pk = pubkey(7);
        let addr = Address::p2pkh(Network::Mainnet, &pk);
        assert_eq!(addr.payload.as_bytes(), hash160(pk.as_bytes()).as_slice());
        assert_eq!(addr.version, ADDRESS_VERSION_P2PKH);

        let script = Script::new(vec![0xaa, 0xbb]);
        let sh = Address::p2sh(Network::Mainnet, &script);
        assert_eq!(sh.payload.as_bytes(), tagged_hash(TAG_SCRIPT, script.as_bytes()).as_bytes());
    }

    #[test]
    fn networks_produce_different_strings_for_the_same_key() {
        let pk = pubkey(1);
        let m = Address::p2pkh(Network::Mainnet, &pk).encode();
        let t = Address::p2pkh(Network::Testnet, &pk).encode();
        let d = Address::p2pkh(Network::Devnet, &pk).encode();
        assert_ne!(m, t);
        assert_ne!(t, d);
        assert_ne!(m, d);
    }

    #[test]
    fn a_mainnet_address_does_not_decode_as_testnet() {
        // Decoding recovers the network from the HRP, so the check is that the
        // recovered network is the one that was encoded.
        let pk = pubkey(1);
        let addr = Address::p2pkh(Network::Testnet, &pk);
        assert_eq!(Address::decode(&addr.encode()).unwrap().network, Network::Testnet);
        assert_ne!(Address::decode(&addr.encode()).unwrap().network, Network::Mainnet);
    }

    #[test]
    fn an_unknown_hrp_is_rejected() {
        let data = [0u8; 21];
        let text = bech32::encode::<Bech32m>(Hrp::parse_unchecked("btc"), &data).unwrap();
        assert_eq!(Address::decode(&text), Err(CryptoError::UnknownHrp("btc".to_owned())));
    }

    #[test]
    fn a_mutated_checksum_is_rejected() {
        let text = Address::p2pkh(Network::Mainnet, &pubkey(1)).encode();
        let mut bytes = text.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'q' { b'p' } else { b'q' };
        let mutated = String::from_utf8(bytes).unwrap();
        assert!(matches!(Address::decode(&mutated), Err(CryptoError::Bech32(_))));
    }

    #[test]
    fn a_mutated_payload_character_is_rejected() {
        let text = Address::p2pkh(Network::Mainnet, &pubkey(1)).encode();
        let mut bytes = text.into_bytes();
        // Just after the "fer1" separator: inside the data part.
        bytes[5] = if bytes[5] == b'q' { b'p' } else { b'q' };
        let mutated = String::from_utf8(bytes).unwrap();
        assert!(Address::decode(&mutated).is_err());
    }

    #[test]
    fn bech32m_is_required_and_bech32_is_not_accepted() {
        let addr = Address::p2pkh(Network::Mainnet, &pubkey(1));
        let mut data = vec![addr.version];
        data.extend_from_slice(addr.payload.as_bytes());

        let m = bech32::encode::<Bech32m>(Hrp::parse_unchecked("fer"), &data).unwrap();
        let b = bech32::encode::<Bech32>(Hrp::parse_unchecked("fer"), &data).unwrap();

        assert_eq!(m, addr.encode(), "encode() must use bech32m");
        assert_ne!(m, b, "the two checksum constants must differ");
        assert!(Address::decode(&m).is_ok());
        assert!(
            matches!(Address::decode(&b), Err(CryptoError::Bech32(_))),
            "a plain-bech32 checksum must be refused"
        );
    }

    #[test]
    fn an_unknown_version_byte_is_rejected() {
        for version in [2u8, 3, 16, 255] {
            let mut data = vec![version];
            data.extend_from_slice(&[0u8; 20]);
            let text = bech32::encode::<Bech32m>(Hrp::parse_unchecked("fer"), &data).unwrap();
            assert_eq!(
                Address::decode(&text),
                Err(CryptoError::UnknownAddressVersion(version)),
                "version {version} was accepted"
            );
        }
    }

    #[test]
    fn a_wrong_payload_length_is_rejected() {
        // Version 0 with a 32-byte payload, and version 1 with a 20-byte one.
        let mut short = vec![ADDRESS_VERSION_P2SH];
        short.extend_from_slice(&[0u8; 20]);
        let text = bech32::encode::<Bech32m>(Hrp::parse_unchecked("fer"), &short).unwrap();
        assert_eq!(
            Address::decode(&text),
            Err(CryptoError::InvalidPayloadLength { version: 1, len: 20 })
        );

        let mut long = vec![ADDRESS_VERSION_P2PKH];
        long.extend_from_slice(&[0u8; 32]);
        let text = bech32::encode::<Bech32m>(Hrp::parse_unchecked("fer"), &long).unwrap();
        assert_eq!(
            Address::decode(&text),
            Err(CryptoError::InvalidPayloadLength { version: 0, len: 32 })
        );
    }

    #[test]
    fn an_empty_data_part_is_rejected() {
        let text = bech32::encode::<Bech32m>(Hrp::parse_unchecked("fer"), &[]).unwrap();
        assert_eq!(Address::decode(&text), Err(CryptoError::EmptyAddressPayload));
    }

    #[test]
    fn junk_is_rejected() {
        for bad in ["", "fer", "fer1", "not an address", "1qqqq", "fer1qqqqqqqq"] {
            assert!(Address::decode(bad).is_err(), "{bad:?} decoded");
        }
    }

    #[test]
    fn uppercase_is_accepted_and_mixed_case_is_not() {
        let addr = Address::p2pkh(Network::Mainnet, &pubkey(1));
        let text = addr.encode();
        assert_eq!(Address::decode(&text.to_uppercase()).unwrap(), addr);

        let mut mixed = text.clone();
        mixed.replace_range(0..1, "F");
        assert!(Address::decode(&mixed).is_err(), "bech32 forbids mixed case");
    }

    #[test]
    fn p2pkh_script_pubkey_is_the_canonical_template() {
        let addr = Address::p2pkh(Network::Mainnet, &pubkey(1));
        let script = addr.script_pubkey();
        let bytes = script.as_bytes();
        assert_eq!(bytes.len(), 25);
        assert_eq!(bytes[0], 0x76, "OP_DUP");
        assert_eq!(bytes[1], 0xa9, "OP_HASH160");
        assert_eq!(bytes[2], 0x14, "push 20");
        assert_eq!(&bytes[3..23], addr.payload.as_bytes());
        assert_eq!(bytes[23], 0x88, "OP_EQUALVERIFY");
        assert_eq!(bytes[24], 0xac, "OP_CHECKSIG");
    }

    #[test]
    fn p2sh_script_pubkey_is_the_canonical_template() {
        let addr = Address::p2sh(Network::Mainnet, &Script::new(vec![0x51]));
        let script = addr.script_pubkey();
        let bytes = script.as_bytes();
        assert_eq!(bytes.len(), 35);
        assert_eq!(bytes[0], 0xaa, "OP_HASH256");
        assert_eq!(bytes[1], 0x20, "push 32");
        assert_eq!(&bytes[2..34], addr.payload.as_bytes());
        assert_eq!(bytes[34], 0x87, "OP_EQUAL");
    }

    #[test]
    fn script_pubkeys_differ_between_address_kinds() {
        let a = Address::p2pkh(Network::Mainnet, &pubkey(1)).script_pubkey();
        let b = Address::p2sh(Network::Mainnet, &Script::new(vec![0x51])).script_pubkey();
        assert_ne!(a, b);
    }

    #[test]
    fn script_pubkey_ignores_the_network() {
        let pk = pubkey(1);
        let m = Address::p2pkh(Network::Mainnet, &pk).script_pubkey();
        let t = Address::p2pkh(Network::Testnet, &pk).script_pubkey();
        assert_eq!(m, t, "the network lives in the address text, not in the script");
    }

    #[test]
    fn payload_helpers_agree() {
        let p = AddressPayload::PubKeyHash([7u8; 20]);
        assert_eq!(p.version(), ADDRESS_VERSION_P2PKH);
        assert_eq!(AddressPayload::from_parts(0, p.as_bytes()).unwrap(), p);

        let s = AddressPayload::ScriptHash([9u8; 32]);
        assert_eq!(s.version(), ADDRESS_VERSION_P2SH);
        assert_eq!(AddressPayload::from_parts(1, s.as_bytes()).unwrap(), s);

        assert_eq!(
            AddressPayload::from_parts(9, &[0u8; 20]),
            Err(CryptoError::UnknownAddressVersion(9))
        );
    }

    #[test]
    fn constructed_addresses_are_canonical() {
        assert!(Address::p2pkh(Network::Mainnet, &pubkey(1)).is_canonical());
        assert!(Address::p2sh(Network::Devnet, &Script::EMPTY).is_canonical());
        let hand_made = Address {
            network: Network::Mainnet,
            version: 1,
            payload: AddressPayload::PubKeyHash([0u8; 20]),
        };
        assert!(!hand_made.is_canonical());
    }

    #[test]
    fn distinct_keys_give_distinct_addresses() {
        let mut seen = std::collections::BTreeSet::new();
        for b in 1u8..=16 {
            assert!(seen.insert(Address::p2pkh(Network::Mainnet, &pubkey(b)).encode()));
        }
    }
}
