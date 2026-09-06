//! Address encoding: round trips, malleability and rejection cases.
//!
//! The property that matters most is **one address, one spelling**. bech32m
//! packs bytes into 5-bit groups, and 21 or 33 bytes never divide evenly, so
//! the last group carries padding bits. A decoder that ignores them accepts
//! several distinct strings for the same payload, and a payment UI that shows
//! one while a watcher indexes another is a reconciliation bug waiting to
//! happen. Ferrum re-encodes on decode and demands the original string back.

#![allow(clippy::unwrap_used)]

use bech32::{Bech32, Bech32m, Hrp};
use ferrum_crypto::{
    ADDRESS_VERSION_P2PKH, ADDRESS_VERSION_P2SH, Address, AddressPayload, CryptoError, SecretKey,
    TAG_SCRIPT, hash160, tagged_hash,
};
use ferrum_types::{Network, Script};
use proptest::prelude::*;

fn hrp(network: Network) -> Hrp {
    Hrp::parse(network.bech32_hrp()).expect("a Ferrum HRP is valid bech32")
}

fn addr_from_bytes(network: Network, data: &[u8]) -> String {
    bech32::encode::<Bech32m>(hrp(network), data).expect("short payload")
}

#[test]
fn every_network_has_its_own_prefix() {
    assert_eq!(Network::Mainnet.bech32_hrp(), "fer");
    assert_eq!(Network::Testnet.bech32_hrp(), "tfer");
    assert_eq!(Network::Devnet.bech32_hrp(), "rfer");
}

#[test]
fn a_p2pkh_address_commits_to_hash160_of_the_x_only_key() {
    let pk = SecretKey::from_bytes(&[0x11; 32]).unwrap().public_key();
    let addr = Address::p2pkh(Network::Mainnet, &pk);
    assert_eq!(addr.version, ADDRESS_VERSION_P2PKH);
    assert_eq!(addr.payload, AddressPayload::PubKeyHash(hash160(pk.as_bytes())));
}

#[test]
fn a_p2sh_address_commits_to_the_tagged_script_hash() {
    let script = Script::new(vec![0x51, 0x87]);
    let addr = Address::p2sh(Network::Testnet, &script);
    assert_eq!(addr.version, ADDRESS_VERSION_P2SH);
    assert_eq!(
        addr.payload,
        AddressPayload::ScriptHash(tagged_hash(TAG_SCRIPT, script.as_bytes()).to_bytes())
    );
}

#[test]
fn bech32m_not_bech32() {
    let pk = SecretKey::from_bytes(&[0x21; 32]).unwrap().public_key();
    let addr = Address::p2pkh(Network::Mainnet, &pk);
    let mut data = vec![addr.version];
    data.extend_from_slice(addr.payload.as_bytes());

    let as_bech32m = bech32::encode::<Bech32m>(hrp(Network::Mainnet), &data).unwrap();
    let as_bech32 = bech32::encode::<Bech32>(hrp(Network::Mainnet), &data).unwrap();

    assert_eq!(addr.encode(), as_bech32m, "encode() must emit bech32m");
    assert_ne!(as_bech32m, as_bech32, "the two checksum constants must differ");
    assert!(Address::decode(&as_bech32m).is_ok());
    assert!(
        matches!(Address::decode(&as_bech32), Err(CryptoError::Bech32(_))),
        "a bech32 checksum must not be accepted for a Ferrum address"
    );

    // Only the last six characters (the checksum) differ.
    let m: Vec<char> = as_bech32m.chars().collect();
    let b: Vec<char> = as_bech32.chars().collect();
    assert_eq!(m.len(), b.len());
    assert_eq!(m[..m.len() - 6], b[..b.len() - 6]);
}

#[test]
fn a_foreign_hrp_is_rejected_even_with_a_good_checksum() {
    for foreign in ["bc", "tb", "bcrt", "fe", "ferr", "xfer"] {
        let data = [ADDRESS_VERSION_P2PKH; 21];
        let text = bech32::encode::<Bech32m>(Hrp::parse(foreign).unwrap(), &data).unwrap();
        assert_eq!(
            Address::decode(&text),
            Err(CryptoError::UnknownHrp(foreign.to_owned())),
            "{foreign} was accepted"
        );
    }
}

#[test]
fn a_testnet_address_is_not_a_mainnet_address() {
    let pk = SecretKey::from_bytes(&[0x31; 32]).unwrap().public_key();
    let main = Address::p2pkh(Network::Mainnet, &pk);
    let test = Address::p2pkh(Network::Testnet, &pk);
    assert_ne!(main.encode(), test.encode());
    assert_eq!(Address::decode(&main.encode()).unwrap().network, Network::Mainnet);
    assert_eq!(Address::decode(&test.encode()).unwrap().network, Network::Testnet);
    // Same key, same payload, different chain: the payload must be identical.
    assert_eq!(main.payload, test.payload);
    assert_eq!(main.script_pubkey(), test.script_pubkey());
}

#[test]
fn every_single_character_mutation_is_rejected() {
    // bech32m guarantees detection of up to four substitutions; one is easy,
    // and a silent acceptance anywhere would be a lost-funds bug.
    let pk = SecretKey::from_bytes(&[0x41; 32]).unwrap().public_key();
    let addr = Address::p2pkh(Network::Mainnet, &pk);
    let text = addr.encode();
    let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    for i in 0..text.len() {
        let original = text.as_bytes()[i];
        for c in charset.bytes() {
            if c == original {
                continue;
            }
            let mut bytes = text.clone().into_bytes();
            bytes[i] = c;
            let mutated = String::from_utf8(bytes).unwrap();
            assert!(
                Address::decode(&mutated) != Ok(addr),
                "mutating position {i} to {} still decoded to the same address",
                c as char
            );
        }
    }
}

#[test]
fn non_canonical_padding_is_rejected() {
    // Build the address by hand at the 5-bit level and set a padding bit.
    // 21 bytes is 168 bits, which occupies 34 field elements (170 bits), so
    // the final element carries two bits that must be zero.
    use bech32::Fe32;
    use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};

    let payload: Vec<u8> = std::iter::once(ADDRESS_VERSION_P2PKH).chain([7u8; 20]).collect();
    let mut fes: Vec<Fe32> = payload.iter().copied().bytes_to_fes().collect();
    assert_eq!(fes.len(), 34);

    let honest: String =
        fes.iter().copied().with_checksum::<Bech32m>(&hrp(Network::Mainnet)).chars().collect();
    assert!(Address::decode(&honest).is_ok(), "the honest encoding must decode");

    // Flip a padding bit in the last group: `byte_iter` throws those bits
    // away, so without the canonicality check this would decode identically.
    let last = fes.len() - 1;
    fes[last] = Fe32::try_from(fes[last].to_u8() ^ 0b1).expect("a 5-bit value");
    let malleated: String =
        fes.iter().copied().with_checksum::<Bech32m>(&hrp(Network::Mainnet)).chars().collect();

    assert_ne!(malleated, honest);
    assert_eq!(
        Address::decode(&malleated),
        Err(CryptoError::NonCanonicalAddress),
        "a non-zero padding bit must not give a second spelling of one address"
    );
}

#[test]
fn unknown_versions_are_rejected_at_both_payload_lengths() {
    for version in [2u8, 3, 15, 16, 17, 127, 128, 255] {
        for payload_len in [20usize, 32] {
            let mut data = vec![version];
            data.extend(std::iter::repeat_n(0u8, payload_len));
            let text = addr_from_bytes(Network::Mainnet, &data);
            assert_eq!(
                Address::decode(&text),
                Err(CryptoError::UnknownAddressVersion(version)),
                "version {version} with a {payload_len}-byte payload was accepted"
            );
        }
    }
}

#[test]
fn a_known_version_with_the_wrong_payload_length_is_rejected() {
    for version in [ADDRESS_VERSION_P2PKH, ADDRESS_VERSION_P2SH] {
        for payload_len in [0usize, 1, 19, 21, 31, 33, 40] {
            let mut data = vec![version];
            data.extend(std::iter::repeat_n(0u8, payload_len));
            let text = addr_from_bytes(Network::Mainnet, &data);
            assert_eq!(
                Address::decode(&text),
                Err(CryptoError::InvalidPayloadLength { version, len: payload_len }),
                "version {version} accepted a {payload_len}-byte payload"
            );
        }
    }
}

#[test]
fn the_locking_scripts_are_the_canonical_templates() {
    let pk = SecretKey::from_bytes(&[0x51; 32]).unwrap().public_key();
    let pkh = hash160(pk.as_bytes());
    let p2pkh = Address::p2pkh(Network::Devnet, &pk);

    let mut expected = vec![0x76u8, 0xa9, 0x14];
    expected.extend_from_slice(&pkh);
    expected.extend_from_slice(&[0x88, 0xac]);
    assert_eq!(p2pkh.script_pubkey().as_bytes(), expected.as_slice());

    let script = Script::new(vec![0x51, 0x51, 0x93, 0x87]);
    let sh = tagged_hash(TAG_SCRIPT, script.as_bytes());
    let p2sh = Address::p2sh(Network::Devnet, &script);

    let mut expected = vec![0xaau8, 0x20];
    expected.extend_from_slice(sh.as_bytes());
    expected.push(0x87);
    assert_eq!(p2sh.script_pubkey().as_bytes(), expected.as_slice());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Encode/decode round trip over every network and both address kinds.
    #[test]
    fn round_trip(
        network_index in 0usize..3,
        is_script in any::<bool>(),
        payload in prop::array::uniform32(any::<u8>()),
    ) {
        let network = Network::ALL[network_index];
        let address = if is_script {
            Address::new(network, AddressPayload::ScriptHash(payload))
        } else {
            let mut short = [0u8; 20];
            short.copy_from_slice(&payload[..20]);
            Address::new(network, AddressPayload::PubKeyHash(short))
        };

        let text = address.encode();
        prop_assert!(text.starts_with(network.bech32_hrp()));
        prop_assert_eq!(Address::decode(&text), Ok(address));
        prop_assert_eq!(Address::decode(&text.to_uppercase()), Ok(address));
        prop_assert_eq!(text.parse::<Address>(), Ok(address));
        prop_assert_eq!(address.to_string(), text);
    }

    /// The script_pubkey embeds the payload verbatim and nothing else.
    #[test]
    fn script_pubkey_embeds_the_payload(
        is_script in any::<bool>(),
        payload in prop::array::uniform32(any::<u8>()),
    ) {
        let address = if is_script {
            Address::new(Network::Mainnet, AddressPayload::ScriptHash(payload))
        } else {
            let mut short = [0u8; 20];
            short.copy_from_slice(&payload[..20]);
            Address::new(Network::Mainnet, AddressPayload::PubKeyHash(short))
        };
        let script = address.script_pubkey();
        let bytes = script.as_bytes();
        let expected_len = if is_script { 35 } else { 25 };
        prop_assert_eq!(bytes.len(), expected_len);
        prop_assert!(
            bytes.windows(address.payload.as_bytes().len())
                .any(|w| w == address.payload.as_bytes())
        );
    }

    /// Distinct payloads always give distinct addresses and scripts.
    #[test]
    fn distinct_payloads_are_distinguishable(
        a in prop::array::uniform20(any::<u8>()),
        b in prop::array::uniform20(any::<u8>()),
    ) {
        prop_assume!(a != b);
        let x = Address::new(Network::Mainnet, AddressPayload::PubKeyHash(a));
        let y = Address::new(Network::Mainnet, AddressPayload::PubKeyHash(b));
        prop_assert_ne!(x.encode(), y.encode());
        prop_assert_ne!(x.script_pubkey(), y.script_pubkey());
    }

    /// Arbitrary text never decodes into a valid address by accident, and
    /// never panics.
    #[test]
    fn arbitrary_text_never_panics(s in "\\PC{0,90}") {
        let _ = Address::decode(&s);
    }

    /// Any single mutated character in the data part breaks the round trip.
    #[test]
    fn a_mutated_character_never_yields_the_same_address(
        payload in prop::array::uniform20(any::<u8>()),
        position in 0usize..38,
    ) {
        let address = Address::new(Network::Mainnet, AddressPayload::PubKeyHash(payload));
        let text = address.encode();
        let position = 4 + position % (text.len() - 4);
        let mut bytes = text.into_bytes();
        bytes[position] = if bytes[position] == b'q' { b'p' } else { b'q' };
        let mutated = String::from_utf8(bytes).expect("bech32 is ASCII");
        prop_assert_ne!(Address::decode(&mutated), Ok(address));
    }
}
