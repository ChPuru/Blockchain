#![allow(clippy::unwrap_used)]

use super::*;

fn seed(byte: u8) -> NodeKey {
    NodeKey::from_seed([byte; NODE_KEY_SEED_LEN])
}

#[test]
fn a_generated_key_is_thirty_two_bytes_of_hex() {
    let key = NodeKey::generate();
    let hex = key.to_hex();
    assert_eq!(hex.len(), NODE_KEY_SEED_LEN * 2);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn two_generated_keys_differ() {
    assert_ne!(NodeKey::generate().to_hex(), NodeKey::generate().to_hex());
}

#[test]
fn the_key_file_is_created_on_first_run_and_reused_after() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.key");
    assert!(!path.exists());

    let first = NodeKey::load_or_create(&path).unwrap();
    assert!(path.exists(), "a devnet must start with no wallet setup");
    let second = NodeKey::load_or_create(&path).unwrap();
    assert_eq!(first.to_hex(), second.to_hex(), "the identity must survive a restart");
}

#[test]
fn the_peer_id_is_stable_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.key");
    let a = NodeKey::load_or_create(&path).unwrap().peer_id().unwrap();
    let b = NodeKey::load_or_create(&path).unwrap().peer_id().unwrap();
    assert_eq!(a, b, "a changing PeerId silently breaks every peer's static list");
}

#[test]
fn the_file_is_hex_with_a_trailing_newline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.key");
    let key = seed(0xab);
    key.write(&path).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text, format!("{}\n", "ab".repeat(32)));
}

#[test]
fn writing_creates_the_data_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deep").join("nested").join("node.key");
    seed(1).write(&path).unwrap();
    assert!(path.exists());
}

#[test]
fn a_key_file_with_a_0x_prefix_or_whitespace_still_parses() {
    let path = Path::new("node.key");
    let hex = "cd".repeat(32);
    assert_eq!(NodeKey::parse(&format!("  {hex}\n"), path).unwrap().to_hex(), hex);
    assert_eq!(NodeKey::parse(&format!("0x{hex}"), path).unwrap().to_hex(), hex);
}

#[test]
fn a_short_key_file_is_refused_rather_than_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.key");
    std::fs::write(&path, "abcd\n").unwrap();
    let e = NodeKey::load_or_create(&path).unwrap_err();
    assert!(matches!(e, NodeError::Io { .. }), "{e}");
    // The file must survive: overwriting it would change the PeerId.
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "abcd\n");
}

#[test]
fn a_non_hex_key_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.key");
    std::fs::write(&path, "not hex at all").unwrap();
    assert!(NodeKey::load_or_create(&path).is_err());
}

#[test]
fn derivation_is_deterministic_for_a_seed() {
    let a = seed(9).mining_address(Network::Devnet).unwrap();
    let b = seed(9).mining_address(Network::Devnet).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, seed(10).mining_address(Network::Devnet).unwrap());
}

#[test]
fn the_mining_address_encodes_for_the_network_asked_for() {
    let key = seed(3);
    let dev = key.mining_address(Network::Devnet).unwrap();
    let main = key.mining_address(Network::Mainnet).unwrap();
    assert_eq!(dev.network, Network::Devnet);
    assert_eq!(main.network, Network::Mainnet);
    assert!(dev.encode().starts_with("rfer"));
    assert!(main.encode().starts_with("fer"));
    // Same key, so the payload is identical; only the network differs.
    assert_eq!(dev.payload, main.payload);
}

#[test]
fn the_mining_key_and_the_network_key_are_independent() {
    let key = seed(5);
    let mining = key.mining_secret().unwrap().to_bytes();
    let network = key.derive(NETWORK_ACCOUNT).unwrap().to_bytes();
    assert_ne!(mining, network, "one scalar must not sign under two schemes");
    assert_ne!(mining, key.seed, "the seed itself is never a signing key");
}

#[test]
fn the_mining_address_round_trips_through_its_encoding() {
    let address = seed(11).mining_address(Network::Devnet).unwrap();
    assert_eq!(Address::decode(&address.encode()).unwrap(), address);
}

#[test]
fn debug_never_prints_the_seed() {
    let text = format!("{:?}", seed(0x7f));
    assert!(text.contains("redacted"), "{text}");
    assert!(!text.contains("7f7f"), "{text}");
}

#[test]
fn a_key_pays_to_its_own_script_pubkey() {
    let key = seed(21);
    let address = key.mining_address(Network::Devnet).unwrap();
    let script = address.script_pubkey();
    assert!(!script.is_empty());
    assert_eq!(script, Address::decode(&address.encode()).unwrap().script_pubkey());
}
