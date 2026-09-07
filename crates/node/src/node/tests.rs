//! A whole node, started and stopped.
//!
//! Every listener binds port zero and the data directory is a temporary one, so
//! these run anywhere and in parallel with each other.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use std::path::Path;
use std::time::Duration;

use ferrum_types::{ChainParams, Network};

use super::*;
use crate::config::{CliOverrides, MapEnv, NodeConfig, resolve};
use crate::error::ConfigError;

/// Poll until the node reaches `height`, or give up after `POLL_ATTEMPTS`.
///
/// A bounded attempt count rather than a wall-clock deadline: `Instant::now` is
/// disallowed workspace-wide by `clippy.toml`, and a test that reaches for a
/// clock is a test somebody will one day copy into code that must not have one.
async fn wait_for_height(node: &Node, height: u64) {
    for _ in 0..POLL_ATTEMPTS {
        if node.chain().tip().1 >= height {
            return;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    panic!("the chain did not reach height {height} within the poll budget");
}

/// How many times a poll loop looks before it gives up.
const POLL_ATTEMPTS: usize = 1_200;

/// How long a poll loop waits between looks: 1200 x 50 ms is a minute.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A devnet configuration on ephemeral ports, in `dir`.
fn test_config(dir: &Path) -> NodeConfig {
    resolve(
        &CliOverrides {
            network: Some("devnet".to_owned()),
            datadir: Some(dir.to_path_buf()),
            rpc_listen: Some("127.0.0.1:0".to_owned()),
            explorer_listen: Some("127.0.0.1:0".to_owned()),
            p2p_listen: Some("/ip4/127.0.0.1/tcp/0".to_owned()),
            ..Default::default()
        },
        &MapEnv::new(),
        None,
    )
    .expect("the test configuration is well formed")
}

// ---------------------------------------------------------------------------
// Engine selection
// ---------------------------------------------------------------------------

#[test]
fn a_pow_only_network_needs_no_bft_engine() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path());
    let router = build_engines(&config).unwrap();
    assert!(router.bft().is_none());
    assert_eq!(router.engine_for_height(0).engine_id(), ferrum_types::BlockSeal::ENGINE_POW);
    assert_eq!(router.forced(), None);
}

#[test]
fn forcing_pow_pins_every_height() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.consensus = Some(crate::config::EngineChoice::Pow);
    let router = build_engines(&config).unwrap();
    assert_eq!(router.forced(), Some(ferrum_types::BlockSeal::ENGINE_POW));
    assert_eq!(router.engine_for_height(1_000_000).engine_id(), ferrum_types::BlockSeal::ENGINE_POW);
}

#[test]
fn forcing_bft_without_a_validator_set_is_a_startup_error() {
    // Better here, loudly, than at the fork height, silently.
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.consensus = Some(crate::config::EngineChoice::Bft);
    assert!(build_engines(&config).is_err());
}

#[test]
fn a_scheduled_activation_builds_a_bft_engine() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.params.bft_activation_height = Some(100);
    config.params.bft_validators = validator_set(4);
    let router = build_engines(&config).unwrap();
    assert!(router.bft().is_some());
    assert_eq!(router.engine_for_height(99).engine_id(), ferrum_types::BlockSeal::ENGINE_POW);
    assert_eq!(router.engine_for_height(100).engine_id(), ferrum_types::BlockSeal::ENGINE_BFT);
}

fn validator_set(n: u8) -> Vec<ferrum_types::ValidatorId> {
    (1..=n)
        .map(|i| {
            let sk = ferrum_crypto::SecretKey::from_bytes(&[i; 32]).unwrap();
            ferrum_types::ValidatorId(*sk.public_key().as_bytes())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The validator key file
// ---------------------------------------------------------------------------

#[test]
fn a_validator_key_is_thirty_two_hex_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("validator.key");
    std::fs::write(&path, format!("{}\n", "11".repeat(32))).unwrap();
    let key = load_validator_key(&path).unwrap();
    assert_eq!(key.to_bytes(), [0x11u8; 32]);

    // The `0x` prefix an operator will inevitably paste.
    std::fs::write(&path, format!("0x{}", "22".repeat(32))).unwrap();
    assert_eq!(load_validator_key(&path).unwrap().to_bytes(), [0x22u8; 32]);
}

#[test]
fn a_malformed_validator_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("validator.key");
    std::fs::write(&path, "abcd").unwrap();
    assert!(load_validator_key(&path).is_err());
    std::fs::write(&path, "not a mnemonic and not hex either").unwrap();
    assert!(load_validator_key(&path).is_err());
    assert!(load_validator_key(&dir.path().join("absent.key")).is_err());
}

#[test]
fn a_validator_key_may_also_be_a_mnemonic() {
    // `chain-cli wallet new --output FILE` writes a mnemonic (CONTRACT 13.1)
    // and `devnet/fork.sh` feeds that same file to `--validator-key`.
    let phrase = "abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon about";
    let phrase: String = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
    let path = Path::new("validator.key");
    let key = parse_validator_key(&phrase, path).unwrap();

    // The same path `chain-cli wallet dump-pubkey` reports: m/44'/7767'/0'/0/0.
    let mnemonic = ferrum_crypto::Mnemonic::from_phrase(&phrase).unwrap();
    let expected = ferrum_wallet::HdKeychain::from_mnemonic(&mnemonic, "", Network::Devnet)
        .unwrap()
        .receive(0, 0)
        .unwrap()
        .secret_key()
        .to_bytes();
    assert_eq!(key.to_bytes(), expected, "the node must sign with the key the CLI reports");
}

#[test]
fn a_hex_validator_key_and_a_mnemonic_are_told_apart() {
    let path = Path::new("validator.key");
    // 64 hex characters is never a mnemonic.
    assert_eq!(
        parse_validator_key(&"ab".repeat(32), path).unwrap().to_bytes(),
        [0xabu8; 32]
    );
    // A mnemonic is never valid hex.
    let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    assert!(parse_validator_key(phrase, path).is_ok());
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_node_starts_at_genesis_and_binds_its_listeners() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::start(test_config(dir.path())).await.unwrap();

    assert_eq!(node.chain().tip().1, 0, "a fresh node starts at genesis");
    assert_eq!(
        node.chain().tip().0,
        ferrum_chain::genesis_hash(&ChainParams::devnet()),
        "genesis is computed from the parameters, never read from a file"
    );
    assert!(node.rpc_addr().is_some());
    assert!(node.explorer_addr().is_some());
    assert_ne!(node.rpc_addr(), node.explorer_addr());
    assert!(node.p2p().is_some());
    assert_eq!(node.mining_address(), None, "no --mine, no miner");
    assert_eq!(node.config().network, Network::Devnet);

    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_node_generates_its_key_on_first_run_and_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join(crate::config::NODE_KEY_FILE);
    assert!(!key_path.exists());

    let node = Node::start(test_config(dir.path())).await.unwrap();
    let first = node.local_peer_id();
    assert!(key_path.exists(), "a devnet must start with no wallet setup");
    node.shutdown().await.unwrap();

    let node = Node::start(test_config(dir.path())).await.unwrap();
    assert_eq!(node.local_peer_id(), first, "the identity must survive a restart");
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutting_down_flushes_the_store_and_stops_every_task() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::start(test_config(dir.path())).await.unwrap();
    let cancel = node.cancel_token();
    assert!(!cancel.is_cancelled());

    node.shutdown().await.unwrap();
    assert!(cancel.is_cancelled(), "every task selects on this token");

    // The store file is closed and reopenable, which is what "flushed" buys.
    let node = Node::start(test_config(dir.path())).await.unwrap();
    assert_eq!(node.chain().tip().1, 0);
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn run_returns_when_the_token_is_cancelled_externally() {
    // The same path SIGINT takes, without sending a signal to the test runner.
    let dir = tempfile::tempdir().unwrap();
    let node = Node::start(test_config(dir.path())).await.unwrap();
    let cancel = node.cancel_token();
    let handle = tokio::spawn(node.run());
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(30), handle).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn a_mining_node_pays_its_own_key_and_climbs() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.mine = true;
    let node = Node::start(config).await.unwrap();

    let expected = NodeKey::load_or_create(&node.config().node_key_path())
        .unwrap()
        .mining_address(Network::Devnet)
        .unwrap()
        .encode();
    assert_eq!(node.mining_address(), Some(expected.as_str()));

    wait_for_height(&node, 1).await;
    let height = node.chain().tip().1;
    assert!(height >= 1, "chaind --mine must climb on devnet");
    assert!(node.metrics().snapshot().blocks_mined >= 1);

    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_mined_block_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.mine = true;
    let node = Node::start(config).await.unwrap();

    wait_for_height(&node, 1).await;
    let tip = node.chain().tip();
    assert!(tip.1 >= 1);
    node.shutdown().await.unwrap();

    let node = Node::start(test_config(dir.path())).await.unwrap();
    assert!(node.chain().tip().1 >= tip.1, "the flush must not have lost the tip");
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_datadir_belonging_to_another_chain_is_refused() {
    // The genesis check working is the point: a node whose parameters differ
    // from the network's cannot sync with it, and finding out at startup is
    // cheaper than finding out at block one.
    let dir = tempfile::tempdir().unwrap();
    let node = Node::start(test_config(dir.path())).await.unwrap();
    node.shutdown().await.unwrap();

    let mut config = test_config(dir.path());
    config.network = Network::Testnet;
    config.params = ChainParams::testnet();
    let e = Node::start(config).await.unwrap_err();
    assert!(
        matches!(e, NodeError::Storage(_) | NodeError::Chain(_)),
        "expected a chain-identity failure, got {e}"
    );
}

#[tokio::test]
async fn the_index_flag_reaches_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.index = true;
    let node = Node::start(config).await.unwrap();
    assert!(node.store().is_indexed());
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_node_subscribes_to_its_own_chain_events() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::start(test_config(dir.path())).await.unwrap();
    let mut events = node.subscribe();
    assert!(events.try_recv().is_err(), "nothing has happened yet");
    node.shutdown().await.unwrap();
}

#[test]
fn the_shutdown_grace_is_bounded() {
    // A service manager sends SIGTERM and then SIGKILL; a grace period longer
    // than its patience turns a clean stop into a hard kill.
    assert!(SHUTDOWN_GRACE >= Duration::from_secs(1));
    assert!(SHUTDOWN_GRACE <= Duration::from_secs(60));
}

#[test]
fn a_mine_address_for_the_wrong_network_never_reaches_the_miner() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path());
    let key = NodeKey::from_seed([5u8; 32]);
    let mainnet = key.mining_address(Network::Mainnet).unwrap();
    let e = resolve_payout(Some(&mainnet), &key, config.network).unwrap_err();
    assert!(
        matches!(e, NodeError::Config(ConfigError::AddressNetworkMismatch { .. })),
        "{e}"
    );
}
