//! `genesis mine` and the `chaind` configuration surface, through the real
//! binaries.
//!
//! `genesis mine` is the command `RUNNING.md` §4 tells an operator to run
//! before launching a network, and CONTRACT §13.1 fixes its last line as
//! `nonce=<n> hash=<hex>`. The header it produces must satisfy its own target
//! — otherwise the first node to start would reject its own genesis — and it
//! must equal the block `ferrum-chain` independently computes from the same
//! parameters, or every joining node would disagree with the published hash.

use assert_cmd::Command;
use ferrum_consensus::{CompactTarget, compact_to_target, hash_meets_target};
use ferrum_types::{BlockHash, Network};
use serde_json::Value;

fn cli() -> Command {
    Command::cargo_bin("chain-cli").expect("chain-cli is a bin target of this crate")
}

fn daemon() -> Command {
    Command::cargo_bin("chaind").expect("chaind is a bin target of this crate")
}

fn stdout_of(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).to_string()
}

#[test]
fn genesis_mine_prints_nonce_and_hash_on_its_last_line() {
    let assert = cli().args(["genesis", "mine", "--network", "devnet"]).assert().success();
    let out = stdout_of(&assert);
    let last = out.lines().next_back().unwrap_or_default();
    assert!(last.starts_with("nonce="), "{out}");
    assert!(last.contains(" hash="), "{out}");

    let hash = last.split("hash=").nth(1).unwrap_or_default();
    assert_eq!(hash.len(), 64, "{last}");
    assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()), "{last}");
}

#[test]
fn the_mined_devnet_genesis_satisfies_its_own_target() {
    let assert =
        cli().args(["--json", "genesis", "mine", "--network", "devnet"]).assert().success();
    let json: Value = serde_json::from_slice(&assert.get_output().stdout).expect("json");

    let hash = BlockHash::from_hex(json["hash"].as_str().expect("a hash")).expect("valid hex");
    let bits = CompactTarget(
        u32::try_from(json["bits"].as_u64().expect("bits")).expect("bits fit in u32"),
    );
    let target = compact_to_target(bits).expect("devnet bits expand");
    assert!(hash_meets_target(&hash, target), "the mined header does not meet its own target");
}

#[test]
fn the_mined_devnet_genesis_is_the_one_a_node_computes() {
    let assert =
        cli().args(["--json", "genesis", "mine", "--network", "devnet"]).assert().success();
    let json: Value = serde_json::from_slice(&assert.get_output().stdout).expect("json");
    let params = Network::Devnet.params();
    assert_eq!(json["hash"], ferrum_chain::genesis_hash(&params).to_string());
}

#[test]
fn genesis_mine_accepts_the_running_md_invocation() {
    // RUNNING.md §4, verbatim in shape.
    let assert = cli()
        .args([
            "--json",
            "genesis",
            "mine",
            "--network",
            "devnet",
            "--message",
            "Ferrum genesis - 2026-09-07",
            "--timestamp",
            "1757203200000",
        ])
        .assert()
        .success();
    let json: Value = serde_json::from_slice(&assert.get_output().stdout).expect("json");
    assert_eq!(json["message"], "Ferrum genesis - 2026-09-07");
    assert_eq!(json["timestamp_ms"], 1_757_203_200_000_u64);
}

#[test]
fn genesis_mine_gives_up_loudly_rather_than_forever() {
    let assert = cli()
        .args(["genesis", "mine", "--network", "mainnet", "--max-tries", "1"])
        .assert()
        .failure();
    assert!(assert.get_output().stdout.is_empty(), "nothing may reach stdout on failure");
    let err = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(err.contains("no genesis nonce"), "{err}");
}

#[test]
fn chaind_resolves_the_devnet_configuration_without_starting() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let assert = daemon()
        .args(["--network", "devnet", "--datadir"])
        .arg(dir.path())
        .args([
            "--rpc-listen",
            "127.0.0.1:18645",
            "--p2p-listen",
            "/ip4/127.0.0.1/tcp/18655",
            "--explorer-listen",
            "127.0.0.1:18665",
            "--metrics-listen",
            "127.0.0.1:19100",
            "--index",
            "--log-format",
            "text",
            "--peer",
            "/ip4/127.0.0.1/tcp/18656",
            "--mine",
            "--print-config",
        ])
        .env("FERRUM_DATADIR", dir.path())
        .assert()
        .success();

    let json: Value = serde_json::from_slice(&assert.get_output().stdout).expect("json");
    assert_eq!(json["network"], "devnet");
    assert_eq!(json["chain_id"], 3);
    assert_eq!(json["rpc_listen"], "127.0.0.1:18645");
    assert_eq!(json["explorer_listen"], "127.0.0.1:18665");
    assert_eq!(json["metrics_listen"], "127.0.0.1:19100");
    assert_eq!(json["mine"], true);
    assert_eq!(json["index"], true);
    assert_eq!(json["peers"][0], "/ip4/127.0.0.1/tcp/18656");
    // No --mine-address: the node will pay the key in <datadir>/node.key.
    assert!(json["mine_address"].is_null());
}

#[test]
fn chaind_reports_the_contract_defaults_when_given_nothing_but_a_datadir() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let assert = daemon()
        .arg("--datadir")
        .arg(dir.path())
        .arg("--print-config")
        .env("FERRUM_DATADIR", dir.path())
        .assert()
        .success();
    let json: Value = serde_json::from_slice(&assert.get_output().stdout).expect("json");
    assert_eq!(json["rpc_listen"], "127.0.0.1:8645");
    assert_eq!(json["p2p_listen"], "/ip4/0.0.0.0/tcp/8655");
    assert_eq!(json["explorer_listen"], "127.0.0.1:8665");
    assert!(json["metrics_listen"].is_null(), "metrics are off unless asked for");
}

#[test]
fn chaind_refuses_an_unusable_listen_address() {
    let assert = daemon().args(["--rpc-listen", "localhost", "--print-config"]).assert().failure();
    let err = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(err.contains("--rpc-listen"), "{err}");
}

#[test]
fn chaind_refuses_an_unknown_network() {
    let assert = daemon().args(["--network", "bitcoin", "--print-config"]).assert().failure();
    let err = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(err.contains("network"), "{err}");
    assert!(err.contains("bitcoin"), "{err}");
}

#[test]
fn chaind_reads_the_fork_script_consensus_file() {
    // devnet/fork.sh writes this file and passes it with --consensus-config.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let key_file = dir.path().join("validator.key");
    cli()
        .arg("--datadir")
        .arg(dir.path())
        .args(["wallet", "new", "--output"])
        .arg(&key_file)
        .env("FERRUM_DATADIR", dir.path())
        .assert()
        .success();

    let assert = cli()
        .arg("--datadir")
        .arg(dir.path())
        .args(["wallet", "dump-pubkey", "--key"])
        .arg(&key_file)
        .env("FERRUM_DATADIR", dir.path())
        .assert()
        .success();
    let pubkey = stdout_of(&assert).lines().next_back().unwrap_or_default().to_owned();

    let fork = dir.path().join("fork.toml");
    std::fs::write(
        &fork,
        format!("bft_activation_height = 120\nbft_validators = [\"{pubkey}\"]\n"),
    )
    .expect("write the fork configuration");

    let assert = daemon()
        .args(["--network", "devnet", "--datadir"])
        .arg(dir.path())
        .arg("--consensus-config")
        .arg(&fork)
        .arg("--validator-key")
        .arg(&key_file)
        .arg("--print-config")
        .env("FERRUM_DATADIR", dir.path())
        .assert()
        .success();
    let json: Value = serde_json::from_slice(&assert.get_output().stdout).expect("json");
    assert_eq!(json["bft_activation_height"], 120);
    assert_eq!(json["bft_validators"], 1);
}

#[test]
fn chain_reindex_says_so_when_the_datadir_holds_no_store() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let assert = cli()
        .arg("--datadir")
        .arg(dir.path())
        .args(["chain", "reindex", "--network", "devnet"])
        .env("FERRUM_DATADIR", dir.path())
        .assert()
        .failure();
    let err = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(err.contains("no store at"), "{err}");
}

#[test]
fn tx_decode_works_without_a_node() {
    // A one-input, one-output transaction, encoded here and decoded there.
    let tx = ferrum_types::Transaction {
        version: 1,
        inputs: vec![ferrum_types::TxIn::new(
            ferrum_types::OutPoint::new(ferrum_types::Txid::ZERO, 1),
            ferrum_types::Script::EMPTY,
        )],
        outputs: vec![ferrum_types::TxOut::new(
            ferrum_types::Amount::from_grains(5_000),
            ferrum_types::Script::EMPTY,
        )],
        lock_time: 0,
    };
    let assert = cli()
        .args(["--json", "tx", "decode", &hex::encode(tx.encode_envelope())])
        .assert()
        .success();
    let json: Value = serde_json::from_slice(&assert.get_output().stdout).expect("json");
    assert_eq!(json["version"], 1);
    assert_eq!(json["vin"][0]["vout"], 1);
    assert_eq!(json["txid"], ferrum_storage::txid(&tx).to_string());
}
