//! Milestone M5, through the real binaries: "create wallet → mine → send →
//! confirm → balance read from the UTXO set, never by rescan."
//!
//! A node runs in-process on ephemeral ports and mines to the CLI wallet's own
//! address. Once the chain is past `coinbase_maturity`, `chain-cli` — a real
//! subprocess, talking JSON-RPC — reads the balance, spends, and watches the
//! payment reach the mempool.
//!
//! The maturity wait is not padding. Coinbase maturity is a **consensus** rule
//! (CONTRACT §8.1 rule 7): a wallet that offered to spend a coinbase sooner
//! would build a transaction that can never confirm, and the failure would be
//! silent. Proving the wallet waits is the point of the test.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use assert_cmd::Command as CliCommand;
use ferrum_node::Node;
use ferrum_node::config::{CliOverrides, MapEnv, resolve};
use ferrum_rpc::FerrumRpcClient as _;
use ferrum_types::Network;
use ferrum_wallet::Wallet;

/// Run `chain-cli` against `rpc_url` with `datadir`, and return stdout.
fn cli(datadir: &Path, rpc_url: &str, args: &[&str]) -> String {
    let assert = CliCommand::cargo_bin("chain-cli")
        .expect("chain-cli is a bin target of this crate")
        .arg("--datadir")
        .arg(datadir)
        .arg("--rpc")
        .arg(rpc_url)
        .args(args)
        .env("FERRUM_DATADIR", datadir)
        .assert()
        .success();
    String::from_utf8_lossy(&assert.get_output().stdout).to_string()
}

/// Like [`cli`], but hands back whether the command succeeded instead of
/// insisting that it did.
fn cli_try(datadir: &Path, rpc_url: &str, args: &[&str]) -> (bool, String) {
    let output = CliCommand::cargo_bin("chain-cli")
        .expect("chain-cli is a bin target of this crate")
        .arg("--datadir")
        .arg(datadir)
        .arg("--rpc")
        .arg(rpc_url)
        .args(args)
        .env("FERRUM_DATADIR", datadir)
        .output()
        .expect("chain-cli ran");
    (output.status.success(), String::from_utf8_lossy(&output.stdout).to_string())
}

/// The last line of stdout — the value CONTRACT §13.1 promises there.
fn last_line(text: &str) -> String {
    text.lines().next_back().unwrap_or_default().trim().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_mine_send_and_read_the_balance_back_from_the_utxo_set() {
    let node_dir = tempfile::tempdir().expect("a temporary directory");
    let wallet_dir = tempfile::tempdir().expect("a temporary directory");
    let params = Network::Devnet.params();

    // ---- create the wallet the node will mine to ------------------------
    // Built here rather than through the CLI so the address is known before
    // the node starts; `chain-cli` then opens the very same keystore.
    let payout = {
        let (mut wallet, _mnemonic) = Wallet::create(
            &ferrum_cli::paths::wallet_path(wallet_dir.path()),
            Network::Devnet,
            "",
            12,
            &mut rand::rngs::OsRng,
        )
        .expect("a new wallet");
        wallet.new_address().expect("a receive address").encode()
    };

    // ---- start a mining node paying that address ------------------------
    let overrides = CliOverrides {
        network: Some("devnet".to_owned()),
        datadir: Some(node_dir.path().to_path_buf()),
        rpc_listen: Some("127.0.0.1:0".to_owned()),
        p2p_listen: Some("/ip4/127.0.0.1/tcp/0".to_owned()),
        explorer_listen: Some("127.0.0.1:0".to_owned()),
        index: Some(true),
        mine: Some(true),
        mine_address: Some(payout.clone()),
        ..CliOverrides::default()
    };
    let config = resolve(&overrides, &MapEnv::new(), None).expect("a resolvable configuration");
    let store_path = config.store_path();
    let node = Node::start(config).await.expect("the node starts");
    let rpc_url =
        format!("http://{}", node.rpc_addr().expect("the node bound its json-rpc listener"));

    let client = Arc::new(
        jsonrpsee::http_client::HttpClientBuilder::default()
            .request_timeout(Duration::from_secs(10))
            .build(&rpc_url)
            .expect("a well-formed url"),
    );

    // ---- wait for the first coinbase to mature --------------------------
    let wanted = params.coinbase_maturity.saturating_add(2);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(240);
    let mut height = 0;
    while tokio::time::Instant::now() < deadline {
        if let Ok(info) = client.get_blockchain_info().await {
            height = info.height;
            if height >= wanted {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(height >= wanted, "the miner reached only height {height} of {wanted} in 240s");

    // ---- the CLI reads the balance out of the UTXO set ------------------
    let node_dir_path = node_dir.path().to_path_buf();
    let wallet_dir_path = wallet_dir.path().to_path_buf();
    assert!(store_path.exists(), "the node opened a store at {}", store_path.display());
    let url = rpc_url.clone();

    let balance_json = tokio::task::spawn_blocking({
        let dir = wallet_dir_path.clone();
        let url = url.clone();
        move || cli(&dir, &url, &["--json", "wallet", "balance"])
    })
    .await
    .expect("the wallet balance subprocess ran");
    let balance: serde_json::Value =
        serde_json::from_str(&balance_json).expect("--json prints one document");

    let confirmed = balance["confirmed_grains"]
        .as_str()
        .and_then(|g| g.parse::<u64>().ok())
        .expect("a confirmed grain count");
    let immature = balance["immature_grains"]
        .as_str()
        .and_then(|g| g.parse::<u64>().ok())
        .expect("an immature grain count");

    assert!(confirmed > 0, "no coinbase matured by height {height}: {balance}");
    assert!(
        immature > 0,
        "the most recent 100 coinbases must still be immature at height {height}: {balance}"
    );

    // ---- spend, and watch the payment reach the mempool ------------------
    let txid = tokio::task::spawn_blocking({
        let dir = wallet_dir_path.clone();
        let url = url.clone();
        let to = payout.clone();
        move || last_line(&cli(&dir, &url, &["wallet", "send", "--to", &to, "--amount", "1.0"]))
    })
    .await
    .expect("the wallet send subprocess ran");

    assert_eq!(txid.len(), 64, "the last line must be a bare txid, got {txid:?}");
    assert!(txid.bytes().all(|b| b.is_ascii_hexdigit()), "{txid}");

    // The node accepted it: it is either still in the mempool or already
    // mined, and `getrawtransaction` finds it either way.
    let found = client.get_raw_transaction(txid.clone(), Some(true)).await;
    assert!(found.is_ok(), "the node does not know {txid}: {found:?}");

    // ---- the same send again, inside the same block interval ------------
    // Both invocations build against the same *confirmed* UTXO set — the node
    // never reports its mempool to `listunspent`/`gettxout` — so the second
    // one used to rebuild a byte-identical transaction, the mempool answered
    // "already in the pool", and `sendrawtransaction` reported that as a plain
    // success. The operator is then told they paid twice and paid once.
    //
    // Either outcome is honest: a refusal, or a genuinely different payment
    // (a block may confirm the first send in between). Reporting the *same*
    // txid as a second success is the thing that must never happen.
    let (repeated_ok, repeated_out) = tokio::task::spawn_blocking({
        let dir = wallet_dir_path.clone();
        let url = url.clone();
        let to = payout.clone();
        move || cli_try(&dir, &url, &["wallet", "send", "--to", &to, "--amount", "1.0"])
    })
    .await
    .expect("the repeated wallet send subprocess ran");

    if repeated_ok {
        assert_ne!(
            last_line(&repeated_out),
            txid,
            "one transaction was reported as two successful payments",
        );
    }

    // ---- the other read commands answer against the same node ------------
    let info = tokio::task::spawn_blocking({
        let dir = wallet_dir_path.clone();
        let url = url.clone();
        move || cli(&dir, &url, &["--json", "chain", "info"])
    })
    .await
    .expect("chain info ran");
    let info: serde_json::Value = serde_json::from_str(&info).expect("json");
    assert_eq!(info["chain"], "devnet");
    assert_eq!(info["engine"], "pow");
    assert!(info["utxo_count"].as_u64().unwrap_or(0) > 0);

    let tip = tokio::task::spawn_blocking({
        let dir = wallet_dir_path.clone();
        let url = url.clone();
        move || last_line(&cli(&dir, &url, &["block", "tip"]))
    })
    .await
    .expect("block tip ran");
    assert_eq!(tip.len(), 64, "block tip must print a bare hash: {tip:?}");

    let root = tokio::task::spawn_blocking({
        let dir = wallet_dir_path.clone();
        let url = url.clone();
        move || last_line(&cli(&dir, &url, &["chain", "stateroot"]))
    })
    .await
    .expect("chain stateroot ran");
    assert_eq!(root.len(), 64, "chain stateroot must print a bare hash: {root:?}");

    // ---- stop, then rebuild the reverse index offline --------------------
    node.shutdown().await.expect("a clean shutdown");

    let reindex = tokio::task::spawn_blocking({
        let dir = node_dir_path.clone();
        let url = url.clone();
        move || cli(&dir, &url, &["--json", "chain", "reindex", "--network", "devnet"])
    })
    .await
    .expect("chain reindex ran");
    let reindex: serde_json::Value = serde_json::from_str(&reindex).expect("json");
    assert_eq!(
        reindex["state_root_unchanged"], true,
        "CONTRACT §8.3: disconnecting and reconnecting must leave an identical state root"
    );
    assert!(reindex["replayed"].as_u64().unwrap_or(0) >= wanted);
}
