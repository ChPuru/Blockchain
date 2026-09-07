//! The node `chaind` starts, driven in process.
//!
//! `chaind` is a front end: it resolves a [`NodeConfig`] and hands it to
//! [`ferrum_node::Node`]. This test drives the same two steps directly, which
//! is the point of that split — the whole runtime (store, genesis, swarm, both
//! listeners, the miner, the shutdown path) is reachable without spawning a
//! process, so a wiring bug fails a test instead of a devnet.
//!
//! Every listener binds port **0** and the real address is read back from the
//! node, so two copies of the suite can run at once and CI never collides with
//! a developer's own devnet.

use std::sync::Arc;
use std::time::Duration;

use ferrum_node::config::{CliOverrides, MapEnv, resolve};
use ferrum_node::{Node, NodeConfig};
use ferrum_rpc::FerrumRpcClient as _;
use ferrum_types::Network;

/// A devnet configuration with every listener on an ephemeral port.
fn devnet_config(datadir: &std::path::Path, mine: bool) -> NodeConfig {
    let overrides = CliOverrides {
        network: Some("devnet".to_owned()),
        datadir: Some(datadir.to_path_buf()),
        rpc_listen: Some("127.0.0.1:0".to_owned()),
        p2p_listen: Some("/ip4/127.0.0.1/tcp/0".to_owned()),
        explorer_listen: Some("127.0.0.1:0".to_owned()),
        index: Some(true),
        mine: Some(mine),
        ..CliOverrides::default()
    };
    // `MapEnv::new()` and no file: the test asserts about the flags it passed,
    // not about whatever `FERRUM_*` the developer happens to have exported.
    resolve(&overrides, &MapEnv::new(), None).expect("a resolvable devnet configuration")
}

/// A client for a running node's JSON-RPC listener.
fn client_for(node: &Node) -> Arc<jsonrpsee::http_client::HttpClient> {
    let addr = node.rpc_addr().expect("the node bound its json-rpc listener");
    Arc::new(
        jsonrpsee::http_client::HttpClientBuilder::default()
            .request_timeout(Duration::from_secs(10))
            .build(format!("http://{addr}"))
            .expect("a well-formed url"),
    )
}

/// Poll until `f` answers, or give up.
async fn wait_for<F, Fut, T>(timeout: Duration, mut f: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(value) = f().await {
            return Some(value);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_node_starts_mines_answers_rpc_and_shuts_down_cleanly() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = devnet_config(dir.path(), true);
    let store_path = config.store_path();
    let node_key = config.node_key_path();

    let node = Node::start(config).await.expect("the node starts");
    let client = client_for(&node);

    // 1. The listener is up and knows which chain it is on.
    let info = wait_for(Duration::from_secs(30), || {
        let client = Arc::clone(&client);
        async move { client.get_blockchain_info().await.ok() }
    })
    .await
    .expect("the node did not answer getblockchaininfo within 30s");
    assert_eq!(info.chain, "devnet");
    assert_eq!(info.chain_id, 3);
    assert!(info.index_enabled, "--index was requested");

    // 2. Genesis is computed from the parameters, not read from a file.
    let genesis = client.get_block_hash(0).await.expect("genesis exists");
    assert_eq!(genesis, ferrum_chain::genesis_hash(&Network::Devnet.params()).to_string());

    // 3. A devnet with no wallet mines to the key in <datadir>/node.key,
    //    which CONTRACT §13.1 requires and devnet/up.sh depends on.
    assert!(node_key.exists(), "the node key was not created on first run");
    assert!(node.mining_address().is_some(), "a mining node must name its payout address");

    // 4. The miner climbs.
    let height = wait_for(Duration::from_secs(60), || {
        let client = Arc::clone(&client);
        async move {
            client.get_blockchain_info().await.ok().filter(|i| i.height >= 2).map(|i| i.height)
        }
    })
    .await
    .expect("the miner did not reach height 2 within 60s");

    // 5. What it produced reads back.
    let hash = client.get_block_hash(1).await.expect("block 1 exists");
    let header = client.get_block_header(hash).await.expect("its header is readable");
    assert_eq!(header.height, 1);
    assert_eq!(header.engine, "pow");
    assert_eq!(client.get_state_root(None).await.expect("a state root").len(), 64);

    // 6. Shutdown takes the same path SIGTERM takes.
    node.shutdown().await.expect("a clean shutdown");

    // 7. The store was flushed: reopening finds at least the height reached.
    let store =
        ferrum_storage::Store::open(&store_path, ferrum_storage::StoreConfig::indexed())
            .expect("the store reopens");
    let (_, reopened) = store.tip().expect("a readable tip").expect("a tip exists");
    assert!(reopened >= height, "reopened at {reopened}, was at {height}");
    assert_eq!(
        store.chain_id().expect("a chain id"),
        Some(Network::Devnet.params().chain_id)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_node_serves_rpc_without_mining() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let node = Node::start(devnet_config(dir.path(), false)).await.expect("the node starts");
    let client = client_for(&node);

    let info = wait_for(Duration::from_secs(30), || {
        let client = Arc::clone(&client);
        async move { client.get_blockchain_info().await.ok() }
    })
    .await
    .expect("the node did not answer within 30s");

    // Genesis only: without --mine nothing is produced locally, and with no
    // peers nothing arrives.
    assert_eq!(info.height, 0);
    assert_eq!(info.mempool_size, 0);
    assert!(node.mining_address().is_none());

    // The network surface answers even with no peers.
    let network = client.get_network_info().await.expect("getnetworkinfo answers");
    assert_eq!(network.chain, "devnet");
    assert_eq!(network.peer_count, 0);
    assert!(!network.local_peer_id.is_empty());
    assert_eq!(network.local_peer_id, node.local_peer_id().to_string());
    assert!(client.get_peer_info().await.expect("getpeerinfo answers").is_empty());

    node.shutdown().await.expect("a clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_node_refuses_a_datadir_belonging_to_another_chain() {
    // A store carries its chain id, so pointing a devnet node at a mainnet
    // datadir has to fail at startup rather than after the first block.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = devnet_config(dir.path(), false);
    {
        let store = ferrum_storage::Store::open(
            &config.store_path(),
            ferrum_storage::StoreConfig::default()
                .with_chain_id(Network::Mainnet.params().chain_id),
        )
        .expect("a mainnet store");
        drop(store);
    }

    assert!(
        Node::start(config).await.is_err(),
        "a mainnet datadir must not open as devnet"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forced_engine_reaches_the_router() {
    // `--consensus pow` pins the engine. The router would have chosen it here
    // anyway, so the assertion is that forcing it changes nothing observable
    // rather than that it breaks the node.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let overrides = CliOverrides {
        network: Some("devnet".to_owned()),
        datadir: Some(dir.path().to_path_buf()),
        rpc_listen: Some("127.0.0.1:0".to_owned()),
        p2p_listen: Some("/ip4/127.0.0.1/tcp/0".to_owned()),
        explorer_listen: Some("127.0.0.1:0".to_owned()),
        consensus: Some("pow".to_owned()),
        ..CliOverrides::default()
    };
    let config = resolve(&overrides, &MapEnv::new(), None).expect("a resolvable configuration");

    let node = Node::start(config).await.expect("the node starts");
    let client = client_for(&node);
    let info = wait_for(Duration::from_secs(30), || {
        let client = Arc::clone(&client);
        async move { client.get_blockchain_info().await.ok() }
    })
    .await
    .expect("the node did not answer within 30s");
    assert_eq!(info.engine, "pow");
    assert!(info.finalized_height.is_none(), "nothing is ever final under proof of work");

    node.shutdown().await.expect("a clean shutdown");
}
