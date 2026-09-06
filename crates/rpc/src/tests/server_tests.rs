//! The two listeners, end to end.
//!
//! These are the tests that prove the wire format rather than asserting about
//! it: the JSON-RPC calls go through the generated `FerrumRpcClient` over a
//! real HTTP socket, and the explorer calls go over a real TCP connection to
//! the `axum` listener. Everything else in the suite drives the handlers
//! directly, which cannot catch a serialisation or routing mistake.

use std::net::SocketAddr;

use jsonrpsee::http_client::HttpClientBuilder;

use crate::api::FerrumRpcClient;
use crate::error::RpcErrorCode;
use crate::server::{
    ExplorerServerConfig, RpcServerConfig, spawn_explorer_server, spawn_rpc_server,
};
use crate::tests::fixture::Fixture;

fn ephemeral() -> SocketAddr {
    "127.0.0.1:0".parse().expect("a literal loopback address")
}

/// A minimal HTTP GET over a raw socket, so the explorer tests do not need an
/// HTTP client dependency.
async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nAccept: */*\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let text = String::from_utf8_lossy(&buffer).into_owned();
    let status = text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
    (status, body)
}

#[tokio::test]
async fn the_rpc_server_answers_the_generated_client() {
    let f = Fixture::build(2, false);
    let server = spawn_rpc_server(RpcServerConfig::at(ephemeral()), f.context()).await.unwrap();
    let client = HttpClientBuilder::default().build(server.http_url()).unwrap();

    let info = client.get_blockchain_info().await.unwrap();
    assert_eq!(info.height, 2);
    assert_eq!(info.chain, "devnet");

    let hash = client.get_block_hash(1).await.unwrap();
    assert_eq!(hash, f.blocks[0].to_hex());

    server.stop();
}

#[tokio::test]
async fn optional_parameters_may_be_omitted_over_the_wire() {
    let f = Fixture::build(1, false);
    let server = spawn_rpc_server(RpcServerConfig::at(ephemeral()), f.context()).await.unwrap();
    let client = HttpClientBuilder::default().build(server.http_url()).unwrap();

    // `None` here is a shorter params array, not a JSON `null`; the defaults
    // have to hold on the server side.
    let block = client.get_block(f.blocks[0].to_hex(), None).await.unwrap();
    assert!(matches!(block, crate::types::rpc::GetBlockResult::Verbose(_)));
    let root = client.get_state_root(None).await.unwrap();
    assert_eq!(root.len(), 64);
    let mempool = client.get_raw_mempool(None).await.unwrap();
    assert!(matches!(mempool, crate::types::rpc::RawMempoolResult::Ids(ref v) if v.is_empty()));

    server.stop();
}

#[tokio::test]
async fn amounts_cross_the_wire_as_strings() {
    let f = Fixture::build(2, false);
    let server = spawn_rpc_server(RpcServerConfig::at(ephemeral()), f.context()).await.unwrap();
    let client = HttpClientBuilder::default().build(server.http_url()).unwrap();

    let balance = client.get_balance(f.miner.encode()).await.unwrap();
    let json = serde_json::to_value(&balance).unwrap();
    assert!(json["confirmed"].is_string(), "an amount is never a JSON number");
    assert!(json["immature"].is_string());
    assert!(json["utxo_count"].is_number(), "a count is a count");

    server.stop();
}

#[tokio::test]
async fn a_rejected_call_keeps_its_code_through_the_client() {
    let f = Fixture::build(1, false);
    let server = spawn_rpc_server(RpcServerConfig::at(ephemeral()), f.context()).await.unwrap();
    let client = HttpClientBuilder::default().build(server.http_url()).unwrap();

    let err = client.get_block_hash(4_242).await.unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains(&RpcErrorCode::HeightOutOfRange.code().to_string()),
        "the stable code must survive the round trip: {text}"
    );

    server.stop();
}

#[tokio::test]
async fn the_rpc_server_reports_the_port_it_actually_bound() {
    let f = Fixture::build(1, false);
    let server = spawn_rpc_server(RpcServerConfig::at(ephemeral()), f.context()).await.unwrap();
    assert_ne!(server.local_addr().port(), 0, "port 0 must resolve to a real port");
    assert!(server.http_url().starts_with("http://127.0.0.1:"));
    assert!(server.ws_url().starts_with("ws://127.0.0.1:"));
    server.stop();
}

#[tokio::test]
async fn binding_a_port_twice_is_an_error_rather_than_a_panic() {
    let f = Fixture::build(1, false);
    let first = spawn_rpc_server(RpcServerConfig::at(ephemeral()), f.context()).await.unwrap();
    let taken = first.local_addr();
    let second = spawn_rpc_server(RpcServerConfig::at(taken), f.context()).await;
    match second {
        Err(e) => assert_eq!(e.code(), RpcErrorCode::InternalError),
        // Some platforms permit the rebind; the contract is only that we do
        // not panic, so a success is acceptable and the handle is dropped.
        Ok(other) => other.stop(),
    }
    first.stop();
}

#[tokio::test]
async fn the_explorer_serves_the_page_and_the_api_on_one_port() {
    let f = Fixture::build(2, false);
    let explorer =
        spawn_explorer_server(ExplorerServerConfig::at(ephemeral()), f.context()).await.unwrap();
    let addr = explorer.local_addr();

    let (status, html) = http_get(addr, "/").await;
    assert_eq!(status, 200);
    assert!(html.contains("Ferrum Explorer"));

    let (status, body) = http_get(addr, "/api/stats").await;
    assert_eq!(status, 200);
    let start = body.find('{').unwrap();
    let end = body.rfind('}').unwrap();
    let json: serde_json::Value = serde_json::from_str(&body[start..=end]).unwrap();
    assert_eq!(json["height"], 2);
    assert_eq!(json["chain"], "devnet");

    explorer.stopped().await;
}

#[tokio::test]
async fn the_explorer_reports_the_port_it_actually_bound() {
    let f = Fixture::build(1, false);
    let explorer =
        spawn_explorer_server(ExplorerServerConfig::at(ephemeral()), f.context()).await.unwrap();
    assert_ne!(explorer.local_addr().port(), 0);
    assert!(explorer.url().starts_with("http://127.0.0.1:"));
    explorer.stopped().await;
}

#[tokio::test]
async fn a_stopped_explorer_stops_answering() {
    let f = Fixture::build(1, false);
    let explorer =
        spawn_explorer_server(ExplorerServerConfig::at(ephemeral()), f.context()).await.unwrap();
    let addr = explorer.local_addr();
    assert_eq!(http_get(addr, "/api/stats").await.0, 200);
    explorer.stopped().await;
    // The listener is closed, so a fresh connection fails. That is what makes
    // a clean shutdown possible before the store is flushed.
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn a_configured_static_page_replaces_the_compiled_in_one() {
    let f = Fixture::build(1, false);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.html");
    std::fs::write(&path, "<h1>a different page</h1>").unwrap();

    let config = ExplorerServerConfig {
        rest: crate::rest::RestConfig {
            static_index: Some(path),
            ..crate::rest::RestConfig::default()
        },
        ..ExplorerServerConfig::at(ephemeral())
    };
    let explorer = spawn_explorer_server(config, f.context()).await.unwrap();
    let (status, body) = http_get(explorer.local_addr(), "/").await;
    assert_eq!(status, 200);
    assert!(body.contains("a different page"));
    explorer.stopped().await;
}

#[tokio::test]
async fn an_unreadable_static_page_falls_back_instead_of_failing_to_start() {
    let f = Fixture::build(1, false);
    let config = ExplorerServerConfig {
        rest: crate::rest::RestConfig {
            static_index: Some(std::path::PathBuf::from("no/such/index.html")),
            ..crate::rest::RestConfig::default()
        },
        ..ExplorerServerConfig::at(ephemeral())
    };
    let explorer = spawn_explorer_server(config, f.context()).await.unwrap();
    let (status, body) = http_get(explorer.local_addr(), "/").await;
    assert_eq!(status, 200, "a missing page must not take the node down");
    assert!(body.contains("Ferrum Explorer"));
    explorer.stopped().await;
}

#[tokio::test]
async fn both_listeners_can_share_one_context() {
    // The node holds one `NodeContext` and hands a clone to each surface; a
    // block connected through one is visible through the other.
    let f = Fixture::build(1, false);
    let ctx = f.context();
    let rpc = spawn_rpc_server(RpcServerConfig::at(ephemeral()), ctx.clone()).await.unwrap();
    let explorer = spawn_explorer_server(ExplorerServerConfig::at(ephemeral()), ctx).await.unwrap();

    f.chain.mine_and_connect(&f.miner.script_pubkey(), Vec::new(), 4_242);

    let client = HttpClientBuilder::default().build(rpc.http_url()).unwrap();
    assert_eq!(client.get_blockchain_info().await.unwrap().height, 2);

    let (_, body) = http_get(explorer.local_addr(), "/api/stats").await;
    let start = body.find('{').unwrap();
    let end = body.rfind('}').unwrap();
    let json: serde_json::Value = serde_json::from_str(&body[start..=end]).unwrap();
    assert_eq!(json["height"], 2);

    rpc.stop();
    explorer.stopped().await;
}
