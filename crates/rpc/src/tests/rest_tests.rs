//! The REST surface, driven through the real `axum` router.
//!
//! Every assertion here is about a field name `explorer/index.html` reads. The
//! page is the client, it is already written, and a renamed field renders as an
//! empty cell rather than an error — so the tests name the fields explicitly
//! instead of round-tripping a struct through itself.

use std::net::SocketAddr;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt;

use crate::context::NodeContext;
use crate::error::RpcErrorCode;
use crate::rest::{RestConfig, RestState, router};
use crate::tests::fixture::{Fixture, key};

/// The peer address every test request appears to come from.
const PEER: &str = "10.1.2.3:44444";

fn app(ctx: NodeContext) -> Router {
    router(RestState::new(ctx, RestConfig::default()))
}

/// Send a request through the router with connection info attached.
///
/// `oneshot` bypasses the listener, so `ConnectInfo` has to be inserted by
/// hand; without it the faucet's per-IP extractor would reject every request.
async fn send(app: &Router, mut request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let peer: SocketAddr = PEER.parse().unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, body.to_vec())
}

async fn get(app: &Router, path: &str) -> (StatusCode, Value) {
    let request = Request::builder().uri(path).body(Body::empty()).unwrap();
    let (status, body) = send(app, request).await;
    let json = serde_json::from_slice(&body)
        .unwrap_or_else(|e| panic!("{path} returned non-JSON ({e}): {:?}", String::from_utf8_lossy(&body)));
    (status, json)
}

// ------------------------------------------------------------- the static page

#[tokio::test]
async fn the_root_serves_the_explorer_page() {
    let f = Fixture::build(1, false);
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let (status, body) = send(&app(f.context()), request).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(body).unwrap();
    assert!(html.contains("<title>Ferrum Explorer</title>"));
    assert!(html.contains("/api/stats"));
}

#[tokio::test]
async fn an_unknown_route_is_a_json_404() {
    let f = Fixture::build(1, false);
    let (status, json) = get(&app(f.context()), "/api/nonesuch").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["code"], Value::from(RpcErrorCode::NotFound.code()));
    assert!(json["error"].is_string(), "the page reads `error` out of a failure");
}

// --------------------------------------------------------------------- stats

#[tokio::test]
async fn stats_carries_every_field_the_home_page_reads() {
    let f = Fixture::build(3, false);
    let (status, json) = get(&app(f.context()), "/api/stats").await;
    assert_eq!(status, StatusCode::OK);
    for field in [
        "chain",
        "height",
        "difficulty",
        "engine",
        "mempool_size",
        "utxo_count",
        "peers",
        "recent_blocks",
        "recent_txs",
        "faucet_enabled",
        "finalized_height",
    ] {
        assert!(json.get(field).is_some(), "/api/stats is missing `{field}`");
    }
    assert_eq!(json["chain"], "devnet");
    assert_eq!(json["height"], 3);
    assert_eq!(json["engine"], "pow");
    assert_eq!(json["peers"], 3);
    assert_eq!(json["faucet_enabled"], false);
    assert_eq!(json["finalized_height"], Value::Null);
    assert!(json["height"].is_number(), "the page computes height - 1");
}

#[tokio::test]
async fn recent_blocks_are_newest_first_with_the_fields_the_table_needs() {
    let f = Fixture::build(3, false);
    let (_, json) = get(&app(f.context()), "/api/stats").await;
    let blocks = json["recent_blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 4, "three mined blocks plus genesis");
    assert_eq!(blocks[0]["height"], 3);
    assert_eq!(blocks[3]["height"], 0);
    for field in ["height", "hash", "tx_count", "size", "timestamp_ms"] {
        assert!(blocks[0].get(field).is_some(), "recent_blocks is missing `{field}`");
    }
}

#[tokio::test]
async fn recent_transactions_carry_string_amounts() {
    let f = Fixture::build(2, false);
    let (_, json) = get(&app(f.context()), "/api/stats").await;
    let txs = json["recent_txs"].as_array().unwrap();
    assert!(!txs.is_empty());
    assert!(txs[0]["value"].is_string(), "an amount must never be a JSON number");
    assert!(txs[0]["fee"].is_string());
    assert_eq!(txs[0]["value"], "5000000000");
    assert!(txs[0]["height"].is_number());
}

#[tokio::test]
async fn a_mempool_transaction_shows_as_pending_in_stats() {
    let f = Fixture::build(1, false);
    f.mempool.insert(
        ferrum_types::Transaction::empty(),
        ferrum_types::Amount::from_grains(500),
        1,
    );
    let (_, json) = get(&app(f.context()), "/api/stats").await;
    assert_eq!(json["mempool_size"], 1);
    let txs = json["recent_txs"].as_array().unwrap();
    assert_eq!(txs[0]["height"], Value::Null, "the page renders a `pending` pill for null");
}

// --------------------------------------------------------------------- blocks

#[tokio::test]
async fn a_block_can_be_fetched_by_height_or_by_hash() {
    let f = Fixture::build(2, false);
    let (status, by_height) = get(&app(f.context()), "/api/block/1").await;
    assert_eq!(status, StatusCode::OK);
    let path = format!("/api/block/{}", f.blocks[0].to_hex());
    let (_, by_hash) = get(&app(f.context()), &path).await;
    assert_eq!(by_height, by_hash, "both spellings of the same block must agree");
}

#[tokio::test]
async fn a_block_carries_the_header_fields_the_page_reads() {
    let f = Fixture::build(2, false);
    let (_, json) = get(&app(f.context()), "/api/block/1").await;
    for field in ["hash", "height", "size", "engine", "total_work", "confirmations", "header", "txs"]
    {
        assert!(json.get(field).is_some(), "/api/block is missing `{field}`");
    }
    let header = &json["header"];
    for field in ["prev_hash", "merkle_root", "timestamp_ms", "bits", "nonce", "version"] {
        assert!(header.get(field).is_some(), "the block header is missing `{field}`");
    }
    assert!(header["bits"].is_number(), "the page evaluates (h.bits >>> 0)");
    assert!(header["nonce"].is_string());
    assert_eq!(json["confirmations"], 2);
    assert_eq!(json["next_hash"], Value::String(f.blocks[1].to_hex()));
}

#[tokio::test]
async fn a_block_transaction_row_has_vin_vout_value_and_fee() {
    let f = Fixture::build(2, true);
    let (_, json) = get(&app(f.context()), "/api/block/3").await;
    let txs = json["txs"].as_array().unwrap();
    assert_eq!(txs.len(), 2, "coinbase plus the fixture's spend");
    for field in ["txid", "vin", "vout", "value", "fee", "coinbase"] {
        assert!(txs[0].get(field).is_some(), "a block tx row is missing `{field}`");
    }
    assert_eq!(txs[0]["coinbase"], true);
    assert_eq!(txs[0]["fee"], "0", "a coinbase pays no fee");
    assert_eq!(txs[1]["fee"], "10000", "the fixture's spend leaves 10 000 grains");
    assert!(txs[1]["value"].is_string());
}

#[tokio::test]
async fn a_missing_block_height_is_a_400_with_a_stable_code() {
    let f = Fixture::build(1, false);
    let (status, json) = get(&app(f.context()), "/api/block/999").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], Value::from(RpcErrorCode::HeightOutOfRange.code()));
}

#[tokio::test]
async fn a_block_id_that_is_neither_a_height_nor_a_hash_is_invalid_hash() {
    let f = Fixture::build(1, false);
    let (status, json) = get(&app(f.context()), "/api/block/wat").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], Value::from(RpcErrorCode::InvalidHash.code()));
}

// --------------------------------------------------------------- transactions

#[tokio::test]
async fn a_transaction_carries_every_field_the_page_reads() {
    let f = Fixture::build(2, true);
    let path = format!("/api/tx/{}", f.spend_txid.unwrap().to_hex());
    let (status, json) = get(&app(f.context()), &path).await;
    assert_eq!(status, StatusCode::OK);
    for field in [
        "txid",
        "version",
        "lock_time",
        "size",
        "coinbase",
        "value",
        "fee",
        "fee_rate",
        "block_hash",
        "height",
        "confirmations",
        "inputs",
        "outputs",
    ] {
        assert!(json.get(field).is_some(), "/api/tx is missing `{field}`");
    }
    assert!(json["lock_time"].is_number(), "the page compares lock_time numerically");
    assert!(json["value"].is_string());
    assert!(json["fee"].is_string());
    assert_eq!(json["coinbase"], false);
    assert_eq!(json["height"], 3);
}

#[tokio::test]
async fn transaction_inputs_resolve_their_funding_output() {
    let f = Fixture::build(2, true);
    let path = format!("/api/tx/{}", f.spend_txid.unwrap().to_hex());
    let (_, json) = get(&app(f.context()), &path).await;
    let inputs = json["inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0]["coinbase"], false);
    assert_eq!(inputs[0]["value"], "5000000000", "the spent coinbase was 50 FRM");
    assert_eq!(inputs[0]["address"], Value::String(f.miner.encode()));
    assert!(inputs[0]["txid"].is_string());
    assert!(inputs[0]["vout"].is_number());
}

#[tokio::test]
async fn a_coinbase_input_is_marked_rather_than_resolved() {
    let f = Fixture::build(1, false);
    let block = f.chain.store.get_block(&f.blocks[0]).unwrap().unwrap();
    let id = ferrum_storage::txid(&block.txs[0]);
    let (_, json) = get(&app(f.context()), &format!("/api/tx/{}", id.to_hex())).await;
    let inputs = json["inputs"].as_array().unwrap();
    assert_eq!(inputs[0]["coinbase"], true);
    assert_eq!(inputs[0]["txid"], Value::Null);
    assert_eq!(json["coinbase"], true);
    assert_eq!(json["fee_rate"], Value::Null, "a coinbase has no fee rate");
}

#[tokio::test]
async fn an_unspent_output_reports_no_spender_and_a_spent_one_names_it() {
    let f = Fixture::build(2, true);
    // The coinbase of block 1 was spent by the fixture's transaction.
    let block = f.chain.store.get_block(&f.blocks[0]).unwrap().unwrap();
    let spent_id = ferrum_storage::txid(&block.txs[0]);
    let (_, json) = get(&app(f.context()), &format!("/api/tx/{}", spent_id.to_hex())).await;
    let outputs = json["outputs"].as_array().unwrap();
    assert_eq!(
        outputs[0]["spent_by"],
        Value::String(f.spend_txid.unwrap().to_hex()),
        "a spent output must name its spender or the page calls it unspent"
    );

    // The spend's own output is still unspent.
    let path = format!("/api/tx/{}", f.spend_txid.unwrap().to_hex());
    let (_, json) = get(&app(f.context()), &path).await;
    let outputs = json["outputs"].as_array().unwrap();
    assert_eq!(outputs[0]["spent_by"], Value::Null);
    assert_eq!(outputs[0]["address"], Value::String(f.recipient.encode()));
    assert_eq!(outputs[0]["script_type"], "p2pkh");
}

#[tokio::test]
async fn an_unknown_transaction_is_a_404() {
    let f = Fixture::build(1, false);
    let (status, json) = get(&app(f.context()), &format!("/api/tx/{}", "44".repeat(32))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["code"], Value::from(RpcErrorCode::NotFound.code()));
}

#[tokio::test]
async fn the_transaction_page_needs_the_index_and_says_so() {
    let f = Fixture::build_with_index(1, false, false);
    let (status, json) = get(&app(f.context()), &format!("/api/tx/{}", "55".repeat(32))).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(json["code"], Value::from(RpcErrorCode::IndexDisabled.code()));
    assert!(json["error"].as_str().unwrap().contains("--index"));
}

// ------------------------------------------------------------------ addresses

#[tokio::test]
async fn an_address_carries_every_field_the_page_reads() {
    let f = Fixture::build(3, false);
    let (status, json) = get(&app(f.context()), &format!("/api/address/{}", f.miner.encode())).await;
    assert_eq!(status, StatusCode::OK);
    for field in [
        "address",
        "script_type",
        "confirmed",
        "immature",
        "pending",
        "utxo_count",
        "tx_count",
        "transactions",
    ] {
        assert!(json.get(field).is_some(), "/api/address is missing `{field}`");
    }
    assert_eq!(json["address"], f.miner.encode());
    assert_eq!(json["script_type"], "p2pkh");
    assert!(json["confirmed"].is_string());
    assert!(json["immature"].is_string());
}

#[tokio::test]
async fn address_history_rows_carry_a_signed_string_delta() {
    let f = Fixture::build(3, false);
    let (_, json) = get(&app(f.context()), &format!("/api/address/{}", f.miner.encode())).await;
    let rows = json["transactions"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "one coinbase per mined block");
    for field in ["txid", "height", "delta", "timestamp_ms"] {
        assert!(rows[0].get(field).is_some(), "an address row is missing `{field}`");
    }
    assert!(rows[0]["delta"].is_string(), "the page tests the leading '-' of delta");
    assert_eq!(rows[0]["delta"], "5000000000");
    assert_eq!(rows[0]["height"], 3, "newest first");
    assert_eq!(rows[2]["height"], 1);
}

#[tokio::test]
async fn spending_shows_as_a_negative_delta() {
    let f = Fixture::build(2, true);
    let (_, json) = get(&app(f.context()), &format!("/api/address/{}", f.miner.encode())).await;
    let rows = json["transactions"].as_array().unwrap();
    let spend = rows
        .iter()
        .find(|r| r["txid"] == Value::String(f.spend_txid.unwrap().to_hex()))
        .expect("the spend is in the miner's history");
    let delta = spend["delta"].as_str().unwrap();
    assert!(delta.starts_with('-'), "delta was {delta}");
}

#[tokio::test]
async fn an_address_from_another_network_is_refused() {
    let f = Fixture::build(1, false);
    let (_, public) = key(9);
    let mainnet = ferrum_crypto::Address::p2pkh(ferrum_types::Network::Mainnet, &public);
    let (status, json) =
        get(&app(f.context()), &format!("/api/address/{}", mainnet.encode())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], Value::from(RpcErrorCode::InvalidAddress.code()));
}

#[tokio::test]
async fn the_address_page_needs_the_index() {
    let f = Fixture::build_with_index(1, false, false);
    let (status, json) =
        get(&app(f.context()), &format!("/api/address/{}", f.miner.encode())).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(json["code"], Value::from(RpcErrorCode::IndexDisabled.code()));
}

// --------------------------------------------------------------------- search

#[tokio::test]
async fn search_resolves_a_height_a_hash_a_txid_and_an_address() {
    let f = Fixture::build(2, true);
    let a = app(f.context());

    let (_, by_height) = get(&a, "/api/search?q=1").await;
    assert_eq!(by_height["kind"], "block");
    assert_eq!(by_height["id"], "1");

    let (_, by_hash) = get(&a, &format!("/api/search?q={}", f.blocks[0].to_hex())).await;
    assert_eq!(by_hash["kind"], "block");

    let (_, by_txid) =
        get(&a, &format!("/api/search?q={}", f.spend_txid.unwrap().to_hex())).await;
    assert_eq!(by_txid["kind"], "tx");

    let (_, by_address) = get(&a, &format!("/api/search?q={}", f.miner.encode())).await;
    assert_eq!(by_address["kind"], "address");
    assert_eq!(by_address["id"], f.miner.encode());
}

#[tokio::test]
async fn a_search_miss_is_a_success_with_nulls() {
    let f = Fixture::build(1, false);
    // The page renders its own "no match" panel and treats a non-2xx as a
    // server failure, so a miss must not be a 404.
    let (status, json) = get(&app(f.context()), "/api/search?q=nothing+here").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["kind"], Value::Null);
    assert_eq!(json["id"], Value::Null);
}

#[tokio::test]
async fn an_empty_search_is_a_miss_rather_than_an_error() {
    let f = Fixture::build(1, false);
    let (status, json) = get(&app(f.context()), "/api/search?q=").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["kind"], Value::Null);
}

// ----------------------------------------------------------------------- cors

#[tokio::test]
async fn read_routes_carry_cors_headers_for_the_browser() {
    let f = Fixture::build(1, false);
    let request = Request::builder()
        .uri("/api/stats")
        .header(header::ORIGIN, "https://example.invalid")
        .body(Body::empty())
        .unwrap();
    let peer: SocketAddr = PEER.parse().unwrap();
    let mut request = request;
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = app(f.context()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        "the explorer is a public read-only API and browsers are the client"
    );
}
