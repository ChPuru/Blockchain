//! The faucet over the REST surface.
//!
//! The rate limiter itself is unit-tested in [`crate::faucet`]; these tests are
//! about the route: the shape of the success body the page reads, the status
//! codes a refusal carries, and the fact that a malformed or oversized request
//! is a rejection rather than a 500.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt;

use crate::context::{Clock, NodeContext};
use crate::error::RpcErrorCode;
use crate::faucet::{Faucet, FaucetConfig, FaucetSource};
use crate::provider::MempoolProvider;
use crate::rest::{RestConfig, RestState, router};
use crate::tests::fixture::{Fixture, address};

/// The peer address every test request appears to come from.
const PEER: &str = "10.1.2.3:44444";

fn app(ctx: NodeContext) -> Router {
    router(RestState::new(ctx, RestConfig::default()))
}

/// Send a request through the router with connection info attached.
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
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn post_json(app: &Router, path: &str, body: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
    let (status, raw) = send(app, request).await;
    (status, serde_json::from_slice(&raw).unwrap_or(Value::Null))
}

/// A faucet source that hands back a fixed transaction.
#[derive(Debug)]
struct AlwaysPays;

impl FaucetSource for AlwaysPays {
    fn build_payment(
        &self,
        _to: &ferrum_crypto::Address,
        _amount: ferrum_types::Amount,
    ) -> Result<ferrum_types::Transaction, crate::error::RpcError> {
        Ok(ferrum_types::Transaction::empty())
    }
}

/// A faucet source with nothing to send.
#[derive(Debug)]
struct AlwaysEmpty;

impl FaucetSource for AlwaysEmpty {
    fn build_payment(
        &self,
        _to: &ferrum_crypto::Address,
        _amount: ferrum_types::Amount,
    ) -> Result<ferrum_types::Transaction, crate::error::RpcError> {
        Err(crate::error::RpcError::new(RpcErrorCode::FaucetDrained, "the wallet is empty"))
    }
}

/// A clock that never moves, so a window never expires mid-test.
#[derive(Debug)]
struct FrozenClock;

impl Clock for FrozenClock {
    fn now_ms(&self) -> u64 {
        1_700_000_000_000
    }
}

fn faucet_app(f: &Fixture, source: Arc<dyn FaucetSource>) -> Router {
    let faucet = Faucet::with_clock(
        FaucetConfig::default().with_ip_limit(60_000, 2),
        source,
        Arc::new(FrozenClock),
    );
    app(f.context().with_faucet(Arc::new(faucet)))
}

#[tokio::test]
async fn the_faucet_pays_and_returns_a_txid() {
    let f = Fixture::build(1, false);
    let a = faucet_app(&f, Arc::new(AlwaysPays));
    let body = format!(r#"{{"address":"{}"}}"#, f.recipient.encode());
    let (status, json) = post_json(&a, "/api/faucet", &body).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert!(json["txid"].is_string(), "the page links to j.txid");
    assert_eq!(json["amount"], "100000000");
    assert_eq!(json["address"], f.recipient.encode());
    assert_eq!(f.mempool.len(), 1, "the payment reaches the mempool");
    assert_eq!(f.network.broadcast_count(), 1, "and is announced");
}

#[tokio::test]
async fn a_payment_the_mempool_refuses_leaves_the_quota_unspent() {
    let f = Fixture::build(1, false);
    let a = faucet_app(&f, Arc::new(AlwaysPays));
    let body = format!(r#"{{"address":"{}"}}"#, f.recipient.encode());

    // The pool refuses the first payment — a conflicting spend, in practice.
    f.mempool.reject_with("conflicting transaction");
    let (status, json) = post_json(&a, "/api/faucet", &body).await;
    assert!(status.is_client_error() || status.is_server_error(), "{json}");
    assert_eq!(f.mempool.len(), 0, "nothing was accepted");

    // The quota must still be there: the payment was never made.
    let (retry_status, retry) = post_json(&a, "/api/faucet", &body).await;
    assert_ne!(
        retry["code"],
        Value::from(RpcErrorCode::FaucetRateLimited.code()),
        "a refused payment spent the address's 24-hour window: {retry}"
    );
    assert_ne!(retry_status, StatusCode::TOO_MANY_REQUESTS, "{retry}");
}

#[tokio::test]
async fn stats_advertises_the_faucet_only_when_one_is_configured() {
    let f = Fixture::build(1, false);
    let (_, without) = get(&app(f.context()), "/api/stats").await;
    assert_eq!(without["faucet_enabled"], false);

    let a = faucet_app(&f, Arc::new(AlwaysPays));
    let (_, with) = get(&a, "/api/stats").await;
    assert_eq!(with["faucet_enabled"], true);
}

#[tokio::test]
async fn the_faucet_refuses_a_second_request_from_the_same_address() {
    let f = Fixture::build(1, false);
    let a = faucet_app(&f, Arc::new(AlwaysPays));
    let body = format!(r#"{{"address":"{}"}}"#, f.recipient.encode());
    assert_eq!(post_json(&a, "/api/faucet", &body).await.0, StatusCode::OK);
    let (status, json) = post_json(&a, "/api/faucet", &body).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json["code"], Value::from(RpcErrorCode::FaucetRateLimited.code()));
    assert!(json["error"].as_str().unwrap().contains("try again"));
}

#[tokio::test]
async fn the_faucet_caps_one_client_across_addresses() {
    let f = Fixture::build(1, false);
    let a = faucet_app(&f, Arc::new(AlwaysPays));
    for i in 0..2u8 {
        let body = format!(r#"{{"address":"{}"}}"#, address(50 + i).encode());
        assert_eq!(post_json(&a, "/api/faucet", &body).await.0, StatusCode::OK, "grant {i}");
    }
    let body = format!(r#"{{"address":"{}"}}"#, address(60).encode());
    let (status, json) = post_json(&a, "/api/faucet", &body).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(json["error"].as_str().unwrap().contains("client"));
}

#[tokio::test]
async fn an_empty_faucet_declines_politely() {
    let f = Fixture::build(1, false);
    let a = faucet_app(&f, Arc::new(AlwaysEmpty));
    let body = format!(r#"{{"address":"{}"}}"#, f.recipient.encode());
    let (status, json) = post_json(&a, "/api/faucet", &body).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["code"], Value::from(RpcErrorCode::FaucetDrained.code()));
    assert_eq!(f.mempool.len(), 0, "nothing was sent");
}

#[tokio::test]
async fn a_node_with_no_faucet_says_so_rather_than_500ing() {
    let f = Fixture::build(1, false);
    let body = format!(r#"{{"address":"{}"}}"#, f.recipient.encode());
    let (status, json) = post_json(&app(f.context()), "/api/faucet", &body).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["code"], Value::from(RpcErrorCode::FaucetDisabled.code()));
}

#[tokio::test]
async fn the_faucet_refuses_a_malformed_address() {
    let f = Fixture::build(1, false);
    let a = faucet_app(&f, Arc::new(AlwaysPays));
    let (status, json) = post_json(&a, "/api/faucet", r#"{"address":"not-an-address"}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], Value::from(RpcErrorCode::InvalidAddress.code()));
}

#[tokio::test]
async fn a_malformed_faucet_body_is_a_rejection_not_a_500() {
    let f = Fixture::build(1, false);
    let a = faucet_app(&f, Arc::new(AlwaysPays));
    let (status, _) = post_json(&a, "/api/faucet", "{ this is not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_faucet_body_missing_the_address_is_rejected() {
    let f = Fixture::build(1, false);
    let a = faucet_app(&f, Arc::new(AlwaysPays));
    let (status, _) = post_json(&a, "/api/faucet", r#"{"addr":"oops"}"#).await;
    assert!(status.is_client_error(), "status was {status}");
}

#[tokio::test]
async fn an_oversized_body_is_refused_by_the_limit_layer() {
    let f = Fixture::build(1, false);
    let a = faucet_app(&f, Arc::new(AlwaysPays));
    let huge = format!(r#"{{"address":"{}"}}"#, "a".repeat(crate::rest::MAX_REQUEST_BODY));
    let (status, _) = post_json(&a, "/api/faucet", &huge).await;
    assert!(status.is_client_error(), "an unbounded body must not be read; got {status}");
}

// ------------------------------------------------ the real wallet-backed source

/// A wallet restored from a fixed mnemonic, so the test is deterministic.
///
/// `MIN_PBKDF2_ITERATIONS` rather than the production work factor: this test is
/// about the faucet, and a 600 000-round KDF would make it the slowest thing in
/// the suite while proving nothing extra.
fn test_wallet(dir: &std::path::Path) -> ferrum_wallet::Wallet {
    let phrase = "abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon about";
    let mnemonic = ferrum_crypto::Mnemonic::from_phrase(phrase).unwrap();
    ferrum_wallet::Wallet::restore_with_params(
        &dir.join("faucet.json"),
        ferrum_types::Network::Devnet,
        &mnemonic,
        "a passphrase",
        ferrum_wallet::KeystoreParams { iterations: ferrum_wallet::MIN_PBKDF2_ITERATIONS },
    )
    .unwrap()
}

#[test]
fn a_wallet_backed_faucet_with_no_coins_reports_drained() {
    use crate::faucet::WalletFaucetSource;

    let f = Fixture::build(1, false);
    let dir = tempfile::tempdir().unwrap();
    let wallet = Arc::new(parking_lot::Mutex::new(test_wallet(dir.path())));
    let source = WalletFaucetSource::new(wallet, f.provider(), 1_000);

    let err = source.build_payment(&f.recipient, ferrum_types::Amount::from_grains(1)).unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::FaucetDrained);
    assert!(err.detail().contains("no coins"), "{}", err.detail());
}

/// Fund `address` with a **non-coinbase** output and return the chain.
///
/// A coinbase would not do: `ferrum-wallet` applies the network's own
/// hundred-block maturity window, not the fixture's shortened one, so a wallet
/// funded by mining would see nothing spendable for a hundred blocks. Paying it
/// from a mature coinbase is both faster and closer to how a real faucet is
/// topped up.
fn funded(f: &Fixture, address: &ferrum_crypto::Address, amount: ferrum_types::Amount) {
    let first = f.block(&f.blocks[0]);
    let prevout = crate::tests::fixture::coinbase_output(&first, 1);
    let payment = crate::tests::fixture::spend_p2pkh(
        prevout,
        &f.miner_key,
        &address.script_pubkey(),
        amount,
        f.chain.params.chain_id,
    );
    f.chain.mine_and_connect(&f.miner.script_pubkey(), vec![payment], 4_242);
}

#[test]
fn a_funded_wallet_faucet_signs_a_spendable_payment() {
    use crate::faucet::WalletFaucetSource;

    let f = Fixture::build(3, false);
    let dir = tempfile::tempdir().unwrap();
    let mut wallet = test_wallet(dir.path());
    let faucet_address = wallet.new_address().unwrap();
    funded(&f, &faucet_address, ferrum_types::Amount::from_grains(10 * ferrum_types::COIN));

    let wallet = Arc::new(parking_lot::Mutex::new(wallet));
    let source = WalletFaucetSource::new(Arc::clone(&wallet), f.provider(), 1_000);
    let amount = ferrum_types::Amount::from_grains(ferrum_types::COIN);
    let payment = source.build_payment(&f.recipient, amount).unwrap();

    // The payment must be a real, verifiable transaction, not a skeleton.
    assert!(!payment.inputs.is_empty());
    assert!(payment.outputs.iter().any(|o| o.value == amount));
    let prevouts: Vec<ferrum_types::Coin> =
        payment.inputs.iter().map(|i| f.coin(&i.prev_out)).collect();
    wallet
        .lock()
        .verify_transaction(&payment, &prevouts, f.chain.params.chain_id)
        .expect("the faucet signs a transaction that verifies");
}

#[test]
fn a_wallet_faucet_refuses_an_address_from_another_network() {
    use crate::faucet::WalletFaucetSource;

    let f = Fixture::build(3, false);
    let dir = tempfile::tempdir().unwrap();
    let mut wallet = test_wallet(dir.path());
    let faucet_address = wallet.new_address().unwrap();
    funded(&f, &faucet_address, ferrum_types::Amount::from_grains(10 * ferrum_types::COIN));

    let (_, public) = crate::tests::fixture::key(77);
    let mainnet = ferrum_crypto::Address::p2pkh(ferrum_types::Network::Mainnet, &public);
    let source =
        WalletFaucetSource::new(Arc::new(parking_lot::Mutex::new(wallet)), f.provider(), 1_000);
    let err = source
        .build_payment(&mainnet, ferrum_types::Amount::from_grains(ferrum_types::COIN))
        .unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::InvalidAddress);
}

#[test]
fn a_faucet_over_a_real_wallet_still_rate_limits() {
    use crate::faucet::WalletFaucetSource;

    let f = Fixture::build(3, false);
    let dir = tempfile::tempdir().unwrap();
    let mut wallet = test_wallet(dir.path());
    let faucet_address = wallet.new_address().unwrap();
    funded(&f, &faucet_address, ferrum_types::Amount::from_grains(10 * ferrum_types::COIN));

    let source = Arc::new(WalletFaucetSource::new(
        Arc::new(parking_lot::Mutex::new(wallet)),
        f.provider(),
        1_000,
    ));
    let faucet = Faucet::with_clock(FaucetConfig::default(), source, Arc::new(FrozenClock));
    assert!(faucet.dispense(&f.recipient, "10.0.0.1", |_| Ok(())).is_ok());
    let err = faucet.dispense(&f.recipient, "10.0.0.1", |_| Ok(())).unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::FaucetRateLimited);
}
