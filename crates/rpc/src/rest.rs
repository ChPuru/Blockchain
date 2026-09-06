//! The `axum` router the explorer talks to (CONTRACT §11).
//!
//! Routes, exactly as `explorer/index.html` calls them:
//!
//! | Method | Path | Handler |
//! |---|---|---|
//! | `GET` | `/` | the static explorer page |
//! | `GET` | `/api/stats` | [`crate::handlers::explorer::stats`] |
//! | `GET` | `/api/block/{height_or_hash}` | [`crate::handlers::explorer::block_view`] |
//! | `GET` | `/api/tx/{txid}` | [`crate::handlers::explorer::tx_view`] |
//! | `GET` | `/api/address/{address}` | [`crate::handlers::explorer::address_view`] |
//! | `GET` | `/api/search?q=` | [`crate::handlers::explorer::search`] |
//! | `POST` | `/api/faucet` | [`crate::faucet`] |
//!
//! Note the path syntax: `axum` 0.8 captures with `{name}`, not the `:name` of
//! 0.7. EIP-3091 writes the shape as `/api/block/:height_or_hash`; the route
//! that implements it is spelled `{height_or_hash}`.
//!
//! # Two layers that are not optional
//!
//! [`MAX_REQUEST_BODY`] caps every request body. Without it, `Json<T>`
//! buffers whatever a client sends before it can be rejected, and a single
//! unauthenticated POST can exhaust the node's memory.
//!
//! CORS is permissive on the read paths because the explorer is a public,
//! read-only API and browsers are the intended clients. It is scoped to the
//! methods and headers the page actually uses rather than mirroring arbitrary
//! request headers back.
//!
//! # Where the client address comes from
//!
//! The faucet's per-IP window keys on the peer address `axum` reports, unless a
//! trusted proxy header is configured. `X-Forwarded-For` is **not** trusted by
//! default: anyone can send it, and trusting it by default turns the per-IP
//! limit into no limit at all. `RestConfig::trust_forwarded_for` exists for the
//! deployment described in `RUNNING.md`, where nginx terminates TLS and sets
//! the header itself.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

use crate::context::{NodeContext, blocking};
use crate::error::{RpcError, RpcErrorCode};
use crate::handlers::{convert, explorer};
use crate::types::explorer::{
    AddressResponse, BlockResponse, FaucetRequest, FaucetResponse, SearchResponse, StatsResponse,
    TxResponse,
};

/// The largest request body the REST surface will read: 64 KiB.
///
/// The only body any route accepts is `{"address": "..."}`, which is under a
/// hundred bytes. The cap is three orders of magnitude above that and still far
/// below anything that could hurt.
pub const MAX_REQUEST_BODY: usize = 64 * 1024;

/// The header a trusted reverse proxy sets.
pub const FORWARDED_FOR: &str = "x-forwarded-for";

/// The explorer page, compiled in.
///
/// Serving the page from the binary means `chaind --explorer-listen` works from
/// any working directory and a devnet script cannot start a node that answers
/// `/api/stats` but 404s on `/`. [`RestConfig::static_index`] overrides it with
/// a file on disk for anyone iterating on the page.
const EMBEDDED_EXPLORER: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../explorer/index.html"));

/// How the REST surface is configured.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RestConfig {
    /// Serve this file at `/` instead of the compiled-in explorer.
    pub static_index: Option<PathBuf>,
    /// Honour `X-Forwarded-For` when keying the faucet's per-IP limit.
    ///
    /// Only turn this on behind a proxy that sets the header itself. See the
    /// module docs.
    pub trust_forwarded_for: bool,
}

/// What the REST handlers share.
#[derive(Clone, Debug)]
pub struct RestState {
    ctx: NodeContext,
    config: Arc<RestConfig>,
    index_html: Arc<String>,
}

impl RestState {
    /// Build the shared state, reading the static page once at startup.
    ///
    /// Reading it here rather than per request means a missing or unreadable
    /// file is a startup warning instead of a 500 for every visitor, and the
    /// page cannot change under a reader mid-session.
    #[must_use]
    pub fn new(ctx: NodeContext, config: RestConfig) -> Self {
        let index_html = match &config.static_index {
            Some(path) => match std::fs::read_to_string(path) {
                Ok(body) => body,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "could not read the configured explorer page; serving the compiled-in one"
                    );
                    EMBEDDED_EXPLORER.to_owned()
                }
            },
            None => EMBEDDED_EXPLORER.to_owned(),
        };
        RestState { ctx, config: Arc::new(config), index_html: Arc::new(index_html) }
    }

    /// The node context behind this surface.
    #[must_use]
    pub fn context(&self) -> &NodeContext {
        &self.ctx
    }
}

/// The explorer's router.
///
/// Mount it with `axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())`
/// so that [`ConnectInfo`] is populated and the faucet can see a peer address.
pub fn router(state: RestState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([header::CONTENT_TYPE, header::ACCEPT]);

    Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/api/stats", get(stats))
        .route("/api/block/{height_or_hash}", get(block))
        .route("/api/tx/{txid}", get(transaction))
        .route("/api/address/{address}", get(address))
        .route("/api/search", get(search))
        .route("/api/faucet", post(faucet))
        .fallback(not_found)
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY))
        .with_state(state)
}

/// `GET /` — the explorer page.
async fn index(State(state): State<RestState>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        state.index_html.as_str().to_owned(),
    )
        .into_response()
}

/// `GET /api/stats`.
async fn stats(State(state): State<RestState>) -> Result<Json<StatsResponse>, RpcError> {
    // The peer count is the only figure that comes from the async
    // peer-to-peer service; everything else is one blocking pass over the
    // store.
    let peers = state.ctx.network().peers().await.len();
    let faucet_enabled = state.ctx.faucet_enabled();
    let (chain, mempool) = state.ctx.handles();
    let body =
        blocking(move || explorer::stats(&*chain, &*mempool, peers, faucet_enabled)).await?;
    Ok(Json(body))
}

/// `GET /api/block/{height_or_hash}`.
async fn block(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> Result<Json<BlockResponse>, RpcError> {
    let chain = Arc::clone(state.ctx.chain());
    Ok(Json(blocking(move || explorer::block_view(&*chain, &id)).await?))
}

/// `GET /api/tx/{txid}`.
async fn transaction(
    State(state): State<RestState>,
    Path(txid): Path<String>,
) -> Result<Json<TxResponse>, RpcError> {
    let (chain, mempool) = state.ctx.handles();
    Ok(Json(blocking(move || explorer::tx_view(&*chain, &*mempool, &txid)).await?))
}

/// `GET /api/address/{address}`.
async fn address(
    State(state): State<RestState>,
    Path(address): Path<String>,
) -> Result<Json<AddressResponse>, RpcError> {
    let (chain, mempool) = state.ctx.handles();
    Ok(Json(blocking(move || explorer::address_view(&*chain, &*mempool, &address)).await?))
}

/// The `?q=` of `/api/search`.
#[derive(Clone, Debug, Deserialize)]
struct SearchQuery {
    /// What the reader typed.
    #[serde(default)]
    q: String,
}

/// `GET /api/search?q=`.
async fn search(
    State(state): State<RestState>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<SearchResponse>, RpcError> {
    let chain = Arc::clone(state.ctx.chain());
    Ok(Json(blocking(move || explorer::search(&*chain, &query.q)).await?))
}

/// `POST /api/faucet`.
///
/// The whole flow: decode the address, check both rate-limit windows, build and
/// sign the payment, hand it to the mempool, and announce it. A refusal at any
/// step is a JSON body with a stable code, which is what the page renders as
/// "Faucet declined: …".
async fn faucet(
    State(state): State<RestState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<FaucetRequest>,
) -> Result<Json<FaucetResponse>, RpcError> {
    let Some(faucet) = state.ctx.faucet().cloned() else {
        return Err(RpcError::new(
            RpcErrorCode::FaucetDisabled,
            "this node does not run a faucet",
        ));
    };
    let client = client_key(&state.config, &headers, peer);
    let network = state.ctx.chain().params().network;
    let amount = faucet.config().amount;
    let (chain, mempool) = state.ctx.handles();
    let requested = request.address.clone();

    let (txid, transaction, address) = blocking(move || {
        let address = convert::parse_address(&requested, network)?;
        let transaction = faucet.dispense(&address, &client)?;
        // The chain handle is not used to build the payment — the source owns
        // that — but a faucet on a node with no tip has nothing to spend, and
        // saying so here beats a confusing selection error.
        chain.tip()?;
        let txid = mempool.submit(transaction.clone())?;
        Ok((txid, transaction, address.encode()))
    })
    .await?;

    if let Err(e) = state.ctx.network().broadcast_tx(transaction).await {
        tracing::warn!(txid = %txid, error = %e, "faucet payment accepted locally but not announced");
    }
    tracing::info!(txid = %txid, address = %address, "faucet payment sent");

    Ok(Json(FaucetResponse { txid: txid.to_hex(), amount: amount.into(), address }))
}

/// The key the faucet's per-IP window counts against.
///
/// The peer address, unless a trusted proxy is configured — see the module
/// docs for why `X-Forwarded-For` is off by default.
fn client_key(config: &RestConfig, headers: &HeaderMap, peer: SocketAddr) -> String {
    if config.trust_forwarded_for
        && let Some(value) = headers.get(FORWARDED_FOR)
        && let Ok(text) = value.to_str()
        && let Some(first) = text.split(',').next()
    {
        let trimmed = first.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    // The port changes per connection; the address is what identifies a client.
    peer.ip().to_string()
}

/// Anything else.
async fn not_found() -> RpcError {
    RpcError::not_found("no such route")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn the_embedded_explorer_is_the_real_page() {
        assert!(EMBEDDED_EXPLORER.contains("Ferrum Explorer"));
        assert!(EMBEDDED_EXPLORER.contains("/api/stats"), "the page must call the API we serve");
        assert!(EMBEDDED_EXPLORER.contains("/api/faucet"));
    }

    #[test]
    fn forwarded_for_is_ignored_unless_it_is_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_FOR, HeaderValue::from_static("1.2.3.4"));
        let peer: SocketAddr = "10.0.0.7:51234".parse().unwrap();

        let untrusted = RestConfig::default();
        assert_eq!(client_key(&untrusted, &headers, peer), "10.0.0.7");

        let trusted = RestConfig { trust_forwarded_for: true, ..RestConfig::default() };
        assert_eq!(client_key(&trusted, &headers, peer), "1.2.3.4");
    }

    #[test]
    fn a_forwarded_chain_uses_the_original_client() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_FOR, HeaderValue::from_static("1.2.3.4, 10.0.0.1, 10.0.0.2"));
        let peer: SocketAddr = "10.0.0.7:51234".parse().unwrap();
        let trusted = RestConfig { trust_forwarded_for: true, ..RestConfig::default() };
        assert_eq!(client_key(&trusted, &headers, peer), "1.2.3.4");
    }

    #[test]
    fn an_empty_forwarded_header_falls_back_to_the_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_FOR, HeaderValue::from_static("   "));
        let peer: SocketAddr = "10.0.0.7:51234".parse().unwrap();
        let trusted = RestConfig { trust_forwarded_for: true, ..RestConfig::default() };
        assert_eq!(client_key(&trusted, &headers, peer), "10.0.0.7");
    }

    #[test]
    fn the_body_limit_is_small_and_explicit() {
        assert_eq!(MAX_REQUEST_BODY, 65_536);
    }
}
