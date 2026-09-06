//! JSON-RPC and REST interfaces for Ferrum, plus the explorer index API
//! (CONTRACT §11).
//!
//! Two surfaces over one node:
//!
//! - **JSON-RPC 2.0** over HTTP and WebSocket on the same port, via
//!   `jsonrpsee` — every method in CONTRACT §11, declared once in [`api`] and
//!   implemented once in [`handlers`].
//! - **REST**, via `axum`, in the shape `explorer/index.html` already calls:
//!   `/api/stats`, `/api/block/:height_or_hash`, `/api/tx/:txid`,
//!   `/api/address/:address`, `/api/search?q=`, `POST /api/faucet`, and the
//!   static page at `/`.
//!
//! # Five things worth knowing before reading further
//!
//! 1. **Amounts are never JSON numbers.** An `Amount` is a `u64` of grains and
//!    a JSON number is a double, exact only to `2^53` — a quarter of the `u64`
//!    range — so a JavaScript client rounds anything above it silently. Every
//!    amount is an integer count of grains carried as a decimal **string**
//!    ([`types::Grains`]); there is a matching comment in
//!    `explorer/index.html` and the two must stay consistent.
//! 2. **The DTOs are not the consensus types.** [`types`] is a deliberate
//!    interface, not a `derive` on `ferrum-types`. A serde attribute on a
//!    consensus struct makes every internal rename a breaking change for every
//!    client.
//! 3. **Every storage call from an `async fn` goes through
//!    `spawn_blocking`.** [`context::blocking`] is the only bridge, and the
//!    synchronous work underneath is plain functions over
//!    [`provider::ChainProvider`]. One hop per request, not one per read.
//! 4. **The node is reached through three traits**, not through a `Store`:
//!    [`provider::ChainProvider`], [`provider::MempoolProvider`] and
//!    [`provider::NetworkProvider`]. That is what makes every handler testable
//!    against an in-memory chain, and it is why this crate does not depend on
//!    `ferrum-mempool` or `ferrum-p2p`.
//! 5. **Every error has a stable number.** The table is [`error::RpcErrorCode`]
//!    and a test pins each value. The REST surface reports the same number
//!    alongside an HTTP status.
//!
//! # Layout
//!
//! | Module | What it owns |
//! |---|---|
//! | [`api`] | the `#[rpc]` trait: the JSON-RPC surface, declared once |
//! | [`handlers`] | the implementation, and the synchronous functions under it |
//! | [`rest`] | the `axum` router the explorer talks to |
//! | [`faucet`] | rate limiting and the payment source |
//! | [`types`] | serde DTOs for both surfaces |
//! | [`error`] | the stable numeric error table |
//! | [`provider`] | the traits the node implements |
//! | [`adapters`] | the production `ChainProvider` over a `ChainManager` |
//! | [`context`] | what a handler is handed, and `spawn_blocking` |
//! | [`server`] | binding, serving and shutting down |
//!
//! # Wiring a node
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use ferrum_rpc::adapters::ChainHandle;
//! use ferrum_rpc::context::NodeContext;
//! use ferrum_rpc::server::{ExplorerServerConfig, RpcServerConfig, spawn_explorer_server,
//!                          spawn_rpc_server};
//!
//! # async fn wire(chain: Arc<ferrum_chain::ChainManager>) -> Result<(), ferrum_rpc::RpcError> {
//! let ctx = NodeContext::new(Arc::new(ChainHandle::new(chain, true)));
//! let rpc = spawn_rpc_server(RpcServerConfig::default(), ctx.clone()).await?;
//! let explorer = spawn_explorer_server(ExplorerServerConfig::default(), ctx).await?;
//! println!("rpc on {}, explorer on {}", rpc.http_url(), explorer.url());
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

pub mod adapters;
pub mod api;
pub mod context;
pub mod error;
pub mod faucet;
pub mod handlers;
pub mod provider;
pub mod rest;
pub mod server;
pub mod types;

#[cfg(test)]
mod tests;

pub use crate::adapters::ChainHandle;
pub use crate::api::{FerrumRpcClient, FerrumRpcServer};
pub use crate::context::{Clock, NodeContext, SystemClock, blocking, now_ms};
pub use crate::error::{
    FERRUM_CODE_BASE, RestErrorBody, RpcError, RpcErrorCode, parse_hash32, parse_hex,
};
pub use crate::faucet::{
    DEFAULT_ADDRESS_WINDOW_MS, DEFAULT_FAUCET_AMOUNT, DEFAULT_FAUCET_FEE_RATE,
    DEFAULT_IP_ALLOWANCE, DEFAULT_IP_WINDOW_MS, DEFAULT_MAX_TRACKED, Faucet, FaucetConfig,
    FaucetSource, WalletFaucetSource,
};
pub use crate::handlers::{FerrumRpcImpl, rpc_module};
pub use crate::provider::{
    ChainProvider, MempoolProvider, MempoolTx, NetworkProvider, NetworkSummary, NoMempool,
    NoNetwork, PeerSummary, SubmitOutcome,
};
pub use crate::rest::{MAX_REQUEST_BODY, RestConfig, RestState, router};
pub use crate::server::{
    DEFAULT_EXPLORER_LISTEN, DEFAULT_RPC_LISTEN, ExplorerServerConfig, ExplorerServerHandle,
    RpcServerConfig, RpcServerHandle, spawn_explorer_server, spawn_rpc_server,
};
pub use crate::types::{Grains, SignedGrains, U64String};
