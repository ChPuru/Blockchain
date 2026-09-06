//! Binding, serving and shutting down both surfaces.
//!
//! Two listeners, because they are two different things with two different
//! threat models:
//!
//! - the **JSON-RPC** listener (`--rpc-listen`, default `127.0.0.1:8645`)
//!   speaks JSON-RPC 2.0 over HTTP *and* WebSocket on the same port, and
//!   carries `submitblock` and `sendrawtransaction`. `RUNNING.md` says to bind
//!   it to localhost unless you mean it, and the default here agrees.
//! - the **explorer** listener (`--explorer-listen`, default `127.0.0.1:8665`)
//!   serves the static page and the read-only REST API, plus the faucet. It is
//!   the one meant to face a reverse proxy.
//!
//! Both return a handle that shuts the listener down. The node holds them for
//! the life of the process and drops them on `SIGINT`, which is what makes a
//! clean shutdown possible before the store is flushed.

use std::net::SocketAddr;

use jsonrpsee::server::{ServerBuilder, ServerHandle};

use crate::api::FerrumRpcServer;
use crate::context::NodeContext;
use crate::error::{RpcError, RpcErrorCode};
use crate::handlers::FerrumRpcImpl;
use crate::rest::{RestConfig, RestState, router};

/// Default JSON-RPC bind address (CONTRACT §13.1).
pub const DEFAULT_RPC_LISTEN: &str = "127.0.0.1:8645";

/// Default explorer bind address (CONTRACT §13.1).
pub const DEFAULT_EXPLORER_LISTEN: &str = "127.0.0.1:8665";

/// Largest JSON-RPC request body: 2 MiB.
///
/// `submitblock` carries a whole block as hex, so the limit has to clear twice
/// `max_block_size` plus JSON framing. Twice a megabyte plus headroom is that,
/// and it is still a bound.
pub const DEFAULT_MAX_RPC_REQUEST_BODY: u32 = 2 * 1024 * 1024 + 64 * 1024;

/// Largest JSON-RPC response body: 8 MiB.
///
/// `getblock` at verbosity 2 expands a one-megabyte block into JSON several
/// times its size.
pub const DEFAULT_MAX_RPC_RESPONSE_BODY: u32 = 8 * 1024 * 1024;

/// Default concurrent connection ceiling.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 100;

/// How the JSON-RPC listener is configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcServerConfig {
    /// Where to bind.
    pub listen: SocketAddr,
    /// Largest request body accepted.
    pub max_request_body: u32,
    /// Largest response body produced.
    pub max_response_body: u32,
    /// Concurrent connection ceiling.
    pub max_connections: u32,
    /// Whether to accept WebSocket upgrades as well as plain HTTP.
    pub websocket: bool,
}

impl Default for RpcServerConfig {
    fn default() -> Self {
        RpcServerConfig {
            listen: default_socket_addr(DEFAULT_RPC_LISTEN, 8645),
            max_request_body: DEFAULT_MAX_RPC_REQUEST_BODY,
            max_response_body: DEFAULT_MAX_RPC_RESPONSE_BODY,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            websocket: true,
        }
    }
}

impl RpcServerConfig {
    /// A configuration bound to `listen`.
    #[must_use]
    pub fn at(listen: SocketAddr) -> Self {
        RpcServerConfig { listen, ..Self::default() }
    }
}

/// How the explorer listener is configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplorerServerConfig {
    /// Where to bind.
    pub listen: SocketAddr,
    /// REST behaviour: static page override and proxy trust.
    pub rest: RestConfig,
}

impl Default for ExplorerServerConfig {
    fn default() -> Self {
        ExplorerServerConfig {
            listen: default_socket_addr(DEFAULT_EXPLORER_LISTEN, 8665),
            rest: RestConfig::default(),
        }
    }
}

impl ExplorerServerConfig {
    /// A configuration bound to `listen`.
    #[must_use]
    pub fn at(listen: SocketAddr) -> Self {
        ExplorerServerConfig { listen, ..Self::default() }
    }
}

/// Parse a compile-time default, falling back to loopback on the given port.
///
/// The two constants are literals this crate controls, so the parse cannot
/// fail; the fallback exists so that a typo in a future edit degrades to a
/// working loopback bind instead of a panic at startup.
fn default_socket_addr(text: &str, port: u16) -> SocketAddr {
    text.parse().unwrap_or_else(|_| SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)))
}

/// A running JSON-RPC listener.
///
/// Dropping this stops the server, which is why the node keeps it alive for the
/// whole process.
#[derive(Debug)]
pub struct RpcServerHandle {
    addr: SocketAddr,
    handle: ServerHandle,
}

impl RpcServerHandle {
    /// The address actually bound. Differs from the configured one when the
    /// port was `0`, which is how the tests get an ephemeral port.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The `http://` URL a client should use.
    #[must_use]
    pub fn http_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The `ws://` URL a client should use.
    #[must_use]
    pub fn ws_url(&self) -> String {
        format!("ws://{}", self.addr)
    }

    /// Ask the server to stop. Idempotent.
    pub fn stop(&self) {
        if let Err(e) = self.handle.stop() {
            tracing::debug!(error = %e, "rpc server was already stopping");
        }
    }

    /// Wait for the server to finish shutting down.
    pub async fn stopped(self) {
        self.handle.stopped().await;
    }
}

/// Bind and start the JSON-RPC server.
///
/// # Errors
/// [`RpcErrorCode::InternalError`] when the address cannot be bound.
pub async fn spawn_rpc_server(
    config: RpcServerConfig,
    ctx: NodeContext,
) -> Result<RpcServerHandle, RpcError> {
    let builder = ServerBuilder::new()
        .max_request_body_size(config.max_request_body)
        .max_response_body_size(config.max_response_body)
        .max_connections(config.max_connections);
    // `http_only` is a hard refusal of the upgrade, not merely "we prefer
    // HTTP": a node that advertises no WebSocket should not half-accept one.
    let builder = if config.websocket { builder } else { builder.http_only() };

    let server = builder.build(config.listen).await.map_err(|e| {
        RpcError::new(
            RpcErrorCode::InternalError,
            format!("could not bind the JSON-RPC listener to {}: {e}", config.listen),
        )
    })?;
    let addr = server.local_addr().map_err(|e| {
        RpcError::new(RpcErrorCode::InternalError, format!("bound socket has no address: {e}"))
    })?;

    let module = FerrumRpcImpl::new(ctx).into_rpc();
    let handle = server.start(module);
    tracing::info!(%addr, websocket = config.websocket, "json-rpc listening");
    Ok(RpcServerHandle { addr, handle })
}

/// A running explorer listener.
#[derive(Debug)]
pub struct ExplorerServerHandle {
    addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl ExplorerServerHandle {
    /// The address actually bound.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The base URL the explorer is served from.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Ask the server to stop serving. Idempotent.
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }

    /// Stop the server and wait for the last in-flight request to finish.
    pub async fn stopped(mut self) {
        self.stop();
        if let Err(e) = self.task.await {
            tracing::debug!(error = %e, "explorer task ended abnormally");
        }
    }
}

/// Bind and start the explorer's REST and static surface.
///
/// The router is mounted with connection info so the faucet can key its per-IP
/// window on a real peer address; without it, every request would share one
/// bucket.
///
/// # Errors
/// [`RpcErrorCode::InternalError`] when the address cannot be bound.
pub async fn spawn_explorer_server(
    config: ExplorerServerConfig,
    ctx: NodeContext,
) -> Result<ExplorerServerHandle, RpcError> {
    let listener = tokio::net::TcpListener::bind(config.listen).await.map_err(|e| {
        RpcError::new(
            RpcErrorCode::InternalError,
            format!("could not bind the explorer listener to {}: {e}", config.listen),
        )
    })?;
    let addr = listener.local_addr().map_err(|e| {
        RpcError::new(RpcErrorCode::InternalError, format!("bound socket has no address: {e}"))
    })?;

    let app = router(RestState::new(ctx, config.rest));
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let served = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async move {
                // A dropped sender is a shutdown too: it means the handle went
                // away, and a listener nobody can stop is a leak.
                let _ = rx.await;
            })
            .await;
        if let Err(e) = served {
            tracing::error!(error = %e, "explorer listener stopped with an error");
        }
    });

    tracing::info!(%addr, "explorer listening");
    Ok(ExplorerServerHandle { addr, shutdown: Some(tx), task })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_default_ports_match_the_contract() {
        assert_eq!(RpcServerConfig::default().listen.port(), 8645);
        assert_eq!(ExplorerServerConfig::default().listen.port(), 8665);
        assert!(RpcServerConfig::default().listen.ip().is_loopback());
    }

    #[test]
    fn the_rpc_body_limit_clears_a_hex_encoded_block() {
        // A 1 000 000-byte block is 2 000 000 hex characters plus framing.
        assert!(u64::from(DEFAULT_MAX_RPC_REQUEST_BODY) > 2_000_000);
    }

    #[test]
    fn a_malformed_default_address_degrades_to_loopback() {
        let addr = default_socket_addr("not an address", 9999);
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 9999);
    }
}
