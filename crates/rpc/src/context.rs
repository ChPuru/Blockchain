//! What every handler is handed, and the one bridge to blocking work.
//!
//! # `blocking` is not optional
//!
//! `ferrum-storage` is synchronous. [`blocking`] is the only place in this
//! crate where a storage call may be reached from an `async fn`, and every
//! handler routes through it. The cost of getting this wrong is invisible in
//! tests and expensive in production: a `redb` read on a Tokio worker parks
//! that worker for the duration of the I/O, and with a handful of workers and
//! a busy store that is a two-second p95 latency bug.
//!
//! The handler functions themselves — everything in [`crate::handlers`] — are
//! plain synchronous functions. Each `async` method wraps *one* call to
//! [`blocking`] around the whole computation rather than one per storage read,
//! so a request that touches thirty coins crosses the thread boundary once.

use std::sync::Arc;

use crate::error::RpcError;
use crate::faucet::Faucet;
use crate::provider::{ChainProvider, MempoolProvider, NetworkProvider, NoMempool, NoNetwork};

/// Everything a handler can reach.
///
/// Cheap to clone: it is four `Arc`s.
#[derive(Clone, Debug)]
pub struct NodeContext {
    chain: Arc<dyn ChainProvider>,
    mempool: Arc<dyn MempoolProvider>,
    network: Arc<dyn NetworkProvider>,
    faucet: Option<Arc<Faucet>>,
}

impl NodeContext {
    /// A context with no mempool, no network and no faucet.
    ///
    /// Useful on its own for an archive node, and the starting point for
    /// [`NodeContext::with_mempool`] and friends.
    #[must_use]
    pub fn new(chain: Arc<dyn ChainProvider>) -> Self {
        NodeContext {
            chain,
            mempool: Arc::new(NoMempool),
            network: Arc::new(NoNetwork),
            faucet: None,
        }
    }

    /// Attach a mempool.
    #[must_use]
    pub fn with_mempool(mut self, mempool: Arc<dyn MempoolProvider>) -> Self {
        self.mempool = mempool;
        self
    }

    /// Attach a peer-to-peer service.
    #[must_use]
    pub fn with_network(mut self, network: Arc<dyn NetworkProvider>) -> Self {
        self.network = network;
        self
    }

    /// Attach a faucet.
    #[must_use]
    pub fn with_faucet(mut self, faucet: Arc<Faucet>) -> Self {
        self.faucet = Some(faucet);
        self
    }

    /// The chain.
    #[must_use]
    pub fn chain(&self) -> &Arc<dyn ChainProvider> {
        &self.chain
    }

    /// The mempool. Always present; [`NoMempool`] when the node has none.
    #[must_use]
    pub fn mempool(&self) -> &Arc<dyn MempoolProvider> {
        &self.mempool
    }

    /// The peer-to-peer service. Always present; [`NoNetwork`] when the node
    /// has none.
    #[must_use]
    pub fn network(&self) -> &Arc<dyn NetworkProvider> {
        &self.network
    }

    /// The faucet, when one is configured.
    #[must_use]
    pub fn faucet(&self) -> Option<&Arc<Faucet>> {
        self.faucet.as_ref()
    }

    /// Whether this node runs a faucet, for `/api/stats`.
    #[must_use]
    pub fn faucet_enabled(&self) -> bool {
        self.faucet.is_some()
    }

    /// Clone the chain and mempool handles for a [`blocking`] closure.
    #[must_use]
    pub(crate) fn handles(&self) -> (Arc<dyn ChainProvider>, Arc<dyn MempoolProvider>) {
        (Arc::clone(&self.chain), Arc::clone(&self.mempool))
    }
}

/// Run synchronous, storage-touching work off the async runtime.
///
/// # Errors
///
/// Propagates the closure's error, and reports a panicked or cancelled task as
/// [`crate::error::RpcErrorCode::InternalError`] rather than poisoning the
/// server.
pub async fn blocking<T, F>(f: F) -> Result<T, RpcError>
where
    F: FnOnce() -> Result<T, RpcError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, "blocking rpc task failed");
            Err(RpcError::internal(format!("blocking task failed: {e}")))
        }
    }
}

/// A source of wall-clock time.
///
/// Injected rather than called directly so that the faucet's rate-limit window
/// can be tested without sleeping. The node uses [`SystemClock`].
pub trait Clock: Send + Sync + std::fmt::Debug + 'static {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

/// The real clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        now_ms()
    }
}

/// Milliseconds since the Unix epoch.
///
/// `clippy.toml` disallows `SystemTime::now` workspace-wide to keep a clock out
/// of the state-transition path, where `BlockCtx` supplies time instead. This
/// crate sits above that seam: `getblocktemplate` has to stamp a candidate
/// block and the faucet has to age its rate-limit window. The exception is
/// taken exactly once, here, in a named function, rather than scattered across
/// handlers where nobody would notice it drifting into a consensus decision.
///
/// A clock before the epoch is impossible on any supported platform and yields
/// `0` rather than a panic.
#[allow(clippy::disallowed_methods)]
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[tokio::test]
    async fn blocking_propagates_the_value() {
        let v = blocking(|| Ok::<_, RpcError>(41u32 + 1)).await.unwrap();
        assert_eq!(v, 42);
    }

    #[tokio::test]
    async fn blocking_propagates_the_error() {
        let e = blocking(|| Err::<(), _>(RpcError::not_found("nothing"))).await.unwrap_err();
        assert_eq!(e.code(), crate::error::RpcErrorCode::NotFound);
    }

    #[test]
    fn the_system_clock_is_after_2020() {
        // 2020-01-01T00:00:00Z in milliseconds. A clock below this means the
        // machine is misconfigured, not that the test is wrong.
        assert!(SystemClock.now_ms() > 1_577_836_800_000);
    }
}
