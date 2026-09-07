//! Logs and metrics: what an operator sees when nothing is wrong, and the
//! numbers they page on when something is.
//!
//! # Logs
//!
//! `tracing`, in two formats. `text` is the default and is what `devnet/*.sh`
//! greps; `json` is one object per line for a collector. The filter comes from
//! `RUST_LOG`, defaulting to `info` for this workspace and `warn` for
//! everything else, so a fresh node is readable without a tutorial.
//!
//! **One line is load-bearing.** A completed reorg must log something matching
//! `/reorg|disconnect|rolled back|new tip/i`, because `devnet/heal.sh` greps
//! for it to show what the losing node did (CONTRACT §13). [`log_reorg`] is
//! that line, and a test in this module asserts the pattern matches it.
//!
//! # Metrics
//!
//! Prometheus, via `metrics` + `metrics-exporter-prometheus`, off unless
//! `--metrics-listen` is given: the endpoint is unauthenticated and a node that
//! exports one by default has an open port nobody asked for.
//!
//! [`NodeMetrics`] keeps an atomic mirror of every value it publishes. That is
//! not redundancy — installing a global recorder is a process-wide, once-only
//! side effect, so without the mirror the only way to test that the node counts
//! blocks correctly would be to scrape an HTTP endpoint.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use ferrum_types::BlockHash;
use metrics_exporter_prometheus::PrometheusBuilder;

use crate::config::LogFormat;
use crate::error::NodeError;

// ---------------------------------------------------------------------------
// Metric names
// ---------------------------------------------------------------------------

/// Height of the active tip.
pub const METRIC_HEIGHT: &str = "ferrum_chain_height";
/// Number of connected peers.
pub const METRIC_PEERS: &str = "ferrum_peer_count";
/// Transactions held in the mempool.
pub const METRIC_MEMPOOL_TXS: &str = "ferrum_mempool_transactions";
/// Bytes held in the mempool.
pub const METRIC_MEMPOOL_BYTES: &str = "ferrum_mempool_bytes";
/// Blocks that became part of the active chain.
pub const METRIC_BLOCKS_ACCEPTED: &str = "ferrum_blocks_accepted_total";
/// Blocks refused for breaking a rule.
pub const METRIC_BLOCKS_REJECTED: &str = "ferrum_blocks_rejected_total";
/// Blocks this node sealed itself.
pub const METRIC_BLOCKS_MINED: &str = "ferrum_blocks_mined_total";
/// Reorganisations completed.
pub const METRIC_REORGS: &str = "ferrum_reorgs_total";
/// Depth of the most recent reorganisation, in disconnected blocks.
pub const METRIC_REORG_DEPTH: &str = "ferrum_reorg_depth";
/// Transactions admitted to the mempool.
pub const METRIC_TXS_ACCEPTED: &str = "ferrum_transactions_accepted_total";
/// Transactions refused by policy or validation.
pub const METRIC_TXS_REJECTED: &str = "ferrum_transactions_rejected_total";
/// Headers accepted during sync.
pub const METRIC_HEADERS_ACCEPTED: &str = "ferrum_headers_accepted_total";
/// Peers disconnected for serving something invalid.
pub const METRIC_PEERS_BANNED: &str = "ferrum_peers_disconnected_total";
/// Messages dropped because a bounded queue was full.
pub const METRIC_SHED: &str = "ferrum_queue_shed_total";

/// Every metric this node publishes, for the documentation test that asserts
/// the names are distinct and correctly prefixed.
pub const ALL_METRICS: &[&str] = &[
    METRIC_HEIGHT,
    METRIC_PEERS,
    METRIC_MEMPOOL_TXS,
    METRIC_MEMPOOL_BYTES,
    METRIC_BLOCKS_ACCEPTED,
    METRIC_BLOCKS_REJECTED,
    METRIC_BLOCKS_MINED,
    METRIC_REORGS,
    METRIC_REORG_DEPTH,
    METRIC_TXS_ACCEPTED,
    METRIC_TXS_REJECTED,
    METRIC_HEADERS_ACCEPTED,
    METRIC_PEERS_BANNED,
    METRIC_SHED,
];

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/// The default `RUST_LOG` filter when the operator sets none.
///
/// Ferrum crates at `info`, everything else at `warn`: a fresh node prints the
/// chain making progress and not the internals of six dependencies.
pub const DEFAULT_LOG_FILTER: &str =
    "warn,ferrum_node=info,ferrum_chain=info,ferrum_p2p=warn,ferrum_rpc=info,ferrum_mempool=info";

/// Install the global tracing subscriber.
///
/// Returns `Ok(false)` when a subscriber was already installed — which is the
/// normal case in a test binary, and is not a failure. A second `chaind` in one
/// process is not a scenario worth failing a node's startup over.
///
/// # Errors
///
/// [`NodeError::Telemetry`] when the filter directive itself is malformed.
pub fn init_tracing(format: LogFormat) -> Result<bool, NodeError> {
    use tracing_subscriber::EnvFilter;

    let filter = match std::env::var("RUST_LOG") {
        Ok(directive) if !directive.is_empty() => EnvFilter::try_new(&directive)
            .map_err(|e| NodeError::Telemetry(format!("RUST_LOG {directive:?}: {e}")))?,
        _ => EnvFilter::try_new(DEFAULT_LOG_FILTER)
            .map_err(|e| NodeError::Telemetry(format!("default log filter: {e}")))?,
    };

    let installed = match format {
        LogFormat::Text => {
            tracing_subscriber::fmt().with_env_filter(filter).with_target(true).try_init().is_ok()
        }
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_target(true)
            .try_init()
            .is_ok(),
    };
    Ok(installed)
}

/// The line `devnet/heal.sh` greps for.
///
/// The script runs `grep -iE 'reorg|disconnect|rolled back|new tip'` over the
/// losing node's log, so this wording is part of the contract, not a style
/// choice. [`REORG_LOG_NEEDLES`] and a test below pin it.
pub fn log_reorg(from: &BlockHash, to: &BlockHash, disconnected: usize, connected: usize) {
    tracing::info!(
        %from,
        %to,
        disconnected,
        connected,
        "{}",
        reorg_line(disconnected, connected)
    );
}

/// The words `devnet/heal.sh` searches for, lowercased.
pub const REORG_LOG_NEEDLES: &[&str] = &["reorg", "disconnect", "rolled back", "new tip"];

/// The message body of a completed-reorg log line.
///
/// Split out from [`log_reorg`] purely so a test can assert the text without
/// installing a subscriber and capturing its output.
#[must_use]
pub fn reorg_line(disconnected: usize, connected: usize) -> String {
    format!("reorg complete: rolled back {disconnected} block(s), connected {connected}, new tip")
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Bind a Prometheus scrape endpoint and install the global recorder.
///
/// Must be called from inside the tokio runtime: the exporter spawns its
/// listener onto the current handle.
///
/// # Errors
///
/// [`NodeError::Telemetry`] when the address cannot be bound or a recorder is
/// already installed.
pub fn install_metrics_exporter(addr: SocketAddr) -> Result<(), NodeError> {
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| NodeError::Telemetry(format!("prometheus exporter on {addr}: {e}")))?;
    describe_metrics();
    tracing::info!(%addr, "prometheus metrics listening");
    Ok(())
}

/// Attach a unit and a description to every metric.
///
/// Called once after the recorder is installed. Descriptions are what make a
/// scrape readable without the source next to it.
pub fn describe_metrics() {
    metrics::describe_gauge!(METRIC_HEIGHT, "height of the active chain tip");
    metrics::describe_gauge!(METRIC_PEERS, "connected peers");
    metrics::describe_gauge!(METRIC_MEMPOOL_TXS, "transactions held in the mempool");
    metrics::describe_gauge!(METRIC_MEMPOOL_BYTES, "bytes held in the mempool");
    metrics::describe_gauge!(METRIC_REORG_DEPTH, "blocks disconnected by the last reorg");
    metrics::describe_counter!(METRIC_BLOCKS_ACCEPTED, "blocks connected to the active chain");
    metrics::describe_counter!(METRIC_BLOCKS_REJECTED, "blocks rejected for breaking a rule");
    metrics::describe_counter!(METRIC_BLOCKS_MINED, "blocks sealed by this node");
    metrics::describe_counter!(METRIC_REORGS, "reorganisations completed");
    metrics::describe_counter!(METRIC_TXS_ACCEPTED, "transactions admitted to the mempool");
    metrics::describe_counter!(METRIC_TXS_REJECTED, "transactions refused");
    metrics::describe_counter!(METRIC_HEADERS_ACCEPTED, "headers accepted during sync");
    metrics::describe_counter!(METRIC_PEERS_BANNED, "peers disconnected for misbehaviour");
    metrics::describe_counter!(METRIC_SHED, "messages dropped by a full bounded queue");
}

/// A `u64` narrowed for a Prometheus gauge.
///
/// `metrics::Gauge::set` takes anything convertible to a 64-bit float, and this
/// workspace forbids naming that type at all (CONTRACT §0.1). `u32` is the
/// widest integer the crate converts from, and it covers four billion blocks,
/// four billion peers and four gigabytes of mempool — every quantity here.
#[must_use]
fn gauge_value(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Every number the node publishes, with an atomic mirror of each.
///
/// The mirror exists so the counting logic is testable: installing a metrics
/// recorder is a once-per-process global side effect, and a test that needed
/// one could not run beside another test that also needed one.
#[derive(Debug, Default)]
pub struct NodeMetrics {
    height: AtomicU64,
    peers: AtomicU64,
    mempool_txs: AtomicU64,
    mempool_bytes: AtomicU64,
    blocks_accepted: AtomicU64,
    blocks_rejected: AtomicU64,
    blocks_mined: AtomicU64,
    reorgs: AtomicU64,
    reorg_depth: AtomicU64,
    txs_accepted: AtomicU64,
    txs_rejected: AtomicU64,
    headers_accepted: AtomicU64,
    peers_disconnected: AtomicU64,
    shed: AtomicU64,
}

impl NodeMetrics {
    /// A fresh set of counters, all zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the active tip height.
    pub fn set_height(&self, height: u64) {
        self.height.store(height, Ordering::Relaxed);
        metrics::gauge!(METRIC_HEIGHT).set(gauge_value(height));
    }

    /// Record the number of connected peers.
    pub fn set_peers(&self, peers: usize) {
        let v = peers as u64;
        self.peers.store(v, Ordering::Relaxed);
        metrics::gauge!(METRIC_PEERS).set(gauge_value(v));
    }

    /// Record the mempool's size, in transactions and in bytes.
    pub fn set_mempool(&self, txs: usize, bytes: usize) {
        let (t, b) = (txs as u64, bytes as u64);
        self.mempool_txs.store(t, Ordering::Relaxed);
        self.mempool_bytes.store(b, Ordering::Relaxed);
        metrics::gauge!(METRIC_MEMPOOL_TXS).set(gauge_value(t));
        metrics::gauge!(METRIC_MEMPOOL_BYTES).set(gauge_value(b));
    }

    /// A block joined the active chain.
    pub fn block_accepted(&self) {
        bump(&self.blocks_accepted, METRIC_BLOCKS_ACCEPTED);
    }

    /// A block was refused for breaking a rule.
    pub fn block_rejected(&self) {
        bump(&self.blocks_rejected, METRIC_BLOCKS_REJECTED);
    }

    /// This node sealed a block.
    pub fn block_mined(&self) {
        bump(&self.blocks_mined, METRIC_BLOCKS_MINED);
    }

    /// A reorganisation completed, `depth` blocks deep.
    pub fn reorg(&self, depth: usize) {
        let depth = depth as u64;
        bump(&self.reorgs, METRIC_REORGS);
        self.reorg_depth.store(depth, Ordering::Relaxed);
        metrics::gauge!(METRIC_REORG_DEPTH).set(gauge_value(depth));
    }

    /// A transaction was admitted to the mempool.
    pub fn tx_accepted(&self) {
        bump(&self.txs_accepted, METRIC_TXS_ACCEPTED);
    }

    /// A transaction was refused.
    pub fn tx_rejected(&self) {
        bump(&self.txs_rejected, METRIC_TXS_REJECTED);
    }

    /// `n` headers were accepted during sync.
    pub fn headers_accepted(&self, n: usize) {
        let n = n as u64;
        self.headers_accepted.fetch_add(n, Ordering::Relaxed);
        metrics::counter!(METRIC_HEADERS_ACCEPTED).increment(n);
    }

    /// A peer was dropped for serving something invalid.
    pub fn peer_disconnected(&self) {
        bump(&self.peers_disconnected, METRIC_PEERS_BANNED);
    }

    /// A message was dropped because a bounded queue was full.
    pub fn shed(&self) {
        bump(&self.shed, METRIC_SHED);
    }

    /// A consistent read of every counter.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            height: self.height.load(Ordering::Relaxed),
            peers: self.peers.load(Ordering::Relaxed),
            mempool_txs: self.mempool_txs.load(Ordering::Relaxed),
            mempool_bytes: self.mempool_bytes.load(Ordering::Relaxed),
            blocks_accepted: self.blocks_accepted.load(Ordering::Relaxed),
            blocks_rejected: self.blocks_rejected.load(Ordering::Relaxed),
            blocks_mined: self.blocks_mined.load(Ordering::Relaxed),
            reorgs: self.reorgs.load(Ordering::Relaxed),
            reorg_depth: self.reorg_depth.load(Ordering::Relaxed),
            txs_accepted: self.txs_accepted.load(Ordering::Relaxed),
            txs_rejected: self.txs_rejected.load(Ordering::Relaxed),
            headers_accepted: self.headers_accepted.load(Ordering::Relaxed),
            peers_disconnected: self.peers_disconnected.load(Ordering::Relaxed),
            shed: self.shed.load(Ordering::Relaxed),
        }
    }
}

/// Increment an atomic mirror and its published counter together.
fn bump(cell: &AtomicU64, name: &'static str) {
    cell.fetch_add(1, Ordering::Relaxed);
    metrics::counter!(name).increment(1);
}

/// A point-in-time reading of [`NodeMetrics`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Active tip height.
    pub height: u64,
    /// Connected peers.
    pub peers: u64,
    /// Transactions in the mempool.
    pub mempool_txs: u64,
    /// Bytes in the mempool.
    pub mempool_bytes: u64,
    /// Blocks connected to the active chain.
    pub blocks_accepted: u64,
    /// Blocks rejected.
    pub blocks_rejected: u64,
    /// Blocks sealed locally.
    pub blocks_mined: u64,
    /// Reorganisations completed.
    pub reorgs: u64,
    /// Depth of the last reorganisation.
    pub reorg_depth: u64,
    /// Transactions admitted.
    pub txs_accepted: u64,
    /// Transactions refused.
    pub txs_rejected: u64,
    /// Headers accepted during sync.
    pub headers_accepted: u64,
    /// Peers dropped for misbehaviour.
    pub peers_disconnected: u64,
    /// Messages dropped by a full queue.
    pub shed: u64,
}

#[cfg(test)]
mod tests;
