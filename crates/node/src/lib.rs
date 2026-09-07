//! The Ferrum node: configuration, wiring, headers-first sync, mining, relay
//! and telemetry (CONTRACT §13, SPEC §12).
//!
//! # What lives here and why
//!
//! Everything above the determinism seam. `ferrum-chain` decides whether a
//! block is valid given a context; this crate decides what the context *is* —
//! which network, which data directory, which peers, what time it is — and then
//! keeps a process alive around it.
//!
//! Three of those decisions are worth stating up front, because each is a place
//! a from-scratch node usually gets it wrong.
//!
//! ## 1. Configuration precedence is per field
//!
//! **CLI flag → environment variable (`FERRUM_*`) → config file → network
//! default**, applied one field at a time (CONTRACT §13, RUNNING §3). A
//! `--metrics-listen` flag and a `[rpc] listen` in the file must *both* take
//! effect; an implementation that picks a whole layer silently loses one of
//! them. See [`config::resolve()`], where every rule has a test of its own.
//!
//! ## 2. The two-hour future-time rule lives here, not in `apply_block`
//!
//! It is the one rule in the protocol that needs a clock. Keeping it above the
//! state-transition seam is exactly what lets a historical block be
//! re-validated identically forever: `apply_block` is a pure function of
//! (pre-state, block, context), and a clock inside it would make the validity
//! of block 400 depend on *when* you ask. The check is
//! [`ferrum_consensus::check_future_time`], called by [`relay::Relay`] on every
//! path a block can arrive by — gossip, sync, and the node's own miner.
//!
//! ## 3. Nothing is unbounded
//!
//! Every queue has a named capacity constant and sheds with a `tracing::warn!`
//! when it is full (CONTRACT §10.3). An unbounded channel does not remove
//! backpressure; it converts backpressure into an out-of-memory kill.
//!
//! # Layout
//!
//! | Module | What it owns |
//! |---|---|
//! | [`config`] | [`NodeConfig`] and the four layers that produce it |
//! | [`node`] | [`node::Node`]: wiring, tasks, shutdown, the node key |
//! | [`sync`] | headers-first sync, and the ban list |
//! | [`miner`] | template, seal, submit, announce |
//! | [`relay`] | gossip in and out, and the validation verdicts |
//! | [`telemetry`] | `tracing` in two formats, and the Prometheus counters |
//! | [`error`] | [`ConfigError`] and [`NodeError`] |
//!
//! # Example
//!
//! ```no_run
//! use ferrum_node::config::{CliOverrides, MapEnv, resolve};
//! use ferrum_node::node::Node;
//!
//! # async fn run() -> Result<(), ferrum_node::NodeError> {
//! let config = resolve(
//!     &CliOverrides { network: Some("devnet".to_owned()), ..Default::default() },
//!     &MapEnv::new(),
//!     None,
//! )?;
//! let node = Node::start(config).await?;
//! node.run().await
//! # }
//! ```

#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod faucet;
pub mod miner;
pub mod node;
pub mod relay;
pub mod sync;
pub mod telemetry;

pub use crate::config::{
    CliOverrides, ConfigFile, ConsensusFile, EngineChoice, LogFormat, NodeArgs, NodeConfig,
    resolve, resolve_from_process,
};
pub use crate::error::{ConfigError, NodeError, ValueSource};
pub use crate::faucet::NodeKeyFaucetSource;
pub use crate::miner::{Miner, Payout, resolve_payout};
pub use crate::node::{Node, NodeKey, wait_for_shutdown_signal};
pub use crate::relay::{Clock, GossipVerdict, Relay, SystemClock};
pub use crate::sync::{PeerBans, SyncManager, SyncNetwork, SyncStats};
pub use crate::telemetry::{
    MetricsSnapshot, NodeMetrics, init_tracing, install_metrics_exporter, log_reorg,
};
