//! The Ferrum node: wiring, headers-first sync, mining, relay and telemetry
//! (CONTRACT §13, SPEC §12).
//!
//! Placeholder module list while the crate is under construction.

#![warn(missing_docs)]

pub mod config;
pub mod error;

pub use crate::config::{CliOverrides, LogFormat, NodeArgs, NodeConfig};
pub use crate::error::{ConfigError, NodeError, ValueSource};
