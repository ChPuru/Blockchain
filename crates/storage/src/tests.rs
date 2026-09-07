//! The store's integration-level suite.
//!
//! These live inside the crate rather than in `tests/` so they can reach the
//! `#[cfg(test)]` crash-injection hook on [`crate::Store`], which is the only
//! honest way to assert that a half-written block leaves no trace.

#![allow(clippy::unwrap_used)]

mod crash;
mod extra;
mod fixtures;
mod index_state;
mod index_tests;
mod ordering;
mod reorg;
mod store_tests;
