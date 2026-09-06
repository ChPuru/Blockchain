//! The crate's test suite.
//!
//! [`fixture`] builds a real devnet chain in memory — a real `Store`, a real
//! `ChainManager`, real proof of work — so that the handlers are exercised
//! against the same code paths a node runs, not against a mock that agrees with
//! them by construction. Devnet's `pow_limit` accepts roughly half of all
//! hashes, so "mining" a fixture block is a handful of nonces.

#![allow(clippy::unwrap_used)]

mod address_tests;
mod error_tests;
mod faucet_tests;
mod fixture;
mod rest_tests;
mod rpc_tests;
mod server_tests;
