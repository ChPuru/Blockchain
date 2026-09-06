//! Unit tests for `ferrum-chain`.
//!
//! Split by the module under test. `support` is the shared devnet miner.
//!
//! Arithmetic in tests is written plainly: `clippy::arithmetic_side_effects`
//! guards the consensus path, and a fixture that had to spell every `+` as a
//! `checked_add` would be unreadable without being safer.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::unwrap_used)]
#![allow(unreachable_pub)]
#![allow(dead_code)]

pub mod apply_tests;
pub mod genesis_tests;
pub mod manager_tests;
pub mod reorg_tests;
pub mod spend_tests;
pub mod support;
pub mod template_tests;
pub mod validate_tests;
