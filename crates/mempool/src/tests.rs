//! Unit tests for `ferrum-mempool`.
//!
//! Split by the behaviour under test. `support` holds the standard-script
//! fixtures and a real devnet chain for the reorg tests.
//!
//! Arithmetic in tests is written plainly: the production paths use checked
//! arithmetic on every monetary quantity, and a fixture that had to spell
//! every `+` as a `checked_add` would be unreadable without being safer.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::unwrap_used)]
#![allow(unreachable_pub)]
#![allow(dead_code)]

pub mod accept_tests;
pub mod lifecycle_tests;
pub mod orphan_tests;
pub mod policy_tests;
pub mod reorg_tests;
pub mod select_tests;
pub mod support;
