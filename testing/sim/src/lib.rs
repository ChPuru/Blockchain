//! Deterministic chain simulator, reference executor and adversarial scenario
//! harness for Ferrum (CONTRACT §14).
//!
//! This crate is the project's substitute for an audit. It does three things
//! that no unit test inside a crate can do:
//!
//! 1. **It validates every block twice.** [`reference::apply_block_reference`]
//!    is a second implementation of the state transition, written from
//!    `docs/SPEC.md` alone and never from `crates/chain/src/apply.rs`.
//!    `tests/differential.rs` runs both over several hundred generated blocks
//!    — coinbases, multi-input spends, timelocks, multisig, P2SH, and
//!    deliberately invalid blocks — and requires the same `Ok`/`Err`, the same
//!    error *variant*, and the same resulting state root on every one. Two
//!    implementations that share an author still catch a misreading of the
//!    specification; one does not.
//! 2. **It pins the state transition to a golden file.** [`replay`] replays a
//!    recorded block sequence, produces the state-root sequence, and diffs it
//!    against `golden/state_roots.json`. A consensus change that nobody
//!    intended turns `cargo test -p ferrum-sim --test determinism` red.
//! 3. **It attacks the chain.** [`scenarios`] holds one module per adversarial
//!    case from CONTRACT §14, each asserting a *specific* error variant. A
//!    test that only asserts "rejected" keeps passing when the block is
//!    rejected for the wrong reason, which is how a rule silently stops being
//!    tested.
//!
//! # Determinism is the whole point
//!
//! Nothing in this crate reads a clock, an operating-system RNG or the network.
//! Fixtures come from [`XorShift64`], a seeded generator written out in
//! [`prng`] rather than pulled from `rand`, and timestamps advance by
//! `target_spacing_ms` from genesis. Two runs on two machines produce
//! byte-identical blocks, which is what makes the golden file maintainable and
//! a scenario failure reproducible.
//!
//! # Layout
//!
//! | Module | What it owns |
//! |---|---|
//! | [`prng`] | [`XorShift64`], the seeded generator every fixture draws from |
//! | [`keys`] | the deterministic keyring and the [`Lock`] vocabulary |
//! | [`sign`] | turning a [`Lock`] into the `script_sig` that satisfies it |
//! | [`view`] | an in-memory [`ferrum_consensus::HeaderView`] |
//! | [`chain_builder`] | [`ChainBuilder`] — the block and transaction factory |
//! | [`mutate`] | the catalogue of single-defect invalid blocks |
//! | [`node`] | [`SimNode`] — a real store, router and chain manager |
//! | [`reference`](mod@reference) | the second, naive state transition |
//! | [`replay`] | the determinism harness and the golden file |
//! | [`scenarios`] | one module per adversarial case |
//! | [`error`] | [`SimError`] |
//!
//! # Example
//!
//! ```
//! use ferrum_sim::{ChainBuilder, XorShift64, apply_block_reference};
//! use ferrum_chain::apply_block;
//!
//! let mut chain = ChainBuilder::devnet(XorShift64::SCENARIO_SEED)?;
//! let ctx = chain.next_ctx()?;
//! let pre = chain.state_view();
//! let block = chain.build_block(&Default::default())?;
//!
//! // Production and the reference agree, block by block.
//! assert_eq!(apply_block(&pre, &block, &ctx), apply_block_reference(&pre, &block, &ctx));
//! # Ok::<(), ferrum_sim::SimError>(())
//! ```

#![warn(missing_docs)]

pub mod chain_builder;
pub mod error;
pub mod keys;
pub mod mutate;
pub mod node;
pub mod prng;
pub mod reference;
pub mod replay;
pub mod scenarios;
pub mod sign;
pub mod view;

pub use crate::chain_builder::{
    BlockPlan, ChainBuilder, DEFAULT_SEQUENCE, MINING_ATTEMPT_BUDGET, SIM_BFT_VALIDATORS,
    SpendableCoin, TxPlan, sim_bft_params, sim_params,
};
pub use crate::error::SimError;
pub use crate::keys::{DEFAULT_KEYRING_SIZE, KEYRING_DOMAIN, KeyRing, Lock};
pub use crate::mutate::{Mutation, invalid_variants, rule_name};
pub use crate::node::SimNode;
pub use crate::prng::XorShift64;
pub use crate::reference::{
    apply_block_reference, reference_block_hash, reference_check_coinbase_script_sig,
    reference_check_transaction_sanity, reference_height_push, reference_is_final,
    reference_leading_push, reference_merkle_root, reference_script_num, reference_txid,
};
pub use crate::replay::{
    GOLDEN_FILE_NAME, GoldenOutcome, GoldenRoots, RecordedChain, golden_path, replay_state_roots,
};
pub use crate::scenarios::{Verdict, judge, matured_chain};
pub use crate::sign::{push_bytes, signature_for, unlock};
pub use crate::view::{SimHeaderView, median_time_past_of};
