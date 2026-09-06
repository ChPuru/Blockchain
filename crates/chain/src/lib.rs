//! Block validation, the state-transition seam, fork choice and reorganisation
//! for Ferrum (CONTRACT §8, SPEC §§3, 4, 7 and 8).
//!
//! This crate is the heart of the system. Everything else feeds it blocks or
//! reads what it decided.
//!
//! # The determinism seam
//!
//! ```text
//! apply_block(pre: &dyn StateView, block: &Block, ctx: &BlockCtx)
//!     -> Result<StateDiff, ValidationError>
//! ```
//!
//! [`apply_block`] is a **pure function**. Given the same pre-state, block and
//! context it returns the same result on every machine, every architecture and
//! every optimisation level, forever. No clock, no RNG, no I/O, no floats, no
//! `HashMap` iteration. That is enforced mechanically —
//! `scripts/check-invariants.sh` greps this crate, and `clippy.toml` declares
//! the offending methods and types disallowed — rather than by review.
//!
//! The one clock-dependent rule in the protocol, the two-hour future-time bound
//! of SPEC §3.2 rule 10, lives in the node above the seam as
//! [`ferrum_consensus::check_future_time`]. Re-validating block 400 must never
//! depend on when you re-validate it.
//!
//! Two rules need the header chain and so are applied by [`ChainManager`]
//! immediately before `apply_block`, through
//! [`ferrum_consensus::ConsensusEngine`]: the difficulty transition
//! (`bits == next_bits(parent)`) and BFT seal verification. Everything else
//! `apply_block` checks itself.
//!
//! # Errors name rules
//!
//! [`ValidationError`] has one variant per rule of SPEC §3 and §4, so a test
//! asserts *why* a block was rejected. A test that only asserts "rejected"
//! passes when the block is rejected for the wrong reason, which is how a rule
//! silently stops being tested.
//!
//! # Fork choice is by work
//!
//! Cumulative work, never height. A chain of a hundred easy blocks can be
//! worth less than ten hard ones. Ties break on the lower block hash, which is
//! deterministic, so two nodes that saw the same candidates in opposite orders
//! still converge. See [`fork_choice`].
//!
//! # Reorganisation is all-or-nothing
//!
//! Walk to the common ancestor, disconnect down, connect forward; if any
//! connect fails, the whole reorg is rolled back to the original tip and the
//! candidate branch is marked `Invalid`. A half-applied reorg leaves a node
//! validating every future block against a UTXO set no other node has. The
//! guaranteed property — disconnect *N* blocks, reconnect them, and the UTXO
//! set is byte-identical with an unchanged `state_root` — is asserted in the
//! test suite.
//!
//! # Layout
//!
//! | Module | What it owns |
//! |---|---|
//! | [`ctx`] | [`BlockCtx`], the ambient context a block is validated in |
//! | [`validate`] | context-free block and transaction rules, BIP-34, locktime |
//! | [`apply`] | [`apply_block`] — the seam |
//! | [`genesis`] | genesis computed from [`ferrum_types::ChainParams`] |
//! | [`fork_choice`] | cumulative-work comparison and the hash tiebreak |
//! | [`reorg`] | planning, executing and rolling back a reorganisation |
//! | [`manager`] | [`ChainManager`] — acceptance, sync helpers, events |
//! | [`template`] | block template assembly for the miner |
//! | [`view`] | the [`ferrum_consensus::HeaderView`] over a store |
//! | [`error`] | [`ValidationError`] and [`ChainError`] |
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use ferrum_chain::{ChainManager, genesis_hash};
//! use ferrum_consensus::EngineRouter;
//! use ferrum_storage::{Store, StoreConfig};
//! use ferrum_types::ChainParams;
//!
//! let params = ChainParams::devnet();
//! let store = Arc::new(Store::open_in_memory(StoreConfig::default())?);
//! let engines = Arc::new(EngineRouter::new(params.clone())?);
//! let chain = ChainManager::open(Arc::clone(&store), params.clone(), engines)?;
//!
//! let g = chain.init_genesis()?;
//! assert_eq!(g, genesis_hash(&params));
//! assert_eq!(chain.tip(), (g, 0));
//! // Idempotent: a second call adopts the genesis already on disk.
//! assert_eq!(chain.init_genesis()?, g);
//! # Ok::<(), ferrum_chain::ChainError>(())
//! ```

#![warn(missing_docs)]
#![warn(clippy::arithmetic_side_effects)]

pub mod apply;
pub mod ctx;
pub mod error;
pub mod fork_choice;
pub mod genesis;
pub mod manager;
pub mod reorg;
pub mod template;
pub mod validate;
pub mod view;

#[cfg(test)]
mod tests;

pub use crate::apply::apply_block;
pub use crate::ctx::BlockCtx;
pub use crate::error::{ChainError, ValidationError};
pub use crate::fork_choice::{TipCandidate, best_of, cumulative_work, is_better};
pub use crate::genesis::{
    GENESIS_MESSAGE_PREFIX, GENESIS_VERSION, genesis_block, genesis_coinbase, genesis_commitment,
    genesis_hash, genesis_header, genesis_message, genesis_script_pubkey,
};
pub use crate::manager::{
    AcceptOutcome, CHAIN_EVENT_CAPACITY, ChainEvent, ChainManager, EventBus, MAX_ORPHAN_BLOCKS,
    OrphanPool,
};
pub use crate::reorg::{
    ReorgOutcome, ReorgPlan, connect_tip_block, entry_hash, entry_of, execute_reorg, plan_reorg,
};
pub use crate::template::{
    BLOCK_FIXED_OVERHEAD, EMPTY_SEAL_SIZE, TEMPLATE_VERSION, block_size_of, build_coinbase,
    build_template, tx_body_size,
};
pub use crate::validate::{
    COINBASE_SCRIPT_SIG_MAX, COINBASE_SCRIPT_SIG_MIN, MEDIAN_TIME_SPAN, build_coinbase_script_sig,
    check_block_sanity, check_coinbase_script_sig, check_coinbase_structure,
    check_transaction_sanity, compute_merkle_root, height_push_data, is_final,
    leading_minimal_push, median_time_past, total_output,
};
pub use crate::view::StoreHeaderView;
