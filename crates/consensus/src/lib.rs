//! Pluggable consensus engines for Ferrum: proof-of-work and BFT.
//!
//! This crate is CONTRACT section 6 and SPEC sections 6 and 9. It answers four
//! questions and nothing else:
//!
//! 1. **What target must this block meet?** — [`asert_next_bits`], the
//!    `aserti3-2d` controller, integer-only.
//! 2. **How much is this block worth in fork choice?** — [`work_from_target`],
//!    cumulative work, never height.
//! 3. **Is this header valid?** — [`ConsensusEngine::validate_header`].
//! 4. **Who decides?** — [`EngineRouter::engine_for_height`], the one
//!    dispatcher that makes the PoW to BFT fork a configuration change.
//!
//! # The dependency rule
//!
//! `ferrum-consensus` depends on `ferrum-types` and `ferrum-crypto` and on
//! **nothing else in the workspace** — never `chain`, `storage`, `mempool`,
//! `p2p`, `rpc`, `wallet` or `node`. CI enforces it (CONTRACT 0.6). That single
//! rule is what makes the engine swap a config change instead of a rewrite:
//! there is no path by which an engine can reach into the state machine.
//! Storage is reached through the [`HeaderView`] trait, which the caller
//! implements.
//!
//! # Determinism
//!
//! Nothing here reads a clock, an RNG or the filesystem, and nothing iterates a
//! `HashMap`. The one clock-dependent rule in the protocol — the two-hour
//! future-time bound — is [`check_future_time`], which the node calls above the
//! state-transition seam so that re-validating block 400 never depends on when
//! you re-validate it.
//!
//! Every arithmetic operation on a consensus quantity is checked or saturating;
//! the crate carries `#![warn(clippy::arithmetic_side_effects)]` and CI denies
//! it. There are no floats: a float in the difficulty controller produces
//! platform-dependent rounding, and the chain splits along CPU architecture
//! lines.
//!
//! # Example
//!
//! ```
//! use ferrum_consensus::{
//!     CompactTarget, EngineRouter, Target, compact_to_target, target_to_compact, work_from_target,
//! };
//! use ferrum_types::{BlockSeal, ChainParams};
//!
//! // The compact encoding round-trips for every canonical value.
//! let bits = CompactTarget(0x1d00_ffff);
//! let target = compact_to_target(bits)?;
//! assert_eq!(target_to_compact(target), bits);
//!
//! // Harder targets are worth more work.
//! let easier = compact_to_target(CompactTarget(0x1e00_ffff))?;
//! assert!(work_from_target(target) > work_from_target(easier));
//!
//! // One dispatcher decides which engine is active at a height.
//! let router = EngineRouter::new(ChainParams::devnet())?;
//! assert_eq!(router.engine_for_height(0).engine_id(), BlockSeal::ENGINE_POW);
//! # Ok::<(), ferrum_consensus::ConsensusError>(())
//! ```

#![warn(missing_docs)]
#![warn(clippy::arithmetic_side_effects)]

pub mod asert;
pub mod bft;
pub mod engine;
pub mod error;
pub mod pow;
pub mod target;

#[cfg(test)]
mod testview;

pub use crate::asert::{
    ANCHOR_HEIGHT, AsertAnchor, AsertParams, CUBIC_C1, CUBIC_C2, CUBIC_C3, CUBIC_ROUND,
    CUBIC_SHIFT, EXPONENT_CLAMP, RADIX, asert_exponent, asert_factor, asert_next_bits,
    asert_next_target, split_exponent,
};
pub use crate::bft::{
    BftCommit, BftEngine, DEFAULT_PRECOMMIT_TIMEOUT, DEFAULT_PREVOTE_TIMEOUT,
    DEFAULT_PROPOSE_TIMEOUT, MIN_VALIDATORS, VOTE_MSG_SIZE, VoteMsg, precommit_digest,
    prevote_digest, proposal_digest,
};
pub use crate::engine::{
    BlockTemplate, ConsensusEngine, EngineRouter, HeaderView, MIN_BLOCK_VERSION, block_hash,
    check_future_time,
};
pub use crate::error::ConsensusError;
pub use crate::pow::{CANCEL_CHECK_INTERVAL, PowEngine};
pub use crate::target::{
    COMPACT_MANTISSA_MASK, COMPACT_SIGN_BIT, TARGET_BITS, Target, Work, compact_to_target,
    difficulty_x1000, hash_meets_target, hash_to_u256, is_canonical_compact, target_to_compact,
    work_from_target,
};

// Re-exported so that a caller can name a target without also depending on
// `ferrum-types` and `primitive-types` directly.
pub use ferrum_types::CompactTarget;
pub use primitive_types::U256;
