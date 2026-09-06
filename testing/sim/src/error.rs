//! The one error type the simulator reports through.
//!
//! Harness failures and consensus verdicts are deliberately different things:
//! a [`ValidationError`] is a statement about a block, while a [`SimError`] is
//! a statement about the harness. A test that conflated the two would pass
//! when the fixture builder broke.

use ferrum_chain::{ChainError, ValidationError};
use ferrum_consensus::ConsensusError;
use ferrum_crypto::CryptoError;
use ferrum_script::ScriptError;
use ferrum_storage::StorageError;

/// Something went wrong building or replaying a simulated chain.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SimError {
    /// A block the harness expected to be valid was rejected.
    #[error("the harness built an invalid block: {0}")]
    Validation(#[from] ValidationError),

    /// The chain layer refused an operation.
    #[error(transparent)]
    Chain(#[from] ChainError),

    /// An engine refused a header, a seal or a target.
    #[error(transparent)]
    Consensus(#[from] ConsensusError),

    /// The store refused an operation.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// A script could not be built or signed.
    #[error(transparent)]
    Script(#[from] ScriptError),

    /// A key or signature operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// Reading or writing the golden state-root file failed.
    #[error("golden file {path}: {detail}")]
    Golden {
        /// Which file.
        path: String,
        /// What went wrong.
        detail: String,
    },

    /// The recorded state-root sequence does not match the golden file.
    ///
    /// This is the determinism gate firing. It is a hard failure, never a
    /// prompt to regenerate: a state root that changed without a deliberate
    /// consensus change is a chain split that has not happened yet.
    #[error(
        "determinism gate: state root at index {index} is {actual}, golden file says {expected} \
         (regenerate only for a deliberate consensus change)"
    )]
    GoldenMismatch {
        /// Which block in the replayed sequence.
        index: usize,
        /// What the golden file records.
        expected: String,
        /// What this run produced.
        actual: String,
    },

    /// The golden file records a different number of blocks than were replayed.
    #[error("determinism gate: golden file has {expected} roots, this run produced {actual}")]
    GoldenLengthMismatch {
        /// How many roots the golden file holds.
        expected: usize,
        /// How many this run produced.
        actual: usize,
    },

    /// The production executor and the reference executor disagreed.
    ///
    /// This is the differential test's finding, and it is an error rather than
    /// an assertion so that every scenario reports it the same way: two
    /// implementations of one specification have diverged, and one of them is
    /// wrong.
    #[error("executors disagree: production said {production}, the reference said {reference}")]
    ExecutorDisagreement {
        /// What `ferrum_chain::apply_block` returned.
        production: String,
        /// What `apply_block_reference` returned.
        reference: String,
    },

    /// The harness ran out of usable coins while building a fixture.
    #[error("no spendable coin available: {0}")]
    NoSpendableCoin(&'static str),

    /// A deterministic derivation that should always succeed did not.
    #[error("fixture construction failed: {0}")]
    Fixture(String),

    /// Proof of work could not be found within the harness's attempt budget.
    ///
    /// Only reachable if a scenario asks for a target far harder than the
    /// devnet limit, which would make the whole run take unbounded time.
    #[error("gave up grinding proof of work after {0} attempts")]
    MiningBudgetExhausted(u64),
}

impl SimError {
    /// Build a [`SimError::Fixture`] from anything printable.
    pub fn fixture(detail: impl Into<String>) -> Self {
        SimError::Fixture(detail.into())
    }

    /// The consensus verdict inside this error, if there is one.
    #[must_use]
    pub fn validation(&self) -> Option<&ValidationError> {
        match self {
            SimError::Validation(v) => Some(v),
            SimError::Chain(c) => c.validation(),
            _ => None,
        }
    }
}
