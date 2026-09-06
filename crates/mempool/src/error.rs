//! Why the local mempool declined a transaction.
//!
//! **Every variant here is a policy verdict, never a consensus one.** A block
//! containing a transaction that produced any of these errors is still
//! perfectly valid, and a node that treated a `MempoolError` as grounds for
//! rejecting a *block* would fork itself off the network. The consensus
//! verdicts live in [`ferrum_chain::ValidationError`]; the only place the two
//! meet is [`MempoolError::Sanity`], which wraps the context-free rules of
//! SPEC §4.1 because a transaction that breaks one of those can never be
//! mined by anybody.
//!
//! One variant per rule, exactly as `ValidationError` does it, so a test
//! asserts *why* a transaction was refused rather than merely that it was. A
//! test that only asserts "rejected" keeps passing when the rejection happens
//! for the wrong reason, which is how a rule silently stops being tested.

use ferrum_chain::ValidationError;
use ferrum_script::ScriptError;
use ferrum_storage::StorageError;
use ferrum_types::{Amount, OutPoint, Txid};

/// Why a transaction was not admitted to the mempool.
///
/// `#[non_exhaustive]` because adding a policy rule must not be a breaking
/// change for the RPC layer that renders these. Every variant is
/// `Clone + PartialEq + Eq` so a test can compare against a constructed value
/// instead of matching a shape.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MempoolError {
    /// A coinbase is only ever valid inside the block that creates it.
    #[error("a coinbase transaction is only valid inside the block that creates it")]
    Coinbase,

    /// The transaction fails the context-free rules of SPEC §4.1.
    ///
    /// The one genuinely consensus-shaped check here: a transaction that
    /// breaks §4.1 cannot be mined by anyone, so refusing to relay it is not
    /// a policy opinion.
    #[error("transaction sanity: {0}")]
    Sanity(#[source] ValidationError),

    /// Larger than [`crate::MAX_STANDARD_TX_SIZE`].
    #[error("transaction is {size} bytes, policy limit is {max}")]
    TooLarge {
        /// The transaction's serialized envelope size.
        size: usize,
        /// [`crate::MAX_STANDARD_TX_SIZE`].
        max: usize,
    },

    /// An output pays to a script [`ferrum_script::templates::classify`] does
    /// not recognise.
    #[error("output {vout} pays to a non-standard script")]
    NonStandardOutput {
        /// Index of the offending output.
        vout: usize,
    },

    /// An unlocking script is not push-only.
    ///
    /// This is a *consensus* rule in Ferrum (SPEC §5.1), re-checked here so
    /// the transaction is refused with a precise reason before the expensive
    /// script machinery runs.
    #[error("input {input_index} has a script_sig that is not push-only")]
    NonPushOnlyScriptSig {
        /// Index of the offending input.
        input_index: usize,
    },

    /// Not final in the next block (SPEC §4.3).
    #[error("transaction is not final at height {height}: lock_time {lock_time}")]
    NonFinal {
        /// The transaction's `lock_time`.
        lock_time: u32,
        /// The height it was judged at — the tip height plus one.
        height: u64,
    },

    /// Another mempool transaction already spends this outpoint.
    ///
    /// **There is no replace-by-fee in v1.** First seen wins, however small
    /// its fee; see the crate documentation for why that is a deliberate
    /// absence rather than an omission.
    #[error(
        "outpoint {out_point} is already spent by mempool transaction {existing}; \
         there is no replace-by-fee in v1"
    )]
    Conflict {
        /// The contested outpoint.
        out_point: OutPoint,
        /// The transaction that got there first.
        existing: Txid,
    },

    /// An input names an output of a transaction we *do* hold, but that
    /// output does not exist.
    ///
    /// Distinct from the orphan case: the parent is known, so waiting for it
    /// cannot help.
    #[error("outpoint {out_point} does not exist")]
    MissingInput {
        /// The unresolvable outpoint.
        out_point: OutPoint,
    },

    /// Spends a coinbase output before `coinbase_maturity` blocks have passed.
    #[error(
        "coinbase output {out_point} from height {coin_height} is immature at height \
         {spend_height}; maturity is {maturity} blocks"
    )]
    ImmatureCoinbaseSpend {
        /// The outpoint being spent too early.
        out_point: OutPoint,
        /// The height the coinbase was mined at.
        coin_height: u64,
        /// The height the spend was judged at.
        spend_height: u64,
        /// `params.coinbase_maturity`.
        maturity: u64,
    },

    /// The sum of the resolved inputs overflows or leaves the money range.
    #[error("the sum of the transaction's inputs is not valid money")]
    InputSumOverflow,

    /// Pays out more than it takes in.
    #[error("transaction spends {inputs} but pays out {outputs}")]
    InsufficientInputValue {
        /// Sum of the resolved inputs.
        inputs: Amount,
        /// Sum of the outputs.
        outputs: Amount,
    },

    /// Below `MempoolConfig::min_fee_rate`, in grains per 1000 bytes.
    #[error("fee rate {fee_rate} is below the {min} grains-per-kB relay minimum")]
    FeeTooLow {
        /// The transaction's fee rate.
        fee_rate: u64,
        /// `MempoolConfig::min_fee_rate`.
        min: u64,
    },

    /// An input's script did not verify.
    #[error("input {input_index} failed script verification: {source}")]
    ScriptVerification {
        /// Index of the failing input.
        input_index: usize,
        /// What the interpreter said.
        #[source]
        source: ScriptError,
    },

    /// The pool is at `max_bytes` and this transaction is the cheapest thing
    /// in it, so admitting it would only evict it again.
    #[error(
        "the mempool holds {size_bytes} of {max_bytes} bytes and this transaction pays too little to displace anything"
    )]
    PoolFull {
        /// Bytes held after the eviction pass.
        size_bytes: usize,
        /// `MempoolConfig::max_bytes`.
        max_bytes: usize,
    },

    /// The backing [`ferrum_storage::StateView`] failed.
    ///
    /// Carried as text rather than as a [`StorageError`] so that
    /// `MempoolError` stays `Clone + PartialEq`. A view failure is an I/O
    /// fault, not a policy rule, and a caller must not treat it as one: a node
    /// that banned a peer because its own disk failed would ban the network.
    #[error("state view failure: {detail}")]
    View {
        /// The storage layer's complaint.
        detail: String,
    },

    /// A checked arithmetic step overflowed. The string names the step.
    #[error("arithmetic overflow while computing {0}")]
    Arithmetic(&'static str),
}

impl MempoolError {
    /// Wrap a storage failure as a non-policy [`MempoolError::View`].
    #[must_use]
    pub fn view(e: &StorageError) -> Self {
        MempoolError::View { detail: e.to_string() }
    }

    /// Whether this verdict means "I could not tell", rather than "no".
    ///
    /// Only a view failure qualifies. A caller relaying transactions should
    /// retry rather than punish the peer that sent it.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(self, MempoolError::View { .. })
    }
}
