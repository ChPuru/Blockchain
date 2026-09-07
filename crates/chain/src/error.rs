//! The two error types this crate reports through.
//!
//! [`ValidationError`] is a **consensus** verdict: it says which rule of
//! SPEC §3 or §4 a block broke. There is one variant per rule, so a test can
//! assert the exact reason a block was rejected rather than merely that it
//! was. A test that only asserts "rejected" keeps passing when the block is
//! rejected for the wrong reason, which is how a rule silently stops being
//! tested (SPEC §3.4).
//!
//! [`ChainError`] is everything *around* that verdict: storage failures, an
//! unknown parent, a reorg that would cross finality. A block that is
//! `Invalid` and a block we simply cannot look up are different facts and the
//! caller acts differently on each — one bans a peer, the other asks it for
//! more data.
//!
//! The header rules delegate to [`ConsensusError`], which already has one
//! variant per rule of SPEC §3.2. Re-spelling them here would give two names
//! for one rule, and the two would eventually disagree.

use ferrum_consensus::ConsensusError;
use ferrum_script::ScriptError;
use ferrum_storage::StorageError;
use ferrum_types::{Amount, BlockHash, Hash32, OutPoint, Txid};

/// Why a block or a transaction is invalid.
///
/// `#[non_exhaustive]` because adding a rule must not be a breaking change for
/// the crates that match on it. Every variant is `Clone + PartialEq + Eq` so a
/// test can compare against a constructed value instead of matching a shape.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    // ---------------------------------------------- SPEC §3.1 context-free
    /// Rule 1a: the block — header, count and transactions, without the seal —
    /// is larger than `params.max_block_size`.
    #[error("block is {size} bytes, limit is {max}")]
    BlockTooLarge {
        /// The block's size excluding the seal, `Block::consensus_size()`.
        size: usize,
        /// `params.max_block_size`.
        max: usize,
    },

    /// Rule 1b: the engine seal is longer than the largest certificate this
    /// validator set can produce.
    ///
    /// The seal is bounded separately from the transactions because it is not
    /// committed to by the block hash and may legally vary between `quorum` and
    /// `n` signatures (DECISIONS D2, D12). Letting it into rule 1 would make one
    /// block hash have several sizes, only some of which fit.
    #[error("block seal is {size} bytes, limit is {max}")]
    SealTooLarge {
        /// The seal payload's length.
        size: usize,
        /// `BlockSeal::max_data_len(params.bft_validators.len())`.
        max: usize,
    },

    /// Rule 2: the block carries no transactions at all.
    #[error("block has no transactions")]
    EmptyBlock,

    /// Rule 2: `txs[0]` is not a coinbase.
    #[error("the first transaction is not a coinbase")]
    MissingCoinbase,

    /// Rule 2: a transaction other than `txs[0]` is a coinbase.
    ///
    /// A second coinbase would be a second subsidy claim.
    #[error("transaction {tx_index} is a second coinbase")]
    MultipleCoinbases {
        /// Position of the offending transaction.
        tx_index: usize,
    },

    /// Rule 3: `compute_merkle_root(txs) != header.merkle_root`.
    #[error("merkle root mismatch: header claims {actual}, transactions give {expected}")]
    MerkleRootMismatch {
        /// The root computed from the block's transactions.
        expected: Hash32,
        /// The root the header commits to.
        actual: Hash32,
    },

    /// Rule 4: the same txid appears twice in one block.
    ///
    /// Two identical transactions in one block would collapse to one UTXO
    /// entry, so the second one's coins would be created and destroyed in the
    /// same breath (BIP-30 / CVE-2012-1909).
    #[error("transaction {txid} appears twice in the block")]
    DuplicateTransaction {
        /// The repeated identifier.
        txid: Txid,
    },

    // -------------------------------------- SPEC §4.1 transaction sanity
    /// A transaction has no inputs.
    #[error("transaction has no inputs")]
    NoInputs,

    /// A transaction has no outputs.
    #[error("transaction has no outputs")]
    NoOutputs,

    /// An output value is negative-by-overflow or above `MAX_MONEY`.
    #[error("output value {value} is outside the valid money range")]
    OutputValueOutOfRange {
        /// The offending value.
        value: Amount,
    },

    /// The sum of a transaction's outputs overflows or leaves the money range.
    #[error("the sum of a transaction's outputs is not valid money")]
    OutputSumOverflow,

    /// Two inputs of one transaction name the same outpoint.
    #[error("outpoint {out_point} is spent twice by one transaction")]
    DuplicateInput {
        /// The outpoint named twice.
        out_point: OutPoint,
    },

    /// A `script_sig` or `script_pubkey` is over `MAX_SCRIPT_SIZE`.
    #[error("script is {len} bytes, limit is {max}")]
    ScriptTooLarge {
        /// The script's length.
        len: usize,
        /// `ferrum_script::MAX_SCRIPT_SIZE`.
        max: usize,
    },

    /// A coinbase does not have exactly one input.
    #[error("coinbase has {count} inputs, expected exactly one")]
    CoinbaseInputCount {
        /// How many inputs it has.
        count: usize,
    },

    /// A coinbase's single input is not [`OutPoint::NULL`].
    #[error("the coinbase input is not the null outpoint")]
    CoinbaseInputNotNull,

    /// A non-coinbase transaction names the null outpoint.
    #[error("input {input_index} of a non-coinbase transaction is the null outpoint")]
    NullInput {
        /// Which input.
        input_index: usize,
    },

    // ------------------------------------------ SPEC §3.2 header context
    /// A header rule failed. [`ConsensusError`] carries one variant per rule.
    ///
    /// The view-dependent parts (`bits == next_bits(parent)`) are checked by
    /// [`crate::ChainManager`]; the pure parts (version, parentage, proof of
    /// work, the timestamp lower bound) are checked inside
    /// [`crate::apply_block`] so the seam is self-contained.
    #[error("header rule: {0}")]
    Header(#[source] ConsensusError),

    /// The seal failed its engine's check.
    #[error("seal rule: {0}")]
    Seal(#[source] ConsensusError),

    // ------------------------------------- SPEC §4.2 contextual validation
    /// An input does not resolve to an unspent coin.
    ///
    /// The caller decides what this means: a mempool reads it as "orphan", a
    /// block validator as "invalid", because a block must be self-contained
    /// given its parent's state. A double spend *within* one block also
    /// surfaces here, on the second spender.
    #[error("transaction {tx_index} spends {out_point}, which is missing or already spent")]
    MissingInput {
        /// Which transaction in the block.
        tx_index: usize,
        /// The outpoint that did not resolve.
        out_point: OutPoint,
    },

    /// A coinbase output was spent before it matured.
    #[error(
        "transaction {tx_index} spends coinbase {out_point} from height {coin_height} at \
         height {spend_height}, before the {maturity}-block maturity"
    )]
    ImmatureCoinbaseSpend {
        /// Which transaction in the block.
        tx_index: usize,
        /// The coinbase output being spent.
        out_point: OutPoint,
        /// The height the coin was created at.
        coin_height: u64,
        /// The height of the block spending it.
        spend_height: u64,
        /// `params.coinbase_maturity`.
        maturity: u64,
    },

    /// The sum of a transaction's inputs overflows or leaves the money range.
    #[error("the sum of transaction {tx_index}'s inputs is not valid money")]
    InputSumOverflow {
        /// Which transaction in the block.
        tx_index: usize,
    },

    /// `sum(inputs) < sum(outputs)`: the transaction creates money.
    #[error("transaction {tx_index} spends {inputs} but pays out {outputs}")]
    InsufficientInputValue {
        /// Which transaction in the block.
        tx_index: usize,
        /// Total resolved input value.
        inputs: Amount,
        /// Total output value.
        outputs: Amount,
    },

    /// The block's accumulated fees overflow or leave the money range.
    #[error("the block's total fees are not valid money")]
    FeeOverflow,

    /// A transaction in the block is not final at this height (SPEC §4.3).
    #[error("transaction {tx_index} is not final: lock_time {lock_time}")]
    NonFinalTransaction {
        /// Which transaction in the block.
        tx_index: usize,
        /// Its `lock_time` field.
        lock_time: u32,
    },

    /// SPEC §4.4 — an input's BIP-68 relative locktime is not satisfied by the
    /// age of the coin it spends.
    ///
    /// `OP_CHECKSEQUENCEVERIFY` only compares the script's operand against the
    /// input's own `sequence`, a field the spender writes freely. It becomes a
    /// timelock only because this rule separately requires the coin to be old
    /// enough for that `sequence` to be legal.
    #[error(
        "transaction {tx_index} input {input_index} needs {required} more blocks: sequence \
         0x{sequence:08x} against a coin from height {coin_height} spent at height {spend_height}"
    )]
    UnsatisfiedRelativeLock {
        /// Which transaction in the block.
        tx_index: usize,
        /// Which input of that transaction.
        input_index: usize,
        /// The input's `sequence` field.
        sequence: u32,
        /// The relative lock the low 16 bits ask for, in blocks.
        required: u32,
        /// The height the spent coin was created at.
        coin_height: u64,
        /// The height this block occupies.
        spend_height: u64,
    },

    /// SPEC §4.4 — an input asks for the 512-second flavour of a relative
    /// locktime, which the determinism seam cannot evaluate.
    ///
    /// BIP-68's time flavour compares the median time past of the block that
    /// *created* the coin against this block's. [`crate::BlockCtx`] carries
    /// only the parent's median, and [`ferrum_types::Coin`] carries only a
    /// height, so the age in seconds is not computable here. An unenforceable
    /// timelock must fail closed: accepting the input would mean the lock is
    /// silently not a lock at all.
    #[error(
        "transaction {tx_index} input {input_index} asks for a 512-second relative locktime \
         (sequence 0x{sequence:08x}), which this validator cannot evaluate"
    )]
    UnsupportedRelativeTimeLock {
        /// Which transaction in the block.
        tx_index: usize,
        /// Which input of that transaction.
        input_index: usize,
        /// The input's `sequence` field.
        sequence: u32,
    },

    /// The block demands more signature verifications than its budget allows.
    ///
    /// `MAX_OPS` is a *per-input* limit and `OP_CHECKMULTISIG` charges `1 + n`
    /// operations for up to `n` verifications, so one input can demand around
    /// 190 of them — and the expensive script lives in the `script_pubkey`,
    /// which is already in the UTXO set, so the spending input costs an
    /// attacker as little as 44 bytes. Without a block-wide budget there is no
    /// proportionality at all between the bytes bought and the work every node
    /// must do. Bitcoin closes the same gap with `MAX_BLOCK_SIGOPS`.
    #[error("block demands {used} signature checks, budget is {budget}")]
    SigCheckBudgetExceeded {
        /// How many checks the block had reached when the budget was passed.
        used: u64,
        /// `max_block_sig_checks(params)`.
        budget: u64,
    },

    /// `script::verify` rejected an input.
    #[error("transaction {tx_index} input {input_index} failed script verification: {source}")]
    ScriptVerification {
        /// Which transaction in the block.
        tx_index: usize,
        /// Which input of that transaction.
        input_index: usize,
        /// Why the script failed.
        #[source]
        source: ScriptError,
    },

    // ------------------------------------------------- SPEC §3.3 coinbase
    /// The coinbase `script_sig` is outside the 2..=100 byte window.
    #[error("coinbase script_sig is {len} bytes, must be between {min} and {max}")]
    CoinbaseScriptSigLength {
        /// Its actual length.
        len: usize,
        /// The inclusive minimum.
        min: usize,
        /// The inclusive maximum.
        max: usize,
    },

    /// The coinbase `script_sig` does not begin with a readable, minimally
    /// encoded push (BIP-34).
    #[error("coinbase script_sig does not begin with a minimally encoded push")]
    CoinbaseMissingHeightPush,

    /// The coinbase's leading push is not this block's height (BIP-34).
    ///
    /// Without a height commitment two blocks can carry identical coinbase
    /// transactions, hence identical txids, and the second overwrites the
    /// first's UTXO entry. That destroyed coins twice on Bitcoin mainnet
    /// (CVE-2012-1909 / BIP-30).
    #[error("coinbase commits to height {found:02x?}, expected a push of {expected}")]
    CoinbaseHeightMismatch {
        /// The height this block occupies.
        expected: u64,
        /// The bytes actually pushed.
        found: Vec<u8>,
    },

    /// The coinbase claims more than `block_subsidy(height) + total_fees`.
    #[error("coinbase claims {claimed} but only {allowed} is available")]
    CoinbaseOverpayment {
        /// What the coinbase's outputs add up to.
        claimed: Amount,
        /// `subsidy + fees`.
        allowed: Amount,
    },

    /// `block_subsidy(height) + total_fees` is not representable.
    #[error("the coinbase allowance overflows the money range")]
    CoinbaseAllowanceOverflow,

    /// Rule 15: an output this block creates already exists in the UTXO set.
    #[error("outpoint {out_point} already exists in the UTXO set")]
    DuplicateOutPoint {
        /// The colliding outpoint.
        out_point: OutPoint,
    },

    // --------------------------------------------------- not a chain rule
    /// The backing [`ferrum_storage::StateView`] failed.
    ///
    /// Carried as text rather than as a [`StorageError`] so that
    /// `ValidationError` stays `Clone + PartialEq`, which is what lets tests
    /// compare verdicts by value. A view failure is an I/O fault, not a
    /// consensus rule, and the caller must not treat it as one: a node that
    /// banned a peer because its own disk failed would ban the network.
    #[error("state view failure: {detail}")]
    View {
        /// The storage layer's complaint.
        detail: String,
    },

    /// A checked arithmetic step overflowed. The string names the step.
    #[error("arithmetic overflow while computing {0}")]
    Arithmetic(&'static str),
}

impl ValidationError {
    /// Wrap a storage failure as a non-consensus [`ValidationError::View`].
    pub(crate) fn view(e: &StorageError) -> Self {
        ValidationError::View { detail: e.to_string() }
    }

    /// Whether this verdict means "I could not tell", rather than "invalid".
    ///
    /// Only [`ValidationError::View`] qualifies. Everything else is a
    /// consensus verdict a peer can be held to.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, ValidationError::View { .. })
    }

    /// Whether the block might become valid once more data arrives.
    ///
    /// [`ValidationError::MissingInput`] is the mempool's "orphan" signal. For
    /// a *block* it is a hard rejection, because a block is self-contained
    /// given its parent's state.
    #[must_use]
    pub fn is_missing_input(&self) -> bool {
        matches!(self, ValidationError::MissingInput { .. })
    }
}

/// Everything that can go wrong around a consensus verdict.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    /// The block broke a consensus rule.
    #[error(transparent)]
    Validation(#[from] ValidationError),

    /// The store refused an operation.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// An engine rejected a header or a seal outside `apply_block`.
    #[error(transparent)]
    Consensus(#[from] ConsensusError),

    /// The block's parent is not known, so it cannot be placed in the tree.
    #[error("parent {0} is unknown")]
    UnknownParent(BlockHash),

    /// The block, or one of its ancestors, was already marked invalid.
    #[error("block {0} is already known to be invalid")]
    KnownInvalid(BlockHash),

    /// A block body the reorg needs is not in the store.
    #[error("no block body for {0}")]
    MissingBlockBody(BlockHash),

    /// A header index entry the walk needs is not in the store.
    #[error("no header index entry for {0}")]
    MissingHeaderEntry(BlockHash),

    /// The store has no tip, so there is nothing to build on.
    #[error("the chain has no tip; call init_genesis first")]
    NoTip,

    /// The store already holds a different genesis block.
    ///
    /// Genesis is computed from [`ferrum_types::ChainParams`], never trusted
    /// from a file. A node whose computed genesis differs from its peers'
    /// cannot sync with them, which is the intended outcome.
    #[error("genesis mismatch: this datadir holds {actual}, these parameters give {expected}")]
    GenesisMismatch {
        /// The genesis these parameters compute.
        expected: BlockHash,
        /// The genesis already in the store.
        actual: BlockHash,
    },

    /// The reorg would rewrite history below the engine's finalized height.
    #[error("reorg to height {fork_height} crosses the finalized height {finalized_height}")]
    ReorgBelowFinalized {
        /// The height the two branches diverge at.
        fork_height: u64,
        /// What the engine considers final.
        finalized_height: u64,
    },

    /// A reorg failed *and* the rollback to the original tip also failed.
    ///
    /// The store is now in a state no chain ever had. There is no honest
    /// recovery short of a reindex, so this is loud rather than silent.
    #[error("reorg rollback failed, the store is inconsistent: {detail}")]
    ReorgRollbackFailed {
        /// What went wrong during the rollback.
        detail: String,
    },

    /// Two branches share no ancestor, which means the store is corrupt.
    #[error("no common ancestor between {a} and {b}")]
    NoCommonAncestor {
        /// One tip.
        a: BlockHash,
        /// The other tip.
        b: BlockHash,
    },

    /// A checked arithmetic step overflowed.
    #[error("arithmetic overflow while computing {0}")]
    Arithmetic(&'static str),

    /// A template could not be built within `max_block_size`.
    #[error("block template is {size} bytes before any transaction, limit is {max}")]
    TemplateTooLarge {
        /// The size the empty template already needs.
        size: usize,
        /// `params.max_block_size`.
        max: usize,
    },
}

impl ChainError {
    /// The consensus verdict inside this error, if there is one.
    #[must_use]
    pub fn validation(&self) -> Option<&ValidationError> {
        match self {
            ChainError::Validation(v) => Some(v),
            _ => None,
        }
    }
}
