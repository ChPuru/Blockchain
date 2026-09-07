//! The one error type every consensus decision reports through.
//!
//! Every variant names a **single rule**, so a test can assert the exact reason
//! a header or a seal was rejected rather than merely that it was. A test that
//! only asserts "rejected" keeps passing when the block is rejected for the
//! wrong reason, which is how a rule silently stops being tested (SPEC 3.4).

use ferrum_types::{BlockHash, CompactTarget};

use crate::target::Target;

/// Why a header, a difficulty transition or a seal is invalid.
///
/// `#[non_exhaustive]` because adding a rule must not be a breaking change for
/// the crates that match on it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConsensusError {
    /// The compact target uses the negative form: mantissa bit `0x00800000`.
    ///
    /// Bitcoin inherited a sign bit from a generic bignum encoding and has
    /// never had a use for it. A negative target is meaningless, so this is a
    /// hard rejection rather than a silent normalisation.
    #[error("compact target {0:#010x} sets the sign bit 0x00800000")]
    NegativeTarget(u32),

    /// The compact target has a zero mantissa but a non-zero exponent: a
    /// non-canonical spelling of zero.
    #[error("compact target {0:#010x} has a zero mantissa with a non-zero exponent")]
    ZeroMantissaTarget(u32),

    /// Expanding the compact target would need more than 256 bits.
    #[error("compact target {0:#010x} expands past 256 bits")]
    TargetOverflow(u32),

    /// The expanded target is zero, which no hash can ever satisfy.
    #[error("a target of zero can never be met")]
    ZeroTarget,

    /// The header's target is easier than the network's `pow_limit`.
    #[error("target {actual} is above the network pow_limit {limit}")]
    TargetAbovePowLimit {
        /// The target the header asks for.
        actual: Target,
        /// The easiest target this network allows.
        limit: Target,
    },

    /// The header hash does not meet its own target.
    #[error("proof of work is insufficient: hash {hash} does not meet target {target}")]
    InsufficientWork {
        /// The block hash that was produced.
        hash: BlockHash,
        /// The target it had to meet.
        target: Target,
    },

    /// `header.bits` is not the value the difficulty rule requires.
    ///
    /// A block that *over*-pays difficulty is just as invalid: there is exactly
    /// one correct target per parent (SPEC 3.2 rule 7).
    #[error("bits {actual} does not match the required {expected}")]
    BadDifficultyTransition {
        /// What the engine computed from the parent.
        expected: CompactTarget,
        /// What the header claims.
        actual: CompactTarget,
    },

    /// `header.prev_hash` does not name the parent it was validated against.
    #[error("header names parent {actual} but was checked against {expected}")]
    WrongParent {
        /// Hash of the parent header supplied by the caller.
        expected: BlockHash,
        /// Hash the header actually commits to.
        actual: BlockHash,
    },

    /// The timestamp is not strictly greater than the parent's median time
    /// past. Equality is rejected, which is what stops a miner from freezing
    /// the clock across a whole median window.
    #[error("timestamp {timestamp_ms} ms is not after median time past {median_time_past_ms} ms")]
    TimestampTooOld {
        /// The header's timestamp, in milliseconds.
        timestamp_ms: u64,
        /// Median time past of the parent, converted to milliseconds.
        median_time_past_ms: u64,
    },

    /// The timestamp is further into the future than `max_future_block_time_ms`
    /// allows. This is the only clock-dependent rule; it lives in the node, not
    /// in the pure state transition (SPEC 3.2 rule 10).
    #[error("timestamp {timestamp_ms} ms is beyond the future limit {limit_ms} ms")]
    TimestampTooFarInFuture {
        /// The header's timestamp, in milliseconds.
        timestamp_ms: u64,
        /// `now + max_future_block_time_ms`.
        limit_ms: u64,
    },

    /// The block version is below the minimum this chain accepts.
    #[error("block version {0} is below the minimum supported version")]
    BadVersion(u32),

    /// The parent header is not in the view, so height and difficulty cannot be
    /// established. The caller may treat this as "orphan", not "invalid".
    #[error("parent header {0} is unknown to this view")]
    UnknownParent(BlockHash),

    /// A header a rule needs is missing from the active chain in the view.
    ///
    /// The difficulty rule no longer raises this: its ASERT anchor is genesis,
    /// read from [`ChainParams`](ferrum_types::ChainParams), because an anchor
    /// resolved through the *active* chain makes difficulty fork-dependent and
    /// splits the network permanently (CONTRACT 6.3).
    #[error("no header at height {0} on the active chain")]
    MissingHeader(u64),

    /// Median time past could not be computed for the parent.
    #[error("median time past is unavailable for {0}")]
    MedianTimePastUnavailable(BlockHash),

    /// The seal names a different engine than the one validating it.
    #[error("seal declares engine {actual} but engine {expected} is active at this height")]
    WrongEngine {
        /// The engine that should have sealed this block.
        expected: u8,
        /// The engine the seal names.
        actual: u8,
    },

    /// A proof-of-work seal carried a payload. The nonce in the header is the
    /// whole PoW seal; anything else is a covert extra field that the block
    /// hash does not commit to.
    #[error("a proof-of-work seal must be empty, found {0} bytes")]
    NonEmptyPowSeal(usize),

    /// The seal payload did not decode as the engine's certificate type.
    #[error("malformed seal: {0}")]
    MalformedSeal(String),

    /// ASERT was handed parameters it cannot work with.
    #[error("invalid ASERT parameters: {0}")]
    InvalidAsertParams(&'static str),

    /// A checked arithmetic step overflowed. The string names the step, so the
    /// message is actionable without a debugger.
    #[error("arithmetic overflow while computing {0}")]
    Arithmetic(&'static str),

    /// A BFT engine was asked for something only a configured validator can
    /// do — signing a vote without a validator key, or forcing `--consensus
    /// bft` on a node that has no BFT engine.
    ///
    /// It is never returned in place of a consensus decision: an engine that
    /// said "valid" without a quorum would be the exact bug the whole design
    /// exists to prevent.
    #[error("this node has no usable BFT engine or validator key")]
    EngineUnavailable,

    /// A BFT header carried a non-zero nonce.
    ///
    /// Nothing grinds a nonce under BFT — the quorum in the seal is the proof,
    /// not the header hash — so a free 64-bit field would let a proposer offer
    /// the same block content under many different block hashes.
    #[error("a BFT header must carry nonce 0, found {0}")]
    NonZeroBftNonce(u64),

    /// A reorg would unwind a block below the engine's finalized height.
    ///
    /// Under BFT a committed block is final by construction: it carries `2f+1`
    /// signatures, and by quorum intersection no conflicting block can ever
    /// gather the same. Refusing the reorg is how that guarantee reaches the
    /// chain layer.
    #[error("reorg to height {fork_height} crosses the finalized height {finalized_height}")]
    ReorgBelowFinalized {
        /// Height of the common ancestor the reorg would rewind to.
        fork_height: u64,
        /// The last height that can never be rewound.
        finalized_height: u64,
    },

    /// A BFT validator set smaller than four cannot tolerate a single fault.
    #[error("BFT needs at least {minimum} validators, got {actual}")]
    ValidatorSetTooSmall {
        /// How many validators were configured.
        actual: usize,
        /// The smallest workable set.
        minimum: usize,
    },

    /// The validator set admits two **disjoint** quorums, so two conflicting
    /// blocks could each gather `2f + 1` signatures at one height.
    ///
    /// Quorum intersection — any two quorums share at least one validator — is
    /// the entire basis for "this chain may halt; it will never fork" and for
    /// [`ReorgBelowFinalized`](Self::ReorgBelowFinalized). With
    /// `f = (n - 1) / 3` and quorum `2f + 1` it holds for every set size but
    /// `n = 6`, where `f = 1`, the quorum is 3 and `3 + 3 = 6`. A single
    /// Byzantine proposer is then enough to commit two different blocks at one
    /// height, so this is a startup failure rather than a warning. Use
    /// `n = 3f + 1`: 4, 7, 10, 13, ….
    #[error("a validator set of {validators} with quorum {quorum} admits two disjoint quorums")]
    NoQuorumIntersection {
        /// How many validators were configured, `n`.
        validators: usize,
        /// The quorum that set produces, `2f + 1`.
        quorum: usize,
    },

    /// The validator set does not fit the `u16` index in a
    /// [`BftCommit`](crate::BftCommit).
    #[error("BFT validator set of {0} does not fit a u16 index")]
    ValidatorSetTooLarge(usize),

    /// The same validator key appears twice, which would let one key vote twice.
    #[error("validator {0} appears more than once in the set")]
    DuplicateValidator(String),

    /// A configured validator id is not a valid x-only BIP-340 public key.
    #[error("validator {index} has an invalid public key: {reason}")]
    InvalidValidatorKey {
        /// Position in `ChainParams::bft_validators`.
        index: usize,
        /// Why the key was rejected.
        reason: String,
    },

    /// A commit named a validator index outside the active set.
    #[error("commit references validator index {index}, but the set holds {size}")]
    ValidatorIndexOutOfRange {
        /// The offending index.
        index: u16,
        /// Size of the active validator set.
        size: usize,
    },

    /// Commit signatures are not in strictly ascending index order.
    ///
    /// A canonical order is what makes a commit's byte encoding unique, so the
    /// same `2f+1` set cannot be spelled two ways — and it rejects a duplicated
    /// index, which would otherwise let one validator fill a whole quorum.
    #[error("commit signatures are not in strictly ascending validator order at position {0}")]
    UnorderedCommitSignatures(usize),

    /// One of the commit signatures failed BIP-340 verification.
    #[error("commit signature from validator {index} is invalid: {reason}")]
    BadCommitSignature {
        /// Which validator's signature failed.
        index: u16,
        /// Why it failed.
        reason: String,
    },

    /// The commit carries fewer valid signatures than `2f + 1`.
    #[error("commit has {have} signatures, quorum is {need}")]
    QuorumNotReached {
        /// Signatures present.
        have: usize,
        /// Signatures required.
        need: usize,
    },

    /// The commit certificate does not describe the block it seals.
    #[error(
        "commit is for {actual} at height {actual_height}, expected {expected} at {expected_height}"
    )]
    CommitMismatch {
        /// Block hash the commit signs.
        actual: BlockHash,
        /// Height the commit claims.
        actual_height: u64,
        /// Block hash being sealed.
        expected: BlockHash,
        /// Height of the block being sealed.
        expected_height: u64,
    },
}

impl ConsensusError {
    /// True when the error means "I do not have enough chain yet", as opposed
    /// to "this block is permanently invalid".
    ///
    /// A syncing node holds these blocks as orphans instead of banning the peer
    /// that sent them; every other variant is a bannable offence.
    pub fn is_missing_context(&self) -> bool {
        matches!(
            self,
            ConsensusError::UnknownParent(_)
                | ConsensusError::MissingHeader(_)
                | ConsensusError::MedianTimePastUnavailable(_)
        )
    }
}
