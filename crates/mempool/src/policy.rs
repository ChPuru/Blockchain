//! Relay policy: the knobs, and the context-free half of acceptance.
//!
//! # Policy is not consensus
//!
//! Nothing in this file changes what a *block* may contain. Every rule here
//! is a local opinion about what this node is willing to store and forward,
//! and a miner that includes a transaction this module refuses has produced a
//! perfectly valid block. Keeping the two apart is not pedantry: a node that
//! enforced relay policy on incoming blocks would reject blocks the rest of
//! the network accepted, which is a unilateral hard fork with no announcement.
//!
//! # What is deliberately absent
//!
//! - **Replace-by-fee.** See [`crate::Mempool`].
//! - **A dust threshold.** Dust is the *wallet's* problem — `ferrum-wallet`
//!   refuses to create an output below `3 * min_relay_fee` — and a relay-level
//!   dust rule buys nothing that the fee-rate floor does not already buy,
//!   while making the set of relayable transactions harder to reason about.
//! - **A transaction-version ceiling.** SPEC §10 names the fee floor, the
//!   standard-script set and the orphan/eviction limits, and nothing else.
//!   Inventing extra standardness rules here would make this node's relay
//!   behaviour differ from the specification other implementations read.

use ferrum_script::is_push_only;
use ferrum_script::templates::{ScriptType, classify};
use ferrum_types::{Amount, ChainParams, Transaction};

use crate::error::MempoolError;

/// Default pool ceiling: 8 MiB of transactions (CONTRACT §9).
pub const DEFAULT_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Default orphan-pool ceiling: 200 transactions (CONTRACT §9).
pub const DEFAULT_MAX_ORPHANS: usize = 200;

/// Default expiry: 336 blocks — a fortnight at the 120 s target spacing
/// (CONTRACT §9).
pub const DEFAULT_EXPIRY_BLOCKS: u64 = 336;

/// The denominator of a fee rate: grains **per 1000 bytes** (CONTRACT §9).
///
/// A thousand, not 1024. `min_relay_fee_per_kb` is quoted per 1000 bytes in
/// [`ChainParams`], and having one of the two mean 1024 would make the floor
/// silently 2.4 % off.
pub const FEE_RATE_DIVISOR: u64 = 1_000;

/// The largest transaction this node relays, in bytes.
///
/// A tenth of `max_block_size`, which is Bitcoin Core's ratio and its reason:
/// a single transaction that fills most of a block is a validation-cost
/// hazard for every node that relays it, and there is no legitimate use that
/// cannot be split. It is policy — a 900 kB transaction in a block is valid.
pub const MAX_STANDARD_TX_SIZE: usize = 100_000;

/// Relay policy knobs.
///
/// # Deviation from CONTRACT §9
///
/// The contract lists four fields; this struct carries a fifth, `params`.
/// [`crate::Mempool::new`] takes nothing but a `MempoolConfig`, and acceptance
/// cannot be performed without the chain parameters: script verification needs
/// `chain_id` (a signature valid on testnet must not verify on mainnet), the
/// maturity rule needs `coinbase_maturity`, and the fee floor's default comes
/// from `min_relay_fee_per_kb`. The four contract fields keep their exact
/// names, types and defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolConfig {
    /// Total serialized bytes the pool may hold before evicting.
    pub max_bytes: usize,
    /// How many transactions the orphan pool may hold.
    pub max_orphans: usize,
    /// The relay floor, in grains per 1000 bytes.
    pub min_fee_rate: u64,
    /// How many blocks an entry may sit in the pool before it is expired.
    pub expiry_blocks: u64,
    /// The chain this pool is relaying for.
    pub params: ChainParams,
}

impl MempoolConfig {
    /// Contract defaults for `params`.
    ///
    /// `min_fee_rate` comes from `params.min_relay_fee_per_kb`, so a network
    /// that chose a different floor gets it without a second place to edit.
    #[must_use]
    pub fn new(params: ChainParams) -> Self {
        let min_fee_rate = params.min_relay_fee_per_kb.to_grains();
        MempoolConfig {
            max_bytes: DEFAULT_MAX_BYTES,
            max_orphans: DEFAULT_MAX_ORPHANS,
            min_fee_rate,
            expiry_blocks: DEFAULT_EXPIRY_BLOCKS,
            params,
        }
    }

    /// Builder: change the pool ceiling.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Builder: change the orphan ceiling.
    #[must_use]
    pub fn with_max_orphans(mut self, max_orphans: usize) -> Self {
        self.max_orphans = max_orphans;
        self
    }

    /// Builder: change the relay floor, in grains per 1000 bytes.
    #[must_use]
    pub fn with_min_fee_rate(mut self, min_fee_rate: u64) -> Self {
        self.min_fee_rate = min_fee_rate;
        self
    }

    /// Builder: change the expiry window, in blocks.
    #[must_use]
    pub fn with_expiry_blocks(mut self, expiry_blocks: u64) -> Self {
        self.expiry_blocks = expiry_blocks;
        self
    }
}

impl Default for MempoolConfig {
    /// Mainnet defaults.
    ///
    /// Mainnet rather than devnet: a configuration mistake that silently
    /// relays under the wrong chain's rules should fail closed on the
    /// strictest parameter set, not the loosest.
    fn default() -> Self {
        MempoolConfig::new(ChainParams::mainnet())
    }
}

/// Fee rate in grains per 1000 bytes: `fee * 1000 / size`, truncating.
///
/// `None` on a zero size — which a real transaction never has — or on
/// overflow, which needs a fee above `2^64 / 1000` grains and is therefore
/// unreachable inside the money range. Both are typed rather than assumed.
///
/// Truncating division, deliberately: rounding up would let a transaction one
/// grain short of the floor pass it.
#[must_use]
pub fn fee_rate(fee: Amount, size: usize) -> Option<u64> {
    let size = u64::try_from(size).ok()?;
    if size == 0 {
        return None;
    }
    fee.to_grains().checked_mul(FEE_RATE_DIVISOR)?.checked_div(size)
}

/// Whether a locking script is one the explorer and wallet can label.
///
/// SPEC §10: "reject non-standard `script_pubkey` types (outside the
/// `classify()` set)". Anything [`classify`] returns
/// [`ScriptType::NonStandard`] for is refused relay — and is still perfectly
/// spendable in a block.
#[must_use]
pub fn is_standard_script_pubkey(script: &ferrum_types::Script) -> bool {
    classify(script) != ScriptType::NonStandard
}

/// The context-free half of acceptance: size and standardness.
///
/// Deliberately *not* included: SPEC §4.1 sanity, which
/// [`ferrum_chain::check_transaction_sanity`] already owns, and which the
/// caller runs first so that a malformed transaction is refused with a
/// consensus-shaped reason.
///
/// # Errors
///
/// [`MempoolError::TooLarge`], [`MempoolError::NonStandardOutput`] or
/// [`MempoolError::NonPushOnlyScriptSig`].
pub fn check_standard(tx: &Transaction, size: usize) -> Result<(), MempoolError> {
    if size > MAX_STANDARD_TX_SIZE {
        return Err(MempoolError::TooLarge { size, max: MAX_STANDARD_TX_SIZE });
    }

    // Push-only unlocking scripts are a consensus rule in Ferrum (SPEC §5.1);
    // checking here means the transaction is refused before the interpreter
    // is started, with a reason that names the input.
    for (input_index, input) in tx.inputs.iter().enumerate() {
        if !is_push_only(&input.script_sig) {
            return Err(MempoolError::NonPushOnlyScriptSig { input_index });
        }
    }

    for (vout, out) in tx.outputs.iter().enumerate() {
        if !is_standard_script_pubkey(&out.script_pubkey) {
            return Err(MempoolError::NonStandardOutput { vout });
        }
    }

    Ok(())
}
