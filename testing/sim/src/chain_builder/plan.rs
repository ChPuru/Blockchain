//! What the factory is asked to build: a spendable coin, a transaction plan
//! and a block plan.
//!
//! Every field of [`BlockPlan`] is an `Option` or a delta, and every `None`
//! means "the value an honest miner would use". A scenario therefore states
//! only the one thing it is changing — a timestamp, a target, a coinbase
//! claiming one grain too much — and everything else stays correct. That is
//! what keeps a fixture down to a single defect, which is what makes the
//! differential test able to name the rule that was broken.

use ferrum_script::sighash::SigHashType;
use ferrum_types::{
    Amount, BlockHash, BlockSeal, Coin, CompactTarget, Hash32, OutPoint, Transaction,
};

use crate::keys::Lock;

/// The default `sequence` the factory puts on an input.
///
/// One below `SEQUENCE_FINAL`, so `lock_time` and `OP_CHECKLOCKTIMEVERIFY` are
/// both enforceable. A fully final sequence opts the input out of locktime
/// entirely, which would silently disarm every timelock fixture.
pub const DEFAULT_SEQUENCE: u32 = 0xffff_fffe;

/// An unspent output the factory knows how to spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendableCoin {
    /// Where it lives.
    pub out_point: OutPoint,
    /// Its value, script, height and coinbase flag.
    pub coin: Coin,
    /// How it is locked, and therefore how it is unlocked.
    pub lock: Lock,
}

impl SpendableCoin {
    /// Whether this coin may be spent in a block at `height`.
    #[must_use]
    pub fn is_mature(&self, height: u64, maturity: u64) -> bool {
        !self.coin.is_coinbase || height >= self.coin.height.saturating_add(maturity)
    }
}

/// What one transaction should look like.
#[derive(Clone, Debug)]
pub struct TxPlan {
    /// The coins to spend, in input order.
    pub inputs: Vec<SpendableCoin>,
    /// Where the money goes, in output order.
    pub outputs: Vec<(Lock, Amount)>,
    /// The transaction's `lock_time`.
    pub lock_time: u32,
    /// The `sequence` every input carries.
    pub sequence: u32,
    /// The transaction version.
    pub version: u32,
    /// Which sighash flavour every signature commits to.
    pub sighash_type: SigHashType,
}

impl Default for TxPlan {
    fn default() -> Self {
        TxPlan {
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            sequence: DEFAULT_SEQUENCE,
            version: 1,
            sighash_type: SigHashType::ALL,
        }
    }
}

impl TxPlan {
    /// Spend `inputs`, paying everything but `fee` to `to`.
    #[must_use]
    pub fn sweep(inputs: Vec<SpendableCoin>, to: Lock, fee: Amount) -> Self {
        let total = inputs.iter().fold(Amount::ZERO, |acc, c| acc.saturating_add(c.coin.value));
        TxPlan { inputs, outputs: vec![(to, total.saturating_sub(fee))], ..TxPlan::default() }
    }

    /// The total value of the coins this plan spends.
    #[must_use]
    pub fn input_total(&self) -> Amount {
        self.inputs.iter().fold(Amount::ZERO, |acc, c| acc.saturating_add(c.coin.value))
    }
}

/// What one block should look like. Every `None` means "the obvious value".
#[derive(Clone, Debug)]
pub struct BlockPlan {
    /// The non-coinbase transactions, in block order.
    pub txs: Vec<Transaction>,
    /// Override the coinbase entirely.
    pub coinbase: Option<Transaction>,
    /// Where the coinbase pays; defaults to key 0's P2PKH.
    pub payout: Option<Lock>,
    /// Extra grains claimed above `subsidy + fees`. `1` is the
    /// overpay-by-one-grain attack.
    pub coinbase_bonus: u64,
    /// Grains the coinbase deliberately leaves unclaimed (burned).
    pub coinbase_burn: u64,
    /// Bytes appended to the BIP-34 height push in the coinbase `script_sig`.
    pub coinbase_extra: Option<Vec<u8>>,
    /// Override the header version.
    pub version: Option<u32>,
    /// Override the header timestamp.
    pub timestamp_ms: Option<u64>,
    /// Override the header target.
    pub bits: Option<CompactTarget>,
    /// Override the parent.
    pub prev_hash: Option<BlockHash>,
    /// Override the height the coinbase commits to.
    pub height: Option<u64>,
    /// Override the Merkle root, breaking the commitment on purpose.
    pub merkle_root: Option<Hash32>,
    /// Override the seal.
    pub seal: Option<BlockSeal>,
    /// Whether to grind a nonce that satisfies the target.
    pub grind: bool,
}

impl Default for BlockPlan {
    fn default() -> Self {
        BlockPlan {
            txs: Vec::new(),
            coinbase: None,
            payout: None,
            coinbase_bonus: 0,
            coinbase_burn: 0,
            coinbase_extra: None,
            version: None,
            timestamp_ms: None,
            bits: None,
            prev_hash: None,
            height: None,
            merkle_root: None,
            seal: None,
            grind: true,
        }
    }
}

impl BlockPlan {
    /// A plan carrying these transactions.
    #[must_use]
    pub fn with_txs(txs: Vec<Transaction>) -> Self {
        BlockPlan { txs, ..BlockPlan::default() }
    }
}
