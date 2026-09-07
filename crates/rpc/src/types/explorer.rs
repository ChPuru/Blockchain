//! The REST data-transfer objects the explorer page reads.
//!
//! **Every field name here is read by `explorer/index.html`.** That file is the
//! client and it is already written; these structs are the contract with it.
//! Where a comment says "the explorer reads this", renaming the field breaks
//! the page silently — the value simply becomes `undefined` and renders as an
//! empty cell.
//!
//! The mapping, one route at a time:
//!
//! | Route | Struct | What the page does with it |
//! |---|---|---|
//! | `GET /api/stats` | [`StatsResponse`] | the stat strip, both tables, the faucet panel |
//! | `GET /api/block/:height_or_hash` | [`BlockResponse`] | the block page |
//! | `GET /api/tx/:txid` | [`TxResponse`] | the transaction page |
//! | `GET /api/address/:address` | [`AddressResponse`] | the address page |
//! | `GET /api/search?q=` | [`SearchResponse`] | a redirect, or "no match" |
//! | `POST /api/faucet` | [`FaucetRequest`] / [`FaucetResponse`] | the faucet form |

use serde::{Deserialize, Serialize};

use crate::types::rpc::BlockHeaderJson;
use crate::types::{Grains, SignedGrains};

/// `GET /api/stats` — the home page in one request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsResponse {
    /// Network name; the page puts it in the badge next to the logo.
    pub chain: String,
    /// Tip height, a JSON number: the page prints it and links to `height-1`.
    pub height: u64,
    /// Tip hash, hex.
    pub best_hash: String,
    /// Difficulty as a decimal string with three places.
    pub difficulty: String,
    /// `pow` or `bft`; the page upper-cases it.
    pub engine: String,
    /// Transactions in the mempool.
    pub mempool_size: usize,
    /// Entries in the UTXO set.
    pub utxo_count: u64,
    /// Connected peers.
    pub peers: usize,
    /// Newest blocks first.
    pub recent_blocks: Vec<RecentBlock>,
    /// Newest transactions first.
    pub recent_txs: Vec<RecentTx>,
    /// Whether to render the faucet panel at all.
    pub faucet_enabled: bool,
    /// Height below which reorgs are impossible, or `null` under PoW — the
    /// page prints "nothing is ever final" for `null`.
    pub finalized_height: Option<u64>,
    /// Cumulative work at the tip, 64 hex characters. Additive.
    pub total_work: String,
    /// Whether the reverse index is on. Additive: without it the block and
    /// transaction pages will report `index disabled` rather than data.
    pub index_enabled: bool,
}

/// One row of the "Recent blocks" table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentBlock {
    /// Height, a number: the page renders `#{height}` and links by it.
    pub height: u64,
    /// Block hash, hex.
    pub hash: String,
    /// Transactions in the block.
    pub tx_count: u32,
    /// `borsh(Block)` length in bytes.
    pub size: u32,
    /// Unix milliseconds; the page turns it into "3m ago".
    pub timestamp_ms: u64,
}

/// One row of the "Recent transactions" table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentTx {
    /// Transaction id, hex.
    pub txid: String,
    /// Sum of the outputs, grains as a string.
    pub value: Grains,
    /// Fee paid, grains as a string; zero for a coinbase.
    pub fee: Grains,
    /// Confirming height, or `null` for a mempool transaction — the page
    /// renders a "pending" pill for `null`.
    pub height: Option<u64>,
}

/// `GET /api/block/:height_or_hash`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockResponse {
    /// Block hash, hex.
    pub hash: String,
    /// Height, a number: the page computes `height - 1` and `height + 1`.
    pub height: u64,
    /// `borsh(Block)` length in bytes.
    pub size: usize,
    /// `pow` or `bft`; the page upper-cases it into a pill.
    pub engine: String,
    /// Cumulative work through this block, 64 hex characters.
    pub total_work: String,
    /// Blocks on top of this one, including itself.
    pub confirmations: u64,
    /// The next block on the active chain; the page enables "next →" when it
    /// is present.
    pub next_hash: Option<String>,
    /// The six header fields; the page reads `prev_hash`, `merkle_root`,
    /// `timestamp_ms`, `bits`, `nonce` and `version` out of this object.
    pub header: BlockHeaderJson,
    /// The block's transactions, in order.
    pub txs: Vec<BlockTxSummary>,
}

/// One row of a block's transaction table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTxSummary {
    /// Transaction id, hex.
    pub txid: String,
    /// Number of inputs; the page renders "N in".
    pub vin: usize,
    /// Number of outputs.
    pub vout: usize,
    /// Sum of the outputs, grains as a string.
    pub value: Grains,
    /// Fee paid, grains as a string. Zero on the coinbase, which the page
    /// renders as a dash instead.
    pub fee: Grains,
    /// Whether this is the coinbase.
    pub coinbase: bool,
}

/// `GET /api/tx/:txid`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxResponse {
    /// Transaction id, hex.
    pub txid: String,
    /// Transaction version.
    pub version: u32,
    /// Absolute lock time; the page compares it against `LOCKTIME_THRESHOLD`
    /// to decide whether to call it a height or a timestamp, so it must stay a
    /// number.
    pub lock_time: u32,
    /// Envelope size in bytes.
    pub size: usize,
    /// Whether this is a coinbase; the page prints "— (coinbase)" for the fee.
    pub coinbase: bool,
    /// Sum of the outputs, grains as a string.
    pub value: Grains,
    /// Fee paid, grains as a string.
    pub fee: Grains,
    /// Grains per 1000 bytes, or `null` for a coinbase.
    pub fee_rate: Option<u64>,
    /// The confirming block, or `null` while it is in the mempool — the page
    /// switches its status pill on this field.
    pub block_hash: Option<String>,
    /// The confirming height.
    pub height: Option<u64>,
    /// Blocks on top of the confirming block, including it.
    pub confirmations: Option<u64>,
    /// The confirming block's timestamp, Unix milliseconds. Additive.
    pub timestamp_ms: Option<u64>,
    /// Inputs, in order.
    pub inputs: Vec<TxInputView>,
    /// Outputs, in order.
    pub outputs: Vec<TxOutputView>,
}

/// One input, resolved against the funding output where possible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInputView {
    /// True for the single input of a coinbase; the page renders a "newly
    /// minted" pill and nothing else.
    pub coinbase: bool,
    /// The funding transaction, hex, or `null` on a coinbase.
    pub txid: Option<String>,
    /// The funding output index, or `null` on a coinbase.
    pub vout: Option<u32>,
    /// The value being spent, grains as a string. Zero when the funding output
    /// could not be resolved — which only happens without the reverse index.
    pub value: Grains,
    /// The address that funded it, when the funding script has one.
    pub address: Option<String>,
    /// What the funding script was.
    pub script_type: Option<String>,
}

/// One output, with the transaction that spent it if it is spent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutputView {
    /// Position within `outputs`.
    pub n: u32,
    /// Value in grains, as a string.
    pub value: Grains,
    /// The paying address, when the script has one.
    pub address: Option<String>,
    /// What the locking script is; the page shows this when there is no
    /// address.
    pub script_type: String,
    /// The transaction that spent this output, or `null` when it is still
    /// unspent — the page renders an "unspent" pill for `null` and a link
    /// otherwise, so a wrong `null` here is a visible lie.
    pub spent_by: Option<String>,
}

/// `GET /api/address/:address`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressResponse {
    /// The address, re-encoded canonically.
    pub address: String,
    /// `p2pkh` or `p2sh`.
    pub script_type: String,
    /// Spendable now, grains as a string.
    pub confirmed: Grains,
    /// Coinbase outputs still inside the maturity window, grains as a string.
    /// The page shows an explanatory paragraph when this is non-zero, and
    /// compares it against the literal string `"0"`.
    pub immature: Grains,
    /// Unconfirmed credits from the mempool, grains as a string.
    pub pending: Grains,
    /// Unspent outputs paying this address.
    pub utxo_count: u64,
    /// Transactions touching this address.
    pub tx_count: u64,
    /// History, newest first. Capped; `tx_count` is not.
    pub transactions: Vec<AddressTx>,
    /// Whether the balances above cover this address's entire history.
    ///
    /// `false` means the scan limit cut the walk short and every figure here
    /// is a lower bound. The page renders a warning rather than presenting a
    /// partial balance as the balance.
    pub complete: bool,
}

/// One row of an address's history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressTx {
    /// Transaction id, hex.
    pub txid: String,
    /// Confirming height, or `null` for a mempool transaction.
    pub height: Option<u64>,
    /// Net change to this address, signed grains as a string. The page tests
    /// the leading `-` to colour the row, so the sign must be textual.
    pub delta: SignedGrains,
    /// The confirming block's timestamp, Unix milliseconds.
    pub timestamp_ms: Option<u64>,
}

/// `GET /api/search?q=`.
///
/// A miss is a **200** with both fields `null`, not a 404: the page renders its
/// own "nothing matches" panel and treats a non-2xx as a server failure.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchResponse {
    /// `block`, `tx` or `address`; the page navigates to `#/{kind}/{id}`.
    pub kind: Option<String>,
    /// The canonical identifier for that kind.
    pub id: Option<String>,
}

/// `POST /api/faucet` request body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaucetRequest {
    /// The bech32m address to pay.
    pub address: String,
}

/// `POST /api/faucet` success body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaucetResponse {
    /// The payment's transaction id; the page links to it.
    pub txid: String,
    /// What was sent, grains as a string.
    pub amount: Grains,
    /// The address that was paid, re-encoded canonically.
    pub address: String,
}
