//! The JSON-RPC data-transfer objects (CONTRACT §11).
//!
//! One struct per response shape named in the contract. Field names are the
//! contract's; anything extra is additive and documented as such, because a
//! client that ignores unknown fields keeps working and a client that misses a
//! renamed one does not.

use serde::{Deserialize, Serialize};

use crate::types::{Grains, U64String};

/// `getblockchaininfo`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockchainInfo {
    /// Network name: `mainnet`, `testnet` or `devnet`.
    pub chain: String,
    /// Height of the active tip.
    pub height: u64,
    /// Hash of the active tip, lowercase hex in natural byte order.
    pub best_hash: String,
    /// Cumulative work at the tip, 64 hex characters, big-endian.
    pub total_work: String,
    /// Difficulty relative to `pow_limit`, to three decimal places.
    ///
    /// A decimal **string** assembled from integer arithmetic: floats are
    /// denied workspace-wide, and a number this visible should not be the one
    /// exception.
    pub difficulty: String,
    /// The engine sealing blocks at this height: `pow` or `bft`.
    pub engine: String,
    /// Height below which reorgs are impossible, or `null` under PoW.
    pub finalized_height: Option<u64>,
    /// Transactions in the mempool.
    pub mempool_size: usize,
    /// Entries in the UTXO set.
    pub utxo_count: u64,
    /// The chain id bound into every signature. Additive.
    pub chain_id: u32,
    /// Whether the reverse index is maintained. Additive.
    pub index_enabled: bool,
}

/// The six header fields, plus the hash they produce.
///
/// `bits` stays a JSON number because `explorer/index.html` renders it with
/// `(h.bits >>> 0).toString(16)`. `nonce` is a string because a miner can
/// drive a `u64` nonce past `2^53`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeaderJson {
    /// `tagged_hash(TAG_HEADER, header_bytes)`, hex.
    pub hash: String,
    /// Header version.
    pub version: u32,
    /// Parent block hash, hex.
    pub prev_hash: String,
    /// Merkle root over the transaction ids, hex.
    pub merkle_root: String,
    /// Unix milliseconds.
    pub timestamp_ms: u64,
    /// Compact target.
    pub bits: u32,
    /// The nonce, as a decimal string.
    pub nonce: U64String,
}

/// `getblockheader`: the header plus where it sits.
///
/// The six header fields are repeated here rather than nested behind
/// `#[serde(flatten)]`. Flatten makes serde buffer the whole object through an
/// intermediate representation that names every scalar type serde knows,
/// including the floating-point ones `clippy.toml` denies workspace-wide, and
/// it costs an allocation per response. A handful of duplicated field
/// declarations is the cheaper trade.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeaderInfo {
    /// `tagged_hash(TAG_HEADER, header_bytes)`, hex.
    pub hash: String,
    /// Header version.
    pub version: u32,
    /// Parent block hash, hex.
    pub prev_hash: String,
    /// Merkle root over the transaction ids, hex.
    pub merkle_root: String,
    /// Unix milliseconds.
    pub timestamp_ms: u64,
    /// Compact target.
    pub bits: u32,
    /// The nonce, as a decimal string.
    pub nonce: U64String,
    /// Height on the chain this header belongs to.
    pub height: u64,
    /// Expanded target, 64 hex characters, big-endian.
    pub target: String,
    /// Difficulty relative to `pow_limit`, three decimal places.
    pub difficulty: String,
    /// Cumulative work through this header, 64 hex characters.
    pub total_work: String,
    /// Blocks on top of this one, including itself; `0` when it is not on the
    /// active chain.
    pub confirmations: u64,
    /// The next block on the active chain, if there is one.
    pub next_hash: Option<String>,
    /// The engine that sealed it: `pow` or `bft`.
    pub engine: String,
}

/// Either the transaction ids or the whole transactions, by verbosity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BlockTxList {
    /// Verbosity 1: identifiers only.
    Ids(Vec<String>),
    /// Verbosity 2: fully decoded.
    Full(Vec<TransactionJson>),
}

/// `getblock` with verbosity 1 or 2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockJson {
    /// Block hash, hex.
    pub hash: String,
    /// Height on the chain this block belongs to.
    pub height: u64,
    /// `borsh(Block)` length in bytes.
    pub size: usize,
    /// The engine that sealed it.
    pub engine: String,
    /// Seal payload, hex; empty under proof of work.
    pub seal: String,
    /// Cumulative work through this block, 64 hex characters.
    pub total_work: String,
    /// Blocks on top of this one, including itself.
    pub confirmations: u64,
    /// The next block on the active chain, if there is one.
    pub next_hash: Option<String>,
    /// The header.
    pub header: BlockHeaderJson,
    /// Number of transactions.
    pub tx_count: usize,
    /// Transaction ids or full transactions, by verbosity.
    pub txs: BlockTxList,
}

/// `getblock`: raw hex at verbosity 0, an object above it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetBlockResult {
    /// Verbosity 0: `borsh(Block)` as hex.
    Hex(String),
    /// Verbosity 1 or 2.
    Verbose(Box<BlockJson>),
}

/// One transaction input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInJson {
    /// True for the single input of a coinbase.
    pub coinbase: bool,
    /// The funding transaction, or `null` on a coinbase.
    pub txid: Option<String>,
    /// The funding output index, or `null` on a coinbase.
    pub vout: Option<u32>,
    /// The unlocking script, hex.
    pub script_sig: String,
    /// The sequence number.
    pub sequence: u32,
}

/// One transaction output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutJson {
    /// Position within `outputs`.
    pub n: u32,
    /// Value in grains, as a string.
    pub value: Grains,
    /// The locking script, hex.
    pub script_pubkey: String,
    /// What the locking script is: `p2pkh`, `p2sh`, `multisig 2-of-3`, ...
    pub script_type: String,
    /// The bech32m address, when the script has one.
    pub address: Option<String>,
}

/// A decoded transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionJson {
    /// `tagged_hash(TAG_TXID, type_byte || borsh(tx))`, hex.
    pub txid: String,
    /// Transaction version.
    pub version: u32,
    /// Absolute lock time: a height below `LOCKTIME_THRESHOLD`, else Unix
    /// seconds.
    pub lock_time: u32,
    /// Envelope size in bytes.
    pub size: usize,
    /// Whether this is the block's coinbase.
    pub coinbase: bool,
    /// Sum of the outputs, in grains.
    pub value: Grains,
    /// Inputs, in order.
    pub vin: Vec<TxInJson>,
    /// Outputs, in order.
    pub vout: Vec<TxOutJson>,
    /// The block that confirmed it, or `null` while it is in the mempool.
    pub block_hash: Option<String>,
    /// The height it was confirmed at.
    pub height: Option<u64>,
    /// Blocks on top of its block, including its own.
    pub confirmations: Option<u64>,
}

/// `getrawtransaction`: hex by default, decoded when `verbose` is set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetRawTransactionResult {
    /// The transaction envelope as hex.
    Hex(String),
    /// The decoded transaction.
    Verbose(Box<TransactionJson>),
}

/// `gettxout`: one unspent output, or `null`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinJson {
    /// The funding transaction, hex.
    pub txid: String,
    /// The output index.
    pub vout: u32,
    /// Value in grains, as a string.
    pub value: Grains,
    /// Locking script, hex.
    pub script_pubkey: String,
    /// What the locking script is.
    pub script_type: String,
    /// The bech32m address, when the script has one.
    pub address: Option<String>,
    /// The height the output was created at.
    pub height: u64,
    /// Whether it came from a coinbase and is therefore subject to maturity.
    pub is_coinbase: bool,
    /// Blocks on top of the block that created it, including that block.
    pub confirmations: u64,
}

/// `getblocktemplate`.
///
/// A miner grinds `header_hex`: patch the eight little-endian bytes at offset
/// 80, hash with `TAG_HEADER`, compare against `target`. When it wins, rebuild
/// the block from `transactions` in order and call `submitblock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateJson {
    /// Height this template would occupy.
    pub height: u64,
    /// Parent hash, hex.
    pub prev_hash: String,
    /// Header version.
    pub version: u32,
    /// Compact target the block must meet.
    pub bits: u32,
    /// Expanded target, 64 hex characters.
    pub target: String,
    /// The timestamp the template was stamped with, Unix milliseconds. A
    /// miner may raise it; the node re-checks it on `submitblock`.
    pub timestamp_ms: u64,
    /// The Merkle root over the template's transactions.
    pub merkle_root: String,
    /// The 88-byte header, hex, with the nonce at zero.
    pub header_hex: String,
    /// Transaction envelopes in block order; index 0 is the coinbase.
    pub transactions: Vec<String>,
    /// What the coinbase pays: subsidy plus fees.
    pub coinbase_value: Grains,
    /// Fees collected from the included transactions.
    pub total_fees: Grains,
    /// `borsh(Block)` length the assembled block will have.
    pub size: usize,
    /// The engine that must seal it.
    pub engine: String,
}

/// `submitblock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitBlockResult {
    /// Whether the block joined the active chain.
    pub accepted: bool,
    /// One of `extended`, `reorged`, `side_chain`, `duplicate`, `orphan`.
    pub outcome: String,
    /// The block's hash, when the outcome names one.
    pub hash: Option<String>,
}

/// `getmempoolinfo`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolInfo {
    /// Transactions held.
    pub size: usize,
    /// Total serialized bytes held.
    pub bytes: usize,
    /// The configured byte budget.
    pub max_bytes: usize,
    /// The relay floor, in grains per 1000 bytes.
    pub min_fee_rate: u64,
}

/// One mempool entry, for `getrawmempool` with `verbose`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolEntryJson {
    /// Envelope size in bytes.
    pub size: usize,
    /// Fee paid, in grains.
    pub fee: Grains,
    /// Grains per 1000 bytes.
    pub fee_rate: u64,
    /// The tip height when it was accepted.
    pub height: u64,
}

/// `getrawmempool`: ids by default, a map when `verbose` is set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RawMempoolResult {
    /// Transaction ids.
    Ids(Vec<String>),
    /// Transaction id to entry. A `BTreeMap`, so the order is stable.
    Verbose(std::collections::BTreeMap<String, MempoolEntryJson>),
}

/// `getbalance`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressBalance {
    /// Spendable now.
    pub confirmed: Grains,
    /// Coinbase outputs still inside the maturity window.
    pub immature: Grains,
    /// Unspent outputs backing the two figures above.
    pub utxo_count: u64,
}

/// One row of `listunspent`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnspentJson {
    /// `"<txid>:<vout>"`.
    pub outpoint: String,
    /// Value in grains, as a string.
    pub value: Grains,
    /// The height the output was created at.
    pub height: u64,
    /// The locking script, hex.
    pub script: String,
}

/// One row of `getpeerinfo`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerJson {
    /// libp2p identity, base58.
    pub peer_id: String,
    /// Multiaddr of the most recent connection.
    pub address: Option<String>,
    /// Agent string from identify.
    pub agent_version: Option<String>,
    /// Protocol version from identify.
    pub protocol_version: Option<String>,
    /// Round-trip time in **integer** milliseconds.
    pub last_rtt_ms: Option<u64>,
    /// Whether the peer is in the configured static list.
    pub is_static: bool,
}

/// `getnetworkinfo`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInfoJson {
    /// Network name.
    pub chain: String,
    /// The chain id bound into every signature.
    pub chain_id: u32,
    /// libp2p identity of this node.
    pub local_peer_id: String,
    /// The protocol version this build speaks.
    pub protocol_version: String,
    /// Addresses the node is listening on.
    pub listen_addresses: Vec<String>,
    /// Connected peers.
    pub peer_count: usize,
    /// Messages the load-shedding queues have dropped since start.
    pub shed_total: u64,
}
