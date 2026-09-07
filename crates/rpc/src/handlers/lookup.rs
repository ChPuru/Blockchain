//! Chain lookups shared by the JSON-RPC and REST handlers.
//!
//! Every function here is synchronous and touches the store, so every caller
//! is inside [`crate::context::blocking`].
//!
//! # Resolving a spent output
//!
//! A confirmed transaction's inputs no longer exist in the UTXO set — that is
//! what "spent" means — so the value and script behind an input have to come
//! from the funding transaction itself. [`resolve_prevout`] tries the UTXO set
//! first (which answers for a *mempool* transaction, whose inputs are still
//! unspent) and falls back to the reverse index. A node without the index
//! cannot answer at all, and says so by returning `None` rather than by
//! reporting a zero it invented.

use ferrum_storage::{BlockIndexEntry, header_hash, txid as compute_txid};
use ferrum_types::{Block, BlockHash, Coin, OutPoint, Script, Transaction, Txid};

use crate::error::{RpcError, RpcErrorCode};
use crate::handlers::convert;
use crate::provider::ChainProvider;

/// How many blocks the explorer's home page lists.
pub const RECENT_BLOCKS: usize = 10;

/// How many transactions the explorer's home page lists.
pub const RECENT_TXS: usize = 10;

/// How many history rows an address page *renders*.
///
/// This caps the list the explorer draws, never the walk that produces the
/// balance. Those two limits used to be one, which meant an address with more
/// than this many transactions — any devnet miner within a minute — reported a
/// balance computed from its oldest thousand rows and an `immature` of zero,
/// because the maturity window is by definition the newest rows and was
/// exactly what got dropped. Truncating a rendered list is a UI decision;
/// truncating a balance is a wrong number.
pub const ADDRESS_HISTORY_LIMIT: usize = 1_000;

/// How many rows one chunk of the full-history walk asks for.
///
/// Large enough that a whole block's worth of entries for one address is
/// normally a single round trip, small enough that a huge address does not
/// materialise its entire history in one allocation.
pub const ADDRESS_SCAN_CHUNK: usize = 1_000;

/// Hard ceiling on the full-history walk behind a balance.
///
/// An address query must be bounded or it is a denial-of-service vector, so
/// the walk stops here. Unlike the old silent truncation the caller is *told*:
/// [`crate::handlers::address::AddressReport::complete`] goes false, and the
/// balance is reported as partial rather than as fact.
pub const ADDRESS_SCAN_LIMIT: usize = 250_000;

/// How far forward [`find_spender`] will look for the transaction that spent
/// an output.
///
/// There is no spend index — `addr_index` maps an address to the transactions
/// that touch it, not an outpoint to its spender — so the spender is found by
/// walking that address's history forward from the funding height. The cap
/// keeps a heavily-used address from turning one page view into a full scan;
/// beyond it the explorer reports the output as unspent-unknown rather than
/// stalling.
pub const SPEND_SCAN_LIMIT: usize = 500;

/// A transaction plus where it was confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedTx {
    /// The transaction.
    pub tx: Transaction,
    /// Its id.
    pub txid: Txid,
    /// The block that contains it.
    pub block_hash: BlockHash,
    /// That block's height.
    pub height: u64,
    /// Its position in `block.txs`; `0` is the coinbase.
    pub index: u32,
    /// That block's timestamp, Unix milliseconds.
    pub timestamp_ms: u64,
}

/// The block index entry for `hash`, or [`RpcErrorCode::NotFound`].
///
/// # Errors
/// [`RpcErrorCode::NotFound`] when the store has never seen the hash.
pub fn entry_or_not_found(
    chain: &dyn ChainProvider,
    hash: &BlockHash,
) -> Result<BlockIndexEntry, RpcError> {
    chain
        .header_entry(hash)?
        .ok_or_else(|| RpcError::not_found(format!("no block {}", hash.to_hex())))
}

/// Whether `hash` is the active-chain block at `height`.
///
/// # Errors
/// Storage failures.
pub fn on_active_chain(
    chain: &dyn ChainProvider,
    hash: &BlockHash,
    height: u64,
) -> Result<bool, RpcError> {
    Ok(chain.hash_at_height(height)?.as_ref() == Some(hash))
}

/// The active-chain block after `height`, if there is one.
///
/// # Errors
/// Storage failures.
pub fn next_hash(
    chain: &dyn ChainProvider,
    height: u64,
    active: bool,
) -> Result<Option<BlockHash>, RpcError> {
    if !active {
        return Ok(None);
    }
    chain.hash_at_height(height.saturating_add(1))
}

/// Resolve `"12"` or a 64-hex block hash to a stored block hash.
///
/// The explorer's search box hands the server whatever the reader typed, so
/// both forms have to work on the same route.
///
/// # Errors
/// [`RpcErrorCode::HeightOutOfRange`] for a height past the tip,
/// [`RpcErrorCode::NotFound`] for an unknown hash, and
/// [`RpcErrorCode::InvalidHash`] for something that is neither.
pub fn resolve_block_id(chain: &dyn ChainProvider, id: &str) -> Result<BlockHash, RpcError> {
    if let Ok(height) = id.parse::<u64>() {
        return chain.hash_at_height(height)?.ok_or_else(|| {
            RpcError::new(RpcErrorCode::HeightOutOfRange, format!("no block at height {height}"))
        });
    }
    let hash = BlockHash(crate::error::parse_hash32(id)?);
    if chain.header_entry(&hash)?.is_none() {
        return Err(RpcError::not_found(format!("no block {}", hash.to_hex())));
    }
    Ok(hash)
}

/// A confirmed transaction by id. Needs the reverse index.
///
/// # Errors
/// [`RpcErrorCode::IndexDisabled`] without the index, and
/// [`RpcErrorCode::StorageFailure`] when the index points at a block the store
/// does not have — which means the database is inconsistent, not that the
/// transaction is missing.
pub fn find_transaction(
    chain: &dyn ChainProvider,
    txid: &Txid,
) -> Result<Option<ConfirmedTx>, RpcError> {
    let Some(location) = chain.tx_location(txid)? else {
        return Ok(None);
    };
    let Some(block) = chain.block(&location.block_hash)? else {
        return Err(RpcError::new(
            RpcErrorCode::StorageFailure,
            format!(
                "tx_index names block {} which the store does not hold",
                location.block_hash.to_hex()
            ),
        ));
    };
    let entry = entry_or_not_found(chain, &location.block_hash)?;
    let index = usize::try_from(location.index).unwrap_or(usize::MAX);
    let Some(tx) = block.txs.get(index).cloned() else {
        return Err(RpcError::new(
            RpcErrorCode::StorageFailure,
            format!("tx_index names position {index} in a block with {} txs", block.txs.len()),
        ));
    };
    Ok(Some(ConfirmedTx {
        txid: *txid,
        tx,
        block_hash: location.block_hash,
        height: entry.height,
        index: location.index,
        timestamp_ms: entry.header.timestamp_ms,
    }))
}

/// The coin an input spends: from the UTXO set if it is still unspent, from the
/// funding transaction otherwise.
///
/// # Errors
/// Storage failures. A missing index is *not* an error here — it yields `None`,
/// because half a transaction page beats none.
pub fn resolve_prevout(
    chain: &dyn ChainProvider,
    out_point: &OutPoint,
) -> Result<Option<Coin>, RpcError> {
    if out_point.is_null() {
        return Ok(None);
    }
    if let Some(coin) = chain.coin(out_point)? {
        return Ok(Some(coin));
    }
    if !chain.index_enabled() {
        return Ok(None);
    }
    let Some(found) = find_transaction(chain, &out_point.txid)? else {
        return Ok(None);
    };
    let vout = usize::try_from(out_point.vout).unwrap_or(usize::MAX);
    let Some(output) = found.tx.outputs.get(vout) else {
        return Ok(None);
    };
    Ok(Some(Coin {
        value: output.value,
        script_pubkey: output.script_pubkey.clone(),
        height: found.height,
        is_coinbase: found.tx.is_coinbase(),
    }))
}

/// [`resolve_prevout`] for every input, in order.
///
/// # Errors
/// Storage failures.
pub fn resolve_prevouts(
    chain: &dyn ChainProvider,
    tx: &Transaction,
) -> Result<Vec<Option<Coin>>, RpcError> {
    let mut out = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        out.push(resolve_prevout(chain, &input.prev_out)?);
    }
    Ok(out)
}

/// The transaction that spent `out_point`, if it can be found.
///
/// `None` means "still unspent, or beyond [`SPEND_SCAN_LIMIT`]". The caller
/// distinguishes the two by checking the UTXO set first, which is cheap.
///
/// # Errors
/// Storage failures. A missing index yields `None`.
pub fn find_spender(
    chain: &dyn ChainProvider,
    out_point: &OutPoint,
    funding_script: &Script,
    from_height: u64,
) -> Result<Option<Txid>, RpcError> {
    if !chain.index_enabled() {
        return Ok(None);
    }
    let mut scanned = 0usize;
    for key in ferrum_storage::address_keys(funding_script) {
        if scanned >= SPEND_SCAN_LIMIT {
            break;
        }
        let remaining = SPEND_SCAN_LIMIT.saturating_sub(scanned);
        let history = chain.address_history(&key, from_height, remaining)?;
        for (_, candidate) in history {
            scanned = scanned.saturating_add(1);
            if candidate == out_point.txid {
                continue;
            }
            let Some(found) = find_transaction(chain, &candidate)? else {
                continue;
            };
            if found.tx.inputs.iter().any(|i| i.prev_out == *out_point) {
                return Ok(Some(candidate));
            }
        }
    }
    Ok(None)
}

/// The active-chain blocks from the tip downwards, newest first.
///
/// # Errors
/// Storage failures.
pub fn recent_blocks(chain: &dyn ChainProvider, count: usize) -> Result<Vec<Block>, RpcError> {
    let (_, tip_height) = chain.tip()?;
    let mut out = Vec::new();
    let mut height = tip_height;
    while out.len() < count {
        let Some(hash) = chain.hash_at_height(height)? else {
            break;
        };
        let Some(block) = chain.block(&hash)? else {
            break;
        };
        out.push(block);
        if height == 0 {
            break;
        }
        height = height.saturating_sub(1);
    }
    Ok(out)
}

/// The id of a transaction, computed the one way the chain computes it.
#[must_use]
pub fn txid_of(tx: &Transaction) -> Txid {
    compute_txid(tx)
}

/// The hash of a header, computed the one way the chain computes it.
#[must_use]
pub fn hash_of(header: &ferrum_types::BlockHeader) -> BlockHash {
    header_hash(header)
}

/// A block's entry, header hash, and whether it is on the active chain.
///
/// The three facts every block-shaped response needs, fetched once.
///
/// # Errors
/// [`RpcErrorCode::NotFound`] for an unknown hash, storage failures otherwise.
pub fn block_position(
    chain: &dyn ChainProvider,
    hash: &BlockHash,
) -> Result<(BlockIndexEntry, bool, u64), RpcError> {
    let entry = entry_or_not_found(chain, hash)?;
    let active = on_active_chain(chain, hash, entry.height)?;
    let (_, tip_height) = chain.tip()?;
    let confirmations = convert::confirmations(tip_height, entry.height, active);
    Ok((entry, active, confirmations))
}
