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
//!
//! # One budget per request, not per row
//!
//! There is no way to read a single confirmed transaction: the reverse index
//! names a `(block, position)` pair and [`ChainProvider::block`] decodes the
//! whole block to get at it. One such read is cheap; the explorer's pages ask
//! for one *per input, per output, per history row*, and a limit that resets
//! for each of those is not a limit — `outputs × SPEND_SCAN_LIMIT` whole-block
//! decodes is an unbounded amount of work behind one unauthenticated `GET`.
//!
//! So every lookup that can read a block body takes a [`BlockReader`], created
//! once per request. It carries two shared allowances — bytes of block body and
//! forward-scan rows — and a small cache, so that resolving thirty inputs that
//! were funded by the same block costs one decode rather than thirty. When an
//! allowance runs out the reader says so ([`BlockReader::truncated`]) and the
//! lookups answer "unknown", which is the same answer a node without the index
//! gives; a caller that reports a balance must pass that through rather than
//! print a number it did not finish computing.

use std::collections::{BTreeMap, VecDeque};

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

/// How far forward [`find_spender`] will look, in total, for the transactions
/// that spent a *request's* outputs.
///
/// There is no spend index — `addr_index` maps an address to the transactions
/// that touch it, not an outpoint to its spender — so the spender is found by
/// walking that address's history forward from the funding height. The cap
/// keeps a heavily-used address from turning one page view into a full scan;
/// beyond it the explorer reports the output as unspent-unknown rather than
/// stalling.
///
/// It is a **per-request** allowance held by [`BlockReader`], deliberately: a
/// transaction with a hundred spent outputs must not cost a hundred scans.
pub const SPEND_SCAN_LIMIT: usize = 500;

/// How many bytes of block body one request may read and decode.
///
/// The unit is bytes rather than blocks because a block is not a fixed amount
/// of work: 64 MiB is roughly sixty-four full mainnet blocks, or a devnet
/// address's entire history. It bounds the cost of any single request without
/// making the common page a lie.
pub const REQUEST_BLOCK_BYTES: usize = 64 * 1024 * 1024;

/// How many decoded block bodies a request keeps in hand.
///
/// Small, and first-in-first-out, because the access pattern that matters is a
/// walk in height order: consecutive history rows and consecutive inputs land
/// in the same handful of blocks. It is also the memory bound —
/// `MAX_CONCURRENT_QUERIES x REQUEST_BLOCK_CACHE x max_block_size` — so it
/// stays small enough that the explorer cannot be the reason a node runs out.
pub const REQUEST_BLOCK_CACHE: usize = 4;

/// What a budgeted block read produced.
#[derive(Clone, Copy, Debug)]
pub enum BlockRead<'b> {
    /// The block body.
    Found(&'b Block),
    /// The store does not hold that block.
    Missing,
    /// This request has spent its budget; the answer is unknown, not absent.
    OverBudget,
}

/// One request's allowance for reading block bodies, plus the blocks it has
/// already read.
///
/// See the module docs for why the allowance belongs to the request rather than
/// to each row of it.
#[derive(Debug)]
pub struct BlockReader<'a> {
    /// The chain underneath.
    chain: &'a dyn ChainProvider,
    /// Bytes of block body this request may still decode.
    bytes_left: usize,
    /// Forward-scan rows this request may still walk.
    spend_rows_left: usize,
    /// Bodies already read, by hash.
    cache: BTreeMap<BlockHash, Block>,
    /// Insertion order, so the cache can drop its oldest entry.
    order: VecDeque<BlockHash>,
    /// Whether any allowance ran out, so an answer is a lower bound.
    truncated: bool,
}

impl<'a> BlockReader<'a> {
    /// A reader with the default allowances.
    #[must_use]
    pub fn new(chain: &'a dyn ChainProvider) -> Self {
        Self::with_budget(chain, REQUEST_BLOCK_BYTES, SPEND_SCAN_LIMIT)
    }

    /// A reader with explicit allowances.
    ///
    /// `block_bytes` is only consulted *before* a read, so a reader built with
    /// any non-zero budget always answers at least one lookup. That is what
    /// keeps "no such transaction" an honest answer rather than a budget
    /// artefact.
    #[must_use]
    pub fn with_budget(
        chain: &'a dyn ChainProvider,
        block_bytes: usize,
        spend_rows: usize,
    ) -> Self {
        BlockReader {
            chain,
            bytes_left: block_bytes,
            spend_rows_left: spend_rows,
            cache: BTreeMap::new(),
            order: VecDeque::new(),
            truncated: false,
        }
    }

    /// The chain this reader reads.
    #[must_use]
    pub fn chain(&self) -> &'a dyn ChainProvider {
        self.chain
    }

    /// Whether an allowance ran out, so what was computed is a lower bound.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Forward-scan rows this request may still walk.
    #[must_use]
    pub const fn spend_rows_left(&self) -> usize {
        self.spend_rows_left
    }

    /// Charge `rows` forward-scan rows to this request.
    pub fn spend_rows(&mut self, rows: usize) {
        self.spend_rows_left = self.spend_rows_left.saturating_sub(rows);
    }

    /// Record that an answer was cut short.
    pub fn mark_truncated(&mut self) {
        self.truncated = true;
    }

    /// A block body, from this request's cache when it has already been read.
    ///
    /// # Errors
    /// Storage failures.
    pub fn read(&mut self, hash: &BlockHash) -> Result<BlockRead<'_>, RpcError> {
        if !self.cache.contains_key(hash) {
            if self.bytes_left == 0 {
                self.truncated = true;
                return Ok(BlockRead::OverBudget);
            }
            let Some(block) = self.chain.block(hash)? else {
                return Ok(BlockRead::Missing);
            };
            self.bytes_left = self.bytes_left.saturating_sub(block.serialized_size());
            while self.order.len() >= REQUEST_BLOCK_CACHE {
                if let Some(oldest) = self.order.pop_front() {
                    self.cache.remove(&oldest);
                } else {
                    break;
                }
            }
            self.order.push_back(*hash);
            self.cache.insert(*hash, block);
        }
        match self.cache.get(hash) {
            Some(block) => Ok(BlockRead::Found(block)),
            // Unreachable: the block was just inserted. `Missing` rather than
            // an `expect`, because a wrong answer here is a 404, not a panic.
            None => Ok(BlockRead::Missing),
        }
    }
}

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
/// `None` means "the index does not name it, or this request has spent its
/// budget". A reader that has not read anything yet always gets to read once
/// (see [`BlockReader::with_budget`]), so the *first* lookup of a request can
/// never answer `None` for the second reason — which is what lets a caller
/// turn it into a 404.
///
/// # Errors
/// [`RpcErrorCode::IndexDisabled`] without the index, and
/// [`RpcErrorCode::StorageFailure`] when the index points at a block the store
/// does not have — which means the database is inconsistent, not that the
/// transaction is missing.
pub fn find_transaction(
    reader: &mut BlockReader<'_>,
    txid: &Txid,
) -> Result<Option<ConfirmedTx>, RpcError> {
    let Some(location) = reader.chain().tx_location(txid)? else {
        return Ok(None);
    };
    let index = usize::try_from(location.index).unwrap_or(usize::MAX);
    let tx = match reader.read(&location.block_hash)? {
        BlockRead::Found(block) => match block.txs.get(index) {
            Some(tx) => tx.clone(),
            None => {
                return Err(RpcError::new(
                    RpcErrorCode::StorageFailure,
                    format!(
                        "tx_index names position {index} in a block with {} txs",
                        block.txs.len()
                    ),
                ));
            }
        },
        BlockRead::Missing => {
            return Err(RpcError::new(
                RpcErrorCode::StorageFailure,
                format!(
                    "tx_index names block {} which the store does not hold",
                    location.block_hash.to_hex()
                ),
            ));
        }
        // Out of budget is "I did not look", not "it is not there".
        BlockRead::OverBudget => return Ok(None),
    };
    let entry = entry_or_not_found(reader.chain(), &location.block_hash)?;
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
    reader: &mut BlockReader<'_>,
    out_point: &OutPoint,
) -> Result<Option<Coin>, RpcError> {
    if out_point.is_null() {
        return Ok(None);
    }
    if let Some(coin) = reader.chain().coin(out_point)? {
        return Ok(Some(coin));
    }
    if !reader.chain().index_enabled() {
        return Ok(None);
    }
    let Some(found) = find_transaction(reader, &out_point.txid)? else {
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
    reader: &mut BlockReader<'_>,
    tx: &Transaction,
) -> Result<Vec<Option<Coin>>, RpcError> {
    let mut out = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        out.push(resolve_prevout(reader, &input.prev_out)?);
    }
    Ok(out)
}

/// The transaction that spent `out_point`, if it can be found.
///
/// `None` means "still unspent, or beyond what this request may scan". The
/// caller distinguishes the first case by checking the UTXO set first, which is
/// cheap.
///
/// The scan draws on the *request's* remaining [`SPEND_SCAN_LIMIT`] rows, so a
/// transaction with a hundred spent outputs costs one scan between them rather
/// than a hundred scans. Outputs later in such a page report their spender as
/// unknown, which the page already renders as "no known spender".
///
/// # Errors
/// Storage failures. A missing index yields `None`.
pub fn find_spender(
    reader: &mut BlockReader<'_>,
    out_point: &OutPoint,
    funding_script: &Script,
    from_height: u64,
) -> Result<Option<Txid>, RpcError> {
    if !reader.chain().index_enabled() {
        return Ok(None);
    }
    for key in ferrum_storage::address_keys(funding_script) {
        let remaining = reader.spend_rows_left();
        if remaining == 0 {
            reader.mark_truncated();
            return Ok(None);
        }
        let history = reader.chain().address_history(&key, from_height, remaining)?;
        for (_, candidate) in history {
            // Charge a row when it is *examined*, not when it is fetched: the
            // scan usually finds its spender in the first row or two, and
            // billing the whole fetched chunk would let one output's lucky hit
            // exhaust the page's allowance for every output after it.
            if reader.spend_rows_left() == 0 {
                reader.mark_truncated();
                return Ok(None);
            }
            reader.spend_rows(1);
            if candidate == out_point.txid {
                continue;
            }
            let Some(found) = find_transaction(reader, &candidate)? else {
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
