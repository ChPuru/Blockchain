//! The `redb`-backed store: blocks, headers, the UTXO set, the undo log and
//! the active-chain head pointer (CONTRACT §7).
//!
//! # The one invariant this file exists to hold
//!
//! **Exactly one write transaction per block, with `meta.tip` written last
//! inside it.** [`Store::connect_block`] and [`Store::disconnect_tip`] each
//! open a single `redb` write transaction, do every mutation the block
//! implies, and set the tip as their final statement before `commit()`.
//!
//! redb commits atomically, so the tip and the UTXO diff land together or
//! neither lands. A store that used two transactions — "apply the diff", then
//! "advance the tip" — would, on a crash between them, come back up with a tip
//! pointing at a height whose diff was only partly applied, and every
//! subsequent block would be validated against a UTXO set that never existed
//! on any chain. That failure is silent, survives restarts, and is only
//! detected when a node's state root diverges from the network's.
//!
//! # Apply order inside a block
//!
//! Connect applies **created outputs first, then spends**; disconnect
//! **restores spends first, then removes created outputs**. The order matters
//! because a block may spend an output it created (a chained transaction), in
//! which case the same outpoint appears in both halves of the
//! [`StateDiff`]. Removing spends before adding creations would leave that
//! outpoint alive — an inflation bug — and the reverse mistake on disconnect
//! would resurrect it.
//!
//! # Everything here is synchronous
//!
//! See the crate-level documentation: an `async fn` must reach these methods
//! through `tokio::task::spawn_blocking`.

use std::collections::BTreeMap;
use std::path::Path;

use ferrum_types::{Block, BlockHash, ChainId, Coin, OutPoint};
use redb::{Database, ReadableTable};

use crate::error::StorageError;
use crate::index;
use crate::tables::{
    ADDR_INDEX, BLOCKS, BlockIndexEntry, HEADERS, HEIGHT, META, META_CHAIN_ID, META_ENGINE,
    META_SCHEMA_VERSION, META_TIP, SCHEMA_VERSION, TX_INDEX, UNDO, UTXO, decode_tip, decode_u32,
    encode_tip, hash_key, height_key, outpoint_key, txid,
};
use crate::undo::UndoBlock;
use crate::view::{StateDiff, StateView};

mod reads;

/// The raw `(key, value)` bytes of a UTXO set, in table order.
pub type UtxoBytes = Vec<(Vec<u8>, Vec<u8>)>;

/// How a [`Store`] is opened.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoreConfig {
    /// Maintain the `tx_index` and `addr_index` reverse index (`chaind --index`).
    ///
    /// Off by default: the index is the explorer's, not consensus's, and a
    /// node without it is fully valid (CONTRACT §7).
    pub index_transactions: bool,
    /// The chain this store must belong to.
    ///
    /// Written into `meta.chain_id` on first open and checked on every later
    /// one, so pointing a mainnet node at a testnet datadir fails immediately
    /// instead of after the first block.
    pub chain_id: Option<ChainId>,
    /// redb read-cache budget in bytes; `None` takes redb's default.
    pub cache_size_bytes: Option<usize>,
}

impl StoreConfig {
    /// A configuration with the reverse index on.
    #[must_use]
    pub fn indexed() -> Self {
        StoreConfig { index_transactions: true, ..Self::default() }
    }

    /// Bind this configuration to a chain id.
    #[must_use]
    pub fn with_chain_id(mut self, id: ChainId) -> Self {
        self.chain_id = Some(id);
        self
    }
}

/// The block store, UTXO set and undo log.
///
/// Every method is synchronous. `Store` is `Send + Sync`; redb serialises
/// writers itself, so callers need no lock of their own.
#[derive(Debug)]
pub struct Store {
    db: Database,
    cfg: StoreConfig,
}

impl Store {
    /// Open (or create) a store at `path`.
    ///
    /// # Errors
    /// Returns [`StorageError::SchemaMismatch`] or
    /// [`StorageError::ChainIdMismatch`] if the database on disk belongs to a
    /// different build or network, and [`StorageError::Db`] for any redb
    /// failure.
    pub fn open(path: &Path, cfg: StoreConfig) -> Result<Self, StorageError> {
        let mut builder = Database::builder();
        if let Some(bytes) = cfg.cache_size_bytes {
            builder.set_cache_size(bytes);
        }
        let db = builder.create(path)?;
        Self::init(db, cfg)
    }

    /// Open a store backed by memory, for tests and dry runs.
    ///
    /// # Errors
    /// Same as [`Store::open`].
    pub fn open_in_memory(cfg: StoreConfig) -> Result<Self, StorageError> {
        let mut builder = Database::builder();
        if let Some(bytes) = cfg.cache_size_bytes {
            builder.set_cache_size(bytes);
        }
        let db = builder.create_with_backend(redb::backends::InMemoryBackend::new())?;
        Self::init(db, cfg)
    }

    /// Create every table and reconcile the metadata.
    ///
    /// Tables are created eagerly because a read transaction against a table
    /// that has never been written fails with `TableDoesNotExist`; creating
    /// them up front turns "empty database" from an error path into the
    /// ordinary path, and error paths that only run once are error paths that
    /// are never tested.
    fn init(db: Database, cfg: StoreConfig) -> Result<Self, StorageError> {
        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(BLOCKS)?;
            let _ = txn.open_table(HEADERS)?;
            let _ = txn.open_table(HEIGHT)?;
            let _ = txn.open_table(UTXO)?;
            let _ = txn.open_table(UNDO)?;
            let _ = txn.open_table(TX_INDEX)?;
            let _ = txn.open_table(ADDR_INDEX)?;

            let mut meta = txn.open_table(META)?;
            match get_bytes(&meta, META_SCHEMA_VERSION)? {
                Some(raw) => {
                    let found = decode_u32("meta.schema_version", &raw)?;
                    if found != SCHEMA_VERSION {
                        return Err(StorageError::SchemaMismatch {
                            expected: SCHEMA_VERSION,
                            found,
                        });
                    }
                }
                None => {
                    meta.insert(META_SCHEMA_VERSION, SCHEMA_VERSION.to_be_bytes().as_slice())?;
                }
            }
            if let Some(want) = cfg.chain_id {
                match get_bytes(&meta, META_CHAIN_ID)? {
                    Some(raw) => {
                        let found = decode_u32("meta.chain_id", &raw)?;
                        if found != want.to_u32() {
                            return Err(StorageError::ChainIdMismatch {
                                expected: want.to_u32(),
                                found,
                            });
                        }
                    }
                    None => {
                        meta.insert(META_CHAIN_ID, want.to_u32().to_be_bytes().as_slice())?;
                    }
                }
            }
        }
        txn.commit()?;
        Ok(Store { db, cfg })
    }

    /// The configuration this store was opened with.
    #[must_use]
    pub fn config(&self) -> &StoreConfig {
        &self.cfg
    }

    /// Whether the reverse index is maintained.
    #[must_use]
    pub fn is_indexed(&self) -> bool {
        self.cfg.index_transactions
    }

    // --------------------------------------------------------------- writes

    /// Store a header index entry. One write transaction.
    ///
    /// # Errors
    /// [`StorageError::Db`] on a redb failure.
    pub fn store_header(&self, e: &BlockIndexEntry) -> Result<(), StorageError> {
        let hash = e.block_hash();
        let bytes = borsh::to_vec(e).map_err(|err| StorageError::corrupt("header", err))?;
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(HEADERS)?;
            t.insert(&hash_key(&hash), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Store a block body. One write transaction.
    ///
    /// # Errors
    /// [`StorageError::Db`] on a redb failure.
    pub fn store_block_body(&self, h: &BlockHash, b: &Block) -> Result<(), StorageError> {
        let bytes = borsh::to_vec(b).map_err(|err| StorageError::corrupt("block", err))?;
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(BLOCKS)?;
            t.insert(&hash_key(h), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Record the consensus engine active at the tip. One write transaction.
    ///
    /// # Errors
    /// [`StorageError::Db`] on a redb failure.
    pub fn set_engine(&self, engine: u8) -> Result<(), StorageError> {
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(META)?;
            t.insert(META_ENGINE, [engine].as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Force everything queued to disk.
    ///
    /// redb's default durability is already `Immediate`, so every commit above
    /// is durable when it returns and this is a no-op commit. It exists so the
    /// node's shutdown path has something honest to call.
    ///
    /// # Errors
    /// [`StorageError::Db`] on a redb failure.
    pub fn flush(&self) -> Result<(), StorageError> {
        let txn = self.db.begin_write()?;
        txn.commit()?;
        Ok(())
    }

    /// Apply `diff`, write the undo record, extend `height`, and set `tip` —
    /// atomically, tip last (CONTRACT §7).
    ///
    /// The block body and its index entry are written here too, so a connected
    /// block is never missing its own body.
    ///
    /// # Errors
    /// - [`StorageError::EntryHeightMismatch`] if `entry.height != height`.
    /// - [`StorageError::NonContiguousConnect`] if `height` is not one past the
    ///   tip (or not `0` on an empty store).
    /// - [`StorageError::ParentMismatch`] if the header does not build on the tip.
    /// - [`StorageError::Db`] / [`StorageError::Corrupt`] on a storage failure.
    pub fn connect_block(
        &self,
        h: &BlockHash,
        height: u64,
        entry: &BlockIndexEntry,
        diff: &StateDiff,
        block: &Block,
    ) -> Result<(), StorageError> {
        if entry.height != height {
            return Err(StorageError::EntryHeightMismatch { entry_height: entry.height, height });
        }
        let block_bytes = borsh::to_vec(block).map_err(|e| StorageError::corrupt("block", e))?;
        let entry_bytes = borsh::to_vec(entry).map_err(|e| StorageError::corrupt("header", e))?;
        let undo = diff.undo_block();
        let undo_bytes = borsh::to_vec(&undo).map_err(|e| StorageError::corrupt("undo", e))?;

        let txn = self.db.begin_write()?;
        // The contiguity check reads the tip *inside* the write transaction:
        // reading it from a separate read transaction would leave a window in
        // which another writer advanced the tip between check and use.
        {
            let meta = txn.open_table(META)?;
            match get_bytes(&meta, META_TIP)? {
                None => {
                    if height != 0 {
                        return Err(StorageError::NonContiguousConnect {
                            tip_height: u64::MAX,
                            height,
                        });
                    }
                }
                Some(raw) => {
                    let (tip_hash, tip_height) = decode_tip(&raw)?;
                    if tip_height.checked_add(1) != Some(height) {
                        return Err(StorageError::NonContiguousConnect { tip_height, height });
                    }
                    if entry.header.prev_hash != tip_hash {
                        return Err(StorageError::ParentMismatch {
                            tip: tip_hash,
                            prev: entry.header.prev_hash,
                        });
                    }
                }
            }
        }

        {
            let mut blocks = txn.open_table(BLOCKS)?;
            blocks.insert(&hash_key(h), block_bytes.as_slice())?;
            let mut headers = txn.open_table(HEADERS)?;
            headers.insert(&hash_key(h), entry_bytes.as_slice())?;
            let mut undo_table = txn.open_table(UNDO)?;
            undo_table.insert(&hash_key(h), undo_bytes.as_slice())?;
            let mut heights = txn.open_table(HEIGHT)?;
            heights.insert(&height_key(height), &hash_key(h))?;

            let mut utxo = txn.open_table(UTXO)?;
            // Creations first, then spends: a block may spend an output it
            // created, and that outpoint is in both halves of the diff.
            for (op, coin) in &diff.created {
                let bytes = borsh::to_vec(coin).map_err(|e| StorageError::corrupt("coin", e))?;
                utxo.insert(&outpoint_key(op), bytes.as_slice())?;
            }
            for (op, _) in &diff.spent {
                utxo.remove(&outpoint_key(op))?;
            }
        }

        if self.cfg.index_transactions {
            let spent = spent_map(&diff.spent);
            index::index_block(&txn, h, height, block, &spent)?;
        }

        // Tip last, inside this same transaction. Nothing below this line.
        {
            let mut meta = txn.open_table(META)?;
            meta.insert(META_ENGINE, [entry.seal_engine].as_slice())?;
            meta.insert(META_TIP, encode_tip(h, height).as_slice())?;
        }
        txn.commit()?;

        tracing::debug!(
            hash = %h, height, created = diff.created.len(), spent = diff.spent.len(),
            "connected block"
        );
        Ok(())
    }

    /// Reverse the tip block using its stored undo record, returning the hash
    /// of the block that was disconnected.
    ///
    /// Guarantees a byte-identical UTXO set: the restored coins come from the
    /// undo record verbatim, and the created outputs are removed by outpoint.
    ///
    /// # Errors
    /// - [`StorageError::NoTip`] on an empty store.
    /// - [`StorageError::CannotDisconnectGenesis`] at height 0.
    /// - [`StorageError::MissingBlock`] / [`StorageError::MissingUndo`] if the
    ///   records needed to reverse the block are absent.
    pub fn disconnect_tip(&self) -> Result<BlockHash, StorageError> {
        let txn = self.db.begin_write()?;

        let (tip_hash, tip_height) = {
            let meta = txn.open_table(META)?;
            let raw = get_bytes(&meta, META_TIP)?.ok_or(StorageError::NoTip)?;
            decode_tip(&raw)?
        };
        if tip_height == 0 {
            return Err(StorageError::CannotDisconnectGenesis);
        }

        let block: Block = {
            let blocks = txn.open_table(BLOCKS)?;
            decode_opt("block", blocks.get(&hash_key(&tip_hash))?.map(|g| g.value().to_vec()))?
                .ok_or(StorageError::MissingBlock(tip_hash))?
        };
        let undo: UndoBlock = {
            let undos = txn.open_table(UNDO)?;
            decode_opt("undo", undos.get(&hash_key(&tip_hash))?.map(|g| g.value().to_vec()))?
                .ok_or(StorageError::MissingUndo(tip_hash))?
        };

        let parent = block.header.prev_hash;
        let parent_height = tip_height.saturating_sub(1);

        {
            let mut utxo = txn.open_table(UTXO)?;
            // Restore spends first, then remove creations — the exact inverse
            // of connect, so an output created and spent inside this block
            // ends up absent rather than resurrected.
            for uc in &undo.spent {
                let bytes =
                    borsh::to_vec(&uc.coin).map_err(|e| StorageError::corrupt("coin", e))?;
                utxo.insert(&outpoint_key(&uc.out_point), bytes.as_slice())?;
            }
            for op in created_outpoints(&block)? {
                utxo.remove(&outpoint_key(&op))?;
            }

            let mut heights = txn.open_table(HEIGHT)?;
            heights.remove(&height_key(tip_height))?;
        }

        if self.cfg.index_transactions {
            let spent: BTreeMap<OutPoint, Coin> =
                undo.spent.iter().map(|u| (u.out_point, u.coin.clone())).collect();
            index::unindex_block(&txn, tip_height, &block, &spent)?;
        }

        // The parent's engine, so `meta.engine` tracks the tip across the
        // PoW→BFT boundary in both directions.
        let parent_engine = {
            let headers = txn.open_table(HEADERS)?;
            decode_opt::<BlockIndexEntry>(
                "header",
                headers.get(&hash_key(&parent))?.map(|g| g.value().to_vec()),
            )?
            .map(|e| e.seal_engine)
        };

        // Tip last, inside this same transaction. Nothing below this line.
        {
            let mut meta = txn.open_table(META)?;
            if let Some(engine) = parent_engine {
                meta.insert(META_ENGINE, [engine].as_slice())?;
            }
            meta.insert(META_TIP, encode_tip(&parent, parent_height).as_slice())?;
        }
        txn.commit()?;

        // `info!`, not `debug!`: a disconnect is rare and significant, and
        // CONTRACT §13.1 requires a completed reorg to leave a line matching
        // /reorg|disconnect|rolled back|new tip/i for `devnet/heal.sh` to grep.
        // A connect logs at `debug!` because it happens every block.
        tracing::info!(
            hash = %tip_hash, height = tip_height, restored = undo.len(),
            "disconnected tip; new tip {} at height {}", parent, parent_height
        );
        Ok(tip_hash)
    }

    /// The raw database, so the ordering suite can drive `redb` directly and
    /// prove that big-endian keys really do scan in numeric order.
    #[cfg(test)]
    pub(crate) fn database(&self) -> &Database {
        &self.db
    }

    fn require_index(&self) -> Result<(), StorageError> {
        if self.cfg.index_transactions { Ok(()) } else { Err(StorageError::IndexDisabled) }
    }

    /// Every write [`Store::connect_block`] performs, followed by dropping the
    /// transaction **without committing** — a crash between the first write and
    /// the commit.
    ///
    /// Exists so the crash-consistency suite can prove that a half-written
    /// block leaves no trace, rather than assuming redb's atomicity.
    #[cfg(test)]
    pub(crate) fn connect_block_then_crash(
        &self,
        h: &BlockHash,
        height: u64,
        entry: &BlockIndexEntry,
        diff: &StateDiff,
        block: &Block,
    ) -> Result<(), StorageError> {
        let block_bytes = borsh::to_vec(block).map_err(|e| StorageError::corrupt("block", e))?;
        let entry_bytes = borsh::to_vec(entry).map_err(|e| StorageError::corrupt("header", e))?;
        let undo_bytes =
            borsh::to_vec(&diff.undo_block()).map_err(|e| StorageError::corrupt("undo", e))?;
        let txn = self.db.begin_write()?;
        {
            let mut blocks = txn.open_table(BLOCKS)?;
            blocks.insert(&hash_key(h), block_bytes.as_slice())?;
            let mut headers = txn.open_table(HEADERS)?;
            headers.insert(&hash_key(h), entry_bytes.as_slice())?;
            let mut undo_table = txn.open_table(UNDO)?;
            undo_table.insert(&hash_key(h), undo_bytes.as_slice())?;
            let mut heights = txn.open_table(HEIGHT)?;
            heights.insert(&height_key(height), &hash_key(h))?;
            let mut utxo = txn.open_table(UTXO)?;
            for (op, coin) in &diff.created {
                let bytes = borsh::to_vec(coin).map_err(|e| StorageError::corrupt("coin", e))?;
                utxo.insert(&outpoint_key(op), bytes.as_slice())?;
            }
            for (op, _) in &diff.spent {
                utxo.remove(&outpoint_key(op))?;
            }
            let mut meta = txn.open_table(META)?;
            meta.insert(META_TIP, encode_tip(h, height).as_slice())?;
        }
        drop(txn); // the crash: no commit
        Ok(())
    }
}

impl StateView for Store {
    fn get_coin(&self, op: &OutPoint) -> Result<Option<Coin>, StorageError> {
        Store::get_coin(self, op)
    }

    fn has_coin(&self, op: &OutPoint) -> Result<bool, StorageError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(UTXO)?;
        Ok(t.get(&outpoint_key(op))?.is_some())
    }
}

/// Every outpoint a block creates, in `(tx index, vout)` order.
fn created_outpoints(block: &Block) -> Result<Vec<OutPoint>, StorageError> {
    let mut out = Vec::new();
    for tx in &block.txs {
        let id = txid(tx);
        for vout in 0..tx.outputs.len() {
            let vout = u32::try_from(vout)
                .map_err(|_| StorageError::TooManyOutputs { count: tx.outputs.len() })?;
            out.push(OutPoint::new(id, vout));
        }
    }
    Ok(out)
}

/// Index the spent coins of a diff by outpoint, for the address indexer.
fn spent_map(spent: &[(OutPoint, Coin)]) -> BTreeMap<OutPoint, Coin> {
    spent.iter().map(|(op, coin)| (*op, coin.clone())).collect()
}

/// Read a `meta` value as owned bytes, from either kind of transaction.
pub(crate) fn get_bytes<T>(table: &T, key: &str) -> Result<Option<Vec<u8>>, StorageError>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    Ok(table.get(key)?.map(|g| g.value().to_vec()))
}

/// Borsh-decode an optional stored record.
pub(crate) fn decode_opt<T: borsh::BorshDeserialize>(
    kind: &'static str,
    bytes: Option<Vec<u8>>,
) -> Result<Option<T>, StorageError> {
    match bytes {
        None => Ok(None),
        Some(b) => borsh::from_slice::<T>(&b).map(Some).map_err(|e| StorageError::corrupt(kind, e)),
    }
}
