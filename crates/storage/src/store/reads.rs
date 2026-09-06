//! Every read path on [`Store`].
//!
//! Split out of `store.rs` so that the file holding the write invariant — one
//! transaction per block, tip last — stays short enough to read in one sitting.
//! Reads are the easy half: each opens a `redb` read transaction, which is a
//! consistent MVCC snapshot, so a long scan never blocks a writer and never
//! sees a half-applied block.

use ferrum_types::{Block, BlockHash, ChainId, Coin, Hash32, OutPoint, Txid};
use redb::ReadableTableMetadata;

use crate::error::StorageError;
use crate::index::TxLocation;
use crate::state_root::StateRootBuilder;
use crate::store::{Store, UtxoBytes, decode_opt, get_bytes};
use crate::tables::{
    self, ADDR_INDEX, BLOCKS, BlockIndexEntry, HEADERS, HEIGHT, META, META_CHAIN_ID, META_ENGINE,
    META_SCHEMA_VERSION, META_TIP, OUTPOINT_KEY_LEN, SCHEMA_VERSION, TX_INDEX, UNDO, UTXO,
    addr_index_key, addr_index_parts, decode_tip, decode_u32, hash_key, height_key, outpoint_key,
    txid_key,
};
use crate::undo::UndoBlock;

impl Store {
    /// The block body for `h`.
    ///
    /// # Errors
    /// [`StorageError::Corrupt`] if the stored bytes do not decode.
    pub fn get_block(&self, h: &BlockHash) -> Result<Option<Block>, StorageError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(BLOCKS)?;
        decode_opt("block", t.get(&hash_key(h))?.map(|g| g.value().to_vec()))
    }

    /// The index entry for `h`, header and all.
    ///
    /// # Errors
    /// [`StorageError::Corrupt`] if the stored bytes do not decode.
    pub fn get_header(&self, h: &BlockHash) -> Result<Option<BlockIndexEntry>, StorageError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(HEADERS)?;
        decode_opt("header", t.get(&hash_key(h))?.map(|g| g.value().to_vec()))
    }

    /// The active-chain block hash at `height`.
    ///
    /// # Errors
    /// [`StorageError::Db`] on a redb failure.
    pub fn hash_at_height(&self, height: u64) -> Result<Option<BlockHash>, StorageError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(HEIGHT)?;
        Ok(t.get(&height_key(height))?.map(|g| BlockHash(Hash32::from_bytes(*g.value()))))
    }

    /// The active tip, or `None` on a store that has never connected a block.
    ///
    /// # Errors
    /// [`StorageError::BadLength`] if `meta.tip` is not 40 bytes.
    pub fn tip(&self) -> Result<Option<(BlockHash, u64)>, StorageError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(META)?;
        match get_bytes(&t, META_TIP)? {
            Some(raw) => decode_tip(&raw).map(Some),
            None => Ok(None),
        }
    }

    /// The tip height, or `None` on an empty store.
    ///
    /// # Errors
    /// As [`Store::tip`].
    pub fn tip_height(&self) -> Result<Option<u64>, StorageError> {
        Ok(self.tip()?.map(|(_, h)| h))
    }

    /// The unspent coin at `op`.
    ///
    /// # Errors
    /// [`StorageError::Corrupt`] if the stored coin does not decode.
    pub fn get_coin(&self, op: &OutPoint) -> Result<Option<Coin>, StorageError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(UTXO)?;
        decode_opt("coin", t.get(&outpoint_key(op))?.map(|g| g.value().to_vec()))
    }

    /// Number of unspent outputs. O(1): redb keeps the count in the B-tree root.
    ///
    /// # Errors
    /// [`StorageError::Db`] on a redb failure.
    pub fn utxo_count(&self) -> Result<u64, StorageError> {
        let txn = self.db.begin_read()?;
        Ok(txn.open_table(UTXO)?.len()?)
    }

    /// Number of stored headers, across every branch.
    ///
    /// # Errors
    /// [`StorageError::Db`] on a redb failure.
    pub fn header_count(&self) -> Result<u64, StorageError> {
        let txn = self.db.begin_read()?;
        Ok(txn.open_table(HEADERS)?.len()?)
    }

    /// Number of stored block bodies, across every branch.
    ///
    /// # Errors
    /// [`StorageError::Db`] on a redb failure.
    pub fn block_count(&self) -> Result<u64, StorageError> {
        let txn = self.db.begin_read()?;
        Ok(txn.open_table(BLOCKS)?.len()?)
    }

    /// Iterate the whole UTXO set in ascending `borsh(OutPoint)` order — which
    /// is the order [`Store::state_root`] hashes in.
    ///
    /// The iterator holds a read snapshot open, so a long scan sees a
    /// consistent set even while blocks are being connected.
    ///
    /// # Errors
    /// [`StorageError::Db`] opening the snapshot; each item may fail to decode.
    pub fn iter_utxos(
        &self,
    ) -> Result<impl Iterator<Item = Result<(OutPoint, Coin), StorageError>>, StorageError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(UTXO)?;
        let range = t.range::<&[u8; OUTPOINT_KEY_LEN]>(..)?;
        Ok(range.map(|entry| {
            let (k, v) = entry?;
            let op = tables::outpoint_from_key(k.value())?;
            let coin = borsh::from_slice::<Coin>(v.value())
                .map_err(|e| StorageError::corrupt("coin", e))?;
            Ok((op, coin))
        }))
    }

    /// The raw `(key, value)` bytes of the whole UTXO set, in table order.
    ///
    /// The byte-for-byte comparison the reorg guarantee is stated in: SPEC §7.3
    /// promises that disconnecting *N* blocks and reconnecting them yields a
    /// *byte-identical* UTXO set, and a comparison of decoded values would not
    /// catch an encoding that changed.
    ///
    /// # Errors
    /// [`StorageError::Db`] on a redb failure.
    pub fn utxo_snapshot(&self) -> Result<UtxoBytes, StorageError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(UTXO)?;
        let mut out = Vec::new();
        for entry in t.range::<&[u8; OUTPOINT_KEY_LEN]>(..)? {
            let (k, v) = entry?;
            out.push((k.value().to_vec(), v.value().to_vec()));
        }
        Ok(out)
    }

    /// The undo record written when `h` was connected.
    ///
    /// Records are kept after a disconnect — like Bitcoin Core's `rev*.dat`
    /// files — and are overwritten by the next connect of the same block.
    ///
    /// # Errors
    /// [`StorageError::Corrupt`] if the stored record does not decode.
    pub fn get_undo(&self, h: &BlockHash) -> Result<Option<UndoBlock>, StorageError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(UNDO)?;
        decode_opt("undo", t.get(&hash_key(h))?.map(|g| g.value().to_vec()))
    }

    /// Where `txid` sits on the active chain.
    ///
    /// # Errors
    /// [`StorageError::IndexDisabled`] when the store was opened without the
    /// index; [`StorageError::Corrupt`] if the stored location does not decode.
    pub fn tx_location(&self, id: &Txid) -> Result<Option<TxLocation>, StorageError> {
        self.require_index()?;
        let txn = self.db.begin_read()?;
        let t = txn.open_table(TX_INDEX)?;
        decode_opt("tx location", t.get(&txid_key(id))?.map(|g| g.value().to_vec()))
    }

    /// Transactions touching `key`, from `from_height` upwards, at most `limit`.
    ///
    /// Results are `(height, txid)` in ascending `(height, position-in-block)`
    /// order. A transaction that touches the address several times — two
    /// outputs to it, say — appears once, because the index key is
    /// `(address, height, tx index)`.
    ///
    /// **Paging.** Pass `from_height = last_returned_height + 1` for the next
    /// page. Because the cursor is a height and not a `(height, index)` pair,
    /// a caller must use a `limit` large enough to swallow a whole block's
    /// worth of entries for one address, or it will skip the remainder of the
    /// last height it saw. That is the shape CONTRACT §7 specifies, and a
    /// height is the cursor an explorer's "older" link already has.
    ///
    /// # Errors
    /// [`StorageError::IndexDisabled`] when the store has no index.
    pub fn address_history(
        &self,
        key: &[u8],
        from_height: u64,
        limit: usize,
    ) -> Result<Vec<(u64, Txid)>, StorageError> {
        self.require_index()?;
        let mut out = Vec::new();
        if limit == 0 {
            return Ok(out);
        }
        let txn = self.db.begin_read()?;
        let t = txn.open_table(ADDR_INDEX)?;
        let start = addr_index_key(key, from_height, 0);
        let end = addr_index_key(key, u64::MAX, u32::MAX);
        for entry in t.range::<&[u8]>(start.as_slice()..=end.as_slice())? {
            let (k, v) = entry?;
            let raw = k.value();
            // A longer address key can share this key's prefix — a 32-byte
            // script hash beginning with a 20-byte pubkey hash — and would
            // otherwise fall inside the range. Pin the exact shape.
            if raw.len() != key.len() + tables::ADDR_INDEX_SUFFIX_LEN {
                continue;
            }
            let (addr, height, _idx) = addr_index_parts(raw)?;
            if addr != key {
                continue;
            }
            out.push((height, Txid(Hash32::from_bytes(*v.value()))));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// The sorted binary Merkle root over the whole UTXO set (CONTRACT §7).
    ///
    /// Not consensus state; used by the determinism harness, the
    /// reference-executor differential and `getstateroot`.
    ///
    /// # Errors
    /// [`StorageError::Db`] on a redb failure.
    pub fn state_root(&self) -> Result<Hash32, StorageError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(UTXO)?;
        let mut builder = StateRootBuilder::new();
        for entry in t.range::<&[u8; OUTPOINT_KEY_LEN]>(..)? {
            let (k, v) = entry?;
            builder.push_bytes(k.value(), v.value());
        }
        Ok(builder.finish())
    }

    /// The on-disk schema version.
    ///
    /// # Errors
    /// [`StorageError::BadLength`] if the stored value is not four bytes.
    pub fn schema_version(&self) -> Result<u32, StorageError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(META)?;
        match get_bytes(&t, META_SCHEMA_VERSION)? {
            Some(raw) => decode_u32("meta.schema_version", &raw),
            None => Ok(SCHEMA_VERSION),
        }
    }

    /// The chain id recorded in the database, if one was ever written.
    ///
    /// # Errors
    /// [`StorageError::BadLength`] if the stored value is not four bytes.
    pub fn chain_id(&self) -> Result<Option<ChainId>, StorageError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(META)?;
        match get_bytes(&t, META_CHAIN_ID)? {
            Some(raw) => Ok(Some(ChainId(decode_u32("meta.chain_id", &raw)?))),
            None => Ok(None),
        }
    }

    /// The consensus engine id of the current tip, if any.
    ///
    /// # Errors
    /// [`StorageError::BadLength`] if the stored value is not one byte.
    pub fn engine(&self) -> Result<Option<u8>, StorageError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(META)?;
        match get_bytes(&t, META_ENGINE)? {
            Some(raw) => match raw.as_slice() {
                [b] => Ok(Some(*b)),
                other => Err(StorageError::BadLength {
                    kind: "meta.engine",
                    expected: 1,
                    found: other.len(),
                }),
            },
            None => Ok(None),
        }
    }
}
