//! `redb`-backed block store, UTXO set, undo log and reverse index for Ferrum
//! (CONTRACT §7).
//!
//! # Every method here is synchronous, and that is deliberate
//!
//! `redb` is a synchronous embedded database. **Every call from an `async fn`
//! must go through `tokio::task::spawn_blocking`**, and CI greps for direct
//! `Store::` calls inside `async fn` bodies. A synchronous database call on a
//! Tokio worker thread parks that worker for the duration of the I/O; with a
//! handful of workers and a busy store, that is a two-second p95 latency bug
//! that only appears under load and never in a test.
//!
//! ```ignore
//! // In an async context:
//! let store = Arc::clone(&self.store);
//! let hash = hash;
//! let block = tokio::task::spawn_blocking(move || store.get_block(&hash)).await??;
//! ```
//!
//! # The four rules this crate exists to enforce
//!
//! 1. **One write transaction per block, tip last.**
//!    [`Store::connect_block`] and [`Store::disconnect_tip`] each open exactly
//!    one `redb` write transaction and write `meta.tip` as their final
//!    statement inside it. A tip that can be observed ahead of the diff it
//!    names is a corrupt chain that survives restarts.
//! 2. **Numeric keys are big-endian.** Bytewise order then equals numeric
//!    order. Little-endian height keys break at block 256 — late enough that
//!    every small fixture passes.
//! 3. **Undo records are written from the first commit.** They cannot be
//!    retrofitted: the records for historical blocks do not exist, so adding
//!    them later forces a reindex on every deployed node. See [`undo`].
//! 4. **The reverse index is not consensus state.** It is built only when
//!    [`StoreConfig::index_transactions`] is on, and a node without it is
//!    fully valid.
//!
//! # Layout
//!
//! | Module | What it owns |
//! |---|---|
//! | [`tables`] | table definitions, key encodings, [`BlockIndexEntry`] |
//! | [`store`] | [`Store`] — its writes; the reads live in `store::reads` |
//! | [`view`] | [`StateView`], [`OverlayView`], [`StateDiff`] |
//! | [`undo`] | [`UndoBlock`], [`UndoCoin`] |
//! | [`index`] | [`TxLocation`] and the address-key extractor |
//! | [`state_root`] | the UTXO-set Merkle root |
//! | [`error`] | [`StorageError`] |
//!
//! # Example
//!
//! ```
//! use ferrum_storage::{StateDiff, Store, StoreConfig, BlockIndexEntry, BlockStatus, tables};
//! use ferrum_types::{Amount, Block, BlockHeader, BlockHash, BlockSeal, Coin, CompactTarget,
//!                    Hash32, OutPoint, Script, Transaction, TxIn, TxOut};
//!
//! let store = Store::open_in_memory(StoreConfig::default())?;
//! assert_eq!(store.tip()?, None);
//!
//! // A genesis block whose coinbase creates one output.
//! let coinbase = Transaction {
//!     version: 1,
//!     inputs: vec![TxIn::coinbase(Script::new(vec![0x00, 0x01]))],
//!     outputs: vec![TxOut::new(Amount::from_grains(50), Script::new(vec![0x51]))],
//!     lock_time: 0,
//! };
//! let header = BlockHeader {
//!     version: 1,
//!     prev_hash: BlockHash::ZERO,
//!     merkle_root: Hash32::ZERO,
//!     timestamp_ms: 1_700_000_000_000,
//!     bits: CompactTarget(0x1d00_ffff),
//!     nonce: 0,
//! };
//! let block = Block::new(header, vec![coinbase.clone()], BlockSeal::POW);
//! let hash = tables::header_hash(&block.header);
//! let entry = BlockIndexEntry::from_block(&block, 0, [0u8; 32], BlockStatus::Valid)?;
//!
//! let out = OutPoint::new(tables::txid(&coinbase), 0);
//! let coin = Coin { value: Amount::from_grains(50), script_pubkey: Script::new(vec![0x51]),
//!                   height: 0, is_coinbase: true };
//! let diff = StateDiff { spent: vec![], created: vec![(out, coin.clone())] };
//!
//! store.connect_block(&hash, 0, &entry, &diff, &block)?;
//! assert_eq!(store.tip()?, Some((hash, 0)));
//! assert_eq!(store.get_coin(&out)?, Some(coin));
//! assert_eq!(store.utxo_count()?, 1);
//! # Ok::<(), ferrum_storage::StorageError>(())
//! ```

#![warn(missing_docs)]

pub mod error;
pub mod index;
pub mod state_root;
pub mod store;
pub mod tables;
pub mod undo;
pub mod view;

#[cfg(test)]
mod tests;

pub use crate::error::StorageError;
pub use crate::index::{ADDR_KEY_PKH_LEN, ADDR_KEY_SCRIPT_LEN, TxLocation, address_keys};
pub use crate::state_root::{
    StateRootBuilder, state_root_leaf, state_root_leaf_bytes, state_root_of,
    state_root_of_sorted_leaves,
};
pub use crate::store::{Store, StoreConfig, UtxoBytes};
pub use crate::tables::{
    ADDR_INDEX_SUFFIX_LEN, BlockIndexEntry, BlockStatus, HASH_KEY_LEN, HEIGHT_KEY_LEN,
    OUTPOINT_KEY_LEN, SCHEMA_VERSION, TIP_VALUE_LEN, addr_index_key, addr_index_parts, header_hash,
    height_key, outpoint_key, txid,
};
pub use crate::undo::{UndoBlock, UndoCoin};
pub use crate::view::{EmptyView, MapView, OverlayView, StateDiff, StateView};
