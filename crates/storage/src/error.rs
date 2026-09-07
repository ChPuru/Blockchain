//! The one error type every `ferrum-storage` call returns.
//!
//! The enum is `#[non_exhaustive]` so a new failure mode is not a breaking
//! change, and every variant names a *specific* thing that went wrong. Tests
//! assert the exact variant: a test that only asserts "it failed" keeps
//! passing when the code starts failing for a different reason, which is how a
//! rule silently stops being tested.
//!
//! `redb`'s own error family is collapsed into [`StorageError::Db`] because
//! callers above this crate cannot act on the difference between a
//! `TableError` and a `TransactionError` — both mean "the database refused the
//! operation".

use ferrum_types::BlockHash;

/// Every failure `ferrum-storage` can report.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The underlying `redb` database refused an operation.
    ///
    /// Boxed because `redb::Error` is over a hundred bytes wide and this enum
    /// is the `Err` half of every signature in the crate; an unboxed variant
    /// makes every `Result` that size, on the success path too.
    #[error("redb: {0}")]
    Db(#[source] Box<redb::Error>),

    /// A stored record could not be decoded. This means on-disk corruption or
    /// a schema change that was not caught by [`StorageError::SchemaMismatch`].
    #[error("corrupt {kind} record: {detail}")]
    Corrupt {
        /// Which table or meta key the bad bytes came from.
        kind: &'static str,
        /// The decoder's complaint.
        detail: String,
    },

    /// The database was written by a different schema version.
    ///
    /// Ferrum does not migrate in place: a mismatch means reindex, because a
    /// half-understood on-disk format is worse than a rebuild.
    #[error("schema version mismatch: database has {found}, this build expects {expected}")]
    SchemaMismatch {
        /// The version this build writes.
        expected: u32,
        /// The version found in `meta.schema_version`.
        found: u32,
    },

    /// The database belongs to a different network.
    #[error("chain id mismatch: database has {found}, this node is configured for {expected}")]
    ChainIdMismatch {
        /// The chain id the node was configured with.
        expected: u32,
        /// The chain id found in `meta.chain_id`.
        found: u32,
    },

    /// A write tried to extend the chain non-contiguously.
    ///
    /// The active chain is a list, not a set: connecting height `n + 2` on top
    /// of height `n` would leave `height` with a hole that no reader could
    /// distinguish from a pruned block.
    #[error("non-contiguous connect: tip is at height {tip_height}, block claims height {height}")]
    NonContiguousConnect {
        /// The height currently recorded in `meta.tip` (`u64::MAX` marks an empty store).
        tip_height: u64,
        /// The height the caller tried to connect.
        height: u64,
    },

    /// The connected block does not build on the current tip.
    #[error("parent mismatch: tip is {tip}, block's prev_hash is {prev}")]
    ParentMismatch {
        /// The hash currently recorded in `meta.tip`.
        tip: BlockHash,
        /// The `prev_hash` of the header being connected.
        prev: BlockHash,
    },

    /// `BlockIndexEntry::height` disagreed with the height argument.
    #[error("index entry height {entry_height} does not match connect height {height}")]
    EntryHeightMismatch {
        /// `entry.height`.
        entry_height: u64,
        /// The `height` argument.
        height: u64,
    },

    /// `disconnect_tip` was called on a store that has no tip at all.
    #[error("cannot disconnect: the store has no tip")]
    NoTip,

    /// `disconnect_tip` was called with genesis as the tip.
    ///
    /// Genesis is not reorganisable: it has no parent to fall back to, so a
    /// caller that wants an empty store should create a new one.
    #[error("cannot disconnect the genesis block")]
    CannotDisconnectGenesis,

    /// The undo record needed to reverse a block is missing.
    ///
    /// Undo data cannot be recomputed from the block alone — that is the whole
    /// reason it is written — so this is unrecoverable without a reindex.
    #[error("no undo record for block {0}")]
    MissingUndo(BlockHash),

    /// The block body needed to reverse a block is missing.
    #[error("no block body for {0}")]
    MissingBlock(BlockHash),

    /// The `height` table has no entry for a height at or below the tip.
    #[error("active chain has no block at height {0}")]
    MissingHeight(u64),

    /// A reverse-index query was made against a store built without the index.
    #[error("the transaction/address index is disabled on this store")]
    IndexDisabled,

    /// The reverse index is enabled but does not describe the active tip.
    ///
    /// `index_transactions` is a runtime flag, so a datadir can be written by
    /// a run that maintained `tx_index`/`addr_index` and by a run that did
    /// not. Answering from tables that were left behind by an earlier chain
    /// state is worse than refusing: a caller cannot tell a stale
    /// `TxLocation` from a current one. `meta.index_height` records what the
    /// index really covers, and this is what a reader gets when it disagrees
    /// with the tip.
    #[error(
        "the index covers {} but the tip is at height {tip_height}; run `chain reindex`",
        .indexed_to.map_or_else(|| "no block".to_owned(), |h| format!("height {h}"))
    )]
    IndexIncomplete {
        /// The height the index is complete to, or `None` for "no block".
        indexed_to: Option<u64>,
        /// The height of the active tip the index fails to describe.
        tip_height: u64,
    },

    /// A block carried more transactions than a `u32` index can name.
    ///
    /// Unreachable while `max_block_size` is a megabyte, but the index key
    /// format depends on it, so it is a typed error rather than a cast.
    #[error("block has {count} transactions, more than the index can address")]
    TooManyTransactions {
        /// The transaction count that overflowed.
        count: usize,
    },

    /// A transaction carried more outputs than a `u32` `vout` can name.
    #[error("transaction has {count} outputs, more than a u32 vout can address")]
    TooManyOutputs {
        /// The output count that overflowed.
        count: usize,
    },

    /// A stored value had the wrong length for its fixed-width slot.
    #[error("bad {kind} length: expected {expected} bytes, found {found}")]
    BadLength {
        /// Which record.
        kind: &'static str,
        /// The length the format requires.
        expected: usize,
        /// The length actually stored.
        found: usize,
    },
}

impl StorageError {
    /// Build a [`StorageError::Corrupt`] from a decoder error.
    pub(crate) fn corrupt(kind: &'static str, detail: impl std::fmt::Display) -> Self {
        StorageError::Corrupt { kind, detail: detail.to_string() }
    }
}

// `redb` splits its failures across six types that all convert into
// `redb::Error`. Funnelling them through one variant keeps the match arms
// above this crate about *Ferrum* problems rather than about redb's taxonomy.
macro_rules! from_redb {
    ($($ty:ty),* $(,)?) => {
        $(
            impl From<$ty> for StorageError {
                fn from(e: $ty) -> Self {
                    StorageError::Db(Box::new(e.into()))
                }
            }
        )*
    };
}

from_redb!(
    redb::Error,
    redb::StorageError,
    redb::TableError,
    redb::DatabaseError,
    redb::TransactionError,
    redb::CommitError,
    redb::CompactionError,
    std::io::Error,
);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ferrum_types::Hash32;

    #[test]
    fn corrupt_carries_its_kind_and_detail() {
        let e = StorageError::corrupt("coin", "unexpected end of input");
        let text = e.to_string();
        assert!(text.contains("coin"), "{text}");
        assert!(text.contains("unexpected end of input"), "{text}");
    }

    #[test]
    fn schema_mismatch_reports_both_versions() {
        let e = StorageError::SchemaMismatch { expected: 1, found: 7 };
        let text = e.to_string();
        assert!(text.contains('1') && text.contains('7'), "{text}");
    }

    #[test]
    fn parent_mismatch_displays_both_hashes() {
        let tip = BlockHash(Hash32::from_bytes([1u8; 32]));
        let prev = BlockHash(Hash32::from_bytes([2u8; 32]));
        let text = StorageError::ParentMismatch { tip, prev }.to_string();
        assert!(text.contains(&tip.to_hex()), "{text}");
        assert!(text.contains(&prev.to_hex()), "{text}");
    }

    #[test]
    fn redb_errors_funnel_into_db() {
        let e: StorageError = redb::TableError::TableDoesNotExist("utxo".into()).into();
        assert!(matches!(e, StorageError::Db(_)), "{e:?}");
        assert!(e.to_string().contains("utxo"));
    }

    #[test]
    fn io_errors_funnel_into_db_as_well() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "nope");
        let e: StorageError = io.into();
        assert!(matches!(e, StorageError::Db(_)), "{e:?}");
    }

    #[test]
    fn index_incomplete_names_the_gap_and_the_cure() {
        let e = StorageError::IndexIncomplete { indexed_to: Some(7), tip_height: 91 };
        let text = e.to_string();
        assert!(text.contains("height 7") && text.contains("91"), "{text}");
        assert!(text.contains("chain reindex"), "{text}");
        let empty = StorageError::IndexIncomplete { indexed_to: None, tip_height: 3 };
        assert!(empty.to_string().contains("no block"), "{empty}");
    }

    #[test]
    fn the_error_is_send_sync_and_static() {
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<StorageError>();
    }

    #[test]
    fn the_error_stays_small_enough_to_return_by_value() {
        // Every signature in the crate carries this in its `Err` slot, so its
        // width is the width of every `Result` the crate returns.
        assert!(
            size_of::<StorageError>() <= 128,
            "StorageError grew to {} bytes",
            size_of::<StorageError>()
        );
    }
}
