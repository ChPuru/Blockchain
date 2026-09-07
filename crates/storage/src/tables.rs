//! Table definitions and key encodings (CONTRACT §7).
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `blocks` | `block_hash[32]` | `borsh(Block)` |
//! | `headers` | `block_hash[32]` | `borsh(BlockIndexEntry)` |
//! | `height` | `be_u64(height)` | `block_hash[32]` — the **active** chain only |
//! | `utxo` | `borsh(OutPoint)` (36 B) | `borsh(Coin)` |
//! | `undo` | `block_hash[32]` | `borsh(UndoBlock)` |
//! | `meta` | `&str` | raw bytes (`tip`, `chain_id`, `schema_version`, `engine`, `index_height`) |
//! | `tx_index` | `txid[32]` | `borsh(TxLocation)` |
//! | `addr_index` | `addr_key ‖ be_u64(height) ‖ be_u32(tx_idx)` | `txid[32]` |
//!
//! # Why every numeric key is big-endian
//!
//! redb orders keys by the bytewise comparison of their encodings. A
//! little-endian `u64` height key makes `256` (`00 01 …`) sort *before* `1`
//! (`01 00 …`), so an ordered range scan returns heights out of numeric order
//! — but only once the chain passes height 255. A five-block fixture passes;
//! the bug surfaces in production. Big-endian makes bytewise order equal
//! numeric order for every width, and [`crate::tests`] pins heights
//! 1, 255, 256, 65535, 65536 and 1&nbsp;<<&nbsp;32 against exactly that.
//!
//! The one key that is *not* big-endian is the UTXO key, and deliberately so:
//! CONTRACT §7 defines it as `borsh(OutPoint)`, whose `vout` is little-endian
//! like every other Borsh integer, and CONTRACT §7 also defines the state root
//! over "ascending `borsh(OutPoint)` byte order". Storing the Borsh bytes
//! verbatim makes the table's own iteration order the normative state-root
//! order, so [`crate::Store::state_root`] never has to re-sort.

use borsh::{BorshDeserialize, BorshSerialize};
use ferrum_crypto::{TAG_HEADER, TAG_TXID, tagged_hash};
use ferrum_types::{
    Block, BlockHash, BlockHeader, Hash32, OUTPOINT_SIZE, OutPoint, Transaction, Txid,
};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};

use crate::error::StorageError;

/// On-disk schema version. A mismatch is a reindex, never a silent migration.
pub const SCHEMA_VERSION: u32 = 1;

/// Length of a block-hash key, in bytes.
pub const HASH_KEY_LEN: usize = 32;
/// Length of a UTXO key (`borsh(OutPoint)`), in bytes.
pub const OUTPOINT_KEY_LEN: usize = OUTPOINT_SIZE;
/// Length of a height key (`be_u64`), in bytes.
pub const HEIGHT_KEY_LEN: usize = 8;
/// Length of the `meta.tip` value: `block_hash[32] ‖ be_u64(height)`.
pub const TIP_VALUE_LEN: usize = HASH_KEY_LEN + HEIGHT_KEY_LEN;
/// Bytes appended to an address key: `be_u64(height) ‖ be_u32(tx_idx)`.
pub const ADDR_INDEX_SUFFIX_LEN: usize = 8 + 4;

/// `block_hash[32] -> borsh(Block)`.
pub const BLOCKS: TableDefinition<'static, &[u8; HASH_KEY_LEN], &[u8]> =
    TableDefinition::new("blocks");
/// `block_hash[32] -> borsh(BlockIndexEntry)`.
pub const HEADERS: TableDefinition<'static, &[u8; HASH_KEY_LEN], &[u8]> =
    TableDefinition::new("headers");
/// `be_u64(height) -> block_hash[32]`, for the active chain only.
pub const HEIGHT: TableDefinition<'static, &[u8; HEIGHT_KEY_LEN], &[u8; HASH_KEY_LEN]> =
    TableDefinition::new("height");
/// `borsh(OutPoint) -> borsh(Coin)`.
pub const UTXO: TableDefinition<'static, &[u8; OUTPOINT_KEY_LEN], &[u8]> =
    TableDefinition::new("utxo");
/// `block_hash[32] -> borsh(UndoBlock)`.
pub const UNDO: TableDefinition<'static, &[u8; HASH_KEY_LEN], &[u8]> = TableDefinition::new("undo");
/// `&str -> raw bytes`.
pub const META: TableDefinition<'static, &str, &[u8]> = TableDefinition::new("meta");
/// `txid[32] -> borsh(TxLocation)`. Only written when the index is enabled.
pub const TX_INDEX: TableDefinition<'static, &[u8; HASH_KEY_LEN], &[u8]> =
    TableDefinition::new("tx_index");
/// `addr_key ‖ be_u64(height) ‖ be_u32(tx_idx) -> txid[32]`. Index only.
pub const ADDR_INDEX: TableDefinition<'static, &[u8], &[u8; HASH_KEY_LEN]> =
    TableDefinition::new("addr_index");

/// Every table, so `Store::open` can create them all up front.
///
/// A read transaction on a table that has never been written fails with
/// `TableDoesNotExist`, so creating them eagerly turns "empty database" from
/// an error path into the ordinary path.
pub const TABLE_NAMES: [&str; 8] =
    ["blocks", "headers", "height", "utxo", "undo", "meta", "tx_index", "addr_index"];

/// `meta` key holding `block_hash[32] ‖ be_u64(height)` for the active tip.
pub const META_TIP: &str = "tip";
/// `meta` key holding `be_u32(chain_id)`.
pub const META_CHAIN_ID: &str = "chain_id";
/// `meta` key holding `be_u32(schema_version)`.
pub const META_SCHEMA_VERSION: &str = "schema_version";
/// `meta` key holding the one-byte consensus engine id of the tip.
pub const META_ENGINE: &str = "engine";
/// `meta` key holding `be_u64(height)`: the height the reverse index is
/// complete to.
///
/// Absent means the index describes no block at all. The key exists because
/// [`crate::StoreConfig::index_transactions`] is a *runtime* flag: the same
/// datadir can be written by a run that maintained `tx_index`/`addr_index` and
/// by a run that did not, and nothing on disk used to record which. A reader
/// compares this height against `meta.tip`; anything but equality means the
/// tables do not describe the active chain and must not be answered from.
pub const META_INDEX_HEIGHT: &str = "index_height";

/// How far a block has been validated.
///
/// The four states exist because headers-first sync separates "I have a header
/// that looks right" from "I have the body" from "I have executed it". A node
/// that could not tell them apart would either re-download bodies it already
/// has or re-execute blocks it already validated.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
#[borsh(use_discriminant = true)]
pub enum BlockStatus {
    /// The header is stored and header-valid; the body has not arrived.
    #[default]
    HeaderOnly = 0,
    /// The body is stored but has not been executed against the UTXO set.
    HaveData = 1,
    /// Fully validated and connected at least once.
    Valid = 2,
    /// Permanently rejected. Never retried, and its descendants inherit it.
    Invalid = 3,
}

impl BlockStatus {
    /// Whether the block body is present.
    #[must_use]
    pub const fn has_data(self) -> bool {
        matches!(self, BlockStatus::HaveData | BlockStatus::Valid)
    }

    /// Whether the block has been fully validated.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self, BlockStatus::Valid)
    }
}

/// The `headers` table's value: a header plus everything the fork-choice and
/// the explorer need without touching the body (CONTRACT §7).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct BlockIndexEntry {
    /// The 88-byte header.
    pub header: BlockHeader,
    /// Height on the branch this entry belongs to.
    pub height: u64,
    /// Cumulative work up to and including this block, big-endian `U256`.
    ///
    /// Big-endian so that a bytewise comparison of two entries is a numeric
    /// comparison of their work — fork choice is by cumulative work, never by
    /// height (SPEC §7.1).
    pub total_work: [u8; HASH_KEY_LEN],
    /// Validation state.
    pub status: BlockStatus,
    /// Number of transactions in the block.
    pub tx_count: u32,
    /// Serialized block size in bytes.
    pub size: u32,
    /// `BlockSeal::engine` of the block, so the router can be checked against
    /// history without re-reading the body.
    pub seal_engine: u8,
}

impl BlockIndexEntry {
    /// Build an entry from a whole block.
    ///
    /// # Errors
    /// Returns [`StorageError::TooManyTransactions`] if the block holds more
    /// transactions than a `u32` can count, or [`StorageError::BadLength`] if
    /// it serialises to more than `u32::MAX` bytes. Neither is reachable under
    /// a one-megabyte `max_block_size`; both are typed rather than silently
    /// truncated because a truncated size is a wrong size.
    pub fn from_block(
        block: &Block,
        height: u64,
        total_work: [u8; HASH_KEY_LEN],
        status: BlockStatus,
    ) -> Result<Self, StorageError> {
        let tx_count = u32::try_from(block.txs.len())
            .map_err(|_| StorageError::TooManyTransactions { count: block.txs.len() })?;
        let raw = block.serialized_size();
        let size = u32::try_from(raw).map_err(|_| StorageError::BadLength {
            kind: "block size",
            expected: u32::MAX as usize,
            found: raw,
        })?;
        Ok(BlockIndexEntry {
            header: block.header,
            height,
            total_work,
            status,
            tx_count,
            size,
            seal_engine: block.seal.engine,
        })
    }

    /// The hash of this entry's header.
    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        header_hash(&self.header)
    }
}

/// Big-endian encoding of a height, for the `height` table.
#[inline]
#[must_use]
pub const fn height_key(height: u64) -> [u8; HEIGHT_KEY_LEN] {
    height.to_be_bytes()
}

/// Decode a big-endian height key.
///
/// # Errors
/// Returns [`StorageError::BadLength`] if `k` is not eight bytes.
pub fn height_from_key(k: &[u8]) -> Result<u64, StorageError> {
    let a: [u8; HEIGHT_KEY_LEN] = k.try_into().map_err(|_| StorageError::BadLength {
        kind: "height key",
        expected: HEIGHT_KEY_LEN,
        found: k.len(),
    })?;
    Ok(u64::from_be_bytes(a))
}

/// The 32-byte key for a block hash.
#[inline]
#[must_use]
pub const fn hash_key(h: &BlockHash) -> [u8; HASH_KEY_LEN] {
    *h.as_bytes()
}

/// The 32-byte key for a txid.
#[inline]
#[must_use]
pub const fn txid_key(t: &Txid) -> [u8; HASH_KEY_LEN] {
    *t.as_bytes()
}

/// The block hash of a header: `tagged_hash(TAG_HEADER, header_bytes)`
/// (CONTRACT §2.2).
///
/// `ferrum-consensus` computes the same value from the same two lines. The
/// duplication is deliberate and narrow: `ferrum-storage` sits below the
/// consensus crates in the dependency order and cannot call into them, and a
/// store that could not derive a header's own key would have to be told it by
/// every caller — one more chance to pass the wrong one.
#[must_use]
pub fn header_hash(header: &BlockHeader) -> BlockHash {
    BlockHash(tagged_hash(TAG_HEADER, &header.encode()))
}

/// The txid of a transaction: `tagged_hash(TAG_TXID, tx_envelope)`
/// (CONTRACT §2.1). The type byte is inside the preimage.
#[must_use]
pub fn txid(tx: &Transaction) -> Txid {
    Txid(tagged_hash(TAG_TXID, &tx.encode_envelope()))
}

/// The 36-byte UTXO key, which is exactly `borsh(OutPoint)`.
///
/// Written by hand rather than through `borsh::to_vec` so the hot path does
/// not allocate; a proptest asserts the two agree byte for byte.
#[inline]
#[must_use]
pub fn outpoint_key(op: &OutPoint) -> [u8; OUTPOINT_KEY_LEN] {
    let mut k = [0u8; OUTPOINT_KEY_LEN];
    k[..HASH_KEY_LEN].copy_from_slice(op.txid.as_bytes());
    k[HASH_KEY_LEN..].copy_from_slice(&op.vout.to_le_bytes());
    k
}

/// Decode a UTXO key back into an outpoint.
///
/// # Errors
/// Returns [`StorageError::BadLength`] if `k` is not 36 bytes.
pub fn outpoint_from_key(k: &[u8]) -> Result<OutPoint, StorageError> {
    if k.len() != OUTPOINT_KEY_LEN {
        return Err(StorageError::BadLength {
            kind: "outpoint key",
            expected: OUTPOINT_KEY_LEN,
            found: k.len(),
        });
    }
    let mut txid = [0u8; HASH_KEY_LEN];
    txid.copy_from_slice(&k[..HASH_KEY_LEN]);
    let mut vout = [0u8; 4];
    vout.copy_from_slice(&k[HASH_KEY_LEN..]);
    Ok(OutPoint::new(Txid(Hash32::from_bytes(txid)), u32::from_le_bytes(vout)))
}

/// Reconstruct a block hash from a 32-byte key.
///
/// # Errors
/// Returns [`StorageError::BadLength`] if `k` is not 32 bytes.
pub fn hash_from_key(k: &[u8]) -> Result<BlockHash, StorageError> {
    let a: [u8; HASH_KEY_LEN] = k.try_into().map_err(|_| StorageError::BadLength {
        kind: "hash key",
        expected: HASH_KEY_LEN,
        found: k.len(),
    })?;
    Ok(BlockHash(Hash32::from_bytes(a)))
}

/// `addr_key ‖ be_u64(height) ‖ be_u32(tx_idx)`.
///
/// Big-endian on both suffixes so an ordered scan over one address returns its
/// history in `(height, position-in-block)` order, which is what the explorer
/// renders and what [`crate::Store::address_history`] pages through.
#[must_use]
pub fn addr_index_key(addr_key: &[u8], height: u64, tx_idx: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(addr_key.len() + ADDR_INDEX_SUFFIX_LEN);
    k.extend_from_slice(addr_key);
    k.extend_from_slice(&height.to_be_bytes());
    k.extend_from_slice(&tx_idx.to_be_bytes());
    k
}

/// Split an `addr_index` key into `(addr_key, height, tx_idx)`.
///
/// # Errors
/// Returns [`StorageError::BadLength`] when the key is too short to carry the
/// twelve-byte suffix.
pub fn addr_index_parts(k: &[u8]) -> Result<(&[u8], u64, u32), StorageError> {
    let split = k.len().checked_sub(ADDR_INDEX_SUFFIX_LEN).ok_or(StorageError::BadLength {
        kind: "addr index key",
        expected: ADDR_INDEX_SUFFIX_LEN,
        found: k.len(),
    })?;
    let (addr, suffix) = k.split_at(split);
    let mut h = [0u8; 8];
    h.copy_from_slice(&suffix[..8]);
    let mut i = [0u8; 4];
    i.copy_from_slice(&suffix[8..]);
    Ok((addr, u64::from_be_bytes(h), u32::from_be_bytes(i)))
}

/// Encode the `meta.tip` value: `block_hash[32] ‖ be_u64(height)`.
#[must_use]
pub fn encode_tip(hash: &BlockHash, height: u64) -> [u8; TIP_VALUE_LEN] {
    let mut v = [0u8; TIP_VALUE_LEN];
    v[..HASH_KEY_LEN].copy_from_slice(hash.as_bytes());
    v[HASH_KEY_LEN..].copy_from_slice(&height.to_be_bytes());
    v
}

/// Decode the `meta.tip` value.
///
/// # Errors
/// Returns [`StorageError::BadLength`] if the stored value is not 40 bytes.
pub fn decode_tip(b: &[u8]) -> Result<(BlockHash, u64), StorageError> {
    if b.len() != TIP_VALUE_LEN {
        return Err(StorageError::BadLength {
            kind: "meta.tip",
            expected: TIP_VALUE_LEN,
            found: b.len(),
        });
    }
    let hash = hash_from_key(&b[..HASH_KEY_LEN])?;
    let height = height_from_key(&b[HASH_KEY_LEN..])?;
    Ok((hash, height))
}

/// Decode a big-endian `u32` meta value.
///
/// # Errors
/// Returns [`StorageError::BadLength`] if the stored value is not four bytes.
pub fn decode_u32(kind: &'static str, b: &[u8]) -> Result<u32, StorageError> {
    let a: [u8; 4] =
        b.try_into().map_err(|_| StorageError::BadLength { kind, expected: 4, found: b.len() })?;
    Ok(u32::from_be_bytes(a))
}

/// Decode a big-endian `u64` meta value.
///
/// # Errors
/// Returns [`StorageError::BadLength`] if the stored value is not eight bytes.
pub fn decode_u64(kind: &'static str, b: &[u8]) -> Result<u64, StorageError> {
    let a: [u8; 8] =
        b.try_into().map_err(|_| StorageError::BadLength { kind, expected: 8, found: b.len() })?;
    Ok(u64::from_be_bytes(a))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use proptest::prelude::*;

    #[test]
    fn table_names_are_unique_and_match_the_definitions() {
        let mut sorted = TABLE_NAMES;
        sorted.sort_unstable();
        let mut deduped = sorted.to_vec();
        deduped.dedup();
        assert_eq!(deduped.len(), TABLE_NAMES.len(), "duplicate table name");
        assert!(TABLE_NAMES.contains(&"utxo"));
        assert!(TABLE_NAMES.contains(&"addr_index"));
    }

    #[test]
    fn meta_keys_are_distinct() {
        let keys = [META_TIP, META_CHAIN_ID, META_SCHEMA_VERSION, META_ENGINE, META_INDEX_HEIGHT];
        let mut v = keys.to_vec();
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), keys.len());
    }

    #[test]
    fn height_keys_sort_numerically() {
        // The exact heights the contract calls out: little-endian keys break
        // at 256, late enough that a five-block fixture never notices.
        let heights = [0u64, 1, 255, 256, 65_535, 65_536, 1 << 32, u64::MAX];
        let mut keys: Vec<[u8; 8]> = heights.iter().map(|h| height_key(*h)).collect();
        keys.sort_unstable();
        let back: Vec<u64> = keys.iter().map(|k| height_from_key(k).unwrap()).collect();
        assert_eq!(back, heights.to_vec());
    }

    #[test]
    fn little_endian_would_have_broken_at_256() {
        // Documents the bug this encoding exists to prevent.
        let one = 1u64.to_le_bytes();
        let two_five_six = 256u64.to_le_bytes();
        assert!(two_five_six < one, "little-endian misorders 1 and 256");
        assert!(height_key(1) < height_key(256), "big-endian does not");
    }

    #[test]
    fn height_from_key_rejects_a_short_key() {
        let e = height_from_key(&[0u8; 7]).unwrap_err();
        assert!(matches!(e, StorageError::BadLength { expected: 8, found: 7, .. }), "{e:?}");
    }

    #[test]
    fn tip_value_round_trips() {
        let h = BlockHash(Hash32::from_bytes([9u8; 32]));
        let v = encode_tip(&h, 1 << 33);
        assert_eq!(v.len(), TIP_VALUE_LEN);
        assert_eq!(decode_tip(&v).unwrap(), (h, 1 << 33));
    }

    #[test]
    fn tip_value_rejects_a_wrong_length() {
        let e = decode_tip(&[0u8; 39]).unwrap_err();
        assert!(matches!(e, StorageError::BadLength { kind: "meta.tip", .. }), "{e:?}");
    }

    #[test]
    fn addr_index_key_layout_is_prefix_then_be_suffixes() {
        let k = addr_index_key(&[0xab; 20], 258, 3);
        assert_eq!(k.len(), 20 + ADDR_INDEX_SUFFIX_LEN);
        assert_eq!(&k[..20], &[0xab; 20]);
        assert_eq!(&k[20..28], &258u64.to_be_bytes());
        assert_eq!(&k[28..], &3u32.to_be_bytes());
        let (addr, h, i) = addr_index_parts(&k).unwrap();
        assert_eq!(addr, &[0xab; 20]);
        assert_eq!((h, i), (258, 3));
    }

    #[test]
    fn addr_index_keys_of_one_address_sort_by_height_then_index() {
        let a = [0x11; 20];
        let mut keys = [
            addr_index_key(&a, 300, 0),
            addr_index_key(&a, 2, 5),
            addr_index_key(&a, 2, 1),
            addr_index_key(&a, 1 << 40, 0),
        ];
        keys.sort();
        let parsed: Vec<(u64, u32)> = keys
            .iter()
            .map(|k| {
                let (_, h, i) = addr_index_parts(k).unwrap();
                (h, i)
            })
            .collect();
        assert_eq!(parsed, vec![(2, 1), (2, 5), (300, 0), (1 << 40, 0)]);
    }

    #[test]
    fn addr_index_parts_rejects_a_key_with_no_room_for_the_suffix() {
        let e = addr_index_parts(&[0u8; 11]).unwrap_err();
        assert!(matches!(e, StorageError::BadLength { kind: "addr index key", .. }), "{e:?}");
    }

    #[test]
    fn outpoint_key_rejects_a_wrong_length() {
        let e = outpoint_from_key(&[0u8; 35]).unwrap_err();
        assert!(matches!(e, StorageError::BadLength { expected: 36, found: 35, .. }), "{e:?}");
    }

    #[test]
    fn block_status_discriminants_are_frozen() {
        // The discriminant is the on-disk byte. Renumbering it silently
        // reinterprets every stored header.
        for (status, byte) in [
            (BlockStatus::HeaderOnly, 0u8),
            (BlockStatus::HaveData, 1),
            (BlockStatus::Valid, 2),
            (BlockStatus::Invalid, 3),
        ] {
            assert_eq!(borsh::to_vec(&status).unwrap(), vec![byte], "{status:?}");
        }
        assert_eq!(BlockStatus::default(), BlockStatus::HeaderOnly);
        assert!(BlockStatus::Valid.has_data() && BlockStatus::Valid.is_valid());
        assert!(BlockStatus::HaveData.has_data() && !BlockStatus::HaveData.is_valid());
        assert!(!BlockStatus::HeaderOnly.has_data());
        assert!(!BlockStatus::Invalid.has_data());
    }

    #[test]
    fn block_index_entry_derives_its_counts_from_the_block() {
        let block = ferrum_types::Block::new(
            BlockHeader {
                version: 1,
                prev_hash: BlockHash::ZERO,
                merkle_root: Hash32::ZERO,
                timestamp_ms: 5,
                bits: ferrum_types::CompactTarget(1),
                nonce: 0,
            },
            vec![Transaction::empty()],
            ferrum_types::BlockSeal::POW,
        );
        let e = BlockIndexEntry::from_block(&block, 7, [0u8; 32], BlockStatus::Valid).unwrap();
        assert_eq!(e.height, 7);
        assert_eq!(e.tx_count, 1);
        assert_eq!(e.size as usize, block.serialized_size());
        assert_eq!(e.seal_engine, ferrum_types::BlockSeal::ENGINE_POW);
        assert_eq!(e.block_hash(), header_hash(&block.header));
        let bytes = borsh::to_vec(&e).unwrap();
        assert_eq!(borsh::from_slice::<BlockIndexEntry>(&bytes).unwrap(), e);
    }

    #[test]
    fn total_work_compares_bytewise_because_it_is_big_endian() {
        let mut small = [0u8; 32];
        small[31] = 1;
        let mut large = [0u8; 32];
        large[30] = 1;
        assert!(small < large, "big-endian bytes order like the numbers do");
    }

    #[test]
    fn header_hash_is_the_tagged_hash_of_the_88_byte_encoding() {
        let header = BlockHeader {
            version: 1,
            prev_hash: BlockHash::ZERO,
            merkle_root: Hash32::from_bytes([3u8; 32]),
            timestamp_ms: 1_700_000_000_000,
            bits: ferrum_types::CompactTarget(0x1d00_ffff),
            nonce: 42,
        };
        let bytes = header.encode();
        assert_eq!(bytes.len(), 88);
        assert_eq!(borsh::to_vec(&header).unwrap(), bytes.to_vec(), "encode() is borsh");
        assert_eq!(
            header_hash(&header),
            BlockHash(ferrum_crypto::tagged_hash(ferrum_crypto::TAG_HEADER, &bytes))
        );
        // Domain separation: the same bytes under another tag differ.
        assert_ne!(
            header_hash(&header).hash(),
            ferrum_crypto::tagged_hash(ferrum_crypto::TAG_TXID, &bytes)
        );
    }

    #[test]
    fn a_changed_nonce_changes_the_header_hash() {
        let mut header = BlockHeader {
            version: 1,
            prev_hash: BlockHash::ZERO,
            merkle_root: Hash32::ZERO,
            timestamp_ms: 0,
            bits: ferrum_types::CompactTarget(1),
            nonce: 0,
        };
        let a = header_hash(&header);
        header.nonce = 1;
        assert_ne!(a, header_hash(&header));
    }

    #[test]
    fn txid_covers_the_type_byte() {
        let tx = Transaction::empty();
        let envelope = tx.encode_envelope();
        assert_eq!(envelope[0], ferrum_types::TX_TYPE_STANDARD);
        assert_eq!(txid(&tx), Txid(ferrum_crypto::tagged_hash(ferrum_crypto::TAG_TXID, &envelope)));
        // Not the hash of the bare borsh body.
        assert_ne!(
            txid(&tx).hash(),
            ferrum_crypto::tagged_hash(ferrum_crypto::TAG_TXID, &borsh::to_vec(&tx).unwrap())
        );
    }

    #[test]
    fn decode_u32_round_trips_and_rejects_short_input() {
        assert_eq!(decode_u32("chain_id", &7u32.to_be_bytes()).unwrap(), 7);
        assert!(decode_u32("chain_id", &[0u8; 3]).is_err());
    }

    #[test]
    fn decode_u64_round_trips_and_rejects_short_input() {
        assert_eq!(decode_u64("index_height", &(1u64 << 40).to_be_bytes()).unwrap(), 1 << 40);
        let e = decode_u64("index_height", &[0u8; 7]).unwrap_err();
        assert!(matches!(e, StorageError::BadLength { expected: 8, found: 7, .. }), "{e:?}");
    }

    proptest! {
        #[test]
        fn outpoint_key_equals_borsh(txid_bytes in proptest::array::uniform32(any::<u8>()), vout in any::<u32>()) {
            let op = OutPoint::new(Txid(Hash32::from_bytes(txid_bytes)), vout);
            let key = outpoint_key(&op);
            let borsh_bytes = borsh::to_vec(&op).unwrap();
            prop_assert_eq!(key.as_slice(), borsh_bytes.as_slice());
            prop_assert_eq!(outpoint_from_key(&key).unwrap(), op);
        }

        #[test]
        fn height_key_order_matches_numeric_order(a in any::<u64>(), b in any::<u64>()) {
            prop_assert_eq!(height_key(a).cmp(&height_key(b)), a.cmp(&b));
        }

        #[test]
        fn hash_key_round_trips(bytes in proptest::array::uniform32(any::<u8>())) {
            let h = BlockHash(Hash32::from_bytes(bytes));
            prop_assert_eq!(hash_from_key(&hash_key(&h)).unwrap(), h);
        }
    }
}
