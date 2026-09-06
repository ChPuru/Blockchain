//! Big-endian keys, proved against `redb` itself rather than against
//! `[u8; 8]::cmp`.
//!
//! The failure this guards is specific: little-endian height keys sort
//! correctly for heights 0–255 and then silently invert. Every five-block
//! fixture passes; the chain breaks in production at block 256, and the
//! symptom — `hash_at_height` returning the wrong block — looks nothing like
//! the cause.

use ferrum_types::{BlockHash, Hash32};
use redb::{ReadableTable, ReadableTableMetadata};

use crate::store::{Store, StoreConfig};
use crate::tables::{HEIGHT, HEIGHT_KEY_LEN, height_from_key, height_key};
use crate::tests::fixtures::ChainBuilder;

/// The heights CONTRACT §7 calls out, spanning every byte boundary a
/// little-endian encoding would trip over.
const PROBE_HEIGHTS: [u64; 7] = [0, 1, 255, 256, 65_535, 65_536, 1 << 32];

#[test]
fn an_ordered_scan_returns_the_probe_heights_in_numeric_order() {
    let store = Store::open_in_memory(StoreConfig::default()).unwrap();

    // Write the height entries directly: reaching height 1 << 32 through
    // `connect_block` would mean four billion blocks, and the property under
    // test is the key encoding, not the connect path.
    let db = store.database();
    let txn = db.begin_write().unwrap();
    {
        let mut t = txn.open_table(HEIGHT).unwrap();
        // Deliberately inserted out of order, so a passing scan proves the
        // B-tree ordered them and not the insertion sequence.
        for h in [1u64 << 32, 255, 65_536, 0, 256, 1, 65_535] {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&h.to_be_bytes());
            t.insert(&height_key(h), &hash).unwrap();
        }
    }
    txn.commit().unwrap();

    let read = db.begin_read().unwrap();
    let t = read.open_table(HEIGHT).unwrap();
    assert_eq!(t.len().unwrap(), PROBE_HEIGHTS.len() as u64);

    let mut scanned = Vec::new();
    for entry in t.range::<&[u8; HEIGHT_KEY_LEN]>(..).unwrap() {
        let (k, _) = entry.unwrap();
        scanned.push(height_from_key(k.value()).unwrap());
    }
    assert_eq!(scanned, PROBE_HEIGHTS.to_vec());

    // And each one resolves through the public reader.
    for h in PROBE_HEIGHTS {
        let mut expected = [0u8; 32];
        expected[..8].copy_from_slice(&h.to_be_bytes());
        assert_eq!(
            store.hash_at_height(h).unwrap(),
            Some(BlockHash(Hash32::from_bytes(expected))),
            "height {h}"
        );
    }
}

#[test]
fn a_partial_scan_from_a_height_starts_at_the_right_place() {
    let store = Store::open_in_memory(StoreConfig::default()).unwrap();
    let db = store.database();
    let txn = db.begin_write().unwrap();
    {
        let mut t = txn.open_table(HEIGHT).unwrap();
        for h in PROBE_HEIGHTS {
            t.insert(&height_key(h), &[0u8; 32]).unwrap();
        }
    }
    txn.commit().unwrap();

    let read = db.begin_read().unwrap();
    let t = read.open_table(HEIGHT).unwrap();
    let mut from_256 = Vec::new();
    for entry in t.range::<&[u8; HEIGHT_KEY_LEN]>(&height_key(256)..).unwrap() {
        let (k, _) = entry.unwrap();
        from_256.push(height_from_key(k.value()).unwrap());
    }
    assert_eq!(from_256, vec![256, 65_535, 65_536, 1 << 32]);
}

#[test]
fn three_hundred_connected_blocks_scan_in_order() {
    // The end-to-end version: a chain long enough to cross 255, driven
    // entirely through `connect_block`.
    let store = Store::open_in_memory(StoreConfig::default()).unwrap();
    let mut b = ChainBuilder::new();
    for blk in b.build(300) {
        store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }

    let db = store.database();
    let read = db.begin_read().unwrap();
    let t = read.open_table(HEIGHT).unwrap();
    let mut scanned = Vec::new();
    for entry in t.range::<&[u8; HEIGHT_KEY_LEN]>(..).unwrap() {
        let (k, _) = entry.unwrap();
        scanned.push(height_from_key(k.value()).unwrap());
    }
    assert_eq!(scanned, (0..300u64).collect::<Vec<_>>());
    assert!(store.hash_at_height(255).unwrap().is_some());
    assert_ne!(store.hash_at_height(1).unwrap(), store.hash_at_height(256).unwrap());
}

#[test]
fn the_first_and_last_entries_are_the_lowest_and_highest_heights() {
    let store = Store::open_in_memory(StoreConfig::default()).unwrap();
    let db = store.database();
    let txn = db.begin_write().unwrap();
    {
        let mut t = txn.open_table(HEIGHT).unwrap();
        for h in PROBE_HEIGHTS {
            t.insert(&height_key(h), &[0u8; 32]).unwrap();
        }
    }
    txn.commit().unwrap();
    let read = db.begin_read().unwrap();
    let t = read.open_table(HEIGHT).unwrap();
    let first = t.first().unwrap().unwrap();
    let last = t.last().unwrap().unwrap();
    assert_eq!(height_from_key(first.0.value()).unwrap(), 0);
    assert_eq!(height_from_key(last.0.value()).unwrap(), 1 << 32);
}

#[test]
fn the_utxo_table_scans_in_borsh_key_order() {
    // The state root is defined over ascending `borsh(OutPoint)` bytes, so the
    // table's own order must be exactly that.
    let store = Store::open_in_memory(StoreConfig::default()).unwrap();
    let mut b = ChainBuilder::new();
    for blk in b.build(20) {
        store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let keys: Vec<Vec<u8>> = store.utxo_snapshot().unwrap().into_iter().map(|(k, _)| k).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    assert!(keys.len() > 5, "the fixture should leave a non-trivial set");
    assert!(keys.iter().all(|k| k.len() == crate::tables::OUTPOINT_KEY_LEN));
}
