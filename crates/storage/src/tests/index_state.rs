//! The reverse index has to say whether it is *current*.
//!
//! `tx_index`/`addr_index` are maintained only while
//! [`crate::StoreConfig::index_transactions`] is on. That flag comes from the
//! command line, so the same datadir can be written by a run that maintained
//! the index and by a run that did not. The tables are then stale, and the
//! readers — which used to gate on the runtime flag alone — answered from them
//! as if they were authoritative: a transaction that only ever existed in a
//! reorged-away block came back with a `TxLocation` naming a block that is on
//! no chain, and a transaction in a replacement block came back "not found".
//!
//! These tests pin the fix: `meta.index_height` records the height the index
//! is complete to, every write reconciles it, and a read against an index that
//! does not describe the current tip fails with
//! [`crate::StorageError::IndexIncomplete`] instead of lying.

use tempfile::TempDir;

use crate::error::StorageError;
use crate::store::{Store, StoreConfig};
use crate::tables::txid;
use crate::tests::fixtures::{Built, ChainBuilder, p2pkh, pkh};

/// Connect every block of `blocks` to `store`.
fn connect_all(store: &Store, blocks: &[Built]) {
    for blk in blocks {
        store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
}

/// A main branch of six blocks and a three-block replacement for its last three.
///
/// Returns `(common, orphaned, replacement)`; `orphaned` and `replacement`
/// both build on `common`'s last block, so connecting one after disconnecting
/// the other is a three-block reorg.
fn forked_chain() -> (Vec<Built>, Vec<Built>, Vec<Built>) {
    let mut main = ChainBuilder::new();
    let common = main.build(3);
    let mut fork = main.clone();
    let orphaned = main.build(3);
    let replacement: Vec<Built> =
        (0..3u64).map(|i| fork.next_paying_to(p2pkh(&pkh(700_000 + i)))).collect();
    assert_ne!(orphaned[0].hash, replacement[0].hash, "the branches must differ");
    (common, orphaned, replacement)
}

#[test]
fn a_reorg_with_the_index_off_stops_the_index_answering_as_if_it_were_current() {
    // The finding's scenario, end to end: sync with `--index`, restart without
    // it, take a three-block reorg, restart with `--index` again.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ferrum.redb");
    let (common, orphaned, replacement) = forked_chain();

    let orphan_txid = txid(&orphaned[0].block.txs[0]);
    let replacement_txid = txid(&replacement[0].block.txs[0]);

    {
        let s = Store::open(&path, StoreConfig::indexed()).unwrap();
        connect_all(&s, &common);
        connect_all(&s, &orphaned);
        // While it is genuinely current, the index answers.
        assert_eq!(
            s.tx_location(&orphan_txid).unwrap().map(|l| l.block_hash),
            Some(orphaned[0].hash)
        );
        assert_eq!(s.index_height().unwrap(), Some(5));
    }

    // Restarted without `--index`: the reorg is not mirrored into the tables.
    {
        let s = Store::open(&path, StoreConfig::default()).unwrap();
        for _ in 0..3 {
            s.disconnect_tip().unwrap();
        }
        connect_all(&s, &replacement);
        assert_eq!(s.index_height().unwrap(), None, "an unindexed write must void the record");
    }

    // Restarted with `--index`: the tables describe a chain that no longer
    // exists, and every reader has to say so rather than answer from them.
    let s = Store::open(&path, StoreConfig::indexed()).unwrap();
    assert!(s.is_indexed());
    let err = s.tx_location(&orphan_txid).unwrap_err();
    assert!(matches!(err, StorageError::IndexIncomplete { .. }), "{err:?}");
    assert!(err.to_string().contains("reindex"), "the error must name the cure: {err}");

    let err = s.tx_location(&replacement_txid).unwrap_err();
    assert!(matches!(err, StorageError::IndexIncomplete { .. }), "{err:?}");
    let err = s.address_history(&pkh(700_000), 0, 10).unwrap_err();
    assert!(matches!(err, StorageError::IndexIncomplete { .. }), "{err:?}");
    let err = s.address_history_after(&pkh(0), None, 10).unwrap_err();
    assert!(matches!(err, StorageError::IndexIncomplete { .. }), "{err:?}");
}

#[test]
fn replaying_the_chain_with_the_index_on_makes_it_answer_again() {
    // What `chain reindex` does — disconnect to genesis, reconnect from the
    // stored bodies — has to be able to restore the index, so opening a stale
    // store must not be a dead end.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ferrum.redb");
    let (common, orphaned, replacement) = forked_chain();

    {
        let s = Store::open(&path, StoreConfig::indexed()).unwrap();
        connect_all(&s, &common);
        connect_all(&s, &orphaned);
    }
    {
        let s = Store::open(&path, StoreConfig::default()).unwrap();
        for _ in 0..3 {
            s.disconnect_tip().unwrap();
        }
        connect_all(&s, &replacement);
    }

    let s = Store::open(&path, StoreConfig::indexed()).unwrap();
    assert!(s.tx_location(&txid(&orphaned[0].block.txs[0])).is_err());

    // The replay.
    for _ in 0..5 {
        s.disconnect_tip().unwrap();
    }
    connect_all(&s, &common[1..]);
    connect_all(&s, &replacement);

    assert_eq!(s.index_height().unwrap(), Some(5));
    for blk in common.iter().chain(replacement.iter()) {
        for (i, tx) in blk.block.txs.iter().enumerate() {
            let loc = s.tx_location(&txid(tx)).unwrap().unwrap();
            assert_eq!((loc.block_hash, loc.index), (blk.hash, i as u32));
        }
    }
    // Nothing of the branch that lost survives — not even the rows the
    // unindexed reorg left behind.
    for blk in &orphaned {
        for tx in &blk.block.txs {
            assert_eq!(s.tx_location(&txid(tx)).unwrap(), None, "an orphaned row survived");
        }
    }
    assert!(!s.address_history(&pkh(700_000), 0, 10).unwrap().is_empty());
}

#[test]
fn the_recorded_index_height_follows_the_tip_in_both_directions() {
    let s = Store::open_in_memory(StoreConfig::indexed()).unwrap();
    assert_eq!(s.index_height().unwrap(), None, "nothing is indexed on an empty store");
    let mut b = ChainBuilder::new();
    let built = b.build(4);
    for blk in &built {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
        assert_eq!(s.index_height().unwrap(), Some(blk.height));
    }
    for expected in (0..3).rev() {
        s.disconnect_tip().unwrap();
        assert_eq!(s.index_height().unwrap(), Some(expected));
    }
}

#[test]
fn a_store_that_never_indexed_records_nothing_and_refuses_stale_reads() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ferrum.redb");
    let mut b = ChainBuilder::new();
    let built = b.build(4);
    {
        let s = Store::open(&path, StoreConfig::default()).unwrap();
        connect_all(&s, &built);
        assert_eq!(s.index_height().unwrap(), None);
    }
    let s = Store::open(&path, StoreConfig::indexed()).unwrap();
    // Genesis is re-established so a replay has a contiguous base, but the
    // index does not describe the tip and must not be read from.
    assert_eq!(s.index_height().unwrap(), Some(0));
    let err = s.tx_location(&txid(&built[3].block.txs[0])).unwrap_err();
    assert!(
        matches!(err, StorageError::IndexIncomplete { indexed_to: Some(0), tip_height: 3 }),
        "{err:?}"
    );
}

#[test]
fn an_index_that_matches_the_tip_survives_a_restart_without_a_repair() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ferrum.redb");
    let mut b = ChainBuilder::new();
    let built = b.build(5);
    let before = {
        let s = Store::open(&path, StoreConfig::indexed()).unwrap();
        connect_all(&s, &built);
        index_rows(&s)
    };
    let s = Store::open(&path, StoreConfig::indexed()).unwrap();
    assert_eq!(s.index_height().unwrap(), Some(4));
    assert_eq!(index_rows(&s), before, "a current index must not be rebuilt on open");
    let loc = s.tx_location(&txid(&built[4].block.txs[0])).unwrap().unwrap();
    assert_eq!(loc.block_hash, built[4].hash);
}

#[test]
fn an_empty_store_opened_with_the_index_reads_cleanly() {
    let s = Store::open_in_memory(StoreConfig::indexed()).unwrap();
    assert_eq!(s.index_height().unwrap(), None);
    let unknown = ferrum_types::Txid(ferrum_types::Hash32::from_bytes([7u8; 32]));
    assert_eq!(s.tx_location(&unknown).unwrap(), None);
    assert!(s.address_history(&pkh(1), 0, 10).unwrap().is_empty());
}

/// Every `tx_index` and `addr_index` row, sorted, for comparing two stores.
fn index_rows(s: &Store) -> Vec<(Vec<u8>, Vec<u8>)> {
    use redb::ReadableTable;

    use crate::tables::{ADDR_INDEX, TX_INDEX};

    let read = s.database().begin_read().unwrap();
    let mut out = Vec::new();
    let tx = read.open_table(TX_INDEX).unwrap();
    for entry in ReadableTable::range::<&[u8; 32]>(&tx, ..).unwrap() {
        let (k, v) = entry.unwrap();
        out.push((k.value().to_vec(), v.value().to_vec()));
    }
    let addr = read.open_table(ADDR_INDEX).unwrap();
    for entry in ReadableTable::range::<&[u8]>(&addr, ..).unwrap() {
        let (k, v) = entry.unwrap();
        out.push((k.value().to_vec(), v.value().to_vec()));
    }
    out.sort();
    out
}
