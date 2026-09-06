//! Concurrency, corruption reporting, and the address shapes the default
//! fixture never emits.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ferrum_types::{Hash32, Script};

use crate::error::StorageError;
use crate::store::{Store, StoreConfig};
use crate::tables::{outpoint_key, txid};
use crate::tests::fixtures::ChainBuilder;
use crate::view::StateView;

fn mem() -> Store {
    Store::open_in_memory(StoreConfig::default()).unwrap()
}

fn indexed() -> Store {
    Store::open_in_memory(StoreConfig::indexed()).unwrap()
}

/// Every `(addr_index key, txid)` pair plus every `tx_index` key, sorted.
fn index_snapshot(s: &Store) -> Vec<(Vec<u8>, Vec<u8>)> {
    use crate::tables::{ADDR_INDEX, HASH_KEY_LEN, TX_INDEX};
    use redb::ReadableTable;

    let read = s.database().begin_read().unwrap();
    let mut out = Vec::new();
    let addr = read.open_table(ADDR_INDEX).unwrap();
    for entry in ReadableTable::range::<&[u8]>(&addr, ..).unwrap() {
        let (k, v) = entry.unwrap();
        out.push((k.value().to_vec(), v.value().to_vec()));
    }
    let txs = read.open_table(TX_INDEX).unwrap();
    for entry in ReadableTable::range::<&[u8; HASH_KEY_LEN]>(&txs, ..).unwrap() {
        let (k, v) = entry.unwrap();
        let mut key = b"tx:".to_vec();
        key.extend_from_slice(k.value());
        out.push((key, v.value().to_vec()));
    }
    out.sort();
    out
}

#[test]
fn readers_run_concurrently_with_a_writer() {
    // `Store` is `Send + Sync` and redb is MVCC: a reader sees a consistent
    // snapshot while blocks are being connected, and neither side panics.
    let store = Arc::new(mem());
    let mut b = ChainBuilder::new();
    let built = b.build(40);

    let stop = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..3)
        .map(|_| {
            let store = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let root = store.state_root().unwrap();
                    if store.utxo_count().unwrap() > 0 {
                        assert_ne!(root, Hash32::ZERO);
                    }
                }
            })
        })
        .collect();

    for blk in &built {
        store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        r.join().unwrap();
    }
    assert_eq!(store.tip().unwrap(), Some((built[39].hash, 39)));
}

#[test]
fn flush_is_a_no_op_that_preserves_state() {
    let s = mem();
    let mut b = ChainBuilder::new();
    for blk in b.build(3) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let before = s.utxo_snapshot().unwrap();
    let tip = s.tip().unwrap();
    s.flush().unwrap();
    s.flush().unwrap();
    assert_eq!(s.utxo_snapshot().unwrap(), before);
    assert_eq!(s.tip().unwrap(), tip);
}

#[test]
fn a_store_behind_an_arc_is_a_state_view() {
    let s = Arc::new(mem());
    let mut b = ChainBuilder::new();
    let genesis = b.next(0, false);
    s.connect_block(&genesis.hash, 0, &genesis.entry, &genesis.diff, &genesis.block).unwrap();
    let (op, coin) = &genesis.diff.created[0];
    assert_eq!(StateView::get_coin(&s, op).unwrap().as_ref(), Some(coin));
    assert!(StateView::has_coin(&s, op).unwrap());
}

#[test]
fn the_utxo_snapshot_and_the_iterator_agree() {
    let s = mem();
    let mut b = ChainBuilder::new();
    for blk in b.build(12) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let snapshot = s.utxo_snapshot().unwrap();
    let iterated: Vec<_> = s.iter_utxos().unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(snapshot.len(), iterated.len());
    for ((raw_key, raw_value), (op, coin)) in snapshot.iter().zip(iterated.iter()) {
        assert_eq!(raw_key.as_slice(), outpoint_key(op).as_slice());
        assert_eq!(raw_value, &borsh::to_vec(coin).unwrap());
    }
}

#[test]
fn a_corrupt_coin_is_reported_rather_than_decoded_into_nonsense() {
    use crate::tables::UTXO;
    let s = mem();
    let mut b = ChainBuilder::new();
    let genesis = b.next(0, false);
    s.connect_block(&genesis.hash, 0, &genesis.entry, &genesis.diff, &genesis.block).unwrap();
    let (op, _) = genesis.diff.created[0];

    let txn = s.database().begin_write().unwrap();
    {
        let mut t = txn.open_table(UTXO).unwrap();
        t.insert(&outpoint_key(&op), [0xffu8, 0xff].as_slice()).unwrap();
    }
    txn.commit().unwrap();

    let e = s.get_coin(&op).unwrap_err();
    assert!(matches!(e, StorageError::Corrupt { kind: "coin", .. }), "{e:?}");
    // `has_coin` answers from the key alone, so it still says yes: the crate
    // never guesses at a value it could not decode.
    assert!(StateView::has_coin(&s, &op).unwrap());
}

#[test]
fn a_corrupt_tip_value_is_reported() {
    use crate::tables::{META, META_TIP};
    let s = mem();
    let txn = s.database().begin_write().unwrap();
    {
        let mut t = txn.open_table(META).unwrap();
        t.insert(META_TIP, [1u8, 2, 3].as_slice()).unwrap();
    }
    txn.commit().unwrap();
    let e = s.tip().unwrap_err();
    assert!(matches!(e, StorageError::BadLength { kind: "meta.tip", .. }), "{e:?}");
}

#[test]
fn a_corrupt_engine_value_is_reported() {
    use crate::tables::{META, META_ENGINE};
    let s = mem();
    let txn = s.database().begin_write().unwrap();
    {
        let mut t = txn.open_table(META).unwrap();
        t.insert(META_ENGINE, [1u8, 2].as_slice()).unwrap();
    }
    txn.commit().unwrap();
    assert!(matches!(
        s.engine().unwrap_err(),
        StorageError::BadLength { kind: "meta.engine", expected: 1, found: 2 }
    ));
}

#[test]
fn a_corrupt_block_record_is_reported() {
    use crate::tables::{BLOCKS, hash_key};
    let s = mem();
    let mut b = ChainBuilder::new();
    let genesis = b.next(0, false);
    s.connect_block(&genesis.hash, 0, &genesis.entry, &genesis.diff, &genesis.block).unwrap();
    let txn = s.database().begin_write().unwrap();
    {
        let mut t = txn.open_table(BLOCKS).unwrap();
        t.insert(&hash_key(&genesis.hash), [0x01u8].as_slice()).unwrap();
    }
    txn.commit().unwrap();
    let e = s.get_block(&genesis.hash).unwrap_err();
    assert!(matches!(e, StorageError::Corrupt { kind: "block", .. }), "{e:?}");
}

#[test]
fn a_p2sh_output_is_indexed_under_its_thirty_two_byte_script_hash() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    for blk in b.build(3) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let script_hash = [0x7cu8; 32];
    let mut p2sh = vec![0xaa, 0x20];
    p2sh.extend_from_slice(&script_hash);
    p2sh.push(0x87);
    let blk = b.next_paying_to(Script::new(p2sh));
    s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();

    let history = s.address_history(&script_hash, 0, 10).unwrap();
    assert_eq!(history.len(), 1, "{history:?}");
    assert_eq!(history[0], (blk.height, txid(&blk.block.txs[0])));

    s.disconnect_tip().unwrap();
    assert!(s.address_history(&script_hash, 0, 10).unwrap().is_empty());
}

#[test]
fn a_p2pk_output_is_indexed_under_the_hash_of_its_key() {
    let s = indexed();
    let pk = [0x31u8; 32];
    let mut script = vec![0x20];
    script.extend_from_slice(&pk);
    script.push(0xac);
    let mut b = ChainBuilder::new();
    let blk = b.next_paying_to(Script::new(script));
    s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    let key = ferrum_crypto::hash160(&pk);
    assert_eq!(s.address_history(&key, 0, 10).unwrap().len(), 1);
}

#[test]
fn an_unindexable_script_is_simply_skipped() {
    // An OP_RETURN output has no address; indexing must neither fail nor
    // invent a key for it.
    let s = indexed();
    let mut b = ChainBuilder::new();
    let mut script = vec![0x6a, 0x05];
    script.extend_from_slice(b"hello");
    let blk = b.next_paying_to(Script::new(script));
    s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    assert!(s.tx_location(&txid(&blk.block.txs[0])).unwrap().is_some());
    assert!(index_snapshot(&s).iter().all(|(k, _)| k.starts_with(b"tx:")));
}

#[test]
fn reconnecting_restores_the_index_exactly() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    let built = b.build(9);
    for blk in &built {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let full = index_snapshot(&s);
    for _ in 0..4 {
        s.disconnect_tip().unwrap();
    }
    for blk in &built[5..] {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    assert_eq!(index_snapshot(&s), full);
}

#[test]
fn the_engine_meta_key_follows_the_parent_on_a_disconnect() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let built = b.build(4);
    for blk in &built {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    assert_eq!(s.engine().unwrap(), Some(0));

    s.disconnect_tip().unwrap();
    let mut bft = built[3].clone();
    bft.entry.seal_engine = 1;
    s.connect_block(&bft.hash, bft.height, &bft.entry, &bft.diff, &bft.block).unwrap();
    assert_eq!(s.engine().unwrap(), Some(1));
    // Disconnecting it drops back to the parent's engine, not to nothing.
    s.disconnect_tip().unwrap();
    assert_eq!(s.engine().unwrap(), Some(0));
}

#[test]
fn a_disconnect_leaves_the_undo_record_for_a_later_reconnect() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let built = b.build(5);
    for blk in &built {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let tip = built[4].clone();
    s.disconnect_tip().unwrap();
    let kept = s.get_undo(&tip.hash).unwrap();
    assert_eq!(kept, Some(tip.diff.undo_block()));
    s.connect_block(&tip.hash, tip.height, &tip.entry, &tip.diff, &tip.block).unwrap();
    assert_eq!(s.get_undo(&tip.hash).unwrap(), kept);
}

#[test]
fn undo_digests_distinguish_blocks_that_spent_different_coins() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let built = b.build(8);
    for blk in &built {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let non_empty: Vec<_> = built
        .iter()
        .filter(|blk| !blk.diff.spent.is_empty())
        .map(|blk| s.get_undo(&blk.hash).unwrap().unwrap().digest())
        .collect();
    assert!(non_empty.len() >= 2);
    let mut sorted = non_empty.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), non_empty.len());
}
