//! Disconnect and reconnect — the byte-identity guarantee (SPEC §7.3).
//!
//! > *Disconnecting N blocks and reconnecting them yields a byte-identical
//! > UTXO set and an identical state root.*
//!
//! Byte-identical, not merely equal: a comparison of decoded coins would pass
//! even if the stored encoding had changed, and the state root is computed
//! over the stored bytes.

use crate::store::{Store, StoreConfig};
use crate::tests::fixtures::ChainBuilder;

fn connected(n: usize) -> (Store, ChainBuilder, Vec<crate::tests::fixtures::Built>) {
    let store = Store::open_in_memory(StoreConfig::default()).unwrap();
    let mut b = ChainBuilder::new();
    let built = b.build(n);
    for blk in &built {
        store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    (store, b, built)
}

#[test]
fn connect_six_then_disconnect_six_is_byte_identical() {
    let (store, mut b, _) = connected(14);
    let snapshot = store.utxo_snapshot().unwrap();
    let root = store.state_root().unwrap();
    let tip = store.tip().unwrap();
    let count = store.utxo_count().unwrap();

    let extra = b.build(6);
    for blk in &extra {
        store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    assert_ne!(store.utxo_snapshot().unwrap(), snapshot, "six blocks changed nothing");
    assert_ne!(store.state_root().unwrap(), root);

    for blk in extra.iter().rev() {
        assert_eq!(store.disconnect_tip().unwrap(), blk.hash);
    }

    assert_eq!(store.utxo_snapshot().unwrap(), snapshot, "the UTXO set is not byte-identical");
    assert_eq!(store.state_root().unwrap(), root);
    assert_eq!(store.tip().unwrap(), tip);
    assert_eq!(store.utxo_count().unwrap(), count);
}

#[test]
fn disconnecting_all_the_way_back_to_genesis_is_byte_identical() {
    let store = Store::open_in_memory(StoreConfig::default()).unwrap();
    let mut b = ChainBuilder::new();
    let genesis = b.next(0, false);
    store.connect_block(&genesis.hash, 0, &genesis.entry, &genesis.diff, &genesis.block).unwrap();
    let after_genesis = store.utxo_snapshot().unwrap();
    let genesis_root = store.state_root().unwrap();

    let rest = b.build(12);
    for blk in &rest {
        store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    for _ in 0..rest.len() {
        store.disconnect_tip().unwrap();
    }

    assert_eq!(store.tip().unwrap(), Some((genesis.hash, 0)));
    assert_eq!(store.utxo_snapshot().unwrap(), after_genesis);
    assert_eq!(store.state_root().unwrap(), genesis_root);
}

#[test]
fn disconnect_then_reconnect_returns_to_the_same_bytes() {
    let (store, mut b, _) = connected(10);
    let extra = b.build(6);
    for blk in &extra {
        store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let after = store.utxo_snapshot().unwrap();
    let root = store.state_root().unwrap();

    for _ in 0..6 {
        store.disconnect_tip().unwrap();
    }
    for blk in &extra {
        store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }

    assert_eq!(store.utxo_snapshot().unwrap(), after);
    assert_eq!(store.state_root().unwrap(), root);
    assert_eq!(store.tip().unwrap(), Some((extra[5].hash, extra[5].height)));
}

#[test]
fn disconnecting_a_chained_block_does_not_resurrect_its_internal_output() {
    // The inverse of the apply-order rule: restore spends, then remove
    // creations. Getting it backwards leaves the intermediate output alive
    // after the block is gone.
    let (store, mut b, _) = connected(6);
    let before = store.utxo_snapshot().unwrap();
    let chained = b.next(0, true);
    let created: Vec<_> = chained.diff.created.iter().map(|(o, _)| *o).collect();
    let internal: Vec<_> =
        chained.diff.spent.iter().map(|(o, _)| *o).filter(|o| created.contains(o)).collect();
    assert!(!internal.is_empty());

    store
        .connect_block(&chained.hash, chained.height, &chained.entry, &chained.diff, &chained.block)
        .unwrap();
    store.disconnect_tip().unwrap();

    for op in &internal {
        assert_eq!(store.get_coin(op).unwrap(), None, "an in-block output was resurrected");
    }
    assert_eq!(store.utxo_snapshot().unwrap(), before);
}

#[test]
fn disconnect_removes_the_height_entry_and_moves_the_tip_to_the_parent() {
    let (store, _, built) = connected(5);
    assert_eq!(store.hash_at_height(4).unwrap(), Some(built[4].hash));
    let removed = store.disconnect_tip().unwrap();
    assert_eq!(removed, built[4].hash);
    assert_eq!(store.hash_at_height(4).unwrap(), None);
    assert_eq!(store.tip().unwrap(), Some((built[3].hash, 3)));
}

#[test]
fn a_disconnected_block_keeps_its_body_header_and_undo_record() {
    // The block is now a side-chain candidate, not garbage: a reorg that comes
    // back to it must find its body without re-downloading.
    let (store, _, built) = connected(4);
    let tip = built[3].clone();
    store.disconnect_tip().unwrap();
    assert_eq!(store.get_block(&tip.hash).unwrap(), Some(tip.block.clone()));
    assert_eq!(store.get_header(&tip.hash).unwrap(), Some(tip.entry.clone()));
    assert_eq!(store.get_undo(&tip.hash).unwrap(), Some(tip.diff.undo_block()));
}

#[test]
fn the_restored_coins_are_the_ones_the_undo_record_named() {
    let (store, _, built) = connected(9);
    let tip = built[8].clone();
    // The tip's spends are absent while it is connected.
    for (op, _) in &tip.diff.spent {
        assert_eq!(store.get_coin(op).unwrap(), None);
    }
    store.disconnect_tip().unwrap();
    let created: Vec<_> = tip.diff.created.iter().map(|(o, _)| *o).collect();
    for (op, coin) in &tip.diff.spent {
        if created.contains(op) {
            continue; // created and spent in the same block: stays gone
        }
        assert_eq!(store.get_coin(op).unwrap().as_ref(), Some(coin));
    }
    for (op, _) in &tip.diff.created {
        assert_eq!(store.get_coin(op).unwrap(), None);
    }
}

#[test]
fn a_missing_undo_record_is_a_typed_error_not_a_silent_wrong_answer() {
    use crate::error::StorageError;
    use crate::tables::{UNDO, hash_key};
    let (store, _, built) = connected(3);
    let tip = built[2].hash;
    // Delete the undo record behind the store's back.
    let txn = store.database().begin_write().unwrap();
    {
        let mut t = txn.open_table(UNDO).unwrap();
        t.remove(&hash_key(&tip)).unwrap();
    }
    txn.commit().unwrap();

    let e = store.disconnect_tip().unwrap_err();
    assert!(matches!(e, StorageError::MissingUndo(h) if h == tip), "{e:?}");
    assert_eq!(store.tip().unwrap(), Some((tip, 2)), "the failed disconnect changed nothing");
}

#[test]
fn a_missing_block_body_is_a_typed_error() {
    use crate::error::StorageError;
    use crate::tables::{BLOCKS, hash_key};
    let (store, _, built) = connected(3);
    let tip = built[2].hash;
    let txn = store.database().begin_write().unwrap();
    {
        let mut t = txn.open_table(BLOCKS).unwrap();
        t.remove(&hash_key(&tip)).unwrap();
    }
    txn.commit().unwrap();

    let e = store.disconnect_tip().unwrap_err();
    assert!(matches!(e, StorageError::MissingBlock(h) if h == tip), "{e:?}");
    assert_eq!(store.tip().unwrap(), Some((tip, 2)));
}

#[test]
fn twenty_rounds_of_disconnect_and_reconnect_never_drift() {
    let (store, mut b, _) = connected(8);
    let base = store.utxo_snapshot().unwrap();
    let base_root = store.state_root().unwrap();
    let extra = b.build(3);
    for round in 0..20 {
        for blk in &extra {
            store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
        }
        for _ in 0..extra.len() {
            store.disconnect_tip().unwrap();
        }
        assert_eq!(store.utxo_snapshot().unwrap(), base, "drift after round {round}");
        assert_eq!(store.state_root().unwrap(), base_root, "root drift after round {round}");
    }
}

#[test]
fn the_state_root_after_a_reorg_equals_a_replay_from_zero() {
    // The property M4 turns on: a forced reorg equals a genesis replay.
    let (store, mut b, _) = connected(10);
    let extra = b.build(6);
    for blk in &extra {
        store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    for _ in 0..6 {
        store.disconnect_tip().unwrap();
    }
    for blk in &extra {
        store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }

    let replay = Store::open_in_memory(StoreConfig::default()).unwrap();
    let mut fresh = ChainBuilder::new();
    for blk in fresh.build(16) {
        replay.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }

    assert_eq!(store.tip().unwrap(), replay.tip().unwrap());
    assert_eq!(store.state_root().unwrap(), replay.state_root().unwrap());
    assert_eq!(store.utxo_snapshot().unwrap(), replay.utxo_snapshot().unwrap());
}
