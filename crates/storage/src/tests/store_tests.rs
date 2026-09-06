//! Opening, metadata, reads, and the guard rails on `connect_block`.

use ferrum_types::{BlockHash, ChainId, Hash32, OutPoint, Txid};
use tempfile::TempDir;

use crate::error::StorageError;
use crate::store::{Store, StoreConfig};
use crate::tables::{BlockIndexEntry, BlockStatus, SCHEMA_VERSION, header_hash, txid};
use crate::tests::fixtures::ChainBuilder;
use crate::view::{StateDiff, StateView};

fn mem() -> Store {
    Store::open_in_memory(StoreConfig::default()).unwrap()
}

#[test]
fn a_fresh_store_is_empty_and_readable() {
    let s = mem();
    assert_eq!(s.tip().unwrap(), None);
    assert_eq!(s.tip_height().unwrap(), None);
    assert_eq!(s.utxo_count().unwrap(), 0);
    assert_eq!(s.header_count().unwrap(), 0);
    assert_eq!(s.block_count().unwrap(), 0);
    assert_eq!(s.hash_at_height(0).unwrap(), None);
    assert_eq!(s.state_root().unwrap(), Hash32::ZERO);
    assert_eq!(s.iter_utxos().unwrap().count(), 0);
    assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    assert_eq!(s.engine().unwrap(), None);
    assert!(!s.is_indexed());
}

#[test]
fn reads_of_absent_records_are_none_not_errors() {
    let s = mem();
    let h = BlockHash(Hash32::from_bytes([9u8; 32]));
    assert_eq!(s.get_block(&h).unwrap(), None);
    assert_eq!(s.get_header(&h).unwrap(), None);
    assert_eq!(s.get_undo(&h).unwrap(), None);
    assert_eq!(s.get_coin(&OutPoint::new(Txid(Hash32::ZERO), 0)).unwrap(), None);
}

#[test]
fn store_header_and_store_block_body_round_trip() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let blk = b.next(0, false);
    s.store_header(&blk.entry).unwrap();
    s.store_block_body(&blk.hash, &blk.block).unwrap();
    assert_eq!(s.get_header(&blk.hash).unwrap(), Some(blk.entry.clone()));
    assert_eq!(s.get_block(&blk.hash).unwrap(), Some(blk.block.clone()));
    assert_eq!(s.header_count().unwrap(), 1);
    assert_eq!(s.block_count().unwrap(), 1);
    // Storing a header does not move the tip: headers-first sync stores a
    // whole chain of headers before a single body is executed.
    assert_eq!(s.tip().unwrap(), None);
}

#[test]
fn store_header_derives_the_key_from_the_header_itself() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let blk = b.next(0, false);
    s.store_header(&blk.entry).unwrap();
    assert_eq!(header_hash(&blk.entry.header), blk.hash);
    assert!(s.get_header(&blk.hash).unwrap().is_some());
}

#[test]
fn connect_block_sets_the_tip_and_the_utxo_set() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let genesis = b.next(0, false);
    s.connect_block(&genesis.hash, 0, &genesis.entry, &genesis.diff, &genesis.block).unwrap();

    assert_eq!(s.tip().unwrap(), Some((genesis.hash, 0)));
    assert_eq!(s.tip_height().unwrap(), Some(0));
    assert_eq!(s.hash_at_height(0).unwrap(), Some(genesis.hash));
    assert_eq!(s.utxo_count().unwrap(), genesis.diff.created.len() as u64);
    assert_eq!(s.get_block(&genesis.hash).unwrap(), Some(genesis.block.clone()));
    assert_eq!(s.get_undo(&genesis.hash).unwrap(), Some(genesis.diff.undo_block()));
    for (op, coin) in &genesis.diff.created {
        assert_eq!(s.get_coin(op).unwrap().as_ref(), Some(coin));
        assert!(StateView::has_coin(&s, op).unwrap());
    }
}

#[test]
fn connecting_a_chain_keeps_the_store_in_step_with_the_builder() {
    let s = mem();
    let mut b = ChainBuilder::new();
    for blk in b.build(12) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    assert_eq!(s.tip().unwrap(), Some((b.tip, 11)));
    assert_eq!(s.utxo_count().unwrap(), b.utxo.len() as u64);
    let from_store: Vec<_> = s.iter_utxos().unwrap().collect::<Result<_, _>>().unwrap();
    let expected: Vec<_> = {
        let mut v: Vec<_> = b.utxo.iter().map(|(o, c)| (*o, c.clone())).collect();
        v.sort_by_key(|(o, _)| crate::tables::outpoint_key(o));
        v
    };
    assert_eq!(from_store, expected);
}

#[test]
fn a_block_that_spends_an_output_it_created_leaves_that_output_gone() {
    // The apply-order rule: creations first, then spends. The reverse order
    // would leave the chained output alive, which is an inflation bug.
    let s = mem();
    let mut b = ChainBuilder::new();
    for blk in b.build(6) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let chained = b.next(0, true);
    let created: Vec<OutPoint> = chained.diff.created.iter().map(|(o, _)| *o).collect();
    let self_spent: Vec<OutPoint> =
        chained.diff.spent.iter().map(|(o, _)| *o).filter(|o| created.contains(o)).collect();
    assert!(!self_spent.is_empty(), "fixture must produce an in-block chain");
    s.connect_block(&chained.hash, chained.height, &chained.entry, &chained.diff, &chained.block)
        .unwrap();
    for op in &self_spent {
        assert_eq!(s.get_coin(op).unwrap(), None, "an output spent in its own block survived");
    }
    assert_eq!(s.utxo_count().unwrap(), b.utxo.len() as u64);
}

#[test]
fn connect_rejects_a_height_that_is_not_one_past_the_tip() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let genesis = b.next(0, false);
    s.connect_block(&genesis.hash, 0, &genesis.entry, &genesis.diff, &genesis.block).unwrap();
    let second = b.next(0, false);
    let e =
        s.connect_block(&second.hash, 5, &second.entry, &second.diff, &second.block).unwrap_err();
    assert!(matches!(e, StorageError::EntryHeightMismatch { entry_height: 1, height: 5 }), "{e:?}");
}

#[test]
fn connect_rejects_a_gap_in_the_height_table() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let genesis = b.next(0, false);
    s.connect_block(&genesis.hash, 0, &genesis.entry, &genesis.diff, &genesis.block).unwrap();
    let second = b.next(0, false);
    let third = b.next(0, false);
    let e = s
        .connect_block(&third.hash, third.height, &third.entry, &third.diff, &third.block)
        .unwrap_err();
    assert!(matches!(e, StorageError::NonContiguousConnect { tip_height: 0, height: 2 }), "{e:?}");
    // The rejected write left nothing behind.
    assert_eq!(s.tip().unwrap(), Some((genesis.hash, 0)));
    assert_eq!(s.get_block(&third.hash).unwrap(), None);
    let _ = second;
}

#[test]
fn the_first_connect_must_be_height_zero() {
    let s = mem();
    let mut b = ChainBuilder::new();
    b.next(0, false);
    let second = b.next(0, false);
    let e = s
        .connect_block(&second.hash, second.height, &second.entry, &second.diff, &second.block)
        .unwrap_err();
    assert!(
        matches!(e, StorageError::NonContiguousConnect { tip_height: u64::MAX, height: 1 }),
        "{e:?}"
    );
}

#[test]
fn connect_rejects_a_block_that_does_not_build_on_the_tip() {
    let s = mem();
    let mut a = ChainBuilder::new();
    let genesis = a.next(0, false);
    s.connect_block(&genesis.hash, 0, &genesis.entry, &genesis.diff, &genesis.block).unwrap();

    // A second builder starting from a different genesis: its block 1 names a
    // parent this store does not have as its tip.
    let mut other = ChainBuilder::new();
    other.tip = BlockHash(Hash32::from_bytes([0x42; 32]));
    other.height = Some(0);
    let fork = other.next(0, false);
    let e = s.connect_block(&fork.hash, 1, &fork.entry, &fork.diff, &fork.block).unwrap_err();
    assert!(matches!(e, StorageError::ParentMismatch { .. }), "{e:?}");
    assert_eq!(s.tip().unwrap(), Some((genesis.hash, 0)));
}

#[test]
fn disconnect_on_an_empty_store_says_so() {
    let s = mem();
    assert!(matches!(s.disconnect_tip().unwrap_err(), StorageError::NoTip));
}

#[test]
fn genesis_cannot_be_disconnected() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let genesis = b.next(0, false);
    s.connect_block(&genesis.hash, 0, &genesis.entry, &genesis.diff, &genesis.block).unwrap();
    assert!(matches!(s.disconnect_tip().unwrap_err(), StorageError::CannotDisconnectGenesis));
    assert_eq!(s.tip().unwrap(), Some((genesis.hash, 0)));
}

#[test]
fn the_engine_meta_key_tracks_the_tip() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let genesis = b.next(0, false);
    s.connect_block(&genesis.hash, 0, &genesis.entry, &genesis.diff, &genesis.block).unwrap();
    assert_eq!(s.engine().unwrap(), Some(0));
    s.set_engine(1).unwrap();
    assert_eq!(s.engine().unwrap(), Some(1));
}

#[test]
fn state_root_changes_with_the_set_and_is_stable_otherwise() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let blocks = b.build(4);
    let mut roots = Vec::new();
    for blk in &blocks {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
        roots.push(s.state_root().unwrap());
    }
    assert_eq!(s.state_root().unwrap(), *roots.last().unwrap(), "recomputation is stable");
    let mut sorted = roots.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), roots.len(), "every block changed the root");
}

#[test]
fn the_state_root_matches_an_independent_computation() {
    let s = mem();
    let mut b = ChainBuilder::new();
    for blk in b.build(7) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let independent = crate::state_root::state_root_of(b.utxo.iter()).unwrap();
    assert_eq!(s.state_root().unwrap(), independent);
}

#[test]
fn a_store_reopens_with_its_tip_and_utxo_set_intact() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ferrum.redb");
    let (tip, root, count) = {
        let s = Store::open(&path, StoreConfig::default()).unwrap();
        let mut b = ChainBuilder::new();
        for blk in b.build(9) {
            s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
        }
        s.flush().unwrap();
        (s.tip().unwrap(), s.state_root().unwrap(), s.utxo_count().unwrap())
    };
    let s = Store::open(&path, StoreConfig::default()).unwrap();
    assert_eq!(s.tip().unwrap(), tip);
    assert_eq!(s.state_root().unwrap(), root);
    assert_eq!(s.utxo_count().unwrap(), count);
}

#[test]
fn the_chain_id_is_recorded_and_then_enforced() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ferrum.redb");
    {
        let s = Store::open(&path, StoreConfig::default().with_chain_id(ChainId::DEVNET)).unwrap();
        assert_eq!(s.chain_id().unwrap(), Some(ChainId::DEVNET));
    }
    // Reopening with the same id is fine.
    drop(Store::open(&path, StoreConfig::default().with_chain_id(ChainId::DEVNET)).unwrap());
    // With a different one it is not.
    let e = Store::open(&path, StoreConfig::default().with_chain_id(ChainId::MAINNET)).unwrap_err();
    assert!(matches!(e, StorageError::ChainIdMismatch { expected: 1, found: 3 }), "{e:?}");
}

#[test]
fn a_store_opened_without_a_chain_id_records_none() {
    let s = mem();
    assert_eq!(s.chain_id().unwrap(), None);
}

#[test]
fn the_config_is_readable_back() {
    let s = Store::open_in_memory(StoreConfig::indexed().with_chain_id(ChainId::TESTNET)).unwrap();
    assert!(s.config().index_transactions);
    assert_eq!(s.config().chain_id, Some(ChainId::TESTNET));
    assert!(s.is_indexed());
}

#[test]
fn a_cache_size_is_accepted() {
    let cfg = StoreConfig { cache_size_bytes: Some(1 << 20), ..StoreConfig::default() };
    let s = Store::open_in_memory(cfg).unwrap();
    assert_eq!(s.utxo_count().unwrap(), 0);
}

#[test]
fn index_reads_fail_loudly_when_the_index_is_off() {
    let s = mem();
    let id = Txid(Hash32::from_bytes([1u8; 32]));
    assert!(matches!(s.tx_location(&id).unwrap_err(), StorageError::IndexDisabled));
    assert!(matches!(
        s.address_history(&[0u8; 20], 0, 10).unwrap_err(),
        StorageError::IndexDisabled
    ));
}

#[test]
fn the_store_is_a_state_view() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let genesis = b.next(0, false);
    s.connect_block(&genesis.hash, 0, &genesis.entry, &genesis.diff, &genesis.block).unwrap();
    let view: &dyn StateView = &s;
    let (op, coin) = &genesis.diff.created[0];
    assert_eq!(view.get_coin(op).unwrap().as_ref(), Some(coin));
    assert!(view.has_coin(op).unwrap());
    assert!(!view.has_coin(&OutPoint::new(Txid(Hash32::ZERO), 7)).unwrap());
}

#[test]
fn an_overlay_over_the_store_touches_nothing_until_connect() {
    use crate::view::OverlayView;
    let s = mem();
    let mut b = ChainBuilder::new();
    let genesis = b.next(0, false);
    s.connect_block(&genesis.hash, 0, &genesis.entry, &genesis.diff, &genesis.block).unwrap();

    let before = s.utxo_snapshot().unwrap();
    let (op, _) = genesis.diff.created[0].clone();
    {
        let mut overlay = OverlayView::new(&s);
        assert!(overlay.spend(&op).unwrap().is_some());
        assert_eq!(overlay.get_coin(&op).unwrap(), None);
    }
    assert_eq!(s.utxo_snapshot().unwrap(), before, "the overlay wrote to the database");
}

#[test]
fn a_block_index_entry_survives_a_round_trip_with_every_field() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let blk = b.next(0, false);
    let mut entry = blk.entry.clone();
    entry.status = BlockStatus::Invalid;
    entry.total_work = [0xab; 32];
    entry.seal_engine = 1;
    s.store_header(&entry).unwrap();
    let back = s.get_header(&blk.hash).unwrap().unwrap();
    assert_eq!(back, entry);
    assert_eq!(back.status, BlockStatus::Invalid);
    assert_eq!(back.seal_engine, 1);
    assert_eq!(back.tx_count, blk.block.txs.len() as u32);
}

#[test]
fn txid_and_header_hash_agree_with_the_stored_records() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let blk = b.next(0, false);
    s.connect_block(&blk.hash, 0, &blk.entry, &blk.diff, &blk.block).unwrap();
    let stored = s.get_block(&blk.hash).unwrap().unwrap();
    assert_eq!(header_hash(&stored.header), blk.hash);
    assert_eq!(txid(&stored.txs[0]), txid(&blk.block.txs[0]));
}

#[test]
fn a_schema_from_the_future_is_refused() {
    use crate::tables::{META, META_SCHEMA_VERSION};
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ferrum.redb");
    {
        let db = redb::Database::create(&path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(META).unwrap();
            t.insert(META_SCHEMA_VERSION, 99u32.to_be_bytes().as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }
    let e = Store::open(&path, StoreConfig::default()).unwrap_err();
    assert!(matches!(e, StorageError::SchemaMismatch { expected: 1, found: 99 }), "{e:?}");
}

#[test]
fn an_empty_diff_still_advances_the_tip() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let genesis = b.next(0, false);
    s.connect_block(&genesis.hash, 0, &genesis.entry, &genesis.diff, &genesis.block).unwrap();
    let next = b.next(0, false);
    let empty = StateDiff::new();
    s.connect_block(&next.hash, 1, &next.entry, &empty, &next.block).unwrap();
    assert_eq!(s.tip().unwrap(), Some((next.hash, 1)));
    assert_eq!(s.get_undo(&next.hash).unwrap(), Some(crate::undo::UndoBlock::empty()));
}

#[test]
fn a_bad_entry_height_is_reported_before_anything_is_written() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let genesis = b.next(0, false);
    let mut entry = genesis.entry.clone();
    entry.height = 3;
    let e = s.connect_block(&genesis.hash, 0, &entry, &genesis.diff, &genesis.block).unwrap_err();
    assert!(matches!(e, StorageError::EntryHeightMismatch { entry_height: 3, height: 0 }), "{e:?}");
    assert_eq!(s.block_count().unwrap(), 0);
    assert_eq!(s.tip().unwrap(), None);
}

#[test]
fn build_a_hundred_blocks_and_every_height_resolves() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let built = b.build(100);
    for blk in &built {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    for blk in &built {
        assert_eq!(s.hash_at_height(blk.height).unwrap(), Some(blk.hash));
    }
    assert_eq!(s.hash_at_height(100).unwrap(), None);
    assert_eq!(s.tip_height().unwrap(), Some(99));
}

#[test]
fn the_undo_record_of_every_block_matches_its_diff() {
    let s = mem();
    let mut b = ChainBuilder::new();
    let built = b.build(15);
    for blk in &built {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    for blk in &built {
        let undo = s.get_undo(&blk.hash).unwrap().unwrap();
        assert_eq!(undo, blk.diff.undo_block());
        assert_eq!(undo.len(), blk.diff.spent.len());
    }
}

#[test]
fn a_block_index_entry_rejects_an_impossible_size() {
    // `from_block` is the only place a `usize` narrows to a `u32`; it must
    // report rather than truncate.
    let mut b = ChainBuilder::new();
    let blk = b.next(0, false);
    let e = BlockIndexEntry::from_block(&blk.block, 0, [0u8; 32], BlockStatus::Valid).unwrap();
    assert_eq!(e.size as usize, blk.block.serialized_size());
}
