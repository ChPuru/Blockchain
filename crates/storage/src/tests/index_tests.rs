//! The reverse index: `tx_location`, `address_history` paging, and the
//! requirement that a disconnect removes exactly what a connect wrote.

use crate::error::StorageError;
use crate::index::TxLocation;
use crate::store::{Store, StoreConfig};
use crate::tables::txid;
use crate::tests::fixtures::{ChainBuilder, pkh};

fn indexed() -> Store {
    Store::open_in_memory(StoreConfig::indexed()).unwrap()
}

#[test]
fn every_transaction_of_a_connected_block_is_locatable() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    let built = b.build(8);
    for blk in &built {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    for blk in &built {
        for (i, tx) in blk.block.txs.iter().enumerate() {
            let loc = s.tx_location(&txid(tx)).unwrap().unwrap();
            assert_eq!(loc, TxLocation::new(blk.hash, i as u32));
        }
    }
}

#[test]
fn an_unknown_txid_has_no_location() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    let blk = b.next(0, false);
    s.connect_block(&blk.hash, 0, &blk.entry, &blk.diff, &blk.block).unwrap();
    let unknown = ferrum_types::Txid(ferrum_types::Hash32::from_bytes([0xee; 32]));
    assert_eq!(s.tx_location(&unknown).unwrap(), None);
}

#[test]
fn a_coinbase_output_shows_up_in_its_address_history() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    let built = b.build(5);
    for blk in &built {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    for blk in &built {
        // Each coinbase pays `pkh(height)`.
        let history = s.address_history(&pkh(blk.height), 0, 100).unwrap();
        assert!(
            history.iter().any(|(h, id)| *h == blk.height && *id == txid(&blk.block.txs[0])),
            "coinbase of height {} missing from its own address history",
            blk.height
        );
    }
}

#[test]
fn a_spend_is_indexed_under_the_address_it_spends_from() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    let built = b.build(6);
    for blk in &built {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    // Block 0's coinbase pays pkh(0) and is later spent; the spending
    // transaction must appear under pkh(0) too, at its own height.
    let funded = pkh(0);
    let history = s.address_history(&funded, 0, 100).unwrap();
    assert!(history.len() >= 2, "expected the funding and the spend: {history:?}");
    assert_eq!(history[0].0, 0, "the funding comes first");
    assert!(history.iter().any(|(h, _)| *h > 0), "no spend was indexed");
}

#[test]
fn history_is_ordered_by_height_then_position() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    for blk in b.build(20) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let history = s.address_history(&pkh(0), 0, 1000).unwrap();
    let heights: Vec<u64> = history.iter().map(|(h, _)| *h).collect();
    let mut sorted = heights.clone();
    sorted.sort_unstable();
    assert_eq!(heights, sorted);
}

#[test]
fn paging_with_from_height_and_limit_walks_the_whole_history() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    for blk in b.build(24) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    // Every coinbase pays a distinct address, so scan one address that has
    // several entries: pkh(0) funds block 0 and is spent later.
    let key = pkh(0);
    let all = s.address_history(&key, 0, 1000).unwrap();
    assert!(all.len() >= 2);

    // Page one entry at a time, advancing past each height.
    let mut paged = Vec::new();
    let mut from = 0u64;
    loop {
        let page = s.address_history(&key, from, 1).unwrap();
        let Some((height, id)) = page.first().copied() else { break };
        paged.push((height, id));
        let Some(next) = height.checked_add(1) else { break };
        from = next;
    }
    // Each height in `all` appears once in `paged` (one entry per height for
    // this address), and they are the same heights in the same order.
    let all_heights: Vec<u64> = {
        let mut v: Vec<u64> = all.iter().map(|(h, _)| *h).collect();
        v.dedup();
        v
    };
    let paged_heights: Vec<u64> = paged.iter().map(|(h, _)| *h).collect();
    assert_eq!(paged_heights, all_heights);
}

#[test]
fn limit_zero_returns_nothing_and_limit_caps_the_page() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    for blk in b.build(12) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let key = pkh(0);
    assert!(s.address_history(&key, 0, 0).unwrap().is_empty());
    let all = s.address_history(&key, 0, 1000).unwrap();
    if all.len() > 1 {
        assert_eq!(s.address_history(&key, 0, 1).unwrap().len(), 1);
    }
}

#[test]
fn from_height_skips_earlier_entries() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    for blk in b.build(16) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let key = pkh(0);
    let all = s.address_history(&key, 0, 1000).unwrap();
    let last_height = all.last().unwrap().0;
    let tail = s.address_history(&key, last_height, 1000).unwrap();
    assert_eq!(tail.last(), all.last());
    assert!(tail.len() <= all.len());
    let beyond = s.address_history(&key, last_height + 1, 1000).unwrap();
    assert!(beyond.is_empty(), "{beyond:?}");
}

#[test]
fn an_unknown_address_has_an_empty_history() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    for blk in b.build(4) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    assert!(s.address_history(&[0x5a; 20], 0, 100).unwrap().is_empty());
    assert!(s.address_history(&[0x5a; 32], 0, 100).unwrap().is_empty());
}

#[test]
fn a_thirty_two_byte_key_does_not_collect_a_twenty_byte_key_s_entries() {
    // The prefix hazard: `addr20 ‖ height ‖ idx` and `addr32 ‖ height ‖ idx`
    // can share their first twenty bytes, and a naive range would mix them.
    use crate::tables::{ADDR_INDEX, addr_index_key};
    let s = indexed();
    let short = [0x11u8; 20];
    let mut long = [0x11u8; 32];
    long[20..].copy_from_slice(&[0x00; 12]);

    let txn = s.database().begin_write().unwrap();
    {
        let mut t = txn.open_table(ADDR_INDEX).unwrap();
        t.insert(addr_index_key(&short, 1, 0).as_slice(), &[0xaa; 32]).unwrap();
        t.insert(addr_index_key(&long, 1, 0).as_slice(), &[0xbb; 32]).unwrap();
    }
    txn.commit().unwrap();

    let short_hits = s.address_history(&short, 0, 100).unwrap();
    assert_eq!(short_hits.len(), 1, "{short_hits:?}");
    assert_eq!(short_hits[0].1.as_bytes(), &[0xaa; 32]);

    let long_hits = s.address_history(&long, 0, 100).unwrap();
    assert_eq!(long_hits.len(), 1, "{long_hits:?}");
    assert_eq!(long_hits[0].1.as_bytes(), &[0xbb; 32]);
}

#[test]
fn disconnecting_removes_exactly_what_connecting_wrote() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    let built = b.build(10);
    for blk in &built {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let before = index_snapshot(&s);

    let extra = b.build(4);
    for blk in &extra {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    assert_ne!(index_snapshot(&s), before);

    for _ in 0..extra.len() {
        s.disconnect_tip().unwrap();
    }
    assert_eq!(index_snapshot(&s), before, "the index is not exactly reversible");
}

#[test]
fn a_disconnected_transaction_is_no_longer_locatable() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    let built = b.build(6);
    for blk in &built {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let tip = built.last().unwrap();
    for tx in &tip.block.txs {
        assert!(s.tx_location(&txid(tx)).unwrap().is_some());
    }
    s.disconnect_tip().unwrap();
    for tx in &tip.block.txs {
        assert_eq!(s.tx_location(&txid(tx)).unwrap(), None);
    }
}

#[test]
fn a_store_without_the_index_writes_no_index_rows() {
    let s = Store::open_in_memory(StoreConfig::default()).unwrap();
    let mut b = ChainBuilder::new();
    for blk in b.build(6) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    assert!(index_snapshot(&s).is_empty(), "the index was maintained despite being off");
    assert!(matches!(s.address_history(&pkh(0), 0, 10).unwrap_err(), StorageError::IndexDisabled));
}

#[test]
fn an_indexed_store_and_a_plain_one_agree_on_consensus_state() {
    // The index is not consensus state: turning it on must not change a single
    // byte of the UTXO set or the state root.
    let plain = Store::open_in_memory(StoreConfig::default()).unwrap();
    let with_index = indexed();
    let mut b = ChainBuilder::new();
    for blk in b.build(14) {
        plain.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
        with_index.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    assert_eq!(plain.utxo_snapshot().unwrap(), with_index.utxo_snapshot().unwrap());
    assert_eq!(plain.state_root().unwrap(), with_index.state_root().unwrap());
    assert_eq!(plain.tip().unwrap(), with_index.tip().unwrap());
}

/// Every `(addr_index key, txid)` pair, plus every `tx_index` key, sorted.
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
fn the_exact_cursor_form_walks_every_row_in_chunks() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    for blk in b.build(24) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let key = pkh(0);
    let all = s.address_history_after(&key, None, 1000).unwrap();
    assert!(all.len() >= 2, "this address should have several entries");

    // One row per chunk. An exact (height, tx_idx) cursor always advances, so
    // this reproduces `all` exactly rather than re-reading or skipping a
    // height, which is the whole reason this form exists.
    let mut walked = Vec::new();
    let mut cursor = None;
    loop {
        let page = s.address_history_after(&key, cursor, 1).unwrap();
        let Some(&(height, idx, id)) = page.first() else { break };
        walked.push((height, idx, id));
        cursor = Some((height, idx + 1));
    }
    assert_eq!(walked, all);
}

#[test]
fn a_cursor_resumes_inside_one_height_without_losing_a_row() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    for blk in b.build(16) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let key = pkh(0);
    let all = s.address_history_after(&key, None, 1000).unwrap();
    let (height, idx, _) = all[0];

    // Resuming AT a row returns it; resuming one past it does not. That is the
    // property the height cursor cannot express, and losing it is how a
    // balance silently drops the rows it needs.
    let at = s.address_history_after(&key, Some((height, idx)), 1000).unwrap();
    assert_eq!(at, all);
    let past = s.address_history_after(&key, Some((height, idx + 1)), 1000).unwrap();
    assert_eq!(past.len(), all.len() - 1);
    assert!(!past.iter().any(|&(h, i, _)| h == height && i == idx));
}

#[test]
fn the_contract_paging_view_agrees_with_the_exact_walk() {
    let s = indexed();
    let mut b = ChainBuilder::new();
    for blk in b.build(20) {
        s.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let key = pkh(0);
    let paged = s.address_history(&key, 0, 1000).unwrap();
    let exact: Vec<_> =
        s.address_history_after(&key, None, 1000).unwrap().into_iter().map(|(h, _, id)| (h, id)).collect();
    assert_eq!(paged, exact);
}

#[test]
fn the_exact_cursor_form_needs_the_index() {
    let s = Store::open_in_memory(StoreConfig::default()).unwrap();
    assert!(matches!(
        s.address_history_after(&pkh(0), None, 10).unwrap_err(),
        StorageError::IndexDisabled
    ));
    assert!(s.address_history_after(&pkh(0), None, 0).is_err(), "limit 0 still checks the index");
}
