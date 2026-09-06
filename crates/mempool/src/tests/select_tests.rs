//! Block-template selection: fee order, dependency order and the budget.

use std::collections::BTreeSet;

use ferrum_storage::MapView;
use ferrum_types::OutPoint;

use crate::select::is_final_by_height;
use crate::tests::support::{cfg, coin, id, out, timelocked_tx, tx, unknown_out, view_with};
use crate::{Mempool, MempoolEntry};

fn unit_size() -> usize {
    tx(&[unknown_out(1, 0)], &[1]).serialized_size()
}

fn funds(n: u8, value: u64) -> (MapView, Vec<OutPoint>) {
    let ops: Vec<OutPoint> = (1..=n).map(|i| unknown_out(i, 0)).collect();
    let entries: Vec<(OutPoint, ferrum_types::Coin)> =
        ops.iter().map(|op| (*op, coin(value, 1, false))).collect();
    (view_with(&entries), ops)
}

#[test]
fn an_empty_pool_selects_nothing() {
    let pool = Mempool::new(cfg());
    let view = MapView::new();
    assert!(pool.select_for_block(1_000_000, &view, 1).is_empty());
}

#[test]
fn selection_is_by_descending_fee_rate() {
    let (view, ops) = funds(3, 100_000);
    let pool = Mempool::new(cfg());
    let low = tx(&[ops[0]], &[90_000]);
    let high = tx(&[ops[1]], &[70_000]);
    let middle = tx(&[ops[2]], &[80_000]);
    for t in [&low, &high, &middle] {
        pool.accept(t.clone(), &view, 10, 0).expect("accepted");
    }

    let picked = pool.select_for_block(1_000_000, &view, 11);
    assert_eq!(picked.iter().map(id).collect::<Vec<_>>(), vec![id(&high), id(&middle), id(&low)]);
}

#[test]
fn a_child_never_precedes_its_parent_however_much_more_it_pays() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    // Parent pays 100 grains; child pays 50 000. Sorted purely by fee rate the
    // child leads, and the block would be invalid.
    let parent = tx(&[ops[0]], &[99_900]);
    let child = tx(&[out(&parent, 0)], &[49_900]);
    pool.accept(parent.clone(), &view, 10, 0).expect("accepted");
    pool.accept(child.clone(), &view, 10, 0).expect("accepted");
    assert!(
        pool.get(&id(&child)).expect("held").fee_rate
            > pool.get(&id(&parent)).expect("held").fee_rate
    );

    let picked = pool.select_for_block(1_000_000, &view, 11);
    assert_eq!(picked.iter().map(id).collect::<Vec<_>>(), vec![id(&parent), id(&child)]);
}

#[test]
fn a_three_deep_chain_comes_out_in_dependency_order() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    let a = tx(&[ops[0]], &[99_900]); // fee 100
    let b = tx(&[out(&a, 0)], &[99_000]); // fee 900
    let c = tx(&[out(&b, 0)], &[50_000]); // fee 49 000
    for t in [&c, &b, &a] {
        // Offered youngest first, so the pool's own ordering cannot be what
        // saves the selector.
        pool.accept(t.clone(), &view, 10, 0).expect("accepted or held");
    }
    assert_eq!(pool.len(), 3);

    let picked = pool.select_for_block(1_000_000, &view, 11);
    assert_eq!(picked.iter().map(id).collect::<Vec<_>>(), vec![id(&a), id(&b), id(&c)]);
}

#[test]
fn selection_never_produces_a_transaction_before_the_one_that_funds_it() {
    let (view, ops) = funds(2, 100_000);
    let pool = Mempool::new(cfg());
    let p1 = tx(&[ops[0]], &[99_900]);
    let c1 = tx(&[out(&p1, 0)], &[49_900]);
    let p2 = tx(&[ops[1]], &[99_000]);
    let c2 = tx(&[out(&p2, 0)], &[10_000]);
    for t in [&c1, &c2, &p1, &p2] {
        pool.accept(t.clone(), &view, 10, 0).expect("accepted or held");
    }

    let picked = pool.select_for_block(1_000_000, &view, 11);
    let mut seen: BTreeSet<ferrum_types::Txid> = BTreeSet::new();
    for t in &picked {
        for input in &t.inputs {
            let parent = input.prev_out.txid;
            if picked.iter().any(|other| id(other) == parent) {
                assert!(seen.contains(&parent), "{} came before its parent {parent}", id(t));
            }
        }
        seen.insert(id(t));
    }
    assert_eq!(picked.len(), 4);
}

#[test]
fn the_byte_budget_is_respected() {
    let (view, ops) = funds(3, 100_000);
    let pool = Mempool::new(cfg());
    let low = tx(&[ops[0]], &[90_000]);
    let high = tx(&[ops[1]], &[70_000]);
    let middle = tx(&[ops[2]], &[80_000]);
    for t in [&low, &high, &middle] {
        pool.accept(t.clone(), &view, 10, 0).expect("accepted");
    }

    let picked = pool.select_for_block(unit_size() * 2, &view, 11);
    assert_eq!(picked.iter().map(id).collect::<Vec<_>>(), vec![id(&high), id(&middle)]);
}

#[test]
fn a_zero_budget_selects_nothing() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    pool.accept(tx(&[ops[0]], &[90_000]), &view, 10, 0).expect("accepted");
    assert!(pool.select_for_block(0, &view, 11).is_empty());
}

#[test]
fn a_child_is_dropped_when_its_parent_used_the_whole_budget() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    let parent = tx(&[ops[0]], &[99_900]);
    let child = tx(&[out(&parent, 0)], &[49_900]);
    pool.accept(parent.clone(), &view, 10, 0).expect("accepted");
    pool.accept(child.clone(), &view, 10, 0).expect("accepted");

    let picked = pool.select_for_block(unit_size(), &view, 11);
    assert_eq!(picked.iter().map(id).collect::<Vec<_>>(), vec![id(&parent)]);
}

#[test]
fn a_transaction_whose_input_has_vanished_is_skipped() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    pool.accept(tx(&[ops[0]], &[90_000]), &view, 10, 0).expect("accepted");

    // A view in which that coin never existed — what a reorg leaves behind.
    let empty = MapView::new();
    assert!(pool.select_for_block(1_000_000, &empty, 11).is_empty());
    assert_eq!(pool.len(), 1, "selection is read-only; nothing was evicted");
}

#[test]
fn an_immature_coinbase_spend_is_skipped_until_it_matures() {
    let op = unknown_out(1, 0);
    let view = view_with(&[(op, coin(100_000, 9, true))]);
    let pool = Mempool::new(cfg());
    let t = tx(&[op], &[90_000]);
    pool.accept(t.clone(), &view, 9, 0).expect("accepted at the height it matures");

    assert!(pool.select_for_block(1_000_000, &view, 9).is_empty(), "one block too early");
    assert_eq!(pool.select_for_block(1_000_000, &view, 10).len(), 1);
}

#[test]
fn a_transaction_locked_above_the_target_height_is_skipped() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    let t = timelocked_tx(&[ops[0]], &[90_000], 20);
    pool.accept(t.clone(), &view, 19, 0).expect("relayable one block early");

    assert!(pool.select_for_block(1_000_000, &view, 19).is_empty());
    assert_eq!(pool.select_for_block(1_000_000, &view, 20).len(), 1);
}

#[test]
fn is_final_by_height_lets_time_locked_transactions_through() {
    let t = timelocked_tx(&[unknown_out(1, 0)], &[1], 1_700_000_000);
    // The median time past is not in `select_for_block`'s signature, so the
    // timestamp branch is deferred to `chain::build_template`.
    assert!(is_final_by_height(&t, 5));

    let by_height = timelocked_tx(&[unknown_out(1, 0)], &[1], 5);
    assert!(!is_final_by_height(&by_height, 4));
    assert!(is_final_by_height(&by_height, 5));

    let unlocked = tx(&[unknown_out(1, 0)], &[1]);
    assert!(is_final_by_height(&unlocked, 0));
}

#[test]
fn selection_never_returns_the_same_outpoint_twice() {
    let (view, ops) = funds(2, 100_000);
    let pool = Mempool::new(cfg());
    let a = tx(&[ops[0]], &[99_000]);
    let b = tx(&[out(&a, 0)], &[90_000]);
    let c = tx(&[ops[1]], &[90_000]);
    for t in [&a, &b, &c] {
        pool.accept(t.clone(), &view, 10, 0).expect("accepted");
    }

    let picked = pool.select_for_block(1_000_000, &view, 11);
    let mut spent: BTreeSet<OutPoint> = BTreeSet::new();
    for t in &picked {
        for input in &t.inputs {
            assert!(spent.insert(input.prev_out), "{} is spent twice in one block", input.prev_out);
        }
    }
    assert_eq!(picked.len(), 3);
}

#[test]
fn the_free_function_takes_an_explicit_candidate_list() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    let t = tx(&[ops[0]], &[90_000]);
    pool.accept(t.clone(), &view, 10, 0).expect("accepted");

    let held: Vec<(ferrum_types::Txid, MempoolEntry)> = pool.entries_by_fee();
    let borrowed: Vec<(ferrum_types::Txid, &MempoolEntry)> =
        held.iter().map(|(k, e)| (*k, e)).collect();
    let picked =
        crate::select::select_for_block(&borrowed, 1_000_000, &view, 11, &pool.config().params);
    assert_eq!(picked, vec![t]);
}

#[test]
fn between_two_equal_fees_the_smaller_transaction_is_chosen_first() {
    use crate::tests::support::padded_tx;

    let (view, ops) = funds(2, 100_000);
    let pool = Mempool::new(cfg());
    let lean = tx(&[ops[0]], &[90_000]);
    let fat = padded_tx(&[ops[1]], &[90_000], 80);
    pool.accept(fat.clone(), &view, 10, 0).expect("accepted");
    pool.accept(lean.clone(), &view, 10, 0).expect("accepted");

    // Identical fees, different sizes: fee *rate* is what orders a block.
    assert_eq!(pool.get(&id(&lean)).expect("held").fee, pool.get(&id(&fat)).expect("held").fee);
    let picked = pool.select_for_block(1_000_000, &view, 11);
    assert_eq!(picked.iter().map(id).collect::<Vec<_>>(), vec![id(&lean), id(&fat)]);
}
