//! What happens to an entry after it is admitted: eviction, expiry,
//! confirmation and orphan promotion.

use ferrum_types::{Amount, OutPoint};

use crate::error::MempoolError;
use crate::pool::AcceptResult;
use crate::tests::support::{cfg, coin, coinbase, id, out, tx, unknown_out, view_with};
use crate::{Mempool, MempoolConfig};

/// The encoded size of the one-input, one-output fixture transaction.
fn unit_size() -> usize {
    tx(&[unknown_out(1, 0)], &[1]).serialized_size()
}

/// A view funding `n` independent outpoints with `value` grains each.
fn funds(n: u8, value: u64) -> (ferrum_storage::MapView, Vec<OutPoint>) {
    let ops: Vec<OutPoint> = (1..=n).map(|i| unknown_out(i, 0)).collect();
    let entries: Vec<(OutPoint, ferrum_types::Coin)> =
        ops.iter().map(|op| (*op, coin(value, 1, false))).collect();
    (view_with(&entries), ops)
}

#[test]
fn eviction_removes_the_lowest_fee_rate_first() {
    let (view, ops) = funds(3, 100_000);
    let pool = Mempool::new(cfg().with_max_bytes(unit_size() * 2));

    let cheap = tx(&[ops[0]], &[90_000]); // fee 10 000
    let middle = tx(&[ops[1]], &[80_000]); // fee 20 000
    let dear = tx(&[ops[2]], &[70_000]); // fee 30 000

    pool.accept(cheap.clone(), &view, 10, 0).expect("accepted");
    pool.accept(middle.clone(), &view, 10, 0).expect("accepted");
    let result = pool.accept(dear.clone(), &view, 10, 0).expect("accepted");

    match result {
        AcceptResult::Accepted { evicted, .. } => assert_eq!(evicted, vec![id(&cheap)]),
        other => panic!("expected an acceptance, got {other:?}"),
    }
    assert_eq!(pool.len(), 2);
    assert!(!pool.contains(&id(&cheap)));
    assert!(pool.contains(&id(&middle)));
    assert!(pool.contains(&id(&dear)));
    assert_eq!(pool.size_bytes(), unit_size() * 2);
}

#[test]
fn eviction_releases_the_spent_outpoint_of_its_victim() {
    let (view, ops) = funds(2, 100_000);
    let pool = Mempool::new(cfg().with_max_bytes(unit_size()));
    let cheap = tx(&[ops[0]], &[90_000]);
    let dear = tx(&[ops[1]], &[10_000]);

    pool.accept(cheap, &view, 10, 0).expect("accepted");
    pool.accept(dear, &view, 10, 0).expect("accepted");
    assert_eq!(pool.spender_of(&ops[0]), None, "the evicted entry no longer claims its input");
    assert!(pool.spender_of(&ops[1]).is_some());
}

#[test]
fn eviction_takes_the_victims_descendants_with_it() {
    let (view, ops) = funds(3, 100_000);
    let pool = Mempool::new(cfg().with_max_bytes(unit_size() * 3));

    // A cheap parent with a very well-paying child: the child's own fee rate
    // is the highest in the pool, and it still goes, because it is unminable
    // without the parent.
    let parent = tx(&[ops[0]], &[99_900]); // fee 100
    let child = tx(&[out(&parent, 0)], &[49_900]); // fee 50 000
    let other_a = tx(&[ops[1]], &[80_000]); // fee 20 000
    let other_b = tx(&[ops[2]], &[80_000]); // fee 20 000

    pool.accept(parent.clone(), &view, 10, 0).expect("accepted");
    pool.accept(child.clone(), &view, 10, 0).expect("accepted");
    pool.accept(other_a.clone(), &view, 10, 0).expect("accepted");
    assert!(
        pool.get(&id(&child)).expect("held").fee_rate
            > pool.get(&id(&other_a)).expect("held").fee_rate,
        "the child must out-pay the survivors for this test to mean anything"
    );

    let result = pool.accept(other_b.clone(), &view, 10, 0).expect("accepted");
    match result {
        AcceptResult::Accepted { mut evicted, .. } => {
            evicted.sort_unstable();
            let mut expected = vec![id(&parent), id(&child)];
            expected.sort_unstable();
            assert_eq!(evicted, expected);
        }
        other => panic!("expected an acceptance, got {other:?}"),
    }
    assert_eq!(pool.len(), 2);
    assert!(pool.contains(&id(&other_a)));
    assert!(pool.contains(&id(&other_b)));
}

#[test]
fn a_transaction_that_would_immediately_be_evicted_is_refused() {
    let (view, ops) = funds(3, 100_000);
    let pool = Mempool::new(cfg().with_max_bytes(unit_size() * 2));

    pool.accept(tx(&[ops[0]], &[70_000]), &view, 10, 0).expect("accepted");
    pool.accept(tx(&[ops[1]], &[80_000]), &view, 10, 0).expect("accepted");

    let cheapest = tx(&[ops[2]], &[99_000]);
    let err = pool.accept(cheapest.clone(), &view, 10, 0).expect_err("the pool is full");
    assert!(matches!(err, MempoolError::PoolFull { .. }), "unexpected error: {err}");
    assert_eq!(pool.len(), 2);
    assert!(!pool.contains(&id(&cheapest)));
}

#[test]
fn expiry_drops_only_entries_older_than_the_window() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg().with_expiry_blocks(5));
    let t = tx(&[ops[0]], &[90_000]);
    pool.accept(t.clone(), &view, 10, 0).expect("accepted");

    assert!(pool.expire(14).is_empty(), "four blocks old is not five");
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.expire(15), vec![id(&t)]);
    assert!(pool.is_empty());
    assert_eq!(pool.size_bytes(), 0);
}

#[test]
fn expiry_takes_descendants_with_the_expired_parent() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg().with_expiry_blocks(5));
    let parent = tx(&[ops[0]], &[90_000]);
    let child = tx(&[out(&parent, 0)], &[80_000]);
    pool.accept(parent.clone(), &view, 10, 0).expect("accepted");
    pool.accept(child.clone(), &view, 10, 0).expect("accepted");

    let gone = pool.expire(15);
    assert_eq!(gone.len(), 2, "{gone:?}");
    assert!(pool.is_empty());
}

#[test]
fn expiry_collects_stale_orphans_too() {
    let pool = Mempool::new(cfg().with_expiry_blocks(5));
    let view = ferrum_storage::MapView::new();
    let orphan = tx(&[unknown_out(9, 0)], &[10]);
    pool.accept(orphan.clone(), &view, 10, 0).expect("held");
    assert_eq!(pool.orphan_count(), 1);
    assert_eq!(pool.expire(15), vec![id(&orphan)]);
    assert_eq!(pool.orphan_count(), 0);
}

#[test]
fn accepting_at_a_new_height_sweeps_expired_entries() {
    let (view, ops) = funds(2, 100_000);
    let pool = Mempool::new(cfg().with_expiry_blocks(5));
    let old = tx(&[ops[0]], &[90_000]);
    pool.accept(old.clone(), &view, 10, 0).expect("accepted");

    let fresh = tx(&[ops[1]], &[90_000]);
    pool.accept(fresh.clone(), &view, 20, 0).expect("accepted");
    assert!(!pool.contains(&id(&old)), "the sweep ran on the way in");
    assert!(pool.contains(&id(&fresh)));
    assert_eq!(pool.len(), 1);
}

#[test]
fn remove_confirmed_drops_the_confirmed_transaction() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    let t = tx(&[ops[0]], &[90_000]);
    pool.accept(t.clone(), &view, 10, 0).expect("accepted");

    pool.remove_confirmed(std::slice::from_ref(&t));
    assert!(pool.is_empty());
    assert_eq!(pool.spender_of(&ops[0]), None);
    assert_eq!(pool.size_bytes(), 0);
}

#[test]
fn remove_confirmed_keeps_a_child_of_a_confirmed_parent() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    let parent = tx(&[ops[0]], &[90_000]);
    let child = tx(&[out(&parent, 0)], &[80_000]);
    pool.accept(parent.clone(), &view, 10, 0).expect("accepted");
    pool.accept(child.clone(), &view, 10, 0).expect("accepted");

    // The parent's outputs are real UTXOs now; the child is an ordinary
    // transaction and must not be collateral damage.
    pool.remove_confirmed(std::slice::from_ref(&parent));
    assert_eq!(pool.len(), 1);
    assert!(pool.contains(&id(&child)));
    assert_eq!(pool.spender_of(&out(&parent, 0)), Some(id(&child)));
}

#[test]
fn remove_confirmed_evicts_a_losing_double_spend_and_its_descendants() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    let ours = tx(&[ops[0]], &[90_000]);
    let ours_child = tx(&[out(&ours, 0)], &[80_000]);
    pool.accept(ours.clone(), &view, 10, 0).expect("accepted");
    pool.accept(ours_child.clone(), &view, 10, 0).expect("accepted");

    // Somebody else's spend of the same outpoint got mined.
    let theirs = tx(&[ops[0]], &[70_000]);
    assert_ne!(id(&theirs), id(&ours));
    pool.remove_confirmed(&[theirs]);

    assert!(pool.is_empty(), "the losing branch and everything built on it goes");
    assert_eq!(pool.spender_of(&ops[0]), None);
}

#[test]
fn remove_confirmed_ignores_a_coinbase_null_input() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    let t = tx(&[ops[0]], &[90_000]);
    pool.accept(t.clone(), &view, 10, 0).expect("accepted");

    pool.remove_confirmed(&[coinbase(11, Amount::from_grains(50), b"cb")]);
    assert_eq!(pool.len(), 1, "a coinbase spends nothing a mempool transaction could claim");
}

#[test]
fn remove_confirmed_forgets_an_orphan_that_was_mined() {
    let pool = Mempool::new(cfg());
    let view = ferrum_storage::MapView::new();
    let orphan = tx(&[unknown_out(9, 0)], &[10]);
    pool.accept(orphan.clone(), &view, 10, 0).expect("held");
    pool.remove_confirmed(std::slice::from_ref(&orphan));
    assert_eq!(pool.orphan_count(), 0);
}

#[test]
fn promote_orphans_picks_up_a_parent_that_arrived_in_a_block() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    let parent = tx(&[ops[0]], &[90_000]);
    let child = tx(&[out(&parent, 0)], &[80_000]);

    // The child arrives first and waits; the parent is never relayed, it is
    // simply mined. `accept` can never see that, so the node must ask.
    pool.accept(child.clone(), &view, 10, 0).expect("held");
    assert_eq!(pool.orphan_count(), 1);

    let confirmed = view_with(&[(out(&parent, 0), coin(90_000, 11, false))]);
    let promoted = pool.promote_orphans(&confirmed, 11, 0);
    assert_eq!(promoted, vec![id(&child)]);
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.orphan_count(), 0);
}

#[test]
fn promote_orphans_leaves_a_still_unresolvable_orphan_waiting() {
    let pool = Mempool::new(cfg());
    let view = ferrum_storage::MapView::new();
    let orphan = tx(&[unknown_out(9, 0)], &[10]);
    pool.accept(orphan.clone(), &view, 10, 0).expect("held");

    assert!(pool.promote_orphans(&view, 11, 0).is_empty());
    assert_eq!(pool.orphan_count(), 1, "it goes back to waiting, it is not dropped");
    assert!(pool.is_empty());
}

#[test]
fn promote_orphans_assembles_a_whole_chain_at_once() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    let parent = tx(&[ops[0]], &[90_000]);
    let child = tx(&[out(&parent, 0)], &[80_000]);
    let grandchild = tx(&[out(&child, 0)], &[70_000]);

    pool.accept(grandchild.clone(), &view, 10, 0).expect("held");
    pool.accept(child.clone(), &view, 10, 0).expect("held");
    assert_eq!(pool.orphan_count(), 2);

    let confirmed = view_with(&[(out(&parent, 0), coin(90_000, 11, false))]);
    let mut promoted = pool.promote_orphans(&confirmed, 11, 0);
    promoted.sort_unstable();
    let mut expected = vec![id(&child), id(&grandchild)];
    expected.sort_unstable();
    assert_eq!(promoted, expected);
    assert_eq!(pool.len(), 2);
}

#[test]
fn clear_empties_the_pool_and_the_orphans() {
    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg());
    pool.accept(tx(&[ops[0]], &[90_000]), &view, 10, 0).expect("accepted");
    pool.accept(tx(&[unknown_out(9, 0)], &[10]), &view, 10, 0).expect("held");

    pool.clear();
    assert!(pool.is_empty());
    assert_eq!(pool.orphan_count(), 0);
    assert_eq!(pool.size_bytes(), 0);
    assert_eq!(pool.spender_of(&ops[0]), None);
}

#[test]
fn entries_by_fee_is_ordered_by_descending_fee_rate() {
    let (view, ops) = funds(3, 100_000);
    let pool = Mempool::new(cfg());
    pool.accept(tx(&[ops[0]], &[90_000]), &view, 10, 0).expect("accepted");
    pool.accept(tx(&[ops[1]], &[70_000]), &view, 10, 0).expect("accepted");
    pool.accept(tx(&[ops[2]], &[80_000]), &view, 10, 0).expect("accepted");

    let rates: Vec<u64> = pool.entries_by_fee().iter().map(|(_, e)| e.fee_rate).collect();
    assert_eq!(rates.len(), 3);
    assert!(rates.windows(2).all(|w| w[0] >= w[1]), "not descending: {rates:?}");
}

#[test]
fn size_bytes_is_the_sum_of_the_entries() {
    let (view, ops) = funds(2, 100_000);
    let pool = Mempool::new(cfg());
    let a = tx(&[ops[0]], &[90_000]);
    let b = tx(&[ops[1]], &[90_000]);
    pool.accept(a.clone(), &view, 10, 0).expect("accepted");
    pool.accept(b.clone(), &view, 10, 0).expect("accepted");
    assert_eq!(pool.size_bytes(), a.serialized_size() + b.serialized_size());
}

#[test]
fn a_default_pool_uses_the_mainnet_policy() {
    let pool = Mempool::default();
    assert_eq!(pool.config().max_bytes, crate::DEFAULT_MAX_BYTES);
    assert_eq!(pool.min_fee_rate(), MempoolConfig::default().min_fee_rate);
    assert!(pool.is_empty());
}

#[test]
fn the_pool_is_shareable_across_threads() {
    // The node holds one `Arc<Mempool>` between the p2p task, the RPC server
    // and the miner. If this ever stops compiling, that wiring breaks.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Mempool>();
    assert_send_sync::<crate::MempoolConfig>();
    assert_send_sync::<crate::MempoolError>();

    let shared = std::sync::Arc::new(Mempool::new(cfg()));
    let (view, ops) = funds(1, 100_000);
    let t = tx(&[ops[0]], &[90_000]);
    shared.accept(t.clone(), &view, 10, 0).expect("accepted");
    let reader = std::sync::Arc::clone(&shared);
    std::thread::spawn(move || assert_eq!(reader.len(), 1)).join().expect("the reader thread ran");
}

#[test]
fn promote_orphans_does_not_reset_a_waiting_orphans_expiry_clock() {
    // `Relay::after_tip_move` calls `promote_orphans` on every accepted block.
    // An orphan whose parents never arrive must still age out; if promotion
    // re-stamps it with the current tip height it can never expire, and the
    // pool stays permanently full from one upload.
    let pool = Mempool::new(cfg().with_expiry_blocks(5));
    let view = ferrum_storage::MapView::new();
    let orphan = tx(&[unknown_out(9, 0)], &[10]);
    pool.accept(orphan.clone(), &view, 10, 0).expect("held");

    for height in 11..=15 {
        assert!(pool.promote_orphans(&view, height, 0).is_empty());
        assert_eq!(pool.orphan_count(), 1, "it is still waiting at height {height}");
    }

    // Admitted at 10 with a five-block window: height 15 is exactly the point
    // it must be collected at.
    assert_eq!(pool.expire(15), vec![id(&orphan)]);
    assert_eq!(pool.orphan_count(), 0);
}

#[test]
fn a_chain_longer_than_the_ancestor_limit_is_refused() {
    use crate::tests::support::ascending_fee_chain;

    let op = unknown_out(1, 0);
    let view = view_with(&[(op, coin(1_000_000, 1, false))]);
    let pool = Mempool::new(cfg().with_max_ancestors(5));
    let chain = ascending_fee_chain(op, 1_000_000, 6);

    // Five deep is the limit: the fifth transaction counts itself plus four
    // in-pool ancestors.
    for t in chain.iter().take(5) {
        pool.accept(t.clone(), &view, 10, 0).expect("within the limit");
    }
    let err = pool.accept(chain[5].clone(), &view, 10, 0).expect_err("six is over the limit");
    assert!(matches!(err, MempoolError::TooManyAncestors { count: 6, max: 5 }), "{err}");
    assert_eq!(pool.len(), 5);
}

#[test]
fn an_ancestor_package_larger_than_the_byte_limit_is_refused() {
    use crate::tests::support::padded_tx;

    let (view, ops) = funds(1, 100_000);
    let pool = Mempool::new(cfg().with_max_ancestor_bytes(200));
    let parent = padded_tx(&[ops[0]], &[99_000], 80);
    let child = padded_tx(&[out(&parent, 0)], &[98_000], 80);
    pool.accept(parent.clone(), &view, 10, 0).expect("a lone transaction is its own package");
    let err = pool.accept(child, &view, 10, 0).expect_err("the package is over the byte limit");
    assert!(matches!(err, MempoolError::AncestorPackageTooLarge { .. }), "{err}");
    assert_eq!(pool.len(), 1);
}
