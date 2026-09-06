//! The orphan pool on its own: capacity, promotion and expiry.

use std::collections::BTreeSet;

use crate::orphan::OrphanPool;
use crate::tests::support::{id, tx, unknown_out};

fn waiting_on(parents: &[u8]) -> BTreeSet<ferrum_types::Txid> {
    parents.iter().map(|p| unknown_out(*p, 0).txid).collect()
}

#[test]
fn a_new_pool_is_empty_and_reports_its_capacity() {
    let pool = OrphanPool::new(7);
    assert!(pool.is_empty());
    assert_eq!(pool.len(), 0);
    assert_eq!(pool.capacity(), 7);
    assert!(pool.txids().is_empty());
}

#[test]
fn an_inserted_orphan_is_held_and_readable() {
    let mut pool = OrphanPool::new(4);
    let t = tx(&[unknown_out(1, 0)], &[10]);
    let tid = id(&t);
    assert!(pool.insert(tid, t.clone(), waiting_on(&[1]), 5).is_empty());
    assert!(pool.contains(&tid));
    assert_eq!(pool.len(), 1);
    let entry = pool.get(&tid).expect("held");
    assert_eq!(entry.tx, t);
    assert_eq!(entry.added_height, 5);
    assert_eq!(entry.missing, waiting_on(&[1]));
}

#[test]
fn re_inserting_the_same_orphan_changes_nothing() {
    let mut pool = OrphanPool::new(4);
    let t = tx(&[unknown_out(1, 0)], &[10]);
    let tid = id(&t);
    pool.insert(tid, t.clone(), waiting_on(&[1]), 5);
    assert!(pool.insert(tid, t, waiting_on(&[1]), 99).is_empty());
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.get(&tid).expect("held").added_height, 5, "the first arrival's clock stands");
}

#[test]
fn the_pool_evicts_the_oldest_arrival_when_full() {
    let mut pool = OrphanPool::new(2);
    let a = tx(&[unknown_out(1, 0)], &[10]);
    let b = tx(&[unknown_out(2, 0)], &[10]);
    let c = tx(&[unknown_out(3, 0)], &[10]);
    pool.insert(id(&a), a.clone(), waiting_on(&[1]), 0);
    pool.insert(id(&b), b, waiting_on(&[2]), 0);
    let evicted = pool.insert(id(&c), c, waiting_on(&[3]), 0);
    assert_eq!(evicted, vec![id(&a)], "oldest first, deterministically");
    assert_eq!(pool.len(), 2);
    assert!(!pool.contains(&id(&a)));
}

#[test]
fn a_zero_capacity_pool_holds_nothing() {
    let mut pool = OrphanPool::new(0);
    let t = tx(&[unknown_out(1, 0)], &[10]);
    assert_eq!(pool.insert(id(&t), t.clone(), waiting_on(&[1]), 0), vec![id(&t)]);
    assert!(pool.is_empty());
}

#[test]
fn a_parent_arriving_releases_its_child() {
    let mut pool = OrphanPool::new(4);
    let t = tx(&[unknown_out(1, 0)], &[10]);
    pool.insert(id(&t), t.clone(), waiting_on(&[1]), 0);
    let released = pool.take_children_of(&unknown_out(1, 0).txid);
    assert_eq!(released, vec![t]);
    assert!(pool.is_empty(), "a released orphan leaves the pool");
}

#[test]
fn an_orphan_waiting_on_two_parents_is_only_released_by_the_second() {
    let mut pool = OrphanPool::new(4);
    let t = tx(&[unknown_out(1, 0), unknown_out(2, 0)], &[10]);
    pool.insert(id(&t), t.clone(), waiting_on(&[1, 2]), 0);

    assert!(
        pool.take_children_of(&unknown_out(1, 0).txid).is_empty(),
        "still waiting on the other"
    );
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.get(&id(&t)).expect("held").missing, waiting_on(&[2]));

    assert_eq!(pool.take_children_of(&unknown_out(2, 0).txid), vec![t]);
    assert!(pool.is_empty());
}

#[test]
fn releasing_an_unknown_parent_releases_nothing() {
    let mut pool = OrphanPool::new(4);
    assert!(pool.take_children_of(&unknown_out(9, 0).txid).is_empty());
}

#[test]
fn removing_an_orphan_clears_its_parent_index_too() {
    let mut pool = OrphanPool::new(4);
    let t = tx(&[unknown_out(1, 0)], &[10]);
    pool.insert(id(&t), t.clone(), waiting_on(&[1]), 0);
    assert!(pool.remove(&id(&t)));
    assert!(!pool.remove(&id(&t)), "removing twice is a no-op");
    assert!(pool.take_children_of(&unknown_out(1, 0).txid).is_empty());
}

#[test]
fn expiry_drops_only_what_is_old_enough() {
    let mut pool = OrphanPool::new(8);
    let old = tx(&[unknown_out(1, 0)], &[10]);
    let new = tx(&[unknown_out(2, 0)], &[10]);
    pool.insert(id(&old), old.clone(), waiting_on(&[1]), 100);
    pool.insert(id(&new), new, waiting_on(&[2]), 150);

    assert!(pool.expire(120, 50).is_empty(), "nothing is 50 blocks old yet");
    let gone = pool.expire(150, 50);
    assert_eq!(gone, vec![id(&old)]);
    assert_eq!(pool.len(), 1);
}

#[test]
fn clear_empties_the_pool_and_its_indices() {
    let mut pool = OrphanPool::new(4);
    let t = tx(&[unknown_out(1, 0)], &[10]);
    pool.insert(id(&t), t, waiting_on(&[1]), 0);
    pool.clear();
    assert!(pool.is_empty());
    assert!(pool.take_children_of(&unknown_out(1, 0).txid).is_empty());
}

#[test]
fn the_default_pool_uses_the_contract_capacity() {
    assert_eq!(OrphanPool::default().capacity(), crate::DEFAULT_MAX_ORPHANS);
}

#[test]
fn eviction_keeps_evicting_until_the_pool_fits() {
    let mut pool = OrphanPool::new(1);
    let a = tx(&[unknown_out(1, 0)], &[10]);
    let b = tx(&[unknown_out(2, 0)], &[10]);
    pool.insert(id(&a), a.clone(), waiting_on(&[1]), 0);
    let evicted = pool.insert(id(&b), b.clone(), waiting_on(&[2]), 0);
    assert_eq!(evicted, vec![id(&a)]);
    assert_eq!(pool.txids(), vec![id(&b)]);
}
