//! `reconcile_reorg`, against a real chain.
//!
//! These fixtures drive an actual [`ferrum_chain::ChainManager`] over an
//! in-memory store: blocks are mined, accepted, and reorganised by the chain
//! layer, and the mempool is handed exactly the `disconnected`/`connected`
//! lists a node would hand it. A mempool that reconciles correctly against a
//! made-up pair and incorrectly against the real thing is the bug this file
//! exists to catch.

use ferrum_chain::AcceptOutcome;
use ferrum_storage::header_hash;
use ferrum_types::{Block, OutPoint, Transaction};

use crate::Mempool;
use crate::tests::support::{TestChain, cfg, id, out, tx};

/// The value of the coin at `op`.
fn value_at(t: &TestChain, op: &OutPoint) -> u64 {
    t.store.get_coin(op).expect("read").expect("unspent").value.to_grains()
}

/// A transaction spending `op` and paying everything but `fee` to a standard
/// output.
fn spend_with_fee(t: &TestChain, op: OutPoint, fee: u64) -> Transaction {
    let value = value_at(t, &op);
    tx(&[op], &[value - fee])
}

/// Offer `tx` to `pool` at the chain's current tip.
fn offer(pool: &Mempool, chain: &TestChain, transaction: Transaction) {
    pool.accept(transaction, chain.view(), chain.height(), chain.mtp())
        .expect("the fixture builds relayable transactions");
}

/// Build a competing branch of `n` blocks on `parent` and accept every one.
fn branch(t: &TestChain, parent: ferrum_types::BlockHash, n: usize, seed: u64) -> Vec<Block> {
    let mut out_blocks = Vec::with_capacity(n);
    let mut cursor = parent;
    for i in 0..n {
        let nonce =
            seed.checked_add(u64::try_from(i).expect("index fits")).expect("extra nonce fits");
        let block = t.mine_on(&cursor, Vec::new(), nonce);
        cursor = header_hash(&block.header);
        t.accept(block.clone());
        out_blocks.push(block);
    }
    out_blocks
}

#[test]
fn a_transaction_from_a_disconnected_block_returns_to_the_pool() {
    let t = TestChain::new();
    t.mine_and_accept(Vec::new());
    let (fork_point, _) = t.tip();

    let funded = t.coinbase_out(1);
    let payment = spend_with_fee(&t, funded, 10_000);

    let pool = Mempool::new(cfg());
    offer(&pool, &t, payment.clone());
    assert_eq!(pool.len(), 1);

    // It is mined, and the node tells the pool so.
    let mined = t.mine_and_accept(vec![payment.clone()]);
    pool.remove_confirmed(&mined.txs);
    assert!(pool.is_empty());

    // A heavier branch replaces the block that confirmed it.
    let winner = branch(&t, fork_point, 2, 100);
    assert_eq!(t.height(), 3);

    pool.reconcile_reorg(&[mined], &winner, t.view(), t.height());
    assert!(pool.contains(&id(&payment)), "the transaction is unconfirmed again, not lost");
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.orphan_count(), 0);
}

#[test]
fn a_resurrected_transaction_can_be_mined_again() {
    let t = TestChain::new();
    t.mine_and_accept(Vec::new());
    let (fork_point, _) = t.tip();
    let payment = spend_with_fee(&t, t.coinbase_out(1), 10_000);

    let pool = Mempool::new(cfg());
    offer(&pool, &t, payment.clone());
    let mined = t.mine_and_accept(vec![payment.clone()]);
    pool.remove_confirmed(&mined.txs);
    let winner = branch(&t, fork_point, 2, 100);
    pool.reconcile_reorg(&[mined], &winner, t.view(), t.height());

    // The selection must produce a block the chain accepts, which is the only
    // assertion that proves the resurrected entry is genuinely valid again.
    let picked = pool.select_for_block(900_000, t.view(), t.height() + 1);
    assert_eq!(picked, vec![payment.clone()]);
    let block = t.mine_on(&t.tip().0, picked, 7);
    let hash = header_hash(&block.header);
    assert_eq!(t.accept(block), AcceptOutcome::Extended(hash));
}

#[test]
fn a_transaction_double_spent_by_the_new_chain_is_dropped() {
    let t = TestChain::new();
    t.mine_and_accept(Vec::new());
    let (fork_point, _) = t.tip();
    let funded = t.coinbase_out(1);

    let ours = spend_with_fee(&t, funded, 10_000);
    let theirs = spend_with_fee(&t, funded, 20_000);
    assert_ne!(id(&ours), id(&theirs));

    let pool = Mempool::new(cfg());
    offer(&pool, &t, ours.clone());
    let mined = t.mine_and_accept(vec![ours.clone()]);
    pool.remove_confirmed(&mined.txs);

    // The winning branch spends the same coin a different way.
    let rival = t.mine_on(&fork_point, vec![theirs.clone()], 100);
    let rival_hash = header_hash(&rival.header);
    assert_eq!(t.accept(rival.clone()), AcceptOutcome::SideChain(rival_hash));
    let extension = t.mine_on(&rival_hash, Vec::new(), 101);
    assert!(matches!(t.accept(extension.clone()), AcceptOutcome::Reorged { .. }));

    pool.reconcile_reorg(&[mined], &[rival, extension], t.view(), t.height());
    assert!(!pool.contains(&id(&ours)), "the losing spend can never be mined");
    assert!(!pool.contains(&id(&theirs)), "the winning spend is confirmed, not pending");
    assert!(pool.is_empty());
    assert_eq!(pool.orphan_count(), 0);
}

#[test]
fn a_transaction_spending_a_disconnected_coinbase_is_dropped() {
    // The classic reorg bug: the coinbase that funded a pending transaction
    // no longer exists, and no relay can ever produce it.
    let t = TestChain::new();
    t.mine_and_accept(Vec::new());
    let (fork_point, _) = t.tip();
    let doomed_block = t.mine_and_accept(Vec::new()); // height 2
    t.mine_and_accept(Vec::new()); // height 3
    let (_, tip_height) = t.tip();
    assert_eq!(tip_height, 3);

    let funded = t.coinbase_out(2);
    let payment = spend_with_fee(&t, funded, 10_000);
    let pool = Mempool::new(cfg());
    offer(&pool, &t, payment.clone());
    assert_eq!(pool.len(), 1);

    let height_three_block = t.store.get_block(&t.tip().0).expect("read").expect("stored");
    let winner = branch(&t, fork_point, 3, 200);
    assert_eq!(t.height(), 4);

    // `disconnected` is tip-first, exactly as `AcceptOutcome::Reorged` gives it.
    pool.reconcile_reorg(&[height_three_block, doomed_block], &winner, t.view(), t.height());

    assert!(pool.is_empty(), "the coin it spent does not exist on any chain");
    assert_eq!(pool.orphan_count(), 0, "and it must not linger as an orphan either");
}

#[test]
fn a_child_of_a_resurrected_parent_survives_the_reorg() {
    let t = TestChain::new();
    t.mine_and_accept(Vec::new());
    let (fork_point, _) = t.tip();

    let parent = spend_with_fee(&t, t.coinbase_out(1), 10_000);
    let parent_value = parent.outputs[0].value.to_grains();
    let child = tx(&[out(&parent, 0)], &[parent_value - 5_000]);

    let pool = Mempool::new(cfg());
    offer(&pool, &t, parent.clone());
    offer(&pool, &t, child.clone());
    assert_eq!(pool.len(), 2);

    let mined = t.mine_and_accept(vec![parent.clone()]);
    pool.remove_confirmed(&mined.txs);
    assert_eq!(pool.len(), 1, "only the child is left, spending a now-confirmed output");

    let winner = branch(&t, fork_point, 2, 300);
    pool.reconcile_reorg(&[mined], &winner, t.view(), t.height());

    assert_eq!(pool.len(), 2, "parent resurrected, child still spending it");
    assert!(pool.contains(&id(&parent)));
    assert!(pool.contains(&id(&child)));
    assert_eq!(pool.orphan_count(), 0);

    // And the pair still comes out parent-first.
    let picked = pool.select_for_block(900_000, t.view(), t.height() + 1);
    assert_eq!(picked.iter().map(id).collect::<Vec<_>>(), vec![id(&parent), id(&child)]);
}

#[test]
fn a_transaction_confirmed_on_both_branches_is_not_re_added() {
    let t = TestChain::new();
    t.mine_and_accept(Vec::new());
    let (fork_point, _) = t.tip();
    let payment = spend_with_fee(&t, t.coinbase_out(1), 10_000);

    let pool = Mempool::new(cfg());
    offer(&pool, &t, payment.clone());
    let loser = t.mine_and_accept(vec![payment.clone()]);
    pool.remove_confirmed(&loser.txs);

    // The winning branch confirms the very same transaction. Which of the two
    // equal-work height-2 blocks the chain adopts first is a tiebreak, so the
    // fixture asserts where the chain ends up rather than how it got there.
    let winner_first = t.mine_on(&fork_point, vec![payment.clone()], 400);
    let winner_first_hash = header_hash(&winner_first.header);
    t.accept(winner_first.clone());
    let winner_second = t.mine_on(&winner_first_hash, Vec::new(), 401);
    let winner_second_hash = header_hash(&winner_second.header);
    t.accept(winner_second.clone());
    assert_eq!(t.tip(), (winner_second_hash, 3));

    pool.reconcile_reorg(&[loser], &[winner_first, winner_second], t.view(), t.height());
    assert!(pool.is_empty(), "it is confirmed on the chain that won");
}

#[test]
fn reconciliation_keeps_an_orphan_and_promotes_it_when_its_parent_resurfaces() {
    let t = TestChain::new();
    t.mine_and_accept(Vec::new());
    let (fork_point, _) = t.tip();

    let parent = spend_with_fee(&t, t.coinbase_out(1), 10_000);
    let parent_value = parent.outputs[0].value.to_grains();
    let child = tx(&[out(&parent, 0)], &[parent_value - 5_000]);

    // The child alone is offered, so it waits; the parent is only ever mined.
    let pool = Mempool::new(cfg());
    assert!(pool.accept(child.clone(), t.view(), t.height(), t.mtp()).expect("held").is_orphan());
    let mined = t.mine_and_accept(vec![parent.clone()]);
    assert_eq!(pool.orphan_count(), 1);

    let winner = branch(&t, fork_point, 2, 500);
    pool.reconcile_reorg(&[mined], &winner, t.view(), t.height());

    assert_eq!(pool.len(), 2, "the parent came back and released the child");
    assert!(pool.contains(&id(&parent)));
    assert!(pool.contains(&id(&child)));
    assert_eq!(pool.orphan_count(), 0);
}

#[test]
fn reconciliation_with_nothing_disconnected_still_drops_what_the_new_block_spent() {
    let t = TestChain::new();
    t.mine_and_accept(Vec::new());
    let funded = t.coinbase_out(1);

    let ours = spend_with_fee(&t, funded, 10_000);
    let theirs = spend_with_fee(&t, funded, 20_000);
    let pool = Mempool::new(cfg());
    offer(&pool, &t, ours.clone());

    let connected = t.mine_and_accept(vec![theirs.clone()]);
    pool.reconcile_reorg(&[], &[connected], t.view(), t.height());

    assert!(pool.is_empty());
    assert_eq!(pool.spender_of(&funded), None);
}

#[test]
fn reconciliation_preserves_the_expiry_clock_of_an_entry_it_keeps() {
    let t = TestChain::new();
    t.mine_and_accept(Vec::new());
    t.mine_and_accept(Vec::new());
    let (fork_point, _) = t.tip();

    // Funded by block 1's coinbase, so nothing about it changes when blocks
    // above the fork point are replaced.
    let payment = spend_with_fee(&t, t.coinbase_out(1), 10_000);
    let pool = Mempool::new(cfg());
    offer(&pool, &t, payment.clone());
    let admitted_at = pool.get(&id(&payment)).expect("held").added_height;

    let winner = branch(&t, fork_point, 2, 600);
    pool.reconcile_reorg(&[], &winner, t.view(), t.height());

    let entry = pool.get(&id(&payment)).expect("still held");
    assert_eq!(entry.added_height, admitted_at, "a reorg must not reset the expiry clock");
}

#[test]
fn reconciliation_of_an_empty_pool_is_a_no_op() {
    let t = TestChain::new();
    let winner = branch(&t, t.tip().0, 1, 700);
    let pool = Mempool::new(cfg());
    pool.reconcile_reorg(&[], &winner, t.view(), t.height());
    assert!(pool.is_empty());
    assert_eq!(pool.orphan_count(), 0);
}

#[test]
fn a_reorg_deeper_than_the_pool_has_seen_leaves_a_consistent_pool() {
    // "A reorg deeper than the mempool's memory" — the adversarial scenario
    // named in CONTRACT §14. Nothing may be left claiming an outpoint that no
    // longer exists.
    let t = TestChain::new();
    t.mine_and_accept(Vec::new());
    let (fork_point, _) = t.tip();
    for _ in 0..4 {
        t.mine_and_accept(Vec::new());
    }
    assert_eq!(t.height(), 5);

    let pool = Mempool::new(cfg());
    let mut disconnected = Vec::new();
    for h in (2..=5).rev() {
        let hash = t.store.hash_at_height(h).expect("read").expect("on chain");
        disconnected.push(t.store.get_block(&hash).expect("read").expect("stored"));
    }
    // A transaction spending a coinbase from the middle of the doomed branch.
    // The outpoint is captured now: after the reorg, height 3 names a
    // different block entirely.
    let doomed = t.coinbase_out(3);
    let payment = spend_with_fee(&t, doomed, 10_000);
    offer(&pool, &t, payment.clone());

    let winner = branch(&t, fork_point, 5, 800);
    assert_eq!(t.height(), 6);
    pool.reconcile_reorg(&disconnected, &winner, t.view(), t.height());

    assert!(pool.is_empty());
    assert_eq!(pool.orphan_count(), 0);
    assert_eq!(pool.spender_of(&doomed), None);
    assert_eq!(pool.size_bytes(), 0);
    assert!(!pool.contains(&id(&payment)));
}
