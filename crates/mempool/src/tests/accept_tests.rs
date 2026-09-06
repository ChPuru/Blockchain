//! The acceptance path, one rule at a time.
//!
//! Every assertion names the exact [`MempoolError`] variant. A test that only
//! asserted "rejected" would keep passing once the transaction started being
//! rejected for the wrong reason.

use ferrum_chain::ValidationError;
use ferrum_storage::MapView;
use ferrum_types::{Amount, Script, TxOut};

use crate::error::MempoolError;
use crate::policy::fee_rate;
use crate::pool::AcceptResult;
use crate::tests::support::{
    cfg, coin, id, locked, out, params, timelocked_tx, tx, unknown_out, view_with,
};
use crate::{Mempool, MempoolConfig};

/// A pool with the relay floor switched off and one funded outpoint.
fn pool_and_funds(value: u64) -> (Mempool, MapView, ferrum_types::OutPoint) {
    let op = unknown_out(1, 0);
    let view = view_with(&[(op, coin(value, 1, false))]);
    (Mempool::new(cfg()), view, op)
}

#[test]
fn a_funded_transaction_is_admitted_with_its_fee_and_rate() {
    let (pool, view, op) = pool_and_funds(100_000);
    let t = tx(&[op], &[90_000]);
    let size = t.serialized_size();

    let result = pool.accept(t.clone(), &view, 10, 0).expect("accepted");
    assert!(result.is_accepted());
    assert_eq!(result.txid(), id(&t));
    assert_eq!(result.relayable(), vec![id(&t)]);

    let entry = pool.get(&id(&t)).expect("held");
    assert_eq!(entry.fee, Amount::from_grains(10_000));
    assert_eq!(entry.size, size);
    assert_eq!(entry.fee_rate, fee_rate(Amount::from_grains(10_000), size).expect("rate"));
    assert_eq!(entry.added_height, 10, "the tip height when it arrived");
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.size_bytes(), size);
    assert!(!pool.is_empty());
}

#[test]
fn relay_is_idempotent() {
    let (pool, view, op) = pool_and_funds(100_000);
    let t = tx(&[op], &[90_000]);
    pool.accept(t.clone(), &view, 10, 0).expect("accepted");
    let again = pool.accept(t.clone(), &view, 10, 0).expect("no error");
    assert_eq!(again, AcceptResult::AlreadyInPool { txid: id(&t) });
    assert_eq!(again.relayable(), Vec::new(), "already known: nothing new to announce");
    assert_eq!(pool.len(), 1);
}

#[test]
fn a_coinbase_is_never_accepted() {
    let pool = Mempool::new(cfg());
    let view = MapView::new();
    let cb = crate::tests::support::coinbase(1, Amount::from_grains(50), b"x");
    assert_eq!(pool.accept(cb, &view, 10, 0), Err(MempoolError::Coinbase));
}

#[test]
fn a_transaction_with_no_outputs_fails_sanity() {
    let (pool, view, op) = pool_and_funds(100_000);
    let mut t = tx(&[op], &[90_000]);
    t.outputs.clear();
    assert_eq!(pool.accept(t, &view, 10, 0), Err(MempoolError::Sanity(ValidationError::NoOutputs)));
}

#[test]
fn a_transaction_spending_one_outpoint_twice_fails_sanity() {
    let (pool, view, op) = pool_and_funds(100_000);
    let t = tx(&[op, op], &[90_000]);
    assert_eq!(
        pool.accept(t, &view, 10, 0),
        Err(MempoolError::Sanity(ValidationError::DuplicateInput { out_point: op }))
    );
}

#[test]
fn a_non_standard_output_is_refused() {
    let (pool, view, op) = pool_and_funds(100_000);
    let mut t = tx(&[op], &[90_000]);
    t.outputs.push(TxOut::new(Amount::from_grains(1), Script::new(vec![0x51])));
    assert_eq!(pool.accept(t, &view, 10, 0), Err(MempoolError::NonStandardOutput { vout: 1 }));
}

#[test]
fn there_is_no_replace_by_fee() {
    let (pool, view, op) = pool_and_funds(100_000);
    let cheap = tx(&[op], &[99_000]);
    let generous = tx(&[op], &[1_000]);
    pool.accept(cheap.clone(), &view, 10, 0).expect("first seen wins");

    // A hundredfold fee makes no difference: v1 has no replacement policy.
    assert_eq!(
        pool.accept(generous, &view, 10, 0),
        Err(MempoolError::Conflict { out_point: op, existing: id(&cheap) })
    );
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.spender_of(&op), Some(id(&cheap)));
}

#[test]
fn a_transaction_below_the_fee_floor_is_refused() {
    let op = unknown_out(1, 0);
    let view = view_with(&[(op, coin(100_000, 1, false))]);
    let pool = Mempool::new(MempoolConfig::new(params()).with_min_fee_rate(1_000));

    // 110 bytes at a 1000 grains/kB floor needs 110 grains; 100 is short.
    let t = tx(&[op], &[99_900]);
    let size = t.serialized_size();
    let rate = fee_rate(Amount::from_grains(100), size).expect("rate");
    assert_eq!(
        pool.accept(t, &view, 10, 0),
        Err(MempoolError::FeeTooLow { fee_rate: rate, min: 1_000 })
    );
    assert!(pool.is_empty());
}

#[test]
fn a_transaction_exactly_at_the_fee_floor_is_accepted() {
    let op = unknown_out(1, 0);
    let view = view_with(&[(op, coin(100_000, 1, false))]);
    let pool = Mempool::new(MempoolConfig::new(params()).with_min_fee_rate(1_000));
    let probe = tx(&[op], &[0]);
    let size = probe.serialized_size();
    let fee = u64::try_from(size).expect("size fits");
    let t = tx(&[op], &[100_000 - fee]);
    assert_eq!(t.serialized_size(), size, "value does not change the encoded size here");
    assert!(pool.accept(t, &view, 10, 0).expect("accepted").is_accepted());
}

#[test]
fn a_transaction_paying_out_more_than_it_takes_in_is_refused() {
    let (pool, view, op) = pool_and_funds(100_000);
    let t = tx(&[op], &[100_001]);
    assert_eq!(
        pool.accept(t, &view, 10, 0),
        Err(MempoolError::InsufficientInputValue {
            inputs: Amount::from_grains(100_000),
            outputs: Amount::from_grains(100_001),
        })
    );
}

#[test]
fn an_immature_coinbase_spend_is_refused() {
    let op = unknown_out(1, 0);
    let view = view_with(&[(op, coin(100_000, 9, true))]);
    let pool = Mempool::new(cfg());
    // maturity 1: a coinbase from height 9 is spendable from height 10, so at
    // tip 8 the next block is 9 and the spend is early.
    assert_eq!(
        pool.accept(tx(&[op], &[90_000]), &view, 8, 0),
        Err(MempoolError::ImmatureCoinbaseSpend {
            out_point: op,
            coin_height: 9,
            spend_height: 9,
            maturity: 1,
        })
    );
}

#[test]
fn a_mature_coinbase_spend_is_accepted() {
    let op = unknown_out(1, 0);
    let view = view_with(&[(op, coin(100_000, 9, true))]);
    let pool = Mempool::new(cfg());
    assert!(pool.accept(tx(&[op], &[90_000]), &view, 9, 0).expect("accepted").is_accepted());
}

#[test]
fn a_script_that_does_not_satisfy_the_output_is_refused_and_names_the_input() {
    let (pool, view, op) = pool_and_funds(100_000);
    let mut t = tx(&[op], &[90_000]);
    // Pushes `OP_2` where the output commits to `OP_1`.
    t.inputs[0].script_sig = Script::new(vec![0x01, 0x52]);
    let err = pool.accept(t, &view, 10, 0).expect_err("the redeem hash does not match");
    assert!(
        matches!(err, MempoolError::ScriptVerification { input_index: 0, .. }),
        "unexpected error: {err}"
    );
}

#[test]
fn a_script_sig_that_is_not_push_only_is_refused() {
    let (pool, view, op) = pool_and_funds(100_000);
    let mut t = tx(&[op], &[90_000]);
    t.inputs[0].script_sig = Script::new(vec![0x76]);
    assert_eq!(
        pool.accept(t, &view, 10, 0),
        Err(MempoolError::NonPushOnlyScriptSig { input_index: 0 })
    );
}

#[test]
fn finality_is_judged_against_the_next_block_not_the_tip() {
    let (pool, view, op) = pool_and_funds(100_000);
    let t = timelocked_tx(&[op], &[90_000], 10);

    // Tip 8: the next block is 9, and the lock is for 10.
    assert_eq!(
        pool.accept(t.clone(), &view, 8, 0),
        Err(MempoolError::NonFinal { lock_time: 10, height: 9 })
    );
    // Tip 9: the next block *is* 10, so the transaction is relayable now.
    assert!(pool.accept(t, &view, 9, 0).expect("accepted").is_accepted());
}

#[test]
fn a_max_sequence_transaction_is_final_whatever_its_lock_time() {
    let (pool, view, op) = pool_and_funds(100_000);
    let mut t = tx(&[op], &[90_000]);
    t.lock_time = u32::MAX - 1;
    // `tx` leaves every sequence at its default, which is `u32::MAX`.
    assert_eq!(t.inputs[0].sequence, u32::MAX);
    assert!(pool.accept(t, &view, 1, 0).expect("accepted").is_accepted());
}

#[test]
fn a_time_locked_transaction_is_judged_against_the_median_time_past() {
    let (pool, view, op) = pool_and_funds(100_000);
    let t = timelocked_tx(&[op], &[90_000], 1_700_000_000);
    assert_eq!(
        pool.accept(t.clone(), &view, 10, 1_699_999_999),
        Err(MempoolError::NonFinal { lock_time: 1_700_000_000, height: 11 })
    );
    assert!(pool.accept(t, &view, 10, 1_700_000_000).expect("accepted").is_accepted());
}

#[test]
fn an_unknown_input_makes_a_transaction_an_orphan_not_a_rejection() {
    let pool = Mempool::new(cfg());
    let view = MapView::new();
    let t = tx(&[unknown_out(9, 0)], &[10]);
    let result = pool.accept(t.clone(), &view, 10, 0).expect("held, not rejected");
    assert_eq!(
        result,
        AcceptResult::Orphan { txid: id(&t), missing: vec![unknown_out(9, 0).txid] }
    );
    assert!(result.is_orphan());
    assert!(result.relayable().is_empty(), "an orphan is not forwarded until it is validated");
    assert_eq!(pool.orphan_count(), 1);
    assert_eq!(pool.len(), 0, "orphans are not in the pool proper");
    assert_eq!(pool.orphan_txids(), vec![id(&t)]);
}

#[test]
fn a_child_may_spend_an_unconfirmed_parent_output() {
    let (pool, view, op) = pool_and_funds(100_000);
    let parent = tx(&[op], &[90_000]);
    pool.accept(parent.clone(), &view, 10, 0).expect("parent accepted");

    let child = tx(&[out(&parent, 0)], &[80_000]);
    assert!(pool.accept(child.clone(), &view, 10, 0).expect("accepted").is_accepted());
    assert_eq!(pool.len(), 2);
    assert_eq!(pool.spender_of(&out(&parent, 0)), Some(id(&child)));
}

#[test]
fn an_input_naming_a_missing_output_of_a_known_parent_is_invalid_not_an_orphan() {
    let (pool, view, op) = pool_and_funds(100_000);
    let parent = tx(&[op], &[90_000]);
    pool.accept(parent.clone(), &view, 10, 0).expect("parent accepted");

    // The parent has exactly one output; vout 4 will never exist, so waiting
    // for a parent that has already arrived cannot help.
    let bad = tx(&[out(&parent, 4)], &[1]);
    assert_eq!(
        pool.accept(bad, &view, 10, 0),
        Err(MempoolError::MissingInput { out_point: out(&parent, 4) })
    );
    assert_eq!(pool.orphan_count(), 0);
}

#[test]
fn a_parent_arriving_promotes_its_orphan() {
    let (pool, view, op) = pool_and_funds(100_000);
    let parent = tx(&[op], &[90_000]);
    let child = tx(&[out(&parent, 0)], &[80_000]);

    pool.accept(child.clone(), &view, 10, 0).expect("child held");
    assert_eq!(pool.orphan_count(), 1);

    let result = pool.accept(parent.clone(), &view, 10, 0).expect("parent accepted");
    match result {
        AcceptResult::Accepted { promoted, .. } => assert_eq!(promoted, vec![id(&child)]),
        other => panic!("expected an acceptance, got {other:?}"),
    }
    assert_eq!(pool.len(), 2);
    assert_eq!(pool.orphan_count(), 0);
}

#[test]
fn a_chain_of_three_arriving_backwards_is_fully_assembled() {
    let (pool, view, op) = pool_and_funds(100_000);
    let parent = tx(&[op], &[90_000]);
    let child = tx(&[out(&parent, 0)], &[80_000]);
    let grandchild = tx(&[out(&child, 0)], &[70_000]);

    // Reverse order, exactly as gossip may deliver them.
    assert!(pool.accept(grandchild.clone(), &view, 10, 0).expect("held").is_orphan());
    assert!(pool.accept(child.clone(), &view, 10, 0).expect("held").is_orphan());
    assert_eq!(pool.orphan_count(), 2);

    let result = pool.accept(parent.clone(), &view, 10, 0).expect("parent accepted");
    let promoted = match result {
        AcceptResult::Accepted { promoted, .. } => promoted,
        other => panic!("expected an acceptance, got {other:?}"),
    };
    assert_eq!(promoted, vec![id(&child), id(&grandchild)], "parent, then child, then grandchild");

    assert_eq!(pool.orphan_count(), 0);
    assert_eq!(pool.len(), 3);
    for t in [&parent, &child, &grandchild] {
        assert!(pool.contains(&id(t)), "{} should be in the pool", id(t));
    }
}

#[test]
fn an_orphan_waiting_on_two_parents_needs_both() {
    let a = unknown_out(1, 0);
    let b = unknown_out(2, 0);
    let view = view_with(&[(a, coin(100_000, 1, false)), (b, coin(100_000, 1, false))]);
    let pool = Mempool::new(cfg());

    let first = tx(&[a], &[90_000]);
    let second = tx(&[b], &[90_000]);
    let joiner = tx(&[out(&first, 0), out(&second, 0)], &[150_000]);

    assert!(pool.accept(joiner.clone(), &view, 10, 0).expect("held").is_orphan());
    match pool.accept(first, &view, 10, 0).expect("accepted") {
        AcceptResult::Accepted { promoted, .. } => assert!(promoted.is_empty(), "still waiting"),
        other => panic!("expected an acceptance, got {other:?}"),
    }
    match pool.accept(second, &view, 10, 0).expect("accepted") {
        AcceptResult::Accepted { promoted, .. } => assert_eq!(promoted, vec![id(&joiner)]),
        other => panic!("expected an acceptance, got {other:?}"),
    }
    assert_eq!(pool.len(), 3);
}

#[test]
fn a_promoted_orphan_that_no_longer_passes_policy_is_dropped_quietly() {
    let op = unknown_out(1, 0);
    let view = view_with(&[(op, coin(100_000, 1, false))]);
    // A floor high enough that the child cannot clear it.
    let pool = Mempool::new(MempoolConfig::new(params()).with_min_fee_rate(500_000));

    let parent = tx(&[op], &[10_000]);
    let child = tx(&[out(&parent, 0)], &[10_000 - 1]);

    assert!(pool.accept(child.clone(), &view, 10, 0).expect("held").is_orphan());
    match pool.accept(parent.clone(), &view, 10, 0).expect("parent clears the floor") {
        AcceptResult::Accepted { promoted, .. } => assert!(promoted.is_empty()),
        other => panic!("expected an acceptance, got {other:?}"),
    }
    assert_eq!(pool.len(), 1);
    assert!(!pool.contains(&id(&child)));
    assert_eq!(pool.orphan_count(), 0, "a promoted orphan does not go back into the orphan pool");
}

#[test]
fn the_pool_reports_what_it_holds() {
    let (pool, view, op) = pool_and_funds(100_000);
    let t = tx(&[op], &[90_000]);
    pool.accept(t.clone(), &view, 10, 0).expect("accepted");

    assert_eq!(pool.txids(), vec![id(&t)]);
    assert_eq!(pool.entries_by_fee().len(), 1);
    assert!(pool.contains(&id(&t)));
    assert!(pool.get(&id(&t)).is_some());
    assert_eq!(pool.min_fee_rate(), 0);
    assert_eq!(pool.config().params.chain_id, params().chain_id);

    let stranger = tx(&[unknown_out(200, 0)], &[1]);
    assert_eq!(pool.get(&id(&stranger)), None);
    assert!(!pool.contains(&id(&stranger)));
    assert_eq!(pool.spender_of(&unknown_out(200, 0)), None);
    assert!(!locked().is_empty(), "the fixture pays to a real template");
}

#[test]
fn a_view_failure_is_the_only_transient_verdict() {
    assert!(MempoolError::View { detail: "disk".into() }.is_transient());
    assert!(!MempoolError::Coinbase.is_transient());
    assert!(!MempoolError::FeeTooLow { fee_rate: 0, min: 1 }.is_transient());
}

#[test]
fn padding_a_transaction_lowers_its_fee_rate_without_touching_its_fee() {
    use crate::tests::support::{entry_of, funded, padded_tx};

    let (view, op) = funded(1, 100_000);
    let pool = Mempool::new(cfg());

    let lean = tx(&[op], &[90_000]);
    pool.accept(lean.clone(), &view, 10, 0).expect("accepted");
    let lean_entry = entry_of(&pool, &lean);

    // The same fee carried by more bytes: a different transaction, so it needs
    // its own funding.
    let (fat_view, fat_op) = funded(2, 100_000);
    let fat_pool = Mempool::new(cfg());
    let fat = padded_tx(&[fat_op], &[90_000], 80);
    fat_pool.accept(fat.clone(), &fat_view, 10, 0).expect("accepted");
    let fat_entry = entry_of(&fat_pool, &fat);

    assert_eq!(lean_entry.fee, fat_entry.fee, "the padding output pays zero");
    assert!(fat_entry.size > lean_entry.size);
    assert!(fat_entry.fee_rate < lean_entry.fee_rate, "more bytes for the same fee is worth less");
}

#[test]
fn an_op_return_output_is_relayable() {
    use crate::tests::support::padded_tx;

    let (pool, view, op) = pool_and_funds(100_000);
    let t = padded_tx(&[op], &[90_000], 80);
    assert!(pool.accept(t, &view, 10, 0).expect("accepted").is_accepted());
}
