//! `getbalance`, `listunspent` and the address report they share.
//!
//! The point of these tests is that one report backs all three views, so a
//! balance and a history can never disagree about the same address.

use ferrum_storage::txid;
use ferrum_types::{Amount, COIN, Transaction, TxOut};

use crate::error::RpcErrorCode;
use crate::handlers::address::{address_report, get_balance, is_immature, list_unspent};
use crate::tests::fixture::{FIXTURE_MATURITY, Fixture, StubMempool, address};

#[test]
fn every_mined_coinbase_shows_up_in_the_balance() {
    // Maturity is 2 in the fixture, so with a tip at height 4 the coinbases of
    // heights 1 and 2 are spendable and 3 and 4 are not.
    let f = Fixture::build(4, false);
    let chain = f.provider();
    let balance = get_balance(&*chain, &StubMempool::new(), &f.miner.encode()).unwrap();
    assert_eq!(balance.utxo_count, 4);
    assert_eq!(balance.confirmed.to_grains(), 2 * 50 * COIN);
    assert_eq!(balance.immature.to_grains(), 2 * 50 * COIN);
}

#[test]
fn the_maturity_boundary_is_where_the_wallet_puts_it() {
    assert_eq!(FIXTURE_MATURITY, 2);
    let coin = ferrum_types::Coin {
        value: Amount::from_grains(1),
        script_pubkey: ferrum_types::Script::new(vec![0x51]),
        height: 5,
        is_coinbase: true,
    };
    assert!(is_immature(&coin, 6, FIXTURE_MATURITY), "one confirmation is not enough");
    assert!(!is_immature(&coin, 7, FIXTURE_MATURITY), "two confirmations mature it");
}

#[test]
fn a_spend_moves_value_between_two_addresses() {
    let f = Fixture::build(2, true);
    let chain = f.provider();
    let pool = StubMempool::new();

    let recipient = get_balance(&*chain, &pool, &f.recipient.encode()).unwrap();
    // The spend paid the coinbase value less a 10 000-grain fee, and the
    // recipient's output is not a coinbase, so it is spendable immediately.
    assert_eq!(recipient.utxo_count, 1);
    assert_eq!(recipient.confirmed.to_grains(), 50 * COIN - 10_000);
    assert_eq!(recipient.immature.to_grains(), 0);

    let miner = get_balance(&*chain, &pool, &f.miner.encode()).unwrap();
    // Block 1's coinbase was spent; blocks 2 and 3's remain, both immature at
    // a tip of height 3 with a two-block window... except block 1's, which is
    // gone. So: two coinbases left, one of them mature.
    assert_eq!(miner.utxo_count, 2);
}

#[test]
fn listunspent_names_every_outpoint_with_a_string_amount() {
    let f = Fixture::build(3, false);
    let chain = f.provider();
    let rows = list_unspent(&*chain, &StubMempool::new(), &f.miner.encode()).unwrap();
    assert_eq!(rows.len(), 3);
    for row in &rows {
        assert_eq!(row.outpoint.len(), 64 + 2, "outpoint is <txid>:<vout>");
        assert!(row.outpoint.ends_with(":0"));
        assert_eq!(row.value.to_grains(), 50 * COIN);
        assert!(!row.script.is_empty());
    }
    let json = serde_json::to_value(&rows).unwrap();
    assert!(json[0]["value"].is_string(), "an amount is never a JSON number");
    // The four field names the contract lists, and no fewer.
    for field in ["outpoint", "value", "height", "script"] {
        assert!(json[0].get(field).is_some(), "listunspent is missing `{field}`");
    }
}

#[test]
fn heights_in_listunspent_match_the_blocks_that_created_the_coins() {
    let f = Fixture::build(3, false);
    let chain = f.provider();
    let mut heights: Vec<u64> = list_unspent(&*chain, &StubMempool::new(), &f.miner.encode())
        .unwrap()
        .iter()
        .map(|r| r.height)
        .collect();
    heights.sort_unstable();
    assert_eq!(heights, vec![1, 2, 3]);
}

#[test]
fn a_mempool_credit_is_pending_rather_than_confirmed() {
    let f = Fixture::build(2, false);
    let chain = f.provider();
    let pool = StubMempool::new();
    let pending = Transaction {
        version: 1,
        inputs: vec![ferrum_types::TxIn::new(
            ferrum_types::OutPoint::new(ferrum_types::Txid::ZERO, 0),
            ferrum_types::Script::EMPTY,
        )],
        outputs: vec![TxOut::new(Amount::from_grains(4_242), f.recipient.script_pubkey())],
        lock_time: 0,
    };
    pool.insert(pending, Amount::from_grains(100), 2);

    let report = address_report(&*chain, &pool, &f.recipient.encode()).unwrap();
    assert_eq!(report.pending.to_grains(), 4_242);
    assert_eq!(report.confirmed.to_grains(), 0);
    assert_eq!(report.history.len(), 1);
    assert_eq!(report.history[0].height, None, "a mempool entry has no height");
    assert_eq!(report.history[0].delta, 4_242);
}

#[test]
fn history_and_balance_are_computed_from_the_same_key() {
    // The index files a script under the keys `ferrum_storage::address_keys`
    // extracts; the report must use the same key or an address would list a
    // transaction in its history and then attribute no value to it.
    let f = Fixture::build(3, false);
    let chain = f.provider();
    let report = address_report(&*chain, &StubMempool::new(), &f.miner.encode()).unwrap();
    assert_eq!(report.key, f.miner.payload.as_bytes().to_vec());
    let credited: i128 = report.history.iter().map(|h| h.delta).sum();
    let held = i128::from(report.confirmed.to_grains()) + i128::from(report.immature.to_grains());
    assert_eq!(credited, held, "history and balance disagree");
}

#[test]
fn history_is_newest_first() {
    let f = Fixture::build(3, false);
    let chain = f.provider();
    let report = address_report(&*chain, &StubMempool::new(), &f.miner.encode()).unwrap();
    let heights: Vec<Option<u64>> = report.history.iter().map(|h| h.height).collect();
    assert_eq!(heights, vec![Some(3), Some(2), Some(1)]);
}

#[test]
fn an_address_nobody_paid_reports_zeroes() {
    let f = Fixture::build(2, false);
    let chain = f.provider();
    let report = address_report(&*chain, &StubMempool::new(), &address(123).encode()).unwrap();
    assert_eq!(report.confirmed, Amount::ZERO);
    assert_eq!(report.immature, Amount::ZERO);
    assert_eq!(report.pending, Amount::ZERO);
    assert_eq!(report.tx_count(), 0);
    assert_eq!(report.utxo_count(), 0);
}

#[test]
fn address_queries_need_the_index() {
    let f = Fixture::build_with_index(2, false, false);
    let chain = f.provider();
    let err = get_balance(&*chain, &StubMempool::new(), &f.miner.encode()).unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::IndexDisabled);
    let err = list_unspent(&*chain, &StubMempool::new(), &f.miner.encode()).unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::IndexDisabled);
}

#[test]
fn a_malformed_address_is_refused_before_any_lookup() {
    let f = Fixture::build(1, false);
    let chain = f.provider();
    let err = get_balance(&*chain, &StubMempool::new(), "rfer1nonsense").unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::InvalidAddress);
}

#[test]
fn the_genesis_burn_output_belongs_to_no_address() {
    // Genesis pays one provably unspendable OP_RETURN output. It is in the
    // UTXO set, so it must not be attributed to anyone.
    let f = Fixture::build(1, false);
    let genesis = f.block_at(0);
    let script = &genesis.txs[0].outputs[0].script_pubkey;
    assert_eq!(crate::handlers::convert::script_type_name(script), "op_return");
    assert_eq!(
        crate::handlers::convert::address_of_script(script, ferrum_types::Network::Devnet),
        None
    );
    let _ = txid(&genesis.txs[0]);
}
