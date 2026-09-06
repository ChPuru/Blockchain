//! SPEC §4.2 and §3.3: spending against the UTXO overlay, and the coinbase.
//!
//! Split out of `apply_tests` because these are the rules that guard the money
//! supply, and they deserve to be read together: resolve, mature, pay for what
//! you spend, and claim no more than the subsidy plus the fees.

use ferrum_storage::{EmptyView, header_hash};
use ferrum_types::{
    Amount, Block, BlockHash, BlockHeader, ChainParams, Coin, Hash32, OutPoint, Script,
    Transaction, Txid,
};

use crate::apply::apply_block;
use crate::ctx::BlockCtx;
use crate::error::ValidationError;
use crate::tests::support::{
    any_spend_script, block_of, burn_script, coin, coinbase, coinbase_with_script_sig, ctx_at,
    devnet, map_view, out_point, parent_header, spend,
};

const PARENT_MS: u64 = 1_700_000_000_000;
const BLOCK_MS: u64 = PARENT_MS + 120_000;
const MTP_S: u64 = PARENT_MS / 1_000;

fn amount(v: u64) -> Amount {
    Amount::from_grains(v)
}

/// A parent header, its hash and a context for its child at height 1.
fn scene(params: &ChainParams) -> (BlockHeader, BlockHash, BlockCtx) {
    let parent = parent_header(PARENT_MS, params);
    let hash = header_hash(&parent);
    let ctx = ctx_at(1, &parent, MTP_S, params);
    (parent, hash, ctx)
}

fn block_with(txs: Vec<Transaction>, prev: BlockHash, params: &ChainParams) -> Block {
    block_of(txs, prev, BLOCK_MS, params.genesis_bits)
}

// ------------------------------------------------------- contextual rules

#[test]
fn spending_an_output_that_does_not_exist_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let ghost = OutPoint::new(Txid(Hash32::from_bytes([15; 32])), 0);
    let tx = spend(&[ghost], &[(amount(1), any_spend_script())]);
    let block = block_with(vec![coinbase(1, amount(1), b"n"), tx], prev, &params);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::MissingInput { tx_index: 1, out_point: ghost })
    );
}

#[test]
fn a_double_spend_inside_one_block_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([16; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(1_000), 0, false))]);

    let first = spend(&[funded], &[(amount(900), any_spend_script())]);
    let second = spend(&[funded], &[(amount(800), any_spend_script())]);
    let block = block_with(vec![coinbase(1, amount(1), b"n"), first, second], prev, &params);

    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::MissingInput { tx_index: 2, out_point: funded }),
        "the second spender finds the coin already gone"
    );
}

#[test]
fn a_coinbase_spent_before_maturity_is_rejected() {
    let params = devnet();
    let (_, prev, _) = scene(&params);
    let ctx = ctx_at(100, &parent_header(PARENT_MS, &params), MTP_S, &params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([17; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(1_000), 1, true))]);

    let tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    let block =
        block_of(vec![coinbase(100, amount(1), b"n"), tx], prev, BLOCK_MS, params.genesis_bits);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::ImmatureCoinbaseSpend {
            tx_index: 1,
            out_point: funded,
            coin_height: 1,
            spend_height: 100,
            maturity: 100,
        }),
        "height 1 + 100 = 101, so height 100 is one block too early"
    );
}

#[test]
fn a_coinbase_spent_exactly_at_maturity_is_accepted() {
    let params = devnet();
    let parent = parent_header(PARENT_MS, &params);
    let prev = header_hash(&parent);
    let ctx = ctx_at(101, &parent, MTP_S, &params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([18; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(1_000), 1, true))]);

    let tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    let reward = params.block_subsidy(101).checked_add(amount(100)).unwrap();
    let block =
        block_of(vec![coinbase(101, reward, b"n"), tx], prev, BLOCK_MS, params.genesis_bits);
    assert!(apply_block(&pre, &block, &ctx).is_ok());
}

#[test]
fn a_transaction_that_spends_more_than_it_holds_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([19; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(100), 0, false))]);
    let tx = spend(&[funded], &[(amount(101), any_spend_script())]);
    let block = block_with(vec![coinbase(1, amount(1), b"n"), tx], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::InsufficientInputValue {
            tx_index: 1,
            inputs: amount(100),
            outputs: amount(101),
        })
    );
}

#[test]
fn an_input_sum_outside_the_money_range_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let a = OutPoint::new(Txid(Hash32::from_bytes([20; 32])), 0);
    let b = OutPoint::new(Txid(Hash32::from_bytes([20; 32])), 1);
    let pre =
        map_view(&[(a, coin(Amount::MAX_MONEY, 0, false)), (b, coin(Amount::MAX_MONEY, 0, false))]);
    let tx = spend(&[a, b], &[(amount(1), any_spend_script())]);
    let block = block_with(vec![coinbase(1, amount(1), b"n"), tx], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::InputSumOverflow { tx_index: 1 })
    );
}

#[test]
fn a_non_final_transaction_makes_the_block_invalid() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([21; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(1_000), 0, false))]);
    let mut tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    tx.lock_time = 50; // a height lock, and we are at height 1
    tx.inputs[0].sequence = 0;
    let reward = params.block_subsidy(1).checked_add(amount(100)).unwrap();
    let block = block_with(vec![coinbase(1, reward, b"n"), tx], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::NonFinalTransaction { tx_index: 1, lock_time: 50 })
    );
}

#[test]
fn a_script_that_does_not_satisfy_its_output_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([22; 32])), 0);
    let unspendable =
        Coin { value: amount(1_000), script_pubkey: burn_script(), height: 0, is_coinbase: false };
    let pre = map_view(&[(funded, unspendable)]);
    let tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    let reward = params.block_subsidy(1).checked_add(amount(100)).unwrap();
    let block = block_with(vec![coinbase(1, reward, b"n"), tx], prev, &params);
    assert!(matches!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::ScriptVerification { tx_index: 1, input_index: 0, .. })
    ));
}

#[test]
fn fees_accumulate_across_transactions() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let a = OutPoint::new(Txid(Hash32::from_bytes([23; 32])), 0);
    let b = OutPoint::new(Txid(Hash32::from_bytes([24; 32])), 0);
    let pre = map_view(&[(a, coin(amount(500), 0, false)), (b, coin(amount(500), 0, false))]);
    let tx1 = spend(&[a], &[(amount(450), any_spend_script())]);
    let tx2 = spend(&[b], &[(amount(430), any_spend_script())]);
    let reward = params.block_subsidy(1).checked_add(amount(120)).unwrap();

    let ok = block_with(vec![coinbase(1, reward, b"n"), tx1.clone(), tx2.clone()], prev, &params);
    assert!(apply_block(&pre, &ok, &ctx).is_ok(), "50 + 70 grains of fees");

    let over = block_with(
        vec![coinbase(1, reward.checked_add(amount(1)).unwrap(), b"n"), tx1, tx2],
        prev,
        &params,
    );
    assert!(matches!(
        apply_block(&pre, &over, &ctx),
        Err(ValidationError::CoinbaseOverpayment { .. })
    ));
}

// ------------------------------------------------------------ coinbase rules

#[test]
fn a_coinbase_that_overpays_by_one_grain_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let subsidy = params.block_subsidy(1);
    let greedy = subsidy.checked_add(amount(1)).unwrap();
    let block = block_with(vec![coinbase(1, greedy, b"n")], prev, &params);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::CoinbaseOverpayment { claimed: greedy, allowed: subsidy })
    );
}

#[test]
fn a_coinbase_paying_exactly_the_subsidy_is_accepted() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let block = block_with(vec![coinbase(1, params.block_subsidy(1), b"n")], prev, &params);
    assert!(apply_block(&EmptyView, &block, &ctx).is_ok());
}

#[test]
fn a_coinbase_without_the_height_push_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    // OP_DUP OP_DUP: two bytes, so the length rule passes and only BIP-34 can
    // reject it. Without this rule two blocks share a coinbase txid, which is
    // CVE-2012-1909.
    let cb = coinbase_with_script_sig(Script::new(vec![0x76, 0x76]), amount(1));
    let block = block_with(vec![cb], prev, &params);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::CoinbaseMissingHeightPush)
    );
}

#[test]
fn a_coinbase_committing_to_another_height_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let block = block_with(vec![coinbase(2, amount(1), b"n")], prev, &params);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::CoinbaseHeightMismatch { expected: 1, found: vec![0x02] })
    );
}

#[test]
fn a_one_byte_coinbase_script_sig_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let cb = coinbase_with_script_sig(Script::new(vec![0x51]), amount(1));
    let block = block_with(vec![cb], prev, &params);
    assert!(matches!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::CoinbaseScriptSigLength { len: 1, .. })
    ));
}

#[test]
fn an_over_long_coinbase_script_sig_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let mut sig = vec![0x51];
    sig.extend(std::iter::repeat_n(0x61u8, 200));
    let cb = coinbase_with_script_sig(Script::new(sig), amount(1));
    let block = block_with(vec![cb], prev, &params);
    assert!(matches!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::CoinbaseScriptSigLength { len: 201, .. })
    ));
}

#[test]
fn creating_an_outpoint_that_already_exists_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let cb = coinbase(1, amount(1), b"n");
    let collision = out_point(&cb, 0);
    let pre = map_view(&[(collision, coin(amount(7), 0, true))]);
    let block = block_with(vec![cb], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::DuplicateOutPoint { out_point: collision })
    );
}

#[test]
fn a_non_coinbase_output_colliding_with_the_utxo_set_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([25; 32])), 0);
    let tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    let collision = out_point(&tx, 0);
    let pre = map_view(&[
        (funded, coin(amount(1_000), 0, false)),
        (collision, coin(amount(3), 0, false)),
    ]);
    let reward = params.block_subsidy(1).checked_add(amount(100)).unwrap();
    let block = block_with(vec![coinbase(1, reward, b"n"), tx], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::DuplicateOutPoint { out_point: collision })
    );
}
