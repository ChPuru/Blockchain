//! Unit tests for the coin selector, driven entirely through its public API.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use ferrum_types::{Amount, Coin, OutPoint, Txid};
use ferrum_wallet::{
    BNB_MAX_TRIES, Candidate, FeeRate, P2PKH_INPUT_BYTES, P2PKH_OUTPUT_BYTES, SelectionParams,
    SelectionStrategy, TX_OVERHEAD_BYTES, WalletError, select_coins,
};

fn script() -> ferrum_types::Script {
    ferrum_script::templates::p2pkh(&[9u8; 20])
}

fn coin(value: u64) -> Coin {
    Coin {
        value: Amount::from_grains(value),
        script_pubkey: script(),
        height: 1,
        is_coinbase: false,
    }
}

fn out_point(n: u8) -> OutPoint {
    OutPoint::new(Txid::from_bytes([n; 32]), 0)
}

fn params(fee_rate: u64) -> SelectionParams {
    SelectionParams {
        fee_rate: FeeRate::from_per_kb(fee_rate).unwrap(),
        dust_threshold: Amount::from_grains(3_000),
        base_size: TX_OVERHEAD_BYTES + P2PKH_OUTPUT_BYTES,
        change_output_size: P2PKH_OUTPUT_BYTES,
        change_spend_size: P2PKH_INPUT_BYTES,
    }
}

fn pool(values: &[u64], fee_rate: u64) -> Vec<Candidate> {
    let rate = FeeRate::from_per_kb(fee_rate).unwrap();
    values
        .iter()
        .enumerate()
        .filter_map(|(i, v)| Candidate::price(out_point(i as u8), coin(*v), rate).ok().flatten())
        .collect()
}

#[test]
fn a_candidate_that_cannot_pay_for_itself_is_dropped() {
    let rate = FeeRate::from_per_kb(1_000).unwrap();
    // 143-byte input at 1 grain/byte costs 143 grains.
    assert!(Candidate::price(out_point(1), coin(100), rate).unwrap().is_none());
    assert!(Candidate::price(out_point(1), coin(143), rate).unwrap().is_none());
    assert!(Candidate::price(out_point(1), coin(144), rate).unwrap().is_some());
}

#[test]
fn effective_value_subtracts_the_input_fee() {
    let rate = FeeRate::from_per_kb(1_000).unwrap();
    let c = Candidate::price(out_point(1), coin(10_000), rate).unwrap().unwrap();
    assert_eq!(c.input_bytes, P2PKH_INPUT_BYTES);
    assert_eq!(c.effective_value, Amount::from_grains(10_000 - 143));
}

#[test]
fn branch_and_bound_finds_an_exact_match_and_makes_no_change() {
    let p = params(1_000);
    // base_size = 17 + 37 = 54, base fee = 54. Input fee = 143.
    // A coin worth target + 54 + 143 is an exact changeless match.
    let target = Amount::from_grains(50_000);
    let exact = 50_000 + 54 + 143;
    let candidates = pool(&[exact, 999_999], 1_000);
    let selection = select_coins(&candidates, target, &p).unwrap();
    assert_eq!(selection.strategy, SelectionStrategy::BranchAndBound);
    assert_eq!(selection.change, None);
    assert_eq!(selection.inputs.len(), 1);
    assert_eq!(selection.fee, Amount::from_grains(54 + 143));
    assert_eq!(selection.size, 54 + 143);
}

#[test]
fn branch_and_bound_can_combine_two_coins() {
    let p = params(1_000);
    let target = Amount::from_grains(100_000);
    // 2 inputs: base 54 + 2*143 = 340 total fee.
    let a = 60_000;
    let b = 100_000 + 340 - 60_000;
    let candidates = pool(&[a, b, 5_000_000], 1_000);
    let selection = select_coins(&candidates, target, &p).unwrap();
    assert_eq!(selection.strategy, SelectionStrategy::BranchAndBound);
    assert_eq!(selection.inputs.len(), 2);
    assert_eq!(selection.change, None);
    assert_eq!(selection.fee, Amount::from_grains(340));
}

#[test]
fn largest_first_takes_over_when_no_exact_match_exists() {
    let p = params(1_000);
    let target = Amount::from_grains(50_000);
    let candidates = pool(&[1_000_000], 1_000);
    let selection = select_coins(&candidates, target, &p).unwrap();
    assert_eq!(selection.strategy, SelectionStrategy::LargestFirst);
    assert!(selection.change.is_some());
    assert_eq!(selection.inputs.len(), 1);
}

#[test]
fn largest_first_prefers_the_biggest_coins() {
    let p = params(1_000);
    let target = Amount::from_grains(500_000);
    let candidates = pool(&[100_000, 900_000, 200_000], 1_000);
    let selection = select_coins(&candidates, target, &p).unwrap();
    assert_eq!(selection.inputs.len(), 1);
    assert_eq!(selection.inputs[0].1.value, Amount::from_grains(900_000));
}

#[test]
fn dust_change_is_folded_into_the_fee() {
    let p = params(1_000);
    let target = Amount::from_grains(50_000);
    // Change would be 1_000 grains, below the 3_000-grain dust threshold.
    let value = 50_000 + 54 + 143 + 37 + 1_000;
    let candidates = pool(&[value], 1_000);
    let selection = select_coins(&candidates, target, &p).unwrap();
    assert_eq!(selection.change, None);
    // Every grain not paid to the recipient became fee.
    assert_eq!(selection.fee, Amount::from_grains(value - 50_000));
    assert!(selection.fee_rate() >= 1_000);
}

#[test]
fn change_at_exactly_the_dust_threshold_is_kept() {
    let p = params(1_000);
    let target = Amount::from_grains(50_000);
    let value = 50_000 + 54 + 143 + 37 + 3_000;
    let candidates = pool(&[value], 1_000);
    let selection = select_coins(&candidates, target, &p).unwrap();
    assert_eq!(selection.change, Some(Amount::from_grains(3_000)));
}

#[test]
fn change_one_grain_below_the_dust_threshold_is_dropped() {
    let p = params(1_000);
    let target = Amount::from_grains(50_000);
    let value = 50_000 + 54 + 143 + 37 + 2_999;
    let candidates = pool(&[value], 1_000);
    let selection = select_coins(&candidates, target, &p).unwrap();
    assert_eq!(selection.change, None);
}

#[test]
fn insufficient_funds_names_both_numbers() {
    let p = params(1_000);
    let candidates = pool(&[1_000], 1_000);
    let err = select_coins(&candidates, Amount::from_grains(50_000), &p).unwrap_err();
    match err {
        WalletError::InsufficientFunds { available, required } => {
            assert_eq!(available, 1_000);
            assert!(required > 50_000);
        }
        other => panic!("wrong error: {other:?}"),
    }
}

#[test]
fn an_empty_pool_is_insufficient_funds() {
    let p = params(1_000);
    let err = select_coins(&[], Amount::from_grains(1), &p).unwrap_err();
    assert!(matches!(err, WalletError::InsufficientFunds { available: 0, .. }));
}

#[test]
fn selection_is_reproducible() {
    let p = params(1_000);
    let candidates = pool(&[70_000, 30_000, 90_000, 15_000, 42_000], 1_000);
    let target = Amount::from_grains(100_000);
    let a = select_coins(&candidates, target, &p).unwrap();
    let b = select_coins(&candidates, target, &p).unwrap();
    assert_eq!(a, b);
}

#[test]
fn inputs_come_back_in_outpoint_order() {
    let p = params(1_000);
    let candidates = pool(&[70_000, 30_000, 90_000, 15_000, 42_000], 1_000);
    let selection = select_coins(&candidates, Amount::from_grains(150_000), &p).unwrap();
    let mut sorted = selection.inputs.clone();
    sorted.sort_by(|a, b| a.0.txid.cmp(&b.0.txid).then_with(|| a.0.vout.cmp(&b.0.vout)));
    assert_eq!(selection.inputs, sorted);
}

#[test]
fn cost_of_change_prices_both_halves() {
    let p = params(1_000);
    assert_eq!(
        p.cost_of_change().unwrap(),
        Amount::from_grains((P2PKH_OUTPUT_BYTES + P2PKH_INPUT_BYTES) as u64)
    );
}

#[test]
fn branch_and_bound_never_overshoots_past_the_cost_of_change() {
    let p = params(1_000);
    let target = Amount::from_grains(50_000);
    let base_and_input = 54 + 143;
    // Overshoot by one grain more than the cost of change: BnB must
    // decline and largest-first must take over.
    let over =
        target.to_grains() + base_and_input + (P2PKH_OUTPUT_BYTES + P2PKH_INPUT_BYTES) as u64 + 1;
    let candidates = pool(&[over], 1_000);
    let selection = select_coins(&candidates, target, &p).unwrap();
    assert_eq!(selection.strategy, SelectionStrategy::LargestFirst);
}

#[test]
fn a_pool_of_identical_coins_terminates() {
    let p = params(1_000);
    let values: Vec<u64> = (0..40).map(|_| 10_000u64).collect();
    let candidates = pool(&values, 1_000);
    let selection = select_coins(&candidates, Amount::from_grains(95_000), &p).unwrap();
    assert!(selection.input_total >= Amount::from_grains(95_000));
}

#[test]
fn the_realised_fee_rate_is_never_below_the_request() {
    let p = params(2_500);
    for target in [1_000u64, 12_345, 250_000, 900_000] {
        let candidates = pool(&[400_000, 700_000, 130_000, 55_000], 2_500);
        if let Ok(selection) = select_coins(&candidates, Amount::from_grains(target), &p) {
            assert!(
                selection.fee_rate() >= 2_500,
                "target {target} realised {}",
                selection.fee_rate()
            );
        }
    }
}

#[test]
fn the_branch_and_bound_budget_is_bounded() {
    // A regression guard on the one constant that keeps selection from
    // becoming an unbounded search on a wallet with many coins.
    assert_eq!(BNB_MAX_TRIES, 100_000);
}
