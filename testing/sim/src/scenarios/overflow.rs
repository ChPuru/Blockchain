//! **Attack:** make a sum of money wrap, or leave the money range, so that a
//! transaction appears to balance while creating coins.
//!
//! This is CVE-2010-5139, the value-overflow incident: on 15 August 2010 a
//! transaction with two outputs of roughly `2^63` grains each summed to a
//! small positive number under wrapping arithmetic, and block 74 638 created
//! 184 billion BTC. The fix was a hard fork and a chain rollback.
//!
//! Ferrum closes the class three ways at once, and this module checks each:
//!
//! 1. [`ferrum_types::Amount`] has **no** `impl Add`. Every monetary step is a
//!    `checked_*` call whose `None` becomes a typed error, so a wrap is a
//!    compile-time impossibility rather than a runtime hazard.
//! 2. Every individual output must satisfy `is_valid_money()`
//!    (`0 <= v <= MAX_MONEY`), so a single enormous output is rejected before
//!    any addition happens.
//! 3. The *sum* must also be valid money, so two individually legal outputs
//!    whose total exceeds `MAX_MONEY` are rejected as well — this is the case
//!    that a naive "check each output" implementation misses.
//!
//! The same three rules apply on the input side, so a hand-built pre-state
//! holding two `MAX_MONEY` coins produces
//! [`ValidationError::InputSumOverflow`] rather than a wrapped fee.
//!
//! **Red:** each of the four shapes above is rejected with its own variant.
//! **Green:** a transaction whose sums are large but legal is accepted.

use ferrum_storage::MapView;
use ferrum_types::{
    Amount, Coin, OutPoint, Script, Transaction, TxIn, TxOut, Txid,
};

use crate::chain_builder::{BlockPlan, ChainBuilder};
use crate::error::SimError;
use crate::scenarios::{Verdict, judge};

/// The `OP_1` script every fixture coin here is locked with.
///
/// These transactions never reach script evaluation — they fail on the money
/// rules first — so a signature would only make the fixture harder to read.
#[must_use]
pub fn anyone_script() -> Script {
    Script::new(vec![0x51])
}

/// A pre-state holding `count` coins of `value` each, at outpoints
/// `(seed, 0..count)`.
#[must_use]
pub fn huge_pre_state(seed: u8, count: u32, value: Amount) -> (MapView, Vec<OutPoint>) {
    let txid = Txid(ferrum_types::Hash32::from_bytes([seed; 32]));
    let mut view = MapView::new();
    let mut ops = Vec::with_capacity(count as usize);
    for vout in 0..count {
        let op = OutPoint::new(txid, vout);
        view.insert(
            op,
            Coin {
                value,
                script_pubkey: anyone_script(),
                height: 0,
                is_coinbase: false,
            },
        );
        ops.push(op);
    }
    (view, ops)
}

/// A transaction spending `inputs` and paying `outputs`, with empty
/// `script_sig`s.
#[must_use]
pub fn unsigned_spend(inputs: &[OutPoint], outputs: &[Amount]) -> Transaction {
    Transaction {
        version: 1,
        inputs: inputs
            .iter()
            .map(|op| TxIn::new(*op, Script::EMPTY))
            .collect(),
        outputs: outputs.iter().map(|v| TxOut::new(*v, anyone_script())).collect(),
        lock_time: 0,
    }
}

/// Put `tx` in a block on `chain` and judge it against `pre`.
///
/// # Errors
///
/// [`SimError`] if the block cannot be built or the executors disagree.
pub fn judge_with_pre_state(
    chain: &mut ChainBuilder,
    pre: &MapView,
    tx: Transaction,
) -> Result<Verdict, SimError> {
    let ctx = chain.next_ctx()?;
    let block = chain.build_block(&BlockPlan { txs: vec![tx], ..BlockPlan::default() })?;
    judge(pre, &block, &ctx)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_chain::ValidationError;

    use super::*;
    use crate::prng::XorShift64;

    fn chain() -> ChainBuilder {
        ChainBuilder::devnet(XorShift64::SCENARIO_SEED).unwrap()
    }

    // ---- red -----------------------------------------------------------

    #[test]
    fn a_single_output_above_max_money_is_rejected() {
        let mut c = chain();
        let (pre, ops) = huge_pre_state(0x10, 1, Amount::MAX_MONEY);
        let over = Amount::from_grains(Amount::MAX_MONEY.to_grains() + 1);
        let tx = unsigned_spend(&ops, &[over]);
        match judge_with_pre_state(&mut c, &pre, tx).unwrap().rejection() {
            Some(ValidationError::OutputValueOutOfRange { value }) => assert_eq!(*value, over),
            other => panic!("expected OutputValueOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn two_legal_outputs_whose_sum_is_not_are_rejected() {
        // This is the case a "check each output" implementation misses: both
        // values pass `is_valid_money`, and only the sum does not.
        let mut c = chain();
        let (pre, ops) = huge_pre_state(0x11, 1, Amount::MAX_MONEY);
        let tx = unsigned_spend(&ops, &[Amount::MAX_MONEY, Amount::MAX_MONEY]);
        assert!(tx.outputs.iter().all(|o| o.value.is_valid_money()));
        assert!(matches!(
            judge_with_pre_state(&mut c, &pre, tx).unwrap().rejection(),
            Some(ValidationError::OutputSumOverflow)
        ));
    }

    #[test]
    fn outputs_that_would_wrap_a_u64_are_rejected() {
        // CVE-2010-5139 verbatim: two outputs near 2^63 that wrap to a small
        // positive number under unchecked addition.
        let mut c = chain();
        let (pre, ops) = huge_pre_state(0x12, 1, Amount::MAX_MONEY);
        let half = Amount::from_grains(u64::MAX / 2 + 1);
        let tx = unsigned_spend(&ops, &[half, half]);
        assert_eq!(half.to_grains().wrapping_add(half.to_grains()), 0, "these two wrap to zero");
        assert!(matches!(
            judge_with_pre_state(&mut c, &pre, tx).unwrap().rejection(),
            // The individual values are already outside the money range, so
            // the cheaper rule fires first — which is the correct order.
            Some(ValidationError::OutputValueOutOfRange { .. })
        ));
    }

    #[test]
    fn an_input_sum_above_max_money_is_rejected() {
        let mut c = chain();
        let (pre, ops) = huge_pre_state(0x13, 2, Amount::MAX_MONEY);
        let tx = unsigned_spend(&ops, &[Amount::from_grains(1)]);
        match judge_with_pre_state(&mut c, &pre, tx).unwrap().rejection() {
            Some(ValidationError::InputSumOverflow { tx_index }) => assert_eq!(*tx_index, 1),
            other => panic!("expected InputSumOverflow, got {other:?}"),
        }
    }

    #[test]
    fn paying_out_more_than_was_spent_is_rejected_even_by_one_grain() {
        let mut c = chain();
        let value = Amount::from_grains(1_000_000);
        let (pre, ops) = huge_pre_state(0x14, 1, value);
        let tx = unsigned_spend(&ops, &[Amount::from_grains(1_000_001)]);
        match judge_with_pre_state(&mut c, &pre, tx).unwrap().rejection() {
            Some(ValidationError::InsufficientInputValue { inputs, outputs, .. }) => {
                assert_eq!(*inputs, value);
                assert_eq!(*outputs, Amount::from_grains(1_000_001));
            }
            other => panic!("expected InsufficientInputValue, got {other:?}"),
        }
    }

    // ---- green ---------------------------------------------------------

    #[test]
    fn a_large_but_legal_transaction_is_accepted() {
        let mut c = chain();
        let value = Amount::from_grains(Amount::MAX_MONEY.to_grains() / 4);
        let (pre, ops) = huge_pre_state(0x15, 2, value);
        let half = Amount::from_grains(value.to_grains());
        let tx = unsigned_spend(&ops, &[half, half.saturating_sub(Amount::from_grains(1_000))]);
        let verdict = judge_with_pre_state(&mut c, &pre, tx).unwrap();
        let diff = verdict.diff().expect("half the money supply still balances");
        assert_eq!(diff.spent.len(), 2);
    }

    #[test]
    fn the_amount_type_has_no_unchecked_addition() {
        // The defence is structural, not a runtime check: `Amount` exposes
        // `checked_*`, and there is no `impl Add` to reach for by accident.
        // The two halves are separate on purpose — `checked_add` guards the
        // `u64`, `is_valid_money` guards the consensus range — because a sum
        // can leave the money range long before it wraps, and a rule that
        // only checked for wrapping would miss it.
        assert_eq!(Amount::from_grains(u64::MAX).checked_add(Amount::from_grains(1)), None);
        let over = Amount::MAX_MONEY
            .checked_add(Amount::from_grains(1))
            .expect("MAX_MONEY plus one still fits a u64");
        assert!(!over.is_valid_money(), "and the range check is what rejects it");
        assert_eq!(Amount::ZERO.checked_sub(Amount::from_grains(1)), None);
        assert_eq!(
            Amount::from_grains(2).checked_mul_u64(u64::MAX),
            None,
            "multiplication is checked too"
        );
    }

    #[test]
    fn the_fee_accumulator_is_checked_across_transactions() {
        // Two transactions each paying an enormous fee would overflow the
        // block's fee total if the accumulator were unchecked.
        let mut c = chain();
        let (pre, ops) = huge_pre_state(0x16, 2, Amount::MAX_MONEY);
        let a = unsigned_spend(&ops[0..1], &[Amount::from_grains(1)]);
        let b = unsigned_spend(&ops[1..2], &[Amount::from_grains(1)]);
        let ctx = c.next_ctx().unwrap();
        let block =
            c.build_block(&BlockPlan { txs: vec![a, b], ..BlockPlan::default() }).unwrap();
        // Each transaction alone pays a fee of nearly MAX_MONEY, so the block
        // total cannot be valid money.
        assert!(matches!(
            judge(&pre, &block, &ctx).unwrap().rejection(),
            Some(ValidationError::FeeOverflow)
        ));
    }
}
