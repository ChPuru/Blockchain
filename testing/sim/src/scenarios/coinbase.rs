//! **Attack:** a coinbase that pays itself one grain more than it is owed.
//!
//! The subsidy schedule is the only source of new coins, and fees are recycled
//! rather than created. A coinbase claiming `subsidy + fees + 1` inflates the
//! money supply by one grain per block — 4 320 grains a day at a two-minute
//! spacing, which is invisible in any dashboard and permanent in the ledger.
//! An inflation bug is the one class of consensus bug that cannot be fixed
//! after the fact: the coins exist, someone owns them, and taking them back is
//! a different chain.
//!
//! The rule is `sum(coinbase.outputs) <= block_subsidy(height) + total_fees`
//! (SPEC §3.3 rule 13), with the comparison in checked integer arithmetic on
//! [`ferrum_types::Amount`], which has no `impl Add` precisely so that every
//! monetary step is a `checked_*` call whose `None` is a typed error.
//!
//! **Red:** claiming one grain over is [`ValidationError::CoinbaseOverpayment`]
//! with the exact claimed and allowed amounts.
//! **Green:** claiming exactly the allowance is valid, and claiming *less* is
//! also valid — the difference is burned, which a miner is free to do.

use ferrum_types::Amount;

use crate::chain_builder::{BlockPlan, ChainBuilder};
use crate::error::SimError;
use crate::scenarios::{Verdict, judge};

/// Build a block whose coinbase claims `subsidy + fees + bonus - burn`.
///
/// # Errors
///
/// [`SimError`] if the block cannot be built.
pub fn coinbase_claiming(
    chain: &mut ChainBuilder,
    bonus: u64,
    burn: u64,
) -> Result<Verdict, SimError> {
    let ctx = chain.next_ctx()?;
    let pre = chain.state_view();
    let block = chain.build_block(&BlockPlan {
        coinbase_bonus: bonus,
        coinbase_burn: burn,
        ..BlockPlan::default()
    })?;
    judge(&pre, &block, &ctx)
}

/// The allowance a coinbase has at the tip's next height, with no fees.
///
/// # Errors
///
/// [`SimError::Fixture`] on an empty chain.
pub fn empty_block_allowance(chain: &ChainBuilder) -> Result<Amount, SimError> {
    Ok(chain.params().block_subsidy(chain.height().saturating_add(1)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_chain::ValidationError;

    use super::*;
    use crate::keys::Lock;
    use crate::prng::XorShift64;
    use crate::scenarios::matured_chain;
    use crate::chain_builder::TxPlan;

    fn chain() -> ChainBuilder {
        ChainBuilder::devnet(XorShift64::SCENARIO_SEED).unwrap()
    }

    // ---- red -----------------------------------------------------------

    #[test]
    fn one_grain_over_the_allowance_is_rejected() {
        let mut c = chain();
        let allowed = empty_block_allowance(&c).unwrap();
        let verdict = coinbase_claiming(&mut c, 1, 0).unwrap();
        match verdict.rejection() {
            Some(ValidationError::CoinbaseOverpayment { claimed, allowed: reported }) => {
                assert_eq!(*reported, allowed);
                assert_eq!(*claimed, allowed.checked_add(Amount::from_grains(1)).unwrap());
            }
            other => panic!("expected CoinbaseOverpayment, got {other:?}"),
        }
    }

    #[test]
    fn a_large_overpayment_is_rejected_by_the_same_rule() {
        let mut c = chain();
        let verdict = coinbase_claiming(&mut c, 50 * ferrum_types::COIN, 0).unwrap();
        assert!(matches!(
            verdict.rejection(),
            Some(ValidationError::CoinbaseOverpayment { .. })
        ));
    }

    #[test]
    fn a_coinbase_may_not_keep_a_fee_it_was_not_paid() {
        // A block with no transactions pays no fees, so a coinbase that claims
        // a fee-sized bonus is claiming money nobody spent.
        let mut c = matured_chain(11, 2).unwrap();
        let verdict = coinbase_claiming(&mut c, 10_000, 0).unwrap();
        assert!(matches!(
            verdict.rejection(),
            Some(ValidationError::CoinbaseOverpayment { .. })
        ));
    }

    // ---- green ---------------------------------------------------------

    #[test]
    fn claiming_exactly_the_allowance_is_valid() {
        let mut c = chain();
        assert!(coinbase_claiming(&mut c, 0, 0).unwrap().is_accepted());
    }

    #[test]
    fn claiming_less_than_the_allowance_is_valid_and_burns_the_difference() {
        let mut c = chain();
        let allowed = empty_block_allowance(&c).unwrap();
        let verdict = coinbase_claiming(&mut c, 0, 1).unwrap();
        let diff = verdict.diff().expect("under-claiming is legal");
        let claimed = diff.created.iter().fold(Amount::ZERO, |a, (_, c)| {
            a.checked_add(c.value).unwrap_or(Amount::MAX_MONEY)
        });
        assert_eq!(claimed, allowed.checked_sub(Amount::from_grains(1)).unwrap());
    }

    #[test]
    fn the_allowance_grows_by_exactly_the_fees_a_block_carries() {
        let mut c = matured_chain(12, 2).unwrap();
        let height = c.height() + 1;
        let coins = c.take_mature(2, height);
        assert_eq!(coins.len(), 2);
        let fee = Amount::from_grains(7_777);
        let tx = c.build_tx(&TxPlan::sweep(coins, Lock::P2pkh { key: 3 }, fee)).unwrap();

        let ctx = c.next_ctx().unwrap();
        let pre = c.state_view();
        let subsidy = c.params().block_subsidy(height);

        // Exactly subsidy + fee is fine.
        let ok = c.build_block(&BlockPlan { txs: vec![tx.clone()], ..BlockPlan::default() })
            .unwrap();
        let verdict = judge(&pre, &ok, &ctx).unwrap();
        assert!(verdict.is_accepted());
        assert_eq!(
            ok.txs[0].total_output().unwrap(),
            subsidy.checked_add(fee).unwrap(),
            "the honest coinbase claims subsidy plus the fee"
        );

        // One grain more is not.
        let bad = c
            .build_block(&BlockPlan {
                txs: vec![tx],
                coinbase_bonus: 1,
                ..BlockPlan::default()
            })
            .unwrap();
        match judge(&pre, &bad, &ctx).unwrap().rejection() {
            Some(ValidationError::CoinbaseOverpayment { claimed, allowed }) => {
                assert_eq!(*allowed, subsidy.checked_add(fee).unwrap());
                assert_eq!(claimed.to_grains(), allowed.to_grains() + 1);
            }
            other => panic!("expected CoinbaseOverpayment, got {other:?}"),
        }
    }

    #[test]
    fn the_subsidy_schedule_is_what_bounds_the_allowance() {
        // The rule reads `block_subsidy(height)`, not a constant, so a chain
        // past a halving must accept only the halved amount.
        let params = ferrum_types::ChainParams::devnet();
        let interval = params.halving_interval;
        assert_eq!(params.block_subsidy(0), Amount::from_grains(50 * ferrum_types::COIN));
        assert_eq!(params.block_subsidy(interval), Amount::from_grains(25 * ferrum_types::COIN));
        assert_eq!(params.block_subsidy(u64::MAX), Amount::ZERO);
    }
}
