//! **Attack:** spending one coin twice inside a single block.
//!
//! Two shapes, and Ferrum rejects both with different, deliberately redundant
//! rules:
//!
//! 1. **Two inputs of one transaction naming the same outpoint.** Caught by
//!    SPEC §4.1's duplicate-input check, before any state is touched, as
//!    [`ferrum_chain::ValidationError::DuplicateInput`].
//! 2. **Two transactions in one block spending the same coin.** The first
//!    transaction's inputs are marked spent in the overlay before the next
//!    transaction is validated (SPEC §4.2 step 4), so the second sees nothing
//!    there and fails with [`ferrum_chain::ValidationError::MissingInput`] naming *its* index
//!    in the block.
//!
//! The redundancy is on purpose. The overlay alone would catch both, but the
//! cheap context-free check means a transaction with a duplicated input is
//! rejected before a single database read, and a peer cannot make a node do
//! work by sending obviously malformed transactions.
//!
//! **Red:** both shapes are rejected, each with its own variant.
//! **Green:** the same two transactions spending *different* coins are
//! accepted, and the resulting diff spends each coin exactly once.

use ferrum_types::Amount;

use crate::chain_builder::{BlockPlan, ChainBuilder, SpendableCoin, TxPlan};
use crate::error::SimError;
use crate::keys::Lock;
use crate::scenarios::{Verdict, judge};

/// Two transactions, both spending `coin`, in one block.
///
/// # Errors
///
/// [`SimError`] if the fixture cannot be built.
pub fn double_spend_across_transactions(
    chain: &mut ChainBuilder,
    coin: SpendableCoin,
) -> Result<Verdict, SimError> {
    let first = chain.build_tx(&TxPlan::sweep(
        vec![coin.clone()],
        Lock::P2pkh { key: 1 },
        Amount::from_grains(1_000),
    ))?;
    let second = chain.build_tx(&TxPlan::sweep(
        vec![coin],
        Lock::P2pkh { key: 2 },
        Amount::from_grains(2_000),
    ))?;
    let ctx = chain.next_ctx()?;
    let pre = chain.state_view();
    let block =
        chain.build_block(&BlockPlan { txs: vec![first, second], ..BlockPlan::default() })?;
    judge(&pre, &block, &ctx)
}

/// One transaction naming `coin` twice.
///
/// # Errors
///
/// [`SimError`] if the fixture cannot be built.
pub fn double_spend_within_one_transaction(
    chain: &mut ChainBuilder,
    coin: SpendableCoin,
) -> Result<Verdict, SimError> {
    let plan = TxPlan {
        inputs: vec![coin.clone(), coin.clone()],
        outputs: vec![(Lock::P2pkh { key: 3 }, coin.coin.value)],
        ..TxPlan::default()
    };
    let tx = chain.build_tx(&plan)?;
    let ctx = chain.next_ctx()?;
    let pre = chain.state_view();
    let block = chain.build_block(&BlockPlan { txs: vec![tx], ..BlockPlan::default() })?;
    judge(&pre, &block, &ctx)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_chain::ValidationError;

    use super::*;
    use crate::scenarios::matured_chain;

    fn chain_with_two_coins() -> (ChainBuilder, Vec<SpendableCoin>) {
        let mut chain = matured_chain(21, 4).unwrap();
        let height = chain.height() + 1;
        let coins = chain.take_mature(2, height);
        assert_eq!(coins.len(), 2);
        (chain, coins)
    }

    // ---- red -----------------------------------------------------------

    #[test]
    fn the_second_spender_in_a_block_finds_nothing_to_spend() {
        let (mut chain, coins) = chain_with_two_coins();
        let coin = coins[0].clone();
        let verdict = double_spend_across_transactions(&mut chain, coin.clone()).unwrap();
        match verdict.rejection() {
            Some(ValidationError::MissingInput { tx_index, out_point }) => {
                assert_eq!(*tx_index, 2, "the *second* spender is the one that fails");
                assert_eq!(*out_point, coin.out_point);
            }
            other => panic!("expected MissingInput, got {other:?}"),
        }
    }

    #[test]
    fn one_transaction_may_not_name_the_same_outpoint_twice() {
        let (mut chain, coins) = chain_with_two_coins();
        let coin = coins[0].clone();
        let verdict = double_spend_within_one_transaction(&mut chain, coin.clone()).unwrap();
        match verdict.rejection() {
            Some(ValidationError::DuplicateInput { out_point }) => {
                assert_eq!(*out_point, coin.out_point);
            }
            other => panic!("expected DuplicateInput, got {other:?}"),
        }
    }

    #[test]
    fn a_coin_spent_by_an_earlier_block_cannot_be_spent_again() {
        let (mut chain, coins) = chain_with_two_coins();
        let coin = coins[0].clone();
        let first = chain
            .build_tx(&TxPlan::sweep(
                vec![coin.clone()],
                Lock::P2pkh { key: 4 },
                Amount::from_grains(1_000),
            ))
            .unwrap();
        chain.mine(vec![first]).unwrap();

        // The same coin, one block later.
        let again = chain
            .build_tx(&TxPlan::sweep(
                vec![coin.clone()],
                Lock::P2pkh { key: 5 },
                Amount::from_grains(1_000),
            ))
            .unwrap();
        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        let block =
            chain.build_block(&BlockPlan { txs: vec![again], ..BlockPlan::default() }).unwrap();
        match judge(&pre, &block, &ctx).unwrap().rejection() {
            Some(ValidationError::MissingInput { tx_index, out_point }) => {
                assert_eq!(*tx_index, 1);
                assert_eq!(*out_point, coin.out_point);
            }
            other => panic!("expected MissingInput, got {other:?}"),
        }
    }

    // ---- green ---------------------------------------------------------

    #[test]
    fn two_transactions_spending_two_different_coins_are_accepted() {
        let (mut chain, coins) = chain_with_two_coins();
        let first = chain
            .build_tx(&TxPlan::sweep(
                vec![coins[0].clone()],
                Lock::P2pkh { key: 1 },
                Amount::from_grains(1_000),
            ))
            .unwrap();
        let second = chain
            .build_tx(&TxPlan::sweep(
                vec![coins[1].clone()],
                Lock::P2pkh { key: 2 },
                Amount::from_grains(2_000),
            ))
            .unwrap();
        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        let block = chain
            .build_block(&BlockPlan { txs: vec![first, second], ..BlockPlan::default() })
            .unwrap();
        let verdict = judge(&pre, &block, &ctx).unwrap();
        let diff = verdict.diff().expect("two independent spends are valid");
        assert_eq!(diff.spent.len(), 2);
        assert_eq!(diff.spent[0].0, coins[0].out_point);
        assert_eq!(diff.spent[1].0, coins[1].out_point);
    }

    #[test]
    fn a_transaction_may_spend_an_output_created_earlier_in_the_same_block() {
        // The overlay learns about an output as soon as its transaction is
        // committed, so a chain of spends inside one block is legal — but only
        // in that direction (SPEC §3.3 rule 12).
        let (mut chain, coins) = chain_with_two_coins();
        let value = coins[0].coin.value;
        let parent = chain
            .build_tx(&TxPlan {
                inputs: vec![coins[0].clone()],
                outputs: vec![(Lock::Anyone, value.saturating_sub(Amount::from_grains(1_000)))],
                ..TxPlan::default()
            })
            .unwrap();
        let parent_out = ferrum_types::OutPoint::new(ChainBuilder::txid_of(&parent), 0);
        let child_input = SpendableCoin {
            out_point: parent_out,
            coin: ferrum_types::Coin {
                value: value.saturating_sub(Amount::from_grains(1_000)),
                script_pubkey: Lock::Anyone.script_pubkey(chain.keys()).unwrap(),
                height: chain.height() + 1,
                is_coinbase: false,
            },
            lock: Lock::Anyone,
        };
        let child = chain
            .build_tx(&TxPlan::sweep(
                vec![child_input],
                Lock::P2pkh { key: 6 },
                Amount::from_grains(1_000),
            ))
            .unwrap();

        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        let good = chain
            .build_block(&BlockPlan {
                txs: vec![parent.clone(), child.clone()],
                ..BlockPlan::default()
            })
            .unwrap();
        assert!(judge(&pre, &good, &ctx).unwrap().is_accepted());

        // Reversed, the child names an output that does not exist yet.
        let bad = chain
            .build_block(&BlockPlan { txs: vec![child, parent], ..BlockPlan::default() })
            .unwrap();
        assert!(matches!(
            judge(&pre, &bad, &ctx).unwrap().rejection(),
            Some(ValidationError::MissingInput { tx_index: 1, .. })
        ));
    }
}
