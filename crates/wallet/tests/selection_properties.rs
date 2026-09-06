//! Property tests for coin selection and fee estimation.
//!
//! The three invariants CONTRACT §12 turns on, stated once and checked over
//! thousands of random pools:
//!
//! 1. **Selection never overspends.** Every grain of input is accounted for as
//!    output, change or fee — a selection that "loses" value silently burns
//!    the user's coins, and one that gains value would be an inflation bug if
//!    the same arithmetic ever appeared in the validator.
//! 2. **Selection always covers `target + fee`.** A selection that comes up
//!    short produces a transaction that fails validation, which the wallet
//!    only discovers after broadcasting it.
//! 3. **The realised fee rate is never below the requested one.** Underpaying
//!    is the silent failure: the transaction is valid, it is simply never
//!    mined.
//!
//! Plus the one that makes 3 true in practice: **the size estimated before
//! signing equals the size measured after signing, exactly.**

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use ferrum_crypto::{Address, Mnemonic};
use ferrum_script::sighash::SigHashType;
use ferrum_types::{Amount, ChainId, Coin, Network, OutPoint, Script, Transaction, Txid};
use ferrum_wallet::{
    BuildParams, Candidate, FeeRate, HdKeychain, P2PKH_INPUT_BYTES, P2PKH_OUTPUT_BYTES,
    SelectionParams, SendRequest, TX_OVERHEAD_BYTES, estimate_signed_size, plan_transaction,
    select_coins, sign_transaction, verify_signed,
};
use proptest::prelude::*;

const DUST: Amount = Amount::from_grains(3_000);

fn keychain() -> HdKeychain {
    let mnemonic = Mnemonic::from_entropy(&[0x7bu8; 32]).unwrap();
    HdKeychain::from_mnemonic(&mnemonic, "", Network::Devnet).unwrap()
}

fn address(index: u32) -> Address {
    keychain().address(0, 0, index).unwrap()
}

fn coin(value: u64, index: u32) -> Coin {
    Coin {
        value: Amount::from_grains(value),
        script_pubkey: address(index).script_pubkey(),
        height: 1,
        is_coinbase: false,
    }
}

fn out_point(n: u32) -> OutPoint {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    OutPoint::new(Txid::from_bytes(bytes), 0)
}

fn selection_params(fee_rate: u64) -> SelectionParams {
    SelectionParams {
        fee_rate: FeeRate::from_per_kb(fee_rate).unwrap(),
        dust_threshold: DUST,
        base_size: TX_OVERHEAD_BYTES + P2PKH_OUTPUT_BYTES,
        change_output_size: P2PKH_OUTPUT_BYTES,
        change_spend_size: P2PKH_INPUT_BYTES,
    }
}

fn candidates(values: &[u64], fee_rate: u64) -> Vec<Candidate> {
    let rate = FeeRate::from_per_kb(fee_rate).unwrap();
    values
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            Candidate::price(out_point(i as u32), coin(*v, 0), rate).ok().flatten()
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Money in equals money out: `inputs == outputs + change + fee`.
    #[test]
    fn selection_conserves_value(
        values in prop::collection::vec(1_000u64..50_000_000, 1..12),
        target in 5_000u64..40_000_000,
        fee_rate in 1u64..20_000,
    ) {
        let pool = candidates(&values, fee_rate);
        let params = selection_params(fee_rate);
        if let Ok(selection) = select_coins(&pool, Amount::from_grains(target), &params) {
            let change = selection.change.unwrap_or(Amount::ZERO).to_grains();
            prop_assert_eq!(
                selection.input_total.to_grains(),
                target + change + selection.fee.to_grains(),
            );
        }
    }

    /// A selection always covers the target plus the fee it charges.
    #[test]
    fn selection_covers_target_plus_fee(
        values in prop::collection::vec(1_000u64..50_000_000, 1..12),
        target in 5_000u64..40_000_000,
        fee_rate in 1u64..20_000,
    ) {
        let pool = candidates(&values, fee_rate);
        let params = selection_params(fee_rate);
        if let Ok(selection) = select_coins(&pool, Amount::from_grains(target), &params) {
            prop_assert!(
                selection.input_total.to_grains() >= target + selection.fee.to_grains(),
            );
        }
    }

    /// The realised fee rate is at least the requested one.
    #[test]
    fn selection_never_underpays_the_fee_rate(
        values in prop::collection::vec(1_000u64..50_000_000, 1..12),
        target in 5_000u64..40_000_000,
        fee_rate in 1u64..20_000,
    ) {
        let pool = candidates(&values, fee_rate);
        let params = selection_params(fee_rate);
        if let Ok(selection) = select_coins(&pool, Amount::from_grains(target), &params) {
            prop_assert!(
                selection.fee_rate() >= fee_rate,
                "requested {} realised {}", fee_rate, selection.fee_rate(),
            );
        }
    }

    /// Nothing is selected twice, and nothing is selected that was not offered.
    #[test]
    fn selection_is_a_subset_without_duplicates(
        values in prop::collection::vec(1_000u64..50_000_000, 1..12),
        target in 5_000u64..40_000_000,
        fee_rate in 1u64..20_000,
    ) {
        let pool = candidates(&values, fee_rate);
        let params = selection_params(fee_rate);
        if let Ok(selection) = select_coins(&pool, Amount::from_grains(target), &params) {
            let offered: std::collections::BTreeSet<OutPoint> =
                pool.iter().map(|c| c.out_point).collect();
            let mut seen = std::collections::BTreeSet::new();
            for (op, _) in &selection.inputs {
                prop_assert!(offered.contains(op), "selected a coin that was not offered");
                prop_assert!(seen.insert(*op), "selected the same coin twice");
            }
        }
    }

    /// Change is either absent or worth having: never dust.
    #[test]
    fn selection_never_creates_dust_change(
        values in prop::collection::vec(1_000u64..50_000_000, 1..12),
        target in 5_000u64..40_000_000,
        fee_rate in 1u64..20_000,
    ) {
        let pool = candidates(&values, fee_rate);
        let params = selection_params(fee_rate);
        if let Ok(selection) = select_coins(&pool, Amount::from_grains(target), &params)
            && let Some(change) = selection.change
        {
            prop_assert!(change >= DUST, "created {} grains of dust", change.to_grains());
        }
    }

    /// Selecting twice from the same pool gives the same answer.
    #[test]
    fn selection_is_deterministic(
        values in prop::collection::vec(1_000u64..50_000_000, 1..12),
        target in 5_000u64..40_000_000,
        fee_rate in 1u64..20_000,
    ) {
        let pool = candidates(&values, fee_rate);
        let params = selection_params(fee_rate);
        let a = select_coins(&pool, Amount::from_grains(target), &params);
        let b = select_coins(&pool, Amount::from_grains(target), &params);
        prop_assert_eq!(a.is_ok(), b.is_ok());
        if let (Ok(a), Ok(b)) = (a, b) {
            prop_assert_eq!(a, b);
        }
    }

    /// A pool that cannot reach the target reports insufficient funds rather
    /// than building something short.
    #[test]
    fn an_unreachable_target_is_always_an_error(
        values in prop::collection::vec(1_000u64..100_000, 1..8),
        fee_rate in 1u64..5_000,
    ) {
        let pool = candidates(&values, fee_rate);
        let total: u64 = pool.iter().map(|c| c.coin.value.to_grains()).sum();
        let params = selection_params(fee_rate);
        let result = select_coins(&pool, Amount::from_grains(total + 1), &params);
        prop_assert!(result.is_err());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The whole build path: plan, sign, and check every invariant on the
    /// finished transaction.
    #[test]
    fn a_built_and_signed_transaction_holds_every_invariant(
        values in prop::collection::vec(200_000u64..50_000_000, 1..8),
        target in 10_000u64..40_000_000,
        fee_rate in 1u64..10_000,
    ) {
        let chain = keychain();
        let pool: Vec<(OutPoint, Coin)> = values
            .iter()
            .enumerate()
            .map(|(i, v)| (out_point(i as u32), coin(*v, i as u32 % 4)))
            .collect();
        let req = SendRequest::to(address(31), Amount::from_grains(target), fee_rate);
        let params = BuildParams::at_tip(DUST, 500);
        let Ok(mut plan) = plan_transaction(&pool, &req, &address(30), &params) else {
            return Ok(());
        };

        // Money is conserved.
        let input_total: u64 = plan.selected.iter().map(|(_, c)| c.value.to_grains()).sum();
        let output_total = plan.tx.total_output().unwrap().to_grains();
        prop_assert_eq!(input_total, output_total + plan.fee.to_grains());

        // No dust was created.
        for output in &plan.tx.outputs {
            prop_assert!(output.value >= DUST);
        }

        // The estimate matches the skeleton the planner produced.
        prop_assert_eq!(
            plan.estimated_size,
            estimate_signed_size(&plan.tx, &plan.prevouts()).unwrap(),
        );

        // Sign, then confirm the estimate was exact and the transaction is valid.
        let prevouts = plan.prevouts();
        sign_transaction(
            &mut plan.tx,
            &prevouts,
            ChainId::DEVNET,
            SigHashType::ALL,
            |script: &Script| {
                (0..4u32)
                    .filter_map(|i| chain.receive(0, i).ok())
                    .find(|k| &k.script_pubkey() == script)
                    .map(|k| k.secret_key().clone())
            },
        )
        .unwrap();
        prop_assert_eq!(plan.tx.serialized_size(), plan.estimated_size);
        prop_assert!(verify_signed(&plan.tx, &prevouts, ChainId::DEVNET).is_ok());

        // And it pays at least what was asked for.
        prop_assert!(
            FeeRate::of(plan.fee, plan.tx.serialized_size()) >= fee_rate,
            "requested {} realised {}",
            fee_rate,
            FeeRate::of(plan.fee, plan.tx.serialized_size()),
        );
    }

    /// The size model has no drift on any shape of transaction.
    ///
    /// This is the test that catches a change to the signature or public-key
    /// encoding: a wallet whose estimate is one byte short underpays every
    /// transaction it ever builds, and nothing else fails.
    #[test]
    fn the_size_estimate_never_drifts(
        inputs in 1usize..8,
        outputs in 1usize..8,
    ) {
        let chain = keychain();
        let keys: Vec<_> = (0..inputs).map(|i| chain.receive(0, i as u32).unwrap()).collect();
        let prevouts: Vec<Coin> = keys
            .iter()
            .map(|k| Coin {
                value: Amount::from_grains(10_000_000),
                script_pubkey: k.script_pubkey(),
                height: 1,
                is_coinbase: false,
            })
            .collect();
        let mut tx = Transaction {
            version: 1,
            inputs: (0..inputs)
                .map(|i| ferrum_types::TxIn {
                    prev_out: out_point(i as u32),
                    script_sig: Script::EMPTY,
                    sequence: 0xffff_fffe,
                })
                .collect(),
            outputs: (0..outputs)
                .map(|i| ferrum_types::TxOut {
                    value: Amount::from_grains(1_000_000),
                    script_pubkey: address(100 + i as u32).script_pubkey(),
                })
                .collect(),
            lock_time: 0,
        };

        let estimated = estimate_signed_size(&tx, &prevouts).unwrap();
        sign_transaction(
            &mut tx,
            &prevouts,
            ChainId::DEVNET,
            SigHashType::ALL,
            |script: &Script| {
                keys.iter()
                    .find(|k| &k.script_pubkey() == script)
                    .map(|k| k.secret_key().clone())
            },
        )
        .unwrap();
        prop_assert_eq!(tx.serialized_size(), estimated);
    }
}
