//! The differential test: two executors, every block, no disagreement.
//!
//! `ferrum_chain::apply_block` is the production state transition.
//! `ferrum_sim::apply_block_reference` is a second implementation written from
//! `docs/SPEC.md` alone. This test runs both over several hundred generated
//! blocks and requires that they agree on:
//!
//! * whether the block is valid at all;
//! * **which** rule an invalid block breaks — the exact
//!   [`ValidationError`](ferrum_chain::ValidationError) variant, not merely
//!   that something failed;
//! * the [`StateDiff`](ferrum_storage::StateDiff) a valid block produces, in
//!   order; and
//! * the UTXO-set state root the diff leads to.
//!
//! This is the project's substitute for an audit (CONTRACT §14). A test that
//! only compared `is_ok()` would pass while the two implementations rejected a
//! block for opposite reasons, which is exactly the failure a differential test
//! exists to find.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use ferrum_chain::{BlockCtx, ValidationError, apply_block};
use ferrum_sim::chain_builder::{BlockPlan, ChainBuilder, TxPlan};
use ferrum_sim::mutate::invalid_variants;
use ferrum_sim::{Lock, SimError, XorShift64, apply_block_reference};
use ferrum_storage::{MapView, StateDiff};
use ferrum_types::{Amount, Block, Coin, Hash32, OutPoint, Transaction};

/// How many blocks the main differential sweep covers.
///
/// Past `coinbase_maturity` by a wide margin, so the tail of the run is real
/// spending rather than a hundred empty blocks.
const BLOCKS: usize = 320;

/// The height at which the sweep starts building invalid variants.
///
/// Below `coinbase_maturity` there is nothing to spend, so the state-context
/// mutations would all collapse into the same shape.
const MUTATION_START: u64 = 100;

/// Apply `diff` to a copy of `pre` and hash the result.
fn root_after(pre: &BTreeMap<OutPoint, Coin>, diff: &StateDiff) -> Hash32 {
    let mut post = pre.clone();
    for (op, _) in &diff.spent {
        post.remove(op);
    }
    for (op, coin) in &diff.created {
        post.insert(*op, coin.clone());
    }
    ferrum_storage::state_root_of(post.iter()).unwrap()
}

/// Compare both executors on one block, returning the production verdict.
fn agree(
    pre_map: &BTreeMap<OutPoint, Coin>,
    block: &Block,
    ctx: &BlockCtx,
    what: &str,
) -> Result<StateDiff, ValidationError> {
    let pre: MapView = pre_map.iter().map(|(op, coin)| (*op, coin.clone())).collect();
    let production = apply_block(&pre, block, ctx);
    let reference = apply_block_reference(&pre, block, ctx);

    match (&production, &reference) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a, b, "diffs differ at height {}: {what}", ctx.height);
            assert_eq!(
                root_after(pre_map, a),
                root_after(pre_map, b),
                "state roots differ at height {}: {what}",
                ctx.height
            );
        }
        (Err(a), Err(b)) => {
            assert_eq!(
                a, b,
                "the two executors reject for different reasons at height {}: {what}",
                ctx.height
            );
        }
        (Ok(_), Err(e)) => panic!(
            "production accepted but the reference rejected with {e} at height {}: {what}",
            ctx.height
        ),
        (Err(e), Ok(_)) => panic!(
            "the reference accepted but production rejected with {e} at height {}: {what}",
            ctx.height
        ),
    }
    production
}

/// Build the transactions for one block of the sweep.
///
/// The mix is deliberate: multi-input sweeps exercise the input-sum rules,
/// bare and P2SH multisig exercise `OP_CHECKMULTISIG` and the redeem-script
/// path, and an absolute timelock exercises `OP_CHECKLOCKTIMEVERIFY` together
/// with the block-level finality rule.
fn workload(
    chain: &mut ChainBuilder,
    rng: &mut XorShift64,
    height: u64,
) -> Result<Vec<Transaction>, SimError> {
    if chain.mature(height).is_empty() {
        return Ok(Vec::new());
    }
    let mut txs = Vec::new();
    let batches = rng.range(1, 3);
    for _ in 0..batches {
        let want = usize::try_from(rng.range(1, 3)).unwrap_or(1);
        let coins = chain.take_mature(want, height);
        if coins.is_empty() {
            break;
        }
        let total = coins.iter().fold(Amount::ZERO, |a, c| a.saturating_add(c.coin.value));
        let fee = Amount::from_grains(rng.range(500, 25_000));
        let payable = total.saturating_sub(fee);
        if payable.is_zero() {
            break;
        }
        let mut plan = match rng.below(6) {
            0 => TxPlan::sweep(coins, Lock::P2pkh { key: 1 }, fee),
            1 => TxPlan::sweep(coins, Lock::P2pk { key: 2 }, fee),
            2 => TxPlan::sweep(coins, Lock::Multisig { k: 2, keys: vec![3, 4, 5] }, fee),
            3 => TxPlan::sweep(coins, Lock::P2shMultisig { k: 3, keys: vec![5, 6, 7, 8] }, fee),
            4 => {
                let locktime = u32::try_from(height.saturating_sub(2)).unwrap_or(0);
                TxPlan::sweep(coins, Lock::CltvP2pkh { key: 9, locktime }, fee)
            }
            _ => {
                let half = payable.checked_div_u64(2).unwrap_or(Amount::ZERO);
                TxPlan {
                    inputs: coins,
                    outputs: vec![
                        (Lock::P2pkh { key: 10 }, half),
                        (Lock::P2pkh { key: 11 }, payable.saturating_sub(half)),
                    ],
                    ..TxPlan::default()
                }
            }
        };
        // A transaction spending a CLTV output must carry a `lock_time` that
        // has reached the script's, and the block must be at least that high.
        if let Some(required) = plan
            .inputs
            .iter()
            .filter_map(|c| match c.lock {
                Lock::CltvP2pkh { locktime, .. } => Some(locktime),
                _ => None,
            })
            .max()
        {
            plan.lock_time = required.max(u32::try_from(height.saturating_sub(1)).unwrap_or(0));
        }
        txs.push(chain.build_tx(&plan)?);
    }
    Ok(txs)
}

#[test]
fn the_two_executors_agree_on_every_block() {
    let mut chain = ChainBuilder::devnet(XorShift64::SCENARIO_SEED).unwrap();
    let mut rng = XorShift64::new(0xd1ff_e2e0_0000_0001);
    let mut valid_blocks = 0usize;
    let mut invalid_blocks = 0usize;
    let mut variants_seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    // Genesis itself goes through both executors.
    let genesis = chain.blocks().first().cloned().unwrap();
    let genesis_ctx = chain.ctx_for(0, &genesis.header).unwrap();
    agree(&BTreeMap::new(), &genesis, &genesis_ctx, "genesis").unwrap();

    while chain.blocks().len() < BLOCKS {
        let height = chain.height().saturating_add(1);
        let ctx = chain.next_ctx().unwrap();
        let pre = chain.utxo().clone();

        if height >= MUTATION_START {
            for mutation in invalid_variants(&mut chain, &ctx).unwrap() {
                let verdict = agree(&pre, &mutation.block, &ctx, mutation.name);
                assert!(
                    verdict.is_err(),
                    "a block that breaks '{}' was accepted at height {height}",
                    mutation.name
                );
                if let Err(e) = verdict {
                    variants_seen.insert(variant_name(&e).to_owned());
                }
                invalid_blocks += 1;
            }
        }

        let txs = workload(&mut chain, &mut rng, height).unwrap();
        let block = chain.build_block(&BlockPlan::with_txs(txs)).unwrap();
        let diff = agree(&pre, &block, &ctx, "the honest block").expect("honest block must apply");
        assert_eq!(
            diff.created.len(),
            block.txs.iter().map(|t| t.outputs.len()).sum::<usize>(),
            "every output must appear in the diff"
        );
        chain.connect(&block);
        valid_blocks += 1;
    }

    assert_eq!(valid_blocks, BLOCKS - 1);
    assert!(invalid_blocks > 200, "expected a broad invalid sweep, saw {invalid_blocks}");
    assert!(
        variants_seen.len() >= 15,
        "the sweep must reach many distinct rules, saw {variants_seen:?}"
    );
}

/// The name of a [`ValidationError`] variant, for coverage bookkeeping.
fn variant_name(e: &ValidationError) -> &'static str {
    match e {
        ValidationError::BlockTooLarge { .. } => "BlockTooLarge",
        ValidationError::EmptyBlock => "EmptyBlock",
        ValidationError::MissingCoinbase => "MissingCoinbase",
        ValidationError::MultipleCoinbases { .. } => "MultipleCoinbases",
        ValidationError::MerkleRootMismatch { .. } => "MerkleRootMismatch",
        ValidationError::DuplicateTransaction { .. } => "DuplicateTransaction",
        ValidationError::NoInputs => "NoInputs",
        ValidationError::NoOutputs => "NoOutputs",
        ValidationError::OutputValueOutOfRange { .. } => "OutputValueOutOfRange",
        ValidationError::OutputSumOverflow => "OutputSumOverflow",
        ValidationError::DuplicateInput { .. } => "DuplicateInput",
        ValidationError::ScriptTooLarge { .. } => "ScriptTooLarge",
        ValidationError::CoinbaseInputCount { .. } => "CoinbaseInputCount",
        ValidationError::CoinbaseInputNotNull => "CoinbaseInputNotNull",
        ValidationError::NullInput { .. } => "NullInput",
        ValidationError::Header(_) => "Header",
        ValidationError::Seal(_) => "Seal",
        ValidationError::MissingInput { .. } => "MissingInput",
        ValidationError::ImmatureCoinbaseSpend { .. } => "ImmatureCoinbaseSpend",
        ValidationError::InputSumOverflow { .. } => "InputSumOverflow",
        ValidationError::InsufficientInputValue { .. } => "InsufficientInputValue",
        ValidationError::FeeOverflow => "FeeOverflow",
        ValidationError::NonFinalTransaction { .. } => "NonFinalTransaction",
        ValidationError::ScriptVerification { .. } => "ScriptVerification",
        ValidationError::CoinbaseScriptSigLength { .. } => "CoinbaseScriptSigLength",
        ValidationError::CoinbaseMissingHeightPush => "CoinbaseMissingHeightPush",
        ValidationError::CoinbaseHeightMismatch { .. } => "CoinbaseHeightMismatch",
        ValidationError::CoinbaseOverpayment { .. } => "CoinbaseOverpayment",
        ValidationError::CoinbaseAllowanceOverflow => "CoinbaseAllowanceOverflow",
        ValidationError::DuplicateOutPoint { .. } => "DuplicateOutPoint",
        ValidationError::View { .. } => "View",
        ValidationError::Arithmetic(_) => "Arithmetic",
        _ => "unknown",
    }
}

/// Blocks that break **two** rules at once, to pin the order the rules are
/// checked in.
///
/// SPEC §3 fixes an order and §3.4 requires tests to assert the exact variant,
/// so ordering is observable behaviour rather than an implementation detail.
/// Two places in the documents leave it under-determined — SPEC §3.1 rule 5
/// checks transaction sanity before the header rules while CONTRACT §8.1 lists
/// the header rules first, and the two documents state the coinbase's value
/// and BIP-34 rules in opposite orders. A block that breaks only one rule
/// cannot tell the readings apart; these can, and both executors must still
/// agree.
#[test]
fn the_two_executors_agree_on_the_order_rules_are_checked_in() {
    let mut chain = ChainBuilder::devnet(0x0dde_0000_0000_0001).unwrap();
    chain.advance(103).unwrap();
    let ctx = chain.next_ctx().unwrap();
    let pre = chain.utxo().clone();
    let height = ctx.height;

    // A bad header version *and* a transaction with no outputs. Transaction
    // sanity is a context-free rule, so it must win.
    let block = chain
        .build_block(&BlockPlan {
            version: Some(0),
            txs: vec![Transaction {
                version: 1,
                inputs: vec![ferrum_types::TxIn::new(
                    OutPoint::new(ferrum_types::Txid::ZERO, 3),
                    ferrum_types::Script::EMPTY,
                )],
                outputs: Vec::new(),
                lock_time: 0,
            }],
            ..BlockPlan::default()
        })
        .unwrap();
    let verdict = agree(&pre, &block, &ctx, "bad version and an output-less transaction");
    assert_eq!(verdict, Err(ValidationError::NoOutputs));

    // A bad header version *and* a coinbase whose `script_sig` is too short.
    // The coinbase's BIP-34 rules are state-context rules, so the header wins.
    let block = chain
        .build_block(&BlockPlan {
            version: Some(0),
            coinbase: Some(Transaction {
                version: 1,
                inputs: vec![ferrum_types::TxIn::coinbase(ferrum_types::Script::new(vec![0x00]))],
                outputs: vec![ferrum_types::TxOut::new(
                    Amount::ZERO,
                    ferrum_types::Script::new(vec![0x51]),
                )],
                lock_time: 0,
            }),
            ..BlockPlan::default()
        })
        .unwrap();
    let verdict = agree(&pre, &block, &ctx, "bad version and a short coinbase script_sig");
    assert!(matches!(verdict, Err(ValidationError::Header(_))), "got {verdict:?}");

    // A coinbase that both overpays and commits to the wrong height: the
    // structural rule is cheaper, so it is checked first.
    let block = chain
        .build_block(&BlockPlan {
            coinbase_bonus: 1,
            height: Some(height - 1),
            ..BlockPlan::default()
        })
        .unwrap();
    let verdict = agree(&pre, &block, &ctx, "an overpaying coinbase at the wrong height");
    assert!(
        matches!(verdict, Err(ValidationError::CoinbaseHeightMismatch { .. })),
        "got {verdict:?}"
    );

    // An immature coinbase spend whose signature is also corrupt: maturity is
    // checked for every input before any script runs.
    let young = chain
        .spendable()
        .iter()
        .rev()
        .find(|c| c.coin.is_coinbase && !c.is_mature(height, chain.params().coinbase_maturity))
        .cloned()
        .expect("the most recent coinbase is immature");
    let mut tx = chain
        .build_tx(&TxPlan::sweep(vec![young], Lock::P2pkh { key: 4 }, Amount::from_grains(1_000)))
        .unwrap();
    let mut bytes = tx.inputs[0].script_sig.as_bytes().to_vec();
    bytes[1] ^= 0x01;
    tx.inputs[0].script_sig = ferrum_types::Script::new(bytes);
    let block = chain.build_block(&BlockPlan { txs: vec![tx], ..BlockPlan::default() }).unwrap();
    let verdict = agree(&pre, &block, &ctx, "an immature spend with a corrupt signature");
    assert!(
        matches!(verdict, Err(ValidationError::ImmatureCoinbaseSpend { .. })),
        "got {verdict:?}"
    );

    // A transaction that both overpays its inputs and is not final: the value
    // rule is checked before finality.
    let coin = chain.mature(height).first().cloned().expect("a mature coin");
    let tx = chain
        .build_tx(&TxPlan {
            inputs: vec![coin.clone()],
            outputs: vec![(
                Lock::P2pkh { key: 6 },
                coin.coin.value.checked_add(Amount::from_grains(1)).unwrap(),
            )],
            lock_time: u32::try_from(height + 50).unwrap(),
            ..TxPlan::default()
        })
        .unwrap();
    let block = chain.build_block(&BlockPlan { txs: vec![tx], ..BlockPlan::default() }).unwrap();
    let verdict = agree(&pre, &block, &ctx, "an inflating, non-final transaction");
    assert!(
        matches!(verdict, Err(ValidationError::InsufficientInputValue { .. })),
        "got {verdict:?}"
    );
}

#[test]
fn the_two_executors_agree_on_a_chain_replayed_from_scratch() {
    // A second, independent seed, so the sweep above is not the only shape the
    // reference has ever seen.
    let chain = ferrum_sim::RecordedChain::generate(0x5eed_0002, 130).unwrap();
    let production = chain.state_roots(apply_block).unwrap();
    let reference = chain.state_roots(apply_block_reference).unwrap();
    assert_eq!(production, reference);
    assert_eq!(production.len(), chain.len());
}

#[test]
fn the_reference_reproduces_the_diff_order_production_promises() {
    let mut chain = ChainBuilder::devnet(4242).unwrap();
    chain.advance(103).unwrap();
    let height = chain.height() + 1;
    let coins = chain.take_mature(3, height);
    assert_eq!(coins.len(), 3);
    let tx = chain
        .build_tx(&TxPlan::sweep(coins, Lock::P2pkh { key: 2 }, Amount::from_grains(3_000)))
        .unwrap();
    let ctx = chain.next_ctx().unwrap();
    let pre = chain.utxo().clone();
    let block = chain.build_block(&BlockPlan::with_txs(vec![tx])).unwrap();

    let diff = agree(&pre, &block, &ctx, "a three-input sweep").unwrap();
    // `spent` is in input order and `created` in (tx index, vout) order; the
    // undo record depends on both.
    assert_eq!(diff.spent.len(), 3);
    assert_eq!(diff.created.len(), 2);
    assert!(diff.created[0].1.is_coinbase, "the coinbase output comes first");
    assert!(!diff.created[1].1.is_coinbase, "then the payment output");
}
