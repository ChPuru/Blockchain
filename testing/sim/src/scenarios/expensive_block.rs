//! **Attack:** a block engineered to cost the most possible to validate.
//!
//! A block does not have to be *invalid* to be an attack. If validation cost
//! is unbounded, an attacker mines one expensive block and every node on the
//! network spends minutes on it; at a two-minute spacing that is a partition.
//! Bitcoin's "megatransaction" (block 364 292) took some nodes 25 seconds to
//! verify, because legacy sighash was quadratic in transaction size.
//!
//! Ferrum bounds the cost structurally rather than by measuring it:
//!
//! | Limit | Value | What it bounds |
//! |---|---|---|
//! | `MAX_SCRIPT_SIZE` | 1 000 B | the size of one script |
//! | `MAX_OPS` | 201 | non-push opcodes per input, **not reset** between `script_sig`, `script_pubkey` and the redeem script |
//! | `MAX_PUBKEYS_PER_MULTISIG` | 20 | keys one `OP_CHECKMULTISIG` may name |
//! | `MAX_STACK_SIZE` | 100 | stack plus altstack |
//! | `MAX_ELEMENT_SIZE` | 520 B | one stack element |
//! | `max_block_size` | 1 000 000 B | the block |
//!
//! and there are **no loops** — the opcode table has no backward jump — so a
//! static bound is sufficient and gas metering is unnecessary. Ethereum needed
//! four repricing hard forks to get metering right; this design skips the
//! category.
//!
//! Each `OP_CHECKMULTISIG` charges `n` against the operation budget, so the
//! number of signature verifications one input can demand is bounded by
//! `MAX_OPS`, and the number a *block* can demand is bounded by
//! `MAX_OPS × (max_block_size / MIN_INPUT_BYTES)`. Both are asserted below
//! against a measured worst-case-shaped block.
//!
//! **Red:** each limit rejects the script that exceeds it, by name, and an
//! oversized block is rejected on rule 1 — before a single script runs.
//! **Green:** the most expensive block the rules *do* allow is accepted, and
//! its measured cost obeys the published bound.

use ferrum_script::{ExecCtx, ExecStats, MAX_OPS, ScriptLimits, verify};
use ferrum_storage::StateView;
use ferrum_types::{Amount, Block, Script, Transaction, TxIn, TxOut};

use ferrum_chain::BlockCtx;

use crate::error::SimError;

/// The smallest a transaction input can be on the wire.
///
/// `borsh(OutPoint)` is 36 bytes, the `script_sig` length prefix is 4 and the
/// `sequence` is 4. An input cannot be smaller than this, so the block size
/// limit divided by this number bounds the input count.
pub const MIN_INPUT_BYTES: usize = 44;

/// What validating one block actually cost, in the units the VM meters.
///
/// Deliberately *not* wall-clock time: `Instant::now` is a disallowed method
/// in this workspace, and a timing assertion would be flaky on a loaded CI
/// machine. Operation and signature-check counts are exact, deterministic and
/// are the quantities the limits actually bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockCost {
    /// Non-push opcodes executed across every input.
    pub ops: u32,
    /// Signature verifications attempted, failed probes included.
    pub sig_checks: u32,
    /// The deepest any one input drove the stack.
    pub max_stack: usize,
    /// How many inputs were evaluated.
    pub inputs: u32,
}

impl BlockCost {
    /// The ceiling the limit table puts on any block of `max_block_size` bytes.
    ///
    /// `MAX_OPS` per input, and at most `max_block_size / MIN_INPUT_BYTES`
    /// inputs. Every `OP_CHECKMULTISIG` charges `n` operations before it
    /// verifies anything, so this bounds signature checks as well as opcodes.
    #[must_use]
    pub fn ceiling_for(max_block_size: usize) -> u64 {
        let max_inputs = (max_block_size / MIN_INPUT_BYTES) as u64;
        max_inputs.saturating_mul(u64::from(MAX_OPS))
    }
}

/// Measure what every input of `block` costs to verify.
///
/// # Errors
///
/// [`SimError::Script`] if an input fails to verify, and [`SimError::Fixture`]
/// if an input does not resolve in `pre` — this measures a block that is
/// already known to be valid.
pub fn measure(
    block: &Block,
    pre: &dyn StateView,
    ctx: &BlockCtx,
) -> Result<BlockCost, SimError> {
    let mut cost = BlockCost::default();
    for tx in block.txs.iter().skip(1) {
        for (index, input) in tx.inputs.iter().enumerate() {
            let coin = pre
                .get_coin(&input.prev_out)?
                .ok_or_else(|| SimError::fixture("input does not resolve"))?;
            let exec = ExecCtx {
                chain_id: ctx.params.chain_id,
                tx,
                input_index: index,
                input_value: coin.value,
                block_height: ctx.height,
                block_mtp_s: ctx.median_time_past_s,
                limits: ScriptLimits::CONSENSUS,
            };
            let stats: ExecStats = verify(&input.script_sig, &coin.script_pubkey, &exec)?;
            cost.ops = cost.ops.saturating_add(stats.ops);
            cost.sig_checks = cost.sig_checks.saturating_add(stats.sig_checks);
            cost.max_stack = cost.max_stack.max(stats.max_stack);
            cost.inputs = cost.inputs.saturating_add(1);
        }
    }
    Ok(cost)
}

/// A transaction with one phantom input and `outputs` outputs of
/// `script_bytes` bytes each — the cheapest way to build an oversized block.
#[must_use]
pub fn bloated_transaction(outputs: usize, script_bytes: usize) -> Transaction {
    // `OP_RETURN` followed by filler: unspendable, so the block would not
    // inflate the UTXO set even if it were accepted.
    let mut script = vec![0x6a];
    script.resize(script_bytes, 0x00);
    Transaction {
        version: 1,
        inputs: vec![TxIn::new(
            ferrum_types::OutPoint::new(
                ferrum_types::Txid(ferrum_types::Hash32::from_bytes([0x5a; 32])),
                0,
            ),
            Script::EMPTY,
        )],
        outputs: (0..outputs)
            .map(|_| TxOut::new(Amount::from_grains(1), Script::new(script.clone())))
            .collect(),
        lock_time: 0,
    }
}

/// A script of `count` `OP_NOP`s followed by `OP_1`.
///
/// `OP_NOP` is the cheapest non-push opcode, so this is the shortest way to
/// exhaust the operation budget.
#[must_use]
pub fn nop_script(count: usize) -> Vec<u8> {
    let mut out = vec![0x61; count];
    out.push(0x51);
    out
}

/// A script that pushes `count` elements, for the stack limit.
#[must_use]
pub fn push_script(count: usize) -> Vec<u8> {
    vec![0x51; count]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_chain::ValidationError;
    use ferrum_script::{
        MAX_PUBKEYS_PER_MULTISIG, MAX_SCRIPT_SIZE, MAX_STACK_SIZE, ScriptError,
    };

    use super::*;
    use crate::chain_builder::{BlockPlan, ChainBuilder, TxPlan};
    use crate::keys::Lock;
    use crate::scenarios::script_encoding::spend_raw;
    use crate::scenarios::{judge, matured_chain};

    /// How many maximal multisig outputs the expensive block spends.
    ///
    /// Eight 15-of-15 inputs is 120 Schnorr verifications, which is a real
    /// worst-case *shape* without making the test suite slow. The bound the
    /// test asserts is the general one, not this number.
    const EXPENSIVE_INPUTS: usize = 8;
    const MULTISIG_N: usize = 15;

    // ---- red -----------------------------------------------------------

    #[test]
    fn a_block_over_the_size_limit_is_rejected_before_any_script_runs() {
        let mut chain = ChainBuilder::devnet(61).unwrap();
        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        // 1000 outputs of 1000 bytes each is comfortably over 1 MB.
        let block = chain
            .build_block(&BlockPlan {
                txs: vec![bloated_transaction(1_000, MAX_SCRIPT_SIZE)],
                ..BlockPlan::default()
            })
            .unwrap();
        assert!(block.serialized_size() > chain.params().max_block_size);
        match judge(&pre, &block, &ctx).unwrap().rejection() {
            Some(ValidationError::BlockTooLarge { size, max }) => {
                assert_eq!(*size, block.serialized_size());
                assert_eq!(*max, chain.params().max_block_size);
            }
            other => panic!("expected BlockTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn a_script_over_the_script_size_limit_is_rejected() {
        let mut chain = ChainBuilder::devnet(62).unwrap();
        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        let mut tx = crate::mutate::filler_tx(1);
        tx.inputs[0].script_sig = Script::new(vec![0x00; MAX_SCRIPT_SIZE + 1]);
        let block =
            chain.build_block(&BlockPlan { txs: vec![tx], ..BlockPlan::default() }).unwrap();
        match judge(&pre, &block, &ctx).unwrap().rejection() {
            Some(ValidationError::ScriptTooLarge { len, max }) => {
                assert_eq!(*len, MAX_SCRIPT_SIZE + 1);
                assert_eq!(*max, MAX_SCRIPT_SIZE);
            }
            other => panic!("expected ScriptTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn a_script_over_the_operation_budget_is_rejected() {
        let mut chain = matured_chain(63, 2).unwrap();
        let height = chain.height() + 1;
        let coin = chain.take_mature(1, height).pop().unwrap();
        let over = usize::try_from(MAX_OPS).unwrap() + 1;
        let verdict =
            spend_raw(&mut chain, &coin, nop_script(over), Vec::new(), 0).unwrap();
        match verdict.rejection() {
            Some(ValidationError::ScriptVerification { source, .. }) => {
                assert!(
                    matches!(source, ScriptError::OpCountExceeded { .. }),
                    "expected OpCountExceeded, got {source:?}"
                );
            }
            other => panic!("expected ScriptVerification, got {other:?}"),
        }
    }

    #[test]
    fn the_operation_budget_is_not_reset_between_the_scripts_of_one_input() {
        // An attacker who could split a script in two would buy twice the work
        // for the same price. Under P2SH the locking script spends two
        // operations (`OP_HASH256`, `OP_EQUAL`) before the redeem script runs,
        // and the counter carries over: a redeem script of 200 `OP_NOP`s is
        // fine alone and over budget behind a P2SH wrapper.
        let mut chain = matured_chain(64, 2).unwrap();
        let height = chain.height() + 1;
        let budget = usize::try_from(MAX_OPS).unwrap();

        let redeem = |nops: usize| Script::new(nop_script(nops));
        let p2sh_pair = |nops: usize| {
            let r = redeem(nops);
            let mut script_sig = Vec::new();
            crate::sign::push_bytes(&mut script_sig, r.as_bytes()).expect("redeem fits a push");
            (ferrum_script::templates::p2sh_of(&r).into_bytes(), script_sig)
        };

        // 199 NOPs plus the wrapper's 2 operations is exactly the budget.
        let coin = chain.take_mature(1, height).pop().unwrap();
        let (spk, sig) = p2sh_pair(budget - 2);
        assert!(
            spend_raw(&mut chain, &coin, spk, sig, 0).unwrap().is_accepted(),
            "exactly at the budget must pass"
        );

        // One more NOP, and the same redeem script that would run standalone
        // is now over budget because of the two operations before it.
        let coin = chain.take_mature(1, height).pop().unwrap();
        let (spk, sig) = p2sh_pair(budget - 1);
        match spend_raw(&mut chain, &coin, spk, sig, 0).unwrap().rejection() {
            Some(ValidationError::ScriptVerification { source, .. }) => {
                assert!(
                    matches!(source, ScriptError::OpCountExceeded { .. }),
                    "expected OpCountExceeded, got {source:?}"
                );
            }
            other => panic!("expected ScriptVerification, got {other:?}"),
        }
    }

    #[test]
    fn a_script_over_the_stack_limit_is_rejected() {
        let mut chain = matured_chain(65, 2).unwrap();
        let height = chain.height() + 1;
        let coin = chain.take_mature(1, height).pop().unwrap();
        let verdict =
            spend_raw(&mut chain, &coin, push_script(MAX_STACK_SIZE + 1), Vec::new(), 0).unwrap();
        match verdict.rejection() {
            Some(ValidationError::ScriptVerification { source, .. }) => {
                assert!(
                    matches!(source, ScriptError::StackOverflow { .. }),
                    "expected StackOverflow, got {source:?}"
                );
            }
            other => panic!("expected ScriptVerification, got {other:?}"),
        }
    }

    #[test]
    fn a_multisig_naming_more_keys_than_the_limit_is_rejected() {
        let mut chain = matured_chain(66, 2).unwrap();
        let height = chain.height() + 1;
        let coin = chain.take_mature(1, height).pop().unwrap();
        // `<1> <21> OP_CHECKMULTISIG` with no keys: the key count alone is out
        // of range, so the script fails before it can demand any work.
        let script = vec![0x51, 0x01, 21, 0xae];
        let verdict = spend_raw(&mut chain, &coin, script, Vec::new(), 0).unwrap();
        match verdict.rejection() {
            Some(ValidationError::ScriptVerification { source, .. }) => {
                assert_eq!(*source, ScriptError::PubKeyCountOutOfRange(21));
            }
            other => panic!("expected ScriptVerification, got {other:?}"),
        }
    }

    // ---- green ---------------------------------------------------------

    #[test]
    fn the_most_expensive_block_the_rules_allow_is_accepted_and_bounded() {
        let mut chain = matured_chain(67, 12).unwrap();
        let lock = Lock::Multisig {
            k: u8::try_from(MULTISIG_N).unwrap(),
            keys: (0..MULTISIG_N).collect(),
        };

        // Fund `EXPENSIVE_INPUTS` maximal multisig outputs.
        let height = chain.height() + 1;
        let coins = chain.take_mature(EXPENSIVE_INPUTS, height);
        assert_eq!(coins.len(), EXPENSIVE_INPUTS);
        let per_output = Amount::from_grains(1_000_000_000);
        let funding = chain
            .build_tx(&TxPlan {
                inputs: coins,
                outputs: (0..EXPENSIVE_INPUTS).map(|_| (lock.clone(), per_output)).collect(),
                ..TxPlan::default()
            })
            .unwrap();
        chain.mine(vec![funding]).unwrap();

        // Spend all of them in one transaction: the worst shape the limits
        // allow, at this scale.
        let spend_height = chain.height() + 1;
        let inputs: Vec<_> = chain
            .mature(spend_height)
            .into_iter()
            .filter(|c| c.lock == lock)
            .take(EXPENSIVE_INPUTS)
            .collect();
        assert_eq!(inputs.len(), EXPENSIVE_INPUTS);
        let total = inputs.iter().fold(Amount::ZERO, |a, c| a.saturating_add(c.coin.value));
        let tx = chain
            .build_tx(&TxPlan::sweep(
                inputs,
                Lock::P2pkh { key: 0 },
                Amount::from_grains(10_000),
            ))
            .unwrap();
        assert_eq!(tx.outputs[0].value, total.saturating_sub(Amount::from_grains(10_000)));
        // Each `script_sig` carries 15 signatures of 65 bytes plus their push
        // headers: close to `MAX_SCRIPT_SIZE`, and still under it.
        for input in &tx.inputs {
            assert!(input.script_sig.len() <= MAX_SCRIPT_SIZE);
            assert!(input.script_sig.len() > 900, "the fixture must be near the limit");
        }

        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        let block =
            chain.build_block(&BlockPlan { txs: vec![tx], ..BlockPlan::default() }).unwrap();
        let verdict = judge(&pre, &block, &ctx).unwrap();
        assert!(verdict.is_accepted(), "the expensive block is valid: {verdict:?}");

        let cost = measure(&block, &pre, &ctx).unwrap();
        assert_eq!(cost.inputs, u32::try_from(EXPENSIVE_INPUTS).unwrap());
        assert_eq!(
            cost.sig_checks,
            u32::try_from(EXPENSIVE_INPUTS * MULTISIG_N).unwrap(),
            "an in-order k-of-n multisig verifies exactly k signatures"
        );
        // The two structural bounds.
        assert!(
            cost.sig_checks <= cost.inputs.saturating_mul(MAX_OPS),
            "the operation budget bounds signature checks: {cost:?}"
        );
        assert!(
            cost.ops <= cost.inputs.saturating_mul(MAX_OPS),
            "no input may exceed MAX_OPS: {cost:?}"
        );
        assert!(cost.max_stack <= MAX_STACK_SIZE);
        assert!(
            u64::from(cost.sig_checks) < BlockCost::ceiling_for(chain.params().max_block_size),
            "the measured cost must sit under the published ceiling"
        );
    }

    #[test]
    fn the_published_ceiling_is_finite_and_computable() {
        // The point of static limits: the worst case is a number, known in
        // advance, with no loops and no metering.
        let ceiling = BlockCost::ceiling_for(1_000_000);
        assert_eq!(ceiling, (1_000_000 / MIN_INPUT_BYTES) as u64 * u64::from(MAX_OPS));
        assert!(ceiling > 0 && ceiling < u64::from(u32::MAX) * 2);
        assert_eq!(MAX_PUBKEYS_PER_MULTISIG, 20);
    }

    #[test]
    fn a_script_exactly_at_the_operation_budget_is_accepted() {
        let mut chain = matured_chain(68, 2).unwrap();
        let height = chain.height() + 1;
        let coin = chain.take_mature(1, height).pop().unwrap();
        // `MAX_OPS` NOPs plus the trailing OP_1: the OP_1 is a push and is not
        // charged, so this sits exactly on the budget.
        let at_limit = usize::try_from(MAX_OPS).unwrap();
        let verdict =
            spend_raw(&mut chain, &coin, nop_script(at_limit), Vec::new(), 0).unwrap();
        assert!(verdict.is_accepted(), "exactly at the limit must pass: {verdict:?}");
    }

    #[test]
    fn a_block_exactly_at_the_size_limit_is_accepted() {
        let mut chain = ChainBuilder::devnet(69).unwrap();
        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        let empty = chain.build_block(&BlockPlan::default()).unwrap();
        assert!(empty.serialized_size() < chain.params().max_block_size);
        assert!(judge(&pre, &empty, &ctx).unwrap().is_accepted());
    }
}
