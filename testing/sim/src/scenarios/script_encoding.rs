//! **Attack:** re-spell a script so that two different byte strings mean the
//! same thing.
//!
//! Every alternative spelling of a value is a malleability vector. A third
//! party who can rewrite `0x01 0x01` as `OP_1` changes the `script_sig`, hence
//! the transaction bytes, hence the txid — and any unconfirmed transaction that
//! spends the original output now refers to a transaction that no longer
//! exists. Mt. Gox blamed exactly this class of bug for its 2014 collapse, and
//! Bitcoin needed a soft fork (BIP-62's remnants, then SegWit) to close it.
//!
//! Ferrum enforces minimality **wherever a value is read**, as consensus, from
//! the first commit (SPEC §5 rule 6):
//!
//! * pushes must use the shortest opcode that can express the data —
//!   [`ScriptError::NonMinimalPush`];
//! * `ScriptNum` operands must be minimally encoded —
//!   [`ScriptNum`](ferrum_script::ScriptNum) rejects `0x01 0x00` for `1` with
//!   [`ScriptError::NonMinimalNum`];
//! * `OP_IF`/`OP_NOTIF` accept only `{}` or `{0x01}` as the condition —
//!   [`ScriptError::MinimalIf`];
//! * `script_sig` must be push-only — [`ScriptError::PushOnly`].
//!
//! Every rejection reaches a block as
//! [`ValidationError::ScriptVerification`](ferrum_chain::ValidationError::ScriptVerification)
//! naming the transaction, the input and the underlying script error.
//!
//! **Red:** each non-minimal spelling is rejected with its own script error.
//! **Green:** the minimal spelling of the very same value is accepted.

use ferrum_types::Amount;

use crate::chain_builder::{BlockPlan, ChainBuilder, SpendableCoin, TxPlan};
use crate::error::SimError;
use crate::keys::Lock;
use crate::scenarios::{Verdict, judge};

/// `<operand> OP_1ADD OP_2 OP_NUMEQUAL`: succeeds when the operand reads as 1.
///
/// Reading the operand as a number is what triggers the minimality rule, so
/// this is the smallest script that can tell a minimal `1` from `0x01 0x00`.
#[must_use]
pub fn increment_to_two() -> Vec<u8> {
    vec![0x8b, 0x52, 0x9c]
}

/// `OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF`: the condition operand is read as a
/// boolean, so it must be exactly `{}` or `{0x01}`.
#[must_use]
pub fn minimal_if_gate() -> Vec<u8> {
    vec![0x63, 0x51, 0x67, 0x00, 0x68]
}

/// `<push> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_1` with a caller-supplied operand.
///
/// The operand is pushed with the **minimal** opcode, so that a test about a
/// non-minimal *number* is not accidentally a test about a non-minimal *push*:
/// those are two different rules and each deserves its own fixture.
#[must_use]
pub fn cltv_with_operand(operand: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(operand.len().saturating_add(4));
    match operand {
        [] => out.push(0x00),
        [0x81] => out.push(0x4f),
        [b] if (1..=16).contains(b) => out.push(b.saturating_add(0x50)),
        _ => {
            out.push(u8::try_from(operand.len()).unwrap_or(0));
            out.extend_from_slice(operand);
        }
    }
    out.push(0xb1); // OP_CHECKLOCKTIMEVERIFY
    out.push(0x75); // OP_DROP
    out.push(0x51); // OP_1
    out
}

/// Wrap a raw locking/unlocking script pair as a spendable coin.
#[must_use]
pub fn raw_coin(base: &SpendableCoin, script_pubkey: Vec<u8>, script_sig: Vec<u8>) -> SpendableCoin {
    SpendableCoin {
        out_point: base.out_point,
        coin: base.coin.clone(),
        lock: Lock::Raw { script_pubkey, script_sig },
    }
}

/// Judge a block whose only transaction spends `coin` with its raw scripts.
///
/// The coin is injected into the pre-state with the given locking script, so
/// the scenario controls both halves exactly.
///
/// # Errors
///
/// [`SimError`] if the fixture cannot be built or the executors disagree.
pub fn spend_raw(
    chain: &mut ChainBuilder,
    coin: &SpendableCoin,
    script_pubkey: Vec<u8>,
    script_sig: Vec<u8>,
    lock_time: u32,
) -> Result<Verdict, SimError> {
    let mut fixture = raw_coin(coin, script_pubkey.clone(), script_sig);
    fixture.coin.script_pubkey = ferrum_types::Script::new(script_pubkey);

    let plan = TxPlan {
        inputs: vec![fixture.clone()],
        outputs: vec![(
            Lock::P2pkh { key: 2 },
            fixture.coin.value.saturating_sub(Amount::from_grains(1_000)),
        )],
        lock_time,
        ..TxPlan::default()
    };
    let tx = chain.build_tx(&plan)?;

    // The pre-state must hold the coin under the *raw* locking script.
    let mut pre = chain.state_view();
    pre.insert(fixture.out_point, fixture.coin.clone());

    let ctx = chain.next_ctx()?;
    let block = chain.build_block(&BlockPlan { txs: vec![tx], ..BlockPlan::default() })?;
    judge(&pre, &block, &ctx)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_chain::ValidationError;
    use ferrum_script::ScriptError;

    use super::*;
    use crate::scenarios::matured_chain;

    fn setup() -> (ChainBuilder, SpendableCoin) {
        let mut chain = matured_chain(51, 3).unwrap();
        let height = chain.height() + 1;
        let coin = chain.take_mature(1, height).pop().unwrap();
        (chain, coin)
    }

    fn script_error(verdict: &Verdict) -> ScriptError {
        match verdict.rejection() {
            Some(ValidationError::ScriptVerification { source, .. }) => source.clone(),
            other => panic!("expected ScriptVerification, got {other:?}"),
        }
    }

    // ---- red -----------------------------------------------------------

    #[test]
    fn a_non_minimal_number_is_rejected_where_it_is_read() {
        let (mut chain, coin) = setup();
        // `0x01 0x00` is the value 1 with a redundant leading zero byte.
        let verdict =
            spend_raw(&mut chain, &coin, increment_to_two(), vec![0x02, 0x01, 0x00], 0).unwrap();
        assert_eq!(script_error(&verdict), ScriptError::NonMinimalNum);
    }

    #[test]
    fn a_negative_zero_operand_is_rejected() {
        let (mut chain, coin) = setup();
        // `0x80` is "negative zero", a second spelling of the empty vector.
        let verdict =
            spend_raw(&mut chain, &coin, increment_to_two(), vec![0x01, 0x80], 0).unwrap();
        assert_eq!(script_error(&verdict), ScriptError::NonMinimalNum);
    }

    #[test]
    fn a_non_minimal_push_is_rejected() {
        let (mut chain, coin) = setup();
        // A one-byte push of 0x01 must be spelled OP_1.
        let verdict =
            spend_raw(&mut chain, &coin, increment_to_two(), vec![0x01, 0x01], 0).unwrap();
        assert!(
            matches!(script_error(&verdict), ScriptError::NonMinimalPush { .. }),
            "expected NonMinimalPush"
        );
    }

    #[test]
    fn a_pushdata1_that_a_direct_push_could_express_is_rejected() {
        let (mut chain, coin) = setup();
        // OP_PUSHDATA1 is only minimal above 75 bytes.
        let verdict = spend_raw(
            &mut chain,
            &coin,
            increment_to_two(),
            vec![0x4c, 0x02, 0x01, 0x00],
            0,
        )
        .unwrap();
        assert!(matches!(script_error(&verdict), ScriptError::NonMinimalPush { .. }));
    }

    #[test]
    fn a_truthy_but_non_minimal_if_condition_is_rejected() {
        let (mut chain, coin) = setup();
        // OP_2 is a minimal *push*, but `{0x02}` is not a minimal boolean.
        let verdict = spend_raw(&mut chain, &coin, minimal_if_gate(), vec![0x52], 0).unwrap();
        assert_eq!(script_error(&verdict), ScriptError::MinimalIf);
    }

    #[test]
    fn a_non_minimal_locktime_operand_is_rejected() {
        let (mut chain, coin) = setup();
        let height = chain.height() + 1;
        let lock_time = u32::try_from(height.saturating_sub(1)).unwrap();
        // The locktime 10 spelled with a redundant zero byte.
        let verdict = spend_raw(
            &mut chain,
            &coin,
            cltv_with_operand(&[0x0a, 0x00]),
            Vec::new(),
            lock_time,
        )
        .unwrap();
        assert_eq!(script_error(&verdict), ScriptError::NonMinimalNum);
    }

    #[test]
    fn a_script_sig_that_is_not_push_only_is_rejected() {
        let (mut chain, coin) = setup();
        // `OP_1 OP_DUP OP_DROP` computes the same stack, and is still invalid:
        // push-only is a consensus rule in Ferrum, not a policy rule.
        let verdict =
            spend_raw(&mut chain, &coin, increment_to_two(), vec![0x51, 0x76, 0x75], 0).unwrap();
        assert_eq!(script_error(&verdict), ScriptError::PushOnly);
    }

    #[test]
    fn a_leftover_stack_element_is_rejected() {
        let (mut chain, coin) = setup();
        // The clean-stack rule: `OP_1` on the locking side plus a spare push
        // on the unlocking side leaves two elements.
        let verdict = spend_raw(&mut chain, &coin, vec![0x51], vec![0x51], 0).unwrap();
        assert!(matches!(script_error(&verdict), ScriptError::CleanStack { .. }));
    }

    // ---- green ---------------------------------------------------------

    #[test]
    fn the_minimal_spelling_of_the_same_value_is_accepted() {
        let (mut chain, coin) = setup();
        // OP_1 is the minimal push of the value the red cases tried to spell
        // three other ways.
        let verdict = spend_raw(&mut chain, &coin, increment_to_two(), vec![0x51], 0).unwrap();
        assert!(verdict.is_accepted(), "got {verdict:?}");
    }

    #[test]
    fn the_minimal_if_condition_is_accepted() {
        let (mut chain, coin) = setup();
        let verdict = spend_raw(&mut chain, &coin, minimal_if_gate(), vec![0x51], 0).unwrap();
        assert!(verdict.is_accepted(), "got {verdict:?}");
    }

    #[test]
    fn the_minimal_locktime_operand_is_accepted() {
        let (mut chain, coin) = setup();
        let height = chain.height() + 1;
        let lock_time = u32::try_from(height.saturating_sub(1)).unwrap();
        let verdict =
            spend_raw(&mut chain, &coin, cltv_with_operand(&[0x0a]), Vec::new(), lock_time)
                .unwrap();
        assert!(verdict.is_accepted(), "got {verdict:?}");
    }

    #[test]
    fn minimality_is_enforced_in_untaken_branches_too() {
        // Ferrum has no `OP_NOP1..10` soft-fork hooks, so the opcode table is
        // exhaustive and an undefined byte fails even where it is skipped.
        let (mut chain, coin) = setup();
        // OP_IF <undefined 0xba> OP_ELSE OP_1 OP_ENDIF, taking the ELSE branch.
        let script_pubkey = vec![0x63, 0xba, 0x67, 0x51, 0x68];
        let verdict = spend_raw(&mut chain, &coin, script_pubkey, vec![0x00], 0).unwrap();
        assert_eq!(script_error(&verdict), ScriptError::InvalidOpcode(0xba));
    }
}
