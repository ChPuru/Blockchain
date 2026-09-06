//! `OP_IF` / `OP_NOTIF` / `OP_ELSE` / `OP_ENDIF`.
//!
//! The rule that catches people out: opcodes in an untaken branch are *skipped*
//! but the branch is still **parsed**. An undefined byte fails the script from
//! inside a dead branch, and an unbalanced conditional fails wherever it is.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{assert_err, assert_stack, push, run_empty, run_with_limits};
use ferrum_script::{ScriptError, ScriptLimits};

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_IF: u8 = 0x63;
const OP_NOTIF: u8 = 0x64;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_RETURN: u8 = 0x6a;
const OP_DUP: u8 = 0x76;
const OP_ADD: u8 = 0x93;

#[test]
fn if_takes_the_true_branch() {
    assert_stack(&[OP_1, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF], &[&[2]]);
    assert_stack(&[OP_0, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF], &[&[3]]);
}

#[test]
fn notif_inverts_the_condition() {
    assert_stack(&[OP_0, OP_NOTIF, OP_2, OP_ELSE, OP_3, OP_ENDIF], &[&[2]]);
    assert_stack(&[OP_1, OP_NOTIF, OP_2, OP_ELSE, OP_3, OP_ENDIF], &[&[3]]);
}

#[test]
fn if_without_else_is_fine() {
    assert_stack(&[OP_1, OP_IF, OP_2, OP_ENDIF], &[&[2]]);
    assert_stack(&[OP_0, OP_IF, OP_2, OP_ENDIF], &[]);
}

#[test]
fn the_condition_is_consumed() {
    // OP_1 is popped by OP_IF, so only the branch result remains.
    assert_stack(&[OP_1, OP_1, OP_IF, OP_ENDIF], &[&[1]]);
}

#[test]
fn nested_conditionals_track_correctly() {
    // 1 -> outer true, 1 -> inner true.
    assert_stack(
        &[OP_1, OP_IF, OP_1, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF, OP_ELSE, OP_3, OP_ENDIF],
        &[&[2]],
    );
    // 1 -> outer true, 0 -> inner false.
    assert_stack(
        &[OP_1, OP_IF, OP_0, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF, OP_ELSE, OP_3, OP_ENDIF],
        &[&[3]],
    );
    // 0 -> outer false: the whole inner conditional is dead and the inner
    // condition is never popped.
    assert_stack(
        &[OP_0, OP_IF, OP_1, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF, OP_ELSE, OP_2, OP_ENDIF],
        &[&[2]],
    );
}

#[test]
fn a_dead_branch_does_not_execute_its_opcodes() {
    // OP_RETURN inside a dead branch is skipped, not executed.
    assert_stack(&[OP_0, OP_IF, OP_RETURN, OP_ENDIF, OP_1], &[&[1]]);
    // ...and executes when the branch is live.
    assert_err(&[OP_1, OP_IF, OP_RETURN, OP_ENDIF], vec![], ScriptError::OpReturn);
}

#[test]
fn a_dead_branch_still_rejects_an_undefined_opcode() {
    assert_err(&[OP_0, OP_IF, 0xff, OP_ENDIF, OP_1], vec![], ScriptError::InvalidOpcode(0xff));
    assert_err(&[OP_0, OP_IF, 0x50, OP_ENDIF, OP_1], vec![], ScriptError::InvalidOpcode(0x50));
    // OP_PUSHDATA4 does not exist in Ferrum, even where it would be skipped.
    assert_err(&[OP_0, OP_IF, 0x4e, OP_ENDIF, OP_1], vec![], ScriptError::InvalidOpcode(0x4e));
}

#[test]
fn a_dead_branch_still_charges_its_opcodes() {
    // 30 dead OP_DUPs against a limit of 20: the count is charged whether or
    // not the branch runs, so a long dead branch is not free work.
    let mut s = vec![OP_0, OP_IF];
    s.extend(std::iter::repeat_n(OP_DUP, 30));
    s.push(OP_ENDIF);
    s.push(OP_1);
    let limits = ScriptLimits { max_ops: 20, ..ScriptLimits::CONSENSUS };
    assert_eq!(
        run_with_limits(&s, Vec::new(), limits),
        Err(ScriptError::OpCountExceeded { max: 20 })
    );
}

#[test]
fn unbalanced_conditionals_fail() {
    assert_err(&[OP_1, OP_IF], vec![], ScriptError::UnbalancedConditional);
    assert_err(&[OP_1, OP_IF, OP_ELSE], vec![], ScriptError::UnbalancedConditional);
    assert_err(&[OP_ENDIF], vec![], ScriptError::UnbalancedConditional);
    assert_err(&[OP_ELSE], vec![], ScriptError::UnbalancedConditional);
    assert_err(&[OP_1, OP_IF, OP_ENDIF, OP_ENDIF], vec![], ScriptError::UnbalancedConditional);
    // Nested, missing one OP_ENDIF.
    assert_err(&[OP_1, OP_IF, OP_1, OP_IF, OP_ENDIF], vec![], ScriptError::UnbalancedConditional);
}

#[test]
fn an_unbalanced_conditional_inside_a_dead_branch_still_fails() {
    assert_err(&[OP_0, OP_IF, OP_1, OP_IF, OP_ENDIF], vec![], ScriptError::UnbalancedConditional);
}

#[test]
fn a_second_else_is_rejected() {
    assert_err(
        &[OP_1, OP_IF, OP_1, OP_ELSE, OP_2, OP_ELSE, OP_3, OP_ENDIF],
        vec![],
        ScriptError::DuplicateElse,
    );
    // Even in a dead branch, because it is script malleability either way.
    assert_err(
        &[OP_0, OP_IF, OP_1, OP_ELSE, OP_2, OP_ELSE, OP_3, OP_ENDIF],
        vec![],
        ScriptError::DuplicateElse,
    );
}

#[test]
fn the_condition_must_be_minimally_encoded() {
    // 0x02 is truthy but not `{}` or `{0x01}`.
    let mut s = push(&[0x02]);
    s.extend_from_slice(&[OP_IF, OP_1, OP_ENDIF]);
    assert_err(&s, vec![], ScriptError::MinimalIf);

    // 0x00 is falsy but is not the canonical `{}`.
    let mut s = push(&[0x00]);
    s.extend_from_slice(&[OP_IF, OP_1, OP_ENDIF]);
    assert_err(&s, vec![], ScriptError::MinimalIf);

    // Negative zero.
    let mut s = push(&[0x80]);
    s.extend_from_slice(&[OP_IF, OP_1, OP_ENDIF]);
    assert_err(&s, vec![], ScriptError::MinimalIf);

    // Two bytes, however truthy.
    let mut s = push(&[0x01, 0x00]);
    s.extend_from_slice(&[OP_IF, OP_1, OP_ENDIF]);
    assert_err(&s, vec![], ScriptError::MinimalIf);

    // The two legal spellings.
    assert!(run_empty(&[OP_0, OP_IF, OP_1, OP_ENDIF]).is_ok());
    assert!(run_empty(&[OP_1, OP_IF, OP_1, OP_ENDIF]).is_ok());
}

#[test]
fn notif_enforces_the_same_minimality() {
    let mut s = push(&[0x02]);
    s.extend_from_slice(&[OP_NOTIF, OP_1, OP_ENDIF]);
    assert_err(&s, vec![], ScriptError::MinimalIf);
}

#[test]
fn if_on_an_empty_stack_underflows() {
    assert_err(
        &[OP_IF, OP_1, OP_ENDIF],
        vec![],
        ScriptError::StackUnderflow { needed: 1, found: 0 },
    );
}

#[test]
fn arithmetic_survives_a_branch() {
    assert_stack(&[OP_1, OP_IF, OP_2, OP_3, OP_ADD, OP_ELSE, OP_0, OP_ENDIF], &[&[5]]);
}
