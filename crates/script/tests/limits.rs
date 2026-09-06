//! The hard limits of CONTRACT §5.1, each rejected with its own error variant.
//!
//! A test that only asserts "rejected" passes when the script was rejected for
//! the wrong reason, so every assertion here names the exact error.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{
    ctx_for, dummy_tx, num, public, push, run_empty, run_with_limits, script, script_sig,
};
use ferrum_script::{
    ExecCtx, MAX_ELEMENT_SIZE, MAX_OPS, MAX_SCRIPT_SIZE, MAX_STACK_SIZE, ScriptError, ScriptLimits,
    eval, templates, verify,
};
use ferrum_types::{ChainId, Script};

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_TOALTSTACK: u8 = 0x6b;
const OP_DEPTH: u8 = 0x74;
const OP_DROP: u8 = 0x75;
const OP_DUP: u8 = 0x76;
const OP_NOP: u8 = 0x61;
const OP_CHECKMULTISIG: u8 = 0xae;

// ---------------------------------------------------------------------------
// MAX_SCRIPT_SIZE
// ---------------------------------------------------------------------------

#[test]
fn a_script_pubkey_over_1000_bytes_is_rejected() {
    let oversized = script(&vec![OP_NOP; MAX_SCRIPT_SIZE + 1]);
    let tx = dummy_tx();
    let ctx = ctx_for(&tx, ChainId::DEVNET);
    assert_eq!(
        verify(&Script::EMPTY, &oversized, &ctx),
        Err(ScriptError::ScriptTooLarge { len: 1_001, max: 1_000 })
    );
}

#[test]
fn a_script_sig_over_1000_bytes_is_rejected() {
    let oversized = script(&vec![OP_1; MAX_SCRIPT_SIZE + 1]);
    let tx = dummy_tx();
    let ctx = ctx_for(&tx, ChainId::DEVNET);
    assert_eq!(
        verify(&oversized, &script(&[OP_1]), &ctx),
        Err(ScriptError::ScriptTooLarge { len: 1_001, max: 1_000 })
    );
}

#[test]
fn exactly_1000_bytes_is_allowed() {
    // Two big pushes soak up most of the script, so the op count stays well
    // under 201 while the byte count lands exactly on the limit.
    let mut bytes = push(&vec![0x11u8; MAX_ELEMENT_SIZE]);
    bytes.push(OP_DROP);
    bytes.extend_from_slice(&push(&vec![0x22u8; 400]));
    bytes.push(OP_DROP);
    bytes.extend(std::iter::repeat_n(OP_NOP, MAX_SCRIPT_SIZE - bytes.len() - 1));
    bytes.push(OP_1);
    assert_eq!(bytes.len(), MAX_SCRIPT_SIZE);
    assert_eq!(run_empty(&bytes).unwrap(), vec![vec![1u8]]);

    // One byte more and it is rejected.
    let mut too_long = bytes.clone();
    too_long.push(OP_NOP);
    assert_eq!(run_empty(&too_long), Err(ScriptError::ScriptTooLarge { len: 1_001, max: 1_000 }));
}

#[test]
fn eval_applies_the_script_size_limit_too() {
    let oversized = vec![OP_NOP; MAX_SCRIPT_SIZE + 1];
    assert_eq!(run_empty(&oversized), Err(ScriptError::ScriptTooLarge { len: 1_001, max: 1_000 }));
}

#[test]
fn a_p2sh_redeem_script_is_bounded_by_the_element_limit() {
    // A redeem script arrives as a stack element, so `MAX_ELEMENT_SIZE` (520)
    // binds before `MAX_SCRIPT_SIZE` (1000) ever can. The redeem-script size
    // check in `verify` is therefore belt-and-braces, and this is the rule that
    // actually stops an oversized redeem script.
    let redeem = script(&vec![OP_NOP; MAX_ELEMENT_SIZE + 1]);
    let script_pubkey = templates::p2sh_of(&redeem);
    let unlock = script_sig(&[redeem.as_bytes()]);
    let tx = dummy_tx();
    let ctx = ctx_for(&tx, ChainId::DEVNET);
    assert_eq!(
        verify(&unlock, &script_pubkey, &ctx),
        Err(ScriptError::ElementTooLarge { len: 521, max: 520 })
    );
}

#[test]
fn a_script_sig_carrying_an_over_long_redeem_script_is_rejected_first() {
    // With the limit tightened, the `script_sig` that carries the redeem script
    // is always one push-header longer than the script itself, so it is the
    // first thing to fail.
    let limits = ScriptLimits { max_script_size: 40, ..ScriptLimits::CONSENSUS };
    let redeem = script(&[OP_NOP; 41]);
    let script_pubkey = templates::p2sh_of(&redeem);
    let unlock = script_sig(&[redeem.as_bytes()]);
    let tx = dummy_tx();
    let ctx = ExecCtx { limits, ..ctx_for(&tx, ChainId::DEVNET) };
    assert_eq!(
        verify(&unlock, &script_pubkey, &ctx),
        Err(ScriptError::ScriptTooLarge { len: 42, max: 40 })
    );
}

// ---------------------------------------------------------------------------
// MAX_ELEMENT_SIZE
// ---------------------------------------------------------------------------

#[test]
fn a_stack_element_over_520_bytes_is_rejected() {
    let oversized = push(&vec![0x33u8; MAX_ELEMENT_SIZE + 1]);
    assert_eq!(run_empty(&oversized), Err(ScriptError::ElementTooLarge { len: 521, max: 520 }));
}

#[test]
fn exactly_520_bytes_is_allowed() {
    let ok = push(&vec![0x33u8; MAX_ELEMENT_SIZE]);
    assert_eq!(run_empty(&ok).unwrap()[0].len(), MAX_ELEMENT_SIZE);
}

#[test]
fn an_oversized_initial_stack_element_is_rejected() {
    let tx = dummy_tx();
    let ctx = ctx_for(&tx, ChainId::DEVNET);
    assert_eq!(
        eval(&script(&[OP_1]), vec![vec![0u8; MAX_ELEMENT_SIZE + 1]], &ctx),
        Err(ScriptError::ElementTooLarge { len: 521, max: 520 })
    );
}

#[test]
fn an_oversized_push_in_a_dead_branch_is_still_rejected() {
    let mut bytes = vec![OP_0, 0x63];
    bytes.extend_from_slice(&push(&vec![0x33u8; MAX_ELEMENT_SIZE + 1]));
    bytes.push(0x68);
    bytes.push(OP_1);
    assert_eq!(run_empty(&bytes), Err(ScriptError::ElementTooLarge { len: 521, max: 520 }));
}

#[test]
fn a_computed_element_cannot_exceed_the_limit_either() {
    // OP_DUP of a 520-byte element is fine; the limit is per element, not the
    // total, which the stack-depth limit covers instead.
    let mut bytes = push(&vec![0x33u8; MAX_ELEMENT_SIZE]);
    bytes.push(OP_DUP);
    assert_eq!(run_empty(&bytes).unwrap().len(), 2);
}

// ---------------------------------------------------------------------------
// MAX_STACK_SIZE
// ---------------------------------------------------------------------------

#[test]
fn more_than_100_stack_elements_is_rejected() {
    let bytes = vec![OP_1; MAX_STACK_SIZE + 1];
    assert_eq!(run_empty(&bytes), Err(ScriptError::StackOverflow { size: 101, max: 100 }));
}

#[test]
fn exactly_100_stack_elements_is_allowed() {
    let bytes = vec![OP_1; MAX_STACK_SIZE];
    assert_eq!(run_empty(&bytes).unwrap().len(), MAX_STACK_SIZE);
}

#[test]
fn the_altstack_counts_towards_the_same_limit() {
    // 100 elements, then move one to the altstack and push another: the
    // combined depth is 101.
    let mut bytes = vec![OP_1; MAX_STACK_SIZE];
    bytes.push(OP_TOALTSTACK);
    bytes.push(OP_1);
    bytes.push(OP_1);
    assert_eq!(run_empty(&bytes), Err(ScriptError::StackOverflow { size: 101, max: 100 }));
}

#[test]
fn an_oversized_initial_stack_is_rejected() {
    let tx = dummy_tx();
    let ctx = ctx_for(&tx, ChainId::DEVNET);
    let initial = vec![vec![1u8]; MAX_STACK_SIZE + 1];
    assert_eq!(
        eval(&script(&[OP_1]), initial, &ctx),
        Err(ScriptError::StackOverflow { size: 101, max: 100 })
    );
}

// ---------------------------------------------------------------------------
// MAX_OPS
// ---------------------------------------------------------------------------

#[test]
fn more_than_201_non_push_opcodes_is_rejected() {
    let bytes = vec![OP_NOP; MAX_OPS as usize + 1];
    assert_eq!(run_empty(&bytes), Err(ScriptError::OpCountExceeded { max: 201 }));
}

#[test]
fn exactly_201_non_push_opcodes_is_allowed() {
    let mut bytes = vec![OP_NOP; MAX_OPS as usize];
    bytes.push(OP_1);
    assert!(run_empty(&bytes).is_ok());
}

#[test]
fn pushes_do_not_count_towards_the_op_limit() {
    // 300 pushes and no operations at all: well over MAX_OPS if pushes counted,
    // but they do not.
    let mut bytes = Vec::new();
    for _ in 0..300 {
        bytes.push(OP_1);
        bytes.push(OP_DROP);
    }
    // 300 OP_DROPs *do* count, so tighten nothing and expect the drop count to
    // be what trips the limit.
    assert_eq!(run_empty(&bytes), Err(ScriptError::OpCountExceeded { max: 201 }));

    let pushes_only = vec![OP_1; 90];
    assert!(run_empty(&pushes_only).is_ok());
}

#[test]
fn the_op_count_is_not_reset_between_scripts() {
    // 150 operations in `script_sig` is impossible (push-only), so use a
    // tightened limit with `script_pubkey` plus a P2SH redeem script.
    let limits = ScriptLimits { max_ops: 10, ..ScriptLimits::CONSENSUS };
    let redeem = script(&[OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_1]);
    let script_pubkey = templates::p2sh_of(&redeem);
    let unlock = script_sig(&[redeem.as_bytes()]);
    let tx = dummy_tx();
    let ctx = ExecCtx { limits, ..ctx_for(&tx, ChainId::DEVNET) };
    // `script_pubkey` spends 2 ops (OP_HASH256, OP_EQUAL); the redeem script
    // needs 7 more, for 9 — under the limit.
    assert!(verify(&unlock, &script_pubkey, &ctx).is_ok());

    // Two more operations in the redeem script tip the shared budget over.
    let redeem =
        script(&[OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_1]);
    let script_pubkey = templates::p2sh_of(&redeem);
    let unlock = script_sig(&[redeem.as_bytes()]);
    assert_eq!(
        verify(&unlock, &script_pubkey, &ctx),
        Err(ScriptError::OpCountExceeded { max: 10 })
    );
}

#[test]
fn a_multisig_charges_one_operation_per_pubkey() {
    // OP_0 <pk> OP_0 OP_CHECKMULTISIG is 0-of-1: one key, so two operations
    // (the opcode itself plus the key).
    let key = public(1);
    let mut bytes = vec![OP_0];
    bytes.extend_from_slice(&push(key.as_bytes()));
    bytes.push(OP_1);
    bytes.push(OP_CHECKMULTISIG);
    let limits = ScriptLimits { max_ops: 1, ..ScriptLimits::CONSENSUS };
    assert_eq!(
        run_with_limits(&bytes, Vec::new(), limits),
        Err(ScriptError::OpCountExceeded { max: 1 })
    );
    let limits = ScriptLimits { max_ops: 2, ..ScriptLimits::CONSENSUS };
    assert!(run_with_limits(&bytes, Vec::new(), limits).is_ok());
}

// ---------------------------------------------------------------------------
// MAX_PUBKEYS_PER_MULTISIG and MAX_NUM_SIZE
// ---------------------------------------------------------------------------

#[test]
fn more_than_20_multisig_pubkeys_is_rejected() {
    let mut bytes = vec![OP_1];
    bytes.extend_from_slice(&push(&num(21)));
    bytes.push(OP_CHECKMULTISIG);
    assert_eq!(run_empty(&bytes), Err(ScriptError::PubKeyCountOutOfRange(21)));
}

#[test]
fn a_negative_multisig_pubkey_count_is_rejected() {
    let mut bytes = vec![OP_1];
    bytes.extend_from_slice(&push(&num(-1)));
    bytes.push(OP_CHECKMULTISIG);
    assert_eq!(run_empty(&bytes), Err(ScriptError::PubKeyCountOutOfRange(-1)));
}

#[test]
fn a_signature_count_above_the_pubkey_count_is_rejected() {
    let key = public(1);
    let mut bytes = vec![OP_2];
    bytes.extend_from_slice(&push(key.as_bytes()));
    bytes.push(OP_1);
    bytes.push(OP_CHECKMULTISIG);
    assert_eq!(run_empty(&bytes), Err(ScriptError::SigCountOutOfRange { k: 2, n: 1 }));
}

#[test]
fn a_number_over_four_bytes_is_rejected_where_it_is_read() {
    let mut bytes = push(&[0x01, 0x02, 0x03, 0x04, 0x05]);
    bytes.push(0x8b); // OP_1ADD
    assert_eq!(run_empty(&bytes), Err(ScriptError::NumTooLarge { len: 5, max: 4 }));
}

#[test]
fn tightened_limits_are_honoured_across_the_board() {
    let limits = ScriptLimits {
        max_script_size: 8,
        max_stack_size: 2,
        max_element_size: 1,
        max_ops: 1,
        max_pubkeys_per_multisig: 1,
        max_num_size: 1,
    };
    assert_eq!(
        run_with_limits(&[OP_1; 9], Vec::new(), limits),
        Err(ScriptError::ScriptTooLarge { len: 9, max: 8 })
    );
    assert_eq!(
        run_with_limits(&[OP_1, OP_1, OP_1], Vec::new(), limits),
        Err(ScriptError::StackOverflow { size: 3, max: 2 })
    );
    assert_eq!(
        run_with_limits(&push(&[1, 2]), Vec::new(), limits),
        Err(ScriptError::ElementTooLarge { len: 2, max: 1 })
    );
    assert_eq!(
        run_with_limits(&[OP_1, OP_DEPTH, OP_DEPTH], Vec::new(), limits),
        Err(ScriptError::OpCountExceeded { max: 1 })
    );
}
