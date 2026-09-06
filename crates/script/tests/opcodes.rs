//! Opcode semantics, one behaviour at a time.
//!
//! Every test drives `eval` rather than `verify`, so the stack after the script
//! is visible and the clean-stack rule does not get in the way.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{assert_err, assert_stack, num, push, run, run_empty};
use ferrum_script::ScriptError;

// Opcode bytes, so a test reads like the script it runs.
const OP_0: u8 = 0x00;
const OP_1NEGATE: u8 = 0x4f;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_4: u8 = 0x54;
const OP_16: u8 = 0x60;
const OP_NOP: u8 = 0x61;
const OP_VERIFY: u8 = 0x69;
const OP_RETURN: u8 = 0x6a;
const OP_TOALTSTACK: u8 = 0x6b;
const OP_FROMALTSTACK: u8 = 0x6c;
const OP_2DUP: u8 = 0x72;
const OP_IFDUP: u8 = 0x73;
const OP_DEPTH: u8 = 0x74;
const OP_DROP: u8 = 0x75;
const OP_DUP: u8 = 0x76;
const OP_NIP: u8 = 0x77;
const OP_OVER: u8 = 0x78;
const OP_PICK: u8 = 0x79;
const OP_ROLL: u8 = 0x7a;
const OP_ROT: u8 = 0x7b;
const OP_SWAP: u8 = 0x7c;
const OP_TUCK: u8 = 0x7d;
const OP_SIZE: u8 = 0x82;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_1ADD: u8 = 0x8b;
const OP_1SUB: u8 = 0x8c;
const OP_NEGATE: u8 = 0x8f;
const OP_ABS: u8 = 0x90;
const OP_NOT: u8 = 0x91;
const OP_0NOTEQUAL: u8 = 0x92;
const OP_ADD: u8 = 0x93;
const OP_SUB: u8 = 0x94;
const OP_BOOLAND: u8 = 0x9a;
const OP_BOOLOR: u8 = 0x9b;
const OP_NUMEQUAL: u8 = 0x9c;
const OP_NUMEQUALVERIFY: u8 = 0x9d;
const OP_NUMNOTEQUAL: u8 = 0x9e;
const OP_LESSTHAN: u8 = 0x9f;
const OP_GREATERTHAN: u8 = 0xa0;
const OP_LESSTHANOREQUAL: u8 = 0xa1;
const OP_GREATERTHANOREQUAL: u8 = 0xa2;
const OP_MIN: u8 = 0xa3;
const OP_MAX: u8 = 0xa4;
const OP_WITHIN: u8 = 0xa5;
const OP_RIPEMD160: u8 = 0xa6;
const OP_SHA256: u8 = 0xa7;
const OP_HASH160: u8 = 0xa9;
const OP_HASH256: u8 = 0xaa;

const TRUE: &[u8] = &[1];
const FALSE: &[u8] = &[];

#[test]
fn push_constants_land_on_the_stack() {
    assert_stack(&[OP_0], &[FALSE]);
    assert_stack(&[OP_1], &[&[1]]);
    assert_stack(&[OP_16], &[&[16]]);
    assert_stack(&[OP_1NEGATE], &[&[0x81]]);
}

#[test]
fn direct_push_and_pushdata() {
    assert_stack(&push(&[0xaa, 0xbb]), &[&[0xaa, 0xbb]]);
    let long = vec![0x5au8; 100];
    assert_stack(&push(&long), &[&long]);
    let longer = vec![0x5au8; 300];
    assert_stack(&push(&longer), &[&longer]);
}

#[test]
fn op_nop_does_nothing() {
    assert_stack(&[OP_1, OP_NOP], &[TRUE]);
}

#[test]
fn op_verify_consumes_and_checks() {
    assert_stack(&[OP_1, OP_VERIFY], &[]);
    assert_err(&[OP_0, OP_VERIFY], vec![], ScriptError::VerifyFailed);
    assert_err(&[OP_VERIFY], vec![], ScriptError::StackUnderflow { needed: 1, found: 0 });
}

#[test]
fn op_return_always_fails() {
    assert_err(&[OP_RETURN], vec![], ScriptError::OpReturn);
    assert_err(&[OP_1, OP_RETURN], vec![], ScriptError::OpReturn);
}

#[test]
fn altstack_round_trip() {
    assert_stack(&[OP_1, OP_TOALTSTACK, OP_2, OP_FROMALTSTACK], &[&[2], &[1]]);
    assert_err(&[OP_FROMALTSTACK], vec![], ScriptError::AltStackUnderflow);
    assert_err(&[OP_TOALTSTACK], vec![], ScriptError::StackUnderflow { needed: 1, found: 0 });
}

#[test]
fn altstack_does_not_survive_between_scripts() {
    // `eval` runs one script, so this only checks that the altstack is emptied
    // at the start; the cross-script case lives in verify_rules.rs.
    assert_stack(&[OP_1, OP_TOALTSTACK, OP_FROMALTSTACK], &[TRUE]);
}

#[test]
fn op_dup_and_drop() {
    assert_stack(&[OP_1, OP_DUP], &[&[1], &[1]]);
    assert_stack(&[OP_1, OP_2, OP_DROP], &[&[1]]);
    assert_err(&[OP_DUP], vec![], ScriptError::StackUnderflow { needed: 1, found: 0 });
}

#[test]
fn op_ifdup_only_duplicates_truth() {
    assert_stack(&[OP_1, OP_IFDUP], &[&[1], &[1]]);
    assert_stack(&[OP_0, OP_IFDUP], &[FALSE]);
}

#[test]
fn op_depth_counts_the_stack() {
    assert_stack(&[OP_DEPTH], &[FALSE]);
    assert_stack(&[OP_1, OP_2, OP_DEPTH], &[&[1], &[2], &[2]]);
}

#[test]
fn op_nip_over_swap_tuck_rot() {
    assert_stack(&[OP_1, OP_2, OP_NIP], &[&[2]]);
    assert_stack(&[OP_1, OP_2, OP_OVER], &[&[1], &[2], &[1]]);
    assert_stack(&[OP_1, OP_2, OP_SWAP], &[&[2], &[1]]);
    assert_stack(&[OP_1, OP_2, OP_TUCK], &[&[2], &[1], &[2]]);
    assert_stack(&[OP_1, OP_2, OP_3, OP_ROT], &[&[2], &[3], &[1]]);
    assert_stack(&[OP_1, OP_2, OP_2DUP], &[&[1], &[2], &[1], &[2]]);
}

#[test]
fn stack_shuffles_underflow_precisely() {
    assert_err(&[OP_1, OP_NIP], vec![], ScriptError::StackUnderflow { needed: 2, found: 1 });
    assert_err(&[OP_1, OP_SWAP], vec![], ScriptError::StackUnderflow { needed: 2, found: 1 });
    assert_err(&[OP_1, OP_2, OP_ROT], vec![], ScriptError::StackUnderflow { needed: 3, found: 2 });
    assert_err(&[OP_1, OP_TUCK], vec![], ScriptError::StackUnderflow { needed: 2, found: 1 });
    assert_err(&[OP_1, OP_2DUP], vec![], ScriptError::StackUnderflow { needed: 2, found: 1 });
    assert_err(&[OP_OVER], vec![], ScriptError::StackUnderflow { needed: 2, found: 0 });
}

#[test]
fn op_pick_copies_and_op_roll_moves() {
    assert_stack(&[OP_1, OP_2, OP_3, OP_2, OP_PICK], &[&[1], &[2], &[3], &[1]]);
    assert_stack(&[OP_1, OP_2, OP_3, OP_2, OP_ROLL], &[&[2], &[3], &[1]]);
    assert_stack(&[OP_1, OP_0, OP_PICK], &[&[1], &[1]]);
    assert_stack(&[OP_1, OP_0, OP_ROLL], &[&[1]]);
}

#[test]
fn pick_and_roll_reject_out_of_range_indexes() {
    assert_err(
        &[OP_1, OP_2, OP_PICK],
        vec![],
        ScriptError::InvalidStackIndex { index: 2, depth: 1 },
    );
    assert_err(
        &[OP_1, OP_2, OP_ROLL],
        vec![],
        ScriptError::InvalidStackIndex { index: 2, depth: 1 },
    );
    let mut s = vec![OP_1];
    s.extend_from_slice(&push(&num(-1)));
    s.push(OP_PICK);
    assert_err(&s, vec![], ScriptError::InvalidStackIndex { index: -1, depth: 1 });
}

#[test]
fn op_size_measures_without_popping() {
    let mut s = push(&[0u8; 5]);
    s.push(OP_SIZE);
    assert_stack(&s, &[&[0u8; 5], &[5]]);
    assert_stack(&[OP_0, OP_SIZE], &[FALSE, FALSE]);
}

#[test]
fn op_equal_and_equalverify() {
    assert_stack(&[OP_1, OP_1, OP_EQUAL], &[TRUE]);
    assert_stack(&[OP_1, OP_2, OP_EQUAL], &[FALSE]);
    assert_stack(&[OP_1, OP_1, OP_EQUALVERIFY], &[]);
    assert_err(&[OP_1, OP_2, OP_EQUALVERIFY], vec![], ScriptError::EqualVerifyFailed);
    // Byte equality, not numeric: 0x00 and the empty string are different.
    let mut s = push(&[0x00]);
    s.push(OP_0);
    s.push(OP_EQUAL);
    assert_stack(&s, &[FALSE]);
}

#[test]
fn unary_arithmetic() {
    assert_stack(&[OP_1, OP_1ADD], &[&[2]]);
    assert_stack(&[OP_1, OP_1SUB], &[FALSE]);
    assert_stack(&[OP_1, OP_NEGATE], &[&[0x81]]);
    assert_stack(&[OP_1NEGATE, OP_ABS], &[&[1]]);
    assert_stack(&[OP_0, OP_NOT], &[TRUE]);
    assert_stack(&[OP_1, OP_NOT], &[FALSE]);
    assert_stack(&[OP_0, OP_0NOTEQUAL], &[FALSE]);
    assert_stack(&[OP_2, OP_0NOTEQUAL], &[TRUE]);
}

#[test]
fn binary_arithmetic() {
    assert_stack(&[OP_2, OP_3, OP_ADD], &[&[5]]);
    assert_stack(&[OP_3, OP_2, OP_SUB], &[&[1]]);
    assert_stack(&[OP_2, OP_3, OP_SUB], &[&[0x81]]);
    assert_stack(&[OP_2, OP_3, OP_MIN], &[&[2]]);
    assert_stack(&[OP_2, OP_3, OP_MAX], &[&[3]]);
}

#[test]
fn comparisons() {
    assert_stack(&[OP_1, OP_1, OP_NUMEQUAL], &[TRUE]);
    assert_stack(&[OP_1, OP_2, OP_NUMEQUAL], &[FALSE]);
    assert_stack(&[OP_1, OP_1, OP_NUMEQUALVERIFY], &[]);
    assert_err(&[OP_1, OP_2, OP_NUMEQUALVERIFY], vec![], ScriptError::NumEqualVerifyFailed);
    assert_stack(&[OP_1, OP_2, OP_NUMNOTEQUAL], &[TRUE]);
    assert_stack(&[OP_1, OP_2, OP_LESSTHAN], &[TRUE]);
    assert_stack(&[OP_2, OP_1, OP_GREATERTHAN], &[TRUE]);
    assert_stack(&[OP_2, OP_2, OP_LESSTHANOREQUAL], &[TRUE]);
    assert_stack(&[OP_2, OP_2, OP_GREATERTHANOREQUAL], &[TRUE]);
    assert_stack(&[OP_1, OP_0, OP_BOOLAND], &[FALSE]);
    assert_stack(&[OP_1, OP_1, OP_BOOLAND], &[TRUE]);
    assert_stack(&[OP_1, OP_0, OP_BOOLOR], &[TRUE]);
    assert_stack(&[OP_0, OP_0, OP_BOOLOR], &[FALSE]);
}

#[test]
fn op_within_is_half_open() {
    // 2 within [1, 3) is true.
    assert_stack(&[OP_2, OP_1, OP_3, OP_WITHIN], &[TRUE]);
    // 3 within [1, 3) is false: the upper bound is exclusive.
    assert_stack(&[OP_3, OP_1, OP_3, OP_WITHIN], &[FALSE]);
    assert_stack(&[OP_1, OP_1, OP_3, OP_WITHIN], &[TRUE]);
    assert_stack(&[OP_0, OP_1, OP_3, OP_WITHIN], &[FALSE]);
}

#[test]
fn arithmetic_operands_are_limited_to_four_bytes() {
    let mut s = push(&num(0x7fff_ffff));
    s.extend_from_slice(&push(&num(1)));
    s.push(OP_ADD);
    // The result is five bytes wide, which is legal to produce.
    let stack = run_empty(&s).unwrap();
    assert_eq!(stack, vec![vec![0x00, 0x00, 0x00, 0x80, 0x00]]);

    // ...but not legal to read back.
    let mut s2 = s.clone();
    s2.push(OP_1ADD);
    assert_eq!(run_empty(&s2), Err(ScriptError::NumTooLarge { len: 5, max: 4 }));
}

#[test]
fn non_minimal_numbers_are_rejected_where_they_are_read() {
    let mut s = push(&[0x01, 0x00]);
    s.push(OP_1ADD);
    assert_err(&s, vec![], ScriptError::NonMinimalNum);

    // Negative zero is a non-minimal zero.
    let mut s = push(&[0x80]);
    s.push(OP_1ADD);
    assert_err(&s, vec![], ScriptError::NonMinimalNum);
}

#[test]
fn hash_opcodes_produce_the_right_lengths() {
    let stack = run(&[OP_HASH160], vec![b"ferrum".to_vec()]).unwrap();
    assert_eq!(stack[0], ferrum_crypto::hash160(b"ferrum").to_vec());
    assert_eq!(stack[0].len(), 20);

    let stack = run(&[OP_SHA256], vec![b"ferrum".to_vec()]).unwrap();
    assert_eq!(stack[0], ferrum_crypto::sha256(b"ferrum").to_vec());

    let stack = run(&[OP_HASH256], vec![b"ferrum".to_vec()]).unwrap();
    assert_eq!(stack[0], ferrum_crypto::hash256(b"ferrum").as_bytes().to_vec());
    assert_eq!(stack[0].len(), 32);

    let stack = run(&[OP_RIPEMD160], vec![b"ferrum".to_vec()]).unwrap();
    assert_eq!(stack[0].len(), 20);
    // RIPEMD-160 of the empty string, the published test vector.
    let stack = run(&[OP_RIPEMD160], vec![Vec::new()]).unwrap();
    assert_eq!(hex::encode(&stack[0]), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
}

#[test]
fn op_hash256_is_not_bitcoins_double_sha256() {
    let stack = run(&[OP_HASH256], vec![b"x".to_vec()]).unwrap();
    let double_sha = ferrum_crypto::sha256(&ferrum_crypto::sha256(b"x"));
    assert_ne!(stack[0], double_sha.to_vec());
}

#[test]
fn undefined_opcodes_fail_the_script() {
    for byte in [0x4e, 0x50, 0x62, 0x65, 0x66, 0x6d, 0x7e, 0x83, 0xa8, 0xab, 0xb0, 0xb3, 0xff] {
        assert_eq!(run_empty(&[OP_1, byte]), Err(ScriptError::InvalidOpcode(byte)), "0x{byte:02x}");
    }
}

#[test]
fn arithmetic_on_an_empty_stack_underflows_rather_than_panicking() {
    for op in [
        OP_1ADD,
        OP_1SUB,
        OP_NEGATE,
        OP_ABS,
        OP_NOT,
        OP_0NOTEQUAL,
        OP_ADD,
        OP_SUB,
        OP_BOOLAND,
        OP_BOOLOR,
        OP_NUMEQUAL,
        OP_NUMNOTEQUAL,
        OP_LESSTHAN,
        OP_GREATERTHAN,
        OP_MIN,
        OP_MAX,
        OP_WITHIN,
        OP_SIZE,
        OP_HASH160,
        OP_HASH256,
        OP_SHA256,
        OP_RIPEMD160,
        OP_EQUAL,
    ] {
        let err = run_empty(&[op]).unwrap_err();
        assert!(matches!(err, ScriptError::StackUnderflow { .. }), "0x{op:02x} gave {err:?}");
    }
}

#[test]
fn op_4_and_friends_are_just_pushes() {
    assert_stack(&[OP_4], &[&[4]]);
    assert_stack(&[OP_4, OP_4, OP_ADD], &[&[8]]);
}
