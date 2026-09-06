//! The rules `verify` applies around the interpreter: push-only `script_sig`,
//! the clean-stack rule, and the shape a signature must have.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{ctx_for, pkh, public, push, script, script_sig, secret, sign_all, spending_tx};
use ferrum_crypto::hash160;
use ferrum_script::sighash::SigHashType;
use ferrum_script::{ScriptError, is_push_only, templates, verify};
use ferrum_types::{ChainId, Script};

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_NOP: u8 = 0x61;
const OP_DUP: u8 = 0x76;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
const NOT_FINAL: u32 = 0xffff_fffe;

fn check(unlock: &Script, lock: &Script) -> Result<ferrum_script::ExecStats, ScriptError> {
    let tx = spending_tx(unlock.clone(), NOT_FINAL, 0);
    let ctx = ctx_for(&tx, ChainId::DEVNET);
    verify(unlock, lock, &ctx)
}

// ---------------------------------------------------------------------------
// script_sig must be push-only — a consensus rule, not policy
// ---------------------------------------------------------------------------

#[test]
fn a_script_sig_containing_an_operation_is_rejected() {
    assert_eq!(check(&script(&[OP_1, OP_DUP]), &script(&[OP_1])), Err(ScriptError::PushOnly));
    assert_eq!(check(&script(&[OP_NOP]), &script(&[OP_1])), Err(ScriptError::PushOnly));
    assert_eq!(check(&script(&[OP_1, 0x87]), &script(&[OP_1])), Err(ScriptError::PushOnly));
}

#[test]
fn a_push_only_script_sig_is_accepted() {
    assert!(check(&script(&[OP_1]), &script(&[])).is_ok());
    assert!(check(&Script::EMPTY, &script(&[OP_1])).is_ok());
    assert!(is_push_only(&script(&[OP_0, OP_1, 0x02, 0xaa, 0xbb])));
}

#[test]
fn every_constant_push_counts_as_push_only() {
    // OP_0, OP_1NEGATE, OP_1..OP_16, direct pushes, OP_PUSHDATA1/2.
    let mut bytes = vec![OP_0, 0x4f];
    bytes.extend(0x51u8..=0x60);
    bytes.extend_from_slice(&push(&[0xaa, 0xbb]));
    bytes.extend_from_slice(&push(&[0x11u8; 100]));
    bytes.extend_from_slice(&push(&[0x22u8; 300]));
    assert!(is_push_only(&script(&bytes)));
}

#[test]
fn a_malformed_script_sig_reports_the_parse_error_not_push_only() {
    // A truncated push is a decoding failure, and the caller deserves to know
    // that rather than a generic "not push-only".
    assert_eq!(
        check(&script(&[0x05, 0x01]), &script(&[OP_1])),
        Err(ScriptError::TruncatedPush { opcode: 0x05, needed: 5, found: 1 })
    );
    assert_eq!(
        check(&script(&[0x01, 0x01]), &script(&[OP_1])),
        Err(ScriptError::NonMinimalPush { opcode: 0x01, len: 1 })
    );
}

// ---------------------------------------------------------------------------
// Clean stack
// ---------------------------------------------------------------------------

#[test]
fn a_leftover_stack_element_fails() {
    assert_eq!(check(&script(&[OP_1]), &script(&[OP_1])), Err(ScriptError::CleanStack { size: 2 }));
    assert_eq!(
        check(&script(&[OP_1, OP_1, OP_1]), &script(&[])),
        Err(ScriptError::CleanStack { size: 3 })
    );
}

#[test]
fn an_empty_final_stack_fails() {
    assert_eq!(check(&Script::EMPTY, &Script::EMPTY), Err(ScriptError::CleanStack { size: 0 }));
    assert_eq!(check(&script(&[OP_1]), &script(&[0x75])), Err(ScriptError::CleanStack { size: 0 }));
}

#[test]
fn a_single_false_element_fails_as_eval_false() {
    assert_eq!(check(&Script::EMPTY, &script(&[OP_0])), Err(ScriptError::EvalFalse));
    assert_eq!(check(&script(&[OP_0]), &Script::EMPTY), Err(ScriptError::EvalFalse));
    // Negative zero is false.
    assert_eq!(check(&script(&push(&[0x80])), &Script::EMPTY), Err(ScriptError::EvalFalse));
}

#[test]
fn any_truthy_value_satisfies_the_final_check() {
    assert!(check(&script(&push(&[0x02])), &Script::EMPTY).is_ok());
    assert!(check(&script(&push(&[0x00, 0x01])), &Script::EMPTY).is_ok());
    assert!(check(&script(&push(&[0x80, 0x00])), &Script::EMPTY).is_ok());
}

// ---------------------------------------------------------------------------
// Signature shape
// ---------------------------------------------------------------------------

#[test]
fn a_signature_of_the_wrong_length_fails_the_script() {
    let key = public(1);
    let lock = script(&{
        let mut v = push(key.as_bytes());
        v.push(OP_CHECKSIG);
        v
    });
    for len in [0usize, 1, 63, 64, 66, 100] {
        let unlock = script_sig(&[&vec![0u8; len]]);
        assert_eq!(
            check(&unlock, &lock),
            Err(ScriptError::InvalidSignatureLength(len)),
            "length {len}"
        );
    }
}

#[test]
fn an_unknown_sighash_type_byte_fails_the_script() {
    let key = public(1);
    let lock = script(&{
        let mut v = push(key.as_bytes());
        v.push(OP_CHECKSIG);
        v
    });
    for byte in [0x00u8, 0x04, 0x05, 0x7f, 0x80, 0x84, 0xff] {
        let mut signature = vec![0u8; 64];
        signature.push(byte);
        assert_eq!(
            check(&script_sig(&[&signature]), &lock),
            Err(ScriptError::InvalidSigHashType(byte)),
            "0x{byte:02x}"
        );
    }
}

#[test]
fn every_legal_sighash_type_byte_is_accepted_by_the_parser() {
    let key = public(1);
    let lock = script(&{
        let mut v = push(key.as_bytes());
        v.push(OP_CHECKSIG);
        v
    });
    for ty in SigHashType::ALL_TYPES {
        let mut signature = vec![0u8; 64];
        signature.push(ty.to_byte());
        let result = check(&script_sig(&[&signature]), &lock);
        // The zero signature never verifies, but it must fail on verification,
        // not on decoding.
        assert!(
            matches!(
                result,
                Err(ScriptError::EvalFalse) | Err(ScriptError::SigHashSingleOutOfRange { .. })
            ),
            "{ty} gave {result:?}"
        );
    }
}

#[test]
fn a_public_key_of_the_wrong_length_fails_the_script() {
    let lock = script(&[OP_CHECKSIG]);
    let mut signature = vec![0u8; 64];
    signature.push(0x01);
    for len in [0usize, 1, 31, 33, 64] {
        let unlock = script_sig(&[&signature, &vec![7u8; len]]);
        assert_eq!(check(&unlock, &lock), Err(ScriptError::InvalidPublicKey), "length {len}");
    }
}

#[test]
fn a_32_byte_value_that_is_not_a_point_fails_the_script() {
    let lock = script(&[OP_CHECKSIG]);
    let mut signature = vec![0u8; 64];
    signature.push(0x01);
    // The field prime is not a valid x coordinate.
    let not_a_point = [0xffu8; 32];
    let unlock = script_sig(&[&signature, &not_a_point]);
    assert_eq!(check(&unlock, &lock), Err(ScriptError::InvalidPublicKey));
}

#[test]
fn checksigverify_fails_hard_rather_than_pushing_false() {
    let key = secret(2);
    let mut lock_bytes = push(key.public_key().as_bytes());
    lock_bytes.push(OP_CHECKSIGVERIFY);
    lock_bytes.push(OP_1);
    let lock = script(&lock_bytes);

    // A well-formed but wrong signature.
    let other = secret(3);
    let tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&other, &tx, &lock, ChainId::DEVNET);
    assert_eq!(check(&script_sig(&[&signature]), &lock), Err(ScriptError::CheckSigVerifyFailed));
}

#[test]
fn checkmultisigverify_fails_hard_rather_than_pushing_false() {
    let key = secret(2);
    let mut lock_bytes = vec![OP_1];
    lock_bytes.extend_from_slice(&push(key.public_key().as_bytes()));
    lock_bytes.push(OP_1);
    lock_bytes.push(OP_CHECKMULTISIGVERIFY);
    lock_bytes.push(OP_1);
    let lock = script(&lock_bytes);

    let other = secret(3);
    let tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&other, &tx, &lock, ChainId::DEVNET);
    assert_eq!(
        check(&script_sig(&[&signature]), &lock),
        Err(ScriptError::CheckMultiSigVerifyFailed)
    );
}

#[test]
fn a_zero_of_zero_multisig_succeeds_trivially() {
    // Degenerate but well defined: no keys, no signatures, nothing to check.
    let lock = script(&[OP_0, OP_0, 0xae]);
    assert!(check(&Script::EMPTY, &lock).is_ok());
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[test]
fn stats_report_what_the_input_cost() {
    let key = secret(4);
    let lock = templates::p2pkh(&hash160(key.public_key().as_bytes()));
    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&key, &tx, &lock, ChainId::DEVNET);
    tx.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);

    let ctx = ctx_for(&tx, ChainId::DEVNET);
    let stats = verify(&tx.inputs[0].script_sig, &lock, &ctx).unwrap();
    // OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG.
    assert_eq!(stats.ops, 4);
    assert_eq!(stats.sig_checks, 1);
    // sig, pubkey, the duplicate and the pushed hash all coexist for one step.
    assert_eq!(stats.max_stack, 4);
}

#[test]
fn the_p2sh_hash_is_the_tagged_script_hash_not_a_double_sha() {
    let redeem = templates::p2pkh(&pkh(5));
    let expected = ferrum_crypto::hash256(redeem.as_bytes());
    assert_eq!(templates::p2sh_of(&redeem), templates::p2sh(&expected));

    let double_sha = ferrum_crypto::sha256(&ferrum_crypto::sha256(redeem.as_bytes()));
    assert_ne!(expected.as_bytes(), &double_sha);
}

#[test]
fn op_2_is_not_a_valid_script_pubkey_on_its_own_but_is_truthy() {
    // Sanity: a bare `OP_2` leaves one truthy element, which passes. This is
    // what makes the clean-stack rule the only thing standing between a valid
    // spend and a stack full of junk.
    assert!(check(&Script::EMPTY, &script(&[OP_2])).is_ok());
}
