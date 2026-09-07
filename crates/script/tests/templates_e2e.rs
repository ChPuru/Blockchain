//! End-to-end spends: build a real `Transaction`, sign it with `ferrum-crypto`,
//! and run `verify` over the result.
//!
//! Every template in CONTRACT §5.6 is exercised here, and each one is also
//! shown *failing* for the right reason — a test that only proves the happy
//! path passes when the signature check has been deleted.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{
    INPUT_VALUE, ctx_for, pkh, public, script, script_sig, secret, sign, sign_all, spending_tx,
};
use ferrum_crypto::{hash160, hash256};
use ferrum_script::sighash::SigHashType;
use ferrum_script::{ExecCtx, ScriptError, ScriptType, templates, verify};
use ferrum_types::{ChainId, LOCKTIME_THRESHOLD, Script, Transaction};

const NOT_FINAL: u32 = 0xffff_fffe;

/// Run `verify` for input 0 of `tx` against `script_pubkey` on `chain`.
fn check(
    tx: &Transaction,
    script_pubkey: &Script,
    chain: ChainId,
) -> Result<ferrum_script::ExecStats, ScriptError> {
    let ctx = ctx_for(tx, chain);
    verify(&tx.inputs[0].script_sig, script_pubkey, &ctx)
}

// ---------------------------------------------------------------------------
// P2PK
// ---------------------------------------------------------------------------

#[test]
fn p2pk_round_trip() {
    let key = secret(1);
    let script_pubkey = templates::p2pk(&key.public_key());
    assert_eq!(templates::classify(&script_pubkey), ScriptType::P2PK);

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&key, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&signature]);

    let stats = check(&tx, &script_pubkey, ChainId::MAINNET).unwrap();
    assert_eq!(stats.sig_checks, 1);
    assert_eq!(stats.ops, 1);
}

#[test]
fn p2pk_rejects_the_wrong_key() {
    let key = secret(1);
    let script_pubkey = templates::p2pk(&public(2));

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&key, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&signature]);

    assert_eq!(check(&tx, &script_pubkey, ChainId::MAINNET), Err(ScriptError::EvalFalse));
}

// ---------------------------------------------------------------------------
// P2PKH
// ---------------------------------------------------------------------------

#[test]
fn p2pkh_round_trip() {
    let key = secret(3);
    let script_pubkey = templates::p2pkh(&hash160(key.public_key().as_bytes()));
    assert_eq!(templates::classify(&script_pubkey), ScriptType::P2PKH);

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&key, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);

    let stats = check(&tx, &script_pubkey, ChainId::MAINNET).unwrap();
    assert_eq!(stats.sig_checks, 1);
}

#[test]
fn p2pkh_rejects_a_key_that_hashes_wrong() {
    let key = secret(3);
    let script_pubkey = templates::p2pkh(&pkh(4));

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&key, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);

    assert_eq!(check(&tx, &script_pubkey, ChainId::MAINNET), Err(ScriptError::EqualVerifyFailed));
}

#[test]
fn p2pkh_rejects_a_tampered_output() {
    let key = secret(3);
    let script_pubkey = templates::p2pkh(&hash160(key.public_key().as_bytes()));

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&key, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);
    assert!(check(&tx, &script_pubkey, ChainId::MAINNET).is_ok());

    // Move the money somewhere else after signing: SIGHASH_ALL committed to it.
    tx.outputs[0].value = ferrum_types::Amount::from_grains(1);
    assert_eq!(check(&tx, &script_pubkey, ChainId::MAINNET), Err(ScriptError::EvalFalse));
}

#[test]
fn p2pkh_rejects_a_tampered_input_value() {
    let key = secret(3);
    let script_pubkey = templates::p2pkh(&hash160(key.public_key().as_bytes()));

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&key, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);

    // The sighash commits to the amount being spent — this is the whole point
    // of the BIP-143 shape.
    let ctx = ExecCtx {
        input_value: ferrum_types::Amount::from_grains(1),
        ..ctx_for(&tx, ChainId::MAINNET)
    };
    assert_eq!(verify(&tx.inputs[0].script_sig, &script_pubkey, &ctx), Err(ScriptError::EvalFalse));
}

// ---------------------------------------------------------------------------
// Cross-chain replay — the required test
// ---------------------------------------------------------------------------

#[test]
fn a_signature_made_under_chain_id_2_fails_under_chain_id_1() {
    let key = secret(5);
    let script_pubkey = templates::p2pkh(&hash160(key.public_key().as_bytes()));

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    // Signed for testnet.
    let signature = sign_all(&key, &tx, &script_pubkey, ChainId(2));
    tx.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);

    assert!(check(&tx, &script_pubkey, ChainId(2)).is_ok(), "valid on its own chain");
    assert_eq!(
        check(&tx, &script_pubkey, ChainId(1)),
        Err(ScriptError::EvalFalse),
        "a testnet signature must not be replayable on mainnet"
    );
    assert_eq!(check(&tx, &script_pubkey, ChainId(3)), Err(ScriptError::EvalFalse));
}

#[test]
fn cross_chain_replay_is_blocked_for_p2pk_too() {
    let key = secret(6);
    let script_pubkey = templates::p2pk(&key.public_key());

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&key, &tx, &script_pubkey, ChainId(2));
    tx.inputs[0].script_sig = script_sig(&[&signature]);

    assert!(check(&tx, &script_pubkey, ChainId(2)).is_ok());
    assert_eq!(check(&tx, &script_pubkey, ChainId(1)), Err(ScriptError::EvalFalse));
}

// ---------------------------------------------------------------------------
// P2SH
// ---------------------------------------------------------------------------

#[test]
fn p2sh_round_trip_over_a_p2pkh_redeem_script() {
    let key = secret(7);
    let redeem = templates::p2pkh(&hash160(key.public_key().as_bytes()));
    let script_pubkey = templates::p2sh_of(&redeem);
    assert_eq!(templates::classify(&script_pubkey), ScriptType::P2SH);

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    // The redeem script, not the P2SH wrapper, is the `script_code`.
    let signature = sign_all(&key, &tx, &redeem, ChainId::MAINNET);
    tx.inputs[0].script_sig =
        script_sig(&[&signature, key.public_key().as_bytes(), redeem.as_bytes()]);

    let stats = check(&tx, &script_pubkey, ChainId::MAINNET).unwrap();
    assert_eq!(stats.sig_checks, 1);
}

#[test]
fn p2sh_rejects_a_redeem_script_with_the_wrong_hash() {
    let key = secret(7);
    let redeem = templates::p2pkh(&hash160(key.public_key().as_bytes()));
    let other = templates::p2pkh(&pkh(8));
    let script_pubkey = templates::p2sh_of(&other);

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&key, &tx, &redeem, ChainId::MAINNET);
    tx.inputs[0].script_sig =
        script_sig(&[&signature, key.public_key().as_bytes(), redeem.as_bytes()]);

    // OP_EQUAL leaves false, so the outer script fails before the redeem script
    // ever runs.
    assert_eq!(check(&tx, &script_pubkey, ChainId::MAINNET), Err(ScriptError::EvalFalse));
}

#[test]
fn p2sh_does_not_recurse() {
    // A redeem script that is itself shaped like P2SH executes as an ordinary
    // script: `OP_HASH256 <h> OP_EQUAL` over a pushed preimage.
    let preimage = b"ferrum-p2sh-non-recursion".to_vec();
    let inner_hash = hash256(&preimage);
    let redeem = templates::p2sh(&inner_hash);
    let script_pubkey = templates::p2sh_of(&redeem);

    let tx = spending_tx(script_sig(&[&preimage, redeem.as_bytes()]), NOT_FINAL, 0);
    // If P2SH recursed, the interpreter would try to take `preimage` as a
    // second redeem script and fail; because it does not, the redeem script
    // simply evaluates to true.
    assert!(check(&tx, &script_pubkey, ChainId::DEVNET).is_ok());
}

#[test]
fn p2sh_redeem_script_must_leave_a_clean_stack() {
    // A redeem script that leaves two elements fails the clean-stack rule even
    // though both are true.
    let redeem = script(&[0x51, 0x51]);
    let script_pubkey = templates::p2sh_of(&redeem);
    let tx = spending_tx(script_sig(&[redeem.as_bytes()]), NOT_FINAL, 0);
    assert_eq!(
        check(&tx, &script_pubkey, ChainId::DEVNET),
        Err(ScriptError::CleanStack { size: 2 })
    );
}

// ---------------------------------------------------------------------------
// 2-of-3 multisig
// ---------------------------------------------------------------------------

#[test]
fn two_of_three_multisig_round_trip() {
    let keys = [secret(11), secret(12), secret(13)];
    let publics: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let script_pubkey = templates::multisig(2, &publics).unwrap();
    assert_eq!(templates::classify(&script_pubkey), ScriptType::Multisig { k: 2, n: 3 });

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let sig1 = sign_all(&keys[0], &tx, &script_pubkey, ChainId::MAINNET);
    let sig3 = sign_all(&keys[2], &tx, &script_pubkey, ChainId::MAINNET);
    // Signatures must appear in the same order as their keys.
    tx.inputs[0].script_sig = script_sig(&[&sig1, &sig3]);

    let stats = check(&tx, &script_pubkey, ChainId::MAINNET).unwrap();
    // key1 matches immediately, key3 is found after probing key2.
    assert_eq!(stats.sig_checks, 3);
}

#[test]
fn multisig_needs_no_dummy_element() {
    // Bitcoin would need an extra `OP_0` at the bottom of the `script_sig`.
    // Supplying one here leaves it on the stack and breaks the clean-stack rule.
    let keys = [secret(11), secret(12), secret(13)];
    let publics: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let script_pubkey = templates::multisig(2, &publics).unwrap();

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let sig1 = sign_all(&keys[0], &tx, &script_pubkey, ChainId::MAINNET);
    let sig2 = sign_all(&keys[1], &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&[], &sig1, &sig2]);

    assert_eq!(
        check(&tx, &script_pubkey, ChainId::MAINNET),
        Err(ScriptError::CleanStack { size: 2 })
    );
}

#[test]
fn multisig_rejects_out_of_order_signatures() {
    let keys = [secret(11), secret(12), secret(13)];
    let publics: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let script_pubkey = templates::multisig(2, &publics).unwrap();

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let sig1 = sign_all(&keys[0], &tx, &script_pubkey, ChainId::MAINNET);
    let sig3 = sign_all(&keys[2], &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&sig3, &sig1]);

    assert_eq!(check(&tx, &script_pubkey, ChainId::MAINNET), Err(ScriptError::EvalFalse));
}

#[test]
fn multisig_rejects_a_duplicate_signature() {
    let keys = [secret(11), secret(12), secret(13)];
    let publics: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let script_pubkey = templates::multisig(2, &publics).unwrap();

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let sig1 = sign_all(&keys[0], &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&sig1, &sig1]);

    assert_eq!(check(&tx, &script_pubkey, ChainId::MAINNET), Err(ScriptError::EvalFalse));
}

#[test]
fn one_of_one_multisig_round_trip() {
    let key = secret(14);
    let script_pubkey = templates::multisig(1, &[key.public_key()]).unwrap();
    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let sig = sign_all(&key, &tx, &script_pubkey, ChainId::DEVNET);
    tx.inputs[0].script_sig = script_sig(&[&sig]);
    assert!(check(&tx, &script_pubkey, ChainId::DEVNET).is_ok());
}

#[test]
fn a_p2sh_wrapped_multisig_is_how_it_is_used_in_practice() {
    let keys = [secret(11), secret(12), secret(13)];
    let publics: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let redeem = templates::multisig(2, &publics).unwrap();
    let script_pubkey = templates::p2sh_of(&redeem);

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let sig1 = sign_all(&keys[0], &tx, &redeem, ChainId::MAINNET);
    let sig2 = sign_all(&keys[1], &tx, &redeem, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&sig1, &sig2, redeem.as_bytes()]);

    assert!(check(&tx, &script_pubkey, ChainId::MAINNET).is_ok());
}

// ---------------------------------------------------------------------------
// CLTV timelock
// ---------------------------------------------------------------------------

#[test]
fn cltv_timelock_round_trip_by_height() {
    let key = secret(21);
    let script_pubkey = templates::cltv_p2pkh(600_000, &hash160(key.public_key().as_bytes()));
    assert_eq!(templates::classify(&script_pubkey), ScriptType::Cltv);

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 600_000);
    let signature = sign_all(&key, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);

    assert!(check(&tx, &script_pubkey, ChainId::MAINNET).is_ok());
}

#[test]
fn cltv_rejects_a_transaction_locked_too_early() {
    let key = secret(21);
    let script_pubkey = templates::cltv_p2pkh(600_000, &hash160(key.public_key().as_bytes()));

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 599_999);
    let signature = sign_all(&key, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);

    assert_eq!(
        check(&tx, &script_pubkey, ChainId::MAINNET),
        Err(ScriptError::UnsatisfiedLockTime { required: 600_000, tx: 599_999 })
    );
}

#[test]
fn cltv_round_trip_with_a_locktime_that_needs_five_bytes() {
    // A locktime at or above 0x8000_0000 needs the extra sign byte, which is
    // why the operand limit is five and not MAX_NUM_SIZE. The VM executes it,
    // so `classify` has to agree — otherwise the mempool calls this output
    // NonStandard and refuses to relay a script the library itself builds.
    // Unix timestamps cross that boundary in January 2038.
    let key = secret(23);
    let deadline: u32 = 0x8000_0000;
    let script_pubkey = templates::cltv_p2pkh(deadline, &hash160(key.public_key().as_bytes()));
    assert_eq!(templates::classify(&script_pubkey), ScriptType::Cltv);

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, deadline);
    let signature = sign_all(&key, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);

    assert!(check(&tx, &script_pubkey, ChainId::MAINNET).is_ok());

    // And one second early still fails on the locktime, not on the encoding.
    let mut early = spending_tx(Script::EMPTY, NOT_FINAL, deadline - 1);
    let signature = sign_all(&key, &early, &script_pubkey, ChainId::MAINNET);
    early.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);
    assert_eq!(
        check(&early, &script_pubkey, ChainId::MAINNET),
        Err(ScriptError::UnsatisfiedLockTime { required: u64::from(deadline), tx: deadline - 1 })
    );
}

#[test]
fn cltv_round_trip_by_timestamp() {
    let key = secret(22);
    let deadline = LOCKTIME_THRESHOLD + 86_400;
    let script_pubkey = templates::cltv_p2pkh(deadline, &hash160(key.public_key().as_bytes()));

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, deadline);
    let signature = sign_all(&key, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);

    assert!(check(&tx, &script_pubkey, ChainId::MAINNET).is_ok());
}

// ---------------------------------------------------------------------------
// HTLC, both branches
// ---------------------------------------------------------------------------

/// `(script_pubkey, preimage)` for an HTLC between key `receiver` and key
/// `refund`, timing out at `timeout`.
fn htlc_pair(receiver: u8, refund: u8, timeout: u32) -> (Script, Vec<u8>) {
    let preimage = b"ferrum htlc preimage".to_vec();
    let hash = hash160(&preimage);
    let s = templates::htlc(&hash, &pkh(receiver), timeout, &pkh(refund));
    (s, preimage)
}

#[test]
fn htlc_preimage_branch_round_trip() {
    let receiver = secret(31);
    let (script_pubkey, preimage) = htlc_pair(31, 32, 700_000);
    assert_eq!(templates::classify(&script_pubkey), ScriptType::Htlc);

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&receiver, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig =
        script_sig(&[&signature, receiver.public_key().as_bytes(), &preimage, &[1u8]]);

    let stats = check(&tx, &script_pubkey, ChainId::MAINNET).unwrap();
    assert_eq!(stats.sig_checks, 1);
}

#[test]
fn htlc_preimage_branch_rejects_a_wrong_preimage() {
    let receiver = secret(31);
    let (script_pubkey, _) = htlc_pair(31, 32, 700_000);

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&receiver, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig =
        script_sig(&[&signature, receiver.public_key().as_bytes(), b"not the preimage", &[1u8]]);

    assert_eq!(check(&tx, &script_pubkey, ChainId::MAINNET), Err(ScriptError::EqualVerifyFailed));
}

#[test]
fn htlc_timeout_refund_branch_round_trip() {
    let refund = secret(32);
    let (script_pubkey, _) = htlc_pair(31, 32, 700_000);

    // The refund path needs the transaction itself to be locked to the timeout.
    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 700_000);
    let signature = sign_all(&refund, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&signature, refund.public_key().as_bytes(), &[]]);

    let stats = check(&tx, &script_pubkey, ChainId::MAINNET).unwrap();
    assert_eq!(stats.sig_checks, 1);
}

#[test]
fn htlc_refund_is_impossible_before_the_timeout() {
    let refund = secret(32);
    let (script_pubkey, _) = htlc_pair(31, 32, 700_000);

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 699_999);
    let signature = sign_all(&refund, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&signature, refund.public_key().as_bytes(), &[]]);

    assert_eq!(
        check(&tx, &script_pubkey, ChainId::MAINNET),
        Err(ScriptError::UnsatisfiedLockTime { required: 700_000, tx: 699_999 })
    );
}

#[test]
fn htlc_receiver_cannot_use_the_refund_branch() {
    let receiver = secret(31);
    let (script_pubkey, _) = htlc_pair(31, 32, 700_000);

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 700_000);
    let signature = sign_all(&receiver, &tx, &script_pubkey, ChainId::MAINNET);
    tx.inputs[0].script_sig = script_sig(&[&signature, receiver.public_key().as_bytes(), &[]]);

    assert_eq!(check(&tx, &script_pubkey, ChainId::MAINNET), Err(ScriptError::EqualVerifyFailed));
}

#[test]
fn htlc_branch_selector_must_be_minimal() {
    let receiver = secret(31);
    let (script_pubkey, preimage) = htlc_pair(31, 32, 700_000);

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign_all(&receiver, &tx, &script_pubkey, ChainId::MAINNET);
    // 0x02 is truthy but is not `{0x01}`.
    tx.inputs[0].script_sig =
        script_sig(&[&signature, receiver.public_key().as_bytes(), &preimage, &[2u8]]);

    assert_eq!(check(&tx, &script_pubkey, ChainId::MAINNET), Err(ScriptError::MinimalIf));
}

// ---------------------------------------------------------------------------
// Sighash types, end to end
// ---------------------------------------------------------------------------

#[test]
fn sighash_none_lets_outputs_change_after_signing() {
    let key = secret(41);
    let script_pubkey = templates::p2pkh(&hash160(key.public_key().as_bytes()));

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature =
        sign(&key, &tx, 0, &script_pubkey, INPUT_VALUE, ChainId::MAINNET, SigHashType::NONE);
    tx.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);
    assert!(check(&tx, &script_pubkey, ChainId::MAINNET).is_ok());

    tx.outputs[0].value = ferrum_types::Amount::from_grains(42);
    assert!(check(&tx, &script_pubkey, ChainId::MAINNET).is_ok(), "NONE ignores outputs");
}

#[test]
fn sighash_single_commits_to_the_matching_output_only() {
    let key = secret(42);
    let script_pubkey = templates::p2pkh(&hash160(key.public_key().as_bytes()));

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    tx.outputs
        .push(ferrum_types::TxOut::new(ferrum_types::Amount::from_grains(5), script(&[0x51])));
    let signature =
        sign(&key, &tx, 0, &script_pubkey, INPUT_VALUE, ChainId::MAINNET, SigHashType::SINGLE);
    tx.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);
    assert!(check(&tx, &script_pubkey, ChainId::MAINNET).is_ok());

    // Output 1 is not committed to.
    tx.outputs[1].value = ferrum_types::Amount::from_grains(999);
    assert!(check(&tx, &script_pubkey, ChainId::MAINNET).is_ok());

    // Output 0 is.
    tx.outputs[0].value = ferrum_types::Amount::from_grains(999);
    assert_eq!(check(&tx, &script_pubkey, ChainId::MAINNET), Err(ScriptError::EvalFalse));
}

#[test]
fn sighash_single_without_a_matching_output_is_an_error_in_script_too() {
    let key = secret(43);
    let script_pubkey = templates::p2pkh(&hash160(key.public_key().as_bytes()));

    // Two inputs, one output: input 1 has nothing to sign.
    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    tx.inputs.push(ferrum_types::TxIn {
        prev_out: ferrum_types::OutPoint::new(ferrum_types::Txid::from_bytes([2u8; 32]), 1),
        script_sig: Script::EMPTY,
        sequence: NOT_FINAL,
    });

    // A syntactically valid signature carrying SIGHASH_SINGLE.
    let mut signature = vec![0u8; 64];
    signature.push(SigHashType::SINGLE.to_byte());
    let unlock = script_sig(&[&signature, key.public_key().as_bytes()]);

    let ctx = ExecCtx { input_index: 1, ..ctx_for(&tx, ChainId::MAINNET) };
    assert_eq!(
        verify(&unlock, &script_pubkey, &ctx),
        Err(ScriptError::SigHashSingleOutOfRange { input_index: 1, outputs: 1 })
    );
}

#[test]
fn anyonecanpay_survives_a_new_input() {
    let key = secret(44);
    let script_pubkey = templates::p2pkh(&hash160(key.public_key().as_bytes()));

    let mut tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let signature = sign(
        &key,
        &tx,
        0,
        &script_pubkey,
        INPUT_VALUE,
        ChainId::MAINNET,
        SigHashType::ALL_ANYONECANPAY,
    );
    tx.inputs[0].script_sig = script_sig(&[&signature, key.public_key().as_bytes()]);
    assert!(check(&tx, &script_pubkey, ChainId::MAINNET).is_ok());

    tx.inputs.push(ferrum_types::TxIn {
        prev_out: ferrum_types::OutPoint::new(ferrum_types::Txid::from_bytes([9u8; 32]), 3),
        script_sig: Script::EMPTY,
        sequence: 7,
    });
    assert!(
        check(&tx, &script_pubkey, ChainId::MAINNET).is_ok(),
        "ANYONECANPAY does not commit to other inputs"
    );
}
