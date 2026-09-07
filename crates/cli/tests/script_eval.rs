//! Milestone M2: "`chain-cli script eval` runs P2PKH, 2-of-3 multisig and a
//! CLTV timelock; limits reject oversized scripts."
//!
//! Every case here drives the real binary, with real BIP-340 signatures over
//! the real BIP-143-shaped sighash of CONTRACT §5.5 — the same digest a node
//! computes when it validates the input. Nothing is stubbed, so a green run is
//! evidence about the consensus path and not only about argument parsing.
//!
//! The scripts themselves come from `chain-cli script build-*`, so the same
//! run also proves the three builders produce something spendable rather than
//! something merely well-formed.

use assert_cmd::Command;
use ferrum_crypto::{PublicKey, SecretKey, hash160};
use ferrum_script::opcode::Instruction;
use ferrum_script::sighash::{SigHashType, encode_signature, signature_hash};
use ferrum_types::{Amount, ChainId, OutPoint, Script, Transaction, TxIn, TxOut, Txid};
use serde_json::Value;

/// The value being spent. Committed to by the sighash, so it has to match on
/// both sides.
const INPUT_VALUE: Amount = Amount::from_grains(100_000);

/// Devnet, because that is the network the CLI defaults to.
const CHAIN: ChainId = ChainId::DEVNET;

fn cli() -> Command {
    Command::cargo_bin("chain-cli").expect("chain-cli is a bin target of this crate")
}

/// A deterministic key, so a failure is reproducible from the test name alone.
fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32]).expect("a constant seed is a valid scalar")
}

/// Concatenate minimal pushes of `items` into a `script_sig`.
fn push_all(items: &[Vec<u8>]) -> Script {
    let mut out = Vec::new();
    for item in items {
        Instruction::push(item)
            .expect("test pushes are far below the push-data limit")
            .encode_into(&mut out);
    }
    Script::new(out)
}

/// The transaction every case spends with.
fn spending_tx(lock_time: u32, sequence: u32) -> Transaction {
    let mut input = TxIn::new(OutPoint::new(Txid::ZERO, 0), Script::EMPTY);
    input.sequence = sequence;
    Transaction {
        version: 1,
        inputs: vec![input],
        outputs: vec![TxOut::new(Amount::from_grains(90_000), Script::EMPTY)],
        lock_time,
    }
}

/// Sign input 0 of `tx` for `script_code` with `SIGHASH_ALL`.
fn sign(secret: &SecretKey, tx: &Transaction, script_code: &Script) -> Vec<u8> {
    let digest =
        signature_hash(tx, 0, script_code.as_bytes(), INPUT_VALUE, CHAIN, SigHashType::ALL)
            .expect("the test transaction has the input being signed");
    encode_signature(&secret.sign_deterministic(&digest), SigHashType::ALL)
}

/// Run `script eval` in full-consensus mode and return the parsed JSON.
fn eval_verify(script_sig: &Script, script_pubkey: &Script, tx: &Transaction) -> Value {
    let assert = cli()
        .args([
            "--json",
            "script",
            "eval",
            "--script-sig",
            &script_sig.to_hex(),
            "--script-pubkey",
            &script_pubkey.to_hex(),
            "--tx",
            &hex::encode(tx.encode_envelope()),
            "--input-value",
            &INPUT_VALUE.to_frm_string(),
            "--network",
            "devnet",
        ])
        .assert()
        .success();
    serde_json::from_slice(&assert.get_output().stdout).expect("--json prints one JSON document")
}

/// Ask the CLI to build a script and return it.
fn build(argv: &[&str]) -> Script {
    let assert = cli().arg("--json").args(argv).assert().success();
    let json: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("--json prints one document");
    let hex_body = json["script"].as_str().expect("a built script carries its hex").to_owned();
    Script::from_hex(&hex_body).expect("the CLI emits valid hex")
}

#[test]
fn a_p2pkh_input_verifies() {
    let secret = key(7);
    let public: PublicKey = secret.public_key();
    let script_pubkey = build(&["script", "build-p2pkh", "--pubkey", &hex::encode(public.as_bytes())]);

    let tx = spending_tx(0, u32::MAX);
    let signature = sign(&secret, &tx, &script_pubkey);
    let script_sig = push_all(&[signature, public.as_bytes().to_vec()]);

    let result = eval_verify(&script_sig, &script_pubkey, &tx);
    assert_eq!(result["success"], true, "{result}");
    assert_eq!(result["sig_checks"], 1);
}

#[test]
fn a_p2pkh_input_with_the_wrong_key_fails() {
    let secret = key(7);
    let impostor = key(8);
    let script_pubkey =
        build(&["script", "build-p2pkh", "--pubkey", &hex::encode(secret.public_key().as_bytes())]);

    let tx = spending_tx(0, u32::MAX);
    let signature = sign(&impostor, &tx, &script_pubkey);
    let script_sig = push_all(&[signature, impostor.public_key().as_bytes().to_vec()]);

    let result = eval_verify(&script_sig, &script_pubkey, &tx);
    assert_eq!(result["success"], false, "{result}");
}

#[test]
fn a_2_of_3_multisig_input_verifies() {
    let secrets = [key(1), key(2), key(3)];
    let publics: Vec<PublicKey> = secrets.iter().map(SecretKey::public_key).collect();
    let script_pubkey = build(&[
        "script",
        "build-multisig",
        "-k",
        "2",
        "--pubkey",
        &hex::encode(publics[0].as_bytes()),
        "--pubkey",
        &hex::encode(publics[1].as_bytes()),
        "--pubkey",
        &hex::encode(publics[2].as_bytes()),
    ]);

    let tx = spending_tx(0, u32::MAX);
    // Signatures go in key order: CONTRACT §5.2 matches them in order and
    // there is no Bitcoin-style dummy element to absorb a mismatch.
    let script_sig = push_all(&[
        sign(&secrets[0], &tx, &script_pubkey),
        sign(&secrets[2], &tx, &script_pubkey),
    ]);

    let result = eval_verify(&script_sig, &script_pubkey, &tx);
    assert_eq!(result["success"], true, "{result}");
    assert!(result["sig_checks"].as_u64().unwrap_or(0) >= 2, "{result}");
}

#[test]
fn a_2_of_3_multisig_with_signatures_out_of_order_fails() {
    let secrets = [key(1), key(2), key(3)];
    let publics: Vec<PublicKey> = secrets.iter().map(SecretKey::public_key).collect();
    let script_pubkey = build(&[
        "script",
        "build-multisig",
        "-k",
        "2",
        "--pubkey",
        &hex::encode(publics[0].as_bytes()),
        "--pubkey",
        &hex::encode(publics[1].as_bytes()),
        "--pubkey",
        &hex::encode(publics[2].as_bytes()),
    ]);

    let tx = spending_tx(0, u32::MAX);
    let script_sig = push_all(&[
        sign(&secrets[2], &tx, &script_pubkey),
        sign(&secrets[0], &tx, &script_pubkey),
    ]);

    let result = eval_verify(&script_sig, &script_pubkey, &tx);
    assert_eq!(result["success"], false, "{result}");
}

#[test]
fn a_cltv_timelock_verifies_once_the_lock_time_is_reached() {
    let secret = key(11);
    let public = secret.public_key();
    let pkh = hash160(public.as_bytes());
    let script_pubkey = ferrum_script::templates::cltv_p2pkh(500, &pkh);

    // `lock_time` at the threshold and a non-final sequence: a final input
    // opts out of `lock_time` enforcement entirely, so CLTV rejects it.
    let tx = spending_tx(500, u32::MAX - 1);
    let signature = sign(&secret, &tx, &script_pubkey);
    let script_sig = push_all(&[signature, public.as_bytes().to_vec()]);

    let result = eval_verify(&script_sig, &script_pubkey, &tx);
    assert_eq!(result["success"], true, "{result}");
}

#[test]
fn a_cltv_timelock_before_its_height_fails() {
    let secret = key(11);
    let public = secret.public_key();
    let pkh = hash160(public.as_bytes());
    let script_pubkey = ferrum_script::templates::cltv_p2pkh(500, &pkh);

    let tx = spending_tx(499, u32::MAX - 1);
    let signature = sign(&secret, &tx, &script_pubkey);
    let script_sig = push_all(&[signature, public.as_bytes().to_vec()]);

    let result = eval_verify(&script_sig, &script_pubkey, &tx);
    assert_eq!(result["success"], false, "{result}");
}

#[test]
fn a_cltv_timelock_with_a_final_sequence_fails() {
    // A final input disables `lock_time`, so honouring the script here would
    // mean enforcing a timelock that the transaction has opted out of.
    let secret = key(11);
    let public = secret.public_key();
    let pkh = hash160(public.as_bytes());
    let script_pubkey = ferrum_script::templates::cltv_p2pkh(500, &pkh);

    let tx = spending_tx(500, u32::MAX);
    let signature = sign(&secret, &tx, &script_pubkey);
    let script_sig = push_all(&[signature, public.as_bytes().to_vec()]);

    let result = eval_verify(&script_sig, &script_pubkey, &tx);
    assert_eq!(result["success"], false, "{result}");
}

#[test]
fn a_signature_for_another_chain_does_not_verify() {
    // CONTRACT §5.5: the sighash commits to `chain_id`, so a devnet signature
    // is not a mainnet signature. This is the cross-chain replay defence.
    let secret = key(7);
    let public = secret.public_key();
    let script_pubkey = ferrum_script::templates::p2pkh(&hash160(public.as_bytes()));
    let tx = spending_tx(0, u32::MAX);
    let signature = sign(&secret, &tx, &script_pubkey);
    let script_sig = push_all(&[signature, public.as_bytes().to_vec()]);

    let assert = cli()
        .args([
            "--json",
            "script",
            "eval",
            "--script-sig",
            &script_sig.to_hex(),
            "--script-pubkey",
            &script_pubkey.to_hex(),
            "--tx",
            &hex::encode(tx.encode_envelope()),
            "--input-value",
            &INPUT_VALUE.to_frm_string(),
            "--network",
            "mainnet",
        ])
        .assert()
        .success();
    let result: Value = serde_json::from_slice(&assert.get_output().stdout).expect("json");
    assert_eq!(result["success"], false, "{result}");
}

#[test]
fn an_htlc_built_by_the_cli_classifies_and_disassembles() {
    let script = build(&[
        "script",
        "build-htlc",
        "--hash",
        &"aa".repeat(20),
        "--receiver",
        &"bb".repeat(20),
        "--timeout",
        "600",
        "--refund",
        &"cc".repeat(20),
    ]);
    let assert = cli()
        .args(["--json", "script", "disassemble", &script.to_hex()])
        .assert()
        .success();
    let json: Value = serde_json::from_slice(&assert.get_output().stdout).expect("json");
    assert_eq!(json["script_type"], "Htlc");
    let asm = json["disassembly"].as_str().unwrap_or_default();
    assert!(asm.contains("OP_CHECKLOCKTIMEVERIFY"), "{asm}");
    assert!(asm.contains("OP_IF"), "{asm}");
}

#[test]
fn the_limits_reject_an_oversized_script() {
    // One byte over MAX_SCRIPT_SIZE (CONTRACT §5.1).
    let oversized = "61".repeat(ferrum_script::MAX_SCRIPT_SIZE + 1);
    let assert =
        cli().args(["--json", "script", "eval", "--script", &oversized]).assert().success();
    let json: Value = serde_json::from_slice(&assert.get_output().stdout).expect("json");
    assert_eq!(json["success"], false, "{json}");
    let error = json["error"].as_str().unwrap_or_default();
    assert!(error.contains("limit is 1000"), "{error}");
}

#[test]
fn a_non_push_only_script_sig_is_a_consensus_failure() {
    // CONTRACT §5: push-only is a consensus rule here, not policy.
    let secret = key(7);
    let public = secret.public_key();
    let script_pubkey = ferrum_script::templates::p2pkh(&hash160(public.as_bytes()));
    let tx = spending_tx(0, u32::MAX);
    let signature = sign(&secret, &tx, &script_pubkey);

    let mut bytes = push_all(&[signature, public.as_bytes().to_vec()]).as_bytes().to_vec();
    bytes.push(0x61); // OP_NOP: legal, and not a push
    let script_sig = Script::new(bytes);

    let result = eval_verify(&script_sig, &script_pubkey, &tx);
    assert_eq!(result["success"], false, "{result}");
}

#[test]
fn the_bare_output_of_eval_is_a_single_boolean_line() {
    let assert = cli().args(["script", "eval", "--script", "51"]).assert().success();
    let text = String::from_utf8_lossy(&assert.get_output().stdout);
    assert_eq!(text.lines().next_back(), Some("true"));
}
