//! Shared helpers for the `ferrum-script` integration tests.

#![allow(dead_code)]
#![allow(unreachable_pub)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use ferrum_crypto::{PublicKey, SecretKey, hash160};
use ferrum_script::sighash::{SigHashType, encode_signature, signature_hash};
use ferrum_script::{ExecCtx, ScriptError, ScriptLimits, ScriptNum, Stack, eval};
use ferrum_types::{Amount, ChainId, OutPoint, Script, Transaction, TxIn, TxOut, Txid};

/// A deterministic secret key. `seed` is repeated across all 32 bytes, so every
/// test key is reproducible and distinct.
pub fn secret(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed.max(1); 32]).unwrap()
}

/// The public key of [`secret`].
pub fn public(seed: u8) -> PublicKey {
    secret(seed).public_key()
}

/// `hash160` of the public key of [`secret`] — a P2PKH payload.
pub fn pkh(seed: u8) -> [u8; 20] {
    hash160(public(seed).as_bytes())
}

/// Wrap raw bytes as a script.
pub fn script(bytes: &[u8]) -> Script {
    Script::new(bytes.to_vec())
}

/// The minimal push encoding of `data`, as script bytes.
pub fn push(data: &[u8]) -> Vec<u8> {
    ferrum_script::opcode::encode_push(data).unwrap()
}

/// A script that pushes each item in order — the shape every `script_sig` has.
pub fn script_sig(items: &[&[u8]]) -> Script {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(&push(item));
    }
    Script::new(out)
}

/// The minimal `ScriptNum` encoding of `v`.
pub fn num(v: i64) -> Vec<u8> {
    ScriptNum::new(v).to_vec()
}

/// A single-input, single-output transaction spending `prev`.
pub fn spending_tx(unlock: Script, sequence: u32, lock_time: u32) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            prev_out: OutPoint::new(Txid::from_bytes([0xab; 32]), 0),
            script_sig: unlock,
            sequence,
        }],
        outputs: vec![TxOut::new(Amount::from_grains(90_000), script(&[0x51]))],
        lock_time,
    }
}

/// The transaction the stack-only tests run against: nothing about it matters
/// except that it exists and has one input.
pub fn dummy_tx() -> Transaction {
    spending_tx(Script::EMPTY, 0xffff_fffe, 0)
}

/// The value every helper here claims is being spent.
pub const INPUT_VALUE: Amount = Amount::from_grains(100_000);

/// A context over `tx` with consensus limits.
pub fn ctx_for(tx: &Transaction, chain_id: ChainId) -> ExecCtx<'_> {
    ExecCtx { input_value: INPUT_VALUE, ..ExecCtx::new(chain_id, tx, 0) }
}

/// Evaluate `script_bytes` over `initial` with consensus limits.
pub fn run(script_bytes: &[u8], initial: Vec<Vec<u8>>) -> Result<Stack, ScriptError> {
    let tx = dummy_tx();
    let ctx = ctx_for(&tx, ChainId::DEVNET);
    eval(&script(script_bytes), initial, &ctx)
}

/// Evaluate `script_bytes` over an empty stack.
pub fn run_empty(script_bytes: &[u8]) -> Result<Stack, ScriptError> {
    run(script_bytes, Vec::new())
}

/// Evaluate with a tightened limit table, so a rejection path can be reached
/// without building a thousand-byte script.
pub fn run_with_limits(
    script_bytes: &[u8],
    initial: Vec<Vec<u8>>,
    limits: ScriptLimits,
) -> Result<Stack, ScriptError> {
    let tx = dummy_tx();
    let ctx = ExecCtx { limits, ..ctx_for(&tx, ChainId::DEVNET) };
    eval(&script(script_bytes), initial, &ctx)
}

/// Assert the stack after running `script_bytes` on an empty stack.
pub fn assert_stack(script_bytes: &[u8], expected: &[&[u8]]) {
    let got = run_empty(script_bytes).unwrap();
    let want: Vec<Vec<u8>> = expected.iter().map(|e| e.to_vec()).collect();
    assert_eq!(got, want, "script {}", hex::encode(script_bytes));
}

/// Assert `script_bytes` fails with exactly `expected`.
pub fn assert_err(script_bytes: &[u8], initial: Vec<Vec<u8>>, expected: ScriptError) {
    assert_eq!(run(script_bytes, initial), Err(expected), "script {}", hex::encode(script_bytes));
}

/// Produce the 65-byte script signature for input `index` of `tx`.
pub fn sign(
    key: &SecretKey,
    tx: &Transaction,
    index: usize,
    script_code: &Script,
    value: Amount,
    chain_id: ChainId,
    ty: SigHashType,
) -> Vec<u8> {
    let digest = signature_hash(tx, index, script_code.as_bytes(), value, chain_id, ty).unwrap();
    encode_signature(&key.sign_deterministic(&digest), ty)
}

/// Sign input 0 with `SIGHASH_ALL` for the given chain, which is what every
/// end-to-end template test wants.
pub fn sign_all(
    key: &SecretKey,
    tx: &Transaction,
    script_code: &Script,
    chain_id: ChainId,
) -> Vec<u8> {
    sign(key, tx, 0, script_code, INPUT_VALUE, chain_id, SigHashType::ALL)
}
