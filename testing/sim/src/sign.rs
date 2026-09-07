//! Turning a [`Lock`] plus a keyring into the `script_sig` that satisfies it.
//!
//! The simulator states what an output is locked with once, as a [`Lock`], and
//! derives both halves from that single statement: [`Lock::script_pubkey`]
//! builds the locking script and [`unlock`] builds the matching unlocking
//! script. A fixture that hand-wrote both would eventually have them disagree,
//! and would then be testing itself rather than the chain.
//!
//! Two details of CONTRACT §5 shape the code here:
//!
//! * a signature is **exactly 65 bytes** — 64 Schnorr plus one sighash-type
//!   byte — never a DER blob of variable length;
//! * `OP_CHECKMULTISIG` pops exactly `n`, the pubkeys, `k` and the `k`
//!   signatures, with **no dummy element**, and matches signatures against
//!   public keys in order. So the `k` signatures are pushed in the same order
//!   the redeem script lists their keys.

use ferrum_script::sighash::{SigHashType, encode_signature, signature_hash};
use ferrum_script::{Instruction, is_push_only};
use ferrum_types::{Amount, ChainId, Script, Transaction};

use crate::error::SimError;
use crate::keys::{KeyRing, Lock};

/// Build the `script_sig` that spends an output locked with `lock`.
///
/// `tx` must already be in its final shape apart from this input's
/// `script_sig`: the sighash commits to every prevout, every sequence and
/// every output, so signing a transaction that is still being assembled
/// produces a signature for a transaction that will never exist.
///
/// # Errors
///
/// [`SimError::Script`] when the sighash cannot be built (for instance
/// `SIGHASH_SINGLE` past the last output), and [`SimError::Fixture`] when the
/// keyring cannot supply a key the lock names.
pub fn unlock(
    tx: &Transaction,
    input_index: usize,
    lock: &Lock,
    input_value: Amount,
    chain_id: ChainId,
    keys: &KeyRing,
    sighash_type: SigHashType,
) -> Result<Script, SimError> {
    let script_code = lock.script_code(keys)?;
    let mut out: Vec<u8> = Vec::new();

    match lock {
        Lock::Anyone => return Ok(Script::EMPTY),
        // Verbatim, and deliberately not checked for push-onlyness or
        // minimality: a scenario that wants a malformed `script_sig` must be
        // able to build one.
        Lock::Raw { script_sig, .. } => return Ok(Script::new(script_sig.clone())),
        Lock::Unspendable { .. } => {
            return Err(SimError::fixture("an OP_RETURN output can never be spent"));
        }
        Lock::P2pk { key } => {
            push_signature(
                &mut out,
                tx,
                input_index,
                &script_code,
                input_value,
                chain_id,
                keys,
                *key,
                sighash_type,
            )?;
        }
        Lock::P2pkh { key } | Lock::CltvP2pkh { key, .. } => {
            push_signature(
                &mut out,
                tx,
                input_index,
                &script_code,
                input_value,
                chain_id,
                keys,
                *key,
                sighash_type,
            )?;
            push_bytes(&mut out, keys.public(*key)?.as_bytes())?;
        }
        Lock::Multisig { .. } => {
            for key in lock.signing_keys() {
                push_signature(
                    &mut out,
                    tx,
                    input_index,
                    &script_code,
                    input_value,
                    chain_id,
                    keys,
                    key,
                    sighash_type,
                )?;
            }
        }
        Lock::P2shMultisig { .. } => {
            for key in lock.signing_keys() {
                push_signature(
                    &mut out,
                    tx,
                    input_index,
                    &script_code,
                    input_value,
                    chain_id,
                    keys,
                    key,
                    sighash_type,
                )?;
            }
            // The redeem script is the *last* push: the interpreter pops it
            // from the top of the stack left by `script_sig`.
            push_bytes(&mut out, script_code.as_bytes())?;
        }
    }

    let script = Script::new(out);
    // `script_sig` must be push-only, and that is a consensus rule in Ferrum
    // rather than a policy one. Asserting it here means a fixture bug is
    // reported as a fixture bug and not as a mysterious `PushOnly` rejection
    // three layers away.
    if !is_push_only(&script) {
        return Err(SimError::fixture("the harness built a non-push-only script_sig"));
    }
    Ok(script)
}

/// The 65-byte signature one key makes over this input.
///
/// The argument list is long because the sighash preimage commits to all of
/// it — the chain id, the whole transaction, the input index, the value being
/// spent, the script code and the sighash flavour (CONTRACT §5.5). Bundling
/// them into a struct would hide the fact that every one of them changes the
/// digest.
///
/// # Errors
///
/// As [`unlock`].
#[allow(clippy::too_many_arguments)]
pub fn signature_for(
    tx: &Transaction,
    input_index: usize,
    script_code: &Script,
    input_value: Amount,
    chain_id: ChainId,
    keys: &KeyRing,
    key: usize,
    sighash_type: SigHashType,
) -> Result<Vec<u8>, SimError> {
    let digest = signature_hash(
        tx,
        input_index,
        script_code.as_bytes(),
        input_value,
        chain_id,
        sighash_type,
    )?;
    let secret = keys.secret(key)?;
    Ok(encode_signature(&secret.sign_deterministic(&digest), sighash_type))
}

#[allow(clippy::too_many_arguments)]
fn push_signature(
    out: &mut Vec<u8>,
    tx: &Transaction,
    input_index: usize,
    script_code: &Script,
    input_value: Amount,
    chain_id: ChainId,
    keys: &KeyRing,
    key: usize,
    sighash_type: SigHashType,
) -> Result<(), SimError> {
    let sig = signature_for(
        tx,
        input_index,
        script_code,
        input_value,
        chain_id,
        keys,
        key,
        sighash_type,
    )?;
    push_bytes(out, &sig)
}

/// Append a minimally encoded push of `data`.
///
/// # Errors
///
/// [`SimError::Script`] when `data` is too large for any push opcode; there is
/// no `OP_PUSHDATA4` because `MAX_SCRIPT_SIZE` is 1000 bytes.
pub fn push_bytes(out: &mut Vec<u8>, data: &[u8]) -> Result<(), SimError> {
    Instruction::push(data)?.encode_into(out);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_script::{ExecCtx, verify};
    use ferrum_types::{OutPoint, TxIn, TxOut, Txid};

    use super::*;
    use crate::keys::DEFAULT_KEYRING_SIZE;

    fn fixture(lock: &Lock, keys: &KeyRing, value: Amount, lock_time: u32, sequence: u32) -> bool {
        let script_pubkey = lock.script_pubkey(keys).unwrap();
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::new(Txid::ZERO, 0),
                script_sig: Script::EMPTY,
                sequence,
            }],
            outputs: vec![TxOut::new(Amount::from_grains(1), Script::new(vec![0x51]))],
            lock_time,
        };
        let script_sig =
            unlock(&tx, 0, lock, value, ChainId::DEVNET, keys, SigHashType::ALL).unwrap();
        tx.inputs[0].script_sig = script_sig;
        let ctx = ExecCtx {
            input_value: value,
            block_height: 10,
            block_mtp_s: 1_000,
            ..ExecCtx::new(ChainId::DEVNET, &tx, 0)
        };
        verify(&tx.inputs[0].script_sig, &script_pubkey, &ctx).is_ok()
    }

    #[test]
    fn every_spendable_lock_round_trips_through_the_interpreter() {
        let keys = KeyRing::deterministic(DEFAULT_KEYRING_SIZE).unwrap();
        let value = Amount::from_grains(100_000);
        assert!(fixture(&Lock::Anyone, &keys, value, 0, u32::MAX));
        assert!(fixture(&Lock::P2pk { key: 0 }, &keys, value, 0, u32::MAX));
        assert!(fixture(&Lock::P2pkh { key: 1 }, &keys, value, 0, u32::MAX));
        assert!(fixture(&Lock::Multisig { k: 2, keys: vec![0, 1, 2] }, &keys, value, 0, u32::MAX));
        assert!(fixture(
            &Lock::P2shMultisig { k: 3, keys: vec![0, 1, 2, 3, 4] },
            &keys,
            value,
            0,
            u32::MAX
        ));
        // CLTV needs a non-final sequence and a transaction locktime that has
        // reached the script's.
        assert!(fixture(&Lock::CltvP2pkh { key: 2, locktime: 5 }, &keys, value, 5, 0xffff_fffe));
    }

    #[test]
    fn an_unspendable_lock_is_refused_by_the_harness_not_by_the_vm() {
        let keys = KeyRing::deterministic(4).unwrap();
        let tx = Transaction::empty();
        let err = unlock(
            &tx,
            0,
            &Lock::Unspendable { payload: vec![1] },
            Amount::ZERO,
            ChainId::DEVNET,
            &keys,
            SigHashType::ALL,
        )
        .unwrap_err();
        assert!(matches!(err, SimError::Fixture(_)));
    }

    #[test]
    fn a_signature_is_exactly_sixty_five_bytes() {
        let keys = KeyRing::deterministic(4).unwrap();
        let lock = Lock::P2pkh { key: 0 };
        let script_code = lock.script_code(&keys).unwrap();
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn::new(OutPoint::new(Txid::ZERO, 0), Script::EMPTY)],
            outputs: vec![TxOut::new(Amount::from_grains(1), Script::EMPTY)],
            lock_time: 0,
        };
        let sig = signature_for(
            &tx,
            0,
            &script_code,
            Amount::from_grains(5),
            ChainId::DEVNET,
            &keys,
            0,
            SigHashType::ALL,
        )
        .unwrap();
        assert_eq!(sig.len(), ferrum_script::SIGNATURE_SIZE);
        assert_eq!(sig.len(), 65);
    }

    #[test]
    fn a_signature_made_for_one_chain_does_not_verify_on_another() {
        let keys = KeyRing::deterministic(DEFAULT_KEYRING_SIZE).unwrap();
        let lock = Lock::P2pkh { key: 4 };
        let value = Amount::from_grains(50_000);
        let script_pubkey = lock.script_pubkey(&keys).unwrap();
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn::new(OutPoint::new(Txid::ZERO, 0), Script::EMPTY)],
            outputs: vec![TxOut::new(Amount::from_grains(1), Script::new(vec![0x51]))],
            lock_time: 0,
        };
        tx.inputs[0].script_sig =
            unlock(&tx, 0, &lock, value, ChainId::TESTNET, &keys, SigHashType::ALL).unwrap();
        let ctx = ExecCtx { input_value: value, ..ExecCtx::new(ChainId::MAINNET, &tx, 0) };
        assert!(verify(&tx.inputs[0].script_sig, &script_pubkey, &ctx).is_err());
    }
}
