//! Signing, and the two checks that must bracket it.
//!
//! # The sighash commits to the chain id
//!
//! Every signature is made over the BIP-143-shaped preimage from
//! `ferrum-script` (CONTRACT §5.5), whose **first four bytes are the chain
//! id**. A signature made for testnet is therefore not a signature for
//! mainnet: replaying a testnet transaction on mainnet fails at
//! `OP_CHECKSIG`, not at some policy layer that a future version might relax.
//! Ethereum retrofitted this as EIP-155 after the DAO fork and users lost
//! money in the gap; it costs four bytes.
//!
//! [`verify_signed`] takes the chain id explicitly for exactly this reason,
//! and the test `a_testnet_signature_does_not_verify_on_mainnet` is the
//! regression test for it.
//!
//! # Size is measured, not assumed
//!
//! [`sign_transaction`] computes the size the signed transaction *will* have
//! before touching a key, then measures the size it actually has afterwards,
//! and fails with [`WalletError::SizeEstimateDrift`] if the two disagree by
//! more than [`SIZE_ESTIMATE_TOLERANCE`] bytes. Underestimating the size
//! underpays the fee, and a transaction that underpays the fee is not a
//! transaction that fails loudly — it is one that sits in mempools until it
//! expires while the user watches nothing happen.

use ferrum_crypto::{PublicKey, SecretKey, hash160};
use ferrum_script::opcode::Instruction;
use ferrum_script::sighash::{SigHashType, encode_signature, signature_hash};
use ferrum_script::{ExecCtx, verify};
use ferrum_types::{ChainId, Coin, Script, Transaction};

use crate::error::WalletError;
use crate::fee::{
    P2PKH_SCRIPT_SIG_BYTES, SIZE_ESTIMATE_TOLERANCE, TX_OVERHEAD_BYTES, input_size, output_size,
};

/// The `script_sig` that spends a P2PKH output: `<sig+type> <pubkey>`.
///
/// Both pushes are direct (65 and 32 bytes are below `OP_PUSHDATA1`), so the
/// result is always exactly [`P2PKH_SCRIPT_SIG_BYTES`] bytes — which is what
/// makes the fee estimate exact rather than approximate.
pub fn p2pkh_script_sig(signature: &[u8], public_key: &PublicKey) -> Result<Script, WalletError> {
    let mut out = Vec::with_capacity(P2PKH_SCRIPT_SIG_BYTES);
    Instruction::push(signature)?.encode_into(&mut out);
    Instruction::push(public_key.as_bytes())?.encode_into(&mut out);
    Ok(Script::new(out))
}

/// The size a signed transaction will have, computed from the prevouts.
///
/// Independent of the current `script_sig` contents, so it gives the same
/// answer on an unsigned skeleton and on a transaction being re-signed.
pub fn estimate_signed_size(tx: &Transaction, prevouts: &[Coin]) -> Result<usize, WalletError> {
    let mut size = TX_OVERHEAD_BYTES;
    for coin in prevouts {
        size = size.saturating_add(input_size(&coin.script_pubkey)?);
    }
    for output in &tx.outputs {
        size = size.saturating_add(output_size(&output.script_pubkey));
    }
    Ok(size)
}

/// Sign one P2PKH input in place.
///
/// The key must actually control the output being spent; a mismatch is
/// [`WalletError::UnknownInputScript`] rather than a signature that fails
/// later for a reason nobody can trace.
pub fn sign_p2pkh_input(
    tx: &mut Transaction,
    index: usize,
    prevout: &Coin,
    key: &SecretKey,
    chain_id: ChainId,
    sighash_type: SigHashType,
) -> Result<(), WalletError> {
    if index >= tx.inputs.len() {
        return Err(WalletError::UnknownInputScript { index });
    }
    let public = key.public_key();
    let expected = ferrum_script::templates::p2pkh(&hash160(public.as_bytes()));
    if expected != prevout.script_pubkey {
        return Err(WalletError::UnknownInputScript { index });
    }

    // The script code for a bare P2PKH is the locking script itself
    // (CONTRACT §5.5); only P2SH substitutes the redeem script.
    let digest = signature_hash(
        tx,
        index,
        prevout.script_pubkey.as_bytes(),
        prevout.value,
        chain_id,
        sighash_type,
    )?;
    let signature = encode_signature(&key.sign_deterministic(&digest), sighash_type);
    let script_sig = p2pkh_script_sig(&signature, &public)?;

    let input = tx.inputs.get_mut(index).ok_or(WalletError::UnknownInputScript { index })?;
    input.script_sig = script_sig;
    Ok(())
}

/// Sign every input of `tx`, looking each key up by the locking script it
/// unlocks.
///
/// Brackets the signing with the size check described in the module docs, then
/// verifies every input through the real interpreter. Verifying here is not
/// belt-and-braces: a wallet that broadcasts an unverifiable transaction has
/// burned the user's time and given them no diagnostic, while verifying costs
/// one signature check per input on a transaction we just built.
pub fn sign_transaction<F>(
    tx: &mut Transaction,
    prevouts: &[Coin],
    chain_id: ChainId,
    sighash_type: SigHashType,
    key_for: F,
) -> Result<(), WalletError>
where
    F: Fn(&Script) -> Option<SecretKey>,
{
    if prevouts.len() != tx.inputs.len() {
        return Err(WalletError::PrevoutCountMismatch {
            expected: tx.inputs.len(),
            found: prevouts.len(),
        });
    }

    let estimated = estimate_signed_size(tx, prevouts)?;

    for index in 0..tx.inputs.len() {
        let prevout = prevouts
            .get(index)
            .ok_or(WalletError::PrevoutCountMismatch {
                expected: tx.inputs.len(),
                found: prevouts.len(),
            })?
            .clone();
        let key =
            key_for(&prevout.script_pubkey).ok_or(WalletError::UnknownInputScript { index })?;
        sign_p2pkh_input(tx, index, &prevout, &key, chain_id, sighash_type)?;
    }

    let actual = tx.serialized_size();
    if actual.abs_diff(estimated) > SIZE_ESTIMATE_TOLERANCE {
        return Err(WalletError::SizeEstimateDrift { estimated, actual });
    }

    verify_signed(tx, prevouts, chain_id)
}

/// Run the script interpreter over every input.
///
/// `chain_id` is the network the transaction is being verified *for*. Passing
/// a different one than it was signed for makes every `OP_CHECKSIG` fail,
/// which is the cross-chain replay defence working as designed.
pub fn verify_signed(
    tx: &Transaction,
    prevouts: &[Coin],
    chain_id: ChainId,
) -> Result<(), WalletError> {
    verify_signed_at(tx, prevouts, chain_id, 0, 0)
}

/// [`verify_signed`] with an explicit block height and median time past, for
/// scripts that carry a timelock.
pub fn verify_signed_at(
    tx: &Transaction,
    prevouts: &[Coin],
    chain_id: ChainId,
    block_height: u64,
    block_mtp_s: u64,
) -> Result<(), WalletError> {
    if prevouts.len() != tx.inputs.len() {
        return Err(WalletError::PrevoutCountMismatch {
            expected: tx.inputs.len(),
            found: prevouts.len(),
        });
    }
    for (index, prevout) in prevouts.iter().enumerate() {
        let script_sig = tx
            .inputs
            .get(index)
            .map(|i| &i.script_sig)
            .ok_or(WalletError::UnknownInputScript { index })?;
        let ctx = ExecCtx {
            input_value: prevout.value,
            block_height,
            block_mtp_s,
            ..ExecCtx::new(chain_id, tx, index)
        };
        verify(script_sig, &prevout.script_pubkey, &ctx)
            .map_err(|source| WalletError::Verification { index, source })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]

    use ferrum_crypto::{Address, Mnemonic};
    use ferrum_types::{Amount, Network, OutPoint, TxIn, TxOut, Txid};

    use super::*;
    use crate::hd::{DerivedKey, HdKeychain};

    fn keychain() -> HdKeychain {
        let mnemonic = Mnemonic::from_entropy(&[0xa5u8; 32]).unwrap();
        HdKeychain::from_mnemonic(&mnemonic, "", Network::Devnet).unwrap()
    }

    fn key(index: u32) -> DerivedKey {
        keychain().receive(0, index).unwrap()
    }

    fn prevout(key: &DerivedKey, value: u64) -> Coin {
        Coin {
            value: Amount::from_grains(value),
            script_pubkey: key.script_pubkey(),
            height: 1,
            is_coinbase: false,
        }
    }

    fn spend(n: usize) -> (Transaction, Vec<Coin>, Vec<DerivedKey>) {
        let keys: Vec<DerivedKey> = (0..n).map(|i| key(i as u32)).collect();
        let prevouts: Vec<Coin> = keys.iter().map(|k| prevout(k, 1_000_000)).collect();
        let tx = Transaction {
            version: 1,
            inputs: (0..n)
                .map(|i| TxIn {
                    prev_out: OutPoint::new(Txid::from_bytes([i as u8; 32]), 0),
                    script_sig: Script::EMPTY,
                    sequence: 0xffff_fffe,
                })
                .collect(),
            outputs: vec![TxOut {
                value: Amount::from_grains(500_000),
                script_pubkey: Address::p2pkh(Network::Devnet, key(99).public_key())
                    .script_pubkey(),
            }],
            lock_time: 0,
        };
        (tx, prevouts, keys)
    }

    fn lookup(keys: &[DerivedKey]) -> impl Fn(&Script) -> Option<SecretKey> + '_ {
        move |script: &Script| {
            keys.iter().find(|k| &k.script_pubkey() == script).map(|k| k.secret_key().clone())
        }
    }

    #[test]
    fn a_single_input_signs_and_verifies() {
        let (mut tx, prevouts, keys) = spend(1);
        sign_transaction(&mut tx, &prevouts, ChainId::DEVNET, SigHashType::ALL, lookup(&keys))
            .unwrap();
        verify_signed(&tx, &prevouts, ChainId::DEVNET).unwrap();
    }

    #[test]
    fn three_inputs_all_sign() {
        let (mut tx, prevouts, keys) = spend(3);
        sign_transaction(&mut tx, &prevouts, ChainId::DEVNET, SigHashType::ALL, lookup(&keys))
            .unwrap();
        assert!(tx.inputs.iter().all(|i| i.script_sig.len() == P2PKH_SCRIPT_SIG_BYTES));
    }

    #[test]
    fn a_script_sig_is_exactly_the_estimated_length() {
        let (mut tx, prevouts, keys) = spend(2);
        let estimated = estimate_signed_size(&tx, &prevouts).unwrap();
        sign_transaction(&mut tx, &prevouts, ChainId::DEVNET, SigHashType::ALL, lookup(&keys))
            .unwrap();
        // Not "within tolerance": exactly equal. Ferrum signatures never vary
        // in length, so any drift at all is a bug in the size model.
        assert_eq!(tx.serialized_size(), estimated);
    }

    #[test]
    fn a_testnet_signature_does_not_verify_on_mainnet() {
        let (mut tx, prevouts, keys) = spend(1);
        // ChainId(2) is testnet.
        sign_transaction(&mut tx, &prevouts, ChainId::TESTNET, SigHashType::ALL, lookup(&keys))
            .unwrap();
        verify_signed(&tx, &prevouts, ChainId::TESTNET).unwrap();

        // ChainId(1) is mainnet: the same bytes must not authorise anything.
        let err = verify_signed(&tx, &prevouts, ChainId::MAINNET).unwrap_err();
        assert!(matches!(err, WalletError::Verification { index: 0, .. }), "{err:?}");
    }

    #[test]
    fn every_pair_of_distinct_chain_ids_is_a_replay_barrier() {
        for signing in [ChainId::MAINNET, ChainId::TESTNET, ChainId::DEVNET] {
            let (mut tx, prevouts, keys) = spend(1);
            sign_transaction(&mut tx, &prevouts, signing, SigHashType::ALL, lookup(&keys)).unwrap();
            for verifying in [ChainId::MAINNET, ChainId::TESTNET, ChainId::DEVNET] {
                let result = verify_signed(&tx, &prevouts, verifying);
                assert_eq!(
                    result.is_ok(),
                    signing == verifying,
                    "signed for {signing:?}, verified for {verifying:?}",
                );
            }
        }
    }

    #[test]
    fn a_changed_output_invalidates_the_signature() {
        let (mut tx, prevouts, keys) = spend(1);
        sign_transaction(&mut tx, &prevouts, ChainId::DEVNET, SigHashType::ALL, lookup(&keys))
            .unwrap();
        tx.outputs[0].value = Amount::from_grains(999_999);
        assert!(verify_signed(&tx, &prevouts, ChainId::DEVNET).is_err());
    }

    #[test]
    fn a_changed_input_value_invalidates_the_signature() {
        let (mut tx, prevouts, keys) = spend(1);
        sign_transaction(&mut tx, &prevouts, ChainId::DEVNET, SigHashType::ALL, lookup(&keys))
            .unwrap();
        let mut lied = prevouts.clone();
        lied[0].value = Amount::from_grains(2_000_000);
        assert!(verify_signed(&tx, &lied, ChainId::DEVNET).is_err());
    }

    #[test]
    fn a_missing_key_is_reported_by_input_index() {
        let (mut tx, prevouts, keys) = spend(2);
        let only_first = &keys[..1];
        let err = sign_transaction(
            &mut tx,
            &prevouts,
            ChainId::DEVNET,
            SigHashType::ALL,
            lookup(only_first),
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::UnknownInputScript { index: 1 }), "{err:?}");
    }

    #[test]
    fn a_prevout_count_mismatch_is_rejected() {
        let (mut tx, prevouts, keys) = spend(2);
        let err = sign_transaction(
            &mut tx,
            &prevouts[..1],
            ChainId::DEVNET,
            SigHashType::ALL,
            lookup(&keys),
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::PrevoutCountMismatch { expected: 2, found: 1 }));
    }

    #[test]
    fn signing_with_the_wrong_key_is_refused_before_it_produces_bytes() {
        let (mut tx, prevouts, _) = spend(1);
        let wrong = key(77);
        let err = sign_p2pkh_input(
            &mut tx,
            0,
            &prevouts[0],
            wrong.secret_key(),
            ChainId::DEVNET,
            SigHashType::ALL,
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::UnknownInputScript { index: 0 }));
        assert!(tx.inputs[0].script_sig.is_empty());
    }

    #[test]
    fn an_out_of_range_input_index_is_refused() {
        let (mut tx, prevouts, keys) = spend(1);
        let err = sign_p2pkh_input(
            &mut tx,
            5,
            &prevouts[0],
            keys[0].secret_key(),
            ChainId::DEVNET,
            SigHashType::ALL,
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::UnknownInputScript { index: 5 }));
    }

    #[test]
    fn signing_is_deterministic() {
        let (mut a, prevouts, keys) = spend(2);
        let mut b = a.clone();
        sign_transaction(&mut a, &prevouts, ChainId::DEVNET, SigHashType::ALL, lookup(&keys))
            .unwrap();
        sign_transaction(&mut b, &prevouts, ChainId::DEVNET, SigHashType::ALL, lookup(&keys))
            .unwrap();
        assert_eq!(a.encode_envelope(), b.encode_envelope());
    }

    #[test]
    fn sighash_none_and_single_also_verify() {
        for ty in [SigHashType::NONE, SigHashType::SINGLE] {
            let (mut tx, prevouts, keys) = spend(1);
            sign_transaction(&mut tx, &prevouts, ChainId::DEVNET, ty, lookup(&keys)).unwrap();
            verify_signed(&tx, &prevouts, ChainId::DEVNET).unwrap();
        }
    }

    #[test]
    fn sighash_none_lets_the_outputs_change() {
        let (mut tx, prevouts, keys) = spend(1);
        sign_transaction(&mut tx, &prevouts, ChainId::DEVNET, SigHashType::NONE, lookup(&keys))
            .unwrap();
        tx.outputs[0].value = Amount::from_grains(1);
        // NONE commits to no outputs, so this is still a valid signature —
        // which is exactly why the wallet defaults to ALL.
        verify_signed(&tx, &prevouts, ChainId::DEVNET).unwrap();
    }

    #[test]
    fn verify_signed_reports_a_prevout_count_mismatch() {
        let (tx, prevouts, _) = spend(2);
        let err = verify_signed(&tx, &prevouts[..1], ChainId::DEVNET).unwrap_err();
        assert!(matches!(err, WalletError::PrevoutCountMismatch { .. }));
    }

    #[test]
    fn estimate_refuses_a_script_it_cannot_size() {
        let (tx, mut prevouts, _) = spend(1);
        prevouts[0].script_pubkey = ferrum_script::templates::p2sh(&ferrum_types::Hash32::ZERO);
        assert!(matches!(
            estimate_signed_size(&tx, &prevouts),
            Err(WalletError::UnsupportedScript)
        ));
    }

    #[test]
    fn a_hand_built_script_sig_is_the_documented_length() {
        let k = key(0);
        let script_sig = p2pkh_script_sig(&[0u8; 65], k.public_key()).unwrap();
        assert_eq!(script_sig.len(), P2PKH_SCRIPT_SIG_BYTES);
        assert!(ferrum_script::is_push_only(&script_sig));
    }
}
