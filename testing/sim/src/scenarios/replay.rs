//! **Attack:** replay a signature made on one chain against another.
//!
//! Every Ferrum network shares its transaction format, its script templates
//! and — because keys are derived from a BIP-39 mnemonic — very often its keys.
//! A testnet or devnet faucet hands out coins to an address whose private key
//! also controls mainnet coins. If the signature preimage did not name the
//! chain, a `script_sig` harvested from a testnet transaction would spend the
//! matching mainnet output verbatim. Ethereum shipped without a chain id and
//! needed EIP-155 to add one after replay attacks between the two chains that
//! followed the DAO fork.
//!
//! Ferrum's sighash preimage begins with `chain_id: u32 LE` (CONTRACT §5.5),
//! so the digest a signature commits to differs between networks and the
//! signature simply fails to verify. A P2PKH script ends in `OP_CHECKSIG`,
//! which *pushes* false rather than aborting, so the clean-stack rule is what
//! turns it into a rejection: exactly one element remains and it is false,
//! which is [`ferrum_script::ScriptError::EvalFalse`]. Inside a block that
//! surfaces as [`ValidationError::ScriptVerification`] naming the transaction
//! and the input.
//!
//! **Red:** a signature made under one `chain_id` fails under another, both in
//! the interpreter and inside a block.
//! **Green:** the same signature under its own `chain_id` verifies, and the two
//! preimages differ in exactly the first four bytes.

use ferrum_script::sighash::{SigHashType, sighash_preimage, signature_hash};
use ferrum_types::{Amount, ChainId, Hash32, Transaction};

use crate::error::SimError;
use crate::keys::{KeyRing, Lock};

/// The sighash digest of `tx` input 0 under each of two chain ids.
///
/// # Errors
///
/// [`SimError::Script`] if the preimage cannot be built.
pub fn digests_under(
    tx: &Transaction,
    lock: &Lock,
    keys: &KeyRing,
    value: Amount,
    a: ChainId,
    b: ChainId,
) -> Result<(Hash32, Hash32), SimError> {
    let script_code = lock.script_code(keys)?;
    let one = signature_hash(tx, 0, script_code.as_bytes(), value, a, SigHashType::ALL)?;
    let two = signature_hash(tx, 0, script_code.as_bytes(), value, b, SigHashType::ALL)?;
    Ok((one, two))
}

/// The two sighash preimages, for the byte-level comparison.
///
/// # Errors
///
/// [`SimError::Script`] if a preimage cannot be built.
pub fn preimages_under(
    tx: &Transaction,
    lock: &Lock,
    keys: &KeyRing,
    value: Amount,
    a: ChainId,
    b: ChainId,
) -> Result<(Vec<u8>, Vec<u8>), SimError> {
    let script_code = lock.script_code(keys)?;
    Ok((
        sighash_preimage(tx, 0, script_code.as_bytes(), value, a, SigHashType::ALL)?,
        sighash_preimage(tx, 0, script_code.as_bytes(), value, b, SigHashType::ALL)?,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_chain::ValidationError;
    use ferrum_script::{ExecCtx, ScriptError, ScriptLimits, verify};
    use ferrum_types::{OutPoint, Script, TxIn, TxOut, Txid};

    use super::*;
    use crate::chain_builder::{BlockPlan, TxPlan};
    use crate::keys::DEFAULT_KEYRING_SIZE;
    use crate::scenarios::{judge, matured_chain};
    use crate::sign::unlock;

    fn one_input_tx(value: Amount) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn::new(OutPoint::new(Txid::ZERO, 0), Script::EMPTY)],
            outputs: vec![TxOut::new(value, Script::new(vec![0x51]))],
            lock_time: 0,
        }
    }

    // ---- red -----------------------------------------------------------

    #[test]
    fn a_testnet_signature_does_not_verify_on_mainnet() {
        let keys = KeyRing::deterministic(DEFAULT_KEYRING_SIZE).unwrap();
        let lock = Lock::P2pkh { key: 0 };
        let value = Amount::from_grains(500_000);
        let mut tx = one_input_tx(Amount::from_grains(499_000));
        tx.inputs[0].script_sig =
            unlock(&tx, 0, &lock, value, ChainId::TESTNET, &keys, SigHashType::ALL).unwrap();

        let script_pubkey = lock.script_pubkey(&keys).unwrap();
        let ctx = ExecCtx {
            chain_id: ChainId::MAINNET,
            tx: &tx,
            input_index: 0,
            input_value: value,
            block_height: 1,
            block_mtp_s: 0,
            limits: ScriptLimits::CONSENSUS,
        };
        // `OP_CHECKSIG` pushes false; the clean-stack rule then rejects the
        // input because the single remaining element is not true.
        assert_eq!(
            verify(&tx.inputs[0].script_sig, &script_pubkey, &ctx),
            Err(ScriptError::EvalFalse)
        );
    }

    #[test]
    fn a_replayed_signature_is_rejected_inside_a_block() {
        // The whole path, not just the interpreter: build a devnet block whose
        // input carries a signature made for testnet.
        let mut chain = matured_chain(31, 3).unwrap();
        let height = chain.height() + 1;
        let coin = chain.take_mature(1, height).pop().unwrap();

        let mut tx = chain
            .build_tx(&TxPlan::sweep(
                vec![coin.clone()],
                Lock::P2pkh { key: 1 },
                Amount::from_grains(1_000),
            ))
            .unwrap();
        // Re-sign the input for a different chain, changing nothing else.
        tx.inputs[0].script_sig = unlock(
            &tx,
            0,
            &coin.lock,
            coin.coin.value,
            ChainId::TESTNET,
            chain.keys(),
            SigHashType::ALL,
        )
        .unwrap();

        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        let block =
            chain.build_block(&BlockPlan { txs: vec![tx], ..BlockPlan::default() }).unwrap();
        match judge(&pre, &block, &ctx).unwrap().rejection() {
            Some(ValidationError::ScriptVerification { tx_index, input_index, source }) => {
                assert_eq!(*tx_index, 1);
                assert_eq!(*input_index, 0);
                assert_eq!(*source, ScriptError::EvalFalse);
            }
            other => panic!("expected ScriptVerification, got {other:?}"),
        }
    }

    #[test]
    fn every_pair_of_networks_produces_a_different_digest() {
        let keys = KeyRing::deterministic(DEFAULT_KEYRING_SIZE).unwrap();
        let lock = Lock::P2pkh { key: 2 };
        let tx = one_input_tx(Amount::from_grains(1));
        let value = Amount::from_grains(2);
        let ids = [ChainId::MAINNET, ChainId::TESTNET, ChainId::DEVNET];
        for (i, a) in ids.iter().enumerate() {
            for b in ids.iter().skip(i + 1) {
                let (x, y) = digests_under(&tx, &lock, &keys, value, *a, *b).unwrap();
                assert_ne!(x, y, "chain ids {a:?} and {b:?} share a digest");
            }
        }
    }

    #[test]
    fn a_multisig_signature_does_not_replay_either() {
        let keys = KeyRing::deterministic(DEFAULT_KEYRING_SIZE).unwrap();
        let lock = Lock::P2shMultisig { k: 2, keys: vec![3, 4, 5] };
        let value = Amount::from_grains(900_000);
        let mut tx = one_input_tx(Amount::from_grains(899_000));
        tx.inputs[0].script_sig =
            unlock(&tx, 0, &lock, value, ChainId::DEVNET, &keys, SigHashType::ALL).unwrap();
        let script_pubkey = lock.script_pubkey(&keys).unwrap();
        let ctx = ExecCtx {
            input_value: value,
            ..ExecCtx::new(ChainId::MAINNET, &tx, 0)
        };
        assert!(verify(&tx.inputs[0].script_sig, &script_pubkey, &ctx).is_err());
    }

    // ---- green ---------------------------------------------------------

    #[test]
    fn the_signature_verifies_on_the_chain_it_was_made_for() {
        let keys = KeyRing::deterministic(DEFAULT_KEYRING_SIZE).unwrap();
        let lock = Lock::P2pkh { key: 0 };
        let value = Amount::from_grains(500_000);
        let mut tx = one_input_tx(Amount::from_grains(499_000));
        tx.inputs[0].script_sig =
            unlock(&tx, 0, &lock, value, ChainId::TESTNET, &keys, SigHashType::ALL).unwrap();
        let script_pubkey = lock.script_pubkey(&keys).unwrap();
        let ctx = ExecCtx {
            input_value: value,
            ..ExecCtx::new(ChainId::TESTNET, &tx, 0)
        };
        assert!(verify(&tx.inputs[0].script_sig, &script_pubkey, &ctx).is_ok());
    }

    #[test]
    fn the_two_preimages_differ_in_exactly_the_leading_chain_id() {
        let keys = KeyRing::deterministic(DEFAULT_KEYRING_SIZE).unwrap();
        let lock = Lock::P2pkh { key: 6 };
        let tx = one_input_tx(Amount::from_grains(10));
        let (a, b) =
            preimages_under(&tx, &lock, &keys, Amount::from_grains(20), ChainId::MAINNET, ChainId::DEVNET)
                .unwrap();
        assert_eq!(a.len(), b.len());
        assert_eq!(&a[..4], &ChainId::MAINNET.to_u32().to_le_bytes());
        assert_eq!(&b[..4], &ChainId::DEVNET.to_u32().to_le_bytes());
        assert_eq!(&a[4..], &b[4..], "only the chain id may differ");
    }

    #[test]
    fn an_honest_devnet_spend_still_confirms() {
        let mut chain = matured_chain(32, 3).unwrap();
        let height = chain.height() + 1;
        let coin = chain.take_mature(1, height).pop().unwrap();
        let tx = chain
            .build_tx(&TxPlan::sweep(vec![coin], Lock::P2pkh { key: 7 }, Amount::from_grains(1_000)))
            .unwrap();
        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        let block =
            chain.build_block(&BlockPlan { txs: vec![tx], ..BlockPlan::default() }).unwrap();
        assert!(judge(&pre, &block, &ctx).unwrap().is_accepted());
    }
}
