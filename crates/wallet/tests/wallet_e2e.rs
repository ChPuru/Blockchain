//! End-to-end scenarios over the public [`Wallet`] surface.
//!
//! These are the milestone-M5 flows from CONTRACT §15: *create wallet → mine →
//! send → confirm → balance read from the UTXO set, never by rescan*, plus the
//! keystore's two mandatory failure modes and the cross-chain replay barrier.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use std::path::PathBuf;

use ferrum_crypto::{Address, Mnemonic};
use ferrum_types::{Amount, COIN, ChainId, Coin, Network, OutPoint, Script, Transaction, Txid};
use ferrum_wallet::{
    KeystoreFile, KeystoreParams, MIN_PBKDF2_ITERATIONS, SendRequest, Wallet, WalletError,
};
use tempfile::TempDir;

fn fast() -> KeystoreParams {
    KeystoreParams::new(MIN_PBKDF2_ITERATIONS).unwrap()
}

fn rng(seed: u64) -> rand::rngs::StdRng {
    <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(seed)
}

fn new_wallet(dir: &TempDir, name: &str, passphrase: &str) -> (Wallet, Mnemonic, PathBuf) {
    let path = dir.path().join(name);
    let (wallet, mnemonic) = Wallet::create_with_params(
        &path,
        Network::Devnet,
        passphrase,
        12,
        fast(),
        &mut rng(0xfe11u64),
    )
    .unwrap();
    (wallet, mnemonic, path)
}

/// A coinbase output paying `address` at `height`.
fn mined(address: &Address, height: u64) -> (OutPoint, Coin) {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&height.to_le_bytes());
    (
        OutPoint::new(Txid::from_bytes(bytes), 0),
        Coin {
            value: Amount::from_grains(50 * COIN),
            script_pubkey: address.script_pubkey(),
            height,
            is_coinbase: true,
        },
    )
}

/// The UTXO set as a node would hand it over after a transaction confirms:
/// the spent coins removed, the new outputs added at `height`.
fn confirm(utxos: &[(OutPoint, Coin)], tx: &Transaction, height: u64) -> Vec<(OutPoint, Coin)> {
    let spent: Vec<OutPoint> = tx.inputs.iter().map(|i| i.prev_out).collect();
    let txid =
        Txid::from(ferrum_crypto::tagged_hash(ferrum_crypto::TAG_TXID, &tx.encode_envelope()));
    let mut next: Vec<(OutPoint, Coin)> =
        utxos.iter().filter(|(op, _)| !spent.contains(op)).cloned().collect();
    for (vout, output) in tx.outputs.iter().enumerate() {
        next.push((
            OutPoint::new(txid, vout as u32),
            Coin {
                value: output.value,
                script_pubkey: output.script_pubkey.clone(),
                height,
                is_coinbase: false,
            },
        ));
    }
    next
}

#[test]
fn create_mine_send_confirm_and_read_the_balance_back() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _, _) = new_wallet(&dir, "m5.json", "pw");
    let maturity = wallet.params().coinbase_maturity;

    // Mine one block to a wallet address.
    let mine_to = wallet.new_address().unwrap();
    let utxos = vec![mined(&mine_to, 1)];

    // Immediately after mining, the subsidy is immature and unspendable.
    wallet.sync(utxos.clone(), 1);
    let balance = wallet.balance_at(1);
    assert_eq!(balance.immature, Amount::from_grains(50 * COIN));
    assert_eq!(balance.confirmed, Amount::ZERO);

    // Exactly `maturity` blocks later it is spendable, and not one block
    // earlier.
    wallet.sync(utxos.clone(), maturity);
    assert_eq!(wallet.balance_at(maturity).immature, Amount::from_grains(50 * COIN));
    wallet.sync(utxos.clone(), 1 + maturity);
    assert_eq!(wallet.balance_at(1 + maturity).confirmed, Amount::from_grains(50 * COIN));

    // Send 10 FRM to a third party.
    let stranger_key = ferrum_crypto::SecretKey::from_bytes(&[0x42u8; 32]).unwrap();
    let payee = Address::p2pkh(Network::Devnet, &stranger_key.public_key());
    let tip = 1 + maturity;
    let req = SendRequest::to(payee, Amount::from_grains(10 * COIN), 1_000);
    let plan = wallet.send(&req, tip).unwrap();

    // The transaction verifies under the wallet's own chain id.
    wallet.verify_transaction(&plan.tx, &plan.prevouts(), wallet.chain_id()).unwrap();
    assert!(plan.fee_rate() >= 1_000);
    assert_eq!(plan.tx.serialized_size(), plan.estimated_size);

    // While it is unconfirmed the spent coin is in flight, not spendable.
    assert_eq!(wallet.balance_at(tip).confirmed, Amount::ZERO);
    assert_eq!(wallet.balance_at(tip).pending, Amount::from_grains(50 * COIN));

    // The node mines it; the wallet is told the new UTXO set and nothing else.
    let confirmed_height = tip + 1;
    let after = confirm(&utxos, &plan.tx, confirmed_height);
    wallet.sync(after, confirmed_height);

    // The balance is now the change, computed from the UTXO set alone.
    let balance = wallet.balance_at(confirmed_height);
    let expected = 50 * COIN - 10 * COIN - plan.fee.to_grains();
    assert_eq!(balance.confirmed, Amount::from_grains(expected));
    assert_eq!(balance.immature, Amount::ZERO);
    assert_eq!(balance.pending, Amount::ZERO);
    // Exactly one coin survived: the change output. The payee's coin is not
    // ours, so `sync` dropped it.
    assert_eq!(wallet.coins().len(), 1);
}

#[test]
fn a_wallet_restarted_never_reissues_an_address() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _, path) = new_wallet(&dir, "restart.json", "pw");
    let issued: Vec<Address> = (0..3).map(|_| wallet.new_address().unwrap()).collect();
    drop(wallet);

    let mut reopened = Wallet::open(&path, "pw").unwrap();
    let next = reopened.new_address().unwrap();
    assert!(!issued.contains(&next));
    assert_eq!(reopened.addresses().len(), 4);

    // And again, to make sure the increment is persisted every time.
    drop(reopened);
    let mut again = Wallet::open(&path, "pw").unwrap();
    let last = again.new_address().unwrap();
    assert!(!issued.contains(&last));
    assert_ne!(last, next);
    assert_eq!(again.addresses().len(), 5);
}

#[test]
fn a_restored_wallet_sees_the_same_coins() {
    let dir = TempDir::new().unwrap();
    let (mut original, mnemonic, _) = new_wallet(&dir, "orig.json", "pw");
    let address = original.new_address().unwrap();
    let utxos = vec![mined(&address, 1)];
    original.sync(utxos.clone(), 500);

    let mut restored = Wallet::restore_with_params(
        &dir.path().join("restored.json"),
        Network::Devnet,
        &mnemonic,
        "a different passphrase",
        fast(),
    )
    .unwrap();
    // The restored wallet has issued no addresses, but the gap limit means it
    // still recognises the coin.
    restored.sync(utxos, 500);
    assert_eq!(restored.balance_at(500).confirmed, original.balance_at(500).confirmed);
}

#[test]
fn a_wrong_passphrase_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    let (wallet, _, path) = new_wallet(&dir, "pw.json", "the right one");
    drop(wallet);
    assert!(matches!(Wallet::open(&path, "the wrong one"), Err(WalletError::WrongPassphrase)));
    // The file is untouched, so the right passphrase still works.
    assert!(Wallet::open(&path, "the right one").is_ok());
}

#[test]
fn a_tampered_keystore_is_detected_not_silently_decrypted() {
    let dir = TempDir::new().unwrap();
    let (wallet, mnemonic, path) = new_wallet(&dir, "tamper.json", "pw");
    drop(wallet);

    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut bytes = hex::decode(&file.ciphertext).unwrap();
    // Flip a bit deep inside the ciphertext, where a stream cipher would
    // happily produce a different-but-parseable phrase.
    let index = bytes.len() / 2;
    bytes[index] ^= 0x20;
    file.ciphertext = hex::encode(&bytes);
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();

    match Wallet::open(&path, "pw") {
        Err(WalletError::KeystoreCorrupt) => {}
        Err(other) => panic!("expected KeystoreCorrupt, got {other:?}"),
        Ok(wallet) => panic!(
            "a tampered keystore opened and produced keys: {:?}",
            wallet.mnemonic().phrase() == mnemonic.phrase()
        ),
    }
}

#[test]
fn a_transaction_signed_for_testnet_does_not_verify_on_mainnet() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("testnet.json");
    let (mut wallet, _) =
        Wallet::create_with_params(&path, Network::Testnet, "pw", 12, fast(), &mut rng(9)).unwrap();
    assert_eq!(wallet.chain_id(), ChainId(2));

    let address = wallet.new_address().unwrap();
    wallet.sync(
        vec![(
            OutPoint::new(Txid::from_bytes([1u8; 32]), 0),
            Coin {
                value: Amount::from_grains(50 * COIN),
                script_pubkey: address.script_pubkey(),
                height: 1,
                is_coinbase: false,
            },
        )],
        500,
    );

    let req = SendRequest::to(address, Amount::from_grains(10 * COIN), 1_000);
    let plan = wallet.send(&req, 500).unwrap();
    let prevouts = plan.prevouts();

    // Valid on the chain it was signed for...
    wallet.verify_transaction(&plan.tx, &prevouts, ChainId(2)).unwrap();
    // ...and worthless on any other.
    let err = wallet.verify_transaction(&plan.tx, &prevouts, ChainId(1)).unwrap_err();
    assert!(matches!(err, WalletError::Verification { index: 0, .. }), "{err:?}");
    assert!(wallet.verify_transaction(&plan.tx, &prevouts, ChainId(3)).is_err());
}

#[test]
fn a_multi_recipient_payment_pays_everyone() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _, _) = new_wallet(&dir, "multi.json", "pw");
    let funded = wallet.new_address().unwrap();
    wallet.sync(vec![mined(&funded, 1)], 1_000);

    let a = wallet.new_address().unwrap();
    let b = wallet.new_address().unwrap();
    let req = SendRequest::to(a, Amount::from_grains(5 * COIN), 1_000)
        .and_to(b, Amount::from_grains(7 * COIN));
    let plan = wallet.send(&req, 1_000).unwrap();

    assert_eq!(plan.tx.outputs.len(), 3); // two recipients plus change
    assert_eq!(plan.tx.outputs[0].value, Amount::from_grains(5 * COIN));
    assert_eq!(plan.tx.outputs[1].value, Amount::from_grains(7 * COIN));
    wallet.verify_transaction(&plan.tx, &plan.prevouts(), wallet.chain_id()).unwrap();
}

#[test]
fn a_send_that_would_leave_dust_change_pays_it_to_the_miner() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _, _) = new_wallet(&dir, "dust.json", "pw");
    let funded = wallet.new_address().unwrap();
    let coin_value = 50 * COIN;
    wallet.sync(
        vec![(
            OutPoint::new(Txid::from_bytes([5u8; 32]), 0),
            Coin {
                value: Amount::from_grains(coin_value),
                script_pubkey: funded.script_pubkey(),
                height: 1,
                is_coinbase: false,
            },
        )],
        1_000,
    );

    // Ask for everything except the fee for a changeless transaction plus a
    // sliver, so the change would be dust.
    let changeless_size = 17 + 143 + 37; // overhead + one input + one output
    let target = coin_value - changeless_size - 1_500;
    let req = SendRequest::to(funded, Amount::from_grains(target), 1_000);
    let plan = wallet.plan_transaction(&req, 1_000).unwrap();

    assert_eq!(plan.change, None, "dust change should have been folded into the fee");
    assert_eq!(plan.tx.outputs.len(), 1);
    assert_eq!(plan.fee, Amount::from_grains(coin_value - target));
    assert!(plan.fee_rate() >= 1_000);
}

#[test]
fn sending_more_than_the_wallet_holds_is_an_error_not_a_short_transaction() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _, _) = new_wallet(&dir, "poor.json", "pw");
    let funded = wallet.new_address().unwrap();
    wallet.sync(vec![mined(&funded, 1)], 1_000);

    let req = SendRequest::to(funded, Amount::from_grains(500 * COIN), 1_000);
    match wallet.plan_transaction(&req, 1_000) {
        Err(WalletError::InsufficientFunds { available, required }) => {
            assert_eq!(available, 50 * COIN);
            assert!(required > 500 * COIN);
        }
        other => panic!("expected InsufficientFunds, got {other:?}"),
    }
}

#[test]
fn the_balance_never_counts_a_foreign_coin() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _, _) = new_wallet(&dir, "foreign.json", "pw");
    let mine = wallet.new_address().unwrap();
    let stranger = Address::p2pkh(
        Network::Devnet,
        &ferrum_crypto::SecretKey::from_bytes(&[0x77u8; 32]).unwrap().public_key(),
    );

    wallet.sync(vec![mined(&mine, 1), mined(&stranger, 2)], 1_000);
    assert_eq!(wallet.coins().len(), 1);
    assert_eq!(wallet.balance_at(1_000).confirmed, Amount::from_grains(50 * COIN));
}

#[test]
fn two_wallets_from_one_mnemonic_agree_on_every_address() {
    let dir = TempDir::new().unwrap();
    let (mut first, mnemonic, _) = new_wallet(&dir, "a.json", "pw");
    let mut second = Wallet::restore_with_params(
        &dir.path().join("b.json"),
        Network::Devnet,
        &mnemonic,
        "another passphrase entirely",
        fast(),
    )
    .unwrap();
    for _ in 0..5 {
        assert_eq!(first.new_address().unwrap(), second.new_address().unwrap());
    }
}

// --------------------------------------------------------------------- change

/// Exactly the query `chain-cli`'s `sync_from_node` and the RPC faucet's
/// `WalletFaucetSource::scripts` make: every address the wallet says it has
/// issued, receive and change, and nothing else.
///
/// A coin paid to a script outside that list is a coin the wallet is never
/// handed, and therefore one it can never spend — however well `Wallet::sync`
/// would have recognised it had anyone asked the node for it.
fn rows_a_node_would_return(wallet: &Wallet, utxos: &[(OutPoint, Coin)]) -> Vec<(OutPoint, Coin)> {
    let watched: Vec<Script> = wallet
        .addresses()
        .iter()
        .chain(wallet.change_addresses().iter())
        .map(Address::script_pubkey)
        .collect();
    utxos.iter().filter(|(_, coin)| watched.contains(&coin.script_pubkey)).cloned().collect()
}

#[test]
fn change_comes_back_spendable_after_a_send_and_a_resync() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _, _) = new_wallet(&dir, "change.json", "pw");
    let funded = wallet.new_address().unwrap();
    let tip = 1_000;

    let chain_utxos = vec![mined(&funded, 1)];
    let rows = rows_a_node_would_return(&wallet, &chain_utxos);
    wallet.sync(rows, tip);
    assert_eq!(wallet.balance_at(tip).confirmed, Amount::from_grains(50 * COIN));

    let stranger = ferrum_crypto::SecretKey::from_bytes(&[0x42u8; 32]).unwrap();
    let payee = Address::p2pkh(Network::Devnet, &stranger.public_key());
    let first =
        wallet.send(&SendRequest::to(payee, Amount::from_grains(10 * COIN), 1_000), tip).unwrap();
    assert!(first.change.is_some(), "a 10 FRM payment out of 50 FRM must produce change");

    // Change is the last output (`crates/wallet/src/build.rs`, "Output order").
    let change_script = first.tx.outputs.last().unwrap().script_pubkey.clone();
    assert!(
        wallet.change_addresses().iter().any(|a| a.script_pubkey() == change_script),
        "the wallet paid change to a script it does not report as one of its own",
    );

    // The block confirms, and the wallet re-syncs the only way a caller can:
    // by asking the node about the addresses the wallet reports.
    let height = tip + 1;
    let chain_utxos = confirm(&chain_utxos, &first.tx, height);
    let rows = rows_a_node_would_return(&wallet, &chain_utxos);
    wallet.sync(rows, height);

    let expected = Amount::from_grains(50 * COIN - 10 * COIN - first.fee.to_grains());
    assert_eq!(
        wallet.balance_at(height).confirmed,
        expected,
        "the change is invisible after a restart-shaped resync",
    );

    // Visible is not enough: it has to be spendable again.
    let second =
        wallet.send(&SendRequest::to(payee, Amount::from_grains(COIN), 1_000), height).unwrap();
    assert!(second.change.is_some());
    assert_ne!(
        second.tx.outputs.last().unwrap().script_pubkey,
        change_script,
        "the second send reused the first send's change address",
    );
}
