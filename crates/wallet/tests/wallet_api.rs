//! Unit-level tests for the [`Wallet`] surface, driven through its public API.
//!
//! The end-to-end flows live in `wallet_e2e.rs`; these cover each method on its
//! own — lifecycle, address issuance, the coin cache and the build path.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use ferrum_crypto::{Address, Mnemonic};
use ferrum_types::{Amount, ChainId, Coin, Network, OutPoint, Txid};
use ferrum_wallet::{
    ADDRESS_GAP_LIMIT, HdKeychain, KeyLocation, KeystoreParams, MIN_PBKDF2_ITERATIONS, SendRequest,
    Wallet, WalletError,
};
use tempfile::TempDir;

fn fast() -> KeystoreParams {
    KeystoreParams::new(MIN_PBKDF2_ITERATIONS).unwrap()
}

fn rng(seed: u64) -> rand::rngs::StdRng {
    <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(seed)
}

fn new_wallet(dir: &TempDir) -> (Wallet, Mnemonic) {
    Wallet::create_with_params(
        &dir.path().join("wallet.json"),
        Network::Devnet,
        "pw",
        12,
        fast(),
        &mut rng(1),
    )
    .unwrap()
}

fn coin_to(address: &Address, value: u64, height: u64, is_coinbase: bool) -> Coin {
    Coin {
        value: Amount::from_grains(value),
        script_pubkey: address.script_pubkey(),
        height,
        is_coinbase,
    }
}

fn op(n: u8) -> OutPoint {
    OutPoint::new(Txid::from_bytes([n; 32]), 0)
}

// ------------------------------------------------------------------- lifecycle

#[test]
fn create_returns_a_mnemonic_of_the_requested_length() {
    let dir = TempDir::new().unwrap();
    let (_, mnemonic) = new_wallet(&dir);
    assert_eq!(mnemonic.phrase().split(' ').count(), 12);
}

#[test]
fn create_supports_every_valid_word_count() {
    for words in [12usize, 15, 18, 21, 24] {
        let dir = TempDir::new().unwrap();
        let (_, mnemonic) = Wallet::create_with_params(
            &dir.path().join("w.json"),
            Network::Devnet,
            "pw",
            words,
            fast(),
            &mut rng(words as u64),
        )
        .unwrap();
        assert_eq!(mnemonic.phrase().split(' ').count(), words);
    }
}

#[test]
fn create_rejects_an_invalid_word_count() {
    let dir = TempDir::new().unwrap();
    let err = Wallet::create_with_params(
        &dir.path().join("w.json"),
        Network::Devnet,
        "pw",
        13,
        fast(),
        &mut rng(1),
    )
    .unwrap_err();
    assert!(matches!(err, WalletError::Crypto(_)));
}

#[test]
fn open_with_the_right_passphrase_recovers_the_same_addresses() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("wallet.json");
    let (mut wallet, _) =
        Wallet::create_with_params(&path, Network::Devnet, "pw", 12, fast(), &mut rng(2)).unwrap();
    let first = wallet.new_address().unwrap();
    drop(wallet);

    let reopened = Wallet::open(&path, "pw").unwrap();
    assert_eq!(reopened.addresses(), vec![first]);
}

#[test]
fn open_with_the_wrong_passphrase_fails() {
    let dir = TempDir::new().unwrap();
    let (wallet, _) = new_wallet(&dir);
    let path = wallet.keystore().path().to_path_buf();
    drop(wallet);
    assert!(matches!(Wallet::open(&path, "nope"), Err(WalletError::WrongPassphrase)));
}

#[test]
fn restore_reproduces_the_same_addresses() {
    let dir = TempDir::new().unwrap();
    let (wallet, mnemonic) = new_wallet(&dir);
    let expected = wallet.current_change_address().unwrap();
    drop(wallet);

    let restored = Wallet::restore_with_params(
        &dir.path().join("restored.json"),
        Network::Devnet,
        &mnemonic,
        "different passphrase",
        fast(),
    )
    .unwrap();
    assert_eq!(restored.current_change_address().unwrap(), expected);
}

#[test]
fn restore_refuses_to_overwrite() {
    let dir = TempDir::new().unwrap();
    let (wallet, mnemonic) = new_wallet(&dir);
    let path = wallet.keystore().path().to_path_buf();
    let err =
        Wallet::restore_with_params(&path, Network::Devnet, &mnemonic, "pw", fast()).unwrap_err();
    assert!(matches!(err, WalletError::KeystoreExists(_)));
}

// ------------------------------------------------------------------- addresses

#[test]
fn new_address_walks_the_index() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let a = wallet.new_address().unwrap();
    let b = wallet.new_address().unwrap();
    let c = wallet.new_address().unwrap();
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_eq!(wallet.addresses(), vec![a, b, c]);
}

#[test]
fn the_address_index_survives_a_close_and_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("wallet.json");
    let (mut wallet, _) =
        Wallet::create_with_params(&path, Network::Devnet, "pw", 12, fast(), &mut rng(3)).unwrap();
    let a = wallet.new_address().unwrap();
    let b = wallet.new_address().unwrap();
    drop(wallet);

    let mut reopened = Wallet::open(&path, "pw").unwrap();
    let c = reopened.new_address().unwrap();
    // The whole point: restarting must never re-issue an address.
    assert_ne!(c, a);
    assert_ne!(c, b);
    assert_eq!(reopened.addresses(), vec![a, b, c]);
}

#[test]
fn a_fresh_wallet_has_no_issued_addresses() {
    let dir = TempDir::new().unwrap();
    let (wallet, _) = new_wallet(&dir);
    assert!(wallet.addresses().is_empty());
    assert!(wallet.change_addresses().is_empty());
}

#[test]
fn change_addresses_have_their_own_index() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let receive = wallet.new_address().unwrap();
    let change = wallet.new_change_address().unwrap();
    assert_ne!(receive, change);
    assert_eq!(wallet.change_addresses(), vec![change]);
    assert_eq!(wallet.addresses(), vec![receive]);
}

#[test]
fn addresses_encode_for_the_wallet_network() {
    for network in Network::ALL {
        let dir = TempDir::new().unwrap();
        let (mut wallet, _) = Wallet::create_with_params(
            &dir.path().join("w.json"),
            network,
            "pw",
            12,
            fast(),
            &mut rng(4),
        )
        .unwrap();
        let address = wallet.new_address().unwrap();
        assert_eq!(address.network, network);
        assert_eq!(wallet.network(), network);
        assert!(address.encode().starts_with(network.bech32_hrp()));
    }
}

#[test]
fn an_issued_address_is_recognised_as_ours() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let address = wallet.new_address().unwrap();
    let location = wallet.locate_script(&address.script_pubkey()).unwrap();
    assert_eq!(location, KeyLocation { account: 0, change: 0, index: 0 });
    assert!(wallet.secret_for_script(&address.script_pubkey()).is_some());
}

#[test]
fn an_address_inside_the_gap_limit_is_recognised() {
    let dir = TempDir::new().unwrap();
    let (wallet, mnemonic) = new_wallet(&dir);
    let keychain = HdKeychain::from_mnemonic(&mnemonic, "", Network::Devnet).unwrap();
    let far = keychain.address(0, 0, ADDRESS_GAP_LIMIT).unwrap();
    assert!(wallet.locate_script(&far.script_pubkey()).is_some());
}

#[test]
fn an_address_past_the_gap_limit_is_not_recognised() {
    let dir = TempDir::new().unwrap();
    let (wallet, mnemonic) = new_wallet(&dir);
    let keychain = HdKeychain::from_mnemonic(&mnemonic, "", Network::Devnet).unwrap();
    let far = keychain.address(0, 0, ADDRESS_GAP_LIMIT + 1).unwrap();
    assert!(wallet.locate_script(&far.script_pubkey()).is_none());
    assert!(wallet.secret_for_script(&far.script_pubkey()).is_none());
}

// ----------------------------------------------------------------------- coins

#[test]
fn sync_keeps_only_coins_this_wallet_controls() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let mine = wallet.new_address().unwrap();
    let foreign = ferrum_script::templates::p2pkh(&[0xffu8; 20]);
    wallet.sync(
        vec![
            (op(1), coin_to(&mine, 1_000, 1, false)),
            (
                op(2),
                Coin {
                    value: Amount::from_grains(9_999),
                    script_pubkey: foreign,
                    height: 1,
                    is_coinbase: false,
                },
            ),
        ],
        10,
    );
    assert_eq!(wallet.coins().len(), 1);
    assert_eq!(wallet.balance_at(10).confirmed, Amount::from_grains(1_000));
}

#[test]
fn balance_splits_confirmed_immature_and_pending() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let a = wallet.new_address().unwrap();
    let maturity = wallet.params().coinbase_maturity;
    // The coinbase is placed one block short of maturity at the tip, computed
    // from the parameters: devnet's window is 10 and mainnet's is 100, and this
    // test is about the three-way split, not about either number.
    let tip = 400;
    let immature_height = tip - maturity + 1;
    wallet.sync(
        vec![
            (op(1), coin_to(&a, 100, 1, false)),
            (op(2), coin_to(&a, 200, immature_height, true)),
            (op(3), coin_to(&a, 300, 500, false)),
        ],
        tip,
    );
    let balance = wallet.balance(tip, maturity);
    assert_eq!(balance.confirmed, Amount::from_grains(100));
    assert_eq!(balance.immature, Amount::from_grains(200));
    assert_eq!(balance.pending, Amount::from_grains(300));
    assert_eq!(balance.total().unwrap(), Amount::from_grains(600));
}

#[test]
fn the_maturity_boundary_is_exactly_maturity_blocks() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let a = wallet.new_address().unwrap();
    let maturity = wallet.params().coinbase_maturity;
    let utxos = vec![(op(2), coin_to(&a, 200, 50, true))];

    wallet.sync(utxos.clone(), 50 + maturity - 1);
    assert_eq!(wallet.balance_at(50 + maturity - 1).immature, Amount::from_grains(200));
    assert_eq!(wallet.balance_at(50 + maturity - 1).confirmed, Amount::ZERO);

    wallet.sync(utxos, 50 + maturity);
    assert_eq!(wallet.balance_at(50 + maturity).confirmed, Amount::from_grains(200));
    assert_eq!(wallet.balance_at(50 + maturity).immature, Amount::ZERO);
}

#[test]
fn list_coins_reports_every_bucket() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let a = wallet.new_address().unwrap();
    wallet.sync(vec![(op(1), coin_to(&a, 100, 1, false))], 10);
    let listed = wallet.list_coins(10);
    assert_eq!(listed.len(), 1);
    assert!(listed[0].status.is_spendable());
    assert_eq!(wallet.spendable_coins(10).len(), 1);
}

// -------------------------------------------------------------------- building

#[test]
fn a_wallet_can_build_sign_and_verify_a_payment() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let mine = wallet.new_address().unwrap();
    wallet.sync(vec![(op(1), coin_to(&mine, 10 * 100_000_000, 1, false))], 200);

    let payee = wallet.new_address().unwrap();
    let req = SendRequest::to(payee, Amount::from_grains(100_000_000), 1_000);
    let plan = wallet.send(&req, 200).unwrap();

    wallet.verify_transaction(&plan.tx, &plan.prevouts(), wallet.chain_id()).unwrap();
    assert!(plan.fee_rate() >= 1_000);
    assert_eq!(plan.tx.serialized_size(), plan.estimated_size);
}

#[test]
fn build_transaction_returns_the_same_skeleton_as_the_plan() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let mine = wallet.new_address().unwrap();
    wallet.sync(vec![(op(1), coin_to(&mine, 10 * 100_000_000, 1, false))], 200);
    let req = SendRequest::to(mine, Amount::from_grains(100_000_000), 1_000);
    let tx = wallet.build_transaction(&req, 200).unwrap();
    let plan = wallet.plan_transaction(&req, 200).unwrap();
    assert_eq!(tx, plan.tx);
    assert!(tx.inputs.iter().all(|i| i.script_sig.is_empty()));
}

#[test]
fn send_reserves_the_inputs_it_spent() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let mine = wallet.new_address().unwrap();
    wallet.sync(vec![(op(1), coin_to(&mine, 10 * 100_000_000, 1, false))], 200);
    let req = SendRequest::to(mine, Amount::from_grains(100_000_000), 1_000);
    let plan = wallet.send(&req, 200).unwrap();
    assert_eq!(wallet.coins().reserved().len(), plan.tx.inputs.len());
    // A second send now has nothing to spend.
    assert!(matches!(wallet.send(&req, 200), Err(WalletError::InsufficientFunds { .. })));
}

#[test]
fn unreserve_makes_coins_selectable_again() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let mine = wallet.new_address().unwrap();
    wallet.sync(vec![(op(1), coin_to(&mine, 10 * 100_000_000, 1, false))], 200);
    let req = SendRequest::to(mine, Amount::from_grains(100_000_000), 1_000);
    let plan = wallet.send(&req, 200).unwrap();
    wallet.unreserve(&plan.out_points());
    assert!(wallet.send(&req, 200).is_ok());
}

#[test]
fn a_payment_to_another_network_is_refused() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let mine = wallet.new_address().unwrap();
    wallet.sync(vec![(op(1), coin_to(&mine, 10 * 100_000_000, 1, false))], 200);

    let foreign = Address { network: Network::Mainnet, ..mine };
    let req = SendRequest::to(foreign, Amount::from_grains(100_000), 1_000);
    let err = wallet.plan_transaction(&req, 200).unwrap_err();
    assert!(matches!(err, WalletError::NetworkMismatch { .. }));
}

#[test]
fn a_change_address_on_another_network_is_refused() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let mine = wallet.new_address().unwrap();
    wallet.sync(vec![(op(1), coin_to(&mine, 10 * 100_000_000, 1, false))], 200);
    let foreign = Address { network: Network::Mainnet, ..mine };
    let req = SendRequest::to(mine, Amount::from_grains(100_000), 1_000).with_change_to(foreign);
    assert!(matches!(wallet.plan_transaction(&req, 200), Err(WalletError::NetworkMismatch { .. })));
}

#[test]
fn change_goes_back_to_the_wallet() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let mine = wallet.new_address().unwrap();
    wallet.sync(vec![(op(1), coin_to(&mine, 10 * 100_000_000, 1, false))], 200);
    let req = SendRequest::to(mine, Amount::from_grains(100_000_000), 1_000);
    let plan = wallet.plan_transaction(&req, 200).unwrap();
    let change_script = plan.tx.outputs.last().unwrap().script_pubkey.clone();
    assert!(wallet.locate_script(&change_script).is_some());
}

#[test]
fn an_immature_coinbase_cannot_be_spent() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let mine = wallet.new_address().unwrap();
    // One block short of maturity: a coinbase mined at height 1 is spendable at
    // `1 + coinbase_maturity`, so at that height exactly it is not.
    let maturity = wallet.params().coinbase_maturity;
    let too_early = maturity;
    wallet.sync(vec![(op(1), coin_to(&mine, 50 * 100_000_000, 1, true))], too_early);
    let req = SendRequest::to(mine, Amount::from_grains(100_000), 1_000);
    assert!(matches!(
        wallet.plan_transaction(&req, too_early),
        Err(WalletError::InsufficientFunds { available: 0, .. })
    ));

    // ...and can once it matures.
    wallet.sync(vec![(op(1), coin_to(&mine, 50 * 100_000_000, 1, true))], 1 + maturity);
    assert!(wallet.plan_transaction(&req, 1 + maturity).is_ok());
}

#[test]
fn signing_uses_the_wallets_own_chain_id() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    assert_eq!(wallet.chain_id(), ChainId::DEVNET);
    let mine = wallet.new_address().unwrap();
    wallet.sync(vec![(op(1), coin_to(&mine, 10 * 100_000_000, 1, false))], 200);
    let req = SendRequest::to(mine, Amount::from_grains(100_000_000), 1_000);
    let plan = wallet.send(&req, 200).unwrap();
    assert!(wallet.verify_transaction(&plan.tx, &plan.prevouts(), ChainId::MAINNET).is_err());
}

#[test]
fn sign_transaction_rejects_a_prevout_it_has_no_key_for() {
    let dir = TempDir::new().unwrap();
    let (mut wallet, _) = new_wallet(&dir);
    let mine = wallet.new_address().unwrap();
    wallet.sync(vec![(op(1), coin_to(&mine, 10 * 100_000_000, 1, false))], 200);
    let req = SendRequest::to(mine, Amount::from_grains(100_000_000), 1_000);
    let mut plan = wallet.plan_transaction(&req, 200).unwrap();

    let mut prevouts = plan.prevouts();
    prevouts[0].script_pubkey = ferrum_script::templates::p2pkh(&[0xaau8; 20]);
    let err = wallet.sign_transaction(&mut plan.tx, &prevouts, wallet.chain_id()).unwrap_err();
    assert!(matches!(err, WalletError::UnknownInputScript { index: 0 }), "{err:?}");
}

#[test]
fn debug_never_prints_key_material() {
    let dir = TempDir::new().unwrap();
    let (wallet, mnemonic) = new_wallet(&dir);
    let rendered = format!("{wallet:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains(mnemonic.phrase()));
    assert_eq!(wallet.mnemonic().phrase(), mnemonic.phrase());
}

#[test]
fn the_dust_threshold_follows_the_network_relay_fee() {
    let dir = TempDir::new().unwrap();
    let (wallet, _) = new_wallet(&dir);
    assert_eq!(
        wallet.dust_threshold(),
        Amount::from_grains(3 * wallet.params().min_relay_fee_per_kb.to_grains())
    );
}
