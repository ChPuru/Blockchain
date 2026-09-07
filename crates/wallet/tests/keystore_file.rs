//! Keystore file-format tests: what the file must refuse to open.
//!
//! Each of these is a way an attacker or a filesystem can hand the wallet a
//! keystore that is not the one it wrote. None of them may produce a key.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use ferrum_crypto::Mnemonic;
use ferrum_types::Network;
use ferrum_wallet::keystore::CIPHER_NAME;
use ferrum_wallet::{
    DEFAULT_PBKDF2_ITERATIONS, KEYSTORE_VERSION, Keystore, KeystoreFile, KeystoreParams,
    MIN_PBKDF2_ITERATIONS, WalletError, WalletMeta,
};
use rand_core::CryptoRngCore;
use tempfile::TempDir;

const _: () = assert!(KEYSTORE_VERSION == 1);

fn fast() -> KeystoreParams {
    KeystoreParams::new(MIN_PBKDF2_ITERATIONS).unwrap()
}

fn mnemonic() -> Mnemonic {
    Mnemonic::from_entropy(&[0x24u8; 32]).unwrap()
}

fn rng() -> impl CryptoRngCore {
    <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(7)
}

fn create(dir: &TempDir, passphrase: &str) -> Keystore {
    Keystore::create(
        &dir.path().join("wallet.json"),
        Network::Devnet,
        &mnemonic(),
        passphrase,
        WalletMeta::default(),
        fast(),
        &mut rng(),
    )
    .unwrap()
}

#[test]
fn a_created_keystore_reopens_with_the_same_mnemonic() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "correct horse battery staple");
    let path = store.path().to_path_buf();
    drop(store);

    let reopened = Keystore::open(&path, "correct horse battery staple").unwrap();
    assert_eq!(reopened.mnemonic().phrase(), mnemonic().phrase());
    assert_eq!(reopened.network(), Network::Devnet);
}

#[test]
fn the_plaintext_mnemonic_never_appears_on_disk() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let raw = std::fs::read_to_string(store.path()).unwrap();
    for word in mnemonic().phrase().split(' ') {
        assert!(!raw.contains(word), "the word {word:?} leaked into the file");
    }
    assert!(!raw.contains(mnemonic().phrase()));
}

#[test]
fn a_wrong_passphrase_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "right");
    let err = Keystore::open(store.path(), "wrong").unwrap_err();
    assert!(matches!(err, WalletError::WrongPassphrase), "{err:?}");
}

#[test]
fn an_empty_passphrase_is_not_a_master_key() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "right");
    assert!(matches!(Keystore::open(store.path(), ""), Err(WalletError::WrongPassphrase)));
}

#[test]
fn a_tampered_ciphertext_is_detected_not_decrypted() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();

    // Flip one bit of the ciphertext. Without a MAC this would decrypt to
    // a mnemonic with one corrupted word and, worse, could still parse.
    let mut bytes = hex::decode(&file.ciphertext).unwrap();
    bytes[0] ^= 0x01;
    file.ciphertext = hex::encode(&bytes);
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();

    let err = Keystore::open(&path, "pw").unwrap_err();
    assert!(matches!(err, WalletError::KeystoreCorrupt), "{err:?}");
}

#[test]
fn a_truncated_ciphertext_is_detected() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file.ciphertext.truncate(file.ciphertext.len() - 2);
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    assert!(matches!(Keystore::open(&path, "pw"), Err(WalletError::KeystoreCorrupt)));
}

#[test]
fn a_tampered_nonce_is_detected() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut bytes = hex::decode(&file.nonce).unwrap();
    bytes[3] ^= 0xff;
    file.nonce = hex::encode(&bytes);
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    assert!(matches!(Keystore::open(&path, "pw"), Err(WalletError::KeystoreCorrupt)));
}

#[test]
fn a_downgraded_iteration_count_is_rejected() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file.kdf.iterations = 1;
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    assert!(matches!(
        Keystore::open(&path, "pw"),
        Err(WalletError::WeakKdfParameters { found: 1, .. })
    ));
}

#[test]
fn a_raised_iteration_count_breaks_the_mac_rather_than_the_key() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file.kdf.iterations = MIN_PBKDF2_ITERATIONS + 1;
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    // A different iteration count derives different keys, so the check
    // value no longer matches: reported as a wrong passphrase, never as a
    // successful open.
    assert!(matches!(Keystore::open(&path, "pw"), Err(WalletError::WrongPassphrase)));
}

#[test]
fn tampering_with_the_address_index_is_detected() {
    let dir = TempDir::new().unwrap();
    let mut store = create(&dir, "pw");
    store.set_meta(WalletMeta { account: 0, next_receive_index: 5, next_change_index: 2 }).unwrap();
    let path = store.path().to_path_buf();

    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file.meta.next_receive_index = 0;
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();

    // Rolling the index back would make the wallet re-issue an address it
    // has already handed out. The MAC covers it, so it cannot be done.
    assert!(matches!(Keystore::open(&path, "pw"), Err(WalletError::KeystoreCorrupt)));
}

#[test]
fn a_tampered_network_is_detected() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file.network = Network::Mainnet;
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    assert!(matches!(Keystore::open(&path, "pw"), Err(WalletError::KeystoreCorrupt)));
}

#[test]
fn set_meta_survives_a_reopen() {
    let dir = TempDir::new().unwrap();
    let mut store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    store.set_meta(WalletMeta { account: 0, next_receive_index: 9, next_change_index: 4 }).unwrap();
    drop(store);

    let reopened = Keystore::open(&path, "pw").unwrap();
    assert_eq!(reopened.meta().next_receive_index, 9);
    assert_eq!(reopened.meta().next_change_index, 4);
}

#[test]
fn creating_over_an_existing_file_is_refused() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let err = Keystore::create(
        store.path(),
        Network::Devnet,
        &mnemonic(),
        "pw",
        WalletMeta::default(),
        fast(),
        &mut rng(),
    )
    .unwrap_err();
    assert!(matches!(err, WalletError::KeystoreExists(_)));
}

#[test]
fn an_unknown_format_version_is_refused() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file.version = 99;
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    assert!(matches!(
        Keystore::open(&path, "pw"),
        Err(WalletError::UnsupportedKeystoreVersion { found: 99, expected: 1 })
    ));
}

#[test]
fn an_unknown_kdf_is_refused() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file.kdf.algorithm = "argon2id".to_owned();
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    assert!(matches!(Keystore::open(&path, "pw"), Err(WalletError::UnsupportedKdf(_))));
}

#[test]
fn an_unknown_cipher_is_refused() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(file.cipher, CIPHER_NAME);
    file.cipher = "aes-256-gcm".to_owned();
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    assert!(matches!(Keystore::open(&path, "pw"), Err(WalletError::UnsupportedKdf(_))));
}

#[test]
fn a_short_salt_is_refused() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file.kdf.salt = hex::encode([1u8; 8]);
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    assert!(matches!(
        Keystore::open(&path, "pw"),
        Err(WalletError::KeystoreFieldLength { field: "kdf.salt", .. })
    ));
}

#[test]
fn non_hex_in_a_field_is_a_malformed_keystore() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file.nonce = "zzzz".to_owned();
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    assert!(matches!(Keystore::open(&path, "pw"), Err(WalletError::MalformedKeystore { .. })));
}

#[test]
fn a_file_that_is_not_json_is_a_malformed_keystore() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("garbage.json");
    std::fs::write(&path, b"not json at all").unwrap();
    assert!(matches!(Keystore::open(&path, "pw"), Err(WalletError::MalformedKeystore { .. })));
}

#[test]
fn a_missing_file_is_an_io_error() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("absent.json");
    assert!(matches!(Keystore::open(&path, "pw"), Err(WalletError::Io { .. })));
}

#[test]
fn two_keystores_of_the_same_mnemonic_have_different_ciphertexts() {
    let dir = TempDir::new().unwrap();
    let a = create(&dir, "pw");
    let mut other_rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(99);
    let b = Keystore::create(
        &dir.path().join("second.json"),
        Network::Devnet,
        &mnemonic(),
        "pw",
        WalletMeta::default(),
        fast(),
        &mut other_rng,
    )
    .unwrap();
    assert_ne!(a.file().ciphertext, b.file().ciphertext);
    assert_ne!(a.file().kdf.salt, b.file().kdf.salt);
}

#[test]
fn weak_keystore_params_are_refused_at_construction() {
    assert!(matches!(
        KeystoreParams::new(10),
        Err(WalletError::WeakKdfParameters { found: 10, minimum: 1_000 })
    ));
    assert_eq!(KeystoreParams::default().iterations, DEFAULT_PBKDF2_ITERATIONS);
}

#[test]
fn debug_never_prints_key_material() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let rendered = format!("{store:?}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(!rendered.contains(mnemonic().phrase()));
}

#[test]
fn the_default_iteration_count_is_a_real_work_factor() {
    // A regression guard: dropping this below OWASP's floor should be a
    // deliberate, reviewed change, not a typo.
    const { assert!(DEFAULT_PBKDF2_ITERATIONS >= 210_000) };
}

// ------------------------------------------------- permissions and durability

/// The keystore holds the mnemonic, and the default passphrase in
/// `chain-cli` is the empty string. A 0644 file is therefore a published
/// wallet on any shared host.
#[cfg(unix)]
#[test]
fn the_keystore_is_created_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new().unwrap();
    let mut store = create(&dir, "");
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(store.path()), 0o600, "a fresh keystore must not be world-readable");

    // And a rewrite must not widen it again: `rename` carries the temporary
    // file's mode onto the destination.
    store.set_meta(WalletMeta { account: 0, next_receive_index: 1, next_change_index: 0 }).unwrap();
    assert_eq!(mode(store.path()), 0o600, "set_meta widened the keystore's permissions");
}

#[test]
fn a_leftover_temp_file_does_not_wedge_the_keystore() {
    let dir = TempDir::new().unwrap();
    let mut store = create(&dir, "pw");
    let mut tmp = store.path().to_path_buf().into_os_string();
    tmp.push(".tmp");
    // What a crash between the write and the rename leaves behind.
    std::fs::write(std::path::PathBuf::from(&tmp), b"half a keystore").unwrap();

    store.set_meta(WalletMeta { account: 0, next_receive_index: 3, next_change_index: 1 }).unwrap();
    let reopened = Keystore::open(store.path(), "pw").unwrap();
    assert_eq!(reopened.meta().next_receive_index, 3);
}

// --------------------------------------------------------- check versus MAC

#[test]
fn a_damaged_check_value_is_not_reported_as_a_wrong_passphrase() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    drop(store);

    let mut file: KeystoreFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut bytes = hex::decode(&file.check).unwrap();
    bytes[0] ^= 0x01;
    file.check = hex::encode(&bytes);
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();

    // `check` is outside the MAC, so it is a hint and not evidence. The tag
    // still authenticates the ciphertext under a key only the right
    // passphrase produces, so this wallet is intact and must open — telling
    // the user their passphrase is wrong is how a recoverable wallet gets
    // deleted with `wallet new --force`.
    let reopened = Keystore::open(&path, "pw").unwrap();
    assert_eq!(reopened.mnemonic().phrase(), mnemonic().phrase());
}

#[test]
fn a_wrong_passphrase_is_still_a_wrong_passphrase() {
    let dir = TempDir::new().unwrap();
    let store = create(&dir, "pw");
    let path = store.path().to_path_buf();
    drop(store);
    // The MAC key is passphrase-derived, so a typo fails *both* comparisons;
    // it must still be named a typo rather than corruption.
    assert!(matches!(Keystore::open(&path, "nope"), Err(WalletError::WrongPassphrase)));
}
