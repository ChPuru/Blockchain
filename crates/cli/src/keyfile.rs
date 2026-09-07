//! Reading and writing the small key files the devnet scripts pass around.
//!
//! `devnet/fork.sh` does exactly this:
//!
//! ```sh
//! chain-cli --datadir "$dir" wallet new --output "$dir/validator.key"
//! pk=$(chain-cli --datadir "$dir" wallet dump-pubkey --key "$dir/validator.key" | tail -1)
//! chaind ... --validator-key "$dir/validator.key"
//! ```
//!
//! One file, written by `wallet new --output`, read back by `wallet
//! dump-pubkey` and by `chaind --validator-key`. So all three agree on one
//! format, and the reader accepts both shapes a key file can plausibly have:
//!
//! | File contents | Interpretation |
//! |---|---|
//! | 64 hex characters (`0x` optional) | a raw 32-byte secret key |
//! | a valid BIP-39 phrase | the seed, taken to `m/44h/7767h/0h/0/0` |
//!
//! `wallet new --output` writes the mnemonic form, because a mnemonic is
//! recoverable by a human from paper and 64 hex characters are not.
//!
//! # Why the key is not encrypted
//!
//! A validator signing key has to be readable by an unattended process at
//! startup; encrypting it and storing the passphrase next to it protects
//! nothing. The file is written with owner-only permissions where the platform
//! has them, and `RUNNING.md` says to keep it out of the repository.

use std::path::Path;

use ferrum_crypto::{Mnemonic, PublicKey, SecretKey};
use ferrum_types::Network;
use ferrum_wallet::{DEFAULT_ACCOUNT, HdKeychain, RECEIVE_CHAIN};
use zeroize::Zeroizing;

use crate::error::{CliError, CliResult};

/// The address index a key file's single key lives at.
///
/// Zero: a key file holds one key, and the first receive key of the first
/// account is the least surprising place for it to be.
pub const KEY_FILE_INDEX: u32 = 0;

/// A key loaded from a file.
#[derive(Debug)]
pub struct LoadedKey {
    /// The signing key.
    pub secret: SecretKey,
    /// Its x-only public key.
    pub public: PublicKey,
    /// The mnemonic, when the file held one.
    pub mnemonic: Option<Mnemonic>,
}

/// Load a secret key from a file in either accepted format.
///
/// # Errors
///
/// [`CliError::Io`] when the file cannot be read and [`CliError::Invalid`]
/// when its contents are neither hex nor a valid mnemonic. The error message
/// never quotes the file's contents.
pub fn load_key_file(path: &Path, network: Network) -> CliResult<LoadedKey> {
    let raw = std::fs::read(path).map_err(|e| CliError::io(path, e))?;
    let text = Zeroizing::new(
        String::from_utf8(raw)
            .map_err(|_| CliError::invalid("--key", path.display().to_string(), "not valid UTF-8"))?,
    );
    parse_key_material(text.trim(), network)
        .map_err(|reason| CliError::invalid("--key", path.display().to_string(), reason))
}

/// Interpret one line of key material.
///
/// Split out from [`load_key_file`] so the format rules are testable without
/// touching the filesystem. The error is a plain reason string, never the
/// material itself.
fn parse_key_material(text: &str, network: Network) -> Result<LoadedKey, String> {
    let hex_body = text.strip_prefix("0x").unwrap_or(text);
    if hex_body.len() == 64 && hex_body.bytes().all(|b| b.is_ascii_hexdigit()) {
        let bytes = hex::decode(hex_body).map_err(|e| e.to_string())?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| "expected 32 bytes".to_owned())?;
        let secret = SecretKey::from_bytes(&array).map_err(|e| e.to_string())?;
        let public = secret.public_key();
        return Ok(LoadedKey { secret, public, mnemonic: None });
    }

    let mnemonic = Mnemonic::from_phrase(text)
        .map_err(|e| format!("not a 32-byte hex key and not a valid mnemonic ({e})"))?;
    let keychain = HdKeychain::from_mnemonic(&mnemonic, "", network).map_err(|e| e.to_string())?;
    let derived =
        keychain.derive(DEFAULT_ACCOUNT, RECEIVE_CHAIN, KEY_FILE_INDEX).map_err(|e| e.to_string())?;
    let secret =
        SecretKey::from_bytes(&derived.secret_key().to_bytes()).map_err(|e| e.to_string())?;
    let public = *derived.public_key();
    Ok(LoadedKey { secret, public, mnemonic: Some(mnemonic) })
}

/// Write a mnemonic to `path`, owner-readable only where the platform allows.
///
/// The file gets a trailing newline so that a shell `$(cat ...)` yields the
/// phrase unchanged.
///
/// # Errors
///
/// [`CliError::Io`] naming the path.
pub fn write_key_file(path: &Path, mnemonic: &Mnemonic) -> CliResult<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| CliError::io(parent, e))?;
    }
    let mut body = Zeroizing::new(String::with_capacity(mnemonic.phrase().len().saturating_add(1)));
    body.push_str(mnemonic.phrase());
    body.push('\n');
    std::fs::write(path, body.as_bytes()).map_err(|e| CliError::io(path, e))?;
    restrict_permissions(path);
    Ok(())
}

/// Narrow a secret file's permissions to the owner where the platform has the
/// concept.
///
/// Best effort: a filesystem without the concept (FAT, some bind mounts) is
/// not a reason to refuse to write the key, and the failure is logged rather
/// than swallowed.
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "could not restrict key file permissions"
            );
        }
    }
    #[cfg(not(unix))]
    {
        // Windows inherits the parent directory ACL, which for a per-user
        // datadir is already owner-only. There is no portable chmod here, and
        // shelling out to icacls from a key-writing path is worse than
        // inheriting.
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn a_mnemonic() -> Mnemonic {
        Mnemonic::from_phrase(PHRASE).unwrap()
    }

    #[test]
    fn a_hex_key_file_round_trips_to_the_same_public_key() {
        let loaded = parse_key_material(&hex::encode([7u8; 32]), Network::Devnet).unwrap();
        let expected = SecretKey::from_bytes(&[7u8; 32]).unwrap().public_key();
        assert_eq!(loaded.public.as_bytes(), expected.as_bytes());
        assert!(loaded.mnemonic.is_none());
    }

    #[test]
    fn the_0x_prefix_is_accepted() {
        let with =
            parse_key_material(&format!("0x{}", hex::encode([9u8; 32])), Network::Devnet).unwrap();
        let without = parse_key_material(&hex::encode([9u8; 32]), Network::Devnet).unwrap();
        assert_eq!(with.public.as_bytes(), without.public.as_bytes());
    }

    #[test]
    fn a_mnemonic_file_derives_the_first_receive_key() {
        let loaded = parse_key_material(PHRASE, Network::Devnet).unwrap();
        let keychain = HdKeychain::from_mnemonic(&a_mnemonic(), "", Network::Devnet).unwrap();
        let expected = keychain.derive(DEFAULT_ACCOUNT, RECEIVE_CHAIN, KEY_FILE_INDEX).unwrap();
        assert_eq!(loaded.public.as_bytes(), expected.public_key().as_bytes());
        assert!(loaded.mnemonic.is_some());
    }

    #[test]
    fn rubbish_is_refused_without_being_echoed() {
        let err = parse_key_material("not a key at all", Network::Devnet).unwrap_err();
        assert!(!err.contains("not a key at all"), "{err}");
    }

    #[test]
    fn write_then_load_gives_back_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validator.key");
        write_key_file(&path, &a_mnemonic()).unwrap();
        let loaded = load_key_file(&path, Network::Devnet).unwrap();
        let expected = parse_key_material(PHRASE, Network::Devnet).unwrap();
        assert_eq!(loaded.public.as_bytes(), expected.public.as_bytes());
    }

    #[test]
    fn a_key_file_ends_with_a_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        write_key_file(&path, &a_mnemonic()).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with('\n'));
        assert_eq!(text.trim(), PHRASE);
    }
}
