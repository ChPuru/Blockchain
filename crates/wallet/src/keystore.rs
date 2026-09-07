//! The encrypted keystore file.
//!
//! # What is on disk, and what never is
//!
//! The file holds the **mnemonic**, encrypted. The 64-byte BIP-39 seed and
//! every private key derived from it are computed in memory and never written
//! anywhere. That ordering matters: a seed on disk is as good as the mnemonic
//! to an attacker but useless to a human trying to recover a wallet on a
//! different implementation, so storing it would be strictly worse in both
//! directions.
//!
//! # The construction, and why it is this one
//!
//! There is no AEAD crate in this workspace — no `chacha20poly1305`, no
//! `aes-gcm` — and the contract forbids adding one. CONTRACT §12 anticipates
//! exactly this and permits **encrypt-then-MAC with HMAC-SHA512**, which is
//! what this module implements:
//!
//! ```text
//! km          = PBKDF2-HMAC-SHA512(passphrase, salt, iterations, 96 bytes)
//! enc_key     = km[0..32]        mac_key = km[32..64]        check = km[64..96]
//! keystream_i = HMAC-SHA512(enc_key, nonce || be_u32(i))
//! ciphertext  = plaintext XOR (keystream_0 || keystream_1 || ...)
//! tag         = HMAC-SHA512(mac_key, domain || header fields || metadata || ciphertext)
//! ```
//!
//! Four properties this buys, each of which a naive design gets wrong:
//!
//! 1. **Encrypt-then-MAC, not MAC-then-encrypt.** The tag is computed over the
//!    *ciphertext*, so a modified file is rejected before a single byte of it
//!    is fed to a key parser. MAC-then-encrypt has produced padding-oracle
//!    attacks for twenty years.
//! 2. **The tag covers the header and the metadata, not just the ciphertext.**
//!    Salt, nonce, iteration count and the address indices are all inside the
//!    MAC. Without that, an attacker could rewrite `iterations` to `1` and
//!    make an offline guessing attack four hundred thousand times cheaper, or
//!    roll `next_receive_index` back so the wallet re-issues an address it has
//!    already used.
//! 3. **A separate check value distinguishes a typo from tampering.** Both
//!    fail, but they fail with different errors, and a user who mistyped
//!    should not be told their file is corrupt. It leaks nothing an attacker
//!    could not already learn by testing a guess against the MAC.
//! 4. **Every comparison is constant-time** ([`subtle`]), so neither the tag
//!    nor the check value can be recovered a byte at a time by timing.
//!
//! The keystream is HMAC-SHA512 in counter mode — the same shape as
//! HKDF-Expand and as NIST SP 800-90A's HMAC_DRBG. It is not a competitive
//! cipher, but it is a construction whose security reduces to HMAC-SHA512
//! being a PRF, which is a far better position than inventing something.
//!
//! # Cost of a guess
//!
//! [`DEFAULT_PBKDF2_ITERATIONS`] is 210 000, OWASP's 2023 floor for
//! PBKDF2-HMAC-SHA512. `MIN_PBKDF2_ITERATIONS` exists so a *file* cannot ask
//! this build to accept a work factor an attacker chose.

use std::fmt;
use std::path::{Path, PathBuf};

use ferrum_crypto::Mnemonic;
use ferrum_types::Network;
use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::WalletError;

type HmacSha512 = Hmac<Sha512>;

/// Keystore format version this build writes and reads.
pub const KEYSTORE_VERSION: u32 = 1;

/// The only KDF name this build accepts.
pub const KDF_PBKDF2_HMAC_SHA512: &str = "pbkdf2-hmac-sha512";

/// The cipher/MAC construction name recorded in the file.
pub const CIPHER_NAME: &str = "hmac-sha512-ctr+hmac-sha512";

/// PBKDF2 iteration count for a freshly created keystore.
///
/// OWASP's 2023 recommendation for PBKDF2-HMAC-SHA512.
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 210_000;

/// The lowest iteration count this build will honour from a file.
///
/// A keystore that asks for fewer is either corrupt or has been edited to make
/// an offline guessing attack cheap, and either way it should not be opened
/// silently.
pub const MIN_PBKDF2_ITERATIONS: u32 = 1_000;

/// Salt length, in bytes.
pub const SALT_LEN: usize = 32;

/// Keystream nonce length, in bytes.
pub const NONCE_LEN: usize = 32;

/// HMAC-SHA512 tag length, in bytes.
pub const MAC_LEN: usize = 64;

/// Passphrase-check length, in bytes.
pub const CHECK_LEN: usize = 32;

/// Bytes of key material PBKDF2 must produce: encryption, MAC and check keys.
pub const KEY_MATERIAL_LEN: usize = 32 + 32 + CHECK_LEN;

/// Domain separator for the authentication tag, so a tag from this file can
/// never be replayed as a tag for anything else.
const MAC_DOMAIN: &[u8] = b"ferrum.v1.keystore.mac";

/// Domain separator for the keystream.
const STREAM_DOMAIN: &[u8] = b"ferrum.v1.keystore.stream";

/// KDF parameters as they appear in the file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Always [`KDF_PBKDF2_HMAC_SHA512`] in this build.
    pub algorithm: String,
    /// PBKDF2 iteration count.
    pub iterations: u32,
    /// Hex-encoded 32-byte salt.
    pub salt: String,
}

/// Tunables for creating a keystore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeystoreParams {
    /// PBKDF2 iteration count.
    pub iterations: u32,
}

impl KeystoreParams {
    /// Build a parameter set, refusing a work factor below
    /// [`MIN_PBKDF2_ITERATIONS`].
    pub fn new(iterations: u32) -> Result<Self, WalletError> {
        if iterations < MIN_PBKDF2_ITERATIONS {
            return Err(WalletError::WeakKdfParameters {
                found: iterations,
                minimum: MIN_PBKDF2_ITERATIONS,
            });
        }
        Ok(KeystoreParams { iterations })
    }
}

impl Default for KeystoreParams {
    fn default() -> Self {
        KeystoreParams { iterations: DEFAULT_PBKDF2_ITERATIONS }
    }
}

/// Wallet bookkeeping that must survive a restart but is not secret.
///
/// Not secret, but **authenticated**: it is inside the MAC, so nobody can roll
/// `next_receive_index` back and make the wallet hand out an address it has
/// already used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletMeta {
    /// BIP-44 account index.
    pub account: u32,
    /// The next unused index on the receive chain.
    pub next_receive_index: u32,
    /// The next unused index on the change chain.
    pub next_change_index: u32,
}

/// The on-disk JSON document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoreFile {
    /// Format version.
    pub version: u32,
    /// Which network this wallet's addresses belong to.
    pub network: Network,
    /// Key-derivation parameters.
    pub kdf: KdfParams,
    /// Name of the cipher/MAC construction, for a future migration to read.
    pub cipher: String,
    /// Hex-encoded 32-byte keystream nonce.
    pub nonce: String,
    /// Hex-encoded encrypted mnemonic.
    pub ciphertext: String,
    /// Hex-encoded 64-byte HMAC-SHA512 tag over everything above plus `meta`.
    pub mac: String,
    /// Hex-encoded 32-byte passphrase-check value.
    pub check: String,
    /// Authenticated, non-secret bookkeeping.
    pub meta: WalletMeta,
}

/// An open keystore: the file, its decrypted mnemonic, and the key material
/// needed to re-seal it.
///
/// Holding the mnemonic for the lifetime of the handle is a deliberate choice
/// that [`crate::Wallet`]'s contract forces: `Wallet::open(path, passphrase)`
/// takes the passphrase once and every later call must work without it. The
/// mitigation is that [`Mnemonic`] and the key material both zeroize on drop
/// and both redact themselves in `Debug`.
pub struct Keystore {
    path: PathBuf,
    file: KeystoreFile,
    mnemonic: Mnemonic,
    /// `enc_key || mac_key || check`.
    keys: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Keystore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keystore")
            .field("path", &self.path)
            .field("network", &self.file.network)
            .field("meta", &self.file.meta)
            .field("secrets", &"<redacted>")
            .finish()
    }
}

impl Keystore {
    /// Encrypt `mnemonic` under `passphrase` and write a new keystore.
    ///
    /// Refuses to overwrite an existing file: a keystore is the only copy of a
    /// key, and clobbering one is unrecoverable.
    pub fn create(
        path: &Path,
        network: Network,
        mnemonic: &Mnemonic,
        passphrase: &str,
        meta: WalletMeta,
        params: KeystoreParams,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, WalletError> {
        if path.exists() {
            return Err(WalletError::KeystoreExists(path.to_path_buf()));
        }
        if params.iterations < MIN_PBKDF2_ITERATIONS {
            return Err(WalletError::WeakKdfParameters {
                found: params.iterations,
                minimum: MIN_PBKDF2_ITERATIONS,
            });
        }

        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let keys = derive_keys(passphrase, &salt, params.iterations);
        let ciphertext = xor_keystream(&keys[..32], &nonce, mnemonic.phrase().as_bytes());

        let mut file = KeystoreFile {
            version: KEYSTORE_VERSION,
            network,
            kdf: KdfParams {
                algorithm: KDF_PBKDF2_HMAC_SHA512.to_owned(),
                iterations: params.iterations,
                salt: hex::encode(salt),
            },
            cipher: CIPHER_NAME.to_owned(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(&*ciphertext),
            mac: String::new(),
            check: hex::encode(&keys[64..]),
            meta,
        };
        file.mac = hex::encode(compute_mac(&keys[32..64], &file, &ciphertext)?);

        let keystore =
            Keystore { path: path.to_path_buf(), file, mnemonic: mnemonic.clone(), keys };
        keystore.persist()?;
        Ok(keystore)
    }

    /// Open and authenticate an existing keystore.
    ///
    /// Fails with [`WalletError::WrongPassphrase`] when the passphrase does not
    /// match and [`WalletError::KeystoreCorrupt`] when it does but the file has
    /// been modified. It never returns a key derived from unauthenticated
    /// bytes.
    pub fn open(path: &Path, passphrase: &str) -> Result<Self, WalletError> {
        let bytes = std::fs::read(path).map_err(|e| WalletError::io(path, e))?;
        let file: KeystoreFile = serde_json::from_slice(&bytes).map_err(|e| {
            WalletError::MalformedKeystore { path: path.to_path_buf(), reason: e.to_string() }
        })?;

        if file.version != KEYSTORE_VERSION {
            return Err(WalletError::UnsupportedKeystoreVersion {
                found: file.version,
                expected: KEYSTORE_VERSION,
            });
        }
        if file.kdf.algorithm != KDF_PBKDF2_HMAC_SHA512 {
            return Err(WalletError::UnsupportedKdf(file.kdf.algorithm.clone()));
        }
        if file.cipher != CIPHER_NAME {
            return Err(WalletError::UnsupportedKdf(file.cipher.clone()));
        }
        if file.kdf.iterations < MIN_PBKDF2_ITERATIONS {
            return Err(WalletError::WeakKdfParameters {
                found: file.kdf.iterations,
                minimum: MIN_PBKDF2_ITERATIONS,
            });
        }

        let salt = decode_field(path, "kdf.salt", &file.kdf.salt, Some(SALT_LEN))?;
        let nonce = decode_field(path, "nonce", &file.nonce, Some(NONCE_LEN))?;
        let stored_mac = decode_field(path, "mac", &file.mac, Some(MAC_LEN))?;
        let stored_check = decode_field(path, "check", &file.check, Some(CHECK_LEN))?;
        let ciphertext = Zeroizing::new(decode_field(path, "ciphertext", &file.ciphertext, None)?);

        let keys = derive_keys(passphrase, &salt, file.kdf.iterations);

        // Both comparisons are constant-time, and both are always evaluated.
        //
        // `check` is *not* inside the MAC, so on its own a mismatch cannot
        // tell a mistyped passphrase from a damaged `check` field — and
        // answering `WrongPassphrase` to the second case sends the user
        // hunting for a passphrase that was never lost, with an intact wallet
        // in front of them. The MAC settles it: its key is derived from the
        // passphrase, so a valid tag proves the passphrase is right and
        // therefore that `check` itself is the damaged field. It is only a
        // hint about the passphrase; the MAC is the authority on the file.
        let check_ok = bool::from(keys[64..].ct_eq(&stored_check));
        let expected_mac = compute_mac(&keys[32..64], &file, &ciphertext)?;
        let mac_ok = bool::from(expected_mac.ct_eq(&stored_mac));
        match (check_ok, mac_ok) {
            (true, true) => {}
            // The tag authenticates every field that matters, so open it and
            // say so rather than losing the wallet over an advisory field.
            (false, true) => tracing::warn!(
                path = %path.display(),
                "keystore check value does not match its contents; the MAC is intact, so the \
                 passphrase is correct and only that field is damaged"
            ),
            // A wrong passphrase derives a wrong MAC key too, so this is the
            // typo case and must keep reporting as one.
            (false, false) => return Err(WalletError::WrongPassphrase),
            (true, false) => return Err(WalletError::KeystoreCorrupt),
        }

        let plaintext = xor_keystream(&keys[..32], &nonce, &ciphertext);
        let phrase = std::str::from_utf8(&plaintext).map_err(|_| WalletError::MalformedPayload)?;
        let mnemonic = Mnemonic::from_phrase(phrase).map_err(|_| WalletError::MalformedPayload)?;

        Ok(Keystore { path: path.to_path_buf(), file, mnemonic, keys })
    }

    /// Where the file lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Which network this wallet is for.
    pub fn network(&self) -> Network {
        self.file.network
    }

    /// The decrypted mnemonic.
    ///
    /// The only way key material leaves this module. `chain-cli wallet
    /// dump-seed` is the caller that needs it.
    pub fn mnemonic(&self) -> &Mnemonic {
        &self.mnemonic
    }

    /// The persisted bookkeeping.
    pub fn meta(&self) -> WalletMeta {
        self.file.meta
    }

    /// The KDF parameters this file was sealed with.
    pub fn kdf(&self) -> &KdfParams {
        &self.file.kdf
    }

    /// Replace the bookkeeping and rewrite the file.
    ///
    /// Only the MAC is recomputed — the ciphertext and nonce are untouched,
    /// because the metadata is authenticated *associated data* rather than
    /// part of the plaintext. That keeps the nonce used exactly once per
    /// encryption, which is the one thing a keystream must never get wrong.
    pub fn set_meta(&mut self, meta: WalletMeta) -> Result<(), WalletError> {
        let ciphertext =
            Zeroizing::new(decode_field(&self.path, "ciphertext", &self.file.ciphertext, None)?);
        self.file.meta = meta;
        self.file.mac = hex::encode(compute_mac(&self.keys[32..64], &self.file, &ciphertext)?);
        self.persist()
    }

    /// The document as it would be written.
    pub fn file(&self) -> &KeystoreFile {
        &self.file
    }

    /// Write the file, replacing any previous contents atomically.
    ///
    /// Written to a sibling temporary file and renamed, so a crash mid-write
    /// leaves the previous keystore intact rather than a truncated one. A
    /// truncated keystore is a lost wallet.
    ///
    /// The temporary file is the one that is created, so it is the one whose
    /// permissions have to be right: `rename` carries the mode across, and a
    /// mode set on the destination *after* the rename would leave a window in
    /// which the ciphertext is world-readable. See [`write_private`].
    fn persist(&self) -> Result<(), WalletError> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| WalletError::io(parent, e))?;
        }
        let json = serde_json::to_vec_pretty(&self.file).map_err(|e| {
            WalletError::MalformedKeystore { path: self.path.clone(), reason: e.to_string() }
        })?;
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        write_private(&tmp, &json)?;
        std::fs::rename(&tmp, &self.path).map_err(|e| WalletError::io(&self.path, e))?;
        Ok(())
    }
}

/// Create `path` and write `bytes` to it, owner-only from the moment it exists.
///
/// `std::fs::write` creates with `0o666 & ~umask` — 0644 under the usual umask
/// — and narrowing it afterwards is too late twice over: the file is
/// world-readable for the length of the write, and a descriptor opened inside
/// that window keeps its access after the mode change, because Unix checks
/// permissions at `open` and never again. So the mode goes on the `open` call
/// itself.
///
/// Windows has no `chmod`; the datadir's own ACL is the protection there, as
/// it is for `node.key` (`crates/node/src/node/keys.rs`).
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), WalletError> {
    use std::io::Write as _;

    // `create_new` is what makes the mode load-bearing rather than advisory —
    // it refuses to write into a file someone else created and pre-opened. A
    // crash can leave our own temp file behind, though, and a leftover must
    // not wedge the wallet permanently, so clear it first.
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(WalletError::io(path, e)),
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| WalletError::io(path, e))?;
    file.write_all(bytes).map_err(|e| WalletError::io(path, e))?;
    // The rename is only atomic with respect to the *previous* file; without
    // this the new contents can still be lost to a power cut after it.
    file.sync_all().map_err(|e| WalletError::io(path, e))?;
    Ok(())
}

/// PBKDF2-HMAC-SHA512 into `enc_key || mac_key || check`.
fn derive_keys(passphrase: &str, salt: &[u8], iterations: u32) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; KEY_MATERIAL_LEN]);
    // The `hmac` feature of `pbkdf2` is off in this workspace, so drive the
    // generic PRF form. HMAC accepts a key of any length, so the only error
    // this can return is unreachable.
    pbkdf2::pbkdf2::<HmacSha512>(passphrase.as_bytes(), salt, iterations, &mut out)
        .expect("HMAC-SHA512 accepts a key of any length");
    out
}

/// HMAC-SHA512 counter-mode keystream, XORed into `data`.
///
/// Symmetric: the same call encrypts and decrypts.
fn xor_keystream(enc_key: &[u8], nonce: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(data.to_vec());
    let mut counter: u32 = 0;
    for chunk in out.chunks_mut(MAC_LEN) {
        // HMAC accepts a key of any length, so this cannot fail.
        let mut mac =
            HmacSha512::new_from_slice(enc_key).expect("HMAC-SHA512 accepts a key of any length");
        mac.update(STREAM_DOMAIN);
        mac.update(nonce);
        mac.update(&counter.to_be_bytes());
        let block = Zeroizing::new(mac.finalize().into_bytes());
        for (byte, key_byte) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= *key_byte;
        }
        counter = counter.saturating_add(1);
    }
    out
}

/// The authenticated message: a fixed-width, order-independent serialisation
/// of every field that must not change.
///
/// Deliberately *not* the JSON bytes. JSON key order, whitespace and number
/// formatting are all free variables, and a MAC over a representation with
/// free variables is a MAC that can be made to disagree with itself.
fn mac_message(file: &KeystoreFile, ciphertext: &[u8]) -> Result<Vec<u8>, WalletError> {
    let salt = hex::decode(&file.kdf.salt).map_err(|_| WalletError::KeystoreFieldLength {
        field: "kdf.salt",
        found: file.kdf.salt.len(),
        expected: SALT_LEN.saturating_mul(2),
    })?;
    let nonce = hex::decode(&file.nonce).map_err(|_| WalletError::KeystoreFieldLength {
        field: "nonce",
        found: file.nonce.len(),
        expected: NONCE_LEN.saturating_mul(2),
    })?;
    let algorithm = file.kdf.algorithm.as_bytes();
    let cipher = file.cipher.as_bytes();

    let mut msg = Vec::with_capacity(ciphertext.len().saturating_add(160));
    msg.extend_from_slice(MAC_DOMAIN);
    msg.extend_from_slice(&file.version.to_le_bytes());
    msg.extend_from_slice(&file.network.chain_id().to_u32().to_le_bytes());
    msg.extend_from_slice(&length_prefix(algorithm.len())?);
    msg.extend_from_slice(algorithm);
    msg.extend_from_slice(&length_prefix(cipher.len())?);
    msg.extend_from_slice(cipher);
    msg.extend_from_slice(&file.kdf.iterations.to_le_bytes());
    msg.extend_from_slice(&length_prefix(salt.len())?);
    msg.extend_from_slice(&salt);
    msg.extend_from_slice(&length_prefix(nonce.len())?);
    msg.extend_from_slice(&nonce);
    msg.extend_from_slice(&file.meta.account.to_le_bytes());
    msg.extend_from_slice(&file.meta.next_receive_index.to_le_bytes());
    msg.extend_from_slice(&file.meta.next_change_index.to_le_bytes());
    msg.extend_from_slice(&length_prefix(ciphertext.len())?);
    msg.extend_from_slice(ciphertext);
    Ok(msg)
}

/// A `u32` little-endian length prefix, so no two field layouts can collide.
fn length_prefix(len: usize) -> Result<[u8; 4], WalletError> {
    u32::try_from(len)
        .map(u32::to_le_bytes)
        .map_err(|_| WalletError::AmountOverflow("encoding a keystore field length"))
}

/// HMAC-SHA512 over [`mac_message`].
fn compute_mac(
    mac_key: &[u8],
    file: &KeystoreFile,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WalletError> {
    let message = mac_message(file, ciphertext)?;
    let mut mac =
        HmacSha512::new_from_slice(mac_key).expect("HMAC-SHA512 accepts a key of any length");
    mac.update(&message);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Hex-decode a field, optionally checking its length.
fn decode_field(
    path: &Path,
    field: &'static str,
    value: &str,
    expected: Option<usize>,
) -> Result<Vec<u8>, WalletError> {
    let bytes = hex::decode(value).map_err(|e| WalletError::MalformedKeystore {
        path: path.to_path_buf(),
        reason: format!("field {field:?}: {e}"),
    })?;
    if let Some(expected) = expected
        && bytes.len() != expected
    {
        return Err(WalletError::KeystoreFieldLength { field, found: bytes.len(), expected });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;

    #[test]
    fn the_keystream_round_trips() {
        let key = [3u8; 32];
        let nonce = [9u8; NONCE_LEN];
        for len in [0usize, 1, 63, 64, 65, 200] {
            let plain = vec![0xabu8; len];
            let cipher = xor_keystream(&key, &nonce, &plain);
            if len > 0 {
                assert_ne!(&*cipher, &plain[..]);
            }
            let back = xor_keystream(&key, &nonce, &cipher);
            assert_eq!(&*back, &plain[..]);
        }
    }

    #[test]
    fn the_keystream_spans_more_than_one_block() {
        // A 24-word mnemonic is over 64 bytes, so the counter must advance.
        let key = [5u8; 32];
        let nonce = [6u8; NONCE_LEN];
        let plain = vec![0u8; 130];
        let cipher = xor_keystream(&key, &nonce, &plain);
        assert_ne!(cipher[..64], cipher[64..128]);
    }
}
