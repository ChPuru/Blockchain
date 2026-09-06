//! The one error type every fallible wallet operation returns.
//!
//! Two design points are worth stating out loud.
//!
//! 1. **Authentication failures are split into two variants on purpose.**
//!    [`WalletError::WrongPassphrase`] and [`WalletError::KeystoreCorrupt`] are
//!    distinguishable because the keystore stores a passphrase *check* value
//!    derived from the same KDF output as the MAC key. Without it a user who
//!    mistypes a passphrase and a user whose file was tampered with see the
//!    same message, and the second one shrugs and retypes. Neither variant
//!    leaks key material: an attacker holding the file can already test a
//!    passphrase guess against the MAC, so the check value costs nothing.
//! 2. **There is no "insufficient funds" boolean.**
//!    [`WalletError::InsufficientFunds`] carries what was available and what
//!    was needed, because a wallet that will not say how short it is by is a
//!    wallet whose users guess.

use std::path::PathBuf;

use ferrum_crypto::CryptoError;
use ferrum_script::ScriptError;
use ferrum_types::{Amount, TypeError};

/// Everything that can go wrong in `ferrum-wallet`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WalletError {
    // ---- keystore ----
    /// A keystore already exists at this path and would have been overwritten.
    #[error("a keystore already exists at {0}")]
    KeystoreExists(PathBuf),

    /// The file at this path is not a keystore, or its JSON is malformed.
    #[error("keystore at {path} is malformed: {reason}")]
    MalformedKeystore {
        /// Where the bad file lives.
        path: PathBuf,
        /// What the parser objected to.
        reason: String,
    },

    /// The keystore was written by a newer (or older) version of the format.
    #[error("keystore version {found} is not supported (this build writes {expected})")]
    UnsupportedKeystoreVersion {
        /// The version byte read from the file.
        found: u32,
        /// The version this build understands.
        expected: u32,
    },

    /// The keystore names a key-derivation function this build cannot run.
    #[error("unsupported key-derivation function {0:?}")]
    UnsupportedKdf(String),

    /// The keystore's KDF work factor is below the floor this build accepts.
    ///
    /// A file that says "one iteration" is either corrupt or an attacker
    /// trying to make an offline guessing attack cheap.
    #[error("keystore iteration count {found} is below the minimum {minimum}")]
    WeakKdfParameters {
        /// The count read from the file.
        found: u32,
        /// The lowest count this build will accept.
        minimum: u32,
    },

    /// A field that must hold a fixed-length hex blob did not.
    #[error("keystore field {field:?} is {found} bytes, expected {expected}")]
    KeystoreFieldLength {
        /// Which field.
        field: &'static str,
        /// Bytes decoded.
        found: usize,
        /// Bytes required.
        expected: usize,
    },

    /// The passphrase did not derive the key this keystore was sealed with.
    #[error("wrong passphrase")]
    WrongPassphrase,

    /// The passphrase was right but the authentication tag did not match: the
    /// ciphertext or the authenticated metadata was modified.
    ///
    /// This is the variant that must fire instead of silently decrypting
    /// garbage into a key.
    #[error("keystore authentication failed: the file has been modified")]
    KeystoreCorrupt,

    /// The decrypted plaintext was not a valid UTF-8 mnemonic phrase.
    #[error("decrypted keystore payload is not a valid mnemonic")]
    MalformedPayload,

    /// Reading or writing the keystore failed.
    #[error("keystore i/o at {path}: {source}")]
    Io {
        /// The path being read or written.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    // ---- addresses and keys ----
    /// An address belongs to a different network than the wallet.
    #[error("address is for {found} but this wallet is for {expected}")]
    NetworkMismatch {
        /// The address's network.
        found: &'static str,
        /// The wallet's network.
        expected: &'static str,
    },

    /// No key in this wallet unlocks the given locking script.
    #[error("no key in this wallet unlocks the script being spent at input {index}")]
    UnknownInputScript {
        /// Which input could not be signed.
        index: usize,
    },

    /// The wallet only signs the script templates it knows how to size.
    #[error("unsupported script type for a wallet-managed coin")]
    UnsupportedScript,

    /// The address index space `0..2^31` was exhausted, or the derivation
    /// produced an invalid scalar (probability `2^-127`).
    #[error("address index {0} is out of range")]
    AddressIndexOutOfRange(u32),

    // ---- coin selection and building ----
    /// Not enough spendable value to cover the requested outputs plus fee.
    #[error("insufficient funds: {available} grains available, {required} grains required")]
    InsufficientFunds {
        /// Sum of the effective values of every spendable coin.
        available: u64,
        /// Target plus the fee the selection would have paid.
        required: u64,
    },

    /// A send request had no outputs.
    #[error("a send request must have at least one output")]
    NoOutputs,

    /// A requested output is at or below the dust threshold.
    #[error("output {index} of {value} grains is below the dust threshold of {threshold} grains")]
    DustOutput {
        /// Which requested output.
        index: usize,
        /// Its value in grains.
        value: u64,
        /// The threshold in grains.
        threshold: u64,
    },

    /// The requested fee rate was zero, which cannot produce a relayable
    /// transaction.
    #[error("fee rate must be at least 1 grain per 1000 bytes")]
    ZeroFeeRate,

    /// A monetary sum overflowed, or left the valid-money range.
    #[error("amount overflow while {0}")]
    AmountOverflow(&'static str),

    /// The transaction would exceed the size a `u32` length prefix, or the
    /// block, can carry.
    #[error("transaction is too large: {0} bytes")]
    TransactionTooLarge(usize),

    // ---- signing ----
    /// `prevouts` did not have one entry per input.
    #[error("expected {expected} prevouts, got {found}")]
    PrevoutCountMismatch {
        /// Number of inputs on the transaction.
        expected: usize,
        /// Number of prevouts supplied.
        found: usize,
    },

    /// The size estimated before signing and the size measured after it
    /// disagree by more than [`crate::fee::SIZE_ESTIMATE_TOLERANCE`] bytes.
    ///
    /// Underestimating is how a wallet produces transactions that never
    /// confirm, so this is a hard error rather than a log line.
    #[error("size estimate drifted: estimated {estimated} bytes, signed to {actual} bytes")]
    SizeEstimateDrift {
        /// Bytes predicted before signing.
        estimated: usize,
        /// Bytes measured after signing.
        actual: usize,
    },

    /// A signed input failed script verification.
    #[error("input {index} failed verification: {source}")]
    Verification {
        /// Which input.
        index: usize,
        /// The interpreter's complaint.
        #[source]
        source: ScriptError,
    },

    // ---- pass-throughs ----
    /// A `ferrum-crypto` operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// A `ferrum-script` operation failed.
    #[error(transparent)]
    Script(#[from] ScriptError),

    /// A `ferrum-types` operation failed.
    #[error(transparent)]
    Type(#[from] TypeError),
}

impl WalletError {
    /// Build an [`WalletError::Io`] for a path.
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        WalletError::Io { path: path.into(), source }
    }

    /// Build an [`WalletError::InsufficientFunds`] from two [`Amount`]s.
    pub(crate) fn insufficient(available: Amount, required: Amount) -> Self {
        WalletError::InsufficientFunds {
            available: available.to_grains(),
            required: required.to_grains(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn insufficient_funds_message_names_both_numbers() {
        let e = WalletError::insufficient(Amount::from_grains(10), Amount::from_grains(25));
        let s = e.to_string();
        assert!(s.contains("10"), "{s}");
        assert!(s.contains("25"), "{s}");
    }

    #[test]
    fn wrong_passphrase_and_corruption_are_distinct_variants() {
        assert!(matches!(WalletError::WrongPassphrase, WalletError::WrongPassphrase));
        assert_ne!(
            WalletError::WrongPassphrase.to_string(),
            WalletError::KeystoreCorrupt.to_string()
        );
    }

    #[test]
    fn crypto_errors_convert() {
        let e: WalletError = CryptoError::InvalidSecretKey.into();
        assert!(matches!(e, WalletError::Crypto(_)));
    }

    #[test]
    fn size_drift_message_shows_both_sizes() {
        let e = WalletError::SizeEstimateDrift { estimated: 191, actual: 250 };
        let s = e.to_string();
        assert!(s.contains("191") && s.contains("250"), "{s}");
    }
}
