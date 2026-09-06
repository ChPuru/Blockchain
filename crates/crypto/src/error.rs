//! The error type returned by every fallible operation in `ferrum-crypto`.
//!
//! One flat enum covers hashing, signatures, mnemonics, key derivation and
//! addresses. Like [`ferrum_types::TypeError`] it is deliberately **not**
//! `#[non_exhaustive]`: downstream crates map these into their own error types
//! with exhaustive `match`es, and the compiler telling them about a new
//! variant is exactly the review prompt we want.
//!
//! Every variant is `Clone + PartialEq`, so a test can assert the *exact*
//! reason a signature, phrase or address was rejected rather than merely that
//! it was rejected.

use thiserror::Error;

/// Every way a Ferrum cryptographic operation can fail.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// A 32-byte scalar was zero or was greater than or equal to the secp256k1
    /// group order, so it is not a valid secret key.
    #[error("invalid secret key: not a scalar in 1..n")]
    InvalidSecretKey,

    /// A 32-byte x-only public key is not the x-coordinate of any point on
    /// secp256k1, or exceeds the field size.
    #[error("invalid public key: not an x-only point on secp256k1")]
    InvalidPublicKey,

    /// A 64-byte signature is not a well-formed `(r, s)` pair: `r` is not a
    /// field element, or `s` is zero or at least the group order.
    #[error("malformed signature: r is not a field element, or s is not in 1..n")]
    InvalidSignatureEncoding,

    /// A signature was well-formed but does not verify against this key and
    /// message.
    #[error("signature verification failed")]
    VerificationFailed,

    /// One item in a [`crate::verify_batch`] call failed. The index is the
    /// position in the input slice, so the caller can ban exactly one peer.
    #[error("batch signature verification failed at index {index}")]
    BatchVerificationFailed {
        /// Position of the offending item in the batch.
        index: usize,
    },

    /// A signature was read from a slice that was not exactly 64 bytes.
    #[error("signature must be exactly 64 bytes, got {0}")]
    InvalidSignatureLength(usize),

    /// A public key was read from a slice that was not exactly 32 bytes.
    #[error("x-only public key must be exactly 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),

    /// A hex string was malformed, or decoded to the wrong number of bytes.
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// A mnemonic had a word count other than 12, 15, 18, 21 or 24.
    #[error("mnemonic must have 12, 15, 18, 21 or 24 words, got {0}")]
    InvalidWordCount(usize),

    /// A mnemonic contained a word that is not in the BIP-39 English list.
    #[error("word {0:?} is not in the BIP-39 English wordlist")]
    UnknownWord(String),

    /// A mnemonic's trailing checksum bits do not match `sha256(entropy)`.
    #[error("mnemonic checksum does not match the entropy")]
    InvalidMnemonicChecksum,

    /// Entropy for a mnemonic was not 16, 20, 24, 28 or 32 bytes.
    #[error("entropy must be 16, 20, 24, 28 or 32 bytes, got {0}")]
    InvalidEntropyLength(usize),

    /// A BIP-32 seed was outside the 16..=64 byte range the specification
    /// allows.
    #[error("seed must be between 16 and 64 bytes, got {0}")]
    InvalidSeedLength(usize),

    /// A child index had bit 31 set where a non-hardened index was required,
    /// or was otherwise out of range.
    #[error("child index {0} is out of range: a bare index must be below 2^31")]
    InvalidChildNumber(u32),

    /// A derivation path string could not be parsed.
    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    /// HMAC produced a tweak at or above the group order, or the tweaked key
    /// was zero. BIP-32 says to skip to the next index; the probability is
    /// below 2^-127 and silently changing the index would hand the caller a
    /// key for an address they did not ask for, so it is an error here.
    #[error("derived key is invalid; use the next child index (probability < 2^-127)")]
    DerivationOutOfRange,

    /// Deriving past depth 255, which the BIP-32 serialisation cannot express.
    #[error("derivation depth would exceed 255")]
    DepthOverflow,

    /// An address' human-readable prefix belongs to no known Ferrum network.
    #[error("unknown address prefix {0:?}: expected fer, tfer or rfer")]
    UnknownHrp(String),

    /// The bech32m layer rejected the string: bad characters, no separator,
    /// mixed case, or a checksum that is not bech32m.
    #[error("bech32m decoding failed: {0}")]
    Bech32(String),

    /// The string decoded, but re-encoding the payload does not reproduce it.
    /// That means the trailing bit-padding was non-zero, which would let two
    /// strings name one address.
    #[error("address is not canonical: re-encoding the payload yields a different string")]
    NonCanonicalAddress,

    /// The address carried a version byte this version of Ferrum does not
    /// know. New versions are a soft addition; old nodes must refuse to pay
    /// to a script they cannot build.
    #[error("unknown address version byte {0}")]
    UnknownAddressVersion(u8),

    /// The address' payload length does not match its version: 20 bytes for
    /// version 0 (P2PKH) and 32 bytes for version 1 (P2SH).
    #[error("address version {version} requires a different payload length, got {len} bytes")]
    InvalidPayloadLength {
        /// The version byte that was decoded.
        version: u8,
        /// The payload length that was decoded, in bytes.
        len: usize,
    },

    /// An address decoded to an empty data part, so it has no version byte.
    #[error("address has an empty data part")]
    EmptyAddressPayload,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn display_messages_are_stable() {
        assert_eq!(
            CryptoError::InvalidSecretKey.to_string(),
            "invalid secret key: not a scalar in 1..n"
        );
        assert_eq!(
            CryptoError::BatchVerificationFailed { index: 3 }.to_string(),
            "batch signature verification failed at index 3"
        );
        assert_eq!(
            CryptoError::InvalidWordCount(13).to_string(),
            "mnemonic must have 12, 15, 18, 21 or 24 words, got 13"
        );
        assert_eq!(
            CryptoError::UnknownWord("frobnicate".to_owned()).to_string(),
            "word \"frobnicate\" is not in the BIP-39 English wordlist"
        );
        assert_eq!(
            CryptoError::InvalidPayloadLength { version: 0, len: 32 }.to_string(),
            "address version 0 requires a different payload length, got 32 bytes"
        );
    }

    #[test]
    fn errors_compare_by_value() {
        assert_eq!(
            CryptoError::BatchVerificationFailed { index: 1 },
            CryptoError::BatchVerificationFailed { index: 1 }
        );
        assert_ne!(
            CryptoError::BatchVerificationFailed { index: 1 },
            CryptoError::BatchVerificationFailed { index: 2 }
        );
        assert_ne!(CryptoError::InvalidSecretKey, CryptoError::InvalidPublicKey);
    }

    #[test]
    fn errors_are_std_errors() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&CryptoError::VerificationFailed);
    }
}
