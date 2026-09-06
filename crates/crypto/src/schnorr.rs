//! BIP-340 Schnorr signatures over secp256k1.
//!
//! The primitive comes from `k256`'s `schnorr` feature; nothing here
//! hand-rolls the algorithm. This module is a thin, *typed* skin over it:
//!
//! - [`SecretKey`] wraps `k256::SecretKey`, which zeroizes on drop.
//! - [`PublicKey`] is the 32-byte **x-only** encoding, as BIP-340 defines it.
//!   Constructing one always checks that the bytes are the x-coordinate of a
//!   real curve point, so a `PublicKey` value is never un-verifiable.
//! - [`Signature`] is 64 opaque bytes. It is deliberately *not* validated on
//!   construction: an attacker-supplied signature is data, and whether it is
//!   well-formed is decided during [`PublicKey::verify`], which is also where
//!   `s >= n` and `r >= p` are rejected.
//!
//! # Determinism
//!
//! [`SecretKey::sign`] is BIP-340 with explicit auxiliary randomness, and
//! [`SecretKey::sign_deterministic`] fixes `aux = [0u8; 32]`. Fixed aux is
//! what makes a test vector reproducible; it is also what BIP-340 explicitly
//! permits when no randomness source is available, because the nonce is still
//! bound to the secret key and the message.
//!
//! ```
//! use ferrum_crypto::{SecretKey, TAG_SIGHASH, tagged_hash};
//!
//! let sk = SecretKey::from_bytes(&[7u8; 32])?;
//! let pk = sk.public_key();
//! let msg = tagged_hash(TAG_SIGHASH, b"spend me");
//! let sig = sk.sign_deterministic(&msg);
//! assert!(pk.verify(&msg, &sig).is_ok());
//! # Ok::<(), ferrum_crypto::CryptoError>(())
//! ```

use std::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use ferrum_types::{Hash32, ValidatorId};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::{SigningKey, VerifyingKey};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Bytes in an x-only BIP-340 public key.
pub const PUBLIC_KEY_SIZE: usize = 32;
/// Bytes in a BIP-340 signature.
pub const SIGNATURE_SIZE: usize = 64;
/// Bytes in a secp256k1 secret scalar.
pub const SECRET_KEY_SIZE: usize = 32;
/// Bytes in a SEC1 *compressed* public key, as BIP-32 serialises parent keys.
pub const COMPRESSED_PUBLIC_KEY_SIZE: usize = 33;

/// A secp256k1 secret scalar. Zeroized on drop.
///
/// The stored scalar is exactly the one the caller supplied. BIP-340 signing
/// conditionally negates it so that the public point has an even y-coordinate,
/// but that negation happens inside the signer and never changes what
/// [`SecretKey::to_bytes`] returns — which matters, because BIP-32 child
/// derivation is defined over the un-negated scalar.
#[derive(Clone)]
pub struct SecretKey(k256::SecretKey);

impl SecretKey {
    /// Parse a 32-byte big-endian scalar.
    ///
    /// Fails when the scalar is zero or at least the group order `n`.
    pub fn from_bytes(b: &[u8; SECRET_KEY_SIZE]) -> Result<Self, CryptoError> {
        k256::SecretKey::from_slice(b).map(SecretKey).map_err(|_| CryptoError::InvalidSecretKey)
    }

    /// Draw a fresh key from a cryptographic RNG.
    pub fn random(rng: &mut impl rand_core::CryptoRngCore) -> Self {
        SecretKey(k256::SecretKey::random(rng))
    }

    /// The 32-byte big-endian scalar. **Callers must zeroize the result.**
    // `&self` because CONTRACT §4 spells the signature that way.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        let mut wide = self.0.to_bytes();
        let mut out = [0u8; SECRET_KEY_SIZE];
        out.copy_from_slice(wide.as_slice());
        wide.as_mut_slice().zeroize();
        out
    }

    /// The matching x-only public key.
    pub fn public_key(&self) -> PublicKey {
        let signing = SigningKey::from(&self.0);
        let mut out = [0u8; PUBLIC_KEY_SIZE];
        out.copy_from_slice(signing.verifying_key().to_bytes().as_slice());
        PublicKey(out)
    }

    /// BIP-340 sign, deterministic given `aux`.
    ///
    /// # Panics
    ///
    /// Never in practice. `k256` only fails here when the derived nonce or the
    /// resulting `s` reduces to zero, which requires hitting one specific
    /// value out of `n ≈ 2^256`; there is no attacker-reachable input that
    /// makes it happen, and returning `Result` from a signing call the
    /// contract declares infallible would push that impossibility into every
    /// caller.
    pub fn sign(&self, msg: &Hash32, aux: &[u8; 32]) -> Signature {
        let signing = SigningKey::from(&self.0);
        let sig = signing
            .sign_raw(msg.as_bytes(), aux)
            .expect("BIP-340 nonce or s is zero: probability 2^-256, unreachable in practice");
        Signature(sig.to_bytes())
    }

    /// BIP-340 sign with `aux = [0u8; 32]`.
    ///
    /// Deterministic, so two nodes signing the same message with the same key
    /// produce byte-identical signatures. Used throughout the tests and by the
    /// BFT engine, where a reproducible vote is easier to reason about than a
    /// randomised one.
    pub fn sign_deterministic(&self, msg: &Hash32) -> Signature {
        self.sign(msg, &[0u8; 32])
    }

    /// The SEC1 *compressed* (33-byte) public key of the underlying scalar.
    ///
    /// BIP-32 non-hardened derivation hashes this, not the x-only form: the
    /// parity byte is part of the specification and dropping it would make our
    /// derivation incompatible with every other BIP-32 implementation.
    pub(crate) fn compressed_public_key(&self) -> [u8; COMPRESSED_PUBLIC_KEY_SIZE] {
        let point = self.0.public_key().to_encoded_point(true);
        let mut out = [0u8; COMPRESSED_PUBLIC_KEY_SIZE];
        // `to_encoded_point(true)` on secp256k1 is always 33 bytes.
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// The wrapped `k256` key, for scalar arithmetic in [`crate::bip32`].
    pub(crate) fn inner(&self) -> &k256::SecretKey {
        &self.0
    }
}

impl PartialEq for SecretKey {
    /// Constant-time, so comparing keys cannot leak them through timing.
    fn eq(&self, other: &Self) -> bool {
        let mut a = self.to_bytes();
        let mut b = other.to_bytes();
        let equal = a.ct_eq(&b).into();
        a.zeroize();
        b.zeroize();
        equal
    }
}

impl Eq for SecretKey {}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material, not even in a panic message.
        f.write_str("SecretKey(<redacted>)")
    }
}

// The inner `k256::SecretKey` is `ZeroizeOnDrop`, so this newtype inherits the
// property through its drop glue.
impl ZeroizeOnDrop for SecretKey {}

/// An x-only BIP-340 public key: the 32-byte x-coordinate of a curve point
/// whose y-coordinate is even.
///
/// Every constructor verifies that the bytes really are on the curve, so a
/// `PublicKey` that exists is a key that can be verified against. Borsh
/// decoding runs the same check, which keeps "decoded values are canonical"
/// true for this type as well.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    /// Parse and validate 32 x-only bytes.
    pub fn from_bytes(b: &[u8; PUBLIC_KEY_SIZE]) -> Result<Self, CryptoError> {
        VerifyingKey::from_bytes(b).map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(PublicKey(*b))
    }

    /// Parse and validate a slice that must be exactly 32 bytes.
    pub fn from_slice(b: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; PUBLIC_KEY_SIZE] =
            b.try_into().map_err(|_| CryptoError::InvalidPublicKeyLength(b.len()))?;
        PublicKey::from_bytes(&arr)
    }

    /// Borrow the 32 x-only bytes.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Copy out the 32 x-only bytes.
    pub const fn to_bytes(self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0
    }

    /// Lowercase hex, 64 characters.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse 64 hex characters, with an optional `0x`.
    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let body = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        let raw = hex::decode(body).map_err(|e| CryptoError::InvalidHex(e.to_string()))?;
        PublicKey::from_slice(&raw)
    }

    /// Verify a BIP-340 signature over a 32-byte message digest.
    ///
    /// Rejects, in this order: a public key that is not on the curve, a
    /// signature whose `r` is not a field element or whose `s` is zero or at
    /// least `n`, and finally a well-formed signature that does not verify.
    pub fn verify(&self, msg: &Hash32, sig: &Signature) -> Result<(), CryptoError> {
        let vk = VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidPublicKey)?;
        let parsed = k256::schnorr::Signature::try_from(sig.0.as_slice())
            .map_err(|_| CryptoError::InvalidSignatureEncoding)?;
        vk.verify_raw(msg.as_bytes(), &parsed).map_err(|_| CryptoError::VerificationFailed)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0)
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut b = [0u8; PUBLIC_KEY_SIZE];
        reader.read_exact(&mut b)?;
        // Validate on decode, so an off-curve key can never enter the system
        // through a peer message or a database row.
        PublicKey::from_bytes(&b)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}

impl From<PublicKey> for ValidatorId {
    fn from(pk: PublicKey) -> Self {
        ValidatorId(pk.0)
    }
}

impl TryFrom<ValidatorId> for PublicKey {
    type Error = CryptoError;

    fn try_from(v: ValidatorId) -> Result<Self, Self::Error> {
        PublicKey::from_bytes(&v.0)
    }
}

/// A 64-byte BIP-340 signature, `r || s`.
///
/// Held as opaque bytes. Validity — `r` a field element, `s` in `1..n` — is
/// checked in [`PublicKey::verify`], because a signature arriving from the
/// network is untrusted input and rejecting it at parse time would only move
/// the same check earlier while making the type harder to carry around.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    /// Wrap 64 raw bytes.
    pub const fn from_bytes(b: [u8; SIGNATURE_SIZE]) -> Self {
        Signature(b)
    }

    /// Wrap a slice that must be exactly 64 bytes.
    pub fn from_slice(b: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; SIGNATURE_SIZE] =
            b.try_into().map_err(|_| CryptoError::InvalidSignatureLength(b.len()))?;
        Ok(Signature(arr))
    }

    /// Borrow the 64 raw bytes.
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }

    /// Copy out the 64 raw bytes.
    pub const fn to_bytes(self) -> [u8; SIGNATURE_SIZE] {
        self.0
    }

    /// Lowercase hex, 128 characters.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse 128 hex characters, with an optional `0x`.
    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let body = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        let raw = hex::decode(body).map_err(|e| CryptoError::InvalidHex(e.to_string()))?;
        Signature::from_slice(&raw)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}

/// Verify many `(key, message, signature)` triples.
///
/// # Implementation note
///
/// `k256` 0.13 exposes no batch verifier for BIP-340, so this loops over
/// [`PublicKey::verify`]. The signature is deliberately the one a real batch
/// verifier wants — a slice of triples, one aggregate `Result` — so that
/// dropping in a Strauss/Pippenger batch check later is a body change with no
/// caller churn. Callers should already be treating a batch failure as "this
/// message is bad", not "this signature is bad".
///
/// The returned [`CryptoError::BatchVerificationFailed`] carries the index of
/// the first failing item, so a peer-scoring caller can attribute the failure.
/// A true batch verifier only learns *that* the batch failed, so callers must
/// not depend on the index being present for every future implementation —
/// re-verify individually if you need attribution.
pub fn verify_batch(items: &[(PublicKey, Hash32, Signature)]) -> Result<(), CryptoError> {
    for (index, (pk, msg, sig)) in items.iter().enumerate() {
        pk.verify(msg, sig).map_err(|_| CryptoError::BatchVerificationFailed { index })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::hashing::{TAG_SIGHASH, tagged_hash};

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_bytes(&[byte; 32]).unwrap()
    }

    fn msg(s: &[u8]) -> Hash32 {
        tagged_hash(TAG_SIGHASH, s)
    }

    #[test]
    fn zero_and_overflowing_scalars_are_rejected() {
        assert_eq!(SecretKey::from_bytes(&[0u8; 32]), Err(CryptoError::InvalidSecretKey));
        // n itself, and everything above it, is out of range.
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        let n: [u8; 32] = n.try_into().unwrap();
        assert_eq!(SecretKey::from_bytes(&n), Err(CryptoError::InvalidSecretKey));
        assert_eq!(SecretKey::from_bytes(&[0xff; 32]), Err(CryptoError::InvalidSecretKey));
        // n - 1 is fine.
        let mut n_minus_1 = n;
        n_minus_1[31] = 0x40;
        assert!(SecretKey::from_bytes(&n_minus_1).is_ok());
    }

    #[test]
    fn secret_key_round_trips_its_bytes_unnegated() {
        for b in [1u8, 2, 3, 7, 0x42] {
            let sk = key(b);
            assert_eq!(sk.to_bytes(), [b; 32], "signing must not mutate the stored scalar");
        }
    }

    #[test]
    fn secret_key_equality_is_by_value() {
        assert_eq!(key(3), key(3));
        assert_ne!(key(3), key(4));
    }

    #[test]
    fn secret_key_debug_is_redacted() {
        assert_eq!(format!("{:?}", key(9)), "SecretKey(<redacted>)");
    }

    #[test]
    fn sign_then_verify() {
        let sk = key(1);
        let pk = sk.public_key();
        let m = msg(b"hello");
        assert_eq!(pk.verify(&m, &sk.sign_deterministic(&m)), Ok(()));
    }

    #[test]
    fn sign_deterministic_is_reproducible() {
        let sk = key(5);
        let m = msg(b"same message");
        assert_eq!(sk.sign_deterministic(&m), sk.sign_deterministic(&m));
        assert_eq!(sk.sign_deterministic(&m), sk.sign(&m, &[0u8; 32]));
    }

    #[test]
    fn different_aux_gives_a_different_but_valid_signature() {
        let sk = key(5);
        let pk = sk.public_key();
        let m = msg(b"same message");
        let a = sk.sign(&m, &[0u8; 32]);
        let b = sk.sign(&m, &[1u8; 32]);
        assert_ne!(a, b, "aux must feed the nonce");
        assert!(pk.verify(&m, &a).is_ok());
        assert!(pk.verify(&m, &b).is_ok());
    }

    #[test]
    fn a_signature_does_not_verify_under_another_key() {
        let m = msg(b"transfer 1 FRM");
        let sig = key(1).sign_deterministic(&m);
        assert_eq!(key(2).public_key().verify(&m, &sig), Err(CryptoError::VerificationFailed));
    }

    #[test]
    fn a_signature_does_not_verify_over_another_message() {
        let sk = key(1);
        let sig = sk.sign_deterministic(&msg(b"pay alice"));
        assert_eq!(
            sk.public_key().verify(&msg(b"pay bob"), &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn flipping_any_signature_bit_breaks_verification() {
        let sk = key(11);
        let pk = sk.public_key();
        let m = msg(b"bit flips");
        let good = sk.sign_deterministic(&m);
        for byte in [0usize, 1, 31, 32, 33, 63] {
            let mut raw = good.to_bytes();
            raw[byte] ^= 0x01;
            let tampered = Signature::from_bytes(raw);
            assert!(pk.verify(&m, &tampered).is_err(), "byte {byte} flip verified");
        }
    }

    #[test]
    fn public_key_rejects_off_curve_bytes() {
        // From BIP-340 vector 5: this x-coordinate is not on the curve.
        let bad = hex::decode("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
            .unwrap();
        assert_eq!(PublicKey::from_slice(&bad), Err(CryptoError::InvalidPublicKey));
        // ...and one that exceeds the field size (BIP-340 vector 14).
        let too_big =
            hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30")
                .unwrap();
        assert_eq!(PublicKey::from_slice(&too_big), Err(CryptoError::InvalidPublicKey));
    }

    #[test]
    fn public_key_rejects_wrong_lengths() {
        assert_eq!(PublicKey::from_slice(&[0u8; 31]), Err(CryptoError::InvalidPublicKeyLength(31)));
        assert_eq!(PublicKey::from_slice(&[0u8; 33]), Err(CryptoError::InvalidPublicKeyLength(33)));
    }

    #[test]
    fn public_key_hex_round_trip() {
        let pk = key(3).public_key();
        assert_eq!(PublicKey::from_hex(&pk.to_hex()).unwrap(), pk);
        assert_eq!(PublicKey::from_hex(&format!("0x{}", pk.to_hex())).unwrap(), pk);
        assert_eq!(pk.to_string(), pk.to_hex());
        assert_eq!(format!("{pk:?}"), format!("PublicKey({})", pk.to_hex()));
        assert!(matches!(PublicKey::from_hex("zz"), Err(CryptoError::InvalidHex(_))));
    }

    #[test]
    fn signature_hex_and_slice_round_trip() {
        let sig = key(3).sign_deterministic(&msg(b"x"));
        assert_eq!(Signature::from_hex(&sig.to_hex()).unwrap(), sig);
        assert_eq!(Signature::from_slice(sig.as_bytes()).unwrap(), sig);
        assert_eq!(Signature::from_slice(&[0u8; 63]), Err(CryptoError::InvalidSignatureLength(63)));
        assert_eq!(sig.to_string(), sig.to_hex());
        assert_eq!(format!("{sig:?}"), format!("Signature({})", sig.to_hex()));
    }

    #[test]
    fn public_key_borsh_round_trips_and_rejects_off_curve() {
        let pk = key(3).public_key();
        let bytes = borsh::to_vec(&pk).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes, pk.as_bytes().to_vec());
        assert_eq!(borsh::from_slice::<PublicKey>(&bytes).unwrap(), pk);

        let bad = hex::decode("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
            .unwrap();
        assert!(borsh::from_slice::<PublicKey>(&bad).is_err());
        // Trailing bytes are never tolerated.
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(borsh::from_slice::<PublicKey>(&extra).is_err());
    }

    #[test]
    fn signature_borsh_round_trips() {
        let sig = key(3).sign_deterministic(&msg(b"x"));
        let bytes = borsh::to_vec(&sig).unwrap();
        assert_eq!(bytes.len(), 64);
        assert_eq!(borsh::from_slice::<Signature>(&bytes).unwrap(), sig);
    }

    #[test]
    fn validator_id_conversions() {
        let pk = key(3).public_key();
        let vid = ValidatorId::from(pk);
        assert_eq!(vid.0, *pk.as_bytes());
        assert_eq!(PublicKey::try_from(vid).unwrap(), pk);
        assert_eq!(PublicKey::try_from(ValidatorId([0u8; 32])), Err(CryptoError::InvalidPublicKey));
    }

    #[test]
    fn compressed_public_key_x_matches_the_x_only_key() {
        for b in [1u8, 2, 3, 9] {
            let sk = key(b);
            let comp = sk.compressed_public_key();
            assert!(comp[0] == 0x02 || comp[0] == 0x03, "not a SEC1 compressed prefix");
            let pk = sk.public_key();
            assert_eq!(&comp[1..], pk.as_bytes().as_slice());
        }
    }

    #[test]
    fn batch_verify_accepts_all_good() {
        let items: Vec<_> = (1u8..=8)
            .map(|b| {
                let sk = key(b);
                let m = msg(&[b]);
                (sk.public_key(), m, sk.sign_deterministic(&m))
            })
            .collect();
        assert_eq!(verify_batch(&items), Ok(()));
        assert_eq!(verify_batch(&[]), Ok(()), "an empty batch trivially verifies");
    }

    #[test]
    fn batch_verify_reports_the_first_bad_index() {
        let mut items: Vec<_> = (1u8..=5)
            .map(|b| {
                let sk = key(b);
                let m = msg(&[b]);
                (sk.public_key(), m, sk.sign_deterministic(&m))
            })
            .collect();
        items[3].1 = msg(b"not what was signed");
        assert_eq!(verify_batch(&items), Err(CryptoError::BatchVerificationFailed { index: 3 }));
    }

    #[test]
    fn batch_verify_rejects_a_malformed_signature() {
        let sk = key(1);
        let m = msg(b"x");
        let bogus = Signature::from_bytes([0xff; 64]);
        assert_eq!(
            verify_batch(&[(sk.public_key(), m, bogus)]),
            Err(CryptoError::BatchVerificationFailed { index: 0 })
        );
    }

    #[test]
    fn random_keys_differ_and_sign() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xfe22_0001);
        let a = SecretKey::random(&mut rng);
        let b = SecretKey::random(&mut rng);
        assert_ne!(a, b);
        let m = msg(b"random");
        assert!(a.public_key().verify(&m, &a.sign_deterministic(&m)).is_ok());
    }
}
