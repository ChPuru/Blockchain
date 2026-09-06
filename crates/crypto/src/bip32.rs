//! BIP-32 hierarchical deterministic key derivation over secp256k1.
//!
//! Ferrum follows BIP-32 exactly, with two substitutions the specification
//! anticipates:
//!
//! - the master HMAC key is `"Ferrum seed"` rather than `"Bitcoin seed"`, so a
//!   Ferrum wallet and a Bitcoin wallet restored from the same BIP-39 phrase
//!   have unrelated key trees (CONTRACT §4);
//! - the coin type is [`COIN_TYPE`] = 7767, giving the BIP-44 path
//!   `m/44'/7767'/account'/change/index`.
//!
//! Everything else — the HMAC-SHA512 child derivation, the scalar addition
//! modulo `n`, the `hash160`-based fingerprints, the hardened/normal split at
//! bit 31 — is BIP-32 unchanged. A unit test re-runs the *official* BIP-32
//! test vector 1 through the same code with the Bitcoin master key, which is
//! what proves the machinery itself is right rather than merely
//! self-consistent.
//!
//! # x-only keys and the parity byte
//!
//! Ferrum signs with BIP-340, whose public keys are x-only. Derivation is
//! nevertheless done on the full secp256k1 key, and non-hardened derivation
//! hashes the 33-byte **compressed** parent public key exactly as BIP-32 says.
//! That is the same choice Bitcoin made for taproot (BIP-86): the x-only form
//! is an output encoding, not a derivation format. Dropping the parity byte
//! would fork Ferrum away from every existing BIP-32 implementation for no
//! benefit.
//!
//! # Only private derivation
//!
//! [`ExtendedKey`] always carries the secret. There is no extended *public*
//! key type, and therefore no watch-only derivation, in v1: an xpub plus one
//! leaked child private key reveals the master private key, and that footgun
//! is not worth shipping before a wallet actually needs it.
//!
//! ```
//! use ferrum_crypto::{DerivationPath, ExtendedKey, Mnemonic};
//!
//! let m = Mnemonic::from_entropy(&[0u8; 16])?;
//! let master = ExtendedKey::master_from_seed(&m.to_seed(""))?;
//! let path: DerivationPath = "m/44'/7767'/0'/0/0".parse()?;
//! let account_key = master.derive_path(&path)?;
//! assert_eq!(account_key.depth(), 5);
//! # Ok::<(), ferrum_crypto::CryptoError>(())
//! ```

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use crate::hashing::hash160;
use crate::schnorr::{PublicKey, SecretKey};

mod path;

pub use crate::bip32::path::{BIP44_PURPOSE, COIN_TYPE, ChildNumber, DerivationPath, HARDENED_BIT};

/// HMAC key for master derivation. Ferrum's counterpart to `"Bitcoin seed"`.
const HD_SEED_KEY: &[u8] = b"Ferrum seed";

/// Shortest seed BIP-32 accepts, in bytes.
pub const MIN_SEED_LEN: usize = 16;
/// Longest seed BIP-32 accepts, in bytes.
pub const MAX_SEED_LEN: usize = 64;

type HmacSha512 = Hmac<Sha512>;

/// A BIP-32 extended private key: a secret scalar plus the chain code and the
/// position metadata that make derivation reproducible.
#[derive(Clone)]
pub struct ExtendedKey {
    secret: SecretKey,
    chain_code: [u8; 32],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: ChildNumber,
}

impl ExtendedKey {
    /// Derive the master key from a BIP-39 (or any) seed.
    ///
    /// `seed` must be 16 to 64 bytes. `HMAC-SHA512("Ferrum seed", seed)` splits
    /// into the master secret (left 32 bytes) and the master chain code (right
    /// 32 bytes).
    pub fn master_from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        Self::master_from_seed_with_key(HD_SEED_KEY, seed)
    }

    /// Master derivation with an explicit HMAC key.
    ///
    /// Private because the key is a consensus-visible constant: exposing it
    /// would invite a caller to derive a tree no other Ferrum node can
    /// reproduce. The unit tests use it to re-run the official BIP-32 vectors
    /// with `"Bitcoin seed"`.
    fn master_from_seed_with_key(hmac_key: &[u8], seed: &[u8]) -> Result<Self, CryptoError> {
        if seed.len() < MIN_SEED_LEN || seed.len() > MAX_SEED_LEN {
            return Err(CryptoError::InvalidSeedLength(seed.len()));
        }
        let mut mac =
            HmacSha512::new_from_slice(hmac_key).expect("HMAC-SHA512 accepts a key of any length");
        mac.update(seed);
        let mut wide = mac.finalize().into_bytes();

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&wide[..32]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&wide[32..]);
        wide.as_mut_slice().zeroize();

        let secret = SecretKey::from_bytes(&secret_bytes);
        secret_bytes.zeroize();
        let secret = secret.map_err(|_| CryptoError::DerivationOutOfRange)?;

        Ok(ExtendedKey {
            secret,
            chain_code,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_number: ChildNumber::ZERO,
        })
    }

    /// Derive one child, hardened or not (BIP-32 CKDpriv).
    pub fn derive_child(&self, index: ChildNumber) -> Result<Self, CryptoError> {
        let depth = self.depth.checked_add(1).ok_or(CryptoError::DepthOverflow)?;

        let mut mac = HmacSha512::new_from_slice(&self.chain_code)
            .expect("HMAC-SHA512 accepts a key of any length");
        if index.is_hardened() {
            // 0x00 || ser256(k_par) — only a private key can do this.
            let mut parent = self.secret.to_bytes();
            mac.update(&[0u8]);
            mac.update(&parent);
            parent.zeroize();
        } else {
            // serP(K_par): the 33-byte compressed public key, parity included.
            mac.update(&self.secret.compressed_public_key());
        }
        mac.update(&index.to_u32().to_be_bytes());
        let mut wide = mac.finalize().into_bytes();

        let mut tweak_bytes = [0u8; 32];
        tweak_bytes.copy_from_slice(&wide[..32]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&wide[32..]);
        wide.as_mut_slice().zeroize();

        // parse256(IL) must be a valid scalar; BIP-32 says skip to the next
        // index if it is not, but silently changing the index would hand the
        // caller a different address than they asked for.
        let tweak = k256::SecretKey::from_slice(&tweak_bytes);
        tweak_bytes.zeroize();
        let tweak = tweak.map_err(|_| CryptoError::DerivationOutOfRange)?;

        // k_child = (IL + k_par) mod n, rejected if it lands on zero.
        let sum = *tweak.to_nonzero_scalar() + *self.secret.inner().to_nonzero_scalar();
        let mut sum_bytes = sum.to_bytes();
        let mut child_bytes = [0u8; 32];
        child_bytes.copy_from_slice(sum_bytes.as_slice());
        sum_bytes.as_mut_slice().zeroize();

        let child_secret = SecretKey::from_bytes(&child_bytes);
        child_bytes.zeroize();
        let secret = child_secret.map_err(|_| CryptoError::DerivationOutOfRange)?;

        Ok(ExtendedKey {
            secret,
            chain_code,
            depth,
            parent_fingerprint: self.fingerprint(),
            child_number: index,
        })
    }

    /// Derive every step of `path` in order.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, CryptoError> {
        let mut current = self.clone();
        for step in path.iter() {
            current = current.derive_child(*step)?;
        }
        Ok(current)
    }

    /// The secret key at this node.
    pub fn secret_key(&self) -> SecretKey {
        self.secret.clone()
    }

    /// The x-only public key at this node.
    pub fn public_key(&self) -> PublicKey {
        self.secret.public_key()
    }

    /// The 32-byte chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Depth below the master key: 0 for the master itself.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// First four bytes of the parent identifier, or zeros for the master.
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        self.parent_fingerprint
    }

    /// The child number this node was derived with.
    pub fn child_number(&self) -> ChildNumber {
        self.child_number
    }

    /// `hash160(serP(K))` — the BIP-32 identifier of this node.
    pub fn identifier(&self) -> [u8; 20] {
        hash160(&self.secret.compressed_public_key())
    }

    /// The first four bytes of [`ExtendedKey::identifier`].
    pub fn fingerprint(&self) -> [u8; 4] {
        let id = self.identifier();
        [id[0], id[1], id[2], id[3]]
    }
}

impl PartialEq for ExtendedKey {
    /// Compares the secret and the chain code in constant time, and computes
    /// all three parts before combining them so that no branch reveals *which*
    /// field differed.
    fn eq(&self, other: &Self) -> bool {
        let meta = self.depth == other.depth
            && self.parent_fingerprint == other.parent_fingerprint
            && self.child_number == other.child_number;
        let chain_code = bool::from(self.chain_code.ct_eq(&other.chain_code));
        let secret = self.secret == other.secret;
        meta & chain_code & secret
    }
}

impl Eq for ExtendedKey {}

impl fmt::Debug for ExtendedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither the secret nor the chain code may reach a log line: the
        // chain code plus one child key is enough to walk the tree.
        f.debug_struct("ExtendedKey")
            .field("depth", &self.depth)
            .field("parent_fingerprint", &hex::encode(self.parent_fingerprint))
            .field("child_number", &self.child_number)
            .field("fingerprint", &hex::encode(self.fingerprint()))
            .field("secret", &"<redacted>")
            .field("chain_code", &"<redacted>")
            .finish()
    }
}

impl Drop for ExtendedKey {
    fn drop(&mut self) {
        // `secret` zeroizes itself; the chain code needs doing by hand.
        self.chain_code.zeroize();
    }
}

impl ZeroizeOnDrop for ExtendedKey {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const SEED: [u8; 32] = [0x2a; 32];

    fn master() -> ExtendedKey {
        ExtendedKey::master_from_seed(&SEED).unwrap()
    }

    #[test]
    fn seed_length_is_enforced() {
        assert_eq!(
            ExtendedKey::master_from_seed(&[0u8; 15]),
            Err(CryptoError::InvalidSeedLength(15))
        );
        assert_eq!(
            ExtendedKey::master_from_seed(&[0u8; 65]),
            Err(CryptoError::InvalidSeedLength(65))
        );
        assert!(ExtendedKey::master_from_seed(&[0u8; 16]).is_ok());
        assert!(ExtendedKey::master_from_seed(&[0u8; 64]).is_ok());
    }

    #[test]
    fn master_derivation_is_deterministic() {
        let a = master();
        let b = master();
        assert_eq!(a.secret_key(), b.secret_key());
        assert_eq!(a.chain_code(), b.chain_code());
        assert_eq!(a.depth(), 0);
        assert_eq!(a.parent_fingerprint(), [0u8; 4]);
        assert_eq!(a.child_number(), ChildNumber::ZERO);
    }

    #[test]
    fn a_different_seed_gives_a_different_master() {
        let a = ExtendedKey::master_from_seed(&[1u8; 32]).unwrap();
        let b = ExtendedKey::master_from_seed(&[2u8; 32]).unwrap();
        assert_ne!(a.secret_key(), b.secret_key());
        assert_ne!(a.chain_code(), b.chain_code());
    }

    #[test]
    fn ferrum_and_bitcoin_master_keys_differ() {
        let ferrum = ExtendedKey::master_from_seed(&SEED).unwrap();
        let bitcoin = ExtendedKey::master_from_seed_with_key(b"Bitcoin seed", &SEED).unwrap();
        assert_ne!(
            ferrum.secret_key(),
            bitcoin.secret_key(),
            "the domain string must separate the two chains"
        );
    }

    #[test]
    fn hardened_and_normal_children_differ() {
        let m = master();
        let normal = m.derive_child(ChildNumber::normal(0).unwrap()).unwrap();
        let hardened = m.derive_child(ChildNumber::hardened(0).unwrap()).unwrap();
        assert_ne!(normal.secret_key(), hardened.secret_key());
        assert_ne!(normal.chain_code(), hardened.chain_code());
        assert_eq!(normal.depth(), 1);
        assert_eq!(hardened.depth(), 1);
    }

    #[test]
    fn derivation_is_deterministic_across_runs() {
        let path: DerivationPath = "m/44'/7767'/0'/0/0".parse().unwrap();
        let first = master().derive_path(&path).unwrap();
        let second = ExtendedKey::master_from_seed(&SEED).unwrap().derive_path(&path).unwrap();
        assert_eq!(first.secret_key(), second.secret_key());
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(first.chain_code(), second.chain_code());
        assert_eq!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn derive_path_equals_repeated_derive_child() {
        let path: DerivationPath = "m/44'/7767'/0'/0/5".parse().unwrap();
        let by_path = master().derive_path(&path).unwrap();
        let mut by_hand = master();
        for step in path.iter() {
            by_hand = by_hand.derive_child(*step).unwrap();
        }
        assert_eq!(by_path.secret_key(), by_hand.secret_key());
        assert_eq!(by_path.depth(), 5);
    }

    #[test]
    fn the_empty_path_returns_the_master() {
        let m = master();
        let same = m.derive_path(&DerivationPath::master()).unwrap();
        assert_eq!(m.secret_key(), same.secret_key());
        assert_eq!(m.chain_code(), same.chain_code());
    }

    #[test]
    fn sibling_indices_give_unrelated_keys() {
        let m = master();
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..8u32 {
            let child = m.derive_child(ChildNumber::normal(i).unwrap()).unwrap();
            assert!(seen.insert(child.public_key().to_bytes()), "index {i} collided");
        }
    }

    #[test]
    fn parent_fingerprint_links_the_chain() {
        let m = master();
        let child = m.derive_child(ChildNumber::hardened(0).unwrap()).unwrap();
        assert_eq!(child.parent_fingerprint(), m.fingerprint());
        let grandchild = child.derive_child(ChildNumber::normal(1).unwrap()).unwrap();
        assert_eq!(grandchild.parent_fingerprint(), child.fingerprint());
        assert_eq!(grandchild.child_number(), ChildNumber::normal(1).unwrap());
    }

    #[test]
    fn identifier_is_hash160_of_the_compressed_key() {
        let m = master();
        assert_eq!(m.identifier().len(), 20);
        assert_eq!(
            m.fingerprint(),
            [m.identifier()[0], m.identifier()[1], m.identifier()[2], m.identifier()[3]]
        );
    }

    #[test]
    fn derived_keys_sign_and_verify() {
        use crate::hashing::{TAG_SIGHASH, tagged_hash};
        let key = master().derive_path(&DerivationPath::ferrum(0, 0, 0).unwrap()).unwrap();
        let sk = key.secret_key();
        let msg = tagged_hash(TAG_SIGHASH, b"spend");
        assert!(key.public_key().verify(&msg, &sk.sign_deterministic(&msg)).is_ok());
        assert_eq!(key.public_key(), sk.public_key());
    }

    #[test]
    fn depth_overflow_is_an_error_not_a_wrap() {
        // Walk to depth 255 cheaply by forging the depth field.
        let mut deep = master();
        deep.depth = 255;
        assert_eq!(
            deep.derive_child(ChildNumber::normal(0).unwrap()).map(|k| k.depth()),
            Err(CryptoError::DepthOverflow)
        );
    }

    #[test]
    fn debug_hides_the_secret_and_chain_code() {
        let shown = format!("{:?}", master());
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains(&hex::encode(master().chain_code())));
    }

    /// The official BIP-32 test vector 1, run through the same CKDpriv code
    /// with the Bitcoin master key. Quoted from BIP-32, not self-generated:
    /// this is what shows the HMAC wiring, the big-endian index and the scalar
    /// addition are right rather than merely internally consistent.
    #[test]
    fn official_bip32_test_vector_one() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let m = ExtendedKey::master_from_seed_with_key(b"Bitcoin seed", &seed).unwrap();
        assert_eq!(
            hex::encode(m.chain_code()),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );
        assert_eq!(
            hex::encode(m.secret_key().to_bytes()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            hex::encode(m.secret_key().compressed_public_key()),
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
        );

        // m/0'
        let c0h = m.derive_child(ChildNumber::hardened(0).unwrap()).unwrap();
        assert_eq!(
            hex::encode(c0h.chain_code()),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );
        assert_eq!(
            hex::encode(c0h.secret_key().to_bytes()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        assert_eq!(hex::encode(c0h.parent_fingerprint()), "3442193e");

        // m/0'/1 — the first *non-hardened* step, which is what exercises the
        // compressed-public-key branch of CKDpriv.
        let c1 = c0h.derive_child(ChildNumber::normal(1).unwrap()).unwrap();
        assert_eq!(
            hex::encode(c1.chain_code()),
            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
        );
        assert_eq!(
            hex::encode(c1.secret_key().to_bytes()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
        assert_eq!(hex::encode(c1.parent_fingerprint()), "5c1bd648");
    }
}
