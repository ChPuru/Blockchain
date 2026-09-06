//! Deterministic key material and the lock types the fixtures use.
//!
//! Keys are derived from a fixed string and an index rather than generated
//! randomly, so the whole keyring — and therefore every address, every
//! `script_pubkey` and every txid downstream of one — is reproducible byte for
//! byte on any machine. `SecretKey::random` would make the golden state-root
//! file in `golden/` impossible to maintain.

use ferrum_crypto::{PublicKey, SecretKey, hash160, hash256, sha256};
use ferrum_script::{ScriptError, templates};
use ferrum_types::Script;

use crate::error::SimError;

/// The domain string the keyring derives from.
///
/// Not a consensus tag: these keys exist only inside the simulator, and using
/// one of the frozen `ferrum.v1.*` tags for test material would blur a line
/// that the tag list exists to keep sharp.
pub const KEYRING_DOMAIN: &[u8] = b"ferrum-sim.keyring.v1";

/// How many keys a default keyring holds.
///
/// [`ferrum_script::MAX_PUBKEYS_PER_MULTISIG`], so that the most expensive
/// script the VM allows — a 20-of-20 `OP_CHECKMULTISIG` — can be built from
/// distinct keys. Key `i` is derived from `i` alone, so raising this number
/// never changes the keys below it.
pub const DEFAULT_KEYRING_SIZE: usize = 20;

/// A deterministic set of BIP-340 keys.
#[derive(Debug)]
pub struct KeyRing {
    secrets: Vec<SecretKey>,
    publics: Vec<PublicKey>,
    hashes: Vec<[u8; 20]>,
}

impl KeyRing {
    /// Derive `n` keys from [`KEYRING_DOMAIN`].
    ///
    /// Key `i` is `sha256(domain || i || attempt)`, retried with a higher
    /// attempt number in the astronomically unlikely event that the digest is
    /// not a valid secp256k1 scalar.
    ///
    /// # Errors
    ///
    /// [`SimError::Fixture`] if 64 successive derivations for one index all
    /// land outside the scalar field, which cannot happen in practice.
    pub fn deterministic(n: usize) -> Result<Self, SimError> {
        let mut secrets = Vec::with_capacity(n);
        let mut publics = Vec::with_capacity(n);
        let mut hashes = Vec::with_capacity(n);
        for i in 0..n {
            let secret = Self::derive(i)?;
            let public = secret.public_key();
            hashes.push(hash160(public.as_bytes()));
            publics.push(public);
            secrets.push(secret);
        }
        Ok(KeyRing { secrets, publics, hashes })
    }

    fn derive(index: usize) -> Result<SecretKey, SimError> {
        for attempt in 0u32..64 {
            let mut preimage = Vec::with_capacity(KEYRING_DOMAIN.len() + 12);
            preimage.extend_from_slice(KEYRING_DOMAIN);
            preimage.extend_from_slice(&(index as u64).to_le_bytes());
            preimage.extend_from_slice(&attempt.to_le_bytes());
            if let Ok(key) = SecretKey::from_bytes(&sha256(&preimage)) {
                return Ok(key);
            }
        }
        Err(SimError::fixture(format!("no valid scalar for key index {index}")))
    }

    /// How many keys the ring holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Whether the ring is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// The secret key at `index`, wrapping around the ring.
    ///
    /// Wrapping rather than panicking keeps a fixture generator that picked an
    /// index from a PRNG total.
    ///
    /// # Errors
    ///
    /// [`SimError::Fixture`] only when the ring is empty.
    pub fn secret(&self, index: usize) -> Result<&SecretKey, SimError> {
        let n = self.secrets.len();
        if n == 0 {
            return Err(SimError::fixture("empty keyring"));
        }
        self.secrets.get(index % n).ok_or_else(|| SimError::fixture("keyring index"))
    }

    /// The public key at `index`, wrapping around the ring.
    ///
    /// # Errors
    ///
    /// [`SimError::Fixture`] only when the ring is empty.
    pub fn public(&self, index: usize) -> Result<&PublicKey, SimError> {
        let n = self.publics.len();
        if n == 0 {
            return Err(SimError::fixture("empty keyring"));
        }
        self.publics.get(index % n).ok_or_else(|| SimError::fixture("keyring index"))
    }

    /// `hash160(x_only_pubkey)` at `index`, wrapping around the ring.
    ///
    /// # Errors
    ///
    /// [`SimError::Fixture`] only when the ring is empty.
    pub fn pubkey_hash(&self, index: usize) -> Result<[u8; 20], SimError> {
        let n = self.hashes.len();
        if n == 0 {
            return Err(SimError::fixture("empty keyring"));
        }
        self.hashes.get(index % n).copied().ok_or_else(|| SimError::fixture("keyring index"))
    }
}

/// How a simulated output is locked, and therefore how it must be spent.
///
/// One enum rather than raw scripts, so a fixture can say *what* it is building
/// and the builder derives both halves — the `script_pubkey` and the matching
/// `script_sig` — from the same statement. A test that hand-wrote both would
/// eventually have them disagree and would then be testing the fixture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lock {
    /// `OP_1`: spendable by anyone with an empty `script_sig`.
    ///
    /// Not a realistic output, but it makes a large fixture block cheap to
    /// build when the point of the block is its size rather than its scripts.
    Anyone,
    /// `<pk> OP_CHECKSIG`.
    P2pk {
        /// Index into the keyring.
        key: usize,
    },
    /// `OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`.
    P2pkh {
        /// Index into the keyring.
        key: usize,
    },
    /// Bare `k`-of-`n` `OP_CHECKMULTISIG`.
    Multisig {
        /// The threshold.
        k: u8,
        /// Indices into the keyring, in the order the script lists them.
        keys: Vec<usize>,
    },
    /// `k`-of-`n` multisig wrapped in P2SH.
    P2shMultisig {
        /// The threshold.
        k: u8,
        /// Indices into the keyring, in the order the redeem script lists them.
        keys: Vec<usize>,
    },
    /// `<locktime> OP_CLTV OP_DROP` followed by a P2PKH tail.
    CltvP2pkh {
        /// Index into the keyring.
        key: usize,
        /// The absolute locktime the spender's `lock_time` must reach.
        locktime: u32,
    },
    /// `OP_RETURN <payload>`: provably unspendable.
    Unspendable {
        /// The committed payload, at most 80 bytes.
        payload: Vec<u8>,
    },
    /// Raw script bytes on both sides, for the scenarios that are about the
    /// script encoding itself.
    ///
    /// Nothing is derived and nothing is checked: the `script_sig` is used
    /// verbatim, including one that is not push-only or not minimally encoded,
    /// because rejecting those is exactly what such a scenario tests.
    Raw {
        /// The locking script.
        script_pubkey: Vec<u8>,
        /// The unlocking script, used byte for byte.
        script_sig: Vec<u8>,
    },
}

impl Lock {
    /// The locking script this lock produces.
    ///
    /// # Errors
    ///
    /// [`SimError::Script`] for a multisig outside `1..=k<=n<=20` or an
    /// `OP_RETURN` payload over 80 bytes, and [`SimError::Fixture`] when the
    /// keyring cannot supply a named key.
    pub fn script_pubkey(&self, keys: &KeyRing) -> Result<Script, SimError> {
        match self {
            Lock::Anyone => Ok(Script::new(vec![0x51])),
            Lock::P2pk { key } => Ok(templates::p2pk(keys.public(*key)?)),
            Lock::P2pkh { key } => Ok(templates::p2pkh(&keys.pubkey_hash(*key)?)),
            Lock::Multisig { k, keys: idx } => Ok(templates::multisig(*k, &Self::pks(keys, idx)?)?),
            Lock::P2shMultisig { .. } => Ok(templates::p2sh(&hash256(
                self.redeem_script(keys)?
                    .ok_or_else(|| SimError::fixture("p2sh without a redeem script"))?
                    .as_bytes(),
            ))),
            Lock::CltvP2pkh { key, locktime } => {
                Ok(templates::cltv_p2pkh(*locktime, &keys.pubkey_hash(*key)?))
            }
            Lock::Unspendable { payload } => Ok(templates::op_return(payload)?),
            Lock::Raw { script_pubkey, .. } => Ok(Script::new(script_pubkey.clone())),
        }
    }

    /// The redeem script, for the P2SH locks only.
    ///
    /// # Errors
    ///
    /// [`SimError::Script`] for a multisig outside the legal `k`/`n` window.
    pub fn redeem_script(&self, keys: &KeyRing) -> Result<Option<Script>, SimError> {
        match self {
            Lock::P2shMultisig { k, keys: idx } => {
                Ok(Some(templates::multisig(*k, &Self::pks(keys, idx)?)?))
            }
            _ => Ok(None),
        }
    }

    /// The script whose bytes go into the sighash preimage: the redeem script
    /// for P2SH, the `script_pubkey` otherwise (CONTRACT §5.5).
    ///
    /// # Errors
    ///
    /// As [`Lock::script_pubkey`].
    pub fn script_code(&self, keys: &KeyRing) -> Result<Script, SimError> {
        match self.redeem_script(keys)? {
            Some(redeem) => Ok(redeem),
            None => self.script_pubkey(keys),
        }
    }

    /// Which keys must sign, in the order the script expects the signatures.
    ///
    /// `OP_CHECKMULTISIG` matches signatures against public keys **in order**,
    /// so the first `k` keys of the set are the canonical signers.
    #[must_use]
    pub fn signing_keys(&self) -> Vec<usize> {
        match self {
            Lock::Anyone | Lock::Unspendable { .. } | Lock::Raw { .. } => Vec::new(),
            Lock::P2pk { key } | Lock::P2pkh { key } | Lock::CltvP2pkh { key, .. } => vec![*key],
            Lock::Multisig { k, keys } | Lock::P2shMultisig { k, keys } => {
                keys.iter().copied().take(usize::from(*k)).collect()
            }
        }
    }

    /// Whether an output with this lock can ever be spent.
    #[must_use]
    pub fn is_spendable(&self) -> bool {
        !matches!(self, Lock::Unspendable { .. })
    }

    fn pks(keys: &KeyRing, idx: &[usize]) -> Result<Vec<PublicKey>, SimError> {
        if idx.is_empty() {
            return Err(SimError::Script(ScriptError::MultisigKeyCount { n: 0, max: 20 }));
        }
        idx.iter().map(|i| keys.public(*i).copied()).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_script::ScriptType;

    use super::*;

    #[test]
    fn the_keyring_is_reproducible() {
        let a = KeyRing::deterministic(DEFAULT_KEYRING_SIZE).unwrap();
        let b = KeyRing::deterministic(DEFAULT_KEYRING_SIZE).unwrap();
        for i in 0..DEFAULT_KEYRING_SIZE {
            assert_eq!(a.public(i).unwrap(), b.public(i).unwrap());
            assert_eq!(a.pubkey_hash(i).unwrap(), b.pubkey_hash(i).unwrap());
        }
    }

    #[test]
    fn keys_are_distinct() {
        let ring = KeyRing::deterministic(DEFAULT_KEYRING_SIZE).unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..ring.len() {
            assert!(seen.insert(*ring.public(i).unwrap().as_bytes()), "key {i} repeats");
        }
    }

    #[test]
    fn indices_wrap_instead_of_panicking() {
        let ring = KeyRing::deterministic(4).unwrap();
        assert_eq!(ring.public(0).unwrap(), ring.public(4).unwrap());
        assert_eq!(ring.public(1).unwrap(), ring.public(9).unwrap());
    }

    #[test]
    fn every_lock_classifies_as_the_template_it_names() {
        let ring = KeyRing::deterministic(DEFAULT_KEYRING_SIZE).unwrap();
        let cases = [
            (Lock::P2pk { key: 0 }, ScriptType::P2PK),
            (Lock::P2pkh { key: 1 }, ScriptType::P2PKH),
            (Lock::Multisig { k: 2, keys: vec![0, 1, 2] }, ScriptType::Multisig { k: 2, n: 3 }),
            (Lock::P2shMultisig { k: 2, keys: vec![0, 1, 2] }, ScriptType::P2SH),
            (Lock::CltvP2pkh { key: 3, locktime: 500 }, ScriptType::Cltv),
            (Lock::Unspendable { payload: vec![1, 2, 3] }, ScriptType::OpReturn),
        ];
        for (lock, expected) in cases {
            let spk = lock.script_pubkey(&ring).unwrap();
            assert_eq!(templates::classify(&spk), expected, "{lock:?}");
        }
    }

    #[test]
    fn p2sh_script_code_is_the_redeem_script_not_the_locking_script() {
        let ring = KeyRing::deterministic(DEFAULT_KEYRING_SIZE).unwrap();
        let lock = Lock::P2shMultisig { k: 2, keys: vec![0, 1, 2] };
        let redeem = lock.redeem_script(&ring).unwrap().unwrap();
        assert_eq!(lock.script_code(&ring).unwrap(), redeem);
        assert_ne!(lock.script_pubkey(&ring).unwrap(), redeem);
    }

    #[test]
    fn signing_keys_take_the_first_k_in_order() {
        let lock = Lock::Multisig { k: 2, keys: vec![7, 3, 5] };
        assert_eq!(lock.signing_keys(), vec![7, 3]);
        assert!(Lock::Anyone.signing_keys().is_empty());
    }
}
