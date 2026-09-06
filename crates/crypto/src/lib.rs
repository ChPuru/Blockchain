//! Domain-separated hashing, BIP-340 Schnorr, Merkle trees and BIP-32/39 for
//! Ferrum.
//!
//! This crate is CONTRACT §4. It sits one level above [`ferrum_types`] and
//! below everything else: `ferrum-script` needs its signatures, `ferrum-chain`
//! its Merkle root, `ferrum-consensus` its block hash, `ferrum-wallet` its key
//! derivation and addresses. It contains no consensus *rules* — no validation,
//! no policy — only the primitives those rules are written in.
//!
//! # The five things worth knowing
//!
//! 1. **Every hash is domain-separated.** [`tagged_hash`] is BLAKE3 in
//!    derive-key mode with a frozen context string. The tag list in
//!    [`hashing`] is frozen by the contract: adding one is fine, changing one
//!    is a hard fork. A test asserts all tags are pairwise distinct *and* that
//!    they produce different digests over several inputs.
//! 2. **Signatures are BIP-340**, taken from `k256`; nothing here hand-rolls
//!    the algorithm. All 19 official BIP-340 vectors run in
//!    `tests/bip340.rs`, including every invalid-signature case.
//! 3. **The Merkle tree promotes, it never duplicates.** That is the fix for
//!    CVE-2012-2459, and `tests/merkle.rs` proves `n` and `n + 1` leaves can
//!    never share a root.
//! 4. **Key material zeroizes.** [`SecretKey`], [`Mnemonic`] and
//!    [`ExtendedKey`] all clear themselves on drop and redact themselves in
//!    `Debug`.
//! 5. **Addresses are bech32m**, never plain bech32, and decoding insists on a
//!    canonical encoding so one address has exactly one spelling.
//!
//! # Example
//!
//! ```
//! use ferrum_crypto::{Address, DerivationPath, ExtendedKey, Mnemonic, TAG_SIGHASH, tagged_hash};
//! use ferrum_types::Network;
//!
//! // A wallet, from phrase to address to signature.
//! let mnemonic = Mnemonic::from_entropy(&[0x42u8; 16])?;
//! let master = ExtendedKey::master_from_seed(&mnemonic.to_seed(""))?;
//! let key = master.derive_path(&DerivationPath::ferrum(0, 0, 0)?)?;
//!
//! let address = Address::p2pkh(Network::Mainnet, &key.public_key());
//! assert_eq!(Address::decode(&address.encode())?, address);
//!
//! let sighash = tagged_hash(TAG_SIGHASH, b"a signature preimage");
//! let signature = key.secret_key().sign_deterministic(&sighash);
//! assert!(key.public_key().verify(&sighash, &signature).is_ok());
//! # Ok::<(), ferrum_crypto::CryptoError>(())
//! ```

#![warn(missing_docs)]

pub mod address;
pub mod bip32;
pub mod bip39;
pub mod error;
pub mod hashing;
pub mod merkle;
pub mod schnorr;

pub use crate::address::{
    ADDRESS_VERSION_P2PKH, ADDRESS_VERSION_P2SH, Address, AddressPayload, P2PKH_PAYLOAD_LEN,
    P2SH_PAYLOAD_LEN,
};
pub use crate::bip32::{
    BIP44_PURPOSE, COIN_TYPE, ChildNumber, DerivationPath, ExtendedKey, HARDENED_BIT, MAX_SEED_LEN,
    MIN_SEED_LEN,
};
pub use crate::bip39::{
    Mnemonic, PBKDF2_ROUNDS, SEED_LEN, VALID_WORD_COUNTS, WORDLIST_LEN, english_wordlist,
    zeroize_seed,
};
pub use crate::error::CryptoError;
pub use crate::hashing::{
    ALL_TAGS, TAG_ADDRESS, TAG_BFT_PRECOMMIT, TAG_BFT_PREVOTE, TAG_BFT_PROPOSAL, TAG_GENESIS,
    TAG_HD_SEED, TAG_HEADER, TAG_MERKLE_LEAF, TAG_MERKLE_NODE, TAG_P2P_MSGID, TAG_SCRIPT,
    TAG_SIGHASH, TAG_STATE_ROOT, TAG_TXID, TAG_UNDO, Tag, hash160, hash256, sha256, tagged_hash,
    tagged_hasher,
};
pub use crate::merkle::{
    MerkleProof, merkle_leaf, merkle_node, merkle_proof, merkle_root, merkle_root_of_leaf_data,
    merkle_verify,
};
pub use crate::schnorr::{
    COMPRESSED_PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE, PublicKey, SECRET_KEY_SIZE, SIGNATURE_SIZE,
    SecretKey, Signature, verify_batch,
};
