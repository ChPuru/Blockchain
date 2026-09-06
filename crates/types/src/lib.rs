//! Core consensus data types for the Ferrum chain.
//!
//! This crate is the foundation every other Ferrum crate stands on, and it
//! depends on nothing but `borsh`, `serde`, `hex` and `thiserror`. It contains
//! no consensus *logic* — no hashing, no signature checks, no validation —
//! only the shapes those rules operate on, plus their canonical encodings.
//!
//! # Encoding rules (CONTRACT §2)
//!
//! Everything on the wire and on disk is **Borsh 1.x**, which gives a bijective
//! object↔bytes mapping:
//!
//! - `Vec<T>` is `u32 LE length || elements`
//! - fixed arrays such as `[u8; 32]` carry no length prefix
//! - a newtype over a single field encodes exactly as that field
//! - enums are `u8 discriminant || variant fields`
//! - `Option<T>` is `0u8` or `1u8 || T`
//! - **decoding rejects trailing bytes** — always `borsh::from_slice`, never a
//!   reader that tolerates a suffix, because a tolerated suffix is a
//!   txid-malleability bug
//!
//! All integers are little-endian on the wire, which is Borsh's convention.
//! Database keys are the one exception and are big-endian, but those are built
//! in `ferrum-storage`, not here.
//!
//! # The two rules worth restating
//!
//! [`Amount`] has no `Add`/`Sub` impls: every monetary operation is a
//! `checked_*` call whose `None` becomes a typed error at the call site.
//!
//! [`Hash32`] displays in **natural byte order**. Ferrum does not reproduce
//! Bitcoin's display reversal.
//!
//! # Example
//!
//! ```
//! use ferrum_types::{Amount, Script, Transaction, TxIn, TxOut, OutPoint};
//!
//! let tx = Transaction {
//!     version: 1,
//!     inputs: vec![TxIn::coinbase(Script::new(vec![0x01, 0x00]))],
//!     outputs: vec![TxOut::new(Amount::from_frm_str("50")?, Script::EMPTY)],
//!     lock_time: 0,
//! };
//! assert!(tx.is_coinbase());
//!
//! let bytes = tx.encode_envelope();
//! assert_eq!(bytes.len(), tx.serialized_size());
//! assert_eq!(Transaction::decode_envelope(&bytes)?, tx);
//!
//! // A trailing byte is never tolerated.
//! let mut malleated = bytes.clone();
//! malleated.push(0);
//! assert!(Transaction::decode_envelope(&malleated).is_err());
//! # Ok::<(), ferrum_types::TypeError>(())
//! ```

#![warn(missing_docs)]

pub mod amount;
pub mod block;
pub mod coin;
pub mod error;
pub mod hash;
pub mod network;
pub mod params;
pub mod script;
pub mod tx;

pub use crate::amount::{Amount, COIN, MAX_MONEY};
pub use crate::block::{Block, BlockHeader, BlockSeal, CompactTarget, HEADER_SIZE};
pub use crate::coin::Coin;
pub use crate::error::TypeError;
pub use crate::hash::{BlockHash, HASH_HEX_LEN, HASH_LEN, Hash32, Txid};
pub use crate::network::{ChainId, Network, ValidatorId};
pub use crate::params::ChainParams;
pub use crate::script::Script;
pub use crate::tx::{
    LOCKTIME_THRESHOLD, OUTPOINT_SIZE, OutPoint, TX_TYPE_STANDARD, Transaction, TxIn, TxOut,
};
