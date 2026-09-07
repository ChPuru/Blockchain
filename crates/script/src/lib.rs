//! The Ferrum stack-based script virtual machine (CONTRACT §5).
//!
//! This crate is the largest surface in the project reachable by
//! unauthenticated input: every byte of every `script_sig` on the network is
//! fed to it. It is written accordingly — every limit present from the first
//! commit, every pop and slice checked, every arithmetic operation a
//! `checked_*`, and **no panic on any input**.
//!
//! # What is different from Bitcoin, and why
//!
//! | Rule | Bitcoin | Ferrum |
//! |---|---|---|
//! | `script_sig` push-only | policy | **consensus** |
//! | Clean stack | policy, added late | **consensus, from day one** |
//! | Minimal pushes / numbers | policy (`MINIMALDATA`) | **consensus, and also in untaken branches** |
//! | Minimal `OP_IF` operand | policy (`MINIMALIF`) | **consensus** |
//! | `OP_NOP1..10` | soft-fork hooks | **absent — the table is exhaustive** |
//! | `OP_CHECKMULTISIG` | pops a dummy element | **pops exactly what it needs** |
//! | `SIGHASH_SINGLE` past the end | returns `uint256(1)` | **an error** |
//! | Signature encoding | DER, variable length | **65 bytes: Schnorr + type byte** |
//! | Sighash | no chain id | **commits to `chain_id`, so no cross-chain replay** |
//!
//! Every one of those differences removes a malleability vector or a class of
//! bug that has cost real money on a live chain.
//!
//! # Example
//!
//! ```
//! use ferrum_crypto::{SecretKey, hash160};
//! use ferrum_script::sighash::{SigHashType, encode_signature, signature_hash};
//! use ferrum_script::{ExecCtx, ScriptType, templates, verify};
//! use ferrum_types::{Amount, ChainId, OutPoint, Script, Transaction, TxIn, TxOut, Txid};
//!
//! // A key and the P2PKH output it locks.
//! let secret = SecretKey::from_bytes(&[7u8; 32])?;
//! let public = secret.public_key();
//! let script_pubkey = templates::p2pkh(&hash160(public.as_bytes()));
//! assert_eq!(templates::classify(&script_pubkey), ScriptType::P2PKH);
//!
//! // A transaction that spends it.
//! let mut tx = Transaction {
//!     version: 1,
//!     inputs: vec![TxIn::new(OutPoint::new(Txid::ZERO, 0), Script::EMPTY)],
//!     outputs: vec![TxOut::new(Amount::from_grains(90_000), Script::EMPTY)],
//!     lock_time: 0,
//! };
//! let value = Amount::from_grains(100_000);
//!
//! // Sign, then build `<sig> <pubkey>`.
//! let digest = signature_hash(
//!     &tx, 0, script_pubkey.as_bytes(), value, ChainId::MAINNET, SigHashType::ALL,
//! )?;
//! let signature = encode_signature(&secret.sign_deterministic(&digest), SigHashType::ALL);
//! let mut script_sig = Vec::new();
//! ferrum_script::opcode::Instruction::push(&signature)?.encode_into(&mut script_sig);
//! ferrum_script::opcode::Instruction::push(public.as_bytes())?.encode_into(&mut script_sig);
//! tx.inputs[0].script_sig = Script::new(script_sig);
//!
//! let ctx = ExecCtx {
//!     input_value: value,
//!     ..ExecCtx::new(ChainId::MAINNET, &tx, 0)
//! };
//! let stats = verify(&tx.inputs[0].script_sig, &script_pubkey, &ctx)?;
//! assert_eq!(stats.sig_checks, 1);
//!
//! // The same signature under a different chain id does not verify.
//! let other = ExecCtx { chain_id: ChainId::TESTNET, ..ExecCtx::new(ChainId::TESTNET, &tx, 0) };
//! assert!(verify(&tx.inputs[0].script_sig, &script_pubkey, &other).is_err());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![warn(missing_docs)]
#![warn(clippy::arithmetic_side_effects)]

pub mod error;
pub mod interpreter;
pub mod limits;
pub mod num;
pub mod opcode;
pub mod parse;
pub mod sighash;
pub mod templates;

pub use crate::error::ScriptError;
pub use crate::interpreter::{ExecCtx, ExecStats, Stack, eval, is_p2sh, verify};
pub use crate::limits::{
    MAX_ELEMENT_SIZE, MAX_NUM_SIZE, MAX_OP_RETURN_PAYLOAD, MAX_OPS, MAX_PUBKEYS_PER_MULTISIG,
    MAX_SCRIPT_SIZE, MAX_STACK_SIZE, SCHNORR_SIGNATURE_SIZE, SIGNATURE_SIZE, ScriptLimits,
};
pub use crate::num::{ScriptNum, cast_to_bool, is_minimal_bool, is_minimally_encoded};
pub use crate::opcode::{Instruction, Opcode};
pub use crate::parse::{disassemble, is_push_only, parse};
pub use crate::sighash::{SigHashType, SighashCache, sighash_preimage, signature_hash};
pub use crate::templates::ScriptType;
