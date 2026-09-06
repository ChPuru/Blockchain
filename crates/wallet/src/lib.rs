//! HD wallet, coin selection and transaction building for Ferrum.
//!
//! This crate is CONTRACT §12. It sits above [`ferrum_types`],
//! [`ferrum_crypto`] and [`ferrum_script`] and below nothing: no node, no
//! storage, no network. That isolation is the design, not an accident — see
//! "Five things worth knowing" below.
//!
//! # Five things worth knowing
//!
//! 1. **Balances come from the UTXO set handed to [`Wallet::sync`], never from
//!    a rescan.** The caller owns the authoritative set; the wallet owns a
//!    view of it. Two sources of truth about the same coins is how wallets
//!    lose money.
//! 2. **Coin selection is branch-and-bound first, largest-first second.**
//!    Branch-and-bound looks for a subset that needs *no change output* —
//!    smaller, cheaper, and one fewer entry in every full node's UTXO set
//!    forever. See [`select`].
//! 3. **The fee is computed from the size the transaction will have once
//!    signed**, not from the unsigned skeleton, and [`sign`] re-measures
//!    afterwards and refuses a transaction whose size drifted. Underestimating
//!    by the 99 bytes a P2PKH signature occupies halves the realised fee rate,
//!    and the failure mode is silent: the transaction simply never confirms.
//! 4. **Signatures commit to the chain id** through the BIP-143-shaped sighash
//!    in `ferrum-script`, so a testnet signature is not a mainnet signature.
//! 5. **The mnemonic is encrypted at rest and the seed never touches disk.**
//!    PBKDF2-HMAC-SHA512 with a random salt, then encrypt-then-MAC; a wrong
//!    passphrase and a tampered file are distinguishable, and neither ever
//!    yields a key. See [`keystore`].
//!
//! # Example
//!
//! ```
//! use ferrum_types::{Amount, Coin, Network, OutPoint, Txid};
//! use ferrum_wallet::{SendRequest, Wallet};
//!
//! let dir = tempfile::tempdir()?;
//! let path = dir.path().join("wallet.json");
//! let mut rng = rand::rngs::OsRng;
//!
//! // Create a wallet and hand out an address.
//! let (mut wallet, _mnemonic) =
//!     Wallet::create(&path, Network::Devnet, "a passphrase", 12, &mut rng)?;
//! let address = wallet.new_address()?;
//!
//! // Someone pays it; the caller tells the wallet about the coin.
//! let coin = Coin {
//!     value: Amount::from_grains(10_000_000),
//!     script_pubkey: address.script_pubkey(),
//!     height: 1,
//!     is_coinbase: false,
//! };
//! wallet.sync(vec![(OutPoint::new(Txid::ZERO, 0), coin)], 100);
//! assert_eq!(wallet.balance_at(100).confirmed, Amount::from_grains(10_000_000));
//!
//! // Spend some of it. `send` plans, signs, verifies and reserves the inputs.
//! let request = SendRequest::to(address, Amount::from_grains(1_000_000), 1_000);
//! let plan = wallet.send(&request, 100)?;
//! wallet.verify_transaction(&plan.tx, &plan.prevouts(), wallet.chain_id())?;
//! assert!(plan.fee_rate() >= 1_000);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![warn(missing_docs)]

pub mod build;
pub mod coins;
pub mod error;
pub mod fee;
pub mod hd;
pub mod keystore;
pub mod select;
pub mod sign;
pub mod wallet;

pub use crate::build::{
    BuildParams, DEFAULT_TX_VERSION, MAX_TRANSACTION_BYTES, SEQUENCE_ENABLE_LOCKTIME, SendRequest,
    TxPlan, plan_transaction,
};
pub use crate::coins::{Balance, CoinCache, CoinStatus, WalletCoin};
pub use crate::error::WalletError;
pub use crate::fee::{
    DUST_RELAY_MULTIPLIER, FeeRate, INPUT_FIXED_BYTES, OUTPUT_FIXED_BYTES, P2PKH_INPUT_BYTES,
    P2PKH_OUTPUT_BYTES, P2PKH_SCRIPT_SIG_BYTES, SIZE_ESTIMATE_TOLERANCE, TX_OVERHEAD_BYTES,
    dust_threshold, input_size, output_size, transaction_size,
};
pub use crate::hd::{
    ADDRESS_GAP_LIMIT, CHANGE_CHAIN, DEFAULT_ACCOUNT, DerivedKey, HdKeychain, MAX_ADDRESS_INDEX,
    RECEIVE_CHAIN,
};
pub use crate::keystore::{
    DEFAULT_PBKDF2_ITERATIONS, KEYSTORE_VERSION, KdfParams, Keystore, KeystoreFile, KeystoreParams,
    MIN_PBKDF2_ITERATIONS, WalletMeta,
};
pub use crate::select::{
    BNB_MAX_TRIES, Candidate, Selection, SelectionParams, SelectionStrategy, select_coins,
};
pub use crate::sign::{
    estimate_signed_size, p2pkh_script_sig, sign_p2pkh_input, sign_transaction, verify_signed,
    verify_signed_at,
};
pub use crate::wallet::{KeyLocation, Wallet};
