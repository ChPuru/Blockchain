//! Fee-ordered transaction mempool with an orphan pool and reorg
//! reconciliation (CONTRACT §9, SPEC §10).
//!
//! # Everything in this crate is policy, not consensus
//!
//! **A block containing a transaction this mempool would reject is still
//! valid, and this node will accept that block.** Nothing here changes what a
//! block may contain. The mempool is a local cache of transactions this node
//! is willing to store, forward and mine; another node with different settings
//! will hold a different set, and both are correct.
//!
//! Conflating the two is how implementations accidentally hard-fork
//! themselves. A node that applied its relay policy to incoming blocks — that
//! refused a block because one of its transactions paid below the local fee
//! floor, or used a script shape the local `classify()` does not name — would
//! reject blocks the rest of the network accepted, and would then be on its
//! own chain without ever having announced a fork. The consensus rules live in
//! [`ferrum_chain`] and produce a [`ferrum_chain::ValidationError`]; the
//! policy rules live here and produce a [`MempoolError`], and the two types
//! are deliberately separate so that no call site can confuse them.
//!
//! The one place they touch is [`MempoolError::Sanity`], which wraps
//! [`ferrum_chain::check_transaction_sanity`]: a transaction that fails the
//! context-free rules of SPEC §4.1 cannot be mined by anybody, so refusing to
//! relay it is not an opinion.
//!
//! # There is no replace-by-fee in v1
//!
//! Stated here because a missing feature that is not written down reads as an
//! oversight. The first transaction to claim an outpoint keeps it; a second
//! one spending the same outpoint is refused with [`MempoolError::Conflict`],
//! however much more it offers. A sender who underpaid waits for the entry to
//! expire after `expiry_blocks` — 336 blocks, about a fortnight at the 120 s
//! target spacing — and then rebroadcasts. See SPEC §10 and §13.
//!
//! # Layout
//!
//! | Module | What it owns |
//! |---|---|
//! | [`pool`] | [`Mempool`], [`MempoolEntry`], [`AcceptResult`] and the three indices |
//! | [`orphan`] | [`OrphanPool`] — transactions waiting for a parent |
//! | [`policy`] | [`MempoolConfig`], the standardness and fee-rate rules |
//! | [`select`] | block-template selection, fee-ordered and dependency-safe |
//! | [`error`] | [`MempoolError`] |
//!
//! # Bounds, and why every one of them is explicit
//!
//! | Bound | Default | What it stops |
//! |---|---|---|
//! | `max_bytes` | 8 MiB | an attacker filling memory with cheap transactions |
//! | `max_orphans` | 200 | orphans are memory nobody paid for |
//! | `min_fee_rate` | `params.min_relay_fee_per_kb` | free relay bandwidth |
//! | `expiry_blocks` | 336 | entries whose inputs the network has forgotten |
//! | `max_ancestors` | 25 | a chain so deep that one block template costs a quadratic scan |
//! | `max_ancestor_bytes` | 101 000 B | the same, measured in bytes |
//! | [`MAX_STANDARD_TX_SIZE`] | 100 000 B | one transaction that is expensive for every relay |
//!
//! Eviction is lowest fee rate first, and it takes the victim's descendants
//! with it: a child is unminable without its parent, so its own fee rate was
//! never the number that mattered.
//!
//! # Synchronous, like the storage layer
//!
//! Nothing here is `async` and nothing here holds a lock across an `await`.
//! `ferrum-storage` is synchronous, so a node calling [`Mempool::accept`] from
//! an `async fn` must go through `tokio::task::spawn_blocking` — the mempool
//! reads the UTXO set through the [`ferrum_storage::StateView`] it is handed,
//! and a synchronous database read on a Tokio worker parks that worker for the
//! duration of the I/O.
//!
//! # Example
//!
//! ```
//! use ferrum_mempool::{Mempool, MempoolConfig};
//! use ferrum_script::templates::p2sh_of;
//! use ferrum_storage::MapView;
//! use ferrum_types::{Amount, ChainParams, Coin, Hash32, OutPoint, Script, Transaction, TxIn,
//!                    TxOut, Txid};
//!
//! let params = ChainParams::devnet();
//! let pool = Mempool::new(MempoolConfig::new(params).with_min_fee_rate(0));
//!
//! // A P2SH output whose redeem script is `OP_1`: standard, and satisfied by
//! // a script_sig that pushes the redeem script and nothing else.
//! let redeem = Script::new(vec![0x51]);
//! let locked = p2sh_of(&redeem);
//! let unlock = Script::new(vec![0x01, 0x51]);
//!
//! let funded = OutPoint::new(Txid(Hash32::from_bytes([7u8; 32])), 0);
//! let mut view = MapView::new();
//! view.insert(funded, Coin {
//!     value: Amount::from_grains(10_000),
//!     script_pubkey: locked.clone(),
//!     height: 1,
//!     is_coinbase: false,
//! });
//!
//! let tx = Transaction {
//!     version: 1,
//!     inputs: vec![TxIn::new(funded, unlock)],
//!     outputs: vec![TxOut::new(Amount::from_grains(9_000), locked)],
//!     lock_time: 0,
//! };
//!
//! let result = pool.accept(tx, &view, 10, 0)?;
//! assert!(result.is_accepted());
//! assert_eq!(pool.len(), 1);
//!
//! // And it is what a block at height 11 would be built from.
//! let picked = pool.select_for_block(1_000_000, &view, 11);
//! assert_eq!(picked.len(), 1);
//! # Ok::<(), ferrum_mempool::MempoolError>(())
//! ```

#![warn(missing_docs)]

pub mod error;
pub mod orphan;
pub mod policy;
pub mod pool;
pub mod select;

#[cfg(test)]
mod tests;

pub use crate::error::MempoolError;
pub use crate::orphan::{OrphanEntry, OrphanPool};
pub use crate::policy::{
    DEFAULT_EXPIRY_BLOCKS, DEFAULT_MAX_ANCESTOR_BYTES, DEFAULT_MAX_ANCESTORS, DEFAULT_MAX_BYTES,
    DEFAULT_MAX_ORPHANS, FEE_RATE_DIVISOR, MAX_STANDARD_TX_SIZE, MempoolConfig, check_standard,
    fee_rate, is_standard_script_pubkey,
};
pub use crate::pool::{AcceptResult, FeeKey, Mempool, MempoolEntry};
pub use crate::select::is_final_by_height;
