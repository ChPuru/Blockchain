//! [`Mempool`] — the pool itself (CONTRACT §9).
//!
//! One `parking_lot::Mutex` guards the three indices and the orphan pool
//! together. Every method takes `&self`, as the contract specifies, so the
//! node can share one `Arc<Mempool>` between the p2p task, the RPC server and
//! the miner without an outer lock. One lock rather than three because the
//! indices are only meaningful in agreement: a reader that saw the fee index
//! updated but not the spent-outpoint index would see a double spend.
//!
//! The lock is never held across an `await` — nothing in this crate is
//! `async` — and never across a storage call that the caller has not already
//! arranged. `ferrum-storage` is synchronous, so an `async` caller must reach
//! this crate through `tokio::task::spawn_blocking`, exactly as it must reach
//! the store.

pub(crate) mod accept;
pub(crate) mod entry;

use std::collections::BTreeSet;

use ferrum_chain::median_time_past;
use ferrum_storage::{StateView, txid};
use ferrum_types::{Block, BlockHeader, OutPoint, Transaction, Txid};
use parking_lot::Mutex;

use crate::error::MempoolError;
use crate::policy::MempoolConfig;
use crate::pool::accept::{Admission, drain_promotions, insert_one};
use crate::pool::entry::Inner;
use crate::select;

pub use crate::pool::entry::{AcceptResult, FeeKey, MempoolEntry};

/// A fee-ordered pool of unconfirmed transactions.
///
/// # This is policy, not consensus
///
/// Every rule this type applies is a local opinion. A block containing a
/// transaction this pool refused is still valid and this node will accept it.
/// The distinction matters more than it sounds: a node that enforced its relay
/// policy on incoming blocks would reject blocks the rest of the network
/// accepted, which is a unilateral hard fork nobody announced.
///
/// # There is no replace-by-fee
///
/// The first transaction to claim an outpoint keeps it. A second transaction
/// spending the same outpoint is refused with [`MempoolError::Conflict`],
/// however much more it offers. This is a deliberate absence, documented
/// rather than forgotten (SPEC §10 and §13): replace-by-fee needs a
/// pinning-resistant replacement policy, and every simple version of one is a
/// free relay-bandwidth amplifier. A sender who underpaid must wait for the
/// transaction to expire after `expiry_blocks`.
///
/// # Example
///
/// ```
/// use ferrum_mempool::{Mempool, MempoolConfig};
/// use ferrum_storage::MapView;
/// use ferrum_types::ChainParams;
///
/// let pool = Mempool::new(MempoolConfig::new(ChainParams::devnet()));
/// assert_eq!(pool.len(), 0);
/// assert!(pool.is_empty());
///
/// // Nothing resolves against an empty UTXO set, so a spend is held as an
/// // orphan rather than rejected: its parent may simply be in flight.
/// let view = MapView::new();
/// assert_eq!(pool.select_for_block(1_000_000, &view, 1), vec![]);
/// ```
#[derive(Debug)]
pub struct Mempool {
    cfg: MempoolConfig,
    inner: Mutex<Inner>,
}

impl Mempool {
    /// An empty pool.
    #[must_use]
    pub fn new(cfg: MempoolConfig) -> Self {
        let inner = Inner::new(cfg.max_orphans);
        Mempool { cfg, inner: Mutex::new(inner) }
    }

    /// The policy this pool was built with.
    #[must_use]
    pub const fn config(&self) -> &MempoolConfig {
        &self.cfg
    }

    /// The relay floor, in grains per 1000 bytes.
    #[must_use]
    pub const fn min_fee_rate(&self) -> u64 {
        self.cfg.min_fee_rate
    }

    // ------------------------------------------------------------------ reads

    /// The entry for `id`, if held.
    #[must_use]
    pub fn get(&self, id: &Txid) -> Option<MempoolEntry> {
        self.inner.lock().entries.get(id).cloned()
    }

    /// Whether `id` is held in the pool proper.
    #[must_use]
    pub fn contains(&self, id: &Txid) -> bool {
        self.inner.lock().entries.contains_key(id)
    }

    /// How many transactions are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }

    /// Whether the pool proper is empty. Orphans are not counted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().entries.is_empty()
    }

    /// Total serialized bytes held.
    #[must_use]
    pub fn size_bytes(&self) -> usize {
        self.inner.lock().size_bytes
    }

    /// Every held txid, in id order — what `getrawmempool` returns.
    #[must_use]
    pub fn txids(&self) -> Vec<Txid> {
        self.inner.lock().entries.keys().copied().collect()
    }

    /// Every held entry, highest fee rate first.
    #[must_use]
    pub fn entries_by_fee(&self) -> Vec<(Txid, MempoolEntry)> {
        let inner = self.inner.lock();
        inner
            .by_fee
            .iter()
            .rev()
            .filter_map(|k| inner.entries.get(&k.txid).map(|e| (k.txid, e.clone())))
            .collect()
    }

    /// Which held transaction claims `op`, if any.
    #[must_use]
    pub fn spender_of(&self, op: &OutPoint) -> Option<Txid> {
        self.inner.lock().spent.get(op).copied()
    }

    /// How many transactions are waiting for a parent.
    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.inner.lock().orphans.len()
    }

    /// Every waiting txid, in id order.
    #[must_use]
    pub fn orphan_txids(&self) -> Vec<Txid> {
        self.inner.lock().orphans.txids()
    }

    // ----------------------------------------------------------------- writes

    /// Offer `tx` to the pool.
    ///
    /// `view` is the UTXO set at the tip, `tip_height` the tip's height and
    /// `mtp_s` its median time past in seconds. Finality is judged against
    /// `tip_height + 1`, because that is the height the transaction would next
    /// be mined at.
    ///
    /// A transaction whose inputs are entirely unknown is *held*, not
    /// rejected: gossip does not preserve order, and dropping a child that
    /// arrived microseconds before its parent would make every multi-output
    /// payment a coin flip. See [`crate::orphan`].
    ///
    /// # Errors
    ///
    /// One [`MempoolError`] variant per policy rule. Every one of them is a
    /// local opinion; none of them makes a block containing the transaction
    /// invalid.
    pub fn accept(
        &self,
        tx: Transaction,
        view: &dyn StateView,
        tip_height: u64,
        mtp_s: u64,
    ) -> Result<AcceptResult, MempoolError> {
        let mut inner = self.inner.lock();
        // The only routine call that knows the current height, so the only
        // place a time-based sweep can happen without a clock.
        let _ = inner.maybe_expire(tip_height, self.cfg.expiry_blocks);

        match insert_one(&mut inner, &self.cfg, tx, view, tip_height, mtp_s)? {
            Admission::Added { txid: id, fee, fee_rate, size, evicted: mut all_evicted } => {
                let (promoted, more) =
                    drain_promotions(&mut inner, &self.cfg, vec![id], view, tip_height, mtp_s);
                all_evicted.extend(more);
                Ok(AcceptResult::Accepted {
                    txid: id,
                    fee,
                    fee_rate,
                    size,
                    promoted,
                    evicted: all_evicted,
                })
            }
            Admission::Orphaned { txid: id, missing } => {
                Ok(AcceptResult::Orphan { txid: id, missing })
            }
            Admission::AlreadyInPool { txid: id } => Ok(AcceptResult::AlreadyInPool { txid: id }),
        }
    }

    /// Choose transactions for a block at `height`, in dependency-safe
    /// descending fee-rate order.
    ///
    /// See [`crate::select`] for the algorithm and for what it does and does
    /// not re-check.
    #[must_use]
    pub fn select_for_block(
        &self,
        max_bytes: usize,
        view: &dyn StateView,
        height: u64,
    ) -> Vec<Transaction> {
        let inner = self.inner.lock();
        let ordered: Vec<(Txid, &MempoolEntry)> = inner
            .by_fee
            .iter()
            .rev()
            .filter_map(|k| inner.entries.get(&k.txid).map(|e| (k.txid, e)))
            .collect();
        select::select_for_block(&ordered, max_bytes, view, height, &self.cfg.params)
    }

    /// Forget the transactions a block just confirmed, and everything that
    /// now conflicts with them.
    ///
    /// The confirmed transactions themselves go. Their *children* stay: a
    /// parent's outputs are real UTXOs now, so a child that was spending an
    /// unconfirmed output is simply a normal transaction. What must go is
    /// anything spending an outpoint the block spent — that is a losing double
    /// spend and can never be mined — together with its descendants.
    ///
    /// Orphans waiting on a now-confirmed parent are *not* promoted here:
    /// promotion needs a UTXO view and this method is given none. Call
    /// [`Mempool::promote_orphans`] after connecting a block.
    pub fn remove_confirmed(&self, txs: &[Transaction]) {
        let mut inner = self.inner.lock();
        let mut consumed: BTreeSet<OutPoint> = BTreeSet::new();

        for tx in txs {
            let id = txid(tx);
            inner.take(&id);
            inner.orphans.remove(&id);
            if tx.is_coinbase() {
                continue;
            }
            for input in &tx.inputs {
                consumed.insert(input.prev_out);
            }
        }

        for op in consumed {
            let Some(spender) = inner.spent.get(&op).copied() else {
                continue;
            };
            let gone = inner.remove_with_descendants(&spender);
            tracing::debug!(
                outpoint = %op,
                removed = gone.len(),
                "evicted a mempool transaction the new block double-spent"
            );
        }
    }

    /// Re-evaluate every waiting orphan against the current state.
    ///
    /// Call this after a block connects: a parent that arrived in the block
    /// rather than over the transaction topic is exactly the case
    /// [`Mempool::accept`]'s own promotion cannot see. Returns the txids that
    /// made it into the pool, which are new to this node and should be
    /// relayed.
    pub fn promote_orphans(&self, view: &dyn StateView, tip_height: u64, mtp_s: u64) -> Vec<Txid> {
        let mut inner = self.inner.lock();
        let waiting = inner.orphans.txids();
        let mut candidates = Vec::with_capacity(waiting.len());
        for id in &waiting {
            if let Some(e) = inner.orphans.take(id) {
                candidates.push(e.tx);
            }
        }

        let mut roots = Vec::new();
        for tx in candidates {
            // A candidate whose parents are still missing is re-orphaned by
            // `insert_one`, so this loop is safe to run over the whole set.
            if let Ok(Admission::Added { txid: id, .. }) =
                insert_one(&mut inner, &self.cfg, tx, view, tip_height, mtp_s)
            {
                roots.push(id);
            }
        }
        let mut promoted = roots.clone();
        let (more, _) = drain_promotions(&mut inner, &self.cfg, roots, view, tip_height, mtp_s);
        promoted.extend(more);
        promoted
    }

    /// Reconcile the pool with a reorganisation (CONTRACT §9, SPEC §7.2 step 5).
    ///
    /// Three things must happen, and the order they happen in is what makes
    /// this correct:
    ///
    /// 1. **Everything is drained.** A held transaction may have been spending
    ///    an output that only existed on the branch that just went away —
    ///    including a coinbase output, which vanishes outright — so every
    ///    entry is judged again rather than trusted.
    /// 2. **The disconnected blocks' transactions are offered back**, oldest
    ///    block first so parents lead. A transaction the new chain already
    ///    confirmed is skipped, and one whose input the new chain spent is
    ///    dropped: it lost the race and can never be mined.
    /// 3. **Everything is re-admitted through the full acceptance path**, so
    ///    a transaction that is now immature, non-final, unfunded or a
    ///    double spend falls out by itself.
    ///
    /// Orphans are kept: a reorg is exactly when a missing parent might turn
    /// up, and the promotion worklist runs at the end.
    ///
    /// `disconnected` is expected tip-first, matching
    /// `ferrum_chain::AcceptOutcome::Reorged`; the order is only an
    /// optimisation, because a child offered before its parent is held as an
    /// orphan and promoted when the parent arrives.
    ///
    /// CONTRACT §9 gives this method no median time past, so it is
    /// reconstructed from the newly connected headers. A time-locked
    /// transaction misjudged by that approximation is dropped from a policy
    /// cache and can be re-relayed; it can never make an invalid block,
    /// because `ferrum_chain::build_template` re-checks finality against the
    /// real median before anything is sealed.
    pub fn reconcile_reorg(
        &self,
        disconnected: &[Block],
        connected: &[Block],
        view: &dyn StateView,
        height: u64,
    ) {
        let mut inner = self.inner.lock();

        let headers: Vec<BlockHeader> = connected.iter().map(|b| b.header).collect();
        let mtp_s = if headers.is_empty() { 0 } else { median_time_past(&headers) };

        // What the new chain confirmed, and what it spent.
        let mut confirmed: BTreeSet<Txid> = BTreeSet::new();
        let mut consumed: BTreeSet<OutPoint> = BTreeSet::new();
        for block in connected {
            for tx in &block.txs {
                confirmed.insert(txid(tx));
                if tx.is_coinbase() {
                    continue;
                }
                for input in &tx.inputs {
                    consumed.insert(input.prev_out);
                }
            }
        }

        // Outputs of a disconnected block's coinbase simply cease to exist:
        // no relay can ever produce the transaction that created them, so a
        // spend of one is dead rather than waiting. This is the reorg case
        // implementations get wrong — the child is held as an orphan forever
        // and quietly occupies the orphan pool until it expires.
        let mut vanished: BTreeSet<OutPoint> = BTreeSet::new();
        for block in disconnected {
            let Some(cb) = block.coinbase() else {
                continue;
            };
            let cb_id = txid(cb);
            for vout in 0..cb.outputs.len() {
                let Ok(vout) = u32::try_from(vout) else {
                    continue;
                };
                let op = OutPoint::new(cb_id, vout);
                // A branch that re-mined the identical coinbase would leave
                // the coin in place; only a genuinely absent one is vanished.
                if view.get_coin(&op).ok().flatten().is_none() {
                    vanished.insert(op);
                }
            }
            if !vanished.is_empty() {
                let dropped = inner.orphans.drop_children_of(&cb_id);
                if !dropped.is_empty() {
                    tracing::debug!(
                        coinbase = %cb_id,
                        dropped = dropped.len(),
                        "dropped orphans waiting on a coinbase the reorg removed"
                    );
                }
            }
        }

        // Drain. Resurrected transactions enter as new arrivals; previously
        // held ones keep the height they were first admitted at, so a reorg
        // does not reset every entry's expiry clock.
        let mut candidates: Vec<(Transaction, u64)> = Vec::new();
        for block in disconnected.iter().rev() {
            for tx in &block.txs {
                if tx.is_coinbase() {
                    continue;
                }
                candidates.push((tx.clone(), height));
            }
        }
        for id in inner.by_fee_descending() {
            if let Some(entry) = inner.take(&id) {
                let added = entry.added_height;
                candidates.push((entry.tx, added));
            }
        }
        inner.clear_entries();

        let mut roots = Vec::new();
        for (tx, added_height) in candidates {
            let id = txid(&tx);
            if confirmed.contains(&id) {
                continue;
            }
            if tx.inputs.iter().any(|i| consumed.contains(&i.prev_out)) {
                tracing::debug!(
                    txid = %id,
                    "dropping a mempool transaction double-spent by the new chain"
                );
                continue;
            }
            if tx.inputs.iter().any(|i| vanished.contains(&i.prev_out)) {
                tracing::debug!(
                    txid = %id,
                    "dropping a mempool transaction that spent a disconnected coinbase"
                );
                continue;
            }
            match insert_one(&mut inner, &self.cfg, tx, view, height, mtp_s) {
                Ok(Admission::Added { txid: id, .. }) => {
                    if let Some(e) = inner.entries.get_mut(&id) {
                        e.added_height = added_height;
                    }
                    roots.push(id);
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(txid = %id, error = %e, "dropped on reorg"),
            }
        }

        let _ = drain_promotions(&mut inner, &self.cfg, roots, view, height, mtp_s);
        inner.last_expiry_height = None;
        let _ = inner.maybe_expire(height, self.cfg.expiry_blocks);
    }

    /// Drop everything admitted more than `expiry_blocks` ago, with its
    /// descendants, and every orphan that old. Returns the removed txids.
    ///
    /// Called for free by [`Mempool::accept`] once per height; exposed so a
    /// node with an idle transaction topic still collects its pool as blocks
    /// arrive.
    pub fn expire(&self, tip_height: u64) -> Vec<Txid> {
        let mut inner = self.inner.lock();
        let mut gone = inner.expire(tip_height, self.cfg.expiry_blocks);
        gone.extend(inner.orphans.expire(tip_height, self.cfg.expiry_blocks));
        inner.last_expiry_height = Some(tip_height);
        gone
    }

    /// Forget everything, orphans included.
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.clear_entries();
        inner.orphans.clear();
        inner.last_expiry_height = None;
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Mempool::new(MempoolConfig::default())
    }
}
