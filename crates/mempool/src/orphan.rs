//! The orphan pool: transactions whose parents have not arrived.
//!
//! Gossip does not preserve order. A wallet that builds a chain of three
//! transactions and broadcasts them together will have them arrive in any
//! order at all, and a node that dropped the child because the parent was two
//! milliseconds behind would make every multi-transaction payment a coin flip.
//! So a transaction with a missing input is *held*, keyed by the txid of each
//! parent it is waiting for, and re-evaluated the moment that parent lands
//! (SPEC §10).
//!
//! # Why it is capped, and capped hard
//!
//! An orphan is memory the sender has not paid for: it costs nothing to
//! fabricate a transaction spending an outpoint that will never exist. So the
//! pool has an explicit ceiling — [`crate::DEFAULT_MAX_ORPHANS`], 200 — and
//! evicting *the oldest* is the eviction rule. Not a random victim, which is
//! what Bitcoin Core does: randomness would make the node's behaviour
//! irreproducible, and this crate is tested by replaying fixed sequences.
//!
//! Nothing in here is consensus. An orphan that is dropped is simply
//! forgotten; the peer that sent it may send it again.

use std::collections::{BTreeMap, BTreeSet};

use ferrum_types::{Transaction, Txid};

/// One transaction waiting for its parents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrphanEntry {
    /// The transaction itself.
    pub tx: Transaction,
    /// Txids of the parents it is waiting for. Never empty.
    pub missing: BTreeSet<Txid>,
    /// The tip height when it arrived, for expiry.
    pub added_height: u64,
    /// Arrival order. Lowest is oldest; the eviction victim.
    pub seq: u64,
}

/// A bounded, deterministic pool of transactions with missing inputs.
///
/// `BTreeMap`/`BTreeSet` throughout: eviction order and promotion order are
/// observable, and a `HashMap` would make two nodes fed the same transactions
/// hold different pools.
#[derive(Clone, Debug)]
pub struct OrphanPool {
    max: usize,
    by_txid: BTreeMap<Txid, OrphanEntry>,
    by_parent: BTreeMap<Txid, BTreeSet<Txid>>,
    by_seq: BTreeMap<u64, Txid>,
    next_seq: u64,
}

impl OrphanPool {
    /// A pool holding at most `max` transactions.
    ///
    /// `max == 0` disables the orphan pool entirely: [`Self::insert`] then
    /// stores nothing and reports the transaction itself as evicted.
    #[must_use]
    pub fn new(max: usize) -> Self {
        OrphanPool {
            max,
            by_txid: BTreeMap::new(),
            by_parent: BTreeMap::new(),
            by_seq: BTreeMap::new(),
            next_seq: 0,
        }
    }

    /// The ceiling this pool was built with.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.max
    }

    /// How many transactions are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_txid.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_txid.is_empty()
    }

    /// Whether `id` is held.
    #[must_use]
    pub fn contains(&self, id: &Txid) -> bool {
        self.by_txid.contains_key(id)
    }

    /// The entry for `id`, if held.
    #[must_use]
    pub fn get(&self, id: &Txid) -> Option<&OrphanEntry> {
        self.by_txid.get(id)
    }

    /// Every held txid, in id order.
    #[must_use]
    pub fn txids(&self) -> Vec<Txid> {
        self.by_txid.keys().copied().collect()
    }

    /// Hold `tx`, waiting on `missing`.
    ///
    /// Returns the txids evicted to make room — the oldest arrivals, or `tx`
    /// itself when the pool's capacity is zero. Re-inserting a transaction
    /// already held refreshes nothing and evicts nothing; the first arrival's
    /// position in the queue is kept, so a peer cannot renew an orphan
    /// indefinitely by resending it.
    pub fn insert(
        &mut self,
        id: Txid,
        tx: Transaction,
        missing: BTreeSet<Txid>,
        added_height: u64,
    ) -> Vec<Txid> {
        debug_assert!(!missing.is_empty(), "an orphan waits on at least one parent");
        if self.by_txid.contains_key(&id) {
            return Vec::new();
        }
        if self.max == 0 {
            return vec![id];
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        for parent in &missing {
            self.by_parent.entry(*parent).or_default().insert(id);
        }
        self.by_seq.insert(seq, id);
        self.by_txid.insert(id, OrphanEntry { tx, missing, added_height, seq });

        let mut evicted = Vec::new();
        while self.by_txid.len() > self.max {
            let Some((_, oldest)) = self.by_seq.iter().next().map(|(s, t)| (*s, *t)) else {
                break;
            };
            self.remove(&oldest);
            evicted.push(oldest);
        }
        evicted
    }

    /// Remove and return every orphan waiting on `parent`.
    ///
    /// An orphan waiting on more than one parent is only released when the
    /// last of them arrives: releasing it early would re-run the whole
    /// acceptance path only to put it straight back.
    pub fn take_children_of(&mut self, parent: &Txid) -> Vec<Transaction> {
        self.take_child_entries_of(parent).into_iter().map(|e| e.tx).collect()
    }

    /// [`Self::take_children_of`], keeping each entry's arrival stamp.
    ///
    /// A released child can still fail re-evaluation and land back here — its
    /// parent may have been evicted again in the meantime — and the caller
    /// needs the original `added_height`/`seq` to hand to
    /// [`Self::restore_age`], or the round trip silently renews the orphan.
    pub fn take_child_entries_of(&mut self, parent: &Txid) -> Vec<OrphanEntry> {
        let Some(children) = self.by_parent.remove(parent) else {
            return Vec::new();
        };
        let mut ready = Vec::new();
        for child in children {
            let still_waiting = {
                let Some(entry) = self.by_txid.get_mut(&child) else {
                    continue;
                };
                entry.missing.remove(parent);
                !entry.missing.is_empty()
            };
            if still_waiting {
                continue;
            }
            if let Some(entry) = self.take(&child) {
                ready.push(entry);
            }
        }
        ready
    }

    /// Drop every orphan waiting on `parent`, whatever else it is waiting for.
    ///
    /// The counterpart to [`Self::take_children_of`]: that one releases a
    /// child because its parent arrived, this one discards it because the
    /// parent has been established never to arrive — the coinbase of a block
    /// that a reorganisation removed, for instance. Returns the dropped
    /// txids.
    pub fn drop_children_of(&mut self, parent: &Txid) -> Vec<Txid> {
        let Some(children) = self.by_parent.get(parent).cloned() else {
            return Vec::new();
        };
        let mut dropped = Vec::new();
        for child in children {
            if self.remove(&child) {
                dropped.push(child);
            }
        }
        dropped
    }

    /// Remove `id`, returning its entry.
    pub fn take(&mut self, id: &Txid) -> Option<OrphanEntry> {
        let entry = self.by_txid.remove(id)?;
        self.by_seq.remove(&entry.seq);
        for parent in &entry.missing {
            if let Some(set) = self.by_parent.get_mut(parent) {
                set.remove(id);
                if set.is_empty() {
                    self.by_parent.remove(parent);
                }
            }
        }
        Some(entry)
    }

    /// Remove `id`, reporting whether it was held.
    pub fn remove(&mut self, id: &Txid) -> bool {
        self.take(id).is_some()
    }

    /// Put an entry's age back where it was.
    ///
    /// [`crate::Mempool::promote_orphans`] re-offers every waiting orphan to
    /// the acceptance path on every block, and one whose parents are still
    /// missing lands back here through [`Self::insert`] — which stamps it with
    /// the *current* tip height. Left alone, that resets the expiry clock on
    /// every block and [`Self::expire`] can never fire: the node renews the
    /// orphan itself, which is exactly what [`Self::insert`]'s own contract
    /// says a peer must not be able to do. Restoring the original
    /// `added_height` and `seq` keeps both the expiry clock and the eviction
    /// queue where the first arrival put them.
    ///
    /// Does nothing when `id` is not held. Returns whether it was.
    pub fn restore_age(&mut self, id: &Txid, added_height: u64, seq: u64) -> bool {
        let Some(entry) = self.by_txid.get_mut(id) else {
            return false;
        };
        let previous = entry.seq;
        entry.added_height = added_height;
        entry.seq = seq;
        self.by_seq.remove(&previous);
        self.by_seq.insert(seq, *id);
        true
    }

    /// Drop everything that arrived more than `expiry_blocks` ago.
    ///
    /// Returns the evicted txids in id order. An orphan whose parent was
    /// confirmed and then spent by someone else waits forever otherwise; this
    /// is the only thing that collects it.
    pub fn expire(&mut self, tip_height: u64, expiry_blocks: u64) -> Vec<Txid> {
        let stale: Vec<Txid> = self
            .by_txid
            .iter()
            .filter(|(_, e)| tip_height.saturating_sub(e.added_height) >= expiry_blocks)
            .map(|(id, _)| *id)
            .collect();
        for id in &stale {
            self.remove(id);
        }
        stale
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        self.by_txid.clear();
        self.by_parent.clear();
        self.by_seq.clear();
    }
}

impl Default for OrphanPool {
    fn default() -> Self {
        OrphanPool::new(crate::policy::DEFAULT_MAX_ORPHANS)
    }
}
