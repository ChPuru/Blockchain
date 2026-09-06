//! The pool's entry type and its three indices.
//!
//! # Three indices, one truth
//!
//! | Index | Answers |
//! |---|---|
//! | `entries: BTreeMap<Txid, MempoolEntry>` | "do I have this transaction?" |
//! | `by_fee: BTreeSet<FeeKey>` | "what is cheapest / dearest?" |
//! | `spent: BTreeMap<OutPoint, Txid>` | "is this outpoint already claimed?" |
//!
//! Every mutation goes through [`Inner::add`] and [`Inner::take`] so the three
//! cannot drift apart. A spent-outpoint index that has lost an entry is a
//! double-spend the pool cannot see, which is the whole reason it exists.
//!
//! All three are ordered maps. Eviction order, selection order and the reason
//! a transaction was refused are all observable, and a `HashMap` would make
//! two nodes given the same transactions behave differently.

use std::collections::{BTreeMap, BTreeSet};

use ferrum_types::{Amount, OutPoint, Transaction, Txid};

use crate::orphan::OrphanPool;

/// One transaction held for relay and mining (CONTRACT §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolEntry {
    /// The transaction.
    pub tx: Transaction,
    /// `sum(inputs) - sum(outputs)`, in grains.
    pub fee: Amount,
    /// Serialized envelope size, in bytes — the same number
    /// [`ferrum_types::Transaction::serialized_size`] reports.
    pub size: usize,
    /// `fee * 1000 / size`, grains per 1000 bytes, truncating.
    pub fee_rate: u64,
    /// The tip height when this entry was admitted, for expiry.
    pub added_height: u64,
}

impl MempoolEntry {
    /// The key this entry occupies in the fee index.
    #[must_use]
    pub fn fee_key(&self, txid: Txid) -> FeeKey {
        FeeKey { fee_rate: self.fee_rate, txid }
    }
}

/// The fee index's key: fee rate first, then txid.
///
/// Ascending iteration gives the eviction victim; `.rev()` gives the mining
/// candidate. The txid is in the key so that two transactions paying the same
/// rate are still ordered — deterministically, and identically on every node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeeKey {
    /// Grains per 1000 bytes.
    pub fee_rate: u64,
    /// The transaction this key belongs to.
    pub txid: Txid,
}

/// Everything the pool owns, behind one lock.
#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) entries: BTreeMap<Txid, MempoolEntry>,
    pub(crate) by_fee: BTreeSet<FeeKey>,
    pub(crate) spent: BTreeMap<OutPoint, Txid>,
    pub(crate) size_bytes: usize,
    pub(crate) orphans: OrphanPool,
    /// The height the last expiry sweep ran at.
    pub(crate) last_expiry_height: Option<u64>,
}

impl Inner {
    /// An empty pool with an orphan pool of `max_orphans`.
    pub(crate) fn new(max_orphans: usize) -> Self {
        Inner {
            entries: BTreeMap::new(),
            by_fee: BTreeSet::new(),
            spent: BTreeMap::new(),
            size_bytes: 0,
            orphans: OrphanPool::new(max_orphans),
            last_expiry_height: None,
        }
    }

    /// Forget every held transaction, keeping the orphan pool.
    pub(crate) fn clear_entries(&mut self) {
        self.entries.clear();
        self.by_fee.clear();
        self.spent.clear();
        self.size_bytes = 0;
    }

    /// Insert an entry and claim every outpoint it spends.
    ///
    /// The caller has already established that no outpoint is claimed by
    /// anything else; a debug assertion holds it to that, because a silent
    /// overwrite here is a double spend the pool would then be blind to.
    pub(crate) fn add(&mut self, txid: Txid, entry: MempoolEntry) {
        for input in &entry.tx.inputs {
            let previous = self.spent.insert(input.prev_out, txid);
            debug_assert!(previous.is_none(), "an outpoint was claimed twice");
        }
        self.by_fee.insert(entry.fee_key(txid));
        self.size_bytes = self.size_bytes.saturating_add(entry.size);
        self.entries.insert(txid, entry);
    }

    /// Remove one entry and release its outpoints. Descendants are left alone.
    pub(crate) fn take(&mut self, txid: &Txid) -> Option<MempoolEntry> {
        let entry = self.entries.remove(txid)?;
        self.by_fee.remove(&entry.fee_key(*txid));
        self.size_bytes = self.size_bytes.saturating_sub(entry.size);
        for input in &entry.tx.inputs {
            // Only release an outpoint this entry actually holds. It always
            // does, but the check costs nothing and a stray release would
            // silently permit a double spend.
            if self.spent.get(&input.prev_out) == Some(txid) {
                self.spent.remove(&input.prev_out);
            }
        }
        Some(entry)
    }

    /// Remove `txid` and everything in the pool that descends from it.
    ///
    /// A child whose parent has left the pool can never be mined from this
    /// pool — its input does not exist anywhere a miner can see — so keeping
    /// it would waste bytes and give `select_for_block` work to reject on
    /// every call. Returns the removed txids, ancestors first.
    pub(crate) fn remove_with_descendants(&mut self, txid: &Txid) -> Vec<Txid> {
        let mut removed = Vec::new();
        let mut queue = vec![*txid];
        while let Some(current) = queue.pop() {
            // Children must be found *before* the entry goes, because the
            // lookup keys are built from its outputs.
            let Some(entry) = self.entries.get(&current) else {
                continue;
            };
            let mut children = Vec::new();
            for vout in 0..entry.tx.outputs.len() {
                let Ok(vout) = u32::try_from(vout) else {
                    continue;
                };
                if let Some(child) = self.spent.get(&OutPoint::new(current, vout)) {
                    children.push(*child);
                }
            }
            if self.take(&current).is_some() {
                removed.push(current);
            }
            queue.extend(children);
        }
        removed
    }

    /// Evict lowest-fee-rate-first until the pool fits in `max_bytes`.
    ///
    /// Evicting an entry takes its descendants with it, which can remove a
    /// transaction paying more than the victim. That is correct and it is
    /// what Bitcoin Core does: a child is unminable without its parent, so its
    /// fee rate on its own was never the number that mattered.
    pub(crate) fn evict_to_fit(&mut self, max_bytes: usize) -> Vec<Txid> {
        let mut evicted = Vec::new();
        while self.size_bytes > max_bytes {
            let Some(key) = self.by_fee.iter().next().copied() else {
                break;
            };
            let gone = self.remove_with_descendants(&key.txid);
            if gone.is_empty() {
                // Unreachable while the indices agree, and an infinite loop if
                // they ever stop agreeing. Drop the orphaned key and carry on
                // rather than spinning forever holding the pool's lock.
                debug_assert!(false, "fee index names a transaction the pool does not hold");
                self.by_fee.remove(&key);
                continue;
            }
            evicted.extend(gone);
        }
        evicted
    }

    /// Drop entries admitted more than `expiry_blocks` ago, with their
    /// descendants.
    ///
    /// Returns the removed txids. A transaction nobody has mined in a
    /// fortnight is not going to be mined; holding it forever is how a pool
    /// fills with transactions whose inputs the network has long forgotten.
    pub(crate) fn expire(&mut self, tip_height: u64, expiry_blocks: u64) -> Vec<Txid> {
        let stale: Vec<Txid> = self
            .entries
            .iter()
            .filter(|(_, e)| tip_height.saturating_sub(e.added_height) >= expiry_blocks)
            .map(|(id, _)| *id)
            .collect();
        let mut removed = Vec::new();
        for id in stale {
            removed.extend(self.remove_with_descendants(&id));
        }
        removed
    }

    /// Run [`Self::expire`] and the orphan pool's, but only once per height.
    ///
    /// Expiry is an O(pool) scan and nothing can expire between two
    /// transactions arriving at the same height, so running it on every
    /// `accept` would make acceptance linear in the pool size for no reason.
    pub(crate) fn maybe_expire(&mut self, tip_height: u64, expiry_blocks: u64) -> Vec<Txid> {
        if self.last_expiry_height == Some(tip_height) {
            return Vec::new();
        }
        self.last_expiry_height = Some(tip_height);
        let mut gone = self.expire(tip_height, expiry_blocks);
        gone.extend(self.orphans.expire(tip_height, expiry_blocks));
        gone
    }

    /// Every transaction, highest fee rate first.
    pub(crate) fn by_fee_descending(&self) -> Vec<Txid> {
        self.by_fee.iter().rev().map(|k| k.txid).collect()
    }
}

/// What accepting a transaction did.
///
/// Not named by CONTRACT §9 beyond the `AcceptResult` type name, so the shape
/// is chosen for the two callers that exist: the RPC `sendrawtransaction`,
/// which wants a txid and nothing else, and the p2p relay task, which wants to
/// know what else it should now announce — a promoted orphan is a transaction
/// this node has just learned about and must forward.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcceptResult {
    /// Admitted to the pool.
    Accepted {
        /// The transaction's id.
        txid: Txid,
        /// Its fee.
        fee: Amount,
        /// Its fee rate, grains per 1000 bytes.
        fee_rate: u64,
        /// Its serialized size.
        size: usize,
        /// Orphans that this arrival unblocked, in promotion order. These are
        /// new to the node and must be relayed.
        promoted: Vec<Txid>,
        /// Transactions evicted to make room, including any evicted while
        /// admitting a promoted orphan.
        evicted: Vec<Txid>,
    },
    /// Held in the orphan pool: at least one input names a transaction this
    /// node has never seen.
    Orphan {
        /// The transaction's id.
        txid: Txid,
        /// The parents it is waiting for.
        missing: Vec<Txid>,
    },
    /// Already held. Relay is idempotent, so this is not an error.
    AlreadyInPool {
        /// The transaction's id.
        txid: Txid,
    },
}

impl AcceptResult {
    /// The transaction's id, whatever happened to it.
    #[must_use]
    pub const fn txid(&self) -> Txid {
        match self {
            AcceptResult::Accepted { txid, .. }
            | AcceptResult::Orphan { txid, .. }
            | AcceptResult::AlreadyInPool { txid } => *txid,
        }
    }

    /// Whether the transaction is now in the pool proper.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, AcceptResult::Accepted { .. })
    }

    /// Whether the transaction is waiting for a parent.
    #[must_use]
    pub const fn is_orphan(&self) -> bool {
        matches!(self, AcceptResult::Orphan { .. })
    }

    /// The txids this node should announce: the transaction itself when it was
    /// admitted, plus every orphan its arrival promoted.
    #[must_use]
    pub fn relayable(&self) -> Vec<Txid> {
        match self {
            AcceptResult::Accepted { txid, promoted, .. } => {
                let mut out = Vec::with_capacity(promoted.len().saturating_add(1));
                out.push(*txid);
                out.extend(promoted.iter().copied());
                out
            }
            AcceptResult::Orphan { .. } | AcceptResult::AlreadyInPool { .. } => Vec::new(),
        }
    }
}
