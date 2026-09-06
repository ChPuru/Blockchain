//! Block-template selection: descending fee rate, respecting in-block
//! dependency order.
//!
//! # The rule that makes this hard
//!
//! A block is validated in transaction order against an overlay of the parent
//! state (SPEC §3.3 rule 12), so a transaction may spend an output created by
//! an **earlier** transaction in the same block and never by a later one. A
//! selector that simply sorted the pool by fee rate would put a well-paying
//! child in front of its cheaper parent and produce a block that every node
//! rejects — after the miner had already spent the electricity sealing it.
//!
//! # The algorithm
//!
//! Repeated passes over the candidates, highest fee rate first. A candidate
//! goes in when every input resolves against the parent state or against
//! something already chosen; when its only missing input belongs to a
//! candidate still waiting, it is deferred to the next pass; anything else is
//! dropped. The loop stops when a pass adds nothing.
//!
//! The result is ordered by `(pass, fee rate)`. A parent is chosen no later
//! than the pass before its child, so the dependency rule holds by
//! construction, and within a pass the order is exactly descending fee rate.
//!
//! # What is re-checked here and what is not
//!
//! Re-checked: that each input still resolves, coinbase maturity at *this*
//! height, and that no created outpoint already exists. All three can change
//! under a reorganisation, and a stale entry would otherwise poison a
//! template.
//!
//! Not re-checked: signatures. They were verified when the transaction was
//! admitted, and a signature commits to the outpoint being spent, so the coin
//! behind an outpoint that still resolves is byte-identical to the one that
//! was verified. Re-verifying every input on every template would make block
//! production quadratic in pool size for no additional safety.
//!
//! Selection is policy. A miner may include anything valid, in any order that
//! satisfies the dependency rule, and a block that leaves money on the table
//! is perfectly valid.

use std::collections::BTreeSet;

use ferrum_storage::{OverlayView, StateView, txid};
use ferrum_types::{ChainParams, Coin, LOCKTIME_THRESHOLD, OutPoint, Transaction, Txid};

use crate::pool::MempoolEntry;

/// What one pass decided about one candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Inclusion {
    /// Chosen; its outputs are now spendable by later candidates.
    Included,
    /// Waiting on a candidate that has not been chosen yet.
    Deferred,
    /// Cannot go in this block at all.
    Rejected,
}

/// Whether `tx` is final at `height`, ignoring the timestamp branch.
///
/// [`crate::Mempool::select_for_block`] is given a height and no median time
/// past — its signature is fixed by CONTRACT §9 — so the time-locked branch of
/// SPEC §4.3 cannot be evaluated here. Time-locked transactions were checked
/// against the real median when they were admitted, and
/// [`ferrum_chain::build_template`] checks every candidate again with the
/// median in hand before the block is sealed. Passing them through is
/// therefore safe; rejecting them would drop transactions whose locks have
/// long expired.
#[must_use]
pub fn is_final_by_height(tx: &Transaction, height: u64) -> bool {
    if tx.lock_time == 0 {
        return true;
    }
    if tx.inputs.iter().all(|i| i.sequence == u32::MAX) {
        return true;
    }
    if tx.lock_time < LOCKTIME_THRESHOLD {
        return u64::from(tx.lock_time) <= height;
    }
    true
}

/// Choose transactions for a block at `height`.
///
/// `candidates` must already be ordered by descending fee rate; the caller
/// owns that ordering because [`crate::Mempool`] keeps a fee index and
/// re-sorting here would throw it away. `max_bytes` is the budget for the
/// transactions themselves, measured in serialized envelope bytes — one byte
/// per transaction more than a block actually pays for them, which is
/// deliberately conservative: a template can never overshoot
/// `max_block_size` because of this function.
///
/// Never returns a child before its parent. Never returns a transaction whose
/// inputs do not resolve, whose coinbase inputs are immature at `height`, or
/// that is not final by height.
#[must_use]
pub fn select_for_block(
    candidates: &[(Txid, &MempoolEntry)],
    max_bytes: usize,
    view: &dyn StateView,
    height: u64,
    params: &ChainParams,
) -> Vec<Transaction> {
    let mut overlay = OverlayView::new(view);
    let mut chosen: Vec<Transaction> = Vec::new();
    let mut used: usize = 0;

    let mut pending: Vec<(Txid, &MempoolEntry)> = candidates.to_vec();
    let mut waiting: BTreeSet<Txid> = pending.iter().map(|(id, _)| *id).collect();

    while !pending.is_empty() {
        let mut progress = false;
        let mut deferred: Vec<(Txid, &MempoolEntry)> = Vec::with_capacity(pending.len());

        for (id, entry) in std::mem::take(&mut pending) {
            // Budget first: it is the cheapest test, and skipping an
            // oversized candidate lets a smaller one behind it in.
            if used.saturating_add(entry.size) > max_bytes {
                waiting.remove(&id);
                continue;
            }
            match try_include(&mut overlay, entry, height, params, &waiting) {
                Inclusion::Included => {
                    used = used.saturating_add(entry.size);
                    chosen.push(entry.tx.clone());
                    waiting.remove(&id);
                    progress = true;
                }
                Inclusion::Deferred => deferred.push((id, entry)),
                Inclusion::Rejected => {
                    waiting.remove(&id);
                }
            }
        }

        if !progress {
            // Everything left is waiting on something that will never come.
            break;
        }
        pending = deferred;
    }

    chosen
}

/// Try to put one candidate into the block.
///
/// The overlay is mutated only on success: a candidate that turns out to be
/// unusable must leave the in-block state exactly as it found it, or the next
/// candidate would be judged against a half-applied transaction.
fn try_include(
    overlay: &mut OverlayView<'_>,
    entry: &MempoolEntry,
    height: u64,
    params: &ChainParams,
    waiting: &BTreeSet<Txid>,
) -> Inclusion {
    let tx = &entry.tx;

    if !is_final_by_height(tx, height) {
        return Inclusion::Rejected;
    }

    // Read-only resolution pass.
    let mut coins: Vec<Coin> = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        let op = input.prev_out;
        match overlay.get_coin(&op) {
            Err(_) => return Inclusion::Rejected,
            Ok(None) => {
                // A parent still in the running: try again next pass.
                if waiting.contains(&op.txid) {
                    return Inclusion::Deferred;
                }
                return Inclusion::Rejected;
            }
            Ok(Some(coin)) => {
                if coin.is_coinbase {
                    let Some(mature_at) = coin.height.checked_add(params.coinbase_maturity) else {
                        return Inclusion::Rejected;
                    };
                    if height < mature_at {
                        return Inclusion::Rejected;
                    }
                }
                coins.push(coin);
            }
        }
    }

    // SPEC §3.3 rule 15 — a created outpoint must not already exist. BIP-34
    // makes this unreachable for coinbases and a txid collision unreachable
    // for everything else, but the inflation path is the wrong place to rely
    // on an argument rather than a check.
    let id = txid(tx);
    for vout in 0..tx.outputs.len() {
        let Ok(vout) = u32::try_from(vout) else {
            return Inclusion::Rejected;
        };
        match overlay.has_coin(&OutPoint::new(id, vout)) {
            Err(_) | Ok(true) => return Inclusion::Rejected,
            Ok(false) => {}
        }
    }

    // Commit.
    for input in &tx.inputs {
        match overlay.spend(&input.prev_out) {
            Ok(Some(_)) => {}
            // Unreachable: every input resolved a moment ago against this same
            // overlay, and nothing else can touch it in between.
            Ok(None) | Err(_) => return Inclusion::Rejected,
        }
    }
    for (vout, out) in tx.outputs.iter().enumerate() {
        let Ok(vout) = u32::try_from(vout) else {
            return Inclusion::Rejected;
        };
        overlay.add(OutPoint::new(id, vout), Coin::new(out.clone(), height, false));
    }

    Inclusion::Included
}
