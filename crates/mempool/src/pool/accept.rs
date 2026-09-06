//! The acceptance path: every rule a transaction must pass to be held, in the
//! order it is cheapest to apply them.
//!
//! The order is not arbitrary. Each step is more expensive than the last, and
//! script verification — the only step that costs real CPU — happens once
//! everything free has already said yes. A relay path that verified
//! signatures before checking the fee floor would hand every peer a free
//! denial-of-service primitive.
//!
//! 1. already held? (a map lookup)
//! 2. coinbase? (one field)
//! 3. SPEC §4.1 sanity (no allocation beyond a `BTreeSet` of outpoints)
//! 4. size and standardness
//! 5. finality against the *next* block
//! 6. conflicts with what the pool already holds — no replace-by-fee
//! 7. input resolution: the UTXO view first, then the pool's own outputs;
//!    anything still missing makes this an orphan
//! 8. coinbase maturity
//! 9. value: sums, fee, fee rate against the floor
//! 10. script verification
//! 11. insert, then evict down to `max_bytes` if the pool is now over
//!
//! None of it is consensus. A block containing a transaction rejected at any
//! step above is valid, and this node will accept that block.

use std::collections::BTreeSet;

use ferrum_chain::{check_transaction_sanity, is_final};
use ferrum_script::{ExecCtx, ScriptLimits, verify};
use ferrum_storage::{StateView, txid};
use ferrum_types::{Amount, Coin, Transaction, Txid};

use crate::error::MempoolError;
use crate::policy::{MempoolConfig, check_standard, fee_rate};
use crate::pool::entry::{Inner, MempoolEntry};

/// What one pass of the acceptance path decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    /// Admitted, possibly evicting others to make room.
    Added { txid: Txid, fee: Amount, fee_rate: u64, size: usize, evicted: Vec<Txid> },
    /// Held in the orphan pool.
    Orphaned { txid: Txid, missing: Vec<Txid> },
    /// Already held; nothing changed.
    AlreadyInPool { txid: Txid },
}

/// Either every input resolved, or the parents that did not.
enum Resolution {
    Coins(Vec<Coin>),
    Missing(BTreeSet<Txid>),
}

/// Run the acceptance path once, without promoting orphans.
///
/// Promotion is the caller's job ([`drain_promotions`]) because an orphan that
/// is promoted may itself unblock another orphan, and a function that
/// recursed into itself here would need a depth bound that a chain of
/// transactions could exhaust.
pub(crate) fn insert_one(
    inner: &mut Inner,
    cfg: &MempoolConfig,
    tx: Transaction,
    view: &dyn StateView,
    tip_height: u64,
    mtp_s: u64,
) -> Result<Admission, MempoolError> {
    let id = txid(&tx);

    // 1. Relay is idempotent: a peer re-announcing a transaction we hold is
    //    normal traffic, not an error.
    if inner.entries.contains_key(&id) {
        return Ok(Admission::AlreadyInPool { txid: id });
    }

    // 2. A coinbase exists only inside the block that creates it.
    if tx.is_coinbase() {
        return Err(MempoolError::Coinbase);
    }

    // 3. SPEC §4.1. A transaction that fails this cannot be mined by anyone,
    //    which is the one place policy and consensus genuinely agree.
    check_transaction_sanity(&tx, &cfg.params).map_err(MempoolError::Sanity)?;

    // 4. Size and standardness.
    let size = tx.serialized_size();
    check_standard(&tx, size)?;

    // 5. Finality is judged against the block this transaction could next go
    //    into, not the tip: a transaction locked to height `h` is relayable
    //    once the tip is `h - 1`, because the next block *is* height `h`.
    let next_height = tip_height.saturating_add(1);
    if !is_final(&tx, next_height, mtp_s) {
        return Err(MempoolError::NonFinal { lock_time: tx.lock_time, height: next_height });
    }

    // 6. No replace-by-fee in v1: the first transaction to claim an outpoint
    //    keeps it, whatever a later one offers.
    for input in &tx.inputs {
        if let Some(existing) = inner.spent.get(&input.prev_out) {
            return Err(MempoolError::Conflict { out_point: input.prev_out, existing: *existing });
        }
    }

    // 7. Resolve.
    let coins = match resolve_inputs(inner, &tx, view, next_height)? {
        Resolution::Coins(coins) => coins,
        Resolution::Missing(missing) => {
            let evicted = inner.orphans.insert(id, tx, missing.clone(), tip_height);
            if !evicted.is_empty() {
                tracing::warn!(
                    orphans = inner.orphans.len(),
                    capacity = inner.orphans.capacity(),
                    dropped = evicted.len(),
                    "orphan pool full; dropped the oldest entries"
                );
            }
            return Ok(Admission::Orphaned { txid: id, missing: missing.into_iter().collect() });
        }
    };

    // 8, 9. Maturity, sums and the fee floor.
    let mut inputs_total = Amount::ZERO;
    for (input, coin) in tx.inputs.iter().zip(coins.iter()) {
        if coin.is_coinbase {
            let mature_at = coin
                .height
                .checked_add(cfg.params.coinbase_maturity)
                .ok_or(MempoolError::Arithmetic("coinbase maturity height"))?;
            if next_height < mature_at {
                return Err(MempoolError::ImmatureCoinbaseSpend {
                    out_point: input.prev_out,
                    coin_height: coin.height,
                    spend_height: next_height,
                    maturity: cfg.params.coinbase_maturity,
                });
            }
        }
        inputs_total =
            inputs_total.checked_add(coin.value).ok_or(MempoolError::InputSumOverflow)?;
        if !inputs_total.is_valid_money() {
            return Err(MempoolError::InputSumOverflow);
        }
    }

    // `check_transaction_sanity` already proved the output sum is valid money.
    let outputs_total = tx.total_output().ok_or(MempoolError::InputSumOverflow)?;
    if inputs_total < outputs_total {
        return Err(MempoolError::InsufficientInputValue {
            inputs: inputs_total,
            outputs: outputs_total,
        });
    }
    let fee = inputs_total
        .checked_sub(outputs_total)
        .ok_or(MempoolError::Arithmetic("transaction fee"))?;
    let rate = fee_rate(fee, size).ok_or(MempoolError::Arithmetic("fee rate"))?;
    if rate < cfg.min_fee_rate {
        return Err(MempoolError::FeeTooLow { fee_rate: rate, min: cfg.min_fee_rate });
    }

    // 10. Scripts last: this is the only step that costs a signature check.
    for (input_index, (input, coin)) in tx.inputs.iter().zip(coins.iter()).enumerate() {
        let exec = ExecCtx {
            chain_id: cfg.params.chain_id,
            tx: &tx,
            input_index,
            input_value: coin.value,
            block_height: next_height,
            block_mtp_s: mtp_s,
            limits: ScriptLimits::CONSENSUS,
        };
        verify(&input.script_sig, &coin.script_pubkey, &exec)
            .map_err(|source| MempoolError::ScriptVerification { input_index, source })?;
    }

    // 11. Admit, then make room.
    let entry = MempoolEntry { tx, fee, size, fee_rate: rate, added_height: tip_height };
    inner.add(id, entry);
    let evicted = inner.evict_to_fit(cfg.max_bytes);
    if !evicted.is_empty() {
        tracing::warn!(
            size_bytes = inner.size_bytes,
            max_bytes = cfg.max_bytes,
            evicted = evicted.len(),
            "mempool over its byte limit; evicted the lowest fee rates"
        );
    }
    // If the arrival was itself the cheapest thing in the pool it has just
    // been evicted again. Say so, rather than reporting an acceptance the
    // caller would then fail to find.
    if !inner.entries.contains_key(&id) {
        return Err(MempoolError::PoolFull {
            size_bytes: inner.size_bytes,
            max_bytes: cfg.max_bytes,
        });
    }

    Ok(Admission::Added { txid: id, fee, fee_rate: rate, size, evicted })
}

/// Resolve every input against the UTXO view, then against the pool's own
/// unconfirmed outputs.
///
/// A pool output is handed back as a [`Coin`] at `next_height` and never
/// coinbase: it is a transaction output that does not exist yet, so the only
/// height that makes sense for it is the height it would first be spendable
/// at. Bitcoin Core does the same thing with its `MEMPOOL_HEIGHT` sentinel.
///
/// An input whose parent is *held* but whose `vout` is out of range is a hard
/// error, not an orphan: waiting for a parent that has already arrived cannot
/// help.
fn resolve_inputs(
    inner: &Inner,
    tx: &Transaction,
    view: &dyn StateView,
    next_height: u64,
) -> Result<Resolution, MempoolError> {
    let mut coins = Vec::with_capacity(tx.inputs.len());
    let mut missing: BTreeSet<Txid> = BTreeSet::new();

    for input in &tx.inputs {
        let op = input.prev_out;
        if let Some(coin) = view.get_coin(&op).map_err(|e| MempoolError::view(&e))? {
            coins.push(coin);
            continue;
        }
        match inner.entries.get(&op.txid) {
            Some(parent) => {
                let index = usize::try_from(op.vout)
                    .map_err(|_| MempoolError::Arithmetic("output index"))?;
                let out = parent
                    .tx
                    .outputs
                    .get(index)
                    .ok_or(MempoolError::MissingInput { out_point: op })?;
                coins.push(Coin::new(out.clone(), next_height, false));
            }
            None => {
                missing.insert(op.txid);
            }
        }
    }

    if missing.is_empty() { Ok(Resolution::Coins(coins)) } else { Ok(Resolution::Missing(missing)) }
}

/// Promote every orphan unblocked by `roots`, transitively.
///
/// A chain that arrived backwards — grandchild, child, parent — is fully
/// assembled by one call with the parent's txid as the only root: admitting
/// the parent releases the child, admitting the child releases the
/// grandchild, and the worklist keeps going until nothing is released.
///
/// Returns `(promoted, evicted)`. A promoted orphan that fails the acceptance
/// path a second time — its fee is now below the floor, or the pool filled up
/// while it waited — is simply dropped; it was never in the pool to begin
/// with.
pub(crate) fn drain_promotions(
    inner: &mut Inner,
    cfg: &MempoolConfig,
    roots: Vec<Txid>,
    view: &dyn StateView,
    tip_height: u64,
    mtp_s: u64,
) -> (Vec<Txid>, Vec<Txid>) {
    let mut promoted = Vec::new();
    let mut evicted = Vec::new();
    let mut queue = roots;

    while let Some(parent) = queue.pop() {
        for child in inner.orphans.take_children_of(&parent) {
            match insert_one(inner, cfg, child, view, tip_height, mtp_s) {
                Ok(Admission::Added { txid, evicted: e, .. }) => {
                    promoted.push(txid);
                    evicted.extend(e);
                    queue.push(txid);
                }
                // Still missing a *different* parent: back into the pool it
                // goes, keyed on whatever it is now waiting for.
                Ok(Admission::Orphaned { .. }) | Ok(Admission::AlreadyInPool { .. }) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "promoted orphan failed re-evaluation");
                }
            }
        }
    }

    (promoted, evicted)
}
