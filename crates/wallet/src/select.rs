//! Coin selection: branch-and-bound first, largest-first as the fallback.
//!
//! # Why two algorithms
//!
//! **Branch-and-bound** looks for a subset of coins whose *effective* value
//! lands inside a narrow window above the target, so the transaction needs no
//! change output at all. A changeless transaction is smaller (37 fewer bytes),
//! cheaper, and — the part that actually matters — it does not add a new
//! entry to the UTXO set that every full node on the network stores forever.
//! It also leaks less: an observer cannot tell which output was the payment.
//! Bitcoin Core has used this since 0.17 and it is the single biggest
//! improvement available to a from-scratch wallet.
//!
//! **Largest-first** is the fallback when no exact match exists. It is not the
//! privacy-optimal choice — it consolidates, which links coins — but it is
//! deterministic, it terminates, and it minimises input count, which minimises
//! the fee. A randomised fallback would need an RNG in a function the contract
//! declares without one, and would make a failing selection impossible to
//! reproduce from a bug report.
//!
//! # Effective value
//!
//! A coin worth `v` that costs `fee(input_bytes)` to spend contributes
//! `v - fee(input_bytes)` towards the target. Selecting on raw value instead
//! is the classic bug: a wallet accumulates just enough raw value, discovers
//! the inputs it added made the transaction bigger, and either underpays the
//! fee or has to start over. Selecting on effective value makes the accounting
//! close in one pass. A coin whose effective value is zero or negative is
//! dropped: spending it costs more than it is worth.
//!
//! # Dust
//!
//! Change below the dust threshold (`3 * min_relay_fee`, CONTRACT §12) is
//! **added to the fee** rather than written as an output. An output worth less
//! than it costs to spend is a permanent tax on every node's UTXO set, and it
//! is unspendable in practice anyway.

use ferrum_types::{Amount, Coin, OutPoint};

use crate::error::WalletError;
use crate::fee::{FeeRate, input_size};

/// How many branches branch-and-bound explores before giving up.
///
/// Bitcoin Core's number. The search is exponential in the worst case, so the
/// bound is what makes selection a bounded-time operation rather than a
/// denial-of-service vector against the wallet's own owner.
pub const BNB_MAX_TRIES: u32 = 100_000;

/// Which algorithm produced a [`Selection`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SelectionStrategy {
    /// An exact match was found; the transaction has no change output.
    BranchAndBound,
    /// No exact match; coins were taken largest-first.
    LargestFirst,
}

/// One coin offered to the selector, with its cost to spend precomputed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// Where the coin lives.
    pub out_point: OutPoint,
    /// The coin.
    pub coin: Coin,
    /// Wire bytes this coin adds once signed.
    pub input_bytes: usize,
    /// `coin.value - fee(input_bytes)`, saturating at zero.
    pub effective_value: Amount,
}

impl Candidate {
    /// Price one coin at a fee rate.
    ///
    /// Returns `Ok(None)` when the coin cannot pay for its own input — such a
    /// coin makes every selection that includes it strictly worse.
    pub fn price(
        out_point: OutPoint,
        coin: Coin,
        fee_rate: FeeRate,
    ) -> Result<Option<Candidate>, WalletError> {
        let input_bytes = input_size(&coin.script_pubkey)?;
        let cost = fee_rate.fee_for_size(input_bytes)?;
        match coin.value.checked_sub(cost) {
            Some(effective_value) if !effective_value.is_zero() => {
                Ok(Some(Candidate { out_point, coin, input_bytes, effective_value }))
            }
            _ => Ok(None),
        }
    }
}

/// Everything coin selection decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    /// The chosen coins, in outpoint order.
    pub inputs: Vec<(OutPoint, Coin)>,
    /// Sum of the chosen coins' raw values.
    pub input_total: Amount,
    /// The fee this transaction will pay.
    pub fee: Amount,
    /// The change amount, or `None` for a changeless transaction.
    pub change: Option<Amount>,
    /// Wire size of the signed transaction this selection implies.
    pub size: usize,
    /// Which algorithm found it.
    pub strategy: SelectionStrategy,
}

impl Selection {
    /// The realised fee rate, in grains per 1000 bytes.
    pub fn fee_rate(&self) -> u64 {
        FeeRate::of(self.fee, self.size)
    }
}

/// Everything selection needs to know about the transaction being built.
#[derive(Clone, Copy, Debug)]
pub struct SelectionParams {
    /// The rate the caller asked for.
    pub fee_rate: FeeRate,
    /// Change below this is folded into the fee instead of written out.
    pub dust_threshold: Amount,
    /// Bytes the transaction costs before any input: overhead plus every
    /// recipient output.
    pub base_size: usize,
    /// Bytes a change output would add.
    pub change_output_size: usize,
    /// Bytes it will one day cost to *spend* the change output, used to price
    /// the whole lifetime cost of creating one.
    pub change_spend_size: usize,
}

impl SelectionParams {
    /// The cost of having a change output at all: writing it now plus spending
    /// it later.
    ///
    /// Branch-and-bound accepts any overshoot smaller than this, because
    /// paying it to the miner is cheaper than carrying a change output.
    pub fn cost_of_change(&self) -> Result<Amount, WalletError> {
        let create = self.fee_rate.fee_for_size(self.change_output_size)?;
        let spend = self.fee_rate.fee_for_size(self.change_spend_size)?;
        create.checked_add(spend).ok_or(WalletError::AmountOverflow("pricing a change output"))
    }
}

/// Select coins to cover `target`.
///
/// `target` is the sum of the recipient outputs; the fee is computed inside
/// and is *not* part of `target`.
pub fn select_coins(
    candidates: &[Candidate],
    target: Amount,
    params: &SelectionParams,
) -> Result<Selection, WalletError> {
    // Descending effective value, ties broken by outpoint so the search order
    // — and therefore the transaction — is reproducible.
    let mut pool: Vec<Candidate> = candidates.to_vec();
    pool.sort_by(|a, b| {
        b.effective_value
            .cmp(&a.effective_value)
            .then_with(|| a.out_point.txid.cmp(&b.out_point.txid))
            .then_with(|| a.out_point.vout.cmp(&b.out_point.vout))
    });

    if let Some(selection) = select_branch_and_bound(&pool, target, params)? {
        return Ok(selection);
    }
    select_largest_first(&pool, target, params)
}

/// Branch-and-bound for a changeless match (CONTRACT §12).
///
/// The search target is `target + fee(base_size)`: when the selected effective
/// values sum to exactly that, `sum(raw values) - target` equals the fee for
/// the resulting size, so the transaction balances with no change output.
/// Anything up to `cost_of_change` above that is accepted and paid to the
/// miner.
///
/// Returns `Ok(None)` when no subset lands in the window, which is the normal
/// case and not an error.
fn select_branch_and_bound(
    pool: &[Candidate],
    target: Amount,
    params: &SelectionParams,
) -> Result<Option<Selection>, WalletError> {
    if pool.is_empty() {
        return Ok(None);
    }
    let base_fee = params.fee_rate.fee_for_size(params.base_size)?;
    let search_target = target
        .checked_add(base_fee)
        .ok_or(WalletError::AmountOverflow("computing a selection target"))?
        .to_grains();
    let cost_of_change = params.cost_of_change()?.to_grains();
    let upper_bound = search_target
        .checked_add(cost_of_change)
        .ok_or(WalletError::AmountOverflow("computing a selection window"))?;

    let effective: Vec<u64> = pool.iter().map(|c| c.effective_value.to_grains()).collect();
    let mut available: u64 = 0;
    for value in &effective {
        available = available
            .checked_add(*value)
            .ok_or(WalletError::AmountOverflow("summing candidate values"))?;
    }
    if available < search_target {
        return Ok(None);
    }

    // `curr_selection[i] == true` means candidate `i` is in the current
    // branch. This is Bitcoin Core's iterative formulation: an explicit
    // include/exclude stack rather than recursion, so the search cannot blow
    // the Rust stack on a wallet with thousands of coins.
    let mut curr_selection: Vec<bool> = Vec::with_capacity(effective.len());
    let mut curr_value: u64 = 0;
    let mut best_selection: Option<Vec<bool>> = None;
    let mut best_waste: u64 = u64::MAX;

    for _ in 0..BNB_MAX_TRIES {
        let mut backtrack = false;
        if curr_value.saturating_add(available) < search_target || curr_value > upper_bound {
            // Cannot reach the target down this branch, or already overshot.
            backtrack = true;
        } else if curr_value >= search_target {
            let waste = curr_value.saturating_sub(search_target);
            if waste <= best_waste {
                best_waste = waste;
                best_selection = Some(curr_selection.clone());
            }
            backtrack = true;
        }

        if backtrack {
            // Unwind past every excluded tail entry, restoring what each made
            // available again.
            while curr_selection.last().copied() == Some(false) {
                curr_selection.pop();
                if let Some(value) = effective.get(curr_selection.len()) {
                    available = available.saturating_add(*value);
                }
            }
            let Some(last) = curr_selection.last_mut() else {
                break;
            };
            // The tail is an included entry; explore its exclusion branch.
            *last = false;
            let index = curr_selection.len().saturating_sub(1);
            if let Some(value) = effective.get(index) {
                curr_value = curr_value.saturating_sub(*value);
            }
        } else {
            let index = curr_selection.len();
            let Some(&value) = effective.get(index) else {
                break;
            };
            available = available.saturating_sub(value);
            // Skip the inclusion branch for a coin identical in value to one
            // we just excluded: the two branches are the same set.
            let duplicate_of_excluded = curr_selection.last().copied() == Some(false)
                && index > 0
                && effective.get(index.saturating_sub(1)) == Some(&value);
            if duplicate_of_excluded {
                curr_selection.push(false);
            } else {
                curr_selection.push(true);
                curr_value = curr_value.saturating_add(value);
            }
        }
    }

    let Some(chosen) = best_selection else {
        return Ok(None);
    };

    let mut inputs = Vec::new();
    let mut input_total = Amount::ZERO;
    let mut input_bytes: usize = 0;
    for (index, included) in chosen.iter().enumerate() {
        if !included {
            continue;
        }
        let candidate =
            pool.get(index).ok_or(WalletError::AmountOverflow("indexing the candidate pool"))?;
        input_total = input_total
            .checked_add(candidate.coin.value)
            .ok_or(WalletError::AmountOverflow("summing selected inputs"))?;
        input_bytes = input_bytes.saturating_add(candidate.input_bytes);
        inputs.push((candidate.out_point, candidate.coin.clone()));
    }
    inputs.sort_by(|a, b| a.0.txid.cmp(&b.0.txid).then_with(|| a.0.vout.cmp(&b.0.vout)));

    let size = params.base_size.saturating_add(input_bytes);
    let fee = input_total
        .checked_sub(target)
        .ok_or(WalletError::AmountOverflow("computing a changeless fee"))?;
    Ok(Some(Selection {
        inputs,
        input_total,
        fee,
        change: None,
        size,
        strategy: SelectionStrategy::BranchAndBound,
    }))
}

/// Largest-first accumulation with a change output.
///
/// At every step the accumulated total is tested against both shapes: a
/// changeless transaction first (cheaper), then one with change. Change below
/// the dust threshold is folded into the fee.
fn select_largest_first(
    pool: &[Candidate],
    target: Amount,
    params: &SelectionParams,
) -> Result<Selection, WalletError> {
    let mut inputs: Vec<(OutPoint, Coin)> = Vec::new();
    let mut input_total = Amount::ZERO;
    let mut input_bytes: usize = 0;

    for candidate in pool {
        input_total = input_total
            .checked_add(candidate.coin.value)
            .ok_or(WalletError::AmountOverflow("summing selected inputs"))?;
        input_bytes = input_bytes.saturating_add(candidate.input_bytes);
        inputs.push((candidate.out_point, candidate.coin.clone()));

        let size_changeless = params.base_size.saturating_add(input_bytes);
        let fee_changeless = params.fee_rate.fee_for_size(size_changeless)?;
        let Some(surplus) = input_total
            .checked_sub(target)
            .and_then(|remaining| remaining.checked_sub(fee_changeless))
        else {
            continue;
        };

        let size_with_change = size_changeless.saturating_add(params.change_output_size);
        let fee_with_change = params.fee_rate.fee_for_size(size_with_change)?;
        let change = input_total
            .checked_sub(target)
            .and_then(|remaining| remaining.checked_sub(fee_with_change));

        inputs.sort_by(|a, b| a.0.txid.cmp(&b.0.txid).then_with(|| a.0.vout.cmp(&b.0.vout)));

        return match change {
            // A change output that is worth having.
            Some(change) if change >= params.dust_threshold => Ok(Selection {
                inputs,
                input_total,
                fee: fee_with_change,
                change: Some(change),
                size: size_with_change,
                strategy: SelectionStrategy::LargestFirst,
            }),
            // Change would be dust, or would not cover its own output: drop it
            // and give the surplus to the miner. `surplus` is bounded above by
            // `dust_threshold + fee(change_output_size)`, so the amount burned
            // this way is small by construction.
            _ => {
                let fee = fee_changeless
                    .checked_add(surplus)
                    .ok_or(WalletError::AmountOverflow("folding dust into the fee"))?;
                Ok(Selection {
                    inputs,
                    input_total,
                    fee,
                    change: None,
                    size: size_changeless,
                    strategy: SelectionStrategy::LargestFirst,
                })
            }
        };
    }

    // Nothing reached the target. Report what was on the table against what
    // the largest possible selection would have needed.
    let size = params.base_size.saturating_add(input_bytes);
    let required = target
        .checked_add(params.fee_rate.fee_for_size(size)?)
        .unwrap_or(Amount::from_grains(u64::MAX));
    Err(WalletError::insufficient(input_total, required))
}
