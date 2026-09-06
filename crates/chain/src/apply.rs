//! [`apply_block`] — the determinism seam.
//!
//! # The one rule this file exists to hold
//!
//! **`apply_block` is a pure function of `(pre, block, ctx)`.** Given the same
//! pre-state, the same block and the same context it returns the same result
//! on every machine, every architecture and every optimisation level, forever.
//!
//! Forbidden inside it, and grepped for by `scripts/check-invariants.sh`: the
//! wall clock, the monotonic clock, randomness, floats, `HashMap`/`HashSet`
//! iteration, I/O, and anything whose result depends on thread scheduling or
//! address-space layout. The only mutable state is an [`OverlayView`], which is
//! a `BTreeMap` and two ordered vectors.
//!
//! The one clock-dependent rule in the protocol — the two-hour future-time
//! bound of SPEC §3.2 rule 10 — lives in the node as
//! [`ferrum_consensus::check_future_time`]. Re-validating block 400 must never
//! depend on when you re-validate it.
//!
//! # What this function does *not* check
//!
//! Two rules need the header chain, which the seam deliberately cannot see:
//!
//! - **`bits == engine.next_bits(parent)`** (SPEC §3.2 rule 7) needs the ASERT
//!   anchor, which lives at height 1 of the active chain.
//! - **BFT seal verification** (rule 11) needs the validator set active at this
//!   height and a `2f+1` count over the header chain.
//!
//! [`crate::ChainManager`] performs both through
//! [`ferrum_consensus::ConsensusEngine`] *before* calling `apply_block`, so a
//! block that reaches the store has had every rule applied. `apply_block`
//! still re-checks every rule it *can* see — version, parentage, proof of work,
//! the timestamp lower bound, the seal shape — so that it is a complete and
//! self-contained verdict for the differential harness and for any caller that
//! holds only a pre-state.

use ferrum_consensus::{
    ConsensusError, MIN_BLOCK_VERSION, Target, compact_to_target, hash_meets_target,
};
use ferrum_script::{ExecCtx, ScriptLimits, verify};
use ferrum_storage::{OverlayView, StateDiff, StateView, header_hash, txid};
use ferrum_types::{Amount, Block, BlockHash, BlockSeal, Coin, OutPoint};

use crate::ctx::BlockCtx;
use crate::error::ValidationError;
use crate::validate::{
    check_block_sanity, check_coinbase_script_sig, check_coinbase_structure, is_final, total_output,
};

/// Validate `block` against `pre` and return the change it makes to the UTXO
/// set.
///
/// The rules are applied in the order SPEC §3 gives, which is normative: an
/// implementation that checks them in a different order can accept a block
/// another node rejects whenever a block breaks two rules at once.
///
/// 1. `serialized_size <= max_block_size`
/// 2. non-empty, `txs[0]` is the only coinbase
/// 3. merkle root matches
/// 4. no duplicate txid
/// 5. every transaction passes §4.1 sanity
/// 6. header: version, parentage, timestamp above the median, proof of work
/// 7. seal shape for the active engine
/// 8. every non-coinbase transaction passes §4.2, in block order, against an
///    overlay — so a transaction may spend an output created by an **earlier**
///    transaction in the same block, never by a later one
/// 9. coinbase: `script_sig` is 2..=100 bytes and begins with a minimally
///    encoded push of the height (BIP-34), and its outputs claim no more than
///    `block_subsidy(height) + total_fees`
/// 10. no output this block creates already exists in the UTXO set
///
/// # Errors
///
/// One [`ValidationError`] variant per rule, so a test can assert the exact
/// reason rather than merely that validation failed.
pub fn apply_block(
    pre: &dyn StateView,
    block: &Block,
    ctx: &BlockCtx,
) -> Result<StateDiff, ValidationError> {
    // ---- SPEC §3.1: rules 1 to 5, context-free ------------------------------
    check_block_sanity(block, &ctx.params)?;

    // ---- SPEC §3.2: the header rules that need no header chain ---------------
    check_header(block, ctx)?;

    // ---- SPEC §3.2 rule 11: the seal's shape ---------------------------------
    check_seal_shape(block, ctx)?;

    // ---- SPEC §3.3 rule 12: contextual transaction validation ----------------
    let mut overlay = OverlayView::new(pre);
    let mut total_fees = Amount::ZERO;

    for (tx_index, tx) in block.txs.iter().enumerate().skip(1) {
        // §4.2.1 — resolve every input against the overlay. A coin spent by an
        // earlier transaction in this same block reads back as absent, so a
        // double spend inside one block lands here, on the second spender.
        let mut coins: Vec<Coin> = Vec::with_capacity(tx.inputs.len());
        let mut inputs_total = Amount::ZERO;
        for input in &tx.inputs {
            let coin = overlay
                .get_coin(&input.prev_out)
                .map_err(|e| ValidationError::view(&e))?
                .ok_or(ValidationError::MissingInput { tx_index, out_point: input.prev_out })?;

            // §4.2.2 — coinbase maturity. Spending a coinbase too early is
            // invalid, not deferred: a block is judged at the height it claims.
            if coin.is_coinbase {
                let mature_at = coin
                    .height
                    .checked_add(ctx.params.coinbase_maturity)
                    .ok_or(ValidationError::Arithmetic("coinbase maturity height"))?;
                if ctx.height < mature_at {
                    return Err(ValidationError::ImmatureCoinbaseSpend {
                        tx_index,
                        out_point: input.prev_out,
                        coin_height: coin.height,
                        spend_height: ctx.height,
                        maturity: ctx.params.coinbase_maturity,
                    });
                }
            }

            // §4.2.5 — the input sum must not overflow and must stay money.
            inputs_total = inputs_total
                .checked_add(coin.value)
                .ok_or(ValidationError::InputSumOverflow { tx_index })?;
            if !inputs_total.is_valid_money() {
                return Err(ValidationError::InputSumOverflow { tx_index });
            }
            coins.push(coin);
        }

        // §4.2.6 — sum(inputs) >= sum(outputs). The difference is the fee.
        let outputs_total = total_output(tx)?;
        if inputs_total < outputs_total {
            return Err(ValidationError::InsufficientInputValue {
                tx_index,
                inputs: inputs_total,
                outputs: outputs_total,
            });
        }
        let fee = inputs_total
            .checked_sub(outputs_total)
            .ok_or(ValidationError::Arithmetic("transaction fee"))?;

        // §4.2.7 — the block's fees accumulate without overflow.
        total_fees = total_fees.checked_add(fee).ok_or(ValidationError::FeeOverflow)?;
        if !total_fees.is_valid_money() {
            return Err(ValidationError::FeeOverflow);
        }

        // §4.3 — finality, against the height and the median time past.
        if !is_final(tx, ctx.height, ctx.median_time_past_s) {
            return Err(ValidationError::NonFinalTransaction { tx_index, lock_time: tx.lock_time });
        }

        // §4.2.3 — scripts, with the spent coin's value and script in scope.
        for (input_index, (input, coin)) in tx.inputs.iter().zip(coins.iter()).enumerate() {
            let exec = ExecCtx {
                chain_id: ctx.params.chain_id,
                tx,
                input_index,
                input_value: coin.value,
                block_height: ctx.height,
                block_mtp_s: ctx.median_time_past_s,
                limits: ScriptLimits::CONSENSUS,
            };
            verify(&input.script_sig, &coin.script_pubkey, &exec).map_err(|source| {
                ValidationError::ScriptVerification { tx_index, input_index, source }
            })?;
        }

        // §4.2.4 — mark spent, then publish this transaction's outputs, so the
        // next transaction in the block can spend them and no earlier one can.
        for input in &tx.inputs {
            overlay
                .spend(&input.prev_out)
                .map_err(|e| ValidationError::view(&e))?
                .ok_or(ValidationError::MissingInput { tx_index, out_point: input.prev_out })?;
        }
        let id = txid(tx);
        for (vout, out) in tx.outputs.iter().enumerate() {
            let index =
                u32::try_from(vout).map_err(|_| ValidationError::Arithmetic("output index"))?;
            let out_point = OutPoint::new(id, index);
            // §3.3 rule 15 — no created output may already exist.
            if overlay.has_coin(&out_point).map_err(|e| ValidationError::view(&e))? {
                return Err(ValidationError::DuplicateOutPoint { out_point });
            }
            overlay.add(out_point, Coin::new(out.clone(), ctx.height, false));
        }
    }

    // ---- SPEC §3.3 rules 13 and 14: the coinbase ----------------------------
    let created_by_coinbase = check_coinbase(block, ctx, total_fees, &overlay)?;

    // The diff's `created` must be in `(tx index, vout)` order, and the
    // coinbase is transaction zero — so its outputs go in front of everything
    // the overlay accumulated.
    let mut diff = overlay.into_diff();
    let mut created = created_by_coinbase;
    created.extend(diff.created);
    diff.created = created;
    Ok(diff)
}

/// SPEC §3.2 — the header rules that are computable without the header chain.
///
/// Genesis is exempt from proof-of-work validation against a parent it does
/// not have, from the difficulty transition, and from the median-time-past
/// bound (SPEC §2). It is *not* exempt from having a zero `prev_hash`.
fn check_header(block: &Block, ctx: &BlockCtx) -> Result<(), ValidationError> {
    let header = &block.header;

    if header.version < MIN_BLOCK_VERSION {
        return Err(ValidationError::Header(ConsensusError::BadVersion(header.version)));
    }

    if ctx.is_genesis() {
        if header.prev_hash != BlockHash::ZERO {
            return Err(ValidationError::Header(ConsensusError::WrongParent {
                expected: BlockHash::ZERO,
                actual: header.prev_hash,
            }));
        }
        return Ok(());
    }

    let expected_parent = header_hash(&ctx.prev_header);
    if header.prev_hash != expected_parent {
        return Err(ValidationError::Header(ConsensusError::WrongParent {
            expected: expected_parent,
            actual: header.prev_hash,
        }));
    }

    // Strictly greater: equality is rejected, which is what stops a miner from
    // freezing the clock across a whole median window.
    let median_time_past_ms = ctx.median_time_past_ms();
    if header.timestamp_ms <= median_time_past_ms {
        return Err(ValidationError::Header(ConsensusError::TimestampTooOld {
            timestamp_ms: header.timestamp_ms,
            median_time_past_ms,
        }));
    }

    if ctx.engine_id == BlockSeal::ENGINE_POW {
        let target = compact_to_target(header.bits).map_err(ValidationError::Header)?;
        if target.is_zero() {
            return Err(ValidationError::Header(ConsensusError::ZeroTarget));
        }
        let limit = Target::from_be_bytes(&ctx.params.pow_limit);
        if target > limit {
            return Err(ValidationError::Header(ConsensusError::TargetAbovePowLimit {
                actual: target,
                limit,
            }));
        }
        let hash = header_hash(header);
        if !hash_meets_target(&hash, target) {
            return Err(ValidationError::Header(ConsensusError::InsufficientWork { hash, target }));
        }
    }

    Ok(())
}

/// SPEC §3.2 rule 11 — the seal's shape.
///
/// The engine-specific *content* of a BFT seal is checked by
/// [`ferrum_consensus::ConsensusEngine::validate_seal`] in
/// [`crate::ChainManager`]: counting `2f+1` signatures needs the validator set
/// active at this height, which the pure seam cannot reach.
fn check_seal_shape(block: &Block, ctx: &BlockCtx) -> Result<(), ValidationError> {
    if block.seal.engine != ctx.engine_id {
        return Err(ValidationError::Seal(ConsensusError::WrongEngine {
            expected: ctx.engine_id,
            actual: block.seal.engine,
        }));
    }
    if ctx.engine_id == BlockSeal::ENGINE_POW && !block.seal.data.is_empty() {
        // The nonce in the header is the whole proof of work. A payload here
        // would be a field the block hash does not commit to, which is free
        // malleability.
        return Err(ValidationError::Seal(ConsensusError::NonEmptyPowSeal(block.seal.data.len())));
    }
    Ok(())
}

/// SPEC §3.3 rules 13 and 14, plus rule 15 for the coinbase's own outputs.
///
/// Returns the coins the coinbase creates, in `vout` order. They are *not*
/// added to the overlay: a coinbase output is unspendable for
/// `coinbase_maturity` blocks, so nothing later in this block could legally
/// reach it.
fn check_coinbase(
    block: &Block,
    ctx: &BlockCtx,
    total_fees: Amount,
    overlay: &OverlayView<'_>,
) -> Result<Vec<(OutPoint, Coin)>, ValidationError> {
    let coinbase = block.txs.first().ok_or(ValidationError::EmptyBlock)?;
    check_coinbase_structure(coinbase)?;

    let input = coinbase.inputs.first().ok_or(ValidationError::CoinbaseInputCount { count: 0 })?;
    check_coinbase_script_sig(&input.script_sig, ctx.height)?;

    let subsidy = ctx.params.block_subsidy(ctx.height);
    let allowed =
        subsidy.checked_add(total_fees).ok_or(ValidationError::CoinbaseAllowanceOverflow)?;
    if !allowed.is_valid_money() {
        return Err(ValidationError::CoinbaseAllowanceOverflow);
    }
    let claimed = total_output(coinbase)?;
    if claimed > allowed {
        // A miner may claim *less* than it is owed; the difference is burned.
        // Claiming one grain more is an inflation bug, and is rejected.
        return Err(ValidationError::CoinbaseOverpayment { claimed, allowed });
    }

    let id = txid(coinbase);
    let mut created = Vec::with_capacity(coinbase.outputs.len());
    for (vout, out) in coinbase.outputs.iter().enumerate() {
        let index = u32::try_from(vout).map_err(|_| ValidationError::Arithmetic("output index"))?;
        let out_point = OutPoint::new(id, index);
        if overlay.has_coin(&out_point).map_err(|e| ValidationError::view(&e))? {
            return Err(ValidationError::DuplicateOutPoint { out_point });
        }
        created.push((out_point, Coin::new(out.clone(), ctx.height, true)));
    }
    Ok(created)
}
