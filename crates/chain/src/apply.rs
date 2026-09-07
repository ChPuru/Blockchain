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
//! - **`bits == engine.next_bits(parent)`** (SPEC §3.2 rule 7) needs the
//!   parent's height, which only the header chain knows. The ASERT anchor is
//!   genesis and comes from `ChainParams`, never from the chain, so difficulty
//!   is a pure function of the parent and the parameters (CONTRACT §6.3).
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
use ferrum_script::limits::{
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_MASK, SEQUENCE_LOCKTIME_TYPE_FLAG,
};
use ferrum_script::sighash::SighashCache;
use ferrum_script::{ExecCtx, ScriptLimits, verify};
use ferrum_storage::{OverlayView, StateDiff, StateView, header_hash, txid};
use ferrum_types::{Amount, Block, BlockHash, BlockSeal, ChainParams, Coin, OutPoint};

use crate::ctx::BlockCtx;
use crate::error::ValidationError;
use crate::validate::{
    check_block_sanity, check_coinbase_script_sig, check_coinbase_structure, is_final, total_output,
};

/// Bytes of the block-size budget that buy one signature verification.
///
/// Fifty, which is Bitcoin's `MAX_BLOCK_SIGOPS` ratio: 20 000 checks for a
/// 1 MB block. The number is a *ratio* rather than a constant so that the
/// budget moves with `max_block_size` instead of silently becoming either
/// unreachable or binding when that parameter is retuned.
pub const BLOCK_BYTES_PER_SIG_CHECK: usize = 50;

/// How many signature verifications one block may demand under `params`.
///
/// `MAX_OPS` bounds a single input and `OP_CHECKMULTISIG` charges `1 + n`
/// operations for up to `n` verifications, so one input can ask for roughly
/// 190 of them. The expensive script sits in the `script_pubkey`, which is
/// already in the UTXO set, so the *spending* input can be as small as 44
/// bytes: without this budget there is no proportionality between the block
/// space an attacker pays for and the verification work every node performs.
#[must_use]
pub fn max_block_sig_checks(params: &ChainParams) -> u64 {
    let checks = params.max_block_size.checked_div(BLOCK_BYTES_PER_SIG_CHECK).unwrap_or(0);
    u64::try_from(checks).unwrap_or(u64::MAX)
}

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
/// 6. header: version, parentage, target, proof of work, timestamp above the
///    median
/// 7. seal shape for the active engine
/// 8. every non-coinbase transaction passes §4.2, in block order, against an
///    overlay — so a transaction may spend an output created by an **earlier**
///    transaction in the same block, never by a later one
/// 9. coinbase: `script_sig` is 2..=100 bytes and begins with a minimally
///    encoded push of the height (BIP-34), and its outputs claim no more than
///    `block_subsidy(height) + total_fees`
/// 10. no output this block creates already exists in the UTXO set — read
///     against the pre-state, and last, so a block breaking this rule and the
///     coinbase's value rule is rejected for the value rule
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
    let sig_check_budget = max_block_sig_checks(&ctx.params);
    let mut sig_checks: u64 = 0;

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

        // §4.4 — relative locktime (BIP-68), against the age of each coin.
        for (input_index, (input, coin)) in tx.inputs.iter().zip(coins.iter()).enumerate() {
            check_relative_lock(tx_index, input_index, input.sequence, coin.height, ctx)?;
        }

        // §4.2.3 — scripts, with the spent coin's value and script in scope.
        //
        // One sighash cache per transaction, shared by every input: the
        // prevout, sequence and output digests depend on the transaction and
        // not on which input is being signed, so building it here is what
        // makes validating an `n`-input transaction cost `O(n)` rather than
        // `O(n²)` (CONTRACT §5.5).
        let sighash_cache = SighashCache::new(tx);
        for (input_index, (input, coin)) in tx.inputs.iter().zip(coins.iter()).enumerate() {
            let exec = ExecCtx {
                chain_id: ctx.params.chain_id,
                tx,
                input_index,
                input_value: coin.value,
                // The coin's age, for the BIP-68 half of
                // `OP_CHECKSEQUENCEVERIFY`. The height is known exactly; the
                // median time past of the block that created the coin is not
                // reachable from this seam, so the 512-second flavour fails
                // closed both here and in the interpreter (see
                // `check_relative_lock`).
                input_height: Some(coin.height),
                input_mtp_s: None,
                block_height: ctx.height,
                block_mtp_s: ctx.median_time_past_s,
                sighash_cache: Some(&sighash_cache),
                limits: ScriptLimits::CONSENSUS,
            };
            let stats =
                verify(&input.script_sig, &coin.script_pubkey, &exec).map_err(|source| {
                    ValidationError::ScriptVerification { tx_index, input_index, source }
                })?;

            // Bill the block for the work that input just cost, and stop the
            // moment the budget is passed rather than after validating the
            // rest — the whole point of the rule is not to do the work.
            sig_checks = sig_checks
                .checked_add(u64::from(stats.sig_checks))
                .ok_or(ValidationError::Arithmetic("block signature checks"))?;
            if sig_checks > sig_check_budget {
                return Err(ValidationError::SigCheckBudgetExceeded {
                    used: sig_checks,
                    budget: sig_check_budget,
                });
            }
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
            overlay.add(OutPoint::new(id, index), Coin::new(out.clone(), ctx.height, false));
        }
    }

    // ---- SPEC §3.3 rules 13 and 14: the coinbase ----------------------------
    let created_by_coinbase = check_coinbase(block, ctx, total_fees)?;

    // The diff's `created` must be in `(tx index, vout)` order, and the
    // coinbase is transaction zero — so its outputs go in front of everything
    // the overlay accumulated.
    let mut diff = overlay.into_diff();
    let mut created = created_by_coinbase;
    created.extend(diff.created);
    diff.created = created;

    // ---- SPEC §3.3 rule 15: no created output already exists ----------------
    check_no_created_outpoint_exists(pre, &diff.created)?;

    Ok(diff)
}

/// SPEC §3.3 rule 15 — no output this block creates may already exist **in the
/// UTXO set**.
///
/// Two words in that sentence are load-bearing, and both were wrong when this
/// check lived inside the transaction loop.
///
/// *In the UTXO set*: the comparison is against `pre`, the parent's state, not
/// against the overlay this block has been mutating. `OverlayView::has_coin`
/// answers `false` for anything the block already spent, so an overlay-based
/// check is defeated by spending the colliding coin earlier in the same block
/// — and `Store::connect_block` would then insert the new coin at that
/// outpoint and immediately remove it again, destroying the block's own
/// output. Rule 15 exists as defence in depth on the inflation path, and a
/// backstop that the attack can switch off is not one.
///
/// *Last*: SPEC §3.3 numbers it 15, after the coinbase's value (13) and BIP-34
/// (14), and CONTRACT §8.1 lists it ninth and last. A block that breaks rule 13
/// and rule 15 together must be rejected for rule 13. `created` arrives in
/// `(tx index, vout)` order, so the first collision reported is the earliest.
///
/// Nothing checks `created` against *itself*: two identical outpoints inside
/// one block would need two identical txids, which rule 4 already rejects.
fn check_no_created_outpoint_exists(
    pre: &dyn StateView,
    created: &[(OutPoint, Coin)],
) -> Result<(), ValidationError> {
    for (out_point, _) in created {
        if pre.has_coin(out_point).map_err(|e| ValidationError::view(&e))? {
            return Err(ValidationError::DuplicateOutPoint { out_point: *out_point });
        }
    }
    Ok(())
}

/// SPEC §4.4 — the chain half of BIP-68, for one resolved input.
///
/// `OP_CHECKSEQUENCEVERIFY` compares its operand against
/// `tx.inputs[i].sequence`, and nothing else. That field is written by the
/// spender, so on its own it proves nothing: the script half of BIP-112 is a
/// timelock only because this rule separately requires the spent coin to be
/// old enough for the `sequence` it is spent with. Without it, a
/// `<n> OP_CHECKSEQUENCEVERIFY OP_DROP …` output is spendable the block after
/// it is created by anyone who can satisfy the rest of the script.
///
/// The boundary is `spend_height >= coin_height + n`, i.e. a lock of `n`
/// blocks requires the coin to be at least `n` blocks deep, and `n == 0` locks
/// nothing. A coin created by an earlier transaction in *this* block has
/// `coin.height == ctx.height`, so any `n >= 1` rejects it, which is correct.
///
/// # The 512-second flavour
///
/// Bit 22 selects a relative lock counted in 512-second units. Evaluating it
/// needs the median time past of the block that *created* the coin;
/// [`BlockCtx`] carries only the parent's median and [`Coin`] carries only a
/// height, so the seam cannot compute it. An unenforceable timelock must fail
/// closed — accepting the input would mean the lock silently is not a lock —
/// so such an input is rejected outright. Lifting that needs the creating
/// block's median in `BlockCtx`; see SPEC §4.4.
fn check_relative_lock(
    tx_index: usize,
    input_index: usize,
    sequence: u32,
    coin_height: u64,
    ctx: &BlockCtx,
) -> Result<(), ValidationError> {
    // Bit 31: this input opts out of relative locktime entirely. `u32::MAX`
    // and the wallet's `0xffff_fffe` both land here.
    if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
        return Ok(());
    }
    if sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
        return Err(ValidationError::UnsupportedRelativeTimeLock {
            tx_index,
            input_index,
            sequence,
        });
    }
    let required = sequence & SEQUENCE_LOCKTIME_MASK;
    let spendable_at = coin_height
        .checked_add(u64::from(required))
        .ok_or(ValidationError::Arithmetic("relative locktime height"))?;
    if ctx.height < spendable_at {
        return Err(ValidationError::UnsatisfiedRelativeLock {
            tx_index,
            input_index,
            sequence,
            required,
            coin_height,
            spend_height: ctx.height,
        });
    }
    Ok(())
}

/// SPEC §3.2 — the header rules that are computable without the header chain.
///
/// The order is normative and is SPEC §3.2's own: version, parentage, then
/// rule 7's target, then rule 8's proof of work, then rule 9's median-time-past
/// bound. A block that breaks two of them at once is rejected for the *first*,
/// and SPEC §3.4 makes that variant observable — so this order is what
/// `PowEngine::validate_header`, CONTRACT §8.1 rule 5 and the reference
/// executor also use.
///
/// Genesis is exempt from proof-of-work validation against a parent it does
/// not have, from the difficulty transition, and from the median-time-past
/// bound (SPEC §2). It is *not* exempt from the version rule, which is why
/// that one is read before the exemption.
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

    // Rules 7 and 8. `bits` is a hashed header field that every node must
    // agree on, so it is expanded and range-checked at *every* height under
    // *every* engine: a target that does not expand, is zero, or is easier
    // than `pow_limit` is malformed whoever sealed the block. Only the hash
    // comparison is proof of work's own business (SPEC §3.2 rule 8, "PoW
    // engine only").
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
    if ctx.engine_id == BlockSeal::ENGINE_POW {
        let hash = header_hash(header);
        if !hash_meets_target(&hash, target) {
            return Err(ValidationError::Header(ConsensusError::InsufficientWork { hash, target }));
        }
    }

    // Rule 9, and it comes *after* the work rules: SPEC §3.2 numbers it 9,
    // CONTRACT §8.1 rule 5 lists it last of the three, `PowEngine::validate_header`
    // checks it last and so does the reference executor. A block that breaks
    // both must be rejected for the same reason by all four.
    //
    // Strictly greater: equality is rejected, which is what stops a miner from
    // freezing the clock across a whole median window.
    let median_time_past_ms = ctx.median_time_past_ms();
    if header.timestamp_ms <= median_time_past_ms {
        return Err(ValidationError::Header(ConsensusError::TimestampTooOld {
            timestamp_ms: header.timestamp_ms,
            median_time_past_ms,
        }));
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

/// SPEC §3.3 rules 13 and 14.
///
/// Returns the coins the coinbase creates, in `vout` order. They are *not*
/// added to the overlay: SPEC §3.3 rule 12 says the coinbase's outputs are
/// outside the overlay its own block is validated against, so a transaction
/// naming one of them is rejected with `MissingInput` at every
/// `coinbase_maturity`. Rule 15 is applied to them by the caller, together
/// with every other created outpoint and after this function's value rule.
fn check_coinbase(
    block: &Block,
    ctx: &BlockCtx,
    total_fees: Amount,
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
        created.push((OutPoint::new(id, index), Coin::new(out.clone(), ctx.height, true)));
    }
    Ok(created)
}
