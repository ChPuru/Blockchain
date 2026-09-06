//! A second, deliberately naive implementation of the state transition.
//!
//! **This module was written from [`docs/SPEC.md`] alone.** It is the
//! project's substitute for an audit (CONTRACT §14): two implementations that
//! share an author still catch a misreading of the specification, and one does
//! not. Copying `crates/chain/src/apply.rs` here would make the differential
//! test in `tests/differential.rs` prove nothing at all, so the rules below are
//! written out longhand from the prose, in the order the prose gives them, with
//! a comment naming the rule each block of code implements.
//!
//! It is naive on purpose:
//!
//! * every lookup goes to the backing [`StateView`]; there is no cache and no
//!   short-circuit, so a caching bug in the production overlay cannot be
//!   mirrored here;
//! * the working set is a [`BTreeMap`], never a `HashMap`, so iteration order
//!   is part of the type rather than part of the run;
//! * the Merkle reduction, the txid, the `ScriptNum` height encoding and the
//!   minimal-push decoder are all re-derived here rather than imported from
//!   `ferrum-chain`.
//!
//! What it deliberately *does* share with production is the type vocabulary —
//! [`ValidationError`], [`StateDiff`], [`ferrum_script::verify`] — because the
//! differential test asserts the exact error variant, and a parallel error
//! enum would only test the translation between the two.
//!
//! # Rule ordering
//!
//! SPEC §3 fixes the order block rules are checked in, and §3.4 requires that
//! tests assert the exact variant, so ordering is observable behaviour, not an
//! implementation detail. Two places in the documents leave an order
//! under-determined, and each is resolved here with a comment:
//!
//! 1. Within one transaction, CONTRACT §8.1 rule 7 gives an explicit ordered
//!    list (resolve, maturity, value, finality, scripts, commit) while SPEC
//!    §4.2 describes a per-input loop. They differ only for a transaction that
//!    breaks two rules at once; the CONTRACT list is followed because it is
//!    the only fully ordered statement of the per-transaction rules.
//! 2. For the coinbase, SPEC §3.3 lists the value rule before the BIP-34
//!    `script_sig` rule while CONTRACT §8.1 rule 8 states them the other way
//!    round. The CONTRACT order is followed: it checks the cheap structural
//!    rule before the one that needs every fee in the block.
//!
//! [`docs/SPEC.md`]: https://github.com/rahuldhali/ferrum/blob/main/docs/SPEC.md

use std::collections::{BTreeMap, BTreeSet};

use ferrum_chain::{BlockCtx, ValidationError};
use ferrum_consensus::{
    ConsensusError, MIN_BLOCK_VERSION, Target, compact_to_target, hash_meets_target,
};
use ferrum_script::{ExecCtx, MAX_SCRIPT_SIZE, ScriptLimits};
use ferrum_storage::{StateDiff, StateView};
use ferrum_types::{
    Amount, Block, BlockHash, BlockSeal, Coin, OutPoint, Script, Transaction, Txid,
};

mod primitives;

pub use crate::reference::primitives::{
    reference_block_hash, reference_height_push, reference_is_final, reference_leading_push,
    reference_merkle_root, reference_script_num, reference_txid,
};

/// The inclusive minimum length of a coinbase `script_sig` (SPEC §3.3 rule 14).
pub const COINBASE_SCRIPT_SIG_MIN: usize = 2;
/// The inclusive maximum length of a coinbase `script_sig` (SPEC §3.3 rule 14).
pub const COINBASE_SCRIPT_SIG_MAX: usize = 100;

// ---------------------------------------------------------------------------
// The naive working set
// ---------------------------------------------------------------------------

/// The block's scratch state: a `BTreeMap` of overrides over a backing view.
///
/// `Some(coin)` is a coin this block created, `None` a coin it spent. There is
/// no read cache: an outpoint the block has not touched is fetched from the
/// base view every single time it is named.
struct NaiveState<'a> {
    base: &'a dyn StateView,
    changes: BTreeMap<OutPoint, Option<Coin>>,
}

impl<'a> NaiveState<'a> {
    fn new(base: &'a dyn StateView) -> Self {
        NaiveState { base, changes: BTreeMap::new() }
    }

    fn get(&self, op: &OutPoint) -> Result<Option<Coin>, ValidationError> {
        match self.changes.get(op) {
            Some(Some(coin)) => Ok(Some(coin.clone())),
            Some(None) => Ok(None),
            None => {
                self.base.get_coin(op).map_err(|e| ValidationError::View { detail: e.to_string() })
            }
        }
    }

    fn spend(&mut self, op: OutPoint) {
        self.changes.insert(op, None);
    }

    fn create(&mut self, op: OutPoint, coin: Coin) {
        self.changes.insert(op, Some(coin));
    }
}

// ---------------------------------------------------------------------------
// SPEC §4.1 — transaction sanity, context-free
// ---------------------------------------------------------------------------

/// SPEC §4.1, in the order the specification lists the bullets.
pub fn reference_check_transaction_sanity(tx: &Transaction) -> Result<(), ValidationError> {
    if tx.inputs.is_empty() {
        return Err(ValidationError::NoInputs);
    }
    if tx.outputs.is_empty() {
        return Err(ValidationError::NoOutputs);
    }
    for out in &tx.outputs {
        if !out.value.is_valid_money() {
            return Err(ValidationError::OutputValueOutOfRange { value: out.value });
        }
    }
    // `total_output` is `None` on either a `u64` overflow or a sum above
    // MAX_MONEY; both are the same verdict.
    if tx.total_output().is_none() {
        return Err(ValidationError::OutputSumOverflow);
    }
    let mut seen: BTreeSet<OutPoint> = BTreeSet::new();
    for input in &tx.inputs {
        if !seen.insert(input.prev_out) {
            return Err(ValidationError::DuplicateInput { out_point: input.prev_out });
        }
    }
    for input in &tx.inputs {
        if input.script_sig.len() > MAX_SCRIPT_SIZE {
            return Err(ValidationError::ScriptTooLarge {
                len: input.script_sig.len(),
                max: MAX_SCRIPT_SIZE,
            });
        }
    }
    for out in &tx.outputs {
        if out.script_pubkey.len() > MAX_SCRIPT_SIZE {
            return Err(ValidationError::ScriptTooLarge {
                len: out.script_pubkey.len(),
                max: MAX_SCRIPT_SIZE,
            });
        }
    }
    if tx.is_coinbase() {
        // `is_coinbase` already means "one input and it is null", so these two
        // are unreachable through it. They are written out anyway because the
        // rule is stated in the specification and a future change to
        // `is_coinbase` must not silently delete a consensus rule.
        if tx.inputs.len() != 1 {
            return Err(ValidationError::CoinbaseInputCount { count: tx.inputs.len() });
        }
        if !tx.inputs.first().is_some_and(|i| i.prev_out.is_null()) {
            return Err(ValidationError::CoinbaseInputNotNull);
        }
    } else {
        for (i, input) in tx.inputs.iter().enumerate() {
            if input.prev_out.is_null() {
                return Err(ValidationError::NullInput { input_index: i });
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SPEC §3.2 — the header rules that need no view
// ---------------------------------------------------------------------------

/// The pure half of SPEC §3.2: version, parentage, target, proof of work and
/// the timestamp lower bound.
///
/// Rule 7 (`bits == next_bits(parent)`) needs the header chain and rule 10 (the
/// two-hour future bound) needs a clock, so neither belongs inside the
/// state-transition seam; both are applied by the caller.
fn reference_check_header(block: &Block, ctx: &BlockCtx) -> Result<(), ValidationError> {
    let header = &block.header;

    // SPEC §2: genesis has no parent, so it is exempt from the proof-of-work
    // comparison against one, from the difficulty transition and from median
    // time past. What it is not exempt from is having a null parent.
    if ctx.is_genesis() {
        if header.prev_hash != BlockHash::ZERO {
            return Err(ValidationError::Header(ConsensusError::WrongParent {
                expected: BlockHash::ZERO,
                actual: header.prev_hash,
            }));
        }
        return Ok(());
    }

    if header.version < MIN_BLOCK_VERSION {
        return Err(ValidationError::Header(ConsensusError::BadVersion(header.version)));
    }

    let parent_hash = reference_block_hash(&ctx.prev_header);
    if header.prev_hash != parent_hash {
        return Err(ValidationError::Header(ConsensusError::WrongParent {
            expected: parent_hash,
            actual: header.prev_hash,
        }));
    }

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

    // SPEC §9: only the proof-of-work engine spends work on the header hash.
    // Under BFT the seal, not the nonce, is the proof.
    if ctx.engine_id == BlockSeal::ENGINE_POW {
        let hash = reference_block_hash(header);
        if !hash_meets_target(&hash, target) {
            return Err(ValidationError::Header(ConsensusError::InsufficientWork { hash, target }));
        }
    }

    // SPEC §3.2 rule 9: strictly greater. Equality is rejected so that a miner
    // cannot freeze the clock across a whole median window.
    let median_time_past_ms = ctx.median_time_past_ms();
    if header.timestamp_ms <= median_time_past_ms {
        return Err(ValidationError::Header(ConsensusError::TimestampTooOld {
            timestamp_ms: header.timestamp_ms,
            median_time_past_ms,
        }));
    }

    Ok(())
}

/// SPEC §3.2 rule 11, for the engine that is active at this height.
fn reference_check_seal(block: &Block, ctx: &BlockCtx) -> Result<(), ValidationError> {
    if block.seal.engine != ctx.engine_id {
        return Err(ValidationError::Seal(ConsensusError::WrongEngine {
            expected: ctx.engine_id,
            actual: block.seal.engine,
        }));
    }
    if ctx.engine_id == BlockSeal::ENGINE_POW && !block.seal.data.is_empty() {
        // The nonce is the whole proof; a payload here is a field the block
        // hash does not commit to, i.e. free malleability.
        return Err(ValidationError::Seal(ConsensusError::NonEmptyPowSeal(block.seal.data.len())));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SPEC §3.3 rule 14 — BIP-34
// ---------------------------------------------------------------------------

/// The coinbase `script_sig` must be 2..=100 bytes and begin with a minimally
/// encoded push of this block's height.
///
/// Without the height commitment, two blocks can carry identical coinbase
/// transactions, hence identical txids, and the second overwrites the first's
/// UTXO entry. That destroyed coins twice on Bitcoin mainnet
/// (CVE-2012-1909 / BIP-30).
pub fn reference_check_coinbase_script_sig(
    script_sig: &Script,
    height: u64,
) -> Result<(), ValidationError> {
    let len = script_sig.len();
    if !(COINBASE_SCRIPT_SIG_MIN..=COINBASE_SCRIPT_SIG_MAX).contains(&len) {
        return Err(ValidationError::CoinbaseScriptSigLength {
            len,
            min: COINBASE_SCRIPT_SIG_MIN,
            max: COINBASE_SCRIPT_SIG_MAX,
        });
    }
    let Some(found) = reference_leading_push(script_sig) else {
        return Err(ValidationError::CoinbaseMissingHeightPush);
    };
    if found != reference_height_push(height) {
        return Err(ValidationError::CoinbaseHeightMismatch { expected: height, found });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

/// The reference state transition: a pure function of `(pre, block, ctx)`.
///
/// Mirrors [`ferrum_chain::apply_block`] in signature and in verdict, and is
/// differentially tested against it on every block the chain builder produces
/// (`tests/differential.rs`).
///
/// # Errors
///
/// One [`ValidationError`] variant per rule of SPEC §3 and §4, so a test can
/// assert *why* a block was rejected rather than merely that it was.
pub fn apply_block_reference(
    pre: &dyn StateView,
    block: &Block,
    ctx: &BlockCtx,
) -> Result<StateDiff, ValidationError> {
    // ================= SPEC §3.1 — context-free =================

    // Rule 1.
    let size = block.serialized_size();
    if size > ctx.params.max_block_size {
        return Err(ValidationError::BlockTooLarge { size, max: ctx.params.max_block_size });
    }

    // Rule 2.
    let Some(coinbase) = block.txs.first() else {
        return Err(ValidationError::EmptyBlock);
    };
    if !coinbase.is_coinbase() {
        return Err(ValidationError::MissingCoinbase);
    }
    for (i, tx) in block.txs.iter().enumerate().skip(1) {
        if tx.is_coinbase() {
            return Err(ValidationError::MultipleCoinbases { tx_index: i });
        }
    }

    // Rule 3.
    let computed_root = reference_merkle_root(&block.txs);
    if computed_root != block.header.merkle_root {
        return Err(ValidationError::MerkleRootMismatch {
            expected: computed_root,
            actual: block.header.merkle_root,
        });
    }

    // Rule 4.
    let mut txids: Vec<Txid> = Vec::with_capacity(block.txs.len());
    let mut seen_txids: BTreeSet<Txid> = BTreeSet::new();
    for tx in &block.txs {
        let id = reference_txid(tx);
        if !seen_txids.insert(id) {
            return Err(ValidationError::DuplicateTransaction { txid: id });
        }
        txids.push(id);
    }

    // Rule 5.
    for tx in &block.txs {
        reference_check_transaction_sanity(tx)?;
    }

    // ================= SPEC §3.2 — header context =================
    reference_check_header(block, ctx)?;
    reference_check_seal(block, ctx)?;

    // ================= SPEC §3.3 — state context =================
    let mut state = NaiveState::new(pre);
    let mut spent: Vec<(OutPoint, Coin)> = Vec::new();
    let mut created: Vec<(OutPoint, Coin)> = Vec::new();

    // The coinbase's outputs come first so that `created` is in
    // (transaction index, vout) order, which is what `StateDiff` promises.
    let coinbase_id = *txids.first().ok_or(ValidationError::EmptyBlock)?;
    for (vout, out) in coinbase.outputs.iter().enumerate() {
        let op = OutPoint::new(coinbase_id, u32::try_from(vout).unwrap_or(u32::MAX));
        let coin = Coin {
            value: out.value,
            script_pubkey: out.script_pubkey.clone(),
            height: ctx.height,
            is_coinbase: true,
        };
        state.create(op, coin.clone());
        created.push((op, coin));
    }

    // Rule 12: every non-coinbase transaction, in block order, against an
    // overlay of the parent's UTXO set. A transaction may spend an output
    // created by an earlier transaction in the same block but never by a
    // later one, because the overlay only learns about an output once that
    // transaction has been committed to it.
    let mut total_fees = Amount::ZERO;
    for (tx_index, tx) in block.txs.iter().enumerate().skip(1) {
        // §4.2 step 1 — resolve.
        let mut resolved: Vec<(OutPoint, Coin)> = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            let Some(coin) = state.get(&input.prev_out)? else {
                return Err(ValidationError::MissingInput { tx_index, out_point: input.prev_out });
            };
            resolved.push((input.prev_out, coin));
        }

        // §4.2 step 2 — coinbase maturity.
        for (op, coin) in &resolved {
            if coin.is_coinbase {
                let matures_at = coin.height.saturating_add(ctx.params.coinbase_maturity);
                if ctx.height < matures_at {
                    return Err(ValidationError::ImmatureCoinbaseSpend {
                        tx_index,
                        out_point: *op,
                        coin_height: coin.height,
                        spend_height: ctx.height,
                        maturity: ctx.params.coinbase_maturity,
                    });
                }
            }
        }

        // §4.2 steps 5 and 6 — the money rules.
        let mut input_sum = Amount::ZERO;
        for (_, coin) in &resolved {
            input_sum = match input_sum.checked_add(coin.value) {
                Some(v) if v.is_valid_money() => v,
                _ => return Err(ValidationError::InputSumOverflow { tx_index }),
            };
        }
        // Sanity already proved this is `Some`; the fallback keeps the
        // function total without an unwrap.
        let output_sum = tx.total_output().ok_or(ValidationError::OutputSumOverflow)?;
        if input_sum < output_sum {
            return Err(ValidationError::InsufficientInputValue {
                tx_index,
                inputs: input_sum,
                outputs: output_sum,
            });
        }
        let fee = input_sum
            .checked_sub(output_sum)
            .ok_or(ValidationError::Arithmetic("transaction fee"))?;
        // §4.2 step 7 — the block's fees accumulate without overflow.
        total_fees = match total_fees.checked_add(fee) {
            Some(v) if v.is_valid_money() => v,
            _ => return Err(ValidationError::FeeOverflow),
        };

        // §4.3 — finality, against median time past rather than the block's
        // own timestamp: a miner controls its own timestamp within a two-hour
        // window but cannot move the median of the last eleven blocks.
        if !reference_is_final(tx, ctx.height, ctx.median_time_past_s) {
            return Err(ValidationError::NonFinalTransaction { tx_index, lock_time: tx.lock_time });
        }

        // §4.2 step 3 — scripts.
        for (input_index, input) in tx.inputs.iter().enumerate() {
            let coin = resolved
                .get(input_index)
                .map(|(_, c)| c)
                .ok_or(ValidationError::Arithmetic("resolved input index"))?;
            let exec = ExecCtx {
                chain_id: ctx.params.chain_id,
                tx,
                input_index,
                input_value: coin.value,
                block_height: ctx.height,
                block_mtp_s: ctx.median_time_past_s,
                limits: ScriptLimits::CONSENSUS,
            };
            ferrum_script::verify(&input.script_sig, &coin.script_pubkey, &exec).map_err(
                |source| ValidationError::ScriptVerification { tx_index, input_index, source },
            )?;
        }

        // §4.2 step 4 — commit: mark every input spent, then create the
        // outputs, so a later transaction in the same block sees both.
        for (op, coin) in resolved {
            state.spend(op);
            spent.push((op, coin));
        }
        let txid = *txids.get(tx_index).ok_or(ValidationError::Arithmetic("txid index"))?;
        for (vout, out) in tx.outputs.iter().enumerate() {
            let op = OutPoint::new(txid, u32::try_from(vout).unwrap_or(u32::MAX));
            let coin = Coin {
                value: out.value,
                script_pubkey: out.script_pubkey.clone(),
                height: ctx.height,
                is_coinbase: false,
            };
            state.create(op, coin.clone());
            created.push((op, coin));
        }
    }

    // Rule 14 — BIP-34. The structural rule is checked before the value rule
    // because it is the cheaper of the two (CONTRACT §8.1 rule 8).
    let coinbase_script_sig = coinbase
        .inputs
        .first()
        .map(|i| &i.script_sig)
        .ok_or(ValidationError::CoinbaseInputCount { count: 0 })?;
    reference_check_coinbase_script_sig(coinbase_script_sig, ctx.height)?;

    // Rule 13 — the coinbase may claim the subsidy plus every fee, and no
    // more. Claiming less is legal: the difference is burned.
    let subsidy = ctx.params.block_subsidy(ctx.height);
    let allowed = match subsidy.checked_add(total_fees) {
        Some(v) if v.is_valid_money() => v,
        _ => return Err(ValidationError::CoinbaseAllowanceOverflow),
    };
    let claimed = coinbase.total_output().ok_or(ValidationError::OutputSumOverflow)?;
    if claimed > allowed {
        return Err(ValidationError::CoinbaseOverpayment { claimed, allowed });
    }

    // Rule 15 — no created output may already exist in the UTXO set. Checked
    // against the *pre*-state, since everything in `created` is by definition
    // in the overlay by now.
    for (op, _) in &created {
        let exists =
            pre.has_coin(op).map_err(|e| ValidationError::View { detail: e.to_string() })?;
        if exists {
            return Err(ValidationError::DuplicateOutPoint { out_point: *op });
        }
    }

    Ok(StateDiff { spent, created })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_types::{LOCKTIME_THRESHOLD, TxIn, TxOut};

    use super::*;

    #[test]
    fn script_num_matches_the_documented_encoding() {
        assert_eq!(reference_script_num(0), Vec::<u8>::new());
        assert_eq!(reference_script_num(1), vec![0x01]);
        assert_eq!(reference_script_num(127), vec![0x7f]);
        // 128 needs the extra byte or its top bit would read as a sign.
        assert_eq!(reference_script_num(128), vec![0x80, 0x00]);
        assert_eq!(reference_script_num(255), vec![0xff, 0x00]);
        assert_eq!(reference_script_num(256), vec![0x00, 0x01]);
        assert_eq!(reference_script_num(-1), vec![0x81]);
        assert_eq!(reference_script_num(-128), vec![0x80, 0x80]);
    }

    #[test]
    fn the_reference_script_num_agrees_with_the_production_encoder() {
        for h in [0u64, 1, 15, 16, 17, 75, 76, 127, 128, 255, 256, 65_535, 65_536, 1_000_000] {
            assert_eq!(reference_height_push(h), ferrum_chain::height_push_data(h), "height {h}");
        }
    }

    #[test]
    fn the_leading_push_decoder_agrees_with_production() {
        let cases: Vec<Script> = vec![
            Script::new(vec![0x00]),
            Script::new(vec![0x51]),
            Script::new(vec![0x60]),
            Script::new(vec![0x4f]),
            Script::new(vec![0x02, 0x80, 0x00]),
            Script::new(vec![0x01, 0x11]),
            // Non-minimal: a one-byte push of 0x01 must be OP_1.
            Script::new(vec![0x01, 0x01]),
            // Non-minimal: PUSHDATA1 of two bytes.
            Script::new(vec![0x4c, 0x02, 0xaa, 0xbb]),
            // Truncated.
            Script::new(vec![0x05, 0x01]),
            // Not a push at all.
            Script::new(vec![0xac]),
            Script::EMPTY,
        ];
        for s in cases {
            assert_eq!(
                reference_leading_push(&s),
                ferrum_chain::leading_minimal_push(&s),
                "script {}",
                s.to_hex()
            );
        }
    }

    #[test]
    fn merkle_promotion_never_duplicates_the_odd_leaf() {
        let tx = |n: u32| Transaction {
            version: n,
            inputs: vec![TxIn::new(OutPoint::new(Txid::ZERO, n), Script::EMPTY)],
            outputs: vec![TxOut::new(Amount::from_grains(1), Script::EMPTY)],
            lock_time: 0,
        };
        let three = vec![tx(1), tx(2), tx(3)];
        let mut four = three.clone();
        four.push(tx(3));
        assert_ne!(
            reference_merkle_root(&three),
            reference_merkle_root(&four),
            "CVE-2012-2459: duplicating the last leaf must change the root"
        );
    }

    #[test]
    fn the_reference_merkle_root_agrees_with_production() {
        let tx = |n: u32| Transaction {
            version: n,
            inputs: vec![TxIn::new(OutPoint::new(Txid::ZERO, n), Script::EMPTY)],
            outputs: vec![TxOut::new(Amount::from_grains(1), Script::EMPTY)],
            lock_time: 0,
        };
        for n in 0..12u32 {
            let txs: Vec<Transaction> = (0..n).map(tx).collect();
            assert_eq!(
                reference_merkle_root(&txs),
                ferrum_chain::compute_merkle_root(&txs),
                "{n} transactions"
            );
        }
    }

    #[test]
    fn the_reference_txid_agrees_with_production() {
        let tx = Transaction {
            version: 3,
            inputs: vec![TxIn::new(OutPoint::new(Txid::ZERO, 7), Script::new(vec![0x51]))],
            outputs: vec![TxOut::new(Amount::from_grains(9), Script::new(vec![0x52]))],
            lock_time: 11,
        };
        assert_eq!(reference_txid(&tx), ferrum_storage::txid(&tx));
    }

    #[test]
    fn finality_matches_production_across_the_threshold() {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::new(Txid::ZERO, 0),
                script_sig: Script::EMPTY,
                sequence: 0,
            }],
            outputs: vec![TxOut::new(Amount::from_grains(1), Script::EMPTY)],
            lock_time: 0,
        };
        for lock_time in [0u32, 1, 99, 100, 101, LOCKTIME_THRESHOLD - 1, LOCKTIME_THRESHOLD] {
            tx.lock_time = lock_time;
            for (height, mtp) in [(0u64, 0u64), (100, 500_000_000), (99, 499_999_999)] {
                assert_eq!(
                    reference_is_final(&tx, height, mtp),
                    ferrum_chain::is_final(&tx, height, mtp),
                    "lock_time {lock_time} at height {height}, mtp {mtp}"
                );
            }
        }
        // A fully final sequence opts out of locktime entirely.
        tx.lock_time = u32::MAX;
        tx.inputs[0].sequence = u32::MAX;
        assert!(reference_is_final(&tx, 0, 0));
        assert!(ferrum_chain::is_final(&tx, 0, 0));
    }
}
