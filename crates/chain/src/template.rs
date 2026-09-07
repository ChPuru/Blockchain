//! Block template assembly: turn a tip, a payout script and a bag of
//! transactions into something an engine can seal.
//!
//! The template is built so that the block it becomes will pass
//! [`crate::apply_block`] unchanged — same merkle root, same coinbase value,
//! same size — because a miner that grinds a nonce onto an invalid block has
//! burned real electricity for nothing, and will do it again on the next block
//! and the next. A test asserts exactly that round trip.
//!
//! Selection is a policy, not a consensus rule: which transactions go in is the
//! miner's business, and a block that omits a paying transaction is perfectly
//! valid. What is *not* policy is that every transaction included must be
//! valid at this height, which is why each candidate is fully checked here —
//! resolved against the UTXO overlay, matured, final, solvent and
//! script-verified — rather than trusted.

use ferrum_consensus::{BlockTemplate, EngineRouter, HeaderView};
use ferrum_script::{ExecCtx, ScriptLimits, SighashCache, verify};
use ferrum_storage::{OverlayView, StateView, Store, txid};
use ferrum_types::{
    Amount, Block, BlockHeader, BlockSeal, ChainParams, Coin, HEADER_SIZE, OutPoint, Script,
    Transaction, TxIn, TxOut,
};

use crate::error::ChainError;
use crate::reorg::entry_of;
use crate::validate::{build_coinbase_script_sig, compute_merkle_root, is_final};
use crate::view::StoreHeaderView;

/// Bytes a block costs before any transaction: the 88-byte header plus the
/// `u32` transaction count.
pub const BLOCK_FIXED_OVERHEAD: usize = HEADER_SIZE.saturating_add(4);

/// Borsh size of a [`BlockSeal`] with an empty payload: `u8` engine plus the
/// `u32` length of an empty `Vec`.
///
/// The seal is **not** part of the size a template budgets against
/// `max_block_size`; see [`block_size_of`]. This is the wire cost of a
/// proof-of-work seal, kept for callers that size a whole encoded block.
pub const EMPTY_SEAL_SIZE: usize = 5;

/// The block version templates are built with.
pub const TEMPLATE_VERSION: u32 = 1;

/// The size a block made of `txs` is measured at by the block-size rule: the
/// header, the transaction count and the transactions, **without the seal**.
///
/// Computed arithmetically so that assembly can test the limit after every
/// added transaction without re-encoding the whole block. A test pins it to
/// [`Block::consensus_size`].
///
/// # Why the seal is not counted
///
/// SPEC §3.1 rule 1 measures exactly this quantity (DECISIONS D12). Budgeting
/// the seal here would be wrong in both directions: the five bytes of an empty
/// seal are not what a BFT height produces — a four-validator certificate is
/// 251 bytes, and one per extra validator more — and reserving the worst case
/// instead would shrink every block by `66·n` bytes to protect a rule that no
/// longer counts it. The certificate is bounded on its own by
/// [`ferrum_types::BlockSeal::max_data_len`], so a full template plus any legal
/// seal is still a valid block.
#[must_use]
pub fn block_size_of(txs: &[Transaction]) -> usize {
    let mut n = BLOCK_FIXED_OVERHEAD;
    for tx in txs {
        n = n.saturating_add(tx_body_size(tx));
    }
    n
}

/// The bytes one transaction adds to a block.
///
/// A block encodes `Vec<Transaction>`, so the envelope's type byte — which
/// exists only in the standalone wire form and in the txid preimage — is not
/// part of it.
#[must_use]
pub fn tx_body_size(tx: &Transaction) -> usize {
    tx.serialized_size().saturating_sub(1)
}

/// Build the coinbase for a block at `height` paying `value` to `payout`.
///
/// The `script_sig` is the BIP-34 height push followed by the extra-nonce, so
/// that two blocks at different heights can never share a coinbase txid and a
/// miner has eight bytes of search space that do not disturb the merkle root's
/// meaning.
///
/// # Errors
///
/// [`ChainError::Validation`] if the `script_sig` would leave the 2..=100 byte
/// window, which needs a height above `2^64` to happen.
pub fn build_coinbase(
    height: u64,
    value: Amount,
    payout: &Script,
    extra_nonce: u64,
) -> Result<Transaction, ChainError> {
    let script_sig = build_coinbase_script_sig(height, &extra_nonce.to_le_bytes())?;
    Ok(Transaction {
        version: TEMPLATE_VERSION,
        inputs: vec![TxIn::coinbase(script_sig)],
        outputs: vec![TxOut::new(value, payout.clone())],
        lock_time: 0,
    })
}

/// The largest seal the engine at this height can attach, as a stand-in block
/// would carry it.
///
/// Only the debug assertion uses it, and only to make the check engine-aware:
/// [`Block::consensus_size`] ignores the seal by construction, so a template
/// that is within budget stays within budget whatever certificate is attached.
fn engine_seal_placeholder(engine_id: u8, params: &ChainParams) -> BlockSeal {
    if engine_id == BlockSeal::ENGINE_BFT {
        BlockSeal::bft(vec![0u8; BlockSeal::max_data_len(params.bft_validators.len())])
    } else {
        BlockSeal::POW
    }
}

/// Assemble a candidate block on top of the current tip.
///
/// `txs` is the mempool's suggestion, already in the order it wants them; this
/// function keeps that order, drops anything that does not validate at this
/// height, and stops adding once `max_block_size` would be exceeded. The
/// coinbase pays exactly `block_subsidy(height) + fees`.
///
/// `now_ms` is the node's wall clock. It is a *parameter* rather than a reading
/// taken here, for the same reason the whole seam takes its context explicitly:
/// template building is testable, and re-running it with the same inputs gives
/// the same block.
///
/// # Errors
///
/// [`ChainError::NoTip`] on a store with no genesis, [`ChainError::Consensus`]
/// if the difficulty transition cannot be computed, and
/// [`ChainError::TemplateTooLarge`] if the coinbase alone does not fit.
pub fn build_template(
    store: &Store,
    params: &ChainParams,
    engines: &EngineRouter,
    payout: &Script,
    extra_nonce: u64,
    txs: Vec<Transaction>,
    now_ms: u64,
) -> Result<BlockTemplate, ChainError> {
    let (tip_hash, tip_height) = store.tip()?.ok_or(ChainError::NoTip)?;
    let tip = entry_of(store, &tip_hash)?;
    let height = tip_height.checked_add(1).ok_or(ChainError::Arithmetic("template height"))?;

    let view = StoreHeaderView::new(store, params);
    let engine = engines.engine_for_height(height);
    let bits = engine.next_bits(&tip.header, &view)?;

    // Strictly greater than the median time past, or the block is invalid the
    // moment it is sealed. A miner whose clock is behind still produces a
    // valid block; it just cannot backdate one.
    let median_time_past_s = view.median_time_past(&tip_hash).unwrap_or(0);
    let earliest_ms = median_time_past_s.saturating_mul(1_000).saturating_add(1);
    let timestamp_ms = now_ms.max(earliest_ms);

    // A placeholder coinbase of the right *shape*, so the size budget counts
    // it. Its value is corrected once the fees are known; the value field is a
    // fixed eight bytes, so the size does not change.
    let placeholder = build_coinbase(height, Amount::ZERO, payout, extra_nonce)?;
    let mut size = block_size_of(std::slice::from_ref(&placeholder));
    if size > params.max_block_size {
        return Err(ChainError::TemplateTooLarge { size, max: params.max_block_size });
    }

    let mut overlay = OverlayView::new(store);
    let mut selected: Vec<Transaction> = Vec::new();
    let mut total_fees = Amount::ZERO;

    for tx in txs {
        let tx_size = tx_body_size(&tx);
        let Some(next_size) = size.checked_add(tx_size) else {
            continue;
        };
        if next_size > params.max_block_size {
            // Keep going: a later, smaller transaction may still fit. Stopping
            // at the first over-large candidate would let one fat transaction
            // cost the miner every fee behind it.
            continue;
        }
        let Some(fee) = admit(&mut overlay, &tx, params, height, median_time_past_s)? else {
            continue;
        };
        let Some(fees) = total_fees.checked_add(fee).filter(|a| a.is_valid_money()) else {
            continue;
        };
        total_fees = fees;
        size = next_size;
        selected.push(tx);
    }

    let subsidy = params.block_subsidy(height);
    let reward = subsidy
        .checked_add(total_fees)
        .filter(|a| a.is_valid_money())
        .ok_or(ChainError::Arithmetic("coinbase reward"))?;
    let coinbase = build_coinbase(height, reward, payout, extra_nonce)?;

    let mut block_txs = Vec::with_capacity(selected.len().saturating_add(1));
    block_txs.push(coinbase);
    block_txs.extend(selected);

    let header = BlockHeader {
        version: TEMPLATE_VERSION,
        prev_hash: tip_hash,
        merkle_root: compute_merkle_root(&block_txs),
        timestamp_ms,
        bits,
        // The engine owns the nonce; it starts at zero and is ground from there.
        nonce: 0,
    };

    // Compared against the seal the *active engine* will attach, not against a
    // proof-of-work seal: a template built at a BFT height is sealed with a
    // commit certificate, and an assertion that only ever holds for an empty
    // seal is an assertion about the wrong block.
    debug_assert_eq!(
        Block::new(header, block_txs.clone(), engine_seal_placeholder(engine.engine_id(), params))
            .consensus_size(),
        block_size_of(&block_txs),
        "incremental size accounting must match the encoder"
    );

    Ok(BlockTemplate::new(header, block_txs, height))
}

/// Try to add `tx` to the overlay, returning its fee when it is valid here.
///
/// `Ok(None)` means "not includable at this height" — missing or already-spent
/// inputs, an immature coinbase, a non-final locktime, a script that does not
/// satisfy its output, or an insolvent transaction. None of those are errors:
/// a mempool holds transactions that are not yet valid on purpose. `Err` is
/// reserved for a failure of the store itself.
fn admit(
    overlay: &mut OverlayView<'_>,
    tx: &Transaction,
    params: &ChainParams,
    height: u64,
    mtp_s: u64,
) -> Result<Option<Amount>, ChainError> {
    if tx.is_coinbase() {
        // Exactly one coinbase per block, and the template builds it itself.
        return Ok(None);
    }
    if crate::validate::check_transaction_sanity(tx, params).is_err() {
        return Ok(None);
    }
    if !is_final(tx, height, mtp_s) {
        return Ok(None);
    }

    let mut coins: Vec<Coin> = Vec::with_capacity(tx.inputs.len());
    let mut inputs_total = Amount::ZERO;
    for input in &tx.inputs {
        let Some(coin) = overlay.get_coin(&input.prev_out)? else {
            return Ok(None);
        };
        if coin.is_coinbase {
            let Some(mature_at) = coin.height.checked_add(params.coinbase_maturity) else {
                return Ok(None);
            };
            if height < mature_at {
                return Ok(None);
            }
        }
        let Some(next) = inputs_total.checked_add(coin.value).filter(|a| a.is_valid_money()) else {
            return Ok(None);
        };
        inputs_total = next;
        coins.push(coin);
    }

    let Some(outputs_total) = tx.total_output() else {
        return Ok(None);
    };
    let Some(fee) = inputs_total.checked_sub(outputs_total) else {
        return Ok(None);
    };

    // One set of sighash mid-states for the whole transaction: without it each
    // input re-hashes every prevout, sequence and output, and template building
    // becomes quadratic in transaction size.
    let sighash_cache = SighashCache::new(tx);
    for (input_index, (input, coin)) in tx.inputs.iter().zip(coins.iter()).enumerate() {
        let exec = ExecCtx {
            chain_id: params.chain_id,
            tx,
            input_index,
            input_value: coin.value,
            // The coin's own height is what BIP-68's block-count flavour counts
            // from. The 512-second flavour needs the median time past of the
            // block that created the coin, which the overlay does not carry, so
            // it is left unset: a relative timelock the template cannot prove
            // has matured fails closed and the candidate is simply not
            // included, which is policy, not a consensus verdict.
            input_height: Some(coin.height),
            input_mtp_s: None,
            block_height: height,
            block_mtp_s: mtp_s,
            sighash_cache: Some(&sighash_cache),
            limits: ScriptLimits::CONSENSUS,
        };
        if verify(&input.script_sig, &coin.script_pubkey, &exec).is_err() {
            return Ok(None);
        }
    }

    // Only now commit the transaction to the overlay, so a rejected candidate
    // leaves no trace and the next one sees the same state.
    for input in &tx.inputs {
        let _spent = overlay.spend(&input.prev_out)?;
    }
    let id = txid(tx);
    for (vout, out) in tx.outputs.iter().enumerate() {
        let Ok(index) = u32::try_from(vout) else {
            return Ok(None);
        };
        overlay.add(OutPoint::new(id, index), Coin::new(out.clone(), height, false));
    }
    Ok(Some(fee))
}
