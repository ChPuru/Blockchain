//! Context-free block and transaction rules (SPEC §3.1 and §4.1), plus the
//! small pure helpers the rest of the crate is built from.
//!
//! Everything here is a pure function of its arguments. Nothing reads a clock,
//! opens a file or iterates a `HashMap`.
//!
//! # Why the order is normative
//!
//! An implementation that checks cheap rules after expensive ones is correct
//! but denial-of-service-prone. An implementation that checks them in a
//! *different* order can accept a block another node rejects, if two rules
//! disagree about the same block. So the order in [`check_block_sanity`] is
//! part of the specification, not an implementation detail (SPEC §3).

use std::collections::BTreeSet;

use ferrum_crypto::merkle_root_of_leaf_data;
use ferrum_script::{
    MAX_SCRIPT_SIZE, ScriptNum,
    opcode::{
        OP_0, OP_1, OP_1NEGATE, OP_16, OP_PUSHBYTES_MAX, OP_PUSHBYTES_MIN, OP_PUSHDATA1,
        OP_PUSHDATA2, minimal_push_opcode,
    },
};
use ferrum_storage::txid;
use ferrum_types::{
    Amount, Block, BlockHeader, ChainParams, Hash32, LOCKTIME_THRESHOLD, Script, Transaction, Txid,
};

use crate::error::ValidationError;

/// How many headers the median-time-past window spans.
///
/// Eleven, matching `ChainParams::median_time_span`. The constant is repeated
/// here because [`median_time_past`] takes no parameter set — its signature is
/// fixed by CONTRACT §8 — and a debug assertion in [`crate::apply_block`]'s
/// callers keeps the two from drifting.
pub const MEDIAN_TIME_SPAN: usize = 11;

/// Smallest permitted coinbase `script_sig`, in bytes (SPEC §3.3 rule 14).
pub const COINBASE_SCRIPT_SIG_MIN: usize = 2;

/// Largest permitted coinbase `script_sig`, in bytes (SPEC §3.3 rule 14).
pub const COINBASE_SCRIPT_SIG_MAX: usize = 100;

/// The Merkle root over a block's transactions.
///
/// Leaves are the **txid bytes**, hashed into leaf position with
/// `TAG_MERKLE_LEAF` and combined with `TAG_MERKLE_NODE` (CONTRACT §4). An odd
/// node at any level is promoted, never duplicated, which is what makes the
/// tree immune to CVE-2012-2459.
///
/// An empty transaction list yields [`Hash32::ZERO`]; a block with no
/// transactions is already rejected by [`check_block_sanity`], so that case
/// exists only to keep the function total.
#[must_use]
pub fn compute_merkle_root(txs: &[Transaction]) -> Hash32 {
    let ids: Vec<Txid> = txs.iter().map(txid).collect();
    merkle_root_of_leaf_data(ids.iter().map(|id| id.as_bytes().as_slice()))
}

/// Median time past, in **seconds**, over the last [`MEDIAN_TIME_SPAN`]
/// headers of `headers`.
///
/// `headers` must be the window *ending at* the block whose median is wanted,
/// ordered oldest first; only its last eleven entries are read. An empty slice
/// gives `0`, which is what genesis has.
///
/// Seconds, not milliseconds: locktime and `OP_CHECKLOCKTIMEVERIFY` compare
/// against Unix seconds, and doing the truncation once, here, is what stops a
/// comparison from happening in mixed units somewhere downstream.
#[must_use]
pub fn median_time_past(headers: &[BlockHeader]) -> u64 {
    let start = headers.len().saturating_sub(MEDIAN_TIME_SPAN);
    let window = headers.get(start..).unwrap_or(&[]);
    if window.is_empty() {
        return 0;
    }
    let mut stamps: Vec<u64> = window.iter().map(BlockHeader::timestamp_s).collect();
    stamps.sort_unstable();
    // `len / 2` is the upper median for an even window, which is Bitcoin's
    // choice and the only one that keeps the value monotonic as the window
    // fills during the first eleven blocks of a chain.
    let mid = stamps.len().checked_div(2).unwrap_or(0);
    stamps.get(mid).copied().unwrap_or(0)
}

/// SPEC §4.1 — transaction sanity, needing nothing but the transaction.
///
/// # Errors
///
/// One variant per rule; see [`ValidationError`].
pub fn check_transaction_sanity(
    tx: &Transaction,
    params: &ChainParams,
) -> Result<(), ValidationError> {
    let _ = params; // every §4.1 rule is parameter-free today; kept for the contract's signature.

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
    // `total_output` is `None` on overflow *or* on leaving the money range.
    let total = tx.total_output().ok_or(ValidationError::OutputSumOverflow)?;
    if !total.is_valid_money() {
        return Err(ValidationError::OutputSumOverflow);
    }

    let is_coinbase = tx.is_coinbase();
    let mut seen = BTreeSet::new();
    for (index, input) in tx.inputs.iter().enumerate() {
        if !is_coinbase && input.prev_out.is_null() {
            return Err(ValidationError::NullInput { input_index: index });
        }
        if !seen.insert(input.prev_out) {
            return Err(ValidationError::DuplicateInput { out_point: input.prev_out });
        }
        check_script_size(&input.script_sig)?;
    }
    for out in &tx.outputs {
        check_script_size(&out.script_pubkey)?;
    }

    if is_coinbase {
        check_coinbase_structure(tx)?;
    }

    Ok(())
}

/// SPEC §4.1 — a coinbase has exactly one input and it is [`OutPoint::NULL`].
///
/// [`Transaction::is_coinbase`] already guarantees both, so this is deliberate
/// redundancy on the inflation path: it is the check that would catch a future
/// change to `is_coinbase` that widened what counts as one.
///
/// [`OutPoint::NULL`]: ferrum_types::OutPoint::NULL
///
/// # Errors
///
/// [`ValidationError::CoinbaseInputCount`] or
/// [`ValidationError::CoinbaseInputNotNull`].
pub fn check_coinbase_structure(tx: &Transaction) -> Result<(), ValidationError> {
    if tx.inputs.len() != 1 {
        return Err(ValidationError::CoinbaseInputCount { count: tx.inputs.len() });
    }
    let Some(input) = tx.inputs.first() else {
        return Err(ValidationError::CoinbaseInputCount { count: 0 });
    };
    if !input.prev_out.is_null() {
        return Err(ValidationError::CoinbaseInputNotNull);
    }
    Ok(())
}

/// SPEC §3.1 — the context-free block rules, in order.
///
/// 1. `serialized_size(block) <= max_block_size`
/// 2. `txs` non-empty, `txs[0]` is a coinbase, no other transaction is
/// 3. `compute_merkle_root(txs) == header.merkle_root`
/// 4. no duplicate txid within the block
/// 5. every transaction passes [`check_transaction_sanity`]
///
/// # Errors
///
/// One variant per rule; see [`ValidationError`].
pub fn check_block_sanity(block: &Block, params: &ChainParams) -> Result<(), ValidationError> {
    // 1. Size first: it is the cheapest rule and it bounds every rule after it.
    let size = block.serialized_size();
    if size > params.max_block_size {
        return Err(ValidationError::BlockTooLarge { size, max: params.max_block_size });
    }

    // 2. Exactly one coinbase, and it is first.
    let Some(first) = block.txs.first() else {
        return Err(ValidationError::EmptyBlock);
    };
    if !first.is_coinbase() {
        return Err(ValidationError::MissingCoinbase);
    }
    for (index, tx) in block.txs.iter().enumerate().skip(1) {
        if tx.is_coinbase() {
            return Err(ValidationError::MultipleCoinbases { tx_index: index });
        }
    }

    // 3. The header must commit to exactly these transactions.
    let computed = compute_merkle_root(&block.txs);
    if computed != block.header.merkle_root {
        return Err(ValidationError::MerkleRootMismatch {
            expected: computed,
            actual: block.header.merkle_root,
        });
    }

    // 4. No duplicate txid. A `BTreeSet`, never a `HashSet`: this is a
    //    consensus path and iteration order must never enter it.
    let mut seen: BTreeSet<Txid> = BTreeSet::new();
    for tx in &block.txs {
        let id = txid(tx);
        if !seen.insert(id) {
            return Err(ValidationError::DuplicateTransaction { txid: id });
        }
    }

    // 5. Every transaction is individually sane.
    for tx in &block.txs {
        check_transaction_sanity(tx, params)?;
    }

    Ok(())
}

/// SPEC §4.3 — is `tx` final at `height` with median time past `mtp_s`?
///
/// Final if `lock_time == 0`, or every input is `0xFFFFFFFF`, or the lock has
/// expired against the height (below [`LOCKTIME_THRESHOLD`]) or against the
/// median time past (at or above it).
///
/// Comparing against the median rather than the block's own timestamp is what
/// makes locktime unmanipulable: a miner controls its own timestamp within a
/// two-hour window, but cannot move the median of the last eleven blocks
/// without controlling most of them.
#[must_use]
pub fn is_final(tx: &Transaction, height: u64, mtp_s: u64) -> bool {
    if tx.lock_time == 0 {
        return true;
    }
    if tx.inputs.iter().all(|i| i.sequence == u32::MAX) {
        return true;
    }
    let lock = u64::from(tx.lock_time);
    if tx.lock_time < LOCKTIME_THRESHOLD { lock <= height } else { lock <= mtp_s }
}

/// The bytes BIP-34 requires a coinbase to push for `height`.
///
/// The height is encoded as a `ScriptNum`: minimal, sign-magnitude,
/// little-endian — the same encoding the script VM reads numbers in, so there
/// is exactly one spelling of each height. Height `0` encodes as the empty
/// push (`OP_0`).
///
/// Heights above `i64::MAX` are not representable and saturate; they are
/// unreachable in a chain whose blocks take two minutes each.
#[must_use]
pub fn height_push_data(height: u64) -> Vec<u8> {
    ScriptNum::new(i64::try_from(height).unwrap_or(i64::MAX)).to_vec()
}

/// Read the leading push of a script, rejecting any non-minimal encoding.
///
/// Returns the pushed bytes, or `None` when the script does not begin with a
/// readable push, when the push runs off the end, or when a shorter encoding
/// of the same data exists.
///
/// This decodes only the first instruction rather than parsing the whole
/// script: a coinbase `script_sig` is never executed, so it is not required to
/// be a valid script, and demanding that it parse would reject blocks the
/// specification allows.
#[must_use]
pub fn leading_minimal_push(script: &Script) -> Option<Vec<u8>> {
    let bytes = script.as_bytes();
    let opcode = *bytes.first()?;
    let data: Vec<u8> = match opcode {
        OP_0 => Vec::new(),
        OP_1NEGATE => vec![0x81],
        OP_1..=OP_16 => {
            // OP_1 pushes 1, so the value is the opcode's distance from OP_1,
            // plus one.
            let v = opcode.wrapping_sub(OP_1).wrapping_add(1);
            vec![v]
        }
        OP_PUSHBYTES_MIN..=OP_PUSHBYTES_MAX => {
            let n = usize::from(opcode);
            let end = 1usize.checked_add(n)?;
            bytes.get(1..end)?.to_vec()
        }
        OP_PUSHDATA1 => {
            let n = usize::from(*bytes.get(1)?);
            let end = 2usize.checked_add(n)?;
            bytes.get(2..end)?.to_vec()
        }
        OP_PUSHDATA2 => {
            let lo = *bytes.get(1)?;
            let hi = *bytes.get(2)?;
            let n = usize::from(u16::from_le_bytes([lo, hi]));
            let end = 3usize.checked_add(n)?;
            bytes.get(3..end)?.to_vec()
        }
        _ => return None,
    };
    // Minimality is what makes "the push of height h" a single byte string
    // rather than a family of them; without it a miner could vary the encoding
    // to grind coinbase txids.
    if minimal_push_opcode(&data)? != opcode {
        return None;
    }
    Some(data)
}

/// SPEC §3.3 rule 14 — the coinbase `script_sig` is 2..=100 bytes and begins
/// with a minimally encoded push of `height` (BIP-34).
///
/// This is the fix for CVE-2012-1909 / BIP-30. Without a height commitment,
/// two blocks can carry byte-identical coinbase transactions, hence identical
/// txids; the second overwrites the first's UTXO entry and the first block's
/// coins are destroyed. It happened twice on Bitcoin mainnet. Enforcing it
/// from genesis costs nothing and closes the class permanently.
///
/// # Errors
///
/// [`ValidationError::CoinbaseScriptSigLength`],
/// [`ValidationError::CoinbaseMissingHeightPush`] or
/// [`ValidationError::CoinbaseHeightMismatch`].
pub fn check_coinbase_script_sig(script_sig: &Script, height: u64) -> Result<(), ValidationError> {
    let len = script_sig.len();
    if !(COINBASE_SCRIPT_SIG_MIN..=COINBASE_SCRIPT_SIG_MAX).contains(&len) {
        return Err(ValidationError::CoinbaseScriptSigLength {
            len,
            min: COINBASE_SCRIPT_SIG_MIN,
            max: COINBASE_SCRIPT_SIG_MAX,
        });
    }
    let found =
        leading_minimal_push(script_sig).ok_or(ValidationError::CoinbaseMissingHeightPush)?;
    let expected = height_push_data(height);
    if found != expected {
        return Err(ValidationError::CoinbaseHeightMismatch { expected: height, found });
    }
    Ok(())
}

/// Build a coinbase `script_sig`: the BIP-34 height push followed by `extra`.
///
/// `extra` is the miner's scratch space — an extra-nonce, a tag, a message.
/// The result is guaranteed to satisfy [`check_coinbase_script_sig`] for
/// `height`, or the function reports why it cannot.
///
/// # Errors
///
/// [`ValidationError::CoinbaseScriptSigLength`] when the two pushes together
/// leave the 2..=100 byte window.
pub fn build_coinbase_script_sig(height: u64, extra: &[u8]) -> Result<Script, ValidationError> {
    let mut bytes = Vec::new();
    push_minimal(&mut bytes, &height_push_data(height));
    push_minimal(&mut bytes, extra);
    let len = bytes.len();
    if !(COINBASE_SCRIPT_SIG_MIN..=COINBASE_SCRIPT_SIG_MAX).contains(&len) {
        return Err(ValidationError::CoinbaseScriptSigLength {
            len,
            min: COINBASE_SCRIPT_SIG_MIN,
            max: COINBASE_SCRIPT_SIG_MAX,
        });
    }
    Ok(Script::new(bytes))
}

/// Append the minimal push of `data` to `out`.
///
/// Data longer than `u16::MAX` cannot be pushed at all; the coinbase
/// `script_sig` is capped at 100 bytes long before that, so the branch is
/// unreachable and appends nothing rather than panicking.
fn push_minimal(out: &mut Vec<u8>, data: &[u8]) {
    let Some(opcode) = minimal_push_opcode(data) else {
        return;
    };
    out.push(opcode);
    match opcode {
        OP_PUSHDATA1 => {
            out.push(u8::try_from(data.len()).unwrap_or(u8::MAX));
            out.extend_from_slice(data);
        }
        OP_PUSHDATA2 => {
            out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(u16::MAX).to_le_bytes());
            out.extend_from_slice(data);
        }
        OP_PUSHBYTES_MIN..=OP_PUSHBYTES_MAX => out.extend_from_slice(data),
        // OP_0, OP_1NEGATE and OP_1..=OP_16 carry their payload in the opcode.
        _ => {}
    }
}

/// The total value of a transaction's outputs, or the typed overflow error.
///
/// # Errors
///
/// [`ValidationError::OutputSumOverflow`].
pub fn total_output(tx: &Transaction) -> Result<Amount, ValidationError> {
    tx.total_output().ok_or(ValidationError::OutputSumOverflow)
}

/// One script size check, shared by inputs and outputs.
fn check_script_size(script: &Script) -> Result<(), ValidationError> {
    if script.len() > MAX_SCRIPT_SIZE {
        return Err(ValidationError::ScriptTooLarge { len: script.len(), max: MAX_SCRIPT_SIZE });
    }
    Ok(())
}
