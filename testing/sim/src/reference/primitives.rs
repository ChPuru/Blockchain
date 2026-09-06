//! The primitives the reference executor re-derives rather than imports.
//!
//! The whole value of a differential test is that the two implementations do
//! not share code. If the reference called `ferrum_chain::compute_merkle_root`
//! it could not catch a bug in it, and the same goes for the txid, the block
//! hash, the `ScriptNum` encoding, the minimal-push decoder and the finality
//! rule. Each is written out here from CONTRACT §2, §4, §5 and SPEC §4.3, and
//! `super::tests` asserts each against its production counterpart — so a
//! disagreement is reported as a disagreement about *that* primitive rather
//! than as a mysterious state-root mismatch three layers up.

use ferrum_crypto::{
    TAG_HEADER, TAG_MERKLE_LEAF, TAG_MERKLE_NODE, TAG_TXID, tagged_hash, tagged_hasher,
};
use ferrum_types::{BlockHash, BlockHeader, Hash32, LOCKTIME_THRESHOLD, Script, Transaction, Txid};

/// `Txid = tagged_hash(TAG_TXID, type_byte || borsh(tx))` (CONTRACT §2.1).
#[must_use]
pub fn reference_txid(tx: &Transaction) -> Txid {
    Txid(tagged_hash(TAG_TXID, &tx.encode_envelope()))
}

/// `BlockHash = tagged_hash(TAG_HEADER, header_bytes)` over the 88 bytes of
/// CONTRACT §2.2.
#[must_use]
pub fn reference_block_hash(header: &BlockHeader) -> BlockHash {
    BlockHash(tagged_hash(TAG_HEADER, &header.encode()))
}

/// The block's Merkle root (CONTRACT §4 and §8).
///
/// The **leaf data** is the txid, and it is still hashed into leaf position
/// with `TAG_MERKLE_LEAF`: `leaf = tagged_hash(TAG_MERKLE_LEAF, txid_bytes)`,
/// `node = tagged_hash(TAG_MERKLE_NODE, left || right)`. Leaf and internal
/// nodes carry different tags so that an internal node hash can never be
/// reinterpreted as a leaf hash — the classic second-preimage defence.
///
/// An odd node at any level is *promoted* unchanged, never duplicated. That is
/// CVE-2012-2459: duplicating the last leaf lets an attacker build a different
/// block with the same root, which a victim then caches as invalid and refuses
/// to accept in its honest form. Promotion makes the tree shape a function of
/// the leaf count alone.
///
/// An empty list is [`Hash32::ZERO`].
#[must_use]
pub fn reference_merkle_root(txs: &[Transaction]) -> Hash32 {
    let mut level: Vec<Hash32> = txs
        .iter()
        .map(|tx| tagged_hash(TAG_MERKLE_LEAF, reference_txid(tx).0.as_bytes()))
        .collect();
    if level.is_empty() {
        return Hash32::ZERO;
    }
    while level.len() > 1 {
        let mut next: Vec<Hash32> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            match (level.get(i), level.get(i.saturating_add(1))) {
                (Some(left), Some(right)) => {
                    let mut hasher = tagged_hasher(TAG_MERKLE_NODE);
                    hasher.update(left.as_bytes());
                    hasher.update(right.as_bytes());
                    next.push(Hash32::from_bytes(*hasher.finalize().as_bytes()));
                }
                // Odd node out: promoted, never duplicated.
                (Some(left), None) => next.push(*left),
                _ => {}
            }
            i = i.saturating_add(2);
        }
        level = next;
    }
    level.first().copied().unwrap_or(Hash32::ZERO)
}

/// `CScriptNum`'s sign-magnitude little-endian encoding of `v` (CONTRACT §5.3).
///
/// Zero is the empty vector; a value whose top byte would set the sign bit
/// gains an extra byte so that the sign is never confused with magnitude.
#[must_use]
pub fn reference_script_num(v: i64) -> Vec<u8> {
    if v == 0 {
        return Vec::new();
    }
    let negative = v < 0;
    let mut magnitude = v.unsigned_abs();
    let mut out = Vec::new();
    while magnitude > 0 {
        out.push(u8::try_from(magnitude & 0xff).unwrap_or(0));
        magnitude >>= 8;
    }
    match out.last_mut() {
        Some(top) if *top & 0x80 != 0 => out.push(if negative { 0x80 } else { 0x00 }),
        Some(top) if negative => *top |= 0x80,
        _ => {}
    }
    out
}

/// The minimally encoded push of `height` a BIP-34 coinbase must begin with.
#[must_use]
pub fn reference_height_push(height: u64) -> Vec<u8> {
    reference_script_num(i64::try_from(height).unwrap_or(i64::MAX))
}

/// Decode the first instruction of `script` as a **minimally encoded** push,
/// returning the data it pushes.
///
/// `None` means the script does not begin with a push at all, the push is
/// truncated, or a shorter encoding of the same data exists. Minimality is a
/// consensus rule wherever a value is read (SPEC §5 rule 6): without it the
/// same coinbase height has several spellings and BIP-34 stops being a
/// uniqueness argument.
#[must_use]
pub fn reference_leading_push(script: &Script) -> Option<Vec<u8>> {
    let bytes = script.as_bytes();
    let opcode = *bytes.first()?;
    let data: Vec<u8> = match opcode {
        // OP_0 pushes the empty vector.
        0x00 => Vec::new(),
        // Direct push of 1..=75 bytes.
        0x01..=0x4b => {
            let len = usize::from(opcode);
            bytes.get(1..1usize.checked_add(len)?)?.to_vec()
        }
        // OP_PUSHDATA1.
        0x4c => {
            let len = usize::from(*bytes.get(1)?);
            bytes.get(2..2usize.checked_add(len)?)?.to_vec()
        }
        // OP_PUSHDATA2, little-endian length.
        0x4d => {
            let lo = u16::from(*bytes.get(1)?);
            let hi = u16::from(*bytes.get(2)?);
            let len = usize::from(lo | (hi << 8));
            bytes.get(3..3usize.checked_add(len)?)?.to_vec()
        }
        // OP_1NEGATE pushes the one-byte sign-magnitude -1.
        0x4f => vec![0x81],
        // OP_1..OP_16.
        0x51..=0x60 => vec![opcode.wrapping_sub(0x50)],
        _ => return None,
    };
    if reference_minimal_push_opcode(&data)? != opcode {
        return None;
    }
    Some(data)
}

/// The one opcode that may legally introduce a push of `data`.
fn reference_minimal_push_opcode(data: &[u8]) -> Option<u8> {
    match data {
        [] => Some(0x00),
        [0x81] => Some(0x4f),
        [b] if (1..=16).contains(b) => Some(b.checked_add(0x50)?),
        _ if data.len() <= 0x4b => u8::try_from(data.len()).ok(),
        _ if data.len() <= 0xff => Some(0x4c),
        _ if data.len() <= 0xffff => Some(0x4d),
        // OP_PUSHDATA4 does not exist: MAX_SCRIPT_SIZE is 1000 bytes.
        _ => None,
    }
}

/// SPEC §4.3: whether `tx` may be included in a block at this height.
#[must_use]
pub fn reference_is_final(tx: &Transaction, height: u64, mtp_s: u64) -> bool {
    if tx.lock_time == 0 {
        return true;
    }
    if tx.inputs.iter().all(|i| i.sequence == u32::MAX) {
        return true;
    }
    if u64::from(tx.lock_time) < u64::from(LOCKTIME_THRESHOLD) {
        u64::from(tx.lock_time) <= height
    } else {
        u64::from(tx.lock_time) <= mtp_s
    }
}
