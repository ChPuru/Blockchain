//! The BIP-143-shaped signature hash (CONTRACT §5.5, ENCODING §5).
//!
//! The preimage is frozen and complete: every field sits at a fixed position
//! and nothing is optional. `script_code` is the only variable-length field and
//! carries its own `u32` length.
//!
//! ```text
//! sighash_preimage :=
//!      chain_id        : u32 LE
//!   || tx_version      : u32 LE
//!   || hash_prevouts   : 32
//!   || hash_sequences  : 32
//!   || input_index     : u32 LE
//!   || outpoint        : 36
//!   || script_code_len : u32 LE
//!   || script_code     : bytes
//!   || input_value     : u64 LE
//!   || input_sequence  : u32 LE
//!   || hash_outputs    : 32
//!   || lock_time       : u32 LE
//!   || sighash_type    : u8
//!
//! sighash := tagged_hash(TAG_SIGHASH, sighash_preimage)
//! ```
//!
//! Three fields carry the weight:
//!
//! - **`chain_id`** makes a signature un-replayable across networks. Ethereum
//!   retrofitted this as EIP-155 after the DAO fork and users lost money in the
//!   gap. It costs four bytes.
//! - **`input_value`** commits to the amount being spent, which is what BIP-143
//!   was written to fix: without it an offline signer cannot know what it is
//!   authorising.
//! - **`hash_prevouts` / `hash_sequences` / `hash_outputs`** are mid-states over
//!   the *whole transaction* and not over the input being signed, so signing or
//!   checking `n` inputs is O(n) rather than Bitcoin's legacy O(n²) — provided
//!   they are computed once per transaction. That is what [`SighashCache`] is
//!   for, and it is not optional on a validation path: recomputing them inside
//!   every signature check makes validation quadratic in transaction size,
//!   which is the exact denial of service this preimage shape exists to remove.
//!   [`signature_hash`] and [`sighash_preimage`] build a throwaway cache, so
//!   they are the convenient form, not the fast one.
//!
//! `SIGHASH_SINGLE` with `input_index >= outputs.len()` is an **error** here.
//! Bitcoin returns the constant `uint256(1)`, which is signable and has cost
//! real money.

use std::cell::OnceCell;

use ferrum_crypto::{Signature, TAG_SIGHASH, tagged_hash};
use ferrum_types::{Amount, ChainId, Hash32, Transaction};

use crate::error::ScriptError;
use crate::limits::{SCHNORR_SIGNATURE_SIZE, SIGNATURE_SIZE};

/// Sign all outputs.
pub const SIGHASH_ALL: u8 = 0x01;
/// Sign no outputs.
pub const SIGHASH_NONE: u8 = 0x02;
/// Sign only the output at the same index as the input being signed.
pub const SIGHASH_SINGLE: u8 = 0x03;
/// Flag: sign only this input, so others may be added afterwards.
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
/// Mask that strips [`SIGHASH_ANYONECANPAY`].
pub const SIGHASH_BASE_MASK: u8 = 0x7f;

/// Which parts of a transaction a signature commits to.
///
/// Only six byte values are legal: `0x01`, `0x02`, `0x03` and each of those
/// with [`SIGHASH_ANYONECANPAY`] set. Everything else is
/// [`ScriptError::InvalidSigHashType`]; there is no "unknown types default to
/// ALL" behaviour, which is a Bitcoin quirk that makes signatures malleable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigHashType(u8);

impl SigHashType {
    /// `0x01` — commit to every output.
    pub const ALL: SigHashType = SigHashType(SIGHASH_ALL);
    /// `0x02` — commit to no outputs.
    pub const NONE: SigHashType = SigHashType(SIGHASH_NONE);
    /// `0x03` — commit only to the output at the input's own index.
    pub const SINGLE: SigHashType = SigHashType(SIGHASH_SINGLE);
    /// `0x81`.
    pub const ALL_ANYONECANPAY: SigHashType = SigHashType(SIGHASH_ALL | SIGHASH_ANYONECANPAY);
    /// `0x82`.
    pub const NONE_ANYONECANPAY: SigHashType = SigHashType(SIGHASH_NONE | SIGHASH_ANYONECANPAY);
    /// `0x83`.
    pub const SINGLE_ANYONECANPAY: SigHashType = SigHashType(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY);

    /// Every legal sighash type, for table-driven tests.
    pub const ALL_TYPES: [SigHashType; 6] = [
        SigHashType::ALL,
        SigHashType::NONE,
        SigHashType::SINGLE,
        SigHashType::ALL_ANYONECANPAY,
        SigHashType::NONE_ANYONECANPAY,
        SigHashType::SINGLE_ANYONECANPAY,
    ];

    /// Parse a sighash-type byte.
    pub const fn from_byte(b: u8) -> Result<SigHashType, ScriptError> {
        match b {
            SIGHASH_ALL | SIGHASH_NONE | SIGHASH_SINGLE => Ok(SigHashType(b)),
            0x81..=0x83 => Ok(SigHashType(b)),
            other => Err(ScriptError::InvalidSigHashType(other)),
        }
    }

    /// The wire byte.
    pub const fn to_byte(self) -> u8 {
        self.0
    }

    /// The type with [`SIGHASH_ANYONECANPAY`] stripped: `0x01`, `0x02` or
    /// `0x03`.
    pub const fn base(self) -> u8 {
        self.0 & SIGHASH_BASE_MASK
    }

    /// True when only this input is committed to.
    pub const fn is_anyonecanpay(self) -> bool {
        self.0 & SIGHASH_ANYONECANPAY != 0
    }

    /// True for `NONE` and `NONE | ANYONECANPAY`.
    pub const fn is_none(self) -> bool {
        self.base() == SIGHASH_NONE
    }

    /// True for `SINGLE` and `SINGLE | ANYONECANPAY`.
    pub const fn is_single(self) -> bool {
        self.base() == SIGHASH_SINGLE
    }
}

impl Default for SigHashType {
    fn default() -> Self {
        SigHashType::ALL
    }
}

impl std::fmt::Display for SigHashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = match self.base() {
            SIGHASH_ALL => "ALL",
            SIGHASH_NONE => "NONE",
            _ => "SINGLE",
        };
        if self.is_anyonecanpay() { write!(f, "{base}|ANYONECANPAY") } else { f.write_str(base) }
    }
}

/// Split a 65-byte script signature into its Schnorr half and its type byte.
///
/// A signature is exactly 65 bytes. Any other length is
/// [`ScriptError::InvalidSignatureLength`] — never a "false" result, because a
/// short signature is a malformed script, not a failed authorisation.
pub fn split_signature(bytes: &[u8]) -> Result<(Signature, SigHashType), ScriptError> {
    if bytes.len() != SIGNATURE_SIZE {
        return Err(ScriptError::InvalidSignatureLength(bytes.len()));
    }
    let (sig_bytes, type_byte) = bytes.split_at(SCHNORR_SIGNATURE_SIZE);
    let sig = Signature::from_slice(sig_bytes)
        .map_err(|_| ScriptError::InvalidSignatureLength(bytes.len()))?;
    let ty = SigHashType::from_byte(type_byte.first().copied().unwrap_or(0))?;
    Ok((sig, ty))
}

/// Append a 65-byte script signature: the Schnorr signature then the type byte.
pub fn encode_signature(sig: &Signature, ty: SigHashType) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNATURE_SIZE);
    out.extend_from_slice(sig.as_bytes());
    out.push(ty.to_byte());
    out
}

/// The transaction-wide mid-states of the preimage, computed at most once each.
///
/// `hash_prevouts`, `hash_sequences` and the `ALL` flavour of `hash_outputs`
/// depend on the transaction and **not** on which input is being signed. That
/// is the entire reason the preimage is shaped this way: hashing them once per
/// transaction makes checking `n` signatures cost `O(n)` instead of Bitcoin's
/// legacy `O(n²)`. Recomputing them inside every signature check gives the
/// quadratic behaviour back — a 1 MB transaction of single-signature inputs
/// re-hashes its own prevout list once per input — which is the denial of
/// service BIP-143 exists to remove.
///
/// A cache belongs to the transaction it was built for. Hold one per
/// transaction and hand it to every input's [`crate::ExecCtx`]; the VM checks
/// [`SighashCache::is_for`] before trusting it, and a shared reference cannot
/// alias a mutation, so an equal pointer means equal bytes.
#[derive(Debug)]
pub struct SighashCache<'a> {
    tx: &'a Transaction,
    prevouts: OnceCell<Hash32>,
    sequences: OnceCell<Hash32>,
    all_outputs: OnceCell<Hash32>,
}

impl<'a> SighashCache<'a> {
    /// An empty cache for `tx`. Nothing is hashed until it is asked for.
    pub fn new(tx: &'a Transaction) -> Self {
        SighashCache {
            tx,
            prevouts: OnceCell::new(),
            sequences: OnceCell::new(),
            all_outputs: OnceCell::new(),
        }
    }

    /// The transaction this cache was built for.
    pub fn tx(&self) -> &'a Transaction {
        self.tx
    }

    /// True when this cache was built for `tx` itself.
    ///
    /// Pointer identity, not equality: a `&Transaction` cannot alias a mutation
    /// for as long as it is held, so the same address is the same bytes, and it
    /// costs nothing to check on a validation path.
    pub fn is_for(&self, tx: &Transaction) -> bool {
        std::ptr::eq(self.tx, tx)
    }

    /// `tagged_hash(TAG_SIGHASH, every input's outpoint)`, memoised.
    fn prevouts(&self) -> Hash32 {
        *self.prevouts.get_or_init(|| hash_prevouts(self.tx))
    }

    /// `tagged_hash(TAG_SIGHASH, every input's sequence)`, memoised.
    fn sequences(&self) -> Hash32 {
        *self.sequences.get_or_init(|| hash_sequences(self.tx))
    }

    /// `tagged_hash(TAG_SIGHASH, every output)`, memoised.
    fn all_outputs(&self) -> Result<Hash32, ScriptError> {
        if let Some(digest) = self.all_outputs.get() {
            return Ok(*digest);
        }
        let digest = hash_all_outputs(self.tx)?;
        // Single-threaded by construction, so this cannot already be set.
        let _ = self.all_outputs.set(digest);
        Ok(digest)
    }

    /// Build the frozen preimage for one input of this transaction.
    ///
    /// # Errors
    ///
    /// [`ScriptError::InvalidInputIndex`] when `input_index` is not an index
    /// into the transaction's inputs, and
    /// [`ScriptError::SigHashSingleOutOfRange`] for a `SIGHASH_SINGLE` with no
    /// matching output.
    pub fn preimage(
        &self,
        input_index: usize,
        script_code: &[u8],
        input_value: Amount,
        chain_id: ChainId,
        ty: SigHashType,
    ) -> Result<Vec<u8>, ScriptError> {
        let tx = self.tx;
        let input = tx.inputs.get(input_index).ok_or(ScriptError::InvalidInputIndex {
            index: input_index,
            inputs: tx.inputs.len(),
        })?;
        let index_u32 = u32::try_from(input_index).map_err(|_| ScriptError::InvalidInputIndex {
            index: input_index,
            inputs: tx.inputs.len(),
        })?;

        let hash_prevouts = if ty.is_anyonecanpay() { Hash32::ZERO } else { self.prevouts() };
        let hash_sequences = if ty.is_anyonecanpay() || ty.is_none() || ty.is_single() {
            Hash32::ZERO
        } else {
            self.sequences()
        };
        let hash_outputs = if ty.is_none() {
            Hash32::ZERO
        } else if ty.is_single() {
            hash_single_output(tx, input_index)?
        } else {
            self.all_outputs()?
        };

        let outpoint = borsh::to_vec(&input.prev_out).map_err(|_| ScriptError::NumericOverflow)?;
        let script_code_len =
            u32::try_from(script_code.len()).map_err(|_| ScriptError::NumericOverflow)?;

        let mut out = Vec::with_capacity(script_code.len().saturating_add(160));
        out.extend_from_slice(&chain_id.to_u32().to_le_bytes());
        out.extend_from_slice(&tx.version.to_le_bytes());
        out.extend_from_slice(hash_prevouts.as_bytes());
        out.extend_from_slice(hash_sequences.as_bytes());
        out.extend_from_slice(&index_u32.to_le_bytes());
        out.extend_from_slice(&outpoint);
        out.extend_from_slice(&script_code_len.to_le_bytes());
        out.extend_from_slice(script_code);
        out.extend_from_slice(&input_value.to_grains().to_le_bytes());
        out.extend_from_slice(&input.sequence.to_le_bytes());
        out.extend_from_slice(hash_outputs.as_bytes());
        out.extend_from_slice(&tx.lock_time.to_le_bytes());
        out.push(ty.to_byte());
        Ok(out)
    }

    /// The digest a BIP-340 signature is made over, for one input of this
    /// transaction.
    ///
    /// # Errors
    ///
    /// As [`SighashCache::preimage`].
    pub fn signature_hash(
        &self,
        input_index: usize,
        script_code: &[u8],
        input_value: Amount,
        chain_id: ChainId,
        ty: SigHashType,
    ) -> Result<Hash32, ScriptError> {
        let preimage = self.preimage(input_index, script_code, input_value, chain_id, ty)?;
        Ok(tagged_hash(TAG_SIGHASH, &preimage))
    }
}

/// Build the frozen sighash preimage.
///
/// Exposed so a wallet, a test vector generator and the CLI can all show the
/// exact bytes being signed rather than only the digest.
///
/// This builds a throwaway [`SighashCache`], so it recomputes the three
/// mid-states every call. Anything signing or verifying more than one input of
/// the same transaction should hold a [`SighashCache`] instead.
///
/// # Errors
///
/// As [`SighashCache::preimage`].
pub fn sighash_preimage(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    input_value: Amount,
    chain_id: ChainId,
    ty: SigHashType,
) -> Result<Vec<u8>, ScriptError> {
    SighashCache::new(tx).preimage(input_index, script_code, input_value, chain_id, ty)
}

/// The digest a BIP-340 signature is made over.
///
/// # Errors
///
/// As [`SighashCache::preimage`].
pub fn signature_hash(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    input_value: Amount,
    chain_id: ChainId,
    ty: SigHashType,
) -> Result<Hash32, ScriptError> {
    SighashCache::new(tx).signature_hash(input_index, script_code, input_value, chain_id, ty)
}

// Counts the transaction-wide digests actually computed.
//
// Thread-local rather than global so parallel tests cannot interfere, and
// `cfg(test)` so it costs nothing in a real build. It exists so a test can
// assert that the three mid-states are hashed once per transaction rather than
// once per signature check — the difference between linear and quadratic
// validation.
#[cfg(test)]
thread_local! {
    pub(crate) static DIGESTS_COMPUTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Record that a transaction-wide digest was computed from scratch.
#[cfg(test)]
fn count_digest() {
    DIGESTS_COMPUTED.with(|c| c.set(c.get().saturating_add(1)));
}

/// The same, compiled away outside tests.
#[cfg(not(test))]
fn count_digest() {}

/// `tagged_hash(TAG_SIGHASH, borsh(outpoint) for every input)`.
fn hash_prevouts(tx: &Transaction) -> Hash32 {
    count_digest();
    let mut buf = Vec::with_capacity(tx.inputs.len().saturating_mul(36));
    for input in &tx.inputs {
        // Borsh into a `Vec` is infallible; `OutPoint` is 36 fixed bytes.
        if let Ok(bytes) = borsh::to_vec(&input.prev_out) {
            buf.extend_from_slice(&bytes);
        }
    }
    tagged_hash(TAG_SIGHASH, &buf)
}

/// `tagged_hash(TAG_SIGHASH, u32 LE sequence for every input)`.
fn hash_sequences(tx: &Transaction) -> Hash32 {
    count_digest();
    let mut buf = Vec::with_capacity(tx.inputs.len().saturating_mul(4));
    for input in &tx.inputs {
        buf.extend_from_slice(&input.sequence.to_le_bytes());
    }
    tagged_hash(TAG_SIGHASH, &buf)
}

/// `tagged_hash(TAG_SIGHASH, borsh(output) for every output)` — the `ALL`
/// flavour, which is the one that is worth caching because it walks the whole
/// transaction.
fn hash_all_outputs(tx: &Transaction) -> Result<Hash32, ScriptError> {
    count_digest();
    let mut buf = Vec::new();
    for output in &tx.outputs {
        let bytes = borsh::to_vec(output).map_err(|_| ScriptError::NumericOverflow)?;
        buf.extend_from_slice(&bytes);
    }
    Ok(tagged_hash(TAG_SIGHASH, &buf))
}

/// `SIGHASH_SINGLE`: the one output at the input's own index.
///
/// Not cached: it hashes a single output, and it depends on the input index, so
/// there is no transaction-wide mid-state to share.
fn hash_single_output(tx: &Transaction, input_index: usize) -> Result<Hash32, ScriptError> {
    let output = tx
        .outputs
        .get(input_index)
        .ok_or(ScriptError::SigHashSingleOutOfRange { input_index, outputs: tx.outputs.len() })?;
    let bytes = borsh::to_vec(output).map_err(|_| ScriptError::NumericOverflow)?;
    Ok(tagged_hash(TAG_SIGHASH, &bytes))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ferrum_types::{OutPoint, Script, TxIn, TxOut, Txid};

    fn tx(inputs: usize, outputs: usize) -> Transaction {
        Transaction {
            version: 1,
            inputs: (0..inputs)
                .map(|i| TxIn {
                    prev_out: OutPoint::new(Txid::from_bytes([i as u8; 32]), i as u32),
                    script_sig: Script::EMPTY,
                    sequence: 0xffff_fffe,
                })
                .collect(),
            outputs: (0..outputs)
                .map(|i| {
                    TxOut::new(
                        Amount::from_grains(1_000 + i as u64),
                        Script::new(vec![0x51, i as u8]),
                    )
                })
                .collect(),
            lock_time: 0,
        }
    }

    fn hash(t: &Transaction, i: usize, ty: SigHashType) -> Result<Hash32, ScriptError> {
        signature_hash(t, i, &[0x51], Amount::from_grains(9_999), ChainId::MAINNET, ty)
    }

    #[test]
    fn only_six_type_bytes_are_legal() {
        for b in 0u8..=255 {
            let expected = matches!(b, 0x01 | 0x02 | 0x03 | 0x81 | 0x82 | 0x83);
            assert_eq!(SigHashType::from_byte(b).is_ok(), expected, "0x{b:02x}");
        }
        assert_eq!(SigHashType::from_byte(0x00), Err(ScriptError::InvalidSigHashType(0x00)));
        assert_eq!(SigHashType::from_byte(0x04), Err(ScriptError::InvalidSigHashType(0x04)));
        assert_eq!(SigHashType::from_byte(0xff), Err(ScriptError::InvalidSigHashType(0xff)));
    }

    #[test]
    fn type_accessors() {
        assert_eq!(SigHashType::default(), SigHashType::ALL);
        assert!(!SigHashType::ALL.is_anyonecanpay());
        assert!(SigHashType::ALL_ANYONECANPAY.is_anyonecanpay());
        assert!(SigHashType::NONE_ANYONECANPAY.is_none());
        assert!(SigHashType::SINGLE_ANYONECANPAY.is_single());
        assert_eq!(SigHashType::SINGLE_ANYONECANPAY.base(), SIGHASH_SINGLE);
        assert_eq!(SigHashType::ALL.to_string(), "ALL");
        assert_eq!(SigHashType::NONE_ANYONECANPAY.to_string(), "NONE|ANYONECANPAY");
        assert_eq!(SigHashType::SINGLE.to_string(), "SINGLE");
    }

    #[test]
    fn preimage_layout_is_fixed() {
        let t = tx(1, 1);
        let script_code = vec![0x76, 0xa9, 0xac];
        let pre = sighash_preimage(
            &t,
            0,
            &script_code,
            Amount::from_grains(7),
            ChainId(3),
            SigHashType::ALL,
        )
        .unwrap();
        // 4 + 4 + 32 + 32 + 4 + 36 + 4 + len + 8 + 4 + 32 + 4 + 1
        assert_eq!(pre.len(), 165 + script_code.len());
        assert_eq!(&pre[0..4], &3u32.to_le_bytes());
        assert_eq!(&pre[4..8], &1u32.to_le_bytes());
        assert_eq!(&pre[72..76], &0u32.to_le_bytes(), "input_index");
        assert_eq!(&pre[76..112], &borsh::to_vec(&t.inputs[0].prev_out).unwrap()[..], "outpoint");
        assert_eq!(&pre[112..116], &(script_code.len() as u32).to_le_bytes(), "script_code_len");
        assert_eq!(&pre[116..119], &script_code[..], "script_code");
        assert_eq!(&pre[119..127], &7u64.to_le_bytes(), "input_value");
        assert_eq!(&pre[127..131], &0xffff_fffeu32.to_le_bytes(), "input_sequence");
        assert_eq!(&pre[163..167], &0u32.to_le_bytes(), "lock_time");
        assert_eq!(pre[pre.len() - 1], 0x01);
    }

    #[test]
    fn anyonecanpay_zeroes_prevouts_and_sequences() {
        let t = tx(2, 2);
        let pre = sighash_preimage(
            &t,
            0,
            &[],
            Amount::ZERO,
            ChainId::MAINNET,
            SigHashType::ALL_ANYONECANPAY,
        )
        .unwrap();
        assert_eq!(&pre[8..40], &[0u8; 32]);
        assert_eq!(&pre[40..72], &[0u8; 32]);
    }

    #[test]
    fn none_and_single_zero_the_sequence_digest() {
        let t = tx(2, 2);
        for ty in [SigHashType::NONE, SigHashType::SINGLE] {
            let pre = sighash_preimage(&t, 0, &[], Amount::ZERO, ChainId::MAINNET, ty).unwrap();
            assert_ne!(&pre[8..40], &[0u8; 32], "prevouts stay for {ty}");
            assert_eq!(&pre[40..72], &[0u8; 32], "sequences zeroed for {ty}");
        }
    }

    #[test]
    fn none_zeroes_the_output_digest() {
        let t = tx(2, 2);
        let pre = sighash_preimage(&t, 0, &[], Amount::ZERO, ChainId::MAINNET, SigHashType::NONE)
            .unwrap();
        // hash_outputs sits at 4+4+32+32+4+36+4+0+8+4 = 128.
        assert_eq!(&pre[128..160], &[0u8; 32]);
    }

    #[test]
    fn single_out_of_range_is_an_error_not_uint256_one() {
        let t = tx(3, 1);
        assert_eq!(
            hash(&t, 2, SigHashType::SINGLE),
            Err(ScriptError::SigHashSingleOutOfRange { input_index: 2, outputs: 1 })
        );
        assert_eq!(
            hash(&t, 1, SigHashType::SINGLE_ANYONECANPAY),
            Err(ScriptError::SigHashSingleOutOfRange { input_index: 1, outputs: 1 })
        );
        // In range, it is fine.
        assert!(hash(&t, 0, SigHashType::SINGLE).is_ok());
    }

    #[test]
    fn input_index_must_be_in_range() {
        let t = tx(1, 1);
        assert_eq!(
            hash(&t, 5, SigHashType::ALL),
            Err(ScriptError::InvalidInputIndex { index: 5, inputs: 1 })
        );
    }

    #[test]
    fn chain_id_changes_the_digest() {
        let t = tx(1, 1);
        let a = signature_hash(&t, 0, &[], Amount::ZERO, ChainId(1), SigHashType::ALL).unwrap();
        let b = signature_hash(&t, 0, &[], Amount::ZERO, ChainId(2), SigHashType::ALL).unwrap();
        let c = signature_hash(&t, 0, &[], Amount::ZERO, ChainId(3), SigHashType::ALL).unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn input_value_changes_the_digest() {
        let t = tx(1, 1);
        let a = signature_hash(&t, 0, &[], Amount::from_grains(1), ChainId(1), SigHashType::ALL)
            .unwrap();
        let b = signature_hash(&t, 0, &[], Amount::from_grains(2), ChainId(1), SigHashType::ALL)
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn script_code_changes_the_digest() {
        let t = tx(1, 1);
        let a = signature_hash(&t, 0, &[0x51], Amount::ZERO, ChainId(1), SigHashType::ALL).unwrap();
        let b = signature_hash(&t, 0, &[0x52], Amount::ZERO, ChainId(1), SigHashType::ALL).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn every_type_produces_a_distinct_digest() {
        let t = tx(2, 2);
        let mut seen = Vec::new();
        for ty in SigHashType::ALL_TYPES {
            let h = hash(&t, 0, ty).unwrap();
            assert!(!seen.contains(&h), "{ty} collided");
            seen.push(h);
        }
    }

    #[test]
    fn none_ignores_output_changes_but_all_does_not() {
        let a = tx(1, 2);
        let mut b = a.clone();
        b.outputs[1] = TxOut::new(Amount::from_grains(5), Script::new(vec![0x52]));
        assert_eq!(hash(&a, 0, SigHashType::NONE), hash(&b, 0, SigHashType::NONE));
        assert_ne!(hash(&a, 0, SigHashType::ALL), hash(&b, 0, SigHashType::ALL));
    }

    #[test]
    fn anyonecanpay_ignores_added_inputs() {
        let a = tx(1, 1);
        let mut b = a.clone();
        b.inputs.push(TxIn {
            prev_out: OutPoint::new(Txid::from_bytes([9u8; 32]), 9),
            script_sig: Script::EMPTY,
            sequence: 7,
        });
        assert_eq!(
            hash(&a, 0, SigHashType::ALL_ANYONECANPAY),
            hash(&b, 0, SigHashType::ALL_ANYONECANPAY)
        );
        assert_ne!(hash(&a, 0, SigHashType::ALL), hash(&b, 0, SigHashType::ALL));
    }

    #[test]
    fn signature_round_trips_through_65_bytes() {
        let sig = Signature::from_bytes([7u8; 64]);
        let encoded = encode_signature(&sig, SigHashType::SINGLE);
        assert_eq!(encoded.len(), 65);
        let (back, ty) = split_signature(&encoded).unwrap();
        assert_eq!(back, sig);
        assert_eq!(ty, SigHashType::SINGLE);
    }

    #[test]
    fn a_signature_must_be_exactly_65_bytes() {
        assert_eq!(split_signature(&[]), Err(ScriptError::InvalidSignatureLength(0)));
        assert_eq!(split_signature(&[0u8; 64]), Err(ScriptError::InvalidSignatureLength(64)));
        assert_eq!(split_signature(&[0u8; 66]), Err(ScriptError::InvalidSignatureLength(66)));
        let mut bad = vec![0u8; 65];
        bad[64] = 0x05;
        assert_eq!(split_signature(&bad), Err(ScriptError::InvalidSigHashType(0x05)));
    }
}
