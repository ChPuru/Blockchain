//! The transaction model and its typed wire envelope.
//!
//! # The envelope (CONTRACT §2.1)
//!
//! ```text
//! tx_envelope := type_byte:u8 || borsh(Transaction)
//! ```
//!
//! `type_byte` is `0x00` (`Standard`) in v1. `0x01..=0x7f` are future
//! transaction types and `0x80..=0xff` are permanently reserved; both are
//! rejected here rather than ignored, because a node that silently accepted an
//! unknown type would have a different view of the chain from one that did not.
//!
//! The type byte is inside the txid preimage, so a v2 transaction can never
//! collide with a v1 txid.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::amount::Amount;
use crate::error::TypeError;
use crate::hash::{Hash32, Txid};
use crate::script::Script;

/// The only transaction type defined in v1.
pub const TX_TYPE_STANDARD: u8 = 0x00;

/// Below this value a `lock_time` is a block height; at or above it, a Unix
/// timestamp in **seconds**.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Borsh-encoded size of an [`OutPoint`]: a 32-byte txid plus a `u32 LE` index.
pub const OUTPOINT_SIZE: usize = 36;

/// Serialize with Borsh into a fresh `Vec`.
///
/// Borsh only fails when the underlying writer fails, and writing into a `Vec`
/// is infallible short of an allocation abort, so this cannot return an error
/// in practice. The `expect` documents that invariant rather than propagating
/// an error that no caller could ever handle.
pub(crate) fn to_vec_infallible<T: BorshSerialize>(value: &T) -> Vec<u8> {
    borsh::to_vec(value).expect("borsh serialization into a Vec cannot fail")
}

/// A reference to one previous transaction output.
///
/// Ordered by `(txid, vout)`, which makes it a well-behaved `BTreeMap` key for
/// the UTXO set and the overlay.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct OutPoint {
    /// The transaction that created the output.
    pub txid: Txid,
    /// Index of the output within that transaction.
    pub vout: u32,
}

impl OutPoint {
    /// The null outpoint used by a coinbase input: the zero txid with an
    /// all-ones index. Bitcoin uses the same shape, and `u32::MAX` is chosen
    /// over `0` so that a null outpoint can never be confused with output 0 of
    /// a (hypothetical) all-zero txid.
    pub const NULL: OutPoint = OutPoint { txid: Txid::ZERO, vout: u32::MAX };

    /// Build an outpoint.
    pub const fn new(txid: Txid, vout: u32) -> Self {
        OutPoint { txid, vout }
    }

    /// True for the coinbase sentinel.
    pub fn is_null(&self) -> bool {
        self.txid.is_zero() && self.vout == u32::MAX
    }
}

impl std::fmt::Display for OutPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

/// A transaction input: which output it spends, the witness data that
/// satisfies that output's script, and its sequence number.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct TxIn {
    /// The output being spent.
    pub prev_out: OutPoint,
    /// The unlocking script. Consensus requires it to be push-only.
    pub script_sig: Script,
    /// `u32::MAX` opts the input out of `lock_time` enforcement.
    pub sequence: u32,
}

impl TxIn {
    /// The sequence value that marks an input as final, disabling `lock_time`.
    pub const SEQUENCE_FINAL: u32 = u32::MAX;

    /// A spend of `prev_out` with the given unlocking script and a final
    /// sequence number.
    pub fn new(prev_out: OutPoint, script_sig: Script) -> Self {
        TxIn { prev_out, script_sig, sequence: Self::SEQUENCE_FINAL }
    }

    /// The coinbase input: the null outpoint plus arbitrary miner data.
    pub fn coinbase(script_sig: Script) -> Self {
        TxIn { prev_out: OutPoint::NULL, script_sig, sequence: Self::SEQUENCE_FINAL }
    }

    /// Borsh-encoded size of this input.
    pub(crate) fn borsh_size(&self) -> usize {
        // outpoint(36) || u32 script length prefix(4) || script || sequence(4)
        OUTPOINT_SIZE.saturating_add(8).saturating_add(self.script_sig.len())
    }
}

/// A transaction output: a value and the script that locks it.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct TxOut {
    /// Value in grains.
    pub value: Amount,
    /// The locking script.
    pub script_pubkey: Script,
}

impl TxOut {
    /// Build an output.
    pub fn new(value: Amount, script_pubkey: Script) -> Self {
        TxOut { value, script_pubkey }
    }

    /// Borsh-encoded size of this output.
    pub(crate) fn borsh_size(&self) -> usize {
        // value(8) || u32 script length prefix(4) || script
        12usize.saturating_add(self.script_pubkey.len())
    }
}

/// A Ferrum transaction.
///
/// The struct is the *body*; the wire and txid forms are the envelope produced
/// by [`Transaction::encode_envelope`].
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct Transaction {
    /// Transaction version. v1 validators accept any value; consensus rules
    /// that care live in `ferrum-chain`.
    pub version: u32,
    /// Inputs, in order. The order is signed over and is consensus-critical.
    pub inputs: Vec<TxIn>,
    /// Outputs, in order. The index of an output is its `vout`.
    pub outputs: Vec<TxOut>,
    /// `< LOCKTIME_THRESHOLD` means a block height, otherwise Unix seconds.
    pub lock_time: u32,
}

impl Transaction {
    /// A transaction with no inputs or outputs, version 1, no lock time.
    pub fn empty() -> Self {
        Transaction { version: 1, inputs: Vec::new(), outputs: Vec::new(), lock_time: 0 }
    }

    /// Exactly one input, and that input spends [`OutPoint::NULL`].
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].prev_out.is_null()
    }

    /// The wire form: `TX_TYPE_STANDARD || borsh(self)`.
    ///
    /// This is also the txid preimage: `Txid = tagged_hash(TAG_TXID, envelope)`.
    pub fn encode_envelope(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.serialized_size());
        out.push(TX_TYPE_STANDARD);
        let mut body = to_vec_infallible(self);
        out.append(&mut body);
        out
    }

    /// Decode a wire envelope.
    ///
    /// Rejects an empty slice, any unknown type byte in `0x00..=0x7f`, every
    /// reserved byte in `0x80..=0xff`, and — through `borsh::from_slice` —
    /// any trailing bytes after a valid body. Tolerating a suffix would be a
    /// txid-malleability bug: two distinct byte strings would decode to the
    /// same transaction with different ids.
    pub fn decode_envelope(b: &[u8]) -> Result<Self, TypeError> {
        let (type_byte, body) = b.split_first().ok_or(TypeError::EmptyEnvelope)?;
        match *type_byte {
            TX_TYPE_STANDARD => {}
            t @ 0x01..=0x7f => return Err(TypeError::UnknownTxType(t)),
            t => return Err(TypeError::ReservedTxType(t)),
        }
        borsh::from_slice(body).map_err(TypeError::decode)
    }

    /// Sum of all output values.
    ///
    /// `None` on `u64` overflow *or* when the total is above `MAX_MONEY` —
    /// both are the same thing to a caller, which must reject the transaction
    /// either way.
    pub fn total_output(&self) -> Option<Amount> {
        let mut total = Amount::ZERO;
        for o in &self.outputs {
            if !o.value.is_valid_money() {
                return None;
            }
            total = total.checked_add(o.value)?;
        }
        total.is_valid_money().then_some(total)
    }

    /// Size in bytes of [`Transaction::encode_envelope`].
    ///
    /// Computed arithmetically rather than by encoding, because block assembly
    /// and mempool eviction call it once per candidate transaction. A proptest
    /// pins it to `encode_envelope().len()`.
    pub fn serialized_size(&self) -> usize {
        self.borsh_size().saturating_add(1)
    }

    /// Borsh-encoded size of the transaction body, without the envelope byte.
    pub(crate) fn borsh_size(&self) -> usize {
        // version(4) || inputs length(4) || ... || outputs length(4) || lock_time(4)
        let mut n: usize = 16;
        for i in &self.inputs {
            n = n.saturating_add(i.borsh_size());
        }
        for o in &self.outputs {
            n = n.saturating_add(o.borsh_size());
        }
        n
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Transaction::empty()
    }
}

/// Convenience: the txid of the zero hash, for tests and sentinels.
impl From<Hash32> for OutPoint {
    fn from(h: Hash32) -> Self {
        OutPoint { txid: Txid(h), vout: 0 }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn txid(byte: u8) -> Txid {
        Txid::from_bytes([byte; 32])
    }

    fn simple_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::new(txid(0x11), 3),
                script_sig: Script::new(vec![0x51]),
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOut::new(Amount::from_grains(50_000), Script::new(vec![0x52, 0x53]))],
            lock_time: 0,
        }
    }

    fn coinbase_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(Script::new(vec![0x01, 0x00]))],
            outputs: vec![TxOut::new(Amount::from_grains(50 * crate::amount::COIN), Script::EMPTY)],
            lock_time: 0,
        }
    }

    #[test]
    fn constants_match_the_contract() {
        assert_eq!(TX_TYPE_STANDARD, 0x00);
        assert_eq!(LOCKTIME_THRESHOLD, 500_000_000);
        assert_eq!(OUTPOINT_SIZE, 36);
        assert_eq!(TxIn::SEQUENCE_FINAL, u32::MAX);
    }

    #[test]
    fn null_outpoint_is_the_coinbase_sentinel() {
        assert!(OutPoint::NULL.is_null());
        assert_eq!(OutPoint::NULL.txid, Txid::ZERO);
        assert_eq!(OutPoint::NULL.vout, u32::MAX);
        assert!(!OutPoint::new(txid(0), 0).is_null(), "zero txid with vout 0 is not null");
        assert!(!OutPoint::new(txid(1), u32::MAX).is_null(), "non-zero txid is not null");
    }

    #[test]
    fn outpoint_is_thirty_six_borsh_bytes() {
        let op = OutPoint::new(txid(0xab), 0x0102_0304);
        let b = borsh::to_vec(&op).unwrap();
        assert_eq!(b.len(), OUTPOINT_SIZE);
        assert_eq!(&b[..32], &[0xabu8; 32]);
        // u32 little-endian, per Borsh.
        assert_eq!(&b[32..], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(borsh::from_slice::<OutPoint>(&b).unwrap(), op);
    }

    #[test]
    fn outpoint_orders_by_txid_then_vout() {
        assert!(OutPoint::new(txid(1), 5) < OutPoint::new(txid(2), 0));
        assert!(OutPoint::new(txid(1), 4) < OutPoint::new(txid(1), 5));
    }

    #[test]
    fn outpoint_display_is_txid_colon_vout() {
        let op = OutPoint::new(txid(0), 7);
        assert_eq!(op.to_string(), format!("{}:7", Txid::ZERO));
    }

    #[test]
    fn is_coinbase_needs_exactly_one_null_input() {
        assert!(coinbase_tx().is_coinbase());
        assert!(!simple_tx().is_coinbase());

        let mut two_inputs = coinbase_tx();
        two_inputs.inputs.push(TxIn::coinbase(Script::EMPTY));
        assert!(!two_inputs.is_coinbase(), "two null inputs is not a coinbase");

        let mut no_inputs = coinbase_tx();
        no_inputs.inputs.clear();
        assert!(!no_inputs.is_coinbase());
    }

    #[test]
    fn envelope_starts_with_the_type_byte() {
        let tx = simple_tx();
        let e = tx.encode_envelope();
        assert_eq!(e[0], TX_TYPE_STANDARD);
        assert_eq!(&e[1..], borsh::to_vec(&tx).unwrap().as_slice());
    }

    #[test]
    fn envelope_round_trips() {
        let tx = simple_tx();
        assert_eq!(Transaction::decode_envelope(&tx.encode_envelope()).unwrap(), tx);
        let cb = coinbase_tx();
        assert_eq!(Transaction::decode_envelope(&cb.encode_envelope()).unwrap(), cb);
    }

    #[test]
    fn decode_rejects_an_empty_slice() {
        assert_eq!(Transaction::decode_envelope(&[]), Err(TypeError::EmptyEnvelope));
    }

    #[test]
    fn decode_rejects_unknown_types_in_the_low_range() {
        let mut e = simple_tx().encode_envelope();
        e[0] = 0x01;
        assert_eq!(Transaction::decode_envelope(&e), Err(TypeError::UnknownTxType(0x01)));
        e[0] = 0x7f;
        assert_eq!(Transaction::decode_envelope(&e), Err(TypeError::UnknownTxType(0x7f)));
    }

    #[test]
    fn decode_rejects_every_reserved_type() {
        let base = simple_tx().encode_envelope();
        for t in 0x80u8..=0xff {
            let mut e = base.clone();
            e[0] = t;
            assert_eq!(
                Transaction::decode_envelope(&e),
                Err(TypeError::ReservedTxType(t)),
                "type byte {t:#04x} must be rejected"
            );
        }
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut e = simple_tx().encode_envelope();
        e.push(0);
        assert!(
            matches!(Transaction::decode_envelope(&e), Err(TypeError::Decode(_))),
            "a trailing byte is a txid-malleability bug and must be rejected"
        );
    }

    #[test]
    fn decode_rejects_a_truncated_body() {
        let e = simple_tx().encode_envelope();
        assert!(Transaction::decode_envelope(&e[..e.len() - 1]).is_err());
        assert!(Transaction::decode_envelope(&e[..1]).is_err());
    }

    #[test]
    fn decode_rejects_an_absurd_vector_length() {
        // version(4) then an inputs length of u32::MAX: borsh must not
        // pre-allocate 4 GiB or accept it.
        let mut b = vec![0u8];
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(Transaction::decode_envelope(&b).is_err());
    }

    #[test]
    fn total_output_sums_outputs() {
        let tx = simple_tx();
        assert_eq!(tx.total_output(), Some(Amount::from_grains(50_000)));
        assert_eq!(Transaction::empty().total_output(), Some(Amount::ZERO));
    }

    #[test]
    fn total_output_is_none_on_overflow() {
        let big = TxOut::new(Amount::from_grains(u64::MAX), Script::EMPTY);
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![big.clone(), big],
            lock_time: 0,
        };
        assert_eq!(tx.total_output(), None);
    }

    #[test]
    fn total_output_is_none_above_max_money() {
        let half = Amount::from_grains(Amount::MAX_MONEY.to_grains() / 2 + 1);
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut::new(half, Script::EMPTY), TxOut::new(half, Script::EMPTY)],
            lock_time: 0,
        };
        assert_eq!(tx.total_output(), None, "the sum exceeds MAX_MONEY");

        let single = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut::new(
                Amount::from_grains(Amount::MAX_MONEY.to_grains() + 1),
                Script::EMPTY,
            )],
            lock_time: 0,
        };
        assert_eq!(single.total_output(), None, "one out-of-range output is enough");
    }

    #[test]
    fn total_output_accepts_exactly_max_money() {
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut::new(Amount::MAX_MONEY, Script::EMPTY)],
            lock_time: 0,
        };
        assert_eq!(tx.total_output(), Some(Amount::MAX_MONEY));
    }

    #[test]
    fn serialized_size_matches_the_envelope() {
        for tx in [simple_tx(), coinbase_tx(), Transaction::empty()] {
            assert_eq!(tx.serialized_size(), tx.encode_envelope().len());
            assert_eq!(tx.borsh_size(), borsh::to_vec(&tx).unwrap().len());
        }
    }

    #[test]
    fn empty_transaction_is_the_default() {
        let t = Transaction::default();
        assert_eq!(t, Transaction::empty());
        assert_eq!(t.version, 1);
        assert!(t.inputs.is_empty() && t.outputs.is_empty());
        assert_eq!(t.lock_time, 0);
        // 4 + 4 + 4 + 4 body, plus the envelope byte.
        assert_eq!(t.serialized_size(), 17);
    }

    #[test]
    fn txin_helpers_set_a_final_sequence() {
        let i = TxIn::new(OutPoint::new(txid(1), 0), Script::EMPTY);
        assert_eq!(i.sequence, TxIn::SEQUENCE_FINAL);
        let c = TxIn::coinbase(Script::new(vec![0x02, 0x00, 0x01]));
        assert!(c.prev_out.is_null());
        assert_eq!(c.sequence, TxIn::SEQUENCE_FINAL);
    }

    #[test]
    fn outpoint_from_hash_defaults_to_vout_zero() {
        let op = OutPoint::from(Hash32::ZERO);
        assert_eq!(op.vout, 0);
        assert_eq!(op.txid, Txid::ZERO);
        assert!(!op.is_null());
    }
}
