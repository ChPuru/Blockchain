//! Bidirectional encoding round-trips (CONTRACT §2).
//!
//! Borsh is chosen because it is bijective, and this file is what holds it to
//! that claim. For every core type we assert **both** directions:
//!
//! * `decode(encode(v)) == v` — no information is lost on the way out, and
//! * `encode(decode(b)) == b` — no *distinct* byte string decodes to the same
//!   value, which is the property that makes a txid non-malleable.
//!
//! The second direction is the one that matters and the one that is usually
//! missing. A codec that tolerated, say, a redundant length prefix or a
//! trailing byte would pass the first check and fail the second.

#![allow(clippy::unwrap_used)]

use borsh::{BorshDeserialize, BorshSerialize};
use ferrum_types::{
    Amount, Block, BlockHash, BlockHeader, BlockSeal, Coin, CompactTarget, Hash32, OutPoint,
    Script, Transaction, TxIn, TxOut, Txid,
};
use proptest::prelude::*;

// --------------------------------------------------------------------------
// strategies
// --------------------------------------------------------------------------

fn arb_hash32() -> impl Strategy<Value = Hash32> {
    any::<[u8; 32]>().prop_map(Hash32::from_bytes)
}

fn arb_txid() -> impl Strategy<Value = Txid> {
    arb_hash32().prop_map(Txid)
}

fn arb_script() -> impl Strategy<Value = Script> {
    prop::collection::vec(any::<u8>(), 0..40).prop_map(Script::new)
}

fn arb_amount() -> impl Strategy<Value = Amount> {
    prop_oneof![
        // The whole u64 range: a decoder must survive out-of-range values, it
        // is validation's job to reject them.
        any::<u64>(),
        0u64..=Amount::MAX_MONEY.to_grains(),
        Just(0u64),
        Just(Amount::MAX_MONEY.to_grains()),
    ]
    .prop_map(Amount::from_grains)
}

fn arb_outpoint() -> impl Strategy<Value = OutPoint> {
    prop_oneof![
        (arb_txid(), any::<u32>()).prop_map(|(txid, vout)| OutPoint { txid, vout }),
        Just(OutPoint::NULL),
    ]
}

fn arb_txin() -> impl Strategy<Value = TxIn> {
    (arb_outpoint(), arb_script(), any::<u32>()).prop_map(|(prev_out, script_sig, sequence)| TxIn {
        prev_out,
        script_sig,
        sequence,
    })
}

fn arb_txout() -> impl Strategy<Value = TxOut> {
    (arb_amount(), arb_script()).prop_map(|(value, script_pubkey)| TxOut { value, script_pubkey })
}

fn arb_transaction() -> impl Strategy<Value = Transaction> {
    (
        any::<u32>(),
        prop::collection::vec(arb_txin(), 0..4),
        prop::collection::vec(arb_txout(), 0..4),
        any::<u32>(),
    )
        .prop_map(|(version, inputs, outputs, lock_time)| Transaction {
            version,
            inputs,
            outputs,
            lock_time,
        })
}

fn arb_header() -> impl Strategy<Value = BlockHeader> {
    (any::<u32>(), arb_hash32(), arb_hash32(), any::<u64>(), any::<u32>(), any::<u64>()).prop_map(
        |(version, prev, root, timestamp_ms, bits, nonce)| BlockHeader {
            version,
            prev_hash: BlockHash(prev),
            merkle_root: root,
            timestamp_ms,
            bits: CompactTarget(bits),
            nonce,
        },
    )
}

fn arb_seal() -> impl Strategy<Value = BlockSeal> {
    (any::<u8>(), prop::collection::vec(any::<u8>(), 0..48))
        .prop_map(|(engine, data)| BlockSeal { engine, data })
}

fn arb_block() -> impl Strategy<Value = Block> {
    (arb_header(), prop::collection::vec(arb_transaction(), 0..3), arb_seal())
        .prop_map(|(header, txs, seal)| Block { header, txs, seal })
}

fn arb_coin() -> impl Strategy<Value = Coin> {
    (arb_amount(), arb_script(), any::<u64>(), any::<bool>()).prop_map(
        |(value, script_pubkey, height, is_coinbase)| Coin {
            value,
            script_pubkey,
            height,
            is_coinbase,
        },
    )
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

/// `decode(encode(v)) == v` and `encode(decode(b)) == b`, in one call.
fn assert_bijective<T>(value: &T) -> Result<(), TestCaseError>
where
    T: BorshSerialize + BorshDeserialize + PartialEq + std::fmt::Debug,
{
    let bytes = borsh::to_vec(value).unwrap();
    let decoded: T = borsh::from_slice(&bytes).unwrap();
    prop_assert_eq!(&decoded, value, "decode(encode(v)) != v");

    let reencoded = borsh::to_vec(&decoded).unwrap();
    prop_assert_eq!(reencoded, bytes, "encode(decode(b)) != b");
    Ok(())
}

/// A trailing byte must never be tolerated by any decoder in the crate.
fn assert_rejects_suffix<T>(value: &T) -> Result<(), TestCaseError>
where
    T: BorshSerialize + BorshDeserialize + std::fmt::Debug,
{
    let mut bytes = borsh::to_vec(value).unwrap();
    bytes.push(0);
    prop_assert!(
        borsh::from_slice::<T>(&bytes).is_err(),
        "a trailing byte was tolerated: that is a malleability bug"
    );
    Ok(())
}

// --------------------------------------------------------------------------
// bidirectional round-trips
// --------------------------------------------------------------------------

proptest! {
    #[test]
    fn hash32_is_bijective(h in arb_hash32()) {
        assert_bijective(&h)?;
        assert_rejects_suffix(&h)?;
    }

    #[test]
    fn outpoint_is_bijective(op in arb_outpoint()) {
        assert_bijective(&op)?;
        assert_rejects_suffix(&op)?;
        prop_assert_eq!(borsh::to_vec(&op).unwrap().len(), ferrum_types::OUTPOINT_SIZE);
    }

    #[test]
    fn script_is_bijective(s in arb_script()) {
        assert_bijective(&s)?;
        assert_rejects_suffix(&s)?;
    }

    #[test]
    fn transaction_is_bijective(tx in arb_transaction()) {
        assert_bijective(&tx)?;
        assert_rejects_suffix(&tx)?;
    }

    #[test]
    fn block_header_is_bijective(h in arb_header()) {
        assert_bijective(&h)?;
        assert_rejects_suffix(&h)?;
        prop_assert_eq!(borsh::to_vec(&h).unwrap().len(), ferrum_types::HEADER_SIZE);
    }

    #[test]
    fn block_is_bijective(b in arb_block()) {
        assert_bijective(&b)?;
        assert_rejects_suffix(&b)?;
    }

    #[test]
    fn coin_is_bijective(c in arb_coin()) {
        assert_bijective(&c)?;
        assert_rejects_suffix(&c)?;
    }

    #[test]
    fn block_seal_is_bijective(s in arb_seal()) {
        assert_bijective(&s)?;
        assert_rejects_suffix(&s)?;
    }

    // ----------------------------------------------------------------------
    // envelope round-trips
    // ----------------------------------------------------------------------

    #[test]
    fn envelope_is_bijective(tx in arb_transaction()) {
        let bytes = tx.encode_envelope();
        let decoded = Transaction::decode_envelope(&bytes).unwrap();
        prop_assert_eq!(&decoded, &tx);
        prop_assert_eq!(decoded.encode_envelope(), bytes);
    }

    #[test]
    fn envelope_rejects_any_suffix(tx in arb_transaction(), suffix in prop::collection::vec(any::<u8>(), 1..8)) {
        let mut bytes = tx.encode_envelope();
        bytes.extend_from_slice(&suffix);
        prop_assert!(Transaction::decode_envelope(&bytes).is_err());
    }

    #[test]
    fn envelope_rejects_every_non_zero_type_byte(tx in arb_transaction(), t in 1u8..=255) {
        let mut bytes = tx.encode_envelope();
        bytes[0] = t;
        prop_assert!(Transaction::decode_envelope(&bytes).is_err(), "type {} was accepted", t);
    }

    // ----------------------------------------------------------------------
    // the same property from the other end: arbitrary bytes
    // ----------------------------------------------------------------------

    /// Whatever a decoder *does* accept must re-encode to the exact same bytes.
    /// This is the direction that catches a tolerated redundant encoding.
    #[test]
    fn arbitrary_bytes_that_decode_re_encode_identically(
        raw in prop::collection::vec(any::<u8>(), 0..64)
    ) {
        if let Ok(tx) = Transaction::decode_envelope(&raw) {
            prop_assert_eq!(tx.encode_envelope(), raw.clone());
        }
        if let Ok(c) = borsh::from_slice::<Coin>(&raw) {
            prop_assert_eq!(borsh::to_vec(&c).unwrap(), raw.clone());
        }
        if let Ok(op) = borsh::from_slice::<OutPoint>(&raw) {
            prop_assert_eq!(borsh::to_vec(&op).unwrap(), raw.clone());
        }
        if let Ok(h) = borsh::from_slice::<BlockHeader>(&raw) {
            prop_assert_eq!(borsh::to_vec(&h).unwrap(), raw.clone());
        }
        if let Ok(b) = borsh::from_slice::<Block>(&raw) {
            prop_assert_eq!(borsh::to_vec(&b).unwrap(), raw);
        }
    }

    /// Decoding must never panic, whatever the input. The workspace fuzz
    /// target covers this properly; this is the cheap in-tree version.
    #[test]
    fn decoding_never_panics(raw in prop::collection::vec(any::<u8>(), 0..128)) {
        let _ = Transaction::decode_envelope(&raw);
        let _ = borsh::from_slice::<Transaction>(&raw);
        let _ = borsh::from_slice::<Block>(&raw);
        let _ = borsh::from_slice::<BlockHeader>(&raw);
        let _ = borsh::from_slice::<Coin>(&raw);
        let _ = borsh::from_slice::<OutPoint>(&raw);
        let _ = borsh::from_slice::<Script>(&raw);
    }

    // ----------------------------------------------------------------------
    // sizes are computed, not guessed
    // ----------------------------------------------------------------------

    #[test]
    fn transaction_serialized_size_is_exact(tx in arb_transaction()) {
        prop_assert_eq!(tx.serialized_size(), tx.encode_envelope().len());
    }

    #[test]
    fn block_serialized_size_is_exact(b in arb_block()) {
        prop_assert_eq!(b.serialized_size(), borsh::to_vec(&b).unwrap().len());
    }

    #[test]
    fn header_manual_encoding_equals_borsh(h in arb_header()) {
        prop_assert_eq!(h.encode().to_vec(), borsh::to_vec(&h).unwrap());
        prop_assert_eq!(BlockHeader::from_bytes(&h.encode()), h);
    }

    // ----------------------------------------------------------------------
    // serde round-trips, for the RPC surface
    // ----------------------------------------------------------------------

    #[test]
    fn serde_json_round_trips(b in arb_block(), c in arb_coin()) {
        let j = serde_json::to_string(&b).unwrap();
        prop_assert_eq!(serde_json::from_str::<Block>(&j).unwrap(), b);
        let j = serde_json::to_string(&c).unwrap();
        prop_assert_eq!(serde_json::from_str::<Coin>(&j).unwrap(), c);
    }

    #[test]
    fn hash_text_round_trips(h in arb_hash32()) {
        prop_assert_eq!(Hash32::from_hex(&h.to_hex()).unwrap(), h);
        prop_assert_eq!(h.to_hex().parse::<Hash32>().unwrap(), h);
        prop_assert_eq!(h.to_hex().len(), 64);
    }

    #[test]
    fn script_hex_round_trips(s in arb_script()) {
        prop_assert_eq!(Script::from_hex(&s.to_hex()).unwrap(), s.clone());
        prop_assert_eq!(s.to_hex().len(), s.len() * 2);
    }
}
