//! The canonical-encoding rules of CONTRACT §2, pinned byte for byte.
//!
//! These are the tests that would fail if someone swapped a codec, changed a
//! field order, or reordered a struct. Everything here is a hand-written
//! expectation, not a round-trip: a round-trip is happy to agree with itself
//! about the wrong layout.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use ferrum_types::{
    Amount, Block, BlockHash, BlockHeader, BlockSeal, Coin, CompactTarget, HEADER_SIZE, Hash32,
    LOCKTIME_THRESHOLD, Network, OUTPOINT_SIZE, OutPoint, Script, TX_TYPE_STANDARD, Transaction,
    TxIn, TxOut, Txid,
};

/// FNV-1a, so "the hash of the bytes" needs no dependency and is itself
/// deterministic across runs and platforms.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Rebuilt from scratch on every call: fresh allocations, so nothing about the
/// memory layout of a previous copy can leak into the encoding.
fn sample_tx() -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![
            TxIn {
                prev_out: OutPoint::new(Txid::from_bytes([0x11; 32]), 7),
                script_sig: Script::new(vec![0x48, 0x30, 0x45]),
                sequence: 0xffff_fffe,
            },
            TxIn { prev_out: OutPoint::NULL, script_sig: Script::EMPTY, sequence: u32::MAX },
        ],
        outputs: vec![
            TxOut::new(Amount::from_grains(1_234_567_890), Script::new(vec![0x76, 0xa9])),
            TxOut::new(Amount::ZERO, Script::EMPTY),
        ],
        lock_time: 500_000_123,
    }
}

fn sample_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_hash: BlockHash::from_bytes([0x0a; 32]),
        merkle_root: Hash32::from_bytes([0x0b; 32]),
        timestamp_ms: 1_735_689_600_000,
        bits: CompactTarget(0x1d00_ffff),
        nonce: 42,
    }
}

// --------------------------------------------------------------------------
// §2.2 header layout
// --------------------------------------------------------------------------

#[test]
fn header_is_exactly_88_bytes() {
    assert_eq!(HEADER_SIZE, 88);
    assert_eq!(borsh::to_vec(&sample_header()).unwrap().len(), 88);
}

#[test]
fn header_field_offsets_are_the_contract_table() {
    // Hand-built bytes, decoded: this pins every offset and every width.
    let mut raw = [0u8; HEADER_SIZE];
    raw[0..4].copy_from_slice(&7u32.to_le_bytes()); // version
    raw[4..36].copy_from_slice(&[0xa1; 32]); // prev_hash
    raw[36..68].copy_from_slice(&[0xb2; 32]); // merkle_root
    raw[68..76].copy_from_slice(&1_700_000_000_000u64.to_le_bytes()); // timestamp_ms
    raw[76..80].copy_from_slice(&0x1c0f_ffffu32.to_le_bytes()); // bits
    raw[80..88].copy_from_slice(&0xdead_beef_0000_0001u64.to_le_bytes()); // nonce

    let h: BlockHeader = borsh::from_slice(&raw).unwrap();
    assert_eq!(h.version, 7);
    assert_eq!(h.prev_hash, BlockHash::from_bytes([0xa1; 32]));
    assert_eq!(h.merkle_root, Hash32::from_bytes([0xb2; 32]));
    assert_eq!(h.timestamp_ms, 1_700_000_000_000);
    assert_eq!(h.bits, CompactTarget(0x1c0f_ffff));
    assert_eq!(h.nonce, 0xdead_beef_0000_0001);

    // And back out again, byte for byte.
    assert_eq!(borsh::to_vec(&h).unwrap(), raw.to_vec());
    assert_eq!(h.encode(), raw);
    assert_eq!(BlockHeader::from_bytes(&raw), h);
}

#[test]
fn header_integers_are_little_endian() {
    let h = BlockHeader {
        version: 0x0403_0201,
        prev_hash: BlockHash::ZERO,
        merkle_root: Hash32::ZERO,
        timestamp_ms: 0x0807_0605_0403_0201,
        bits: CompactTarget(0x0403_0201),
        nonce: 0x0807_0605_0403_0201,
    };
    let b = borsh::to_vec(&h).unwrap();
    assert_eq!(&b[0..4], &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(&b[68..76], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&b[76..80], &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(&b[80..88], &[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn hashes_carry_no_length_prefix() {
    // 32 raw bytes, not `u32 length || bytes`.
    let b = borsh::to_vec(&Hash32::from_bytes([9; 32])).unwrap();
    assert_eq!(b, vec![9u8; 32]);
}

// --------------------------------------------------------------------------
// §2 borsh rules
// --------------------------------------------------------------------------

#[test]
fn vectors_are_a_u32_le_length_then_elements() {
    let s = Script::new(vec![0xaa, 0xbb, 0xcc]);
    assert_eq!(borsh::to_vec(&s).unwrap(), vec![3, 0, 0, 0, 0xaa, 0xbb, 0xcc]);

    let seal = BlockSeal::bft(vec![1, 2]);
    assert_eq!(borsh::to_vec(&seal).unwrap(), vec![1, 2, 0, 0, 0, 1, 2]);
}

#[test]
fn newtypes_encode_exactly_as_their_inner_field() {
    let h = Hash32::from_bytes([3; 32]);
    assert_eq!(borsh::to_vec(&BlockHash(h)).unwrap(), borsh::to_vec(&h).unwrap());
    assert_eq!(borsh::to_vec(&Txid(h)).unwrap(), borsh::to_vec(&h).unwrap());
    assert_eq!(borsh::to_vec(&Amount::from_grains(1)).unwrap(), borsh::to_vec(&1u64).unwrap());
    assert_eq!(borsh::to_vec(&CompactTarget(1)).unwrap(), borsh::to_vec(&1u32).unwrap());
}

#[test]
fn enums_are_a_u8_discriminant() {
    assert_eq!(borsh::to_vec(&Network::Mainnet).unwrap(), vec![0]);
    assert_eq!(borsh::to_vec(&Network::Testnet).unwrap(), vec![1]);
    assert_eq!(borsh::to_vec(&Network::Devnet).unwrap(), vec![2]);
    // An out-of-range discriminant is rejected, not silently mapped.
    assert!(borsh::from_slice::<Network>(&[3]).is_err());
}

#[test]
fn options_are_a_zero_or_one_tag() {
    assert_eq!(borsh::to_vec(&None::<u64>).unwrap(), vec![0]);
    assert_eq!(borsh::to_vec(&Some(1u64)).unwrap(), vec![1, 1, 0, 0, 0, 0, 0, 0, 0]);
    assert!(borsh::from_slice::<Option<u64>>(&[2, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
}

#[test]
fn booleans_reject_anything_but_zero_or_one() {
    let coin =
        Coin { value: Amount::ZERO, script_pubkey: Script::EMPTY, height: 0, is_coinbase: true };
    let mut b = borsh::to_vec(&coin).unwrap();
    assert_eq!(*b.last().unwrap(), 1);
    *b.last_mut().unwrap() = 2;
    assert!(borsh::from_slice::<Coin>(&b).is_err(), "a non-canonical bool must be rejected");
}

// --------------------------------------------------------------------------
// §2.1 the transaction envelope
// --------------------------------------------------------------------------

#[test]
fn envelope_is_the_type_byte_then_the_body() {
    let tx = sample_tx();
    let e = tx.encode_envelope();
    assert_eq!(e[0], TX_TYPE_STANDARD);
    assert_eq!(e[0], 0x00);
    assert_eq!(&e[1..], borsh::to_vec(&tx).unwrap().as_slice());
    assert_eq!(e.len(), tx.serialized_size());
}

#[test]
fn envelope_body_layout_is_pinned() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint::new(Txid::from_bytes([0xcc; 32]), 1),
            script_sig: Script::new(vec![0x51]),
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOut::new(Amount::from_grains(2), Script::new(vec![0x52]))],
        lock_time: 3,
    };
    let mut want = vec![TX_TYPE_STANDARD];
    want.extend_from_slice(&1u32.to_le_bytes()); // version
    want.extend_from_slice(&1u32.to_le_bytes()); // input count
    want.extend_from_slice(&[0xcc; 32]); // prev txid
    want.extend_from_slice(&1u32.to_le_bytes()); // prev vout
    want.extend_from_slice(&1u32.to_le_bytes()); // script_sig length
    want.push(0x51);
    want.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
    want.extend_from_slice(&1u32.to_le_bytes()); // output count
    want.extend_from_slice(&2u64.to_le_bytes()); // value
    want.extend_from_slice(&1u32.to_le_bytes()); // script_pubkey length
    want.push(0x52);
    want.extend_from_slice(&3u32.to_le_bytes()); // lock_time

    assert_eq!(tx.encode_envelope(), want);
    assert_eq!(Transaction::decode_envelope(&want).unwrap(), tx);
}

#[test]
fn decode_envelope_rejects_a_single_trailing_zero_byte() {
    // The exact case named by the contract: valid_bytes ++ [0u8].
    let valid = sample_tx().encode_envelope();
    assert!(Transaction::decode_envelope(&valid).is_ok());

    let mut with_suffix = valid.clone();
    with_suffix.push(0u8);
    assert!(
        Transaction::decode_envelope(&with_suffix).is_err(),
        "tolerating a suffix would make the txid malleable"
    );

    // Any suffix, of any length, on any type.
    for suffix in [vec![0u8], vec![0xff], vec![0u8; 32], vec![1, 2, 3]] {
        let mut b = valid.clone();
        b.extend_from_slice(&suffix);
        assert!(Transaction::decode_envelope(&b).is_err());
    }
}

#[test]
fn every_reserved_and_unknown_type_byte_is_rejected() {
    let body = borsh::to_vec(&sample_tx()).unwrap();
    for t in 0x01u8..=0xff {
        let mut b = vec![t];
        b.extend_from_slice(&body);
        assert!(
            Transaction::decode_envelope(&b).is_err(),
            "type byte {t:#04x} must be rejected in v1"
        );
    }
    // ... and 0x00 is accepted.
    let mut ok = vec![0x00u8];
    ok.extend_from_slice(&body);
    assert!(Transaction::decode_envelope(&ok).is_ok());
}

#[test]
fn other_decoders_reject_trailing_bytes_too() {
    let block = Block::new(sample_header(), vec![sample_tx()], BlockSeal::POW);
    let coin = Coin::new(TxOut::new(Amount::ONE_FRM, Script::new(vec![1])), 5, false);
    let op = OutPoint::new(Txid::from_bytes([1; 32]), 0);

    let mut b = borsh::to_vec(&block).unwrap();
    b.push(0);
    assert!(borsh::from_slice::<Block>(&b).is_err());

    let mut c = borsh::to_vec(&coin).unwrap();
    c.push(0);
    assert!(borsh::from_slice::<Coin>(&c).is_err());

    let mut o = borsh::to_vec(&op).unwrap();
    o.push(0);
    assert!(borsh::from_slice::<OutPoint>(&o).is_err());

    let mut h = borsh::to_vec(&sample_header()).unwrap();
    h.push(0);
    assert!(borsh::from_slice::<BlockHeader>(&h).is_err());
}

// --------------------------------------------------------------------------
// determinism
// --------------------------------------------------------------------------

#[test]
fn encoding_the_same_transaction_1000_times_yields_one_hash() {
    let mut hashes = BTreeSet::new();
    let mut byte_strings = BTreeSet::new();
    for _ in 0..1000 {
        // Rebuilt every iteration, so allocation addresses, capacities and
        // iteration order all get a chance to leak in. None may.
        let bytes = sample_tx().encode_envelope();
        hashes.insert(fnv1a(&bytes));
        byte_strings.insert(bytes);
    }
    assert_eq!(hashes.len(), 1, "encoding is not deterministic");
    assert_eq!(byte_strings.len(), 1);
}

#[test]
fn encoding_a_block_is_deterministic() {
    let mut hashes = BTreeSet::new();
    for _ in 0..1000 {
        let block = Block::new(sample_header(), vec![sample_tx(), sample_tx()], BlockSeal::POW);
        hashes.insert(fnv1a(&borsh::to_vec(&block).unwrap()));
    }
    assert_eq!(hashes.len(), 1);
}

#[test]
fn distinct_transactions_encode_distinctly() {
    // The dual of the determinism test: the encoding must actually depend on
    // the value, or the test above proves nothing.
    let mut hashes = BTreeSet::new();
    for lock_time in 0u32..64 {
        let mut tx = sample_tx();
        tx.lock_time = lock_time;
        hashes.insert(fnv1a(&tx.encode_envelope()));
    }
    assert_eq!(hashes.len(), 64);
}

// --------------------------------------------------------------------------
// constants
// --------------------------------------------------------------------------

#[test]
fn contract_constants() {
    assert_eq!(TX_TYPE_STANDARD, 0x00);
    assert_eq!(LOCKTIME_THRESHOLD, 500_000_000);
    assert_eq!(OUTPOINT_SIZE, 36);
    assert_eq!(HEADER_SIZE, 88);
    assert_eq!(ferrum_types::COIN, 100_000_000);
    assert_eq!(ferrum_types::MAX_MONEY, Amount::MAX_MONEY);
    assert_eq!(BlockSeal::ENGINE_POW, 0);
    assert_eq!(BlockSeal::ENGINE_BFT, 1);
    assert_eq!(borsh::to_vec(&OutPoint::NULL).unwrap().len(), OUTPOINT_SIZE);
}

#[test]
fn a_coinbase_envelope_round_trips_through_every_layer() {
    let cb = Transaction {
        version: 1,
        inputs: vec![TxIn::coinbase(Script::new(vec![0x03, 0x01, 0x02, 0x03]))],
        outputs: vec![TxOut::new(Amount::from_frm_str("50").unwrap(), Script::new(vec![0x51]))],
        lock_time: 0,
    };
    assert!(cb.is_coinbase());
    let block = Block::new(sample_header(), vec![cb.clone()], BlockSeal::POW);
    assert_eq!(block.coinbase(), Some(&cb));

    let bytes = borsh::to_vec(&block).unwrap();
    assert_eq!(bytes.len(), block.serialized_size());
    let back: Block = borsh::from_slice(&bytes).unwrap();
    assert_eq!(back, block);
    assert_eq!(borsh::to_vec(&back).unwrap(), bytes);
    assert_eq!(back.coinbase().unwrap().total_output(), Some(Amount::from_grains(5_000_000_000)));
}
