//! Frozen vectors.
//!
//! The sighash preimage and the standard templates are consensus surface: a
//! refactor that changes a single byte of either is a hard fork. These vectors
//! were generated once from this implementation and are checked in, so the next
//! change to `sighash.rs` or `templates.rs` has to be deliberate rather than
//! accidental.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::script;
use ferrum_script::sighash::{SigHashType, sighash_preimage, signature_hash};
use ferrum_script::templates;
use ferrum_types::{Amount, ChainId, Hash32, OutPoint, Script, Transaction, TxIn, TxOut, Txid};

/// The transaction every vector below is taken over: two inputs, two outputs,
/// two different sequences and a non-zero lock time, so no field can be dropped
/// from the preimage without a vector changing.
fn vector_tx() -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![
            TxIn {
                prev_out: OutPoint::new(Txid::from_bytes([0x11; 32]), 0),
                script_sig: Script::EMPTY,
                sequence: 0xffff_fffe,
            },
            TxIn {
                prev_out: OutPoint::new(Txid::from_bytes([0x22; 32]), 7),
                script_sig: Script::EMPTY,
                sequence: 0x0000_000a,
            },
        ],
        outputs: vec![
            TxOut::new(Amount::from_grains(50_000), script(&[0x51])),
            TxOut::new(Amount::from_grains(25_000), script(&[0x52, 0x53])),
        ],
        lock_time: 600_000,
    }
}

const SCRIPT_CODE: &[u8] = &[0x76, 0xa9, 0x14];
const VALUE: Amount = Amount::from_grains(123_456_789);

/// `(sighash type byte, digest)` for [`vector_tx`] input 0 on mainnet.
const SIGHASH_VECTORS: [(u8, &str); 6] = [
    (0x01, "6873292ae7e6c3d3c291c5c83627c7a40d45286e7ce7e614b68962a519107ef4"),
    (0x02, "7002919106eb973163611c23dc4e184d54a96c9a33fc1956221d9a172c2d33d3"),
    (0x03, "254b35a5b6acdbbd89465b2b351169e2c25dbd0b61e1a9aa58e94dcb9794d5f5"),
    (0x81, "1a593c1af975ae107680cd163e561a0621a991e8e43b65c2fb0ab8546aa88ea8"),
    (0x82, "f6e0a8746b7b54e2df5413cf296f31fbc5841f3beabb0079ef9c6cd484711018"),
    (0x83, "6513db89fae9be5e40bf47135bb925252eba599c9baf1f60f94f10352716a416"),
];

fn digest(ty: SigHashType, chain: ChainId) -> String {
    signature_hash(&vector_tx(), 0, SCRIPT_CODE, VALUE, chain, ty).unwrap().to_hex()
}

#[test]
fn the_sighash_preimage_is_frozen() {
    let pre =
        sighash_preimage(&vector_tx(), 0, SCRIPT_CODE, VALUE, ChainId::MAINNET, SigHashType::ALL)
            .unwrap();
    assert_eq!(pre.len(), 168, "165 fixed bytes plus a 3-byte script_code");
    assert_eq!(
        hex::encode(&pre),
        concat!(
            "01000000",                                                         // chain_id
            "02000000",                                                         // tx version
            "a6904f2fbc50a9180d8f44b58851191cf57a038ee7276519166174813a18424a", // prevouts
            "88dcac1c9a27fe4677a82cdaac56ca2fc948eacfb0da8c48284ff63703db914b", // sequences
            "00000000",                                                         // input index
            "1111111111111111111111111111111111111111111111111111111111111111", // outpoint txid
            "00000000",                                                         // outpoint vout
            "03000000",                                                         // script_code len
            "76a914",                                                           // script_code
            "15cd5b0700000000",                                                 // input value
            "feffffff",                                                         // input sequence
            "1e14ffc6b34fbe02617a3417ae77910cd9709aeb3c3ea905c7228d056d691db8", // outputs
            "c0270900",                                                         // lock_time
            "01",                                                               // sighash type
        )
    );
}

#[test]
fn every_sighash_type_has_a_frozen_digest() {
    for (byte, expected) in SIGHASH_VECTORS {
        let ty = SigHashType::from_byte(byte).unwrap();
        assert_eq!(digest(ty, ChainId::MAINNET), expected, "sighash type 0x{byte:02x}");
    }
}

#[test]
fn the_frozen_digests_are_pairwise_distinct() {
    let mut seen: Vec<&str> = SIGHASH_VECTORS.iter().map(|(_, d)| *d).collect();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(seen.len(), before);
}

#[test]
fn the_same_transaction_hashes_differently_on_every_chain() {
    let mainnet = digest(SigHashType::ALL, ChainId(1));
    let testnet = digest(SigHashType::ALL, ChainId(2));
    let devnet = digest(SigHashType::ALL, ChainId(3));
    assert_ne!(mainnet, testnet);
    assert_ne!(testnet, devnet);
    assert_ne!(mainnet, devnet);
}

#[test]
fn the_second_input_hashes_differently_from_the_first() {
    let first = digest(SigHashType::ALL, ChainId::MAINNET);
    let second =
        signature_hash(&vector_tx(), 1, SCRIPT_CODE, VALUE, ChainId::MAINNET, SigHashType::ALL)
            .unwrap()
            .to_hex();
    assert_ne!(first, second);
}

#[test]
fn template_bytes_are_frozen() {
    assert_eq!(
        templates::p2pkh(&[0xab; 20]).to_hex(),
        "76a914abababababababababababababababababababab88ac"
    );
    assert_eq!(
        templates::p2sh(&Hash32::from_bytes([0xcd; 32])).to_hex(),
        "aa20cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd87"
    );
    assert_eq!(templates::op_return(b"hi").unwrap().to_hex(), "6a026869");
}

#[test]
fn the_cltv_and_htlc_templates_are_frozen() {
    assert_eq!(
        templates::cltv_p2pkh(600_000, &[0x01; 20]).to_hex(),
        "03c02709b17576a914010101010101010101010101010101010101010188ac"
    );
    assert_eq!(
        templates::htlc(&[0x02; 20], &[0x03; 20], 600_000, &[0x04; 20]).to_hex(),
        concat!(
            "63", // OP_IF
            "a914",
            "0202020202020202020202020202020202020202",
            "88", // hash branch
            "76a914",
            "0303030303030303030303030303030303030303",
            "88ac",
            "67", // OP_ELSE
            "03c02709",
            "b1",
            "75", // <600000> OP_CLTV OP_DROP
            "76a914",
            "0404040404040404040404040404040404040404",
            "88ac",
            "68", // OP_ENDIF
        )
    );
}

#[test]
fn a_p2pk_script_is_the_key_then_checksig() {
    let pk = common::public(1);
    assert_eq!(templates::p2pk(&pk).to_hex(), format!("20{}ac", pk.to_hex()));
}
