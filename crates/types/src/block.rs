//! Block headers, seals and blocks.
//!
//! # The 88-byte header (CONTRACT §2.2)
//!
//! | Offset | Size | Field | Type |
//! |---|---|---|---|
//! | 0  | 4  | `version`      | `u32` LE |
//! | 4  | 32 | `prev_hash`    | `[u8;32]` |
//! | 36 | 32 | `merkle_root`  | `[u8;32]` |
//! | 68 | 8  | `timestamp_ms` | `u64` LE |
//! | 76 | 4  | `bits`         | `u32` LE |
//! | 80 | 8  | `nonce`        | `u64` LE |
//!
//! `timestamp_ms` is milliseconds because Bitcoin's `u32` seconds field
//! overflows in 2106 (DECISIONS D4). Median-time-past and locktime comparisons
//! are still done in seconds, because CLTV/CSV semantics are defined that way.
//!
//! # Why the seal is outside the header
//!
//! A BFT commit certificate is formed *after* the header exists and cannot
//! commit to itself. Keeping it in [`Block::seal`], outside both the header
//! and `merkle_root`, means the block hash is identical no matter which
//! `2f + 1` subset of signatures a node happened to collect (DECISIONS D2).

use std::fmt;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::error::TypeError;
use crate::hash::{BlockHash, HASH_LEN, Hash32};
use crate::tx::Transaction;

/// Borsh-encoded size of a [`BlockHeader`], in bytes. Frozen by consensus.
pub const HEADER_SIZE: usize = 88;

/// A difficulty target in Bitcoin's 32-bit compact encoding: `0xEEMMMMMM`,
/// where `EE` is the size in bytes and `MMMMMM` a 24-bit mantissa.
///
/// Expansion, validation and the canonical round-trip live in
/// `ferrum-consensus`; this crate only carries the value.
#[derive(
    Clone,
    Copy,
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
pub struct CompactTarget(pub u32);

impl CompactTarget {
    /// Wrap a raw compact value.
    pub const fn from_u32(v: u32) -> Self {
        CompactTarget(v)
    }

    /// The raw compact value.
    pub const fn to_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for CompactTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

impl fmt::Debug for CompactTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CompactTarget({:#010x})", self.0)
    }
}

impl fmt::LowerHex for CompactTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl FromStr for CompactTarget {
    type Err = TypeError;

    /// `0x`-prefixed input is hex; anything else is decimal. Being explicit
    /// avoids the classic "is 100 a hundred or 256?" bug in config files.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Some(hex) => u32::from_str_radix(hex, 16),
            None => s.parse::<u32>(),
        };
        parsed.map(CompactTarget).map_err(|_| TypeError::InvalidHex(s.to_owned()))
    }
}

impl From<u32> for CompactTarget {
    fn from(v: u32) -> Self {
        CompactTarget(v)
    }
}

impl From<CompactTarget> for u32 {
    fn from(c: CompactTarget) -> Self {
        c.0
    }
}

/// The 88-byte block header.
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
pub struct BlockHeader {
    /// Block version.
    pub version: u32,
    /// Hash of the parent header; `BlockHash::ZERO` for genesis.
    pub prev_hash: BlockHash,
    /// Merkle root over the transaction ids in this block.
    pub merkle_root: Hash32,
    /// Block time, Unix **milliseconds**.
    pub timestamp_ms: u64,
    /// Compact difficulty target.
    pub bits: CompactTarget,
    /// Proof-of-work nonce. Unused (and conventionally zero) under BFT.
    pub nonce: u64,
}

impl BlockHeader {
    /// Byte offset of each field, for documentation and for tests.
    pub const OFFSET_VERSION: usize = 0;
    /// Byte offset of `prev_hash`.
    pub const OFFSET_PREV_HASH: usize = 4;
    /// Byte offset of `merkle_root`.
    pub const OFFSET_MERKLE_ROOT: usize = 36;
    /// Byte offset of `timestamp_ms`.
    pub const OFFSET_TIMESTAMP_MS: usize = 68;
    /// Byte offset of `bits`.
    pub const OFFSET_BITS: usize = 76;
    /// Byte offset of `nonce`.
    pub const OFFSET_NONCE: usize = 80;

    /// The canonical 88-byte encoding — identical to `borsh::to_vec`, but
    /// without the allocation, because this is the block-hash preimage and is
    /// recomputed for every nonce a miner tries.
    ///
    /// A proptest pins it to the Borsh output.
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[Self::OFFSET_VERSION..Self::OFFSET_PREV_HASH]
            .copy_from_slice(&self.version.to_le_bytes());
        out[Self::OFFSET_PREV_HASH..Self::OFFSET_MERKLE_ROOT]
            .copy_from_slice(self.prev_hash.as_bytes());
        out[Self::OFFSET_MERKLE_ROOT..Self::OFFSET_TIMESTAMP_MS]
            .copy_from_slice(self.merkle_root.as_bytes());
        out[Self::OFFSET_TIMESTAMP_MS..Self::OFFSET_BITS]
            .copy_from_slice(&self.timestamp_ms.to_le_bytes());
        out[Self::OFFSET_BITS..Self::OFFSET_NONCE]
            .copy_from_slice(&self.bits.to_u32().to_le_bytes());
        out[Self::OFFSET_NONCE..HEADER_SIZE].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Decode the canonical 88-byte encoding. Infallible: every 88-byte string
    /// is a well-formed header, though not necessarily a *valid* one.
    pub fn from_bytes(b: &[u8; HEADER_SIZE]) -> Self {
        let mut u32_buf = [0u8; 4];
        let mut u64_buf = [0u8; 8];
        let mut hash_buf = [0u8; HASH_LEN];

        u32_buf.copy_from_slice(&b[Self::OFFSET_VERSION..Self::OFFSET_PREV_HASH]);
        let version = u32::from_le_bytes(u32_buf);

        hash_buf.copy_from_slice(&b[Self::OFFSET_PREV_HASH..Self::OFFSET_MERKLE_ROOT]);
        let prev_hash = BlockHash::from_bytes(hash_buf);

        hash_buf.copy_from_slice(&b[Self::OFFSET_MERKLE_ROOT..Self::OFFSET_TIMESTAMP_MS]);
        let merkle_root = Hash32::from_bytes(hash_buf);

        u64_buf.copy_from_slice(&b[Self::OFFSET_TIMESTAMP_MS..Self::OFFSET_BITS]);
        let timestamp_ms = u64::from_le_bytes(u64_buf);

        u32_buf.copy_from_slice(&b[Self::OFFSET_BITS..Self::OFFSET_NONCE]);
        let bits = CompactTarget(u32::from_le_bytes(u32_buf));

        u64_buf.copy_from_slice(&b[Self::OFFSET_NONCE..HEADER_SIZE]);
        let nonce = u64::from_le_bytes(u64_buf);

        BlockHeader { version, prev_hash, merkle_root, timestamp_ms, bits, nonce }
    }

    /// Block time in **seconds**, truncating. Median-time-past, `lock_time`
    /// and CLTV all compare in seconds.
    pub const fn timestamp_s(&self) -> u64 {
        self.timestamp_ms / 1_000
    }
}

/// The consensus-engine seal, carried outside the header.
#[derive(
    Clone,
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
pub struct BlockSeal {
    /// Which engine sealed the block: [`BlockSeal::ENGINE_POW`] or
    /// [`BlockSeal::ENGINE_BFT`].
    pub engine: u8,
    /// Engine payload: empty for PoW, `borsh(BftCommit)` for BFT.
    pub data: Vec<u8>,
}

impl BlockSeal {
    /// Proof of work: the nonce in the header is the whole seal.
    pub const ENGINE_POW: u8 = 0;
    /// Tendermint-shaped BFT: `data` is a `borsh(BftCommit)` certificate.
    pub const ENGINE_BFT: u8 = 1;

    /// The PoW seal: engine 0, no data.
    pub const POW: BlockSeal = BlockSeal { engine: Self::ENGINE_POW, data: Vec::new() };

    /// A BFT seal carrying an encoded commit certificate.
    pub fn bft(data: Vec<u8>) -> Self {
        BlockSeal { engine: Self::ENGINE_BFT, data }
    }

    /// Borsh-encoded size: `u8 engine || u32 length || data`.
    pub(crate) fn borsh_size(&self) -> usize {
        5usize.saturating_add(self.data.len())
    }

    /// Fixed part of a `borsh(BftCommit)`: `height` (8) + `round` (4) +
    /// `block_hash` (32) + the `u32` length of the signature vector.
    pub const BFT_COMMIT_FIXED: usize = 48;

    /// One `(u16 index, 64-byte Signature)` entry of a commit certificate.
    pub const BFT_COMMIT_PER_SIGNATURE: usize = 66;

    /// The largest `data` a legal commit certificate for `validators`
    /// validators can encode to.
    ///
    /// `verify_commit` accepts anywhere from `quorum` to `n` signatures — the
    /// indices only have to be strictly ascending and known — so the bound is
    /// `n`, not the quorum. It is what the block-size rule uses to bound the
    /// seal *separately* from the transactions: the seal is outside everything
    /// the block hash commits to (DECISIONS D2), so it must not be able to
    /// change whether the block fits (DECISIONS D12).
    #[must_use]
    pub const fn max_data_len(validators: usize) -> usize {
        Self::BFT_COMMIT_FIXED
            .saturating_add(Self::BFT_COMMIT_PER_SIGNATURE.saturating_mul(validators))
    }
}

/// A block: header, transactions, and the engine seal.
#[derive(
    Clone,
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
pub struct Block {
    /// The 88-byte header.
    pub header: BlockHeader,
    /// Transactions, coinbase first. The order is committed to by
    /// `header.merkle_root`.
    pub txs: Vec<Transaction>,
    /// The consensus-engine seal.
    pub seal: BlockSeal,
}

impl Block {
    /// Build a block.
    pub fn new(header: BlockHeader, txs: Vec<Transaction>, seal: BlockSeal) -> Self {
        Block { header, txs, seal }
    }

    /// The coinbase transaction: `txs[0]`, but only if it really is one.
    pub fn coinbase(&self) -> Option<&Transaction> {
        self.txs.first().filter(|t| t.is_coinbase())
    }

    /// Size in bytes of `borsh(self)`.
    ///
    /// Note this counts each transaction's *body*, not its envelope: a block
    /// encodes `Vec<Transaction>`, and the type byte lives only in the
    /// standalone wire/txid form. Computed arithmetically because block
    /// assembly checks it against `max_block_size` after every added
    /// transaction; a proptest pins it to `borsh::to_vec(self).len()`.
    pub fn serialized_size(&self) -> usize {
        // header || u32 tx count || txs || seal
        let mut n = HEADER_SIZE.saturating_add(4).saturating_add(self.seal.borsh_size());
        for tx in &self.txs {
            n = n.saturating_add(tx.borsh_size());
        }
        n
    }

    /// Size of everything the block hash commits to: header, transaction count
    /// and transactions, **without the seal**.
    ///
    /// This is what the block-size rule measures (SPEC §3.1 rule 1). The seal
    /// is deliberately outside the header and the merkle root (DECISIONS D2)
    /// and a BFT certificate legally carries anywhere from `quorum` to `n`
    /// signatures, so counting it would make one block hash have several sizes
    /// — and whether the block fit `max_block_size` would depend on which copy
    /// a node received. The seal is bounded on its own instead, by
    /// [`BlockSeal::max_data_len`] (DECISIONS D12).
    pub fn consensus_size(&self) -> usize {
        let mut n = HEADER_SIZE.saturating_add(4);
        for tx in &self.txs {
            n = n.saturating_add(tx.borsh_size());
        }
        n
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::amount::Amount;
    use crate::script::Script;
    use crate::tx::{OutPoint, TxIn, TxOut};

    fn header() -> BlockHeader {
        BlockHeader {
            version: 0x0102_0304,
            prev_hash: BlockHash::from_bytes([0xaa; 32]),
            merkle_root: Hash32::from_bytes([0xbb; 32]),
            timestamp_ms: 0x1122_3344_5566_7788,
            bits: CompactTarget(0x1d00_ffff),
            nonce: 0x99aa_bbcc_ddee_ff00,
        }
    }

    fn coinbase() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(Script::new(vec![0x01, 0x00]))],
            outputs: vec![TxOut::new(Amount::from_grains(5_000_000_000), Script::new(vec![0x51]))],
            lock_time: 0,
        }
    }

    fn spend() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn::new(
                OutPoint::new(crate::hash::Txid::from_bytes([7; 32]), 1),
                Script::new(vec![0x52]),
            )],
            outputs: vec![TxOut::new(Amount::from_grains(1), Script::EMPTY)],
            lock_time: 0,
        }
    }

    #[test]
    fn header_is_exactly_eighty_eight_borsh_bytes() {
        assert_eq!(HEADER_SIZE, 88);
        assert_eq!(borsh::to_vec(&header()).unwrap().len(), 88);
        assert_eq!(borsh::to_vec(&BlockHeader::default()).unwrap().len(), 88);
    }

    #[test]
    fn header_field_offsets_match_the_contract_table() {
        // Hand-build the 88 bytes, then decode: this pins every offset.
        let mut raw = [0u8; HEADER_SIZE];
        raw[0..4].copy_from_slice(&0x0102_0304u32.to_le_bytes());
        raw[4..36].copy_from_slice(&[0xaa; 32]);
        raw[36..68].copy_from_slice(&[0xbb; 32]);
        raw[68..76].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        raw[76..80].copy_from_slice(&0x1d00_ffffu32.to_le_bytes());
        raw[80..88].copy_from_slice(&0x99aa_bbcc_ddee_ff00u64.to_le_bytes());

        let decoded: BlockHeader = borsh::from_slice(&raw).unwrap();
        assert_eq!(decoded, header());
        assert_eq!(decoded.version, 0x0102_0304);
        assert_eq!(decoded.prev_hash.as_bytes(), &[0xaa; 32]);
        assert_eq!(decoded.merkle_root.as_bytes(), &[0xbb; 32]);
        assert_eq!(decoded.timestamp_ms, 0x1122_3344_5566_7788);
        assert_eq!(decoded.bits, CompactTarget(0x1d00_ffff));
        assert_eq!(decoded.nonce, 0x99aa_bbcc_ddee_ff00);

        // ... and re-encoding reproduces the exact bytes.
        assert_eq!(borsh::to_vec(&decoded).unwrap(), raw.to_vec());
    }

    #[test]
    fn integers_in_the_header_are_little_endian() {
        let h = BlockHeader { version: 1, ..BlockHeader::default() };
        let b = borsh::to_vec(&h).unwrap();
        assert_eq!(&b[0..4], &[1, 0, 0, 0], "u32 LE, per Borsh");

        let h = BlockHeader { timestamp_ms: 1, ..BlockHeader::default() };
        let b = borsh::to_vec(&h).unwrap();
        assert_eq!(&b[68..76], &[1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn offset_constants_are_the_table() {
        assert_eq!(BlockHeader::OFFSET_VERSION, 0);
        assert_eq!(BlockHeader::OFFSET_PREV_HASH, 4);
        assert_eq!(BlockHeader::OFFSET_MERKLE_ROOT, 36);
        assert_eq!(BlockHeader::OFFSET_TIMESTAMP_MS, 68);
        assert_eq!(BlockHeader::OFFSET_BITS, 76);
        assert_eq!(BlockHeader::OFFSET_NONCE, 80);
    }

    #[test]
    fn manual_encode_equals_borsh() {
        assert_eq!(header().encode().to_vec(), borsh::to_vec(&header()).unwrap());
        assert_eq!(BlockHeader::from_bytes(&header().encode()), header());
    }

    #[test]
    fn header_borsh_rejects_trailing_and_truncated_bytes() {
        let mut b = borsh::to_vec(&header()).unwrap();
        b.push(0);
        assert!(borsh::from_slice::<BlockHeader>(&b).is_err());
        assert!(borsh::from_slice::<BlockHeader>(&b[..87]).is_err());
    }

    #[test]
    fn timestamp_seconds_truncate() {
        let h = BlockHeader { timestamp_ms: 1_999, ..BlockHeader::default() };
        assert_eq!(h.timestamp_s(), 1);
        let h = BlockHeader { timestamp_ms: 2_000, ..BlockHeader::default() };
        assert_eq!(h.timestamp_s(), 2);
    }

    #[test]
    fn compact_target_formatting_and_parsing() {
        let c = CompactTarget(0x1d00_ffff);
        assert_eq!(c.to_string(), "0x1d00ffff");
        assert_eq!(format!("{c:?}"), "CompactTarget(0x1d00ffff)");
        assert_eq!(format!("{c:x}"), "1d00ffff");
        assert_eq!("0x1d00ffff".parse::<CompactTarget>().unwrap(), c);
        assert_eq!("486604799".parse::<CompactTarget>().unwrap(), c);
        assert!("nonsense".parse::<CompactTarget>().is_err());
        assert_eq!(c.to_u32(), 0x1d00_ffff);
        assert_eq!(CompactTarget::from_u32(7), CompactTarget(7));
        assert_eq!(u32::from(c), 0x1d00_ffff);
        assert_eq!(CompactTarget::from(9u32), CompactTarget(9));
    }

    #[test]
    fn compact_target_serde_is_a_number() {
        let c = CompactTarget(0x1d00_ffff);
        assert_eq!(serde_json::to_string(&c).unwrap(), "486604799");
        assert_eq!(serde_json::from_str::<CompactTarget>("486604799").unwrap(), c);
        assert_eq!(borsh::to_vec(&c).unwrap(), vec![0xff, 0xff, 0x00, 0x1d]);
    }

    #[test]
    fn pow_seal_is_engine_zero_with_no_data() {
        assert_eq!(BlockSeal::ENGINE_POW, 0);
        assert_eq!(BlockSeal::ENGINE_BFT, 1);
        assert_eq!(BlockSeal::POW.engine, 0);
        assert!(BlockSeal::POW.data.is_empty());
        assert_eq!(BlockSeal::default(), BlockSeal { engine: 0, data: Vec::new() });
        let b = borsh::to_vec(&BlockSeal::POW).unwrap();
        assert_eq!(b, vec![0, 0, 0, 0, 0], "engine byte then an empty u32 length");
    }

    #[test]
    fn bft_seal_carries_its_certificate() {
        let s = BlockSeal::bft(vec![1, 2, 3]);
        assert_eq!(s.engine, BlockSeal::ENGINE_BFT);
        assert_eq!(s.data, vec![1, 2, 3]);
        let b = borsh::to_vec(&s).unwrap();
        assert_eq!(b, vec![1, 3, 0, 0, 0, 1, 2, 3]);
        assert_eq!(s.borsh_size(), b.len());
    }

    #[test]
    fn coinbase_accessor_checks_the_shape() {
        let b = Block::new(header(), vec![coinbase(), spend()], BlockSeal::POW);
        assert_eq!(b.coinbase(), Some(&coinbase()));

        let no_cb = Block::new(header(), vec![spend()], BlockSeal::POW);
        assert_eq!(no_cb.coinbase(), None, "txs[0] is not a coinbase");

        let empty = Block::new(header(), vec![], BlockSeal::POW);
        assert_eq!(empty.coinbase(), None);

        // A coinbase in the wrong position is not returned either.
        let misplaced = Block::new(header(), vec![spend(), coinbase()], BlockSeal::POW);
        assert_eq!(misplaced.coinbase(), None);
    }

    #[test]
    fn block_serialized_size_matches_borsh() {
        for b in [
            Block::new(header(), vec![], BlockSeal::POW),
            Block::new(header(), vec![coinbase()], BlockSeal::POW),
            Block::new(header(), vec![coinbase(), spend()], BlockSeal::bft(vec![9; 70])),
        ] {
            assert_eq!(b.serialized_size(), borsh::to_vec(&b).unwrap().len());
        }
    }

    #[test]
    fn empty_block_size_is_header_plus_count_plus_seal() {
        let b = Block::new(header(), vec![], BlockSeal::POW);
        assert_eq!(b.serialized_size(), 88 + 4 + 5);
    }

    #[test]
    fn the_consensus_size_is_the_encoded_size_without_the_seal() {
        // One block hash, several legal seals: the size the block-size rule
        // measures must not move between them (DECISIONS D12).
        let txs = vec![coinbase(), spend()];
        let quorum_sized = Block::new(header(), txs.clone(), BlockSeal::bft(vec![9; 246]));
        let full_sized = Block::new(header(), txs.clone(), BlockSeal::bft(vec![9; 378]));
        let pow = Block::new(header(), txs, BlockSeal::POW);

        assert_eq!(quorum_sized.consensus_size(), full_sized.consensus_size());
        assert_eq!(quorum_sized.consensus_size(), pow.consensus_size());
        assert_ne!(quorum_sized.serialized_size(), full_sized.serialized_size());

        // And it really is the encoding minus the seal, on every one of them.
        for b in [&quorum_sized, &full_sized, &pow] {
            assert_eq!(
                b.consensus_size(),
                borsh::to_vec(b).unwrap().len() - b.seal.borsh_size(),
                "consensus_size is the block without its seal"
            );
        }
    }

    #[test]
    fn a_commit_certificate_is_bounded_by_the_validator_count() {
        // borsh(BftCommit): 8 + 4 + 32 + 4 fixed, then 2 + 64 per signature.
        assert_eq!(BlockSeal::max_data_len(0), 48);
        assert_eq!(BlockSeal::max_data_len(4), 48 + 4 * 66);
        assert_eq!(BlockSeal::max_data_len(7), 48 + 7 * 66);
        // The bound is `n`, not the quorum: `verify_commit` accepts any count
        // between them, so the largest legal certificate carries every key.
        assert!(BlockSeal::max_data_len(7) > BlockSeal::max_data_len(5));
        assert_eq!(BlockSeal::max_data_len(usize::MAX), usize::MAX, "saturates, never wraps");
    }

    #[test]
    fn block_borsh_round_trips() {
        let b = Block::new(header(), vec![coinbase(), spend()], BlockSeal::POW);
        let bytes = borsh::to_vec(&b).unwrap();
        assert_eq!(borsh::from_slice::<Block>(&bytes).unwrap(), b);
        let mut extra = bytes;
        extra.push(0);
        assert!(borsh::from_slice::<Block>(&extra).is_err());
    }

    #[test]
    fn block_serde_json_round_trips() {
        let b = Block::new(header(), vec![coinbase()], BlockSeal::POW);
        let j = serde_json::to_string(&b).unwrap();
        assert_eq!(serde_json::from_str::<Block>(&j).unwrap(), b);
        assert!(j.contains("\"merkle_root\""));
    }
}
