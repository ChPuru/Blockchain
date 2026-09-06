//! Domain-separated hashing: the frozen tag list of CONTRACT §1 and the three
//! digest helpers everything else in Ferrum is built from.
//!
//! # Why derive-key mode
//!
//! Every hash in Ferrum is BLAKE3 in *derive-key* mode:
//! `blake3::Hasher::new_derive_key(TAG)` followed by `update(data)`. The
//! context string is the domain tag. Two different tags produce two unrelated
//! keyed hash functions, so a preimage crafted for one role — a Merkle leaf,
//! say — can never be reinterpreted as a preimage for another — a Merkle
//! internal node, or a BFT precommit. That is the property that kills whole
//! classes of type-confusion attack before they can be written down.
//!
//! **The tag list is frozen.** Adding a tag is allowed; changing or removing
//! one is a hard fork. [`ALL_TAGS`] exists so that a test can iterate it and
//! assert pairwise distinctness, and so a future tag cannot be added without
//! the distinctness test covering it.
//!
//! # Cost
//!
//! `new_derive_key` is not free: it hashes the context string and then sets up
//! a fresh keyed hasher. Re-deriving on every call would roughly halve mining
//! throughput, since the miner inner loop is one `tagged_hash(TAG_HEADER, ..)`
//! over 88 bytes. [`tagged_hasher`] therefore derives each frozen tag hasher
//! exactly once behind a `LazyLock` and hands out clones; cloning a
//! `blake3::Hasher` is a memcpy of its small internal state.
//!
//! ```
//! use ferrum_crypto::{TAG_HEADER, TAG_TXID, tagged_hash};
//!
//! // The same bytes under two tags are unrelated digests.
//! assert_ne!(tagged_hash(TAG_HEADER, b"x"), tagged_hash(TAG_TXID, b"x"));
//! ```

use std::fmt;
use std::sync::LazyLock;

use ferrum_types::Hash32;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// A BLAKE3 derive-key context string: one domain in the hash namespace.
///
/// The inner `&'static str` is public so that a tag can be declared as a
/// `const` in this module and matched elsewhere. Constructing an ad-hoc `Tag`
/// is allowed and works — it simply misses the hasher cache.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag(pub &'static str);

impl Tag {
    /// The context string this tag stands for.
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag({:?})", self.0)
    }
}

/// Transaction id: `Txid = tagged_hash(TAG_TXID, tx_envelope)` (CONTRACT §2.1).
pub const TAG_TXID: Tag = Tag("ferrum.v1.txid");
/// Signature preimage digest (CONTRACT §5.5).
pub const TAG_SIGHASH: Tag = Tag("ferrum.v1.sighash");
/// Block hash: `BlockHash = tagged_hash(TAG_HEADER, header_bytes)` (CONTRACT §2.2).
pub const TAG_HEADER: Tag = Tag("ferrum.v1.header");
/// Merkle leaf, RFC 6962 shape (CONTRACT §4).
pub const TAG_MERKLE_LEAF: Tag = Tag("ferrum.v1.merkle.leaf");
/// Merkle internal node (CONTRACT §4).
pub const TAG_MERKLE_NODE: Tag = Tag("ferrum.v1.merkle.node");
/// Address payload commitment.
pub const TAG_ADDRESS: Tag = Tag("ferrum.v1.address");
/// Script hash for P2SH: `hash256(x) = tagged_hash(TAG_SCRIPT, x)`.
pub const TAG_SCRIPT: Tag = Tag("ferrum.v1.script");
/// UTXO-set Merkle root (CONTRACT §7).
pub const TAG_STATE_ROOT: Tag = Tag("ferrum.v1.state.root");
/// Undo-record digest (CONTRACT §7).
pub const TAG_UNDO: Tag = Tag("ferrum.v1.undo");
/// BFT proposal signing (CONTRACT §6.5).
pub const TAG_BFT_PROPOSAL: Tag = Tag("ferrum.v1.bft.proposal");
/// BFT prevote signing (CONTRACT §6.5).
pub const TAG_BFT_PREVOTE: Tag = Tag("ferrum.v1.bft.prevote");
/// BFT precommit signing (CONTRACT §6.5).
pub const TAG_BFT_PRECOMMIT: Tag = Tag("ferrum.v1.bft.precommit");
/// gossipsub content-addressed message id (CONTRACT §10.1).
pub const TAG_P2P_MSGID: Tag = Tag("ferrum.v1.p2p.msgid");
/// Genesis parameter commitment.
pub const TAG_GENESIS: Tag = Tag("ferrum.v1.genesis");
/// BIP-32 master key derivation domain.
///
/// CONTRACT §4 pins master derivation itself to HMAC-SHA512 with the key
/// `"Ferrum seed"`, exactly as BIP-32 specifies but with the Ferrum string in
/// place of the Bitcoin one, so this tag is reserved for callers that need a
/// domain-separated *commitment* to a seed — a wallet keystore checksum, for
/// instance — rather than for the derivation itself.
pub const TAG_HD_SEED: Tag = Tag("ferrum.v1.hd.seed");

/// Every frozen tag, in the order CONTRACT §1 lists them.
///
/// Iterate this in tests: it is what makes "all tags are pairwise distinct" a
/// property of the list rather than of the tags a test author remembered.
pub const ALL_TAGS: [Tag; 15] = [
    TAG_TXID,
    TAG_SIGHASH,
    TAG_HEADER,
    TAG_MERKLE_LEAF,
    TAG_MERKLE_NODE,
    TAG_ADDRESS,
    TAG_SCRIPT,
    TAG_STATE_ROOT,
    TAG_UNDO,
    TAG_BFT_PROPOSAL,
    TAG_BFT_PREVOTE,
    TAG_BFT_PRECOMMIT,
    TAG_P2P_MSGID,
    TAG_GENESIS,
    TAG_HD_SEED,
];

/// One derive-key hasher per frozen tag, built once on first use.
///
/// Order matches [`ALL_TAGS`]; `tag_index` is the only way in.
static TAG_HASHERS: LazyLock<[blake3::Hasher; ALL_TAGS.len()]> =
    LazyLock::new(|| ALL_TAGS.map(|t| blake3::Hasher::new_derive_key(t.0)));

/// Position of `tag` in [`ALL_TAGS`], or `None` for an ad-hoc tag.
///
/// A linear scan over 15 short string comparisons costs a few nanoseconds,
/// against roughly half a microsecond to re-derive a keyed hasher, so the scan
/// pays for itself many times over in the miner inner loop.
fn tag_index(tag: Tag) -> Option<usize> {
    ALL_TAGS.iter().position(|t| t.0 == tag.0)
}

/// A BLAKE3 hasher already keyed to `tag`, ready for `update`.
///
/// For a frozen tag this is a clone of a cached hasher. For any other tag it
/// derives one on the spot, so an experimental tag still works — it is just
/// slower.
pub fn tagged_hasher(tag: Tag) -> blake3::Hasher {
    match tag_index(tag) {
        Some(i) => TAG_HASHERS[i].clone(),
        // Not in the frozen list: correctness before speed.
        None => blake3::Hasher::new_derive_key(tag.0),
    }
}

/// `BLAKE3-derive-key(tag, data)` as a [`Hash32`].
///
/// This is the single hashing primitive of the whole chain. It is identical to
/// `blake3::derive_key(tag.as_str(), data)`, which a unit test asserts.
pub fn tagged_hash(tag: Tag, data: &[u8]) -> Hash32 {
    let mut hasher = tagged_hasher(tag);
    hasher.update(data);
    Hash32::from_bytes(*hasher.finalize().as_bytes())
}

/// `ripemd160(sha256(x))` — 20 bytes.
///
/// Used only for P2PKH payloads, where 20 bytes buys a shorter address at
/// 80 bits of collision resistance. Everything consensus-critical uses the
/// 32-byte [`tagged_hash`] instead.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

/// Plain single SHA-256.
///
/// Present because BIP-39 checksums and BIP-32 fingerprints are defined over
/// SHA-256 and must interoperate with the rest of the world. It is **not** a
/// Ferrum consensus hash; use [`tagged_hash`] for those.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// `hash256(x) = tagged_hash(TAG_SCRIPT, x)` — the P2SH script hash (§1).
///
/// Named for the `OP_HASH256` opcode that computes it, which is the only place
/// in the script VM where a 32-byte script commitment appears. Note that it is
/// *not* Bitcoin double-SHA-256; a test asserts the difference.
pub fn hash256(data: &[u8]) -> Hash32 {
    tagged_hash(TAG_SCRIPT, data)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Inputs with different lengths and shapes, so distinctness is not shown
    /// only for one convenient message.
    const PROBES: [&[u8]; 6] = [
        b"",
        b"\x00",
        b"a",
        b"ferrum",
        b"\xff\xff\xff\xff\xff\xff\xff\xff",
        b"the quick brown fox jumps over the lazy dog",
    ];

    #[test]
    fn tag_list_matches_the_contract_table() {
        let expected = [
            "ferrum.v1.txid",
            "ferrum.v1.sighash",
            "ferrum.v1.header",
            "ferrum.v1.merkle.leaf",
            "ferrum.v1.merkle.node",
            "ferrum.v1.address",
            "ferrum.v1.script",
            "ferrum.v1.state.root",
            "ferrum.v1.undo",
            "ferrum.v1.bft.proposal",
            "ferrum.v1.bft.prevote",
            "ferrum.v1.bft.precommit",
            "ferrum.v1.p2p.msgid",
            "ferrum.v1.genesis",
            "ferrum.v1.hd.seed",
        ];
        assert_eq!(ALL_TAGS.len(), expected.len(), "the frozen list changed length");
        for (tag, want) in ALL_TAGS.iter().zip(expected.iter()) {
            assert_eq!(tag.0, *want, "tag context string changed: that is a hard fork");
        }
    }

    #[test]
    fn every_tag_context_string_is_distinct() {
        for (i, a) in ALL_TAGS.iter().enumerate() {
            for (j, b) in ALL_TAGS.iter().enumerate() {
                if i != j {
                    assert_ne!(a.0, b.0, "tags {i} and {j} share a context string");
                }
            }
        }
    }

    #[test]
    fn every_tag_is_namespaced() {
        for tag in ALL_TAGS {
            assert!(tag.0.starts_with("ferrum.v1."), "{tag} is missing the version namespace");
        }
    }

    #[test]
    fn distinct_tags_give_distinct_digests_for_every_probe() {
        for probe in PROBES {
            for (i, a) in ALL_TAGS.iter().enumerate() {
                for (j, b) in ALL_TAGS.iter().enumerate() {
                    if i != j {
                        assert_ne!(
                            tagged_hash(*a, probe),
                            tagged_hash(*b, probe),
                            "tags {i} and {j} collide on probe {probe:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_same_tag_gives_the_same_digest() {
        for probe in PROBES {
            for tag in ALL_TAGS {
                assert_eq!(tagged_hash(tag, probe), tagged_hash(tag, probe));
            }
        }
    }

    #[test]
    fn distinct_inputs_under_one_tag_give_distinct_digests() {
        for tag in ALL_TAGS {
            for (i, a) in PROBES.iter().enumerate() {
                for (j, b) in PROBES.iter().enumerate() {
                    if i != j {
                        assert_ne!(tagged_hash(tag, a), tagged_hash(tag, b));
                    }
                }
            }
        }
    }

    #[test]
    fn tagged_hash_equals_blake3_derive_key() {
        // The cache must not change the answer.
        for tag in ALL_TAGS {
            for probe in PROBES {
                assert_eq!(
                    tagged_hash(tag, probe).to_bytes(),
                    blake3::derive_key(tag.0, probe),
                    "cached hasher disagrees with blake3::derive_key for {tag}"
                );
            }
        }
    }

    #[test]
    fn tagged_hasher_is_incremental_and_equals_one_shot() {
        let data = b"ferrum block header bytes go here";
        let mut h = tagged_hasher(TAG_HEADER);
        h.update(&data[..7]);
        h.update(&data[7..]);
        assert_eq!(Hash32::from_bytes(*h.finalize().as_bytes()), tagged_hash(TAG_HEADER, data));
    }

    #[test]
    fn an_ad_hoc_tag_still_works() {
        let custom = Tag("ferrum.test.adhoc");
        assert_eq!(tag_index(custom), None);
        assert_eq!(
            tagged_hash(custom, b"x").to_bytes(),
            blake3::derive_key("ferrum.test.adhoc", b"x")
        );
        for tag in ALL_TAGS {
            assert_ne!(tagged_hash(custom, b"x"), tagged_hash(tag, b"x"));
        }
    }

    #[test]
    fn tag_index_finds_every_frozen_tag() {
        for (i, tag) in ALL_TAGS.iter().enumerate() {
            assert_eq!(tag_index(*tag), Some(i));
        }
    }

    #[test]
    fn tag_display_and_debug() {
        assert_eq!(TAG_TXID.to_string(), "ferrum.v1.txid");
        assert_eq!(format!("{TAG_TXID:?}"), "Tag(\"ferrum.v1.txid\")");
        assert_eq!(TAG_TXID.as_str(), "ferrum.v1.txid");
    }

    #[test]
    fn sha256_known_answer() {
        // FIPS 180-4 example: SHA-256("abc").
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn ripemd160_known_answer() {
        // The RIPEMD-160 reference test vector for "abc".
        let d: [u8; 20] = Ripemd160::digest(b"abc").into();
        assert_eq!(hex::encode(d), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    }

    #[test]
    fn hash160_known_answers() {
        // RIPEMD-160(SHA-256("")) — the canonical hash160 of nothing.
        assert_eq!(hex::encode(hash160(b"")), "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");

        // The Bitcoin genesis coinbase public key hashes to the well-known
        // 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa payload. Any wiring mistake
        // between SHA-256 and RIPEMD-160 changes this value.
        let genesis_pk = hex::decode(
            "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6\
             49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
        )
        .unwrap();
        assert_eq!(hex::encode(hash160(&genesis_pk)), "62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
    }

    #[test]
    fn hash160_is_ripemd160_of_sha256() {
        for probe in PROBES {
            let expected: [u8; 20] = Ripemd160::digest(Sha256::digest(probe)).into();
            assert_eq!(hash160(probe), expected);
        }
    }

    #[test]
    fn hash256_is_the_script_tag_and_not_double_sha256() {
        for probe in PROBES {
            assert_eq!(hash256(probe), tagged_hash(TAG_SCRIPT, probe));
            assert_ne!(hash256(probe).to_bytes(), sha256(&sha256(probe)));
        }
    }

    #[test]
    fn digest_lengths_are_fixed() {
        assert_eq!(sha256(b"x").len(), 32);
        assert_eq!(hash160(b"x").len(), 20);
        assert_eq!(tagged_hash(TAG_TXID, b"x").as_bytes().len(), 32);
    }
}
