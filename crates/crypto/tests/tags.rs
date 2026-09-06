//! The frozen domain-separation table (CONTRACT §1).
//!
//! These assertions live in an integration test, not next to the constants, on
//! purpose. Two reasons:
//!
//! 1. They pin the *public* surface. An integration test compiles against
//!    `ferrum_crypto` exactly as a downstream crate does, so a tag that stops
//!    being re-exported fails here rather than silently disappearing.
//! 2. `crates/crypto/src/hashing.rs` must contain each context string exactly
//!    once. `scripts/check-invariants.sh` greps that file for duplicate tag
//!    literals, because a context string typed twice is a context string that
//!    can be edited in one place and not the other — and editing one is a hard
//!    fork. Keeping the expected table over here means the definition site has
//!    a single occurrence of every literal.

use ferrum_crypto::{
    ALL_TAGS, TAG_ADDRESS, TAG_BFT_PRECOMMIT, TAG_BFT_PREVOTE, TAG_BFT_PROPOSAL, TAG_GENESIS,
    TAG_HD_SEED, TAG_HEADER, TAG_MERKLE_LEAF, TAG_MERKLE_NODE, TAG_P2P_MSGID, TAG_SCRIPT,
    TAG_SIGHASH, TAG_STATE_ROOT, TAG_TXID, TAG_UNDO, Tag,
};

/// The table from CONTRACT §1, in contract order, transcribed by hand.
///
/// Changing a row here is a hard fork; adding one at the end is not.
const CONTRACT_TABLE: [(&str, &str); 15] = [
    ("TAG_TXID", "ferrum.v1.txid"),
    ("TAG_SIGHASH", "ferrum.v1.sighash"),
    ("TAG_HEADER", "ferrum.v1.header"),
    ("TAG_MERKLE_LEAF", "ferrum.v1.merkle.leaf"),
    ("TAG_MERKLE_NODE", "ferrum.v1.merkle.node"),
    ("TAG_ADDRESS", "ferrum.v1.address"),
    ("TAG_SCRIPT", "ferrum.v1.script"),
    ("TAG_STATE_ROOT", "ferrum.v1.state.root"),
    ("TAG_UNDO", "ferrum.v1.undo"),
    ("TAG_BFT_PROPOSAL", "ferrum.v1.bft.proposal"),
    ("TAG_BFT_PREVOTE", "ferrum.v1.bft.prevote"),
    ("TAG_BFT_PRECOMMIT", "ferrum.v1.bft.precommit"),
    ("TAG_P2P_MSGID", "ferrum.v1.p2p.msgid"),
    ("TAG_GENESIS", "ferrum.v1.genesis"),
    ("TAG_HD_SEED", "ferrum.v1.hd.seed"),
];

/// The constants themselves, in the same order as [`CONTRACT_TABLE`].
const CONSTANTS: [Tag; 15] = [
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

#[test]
fn tag_list_matches_the_contract_table() {
    assert_eq!(ALL_TAGS.len(), CONTRACT_TABLE.len(), "the frozen list changed length");
    for (tag, (name, want)) in ALL_TAGS.iter().zip(CONTRACT_TABLE.iter()) {
        assert_eq!(tag.as_str(), *want, "{name} context string changed: that is a hard fork");
    }
}

#[test]
fn every_named_constant_sits_at_its_contract_row() {
    for (i, (tag, (name, want))) in CONSTANTS.iter().zip(CONTRACT_TABLE.iter()).enumerate() {
        assert_eq!(tag.as_str(), *want, "{name} is not the string the contract froze");
        assert_eq!(ALL_TAGS[i].as_str(), tag.as_str(), "{name} is not at ALL_TAGS[{i}]");
    }
}

#[test]
fn tag_display_and_debug() {
    let want = CONTRACT_TABLE[0].1;
    assert_eq!(TAG_TXID.to_string(), want);
    assert_eq!(format!("{TAG_TXID:?}"), format!("Tag({want:?})"));
    assert_eq!(TAG_TXID.as_str(), want);
}
