//! Merkle-tree regression tests, headlined by CVE-2012-2459.
//!
//! # The bug
//!
//! Bitcoin 0.6 built its Merkle tree by **duplicating** the last node of an
//! odd level. That makes the tree shape ambiguous: for a block with an odd
//! number of transactions, appending a copy of the final transaction produces
//! a different block with an identical Merkle root. A node that saw the
//! mutated block first cached the block hash as invalid and then refused the
//! honest block with the same hash — a remote denial of service against any
//! block an attacker could reach first.
//!
//! Ferrum **promotes** the odd node instead, so a tree of `n` leaves and a
//! tree of `n + 1` leaves have different shapes and can never share a root.
//! The test below asserts that for every `n` in `1..=16`, which covers both
//! parities at every level of a small tree.

#![allow(clippy::unwrap_used)]

use ferrum_crypto::{
    MerkleProof, merkle_leaf, merkle_node, merkle_proof, merkle_root, merkle_root_of_leaf_data,
    merkle_verify,
};
use ferrum_types::Hash32;
use proptest::prelude::*;

/// `n` distinct, deterministic leaf hashes.
fn leaves(n: usize) -> Vec<Hash32> {
    (0..n).map(|i| merkle_leaf(format!("leaf-{i}").as_bytes())).collect()
}

#[test]
fn cve_2012_2459_duplicating_the_last_leaf_changes_the_root() {
    for n in 1..=16usize {
        let base = leaves(n);
        let mut duplicated = base.clone();
        duplicated.push(*base.last().unwrap());

        assert_ne!(
            merkle_root(&base),
            merkle_root(&duplicated),
            "CVE-2012-2459: {n} leaves and {n} leaves plus a duplicate share a root"
        );
        assert_eq!(duplicated.len(), n + 1);
    }
}

#[test]
fn cve_2012_2459_duplicating_any_suffix_changes_the_root() {
    // The classic attack duplicates the final leaf, but duplicating the final
    // *k* leaves is the same trick applied further up the tree.
    for n in 2..=16usize {
        let base = leaves(n);
        let root = merkle_root(&base);
        for k in 1..=n {
            let mut mutated = base.clone();
            mutated.extend_from_slice(&base[n - k..]);
            assert_ne!(root, merkle_root(&mutated), "n = {n}, duplicated suffix of {k}");
        }
    }
}

#[test]
fn every_leaf_count_gives_a_distinct_root() {
    // A stronger statement than the CVE test: tree shape is a function of the
    // leaf count, so no two counts can collide for this leaf sequence.
    let mut seen = std::collections::BTreeSet::new();
    for n in 1..=64usize {
        assert!(seen.insert(merkle_root(&leaves(n))), "two leaf counts collided at n = {n}");
    }
}

#[test]
fn empty_tree_is_zero() {
    assert_eq!(merkle_root(&[]), Hash32::ZERO);
    assert_eq!(merkle_root_of_leaf_data(std::iter::empty()), Hash32::ZERO);
}

#[test]
fn a_single_leaf_root_is_the_leaf_hash() {
    let leaf = merkle_leaf(b"the only transaction");
    assert_eq!(merkle_root(&[leaf]), leaf);
    assert_eq!(merkle_root_of_leaf_data(std::iter::once(b"the only transaction".as_slice())), leaf);
}

#[test]
fn the_root_of_two_leaves_is_the_documented_node_hash() {
    let a = merkle_leaf(b"a");
    let b = merkle_leaf(b"b");
    assert_eq!(merkle_root(&[a, b]), merkle_node(&a, &b));
    // ...and the node hash is not the concatenation hashed as a leaf.
    let mut concat = Vec::new();
    concat.extend_from_slice(a.as_bytes());
    concat.extend_from_slice(b.as_bytes());
    assert_ne!(merkle_node(&a, &b), merkle_leaf(&concat));
}

#[test]
fn a_leaf_hash_can_never_be_mistaken_for_a_node_hash() {
    // Second-preimage resistance in the Merkle sense: the leaf and node tags
    // are different derive-key contexts, so the two namespaces are disjoint.
    for i in 0..32u8 {
        let a = merkle_leaf(&[i]);
        let b = merkle_leaf(&[i, i]);
        assert_ne!(merkle_node(&a, &b), merkle_leaf(&[i]));
        assert_ne!(merkle_node(&a, &b), merkle_leaf(&[i, i]));
    }
}

#[test]
fn an_odd_node_is_promoted_and_never_duplicated() {
    // With duplication, three leaves would give node(node(a,b), node(c,c)).
    // With promotion it is node(node(a,b), c). Assert we do the latter.
    let l = leaves(3);
    let promoted = merkle_node(&merkle_node(&l[0], &l[1]), &l[2]);
    let duplicated = merkle_node(&merkle_node(&l[0], &l[1]), &merkle_node(&l[2], &l[2]));
    assert_eq!(merkle_root(&l), promoted);
    assert_ne!(merkle_root(&l), duplicated);
}

#[test]
fn proofs_verify_for_every_index_of_every_size() {
    for n in 1..=33usize {
        let l = leaves(n);
        let root = merkle_root(&l);
        for i in 0..n {
            let proof = merkle_proof(&l, i).unwrap();
            assert!(merkle_verify(&root, &l[i], &proof), "n = {n}, i = {i}");
            assert_eq!(proof.compute_root(&l[i]), root);
        }
    }
}

#[test]
fn a_proof_from_one_tree_does_not_verify_against_another() {
    let a = leaves(9);
    let b = leaves(10);
    let proof = merkle_proof(&a, 8).unwrap();
    assert!(merkle_verify(&merkle_root(&a), &a[8], &proof));
    assert!(!merkle_verify(&merkle_root(&b), &a[8], &proof));
}

#[test]
fn truncating_or_extending_a_proof_breaks_it() {
    let l = leaves(8);
    let root = merkle_root(&l);
    let proof = merkle_proof(&l, 5).unwrap();
    assert_eq!(proof.len(), 3);

    let mut short = proof.clone();
    short.siblings.pop();
    assert!(!merkle_verify(&root, &l[5], &short));

    let mut long = proof.clone();
    long.siblings.push((true, Hash32::ZERO));
    assert!(!merkle_verify(&root, &l[5], &long));
}

#[test]
fn a_reordered_proof_breaks() {
    let l = leaves(16);
    let root = merkle_root(&l);
    let mut proof = merkle_proof(&l, 0).unwrap();
    proof.siblings.reverse();
    assert!(!merkle_verify(&root, &l[0], &proof));
}

#[test]
fn an_empty_proof_only_verifies_a_root_that_is_the_leaf() {
    let leaf = merkle_leaf(b"x");
    let empty = MerkleProof { index: 0, siblings: Vec::new() };
    assert!(merkle_verify(&leaf, &leaf, &empty));
    assert!(!merkle_verify(&Hash32::ZERO, &leaf, &empty));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Round trip over random sizes and indices, odd sizes included.
    #[test]
    fn proof_round_trip(n in 1usize..40, seed in any::<u64>()) {
        let l: Vec<Hash32> =
            (0..n).map(|i| merkle_leaf(&(seed.wrapping_add(i as u64)).to_le_bytes())).collect();
        let root = merkle_root(&l);
        for i in 0..n {
            let proof = merkle_proof(&l, i).expect("index is in range");
            prop_assert_eq!(proof.index, i);
            prop_assert!(merkle_verify(&root, &l[i], &proof));
        }
    }

    /// A proof never verifies a leaf it was not built for.
    #[test]
    fn a_proof_is_specific_to_its_leaf(n in 2usize..24, index in 0usize..24) {
        let index = index % n;
        let l: Vec<Hash32> = (0..n).map(|i| merkle_leaf(&(i as u64).to_le_bytes())).collect();
        let root = merkle_root(&l);
        let proof = merkle_proof(&l, index).expect("index is in range");
        for (other, leaf) in l.iter().enumerate() {
            if other != index {
                prop_assert!(!merkle_verify(&root, leaf, &proof));
            }
        }
    }

    /// Appending a copy of the final leaf always changes the root.
    #[test]
    fn duplication_always_changes_the_root(n in 1usize..40) {
        let l: Vec<Hash32> = (0..n).map(|i| merkle_leaf(&(i as u64).to_le_bytes())).collect();
        let mut dup = l.clone();
        dup.push(*l.last().expect("n >= 1"));
        prop_assert_ne!(merkle_root(&l), merkle_root(&dup));
    }

    /// Changing any single leaf changes the root.
    #[test]
    fn every_leaf_is_committed_to(n in 1usize..24, victim in 0usize..24) {
        let victim = victim % n;
        let l: Vec<Hash32> = (0..n).map(|i| merkle_leaf(&(i as u64).to_le_bytes())).collect();
        let mut mutated = l.clone();
        mutated[victim] = merkle_leaf(b"tampered");
        prop_assert_ne!(merkle_root(&l), merkle_root(&mutated));
    }

    /// `merkle_root_of_leaf_data` is `merkle_root` after leaf hashing.
    #[test]
    fn root_of_leaf_data_matches_manual_hashing(items in prop::collection::vec(
        prop::collection::vec(any::<u8>(), 0..40), 0..24)) {
        let hashed: Vec<Hash32> = items.iter().map(|d| merkle_leaf(d)).collect();
        let by_data = merkle_root_of_leaf_data(items.iter().map(|d| d.as_slice()));
        prop_assert_eq!(by_data, merkle_root(&hashed));
    }

    /// An out-of-range index never yields a proof.
    #[test]
    fn out_of_range_indices_have_no_proof(n in 0usize..24, extra in 0usize..64) {
        let l: Vec<Hash32> = (0..n).map(|i| merkle_leaf(&(i as u64).to_le_bytes())).collect();
        prop_assert!(merkle_proof(&l, n + extra).is_none());
    }
}
