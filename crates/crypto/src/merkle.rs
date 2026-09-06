//! Merkle trees, RFC 6962 shape, immune to CVE-2012-2459.
//!
//! ```text
//! leaf = tagged_hash(TAG_MERKLE_LEAF, data)
//! node = tagged_hash(TAG_MERKLE_NODE, left || right)
//! ```
//!
//! # Promotion, never duplication
//!
//! When a level has an odd number of nodes the last one is **promoted** to the
//! next level unchanged. Bitcoin instead duplicates it, and that is
//! CVE-2012-2459: for a block with an odd tx count, an attacker can append a
//! copy of the last transaction and produce a *different* block with the
//! *same* Merkle root. The victim node caches the mutated block as invalid and
//! then rejects the honest one. Promotion removes the degree of freedom: the
//! tree shape is a function of the leaf count alone, so `n` and `n + 1` leaves
//! can never share a root. [`tests/merkle.rs`](../../tests/merkle.rs) asserts
//! exactly that for every `n` in `1..=16`.
//!
//! Leaf and internal nodes use *different* tags, which is the second half of
//! the classic Merkle second-preimage defence: an internal node hash can never
//! be reinterpreted as a leaf hash.
//!
//! # What the empty and singleton trees are
//!
//! An empty tree has root [`Hash32::ZERO`] — the same value a genesis block
//! uses for `prev_hash`, and a value no real subtree can produce. A single
//! leaf is its own root, matching RFC 6962 once the leaf hashing has already
//! been applied by the caller.
//!
//! ```
//! use ferrum_crypto::{merkle_leaf, merkle_proof, merkle_root, merkle_root_of_leaf_data,
//!                     merkle_verify};
//!
//! let data: [&[u8]; 3] = [b"a", b"b", b"c"];
//! let leaves: Vec<_> = data.iter().map(|d| merkle_leaf(d)).collect();
//!
//! let root = merkle_root(&leaves);
//! assert_eq!(root, merkle_root_of_leaf_data(data.into_iter()));
//!
//! let proof = merkle_proof(&leaves, 2).expect("index 2 exists");
//! assert!(merkle_verify(&root, &leaves[2], &proof));
//! ```

use ferrum_types::Hash32;

use crate::hashing::{TAG_MERKLE_LEAF, TAG_MERKLE_NODE, tagged_hash};

/// Hash one piece of leaf data into a Merkle leaf.
pub fn merkle_leaf(data: &[u8]) -> Hash32 {
    tagged_hash(TAG_MERKLE_LEAF, data)
}

/// Combine two children into their parent node.
pub fn merkle_node(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut hasher = crate::hashing::tagged_hasher(TAG_MERKLE_NODE);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    Hash32::from_bytes(*hasher.finalize().as_bytes())
}

/// Reduce one level of the tree, promoting a trailing odd node.
fn reduce(level: &[Hash32]) -> Vec<Hash32> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    for pair in level.chunks(2) {
        match pair {
            [a, b] => next.push(merkle_node(a, b)),
            // Odd node out: promoted unchanged, never duplicated.
            [a] => next.push(*a),
            _ => {}
        }
    }
    next
}

/// The Merkle root of already-hashed leaves.
///
/// The inputs are *leaf hashes*, not leaf data: use
/// [`merkle_root_of_leaf_data`] when you have raw bytes, or feed txids
/// directly when the leaf is a txid, as `ferrum-chain` does.
///
/// Empty input yields [`Hash32::ZERO`]; a single leaf is its own root.
pub fn merkle_root(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return Hash32::ZERO;
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = reduce(&level);
    }
    level.first().copied().unwrap_or(Hash32::ZERO)
}

/// The Merkle root of raw leaf data, hashing each item with `TAG_MERKLE_LEAF`.
pub fn merkle_root_of_leaf_data<'a>(items: impl Iterator<Item = &'a [u8]>) -> Hash32 {
    let leaves: Vec<Hash32> = items.map(merkle_leaf).collect();
    merkle_root(&leaves)
}

/// An inclusion proof: the sibling at each level, from the leaf upwards.
///
/// `siblings[k].0` is `true` when that sibling sits on the **right**, so the
/// parent is `node(current, sibling)`; `false` means the sibling is on the
/// left and the parent is `node(sibling, current)`.
///
/// A level at which the node was promoted contributes **no** entry, so
/// `siblings.len()` is at most `ceil(log2(n))` and may be smaller. Because of
/// that, verification follows the recorded sides rather than re-deriving them
/// from `index`: without the leaf count there is no way to tell a promotion
/// level from a pairing level. `index` is carried for the caller — it says
/// *which* leaf was proven — and is not consulted by [`merkle_verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    /// Position of the proven leaf in the original slice.
    pub index: usize,
    /// `(sibling_is_on_the_right, sibling_hash)` from the leaf upwards.
    pub siblings: Vec<(bool, Hash32)>,
}

impl MerkleProof {
    /// Number of levels at which a sibling was hashed in.
    pub fn len(&self) -> usize {
        self.siblings.len()
    }

    /// True for a single-leaf tree, where the leaf is already the root.
    pub fn is_empty(&self) -> bool {
        self.siblings.is_empty()
    }

    /// Recompute the root this proof implies, starting from `leaf`.
    pub fn compute_root(&self, leaf: &Hash32) -> Hash32 {
        let mut current = *leaf;
        for (sibling_on_right, sibling) in &self.siblings {
            current = if *sibling_on_right {
                merkle_node(&current, sibling)
            } else {
                merkle_node(sibling, &current)
            };
        }
        current
    }
}

/// Build an inclusion proof for `leaves[index]`.
///
/// Returns `None` when `index` is out of range, which includes every index on
/// an empty tree.
pub fn merkle_proof(leaves: &[Hash32], index: usize) -> Option<MerkleProof> {
    if index >= leaves.len() {
        return None;
    }
    let mut siblings = Vec::new();
    let mut level = leaves.to_vec();
    let mut idx = index;

    while level.len() > 1 {
        // The trailing node of an odd level is promoted, so it has no sibling.
        let promoted = level.len() % 2 == 1 && idx == level.len() - 1;
        if !promoted {
            let (sibling_on_right, sibling_idx) =
                if idx.is_multiple_of(2) { (true, idx + 1) } else { (false, idx - 1) };
            // In range because `promoted` ruled out the only overhang.
            if let Some(sibling) = level.get(sibling_idx) {
                siblings.push((sibling_on_right, *sibling));
            }
        }
        // Pairing and promotion both send index `i` to `i / 2`.
        idx /= 2;
        level = reduce(&level);
    }

    Some(MerkleProof { index, siblings })
}

/// Check that `leaf` is committed to by `root` under `proof`.
pub fn merkle_verify(root: &Hash32, leaf: &Hash32, proof: &MerkleProof) -> bool {
    proof.compute_root(leaf) == *root
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn leaves(n: usize) -> Vec<Hash32> {
        (0..n).map(|i| merkle_leaf(&i.to_le_bytes())).collect()
    }

    #[test]
    fn empty_tree_is_zero() {
        assert_eq!(merkle_root(&[]), Hash32::ZERO);
        assert_eq!(merkle_root_of_leaf_data(std::iter::empty()), Hash32::ZERO);
    }

    #[test]
    fn single_leaf_is_its_own_root() {
        let l = leaves(1);
        assert_eq!(merkle_root(&l), l[0]);
    }

    #[test]
    fn two_leaves_are_one_node() {
        let l = leaves(2);
        assert_eq!(merkle_root(&l), merkle_node(&l[0], &l[1]));
    }

    #[test]
    fn three_leaves_promote_the_third() {
        let l = leaves(3);
        let left = merkle_node(&l[0], &l[1]);
        assert_eq!(merkle_root(&l), merkle_node(&left, &l[2]));
    }

    #[test]
    fn five_leaves_promote_twice() {
        // level0: [0 1 2 3 4] -> [n01 n23 4]
        // level1: [n01 n23 4] -> [n(n01,n23) 4]
        // level2: root = n(n(n01,n23), 4)
        let l = leaves(5);
        let n01 = merkle_node(&l[0], &l[1]);
        let n23 = merkle_node(&l[2], &l[3]);
        let n0123 = merkle_node(&n01, &n23);
        assert_eq!(merkle_root(&l), merkle_node(&n0123, &l[4]));
    }

    #[test]
    fn leaf_and_node_tags_are_separated() {
        // A node hash must never equal the leaf hash of the same bytes.
        let l = leaves(2);
        let mut concat = Vec::new();
        concat.extend_from_slice(l[0].as_bytes());
        concat.extend_from_slice(l[1].as_bytes());
        assert_ne!(merkle_node(&l[0], &l[1]), merkle_leaf(&concat));
    }

    #[test]
    fn merkle_root_of_leaf_data_hashes_its_input() {
        let data: [&[u8]; 3] = [b"a", b"bb", b"ccc"];
        let hashed: Vec<Hash32> = data.iter().map(|d| merkle_leaf(d)).collect();
        assert_eq!(merkle_root_of_leaf_data(data.into_iter()), merkle_root(&hashed));
    }

    #[test]
    fn duplicating_the_last_leaf_changes_the_root() {
        // CVE-2012-2459 in miniature; the integration test covers 1..=16.
        for n in 1..=8usize {
            let l = leaves(n);
            let mut dup = l.clone();
            dup.push(l[n - 1]);
            assert_ne!(merkle_root(&l), merkle_root(&dup), "n = {n}");
        }
    }

    #[test]
    fn proofs_verify_for_every_index_and_size() {
        for n in 1..=17usize {
            let l = leaves(n);
            let root = merkle_root(&l);
            for i in 0..n {
                let proof = merkle_proof(&l, i).unwrap();
                assert_eq!(proof.index, i);
                assert!(merkle_verify(&root, &l[i], &proof), "n = {n}, i = {i}");
            }
        }
    }

    #[test]
    fn proof_for_a_single_leaf_is_empty() {
        let l = leaves(1);
        let proof = merkle_proof(&l, 0).unwrap();
        assert!(proof.is_empty());
        assert_eq!(proof.len(), 0);
        assert!(merkle_verify(&l[0], &l[0], &proof));
    }

    #[test]
    fn out_of_range_index_has_no_proof() {
        assert_eq!(merkle_proof(&[], 0), None);
        assert_eq!(merkle_proof(&leaves(4), 4), None);
        assert_eq!(merkle_proof(&leaves(4), usize::MAX), None);
    }

    #[test]
    fn a_proof_does_not_verify_the_wrong_leaf() {
        let l = leaves(8);
        let root = merkle_root(&l);
        let proof = merkle_proof(&l, 3).unwrap();
        assert!(!merkle_verify(&root, &l[4], &proof));
    }

    #[test]
    fn a_tampered_sibling_breaks_the_proof() {
        let l = leaves(9);
        let root = merkle_root(&l);
        let mut proof = merkle_proof(&l, 0).unwrap();
        proof.siblings[0].1 = Hash32::ZERO;
        assert!(!merkle_verify(&root, &l[0], &proof));
    }

    #[test]
    fn a_flipped_side_flag_breaks_the_proof() {
        let l = leaves(4);
        let root = merkle_root(&l);
        let mut proof = merkle_proof(&l, 1).unwrap();
        proof.siblings[0].0 = !proof.siblings[0].0;
        assert!(!merkle_verify(&root, &l[1], &proof));
    }

    #[test]
    fn proof_length_never_exceeds_the_tree_depth() {
        for n in 1..=64usize {
            let l = leaves(n);
            let depth = usize::BITS as usize - (n - 1).leading_zeros() as usize;
            for i in 0..n {
                let proof = merkle_proof(&l, i).unwrap();
                assert!(proof.len() <= depth, "n = {n}, i = {i}, len = {}", proof.len());
            }
        }
    }

    #[test]
    fn reduce_promotes_rather_than_duplicates() {
        let l = leaves(3);
        let next = reduce(&l);
        assert_eq!(next.len(), 2);
        assert_eq!(next[0], merkle_node(&l[0], &l[1]));
        assert_eq!(next[1], l[2], "the odd node must be carried up unchanged");
    }

    #[test]
    fn root_depends_on_leaf_order() {
        let l = leaves(4);
        let mut swapped = l.clone();
        swapped.swap(0, 1);
        assert_ne!(merkle_root(&l), merkle_root(&swapped));
    }
}
