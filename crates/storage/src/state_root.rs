//! The UTXO-set state root (CONTRACT §7).
//!
//! ```text
//! leaf = tagged_hash(TAG_STATE_ROOT, borsh(OutPoint) || borsh(Coin))
//! root = merkle_root(leaves sorted by ascending borsh(OutPoint) bytes)
//! ```
//!
//! combined with the CONTRACT §4 Merkle rules: an odd node at any level is
//! *promoted*, never duplicated (the CVE-2012-2459 fix), and an empty set
//! hashes to [`Hash32::ZERO`].
//!
//! **This is not consensus state.** No header commits to it, and Ferrum has no
//! light clients precisely because there is no such commitment (SPEC §13). It
//! exists so that two nodes, or a node and the reference executor, can compare
//! their entire UTXO sets in 32 bytes — which is what the determinism replay
//! harness, the differential test and the `getstateroot` RPC all do.
//!
//! # The ordering is `borsh(OutPoint)` bytes, not `Ord for OutPoint`
//!
//! Those are different orders and the difference is easy to miss. `vout` is a
//! little-endian `u32` inside the Borsh encoding, so outpoint `(t, 256)` —
//! `… 00 01 00 00` — sorts *before* `(t, 1)` — `… 01 00 00 00` — bytewise,
//! while `Ord` puts them the other way round. CONTRACT §7 says "ascending
//! `borsh(OutPoint)` byte order", so this module sorts by the 36-byte key and
//! never by [`OutPoint`]'s `Ord`. The `utxo` table is keyed by exactly those
//! bytes, so [`crate::Store::state_root`] gets the right order for free.

use ferrum_crypto::{TAG_STATE_ROOT, merkle_root, tagged_hasher};
use ferrum_types::{Coin, Hash32, OutPoint};

use crate::error::StorageError;
use crate::tables::{OUTPOINT_KEY_LEN, outpoint_key};

/// Hash one UTXO entry from its already-encoded key and value bytes.
///
/// The store passes the raw table bytes straight through, so the leaf never
/// depends on a re-encoding round trip.
#[must_use]
pub fn state_root_leaf_bytes(op_bytes: &[u8], coin_bytes: &[u8]) -> Hash32 {
    let mut hasher = tagged_hasher(TAG_STATE_ROOT);
    hasher.update(op_bytes);
    hasher.update(coin_bytes);
    Hash32::from_bytes(*hasher.finalize().as_bytes())
}

/// Hash one UTXO entry from its typed form.
///
/// # Errors
/// Returns [`StorageError::Corrupt`] if the coin cannot be Borsh-encoded.
pub fn state_root_leaf(op: &OutPoint, coin: &Coin) -> Result<Hash32, StorageError> {
    let coin_bytes = borsh::to_vec(coin).map_err(|e| StorageError::corrupt("coin", e))?;
    Ok(state_root_leaf_bytes(&outpoint_key(op), &coin_bytes))
}

/// The root over leaves that are **already** in ascending key order.
///
/// Callers that iterate the `utxo` table are in that order by construction;
/// everyone else should use [`state_root_of`].
#[must_use]
pub fn state_root_of_sorted_leaves(leaves: &[Hash32]) -> Hash32 {
    merkle_root(leaves)
}

/// The root over `(outpoint, coin)` pairs in **any** order.
///
/// Sorts by `borsh(OutPoint)` bytes first, so the result depends only on the
/// set, never on how the caller happened to enumerate it.
///
/// # Errors
/// Returns [`StorageError::Corrupt`] if a coin cannot be Borsh-encoded.
pub fn state_root_of<'a, I>(entries: I) -> Result<Hash32, StorageError>
where
    I: IntoIterator<Item = (&'a OutPoint, &'a Coin)>,
{
    let mut keyed: Vec<([u8; OUTPOINT_KEY_LEN], Hash32)> = Vec::new();
    for (op, coin) in entries {
        let key = outpoint_key(op);
        let coin_bytes = borsh::to_vec(coin).map_err(|e| StorageError::corrupt("coin", e))?;
        keyed.push((key, state_root_leaf_bytes(&key, &coin_bytes)));
    }
    keyed.sort_unstable_by_key(|entry| entry.0);
    let leaves: Vec<Hash32> = keyed.into_iter().map(|(_, leaf)| leaf).collect();
    Ok(merkle_root(&leaves))
}

/// Incremental accumulator for a state root computed while streaming a table.
///
/// Leaves must be pushed in ascending key order; the store's table cursor
/// guarantees that. Buffering the leaves rather than the whole UTXO set keeps
/// the peak allocation at 32 bytes per entry instead of a full `Coin` each.
#[derive(Clone, Debug, Default)]
pub struct StateRootBuilder {
    leaves: Vec<Hash32>,
}

impl StateRootBuilder {
    /// A builder with no leaves.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append the leaf for one UTXO entry, already encoded.
    pub fn push_bytes(&mut self, op_bytes: &[u8], coin_bytes: &[u8]) {
        self.leaves.push(state_root_leaf_bytes(op_bytes, coin_bytes));
    }

    /// Number of leaves accumulated.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether nothing has been pushed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Finish, producing the root.
    #[must_use]
    pub fn finish(self) -> Hash32 {
        merkle_root(&self.leaves)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ferrum_crypto::{TAG_MERKLE_LEAF, tagged_hash};
    use ferrum_types::{Amount, Script, Txid};
    use proptest::prelude::*;

    fn op(n: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid(Hash32::from_bytes([n; 32])), vout)
    }

    fn coin(v: u64) -> Coin {
        Coin {
            value: Amount::from_grains(v),
            script_pubkey: Script::new(vec![0x51, 0x52]),
            height: 3,
            is_coinbase: false,
        }
    }

    #[test]
    fn an_empty_set_hashes_to_zero() {
        let empty: Vec<(&OutPoint, &Coin)> = Vec::new();
        assert_eq!(state_root_of(empty).unwrap(), Hash32::ZERO);
        assert_eq!(StateRootBuilder::new().finish(), Hash32::ZERO);
    }

    #[test]
    fn a_single_entry_is_its_own_root() {
        let (o, c) = (op(1, 0), coin(5));
        let root = state_root_of([(&o, &c)]).unwrap();
        assert_eq!(root, state_root_leaf(&o, &c).unwrap());
    }

    #[test]
    fn the_leaf_is_domain_separated_from_a_merkle_leaf() {
        let (o, c) = (op(1, 0), coin(5));
        let mut preimage = outpoint_key(&o).to_vec();
        preimage.extend_from_slice(&borsh::to_vec(&c).unwrap());
        assert_eq!(state_root_leaf(&o, &c).unwrap(), tagged_hash(TAG_STATE_ROOT, &preimage));
        assert_ne!(state_root_leaf(&o, &c).unwrap(), tagged_hash(TAG_MERKLE_LEAF, &preimage));
    }

    #[test]
    fn the_leaf_bytes_helper_matches_the_typed_helper() {
        let (o, c) = (op(7, 3), coin(11));
        let coin_bytes = borsh::to_vec(&c).unwrap();
        assert_eq!(
            state_root_leaf_bytes(&outpoint_key(&o), &coin_bytes),
            state_root_leaf(&o, &c).unwrap()
        );
    }

    #[test]
    fn changing_a_coin_changes_the_root() {
        let (o, a, b) = (op(1, 0), coin(5), coin(6));
        assert_ne!(state_root_of([(&o, &a)]).unwrap(), state_root_of([(&o, &b)]).unwrap());
    }

    #[test]
    fn changing_an_outpoint_changes_the_root() {
        let (a, b, c) = (op(1, 0), op(1, 1), coin(5));
        assert_ne!(state_root_of([(&a, &c)]).unwrap(), state_root_of([(&b, &c)]).unwrap());
    }

    #[test]
    fn insertion_order_does_not_matter() {
        let entries = [(op(3, 9), coin(1)), (op(1, 2), coin(2)), (op(2, 0), coin(3))];
        let forward = state_root_of(entries.iter().map(|(o, c)| (o, c))).unwrap();
        let backward = state_root_of(entries.iter().rev().map(|(o, c)| (o, c))).unwrap();
        assert_eq!(forward, backward);
    }

    #[test]
    fn the_order_is_borsh_bytes_not_outpoint_ord() {
        // vout 1 and vout 256 sort one way numerically and the other way as
        // little-endian bytes. The root must follow the bytes.
        let txid = Txid(Hash32::from_bytes([0xaa; 32]));
        let low = OutPoint::new(txid, 1);
        let high = OutPoint::new(txid, 256);
        assert!(low < high, "Ord is numeric");
        assert!(outpoint_key(&high) < outpoint_key(&low), "bytes disagree with Ord");

        let (c1, c2) = (coin(1), coin(2));
        let root = state_root_of([(&low, &c1), (&high, &c2)]).unwrap();
        let by_bytes = state_root_of_sorted_leaves(&[
            state_root_leaf(&high, &c2).unwrap(),
            state_root_leaf(&low, &c1).unwrap(),
        ]);
        let by_ord = state_root_of_sorted_leaves(&[
            state_root_leaf(&low, &c1).unwrap(),
            state_root_leaf(&high, &c2).unwrap(),
        ]);
        assert_eq!(root, by_bytes);
        assert_ne!(root, by_ord, "sorting by Ord would give a different root");
    }

    #[test]
    fn the_builder_matches_the_batch_function() {
        let entries = [(op(1, 0), coin(1)), (op(2, 0), coin(2)), (op(3, 0), coin(3))];
        let mut b = StateRootBuilder::new();
        assert!(b.is_empty());
        for (o, c) in &entries {
            b.push_bytes(&outpoint_key(o), &borsh::to_vec(c).unwrap());
        }
        assert_eq!(b.len(), 3);
        assert_eq!(b.finish(), state_root_of(entries.iter().map(|(o, c)| (o, c))).unwrap());
    }

    #[test]
    fn a_promoted_odd_leaf_never_duplicates() {
        // Three leaves: the third is promoted, not doubled. If it were
        // duplicated, a two-leaf set built from the first two plus a repeat of
        // the third would collide, which is CVE-2012-2459.
        let entries = [(op(1, 0), coin(1)), (op(2, 0), coin(2)), (op(3, 0), coin(3))];
        let three = state_root_of(entries.iter().map(|(o, c)| (o, c))).unwrap();
        let leaves: Vec<Hash32> =
            entries.iter().map(|(o, c)| state_root_leaf(o, c).unwrap()).collect();
        let duplicated = state_root_of_sorted_leaves(&[leaves[0], leaves[1], leaves[2], leaves[2]]);
        assert_ne!(three, duplicated);
    }

    #[test]
    fn removing_an_entry_changes_the_root() {
        let entries = [(op(1, 0), coin(1)), (op(2, 0), coin(2))];
        let both = state_root_of(entries.iter().map(|(o, c)| (o, c))).unwrap();
        let one = state_root_of(entries.iter().take(1).map(|(o, c)| (o, c))).unwrap();
        assert_ne!(both, one);
    }

    proptest! {
        #[test]
        fn the_root_is_independent_of_enumeration_order(
            mut entries in proptest::collection::vec(
                (any::<u8>(), any::<u32>(), any::<u64>()), 0..24
            ),
            rotate in 0usize..24,
        ) {
            // Deduplicate by outpoint: a UTXO set is a map, not a bag.
            entries.sort_unstable();
            entries.dedup_by_key(|(n, v, _)| (*n, *v));

            let built: Vec<(OutPoint, Coin)> = entries
                .iter()
                .map(|(n, v, value)| (op(*n, *v), coin(*value)))
                .collect();

            let canonical = state_root_of(built.iter().map(|(o, c)| (o, c)))?;

            let mut shuffled = built.clone();
            let len = shuffled.len();
            if len != 0 {
                shuffled.rotate_left(rotate % len);
            }
            shuffled.reverse();
            let other = state_root_of(shuffled.iter().map(|(o, c)| (o, c)))?;
            prop_assert_eq!(canonical, other);
        }

        #[test]
        fn distinct_sets_get_distinct_roots(
            a in proptest::collection::btree_map(any::<u32>(), any::<u64>(), 1..8),
            extra in any::<u32>(),
        ) {
            let txid_byte = 0x5au8;
            let set_a: Vec<(OutPoint, Coin)> =
                a.iter().map(|(v, value)| (op(txid_byte, *v), coin(*value))).collect();
            let root_a = state_root_of(set_a.iter().map(|(o, c)| (o, c)))?;

            if !a.contains_key(&extra) {
                let mut set_b = set_a.clone();
                set_b.push((op(txid_byte, extra), coin(1)));
                let root_b = state_root_of(set_b.iter().map(|(o, c)| (o, c)))?;
                prop_assert_ne!(root_a, root_b);
            }
        }
    }
}
