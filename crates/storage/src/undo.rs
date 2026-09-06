//! Undo records — what makes a reorganisation possible without replaying from
//! genesis (CONTRACT §7, SPEC §7.3).
//!
//! Connecting a block *destroys* information: the coins it spends leave the
//! UTXO set, and a `TxIn` records only an outpoint, never the value, script,
//! height or coinbase flag of the output it consumed. Without a record of
//! those four facts, `disconnect_tip` cannot put the coin back, and the only
//! way to undo a block is to rebuild the whole UTXO set from height 0.
//!
//! This is the single most common omission in from-scratch implementations,
//! and it cannot be retrofitted: the records for historical blocks do not
//! exist, so adding undo data later forces a full reindex on every deployed
//! node. Writing it from the first commit costs one extra `Vec` per block.
//!
//! The order matters. [`UndoBlock::spent`] is in the exact order the inputs
//! were spent, which is what lets the explorer attribute a spend to a
//! particular transaction and what makes the reversal deterministic.

use borsh::{BorshDeserialize, BorshSerialize};
use ferrum_crypto::{TAG_UNDO, tagged_hash};
use ferrum_types::{Coin, Hash32, OutPoint};
use serde::{Deserialize, Serialize};

/// One output that a block consumed, plus the outpoint that named it.
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
pub struct UndoCoin {
    /// The outpoint that was spent.
    pub out_point: OutPoint,
    /// The coin as it stood before the spend, restored verbatim on undo.
    pub coin: Coin,
}

impl UndoCoin {
    /// Pair an outpoint with the coin it named.
    #[must_use]
    pub fn new(out_point: OutPoint, coin: Coin) -> Self {
        UndoCoin { out_point, coin }
    }
}

/// Everything a block spent, in input order.
///
/// Created outputs are deliberately *not* recorded: they are recoverable from
/// the block body, which is stored anyway, so duplicating them would double
/// the undo log for no new information.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct UndoBlock {
    /// Spent coins, in the exact order the block's inputs consumed them.
    pub spent: Vec<UndoCoin>,
}

impl UndoBlock {
    /// An undo record for a block that spends nothing (a genesis or a
    /// coinbase-only block).
    #[must_use]
    pub fn empty() -> Self {
        UndoBlock { spent: Vec::new() }
    }

    /// Build an undo record from `(outpoint, coin)` pairs in input order.
    #[must_use]
    pub fn from_spent(spent: &[(OutPoint, Coin)]) -> Self {
        UndoBlock {
            spent: spent.iter().map(|(op, coin)| UndoCoin::new(*op, coin.clone())).collect(),
        }
    }

    /// Number of coins this record restores.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spent.len()
    }

    /// Whether the block spent nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }

    /// A domain-separated digest of the record, for logs and integrity checks.
    ///
    /// Not consensus state — nothing commits to it — but it turns "the undo
    /// log changed" from an invisible event into a one-line diff, which is
    /// worth the eight lines it costs.
    #[must_use]
    pub fn digest(&self) -> Hash32 {
        let bytes = borsh::to_vec(self)
            .expect("borsh serialisation into a Vec is infallible for UndoBlock");
        tagged_hash(TAG_UNDO, &bytes)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ferrum_types::{Amount, Script, Txid};

    fn op(n: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid(Hash32::from_bytes([n; 32])), vout)
    }

    fn coin(v: u64, h: u64, cb: bool) -> Coin {
        Coin {
            value: Amount::from_grains(v),
            script_pubkey: Script::new(vec![0x51]),
            height: h,
            is_coinbase: cb,
        }
    }

    #[test]
    fn from_spent_preserves_input_order() {
        let spent = vec![
            (op(3, 0), coin(1, 1, false)),
            (op(1, 7), coin(2, 2, true)),
            (op(2, 1), coin(3, 3, false)),
        ];
        let undo = UndoBlock::from_spent(&spent);
        assert_eq!(undo.len(), 3);
        // Order is the *input* order, not sorted order: the second entry is
        // still outpoint 1, which sorts first.
        assert_eq!(undo.spent[0].out_point, op(3, 0));
        assert_eq!(undo.spent[1].out_point, op(1, 7));
        assert_eq!(undo.spent[2].out_point, op(2, 1));
    }

    #[test]
    fn empty_record_is_empty() {
        let u = UndoBlock::default();
        assert!(u.is_empty());
        assert_eq!(u.len(), 0);
        assert_eq!(UndoBlock::empty(), u);
    }

    #[test]
    fn borsh_round_trips_and_rejects_a_suffix() {
        let u = UndoBlock::from_spent(&[(op(1, 0), coin(5, 9, true))]);
        let b = borsh::to_vec(&u).unwrap();
        assert_eq!(borsh::from_slice::<UndoBlock>(&b).unwrap(), u);
        let mut extra = b;
        extra.push(0);
        assert!(borsh::from_slice::<UndoBlock>(&extra).is_err());
    }

    #[test]
    fn the_digest_is_order_sensitive() {
        let a =
            UndoBlock::from_spent(&[(op(1, 0), coin(1, 1, false)), (op(2, 0), coin(2, 2, false))]);
        let b =
            UndoBlock::from_spent(&[(op(2, 0), coin(2, 2, false)), (op(1, 0), coin(1, 1, false))]);
        assert_ne!(a.digest(), b.digest(), "input order is part of the record");
    }

    #[test]
    fn the_digest_is_domain_separated() {
        let u = UndoBlock::from_spent(&[(op(1, 0), coin(1, 1, false))]);
        let raw = borsh::to_vec(&u).unwrap();
        assert_ne!(u.digest(), tagged_hash(ferrum_crypto::TAG_TXID, &raw));
    }

    #[test]
    fn the_digest_is_stable_across_calls() {
        let u = UndoBlock::from_spent(&[(op(4, 2), coin(7, 8, true))]);
        assert_eq!(u.digest(), u.digest());
    }

    #[test]
    fn serde_json_round_trips() {
        let u = UndoBlock::from_spent(&[(op(1, 0), coin(5, 9, true))]);
        let j = serde_json::to_string(&u).unwrap();
        assert_eq!(serde_json::from_str::<UndoBlock>(&j).unwrap(), u);
    }

    #[test]
    fn a_restored_coin_is_byte_identical_to_the_original() {
        let original = coin(123_456, 77, true);
        let u = UndoBlock::from_spent(&[(op(9, 3), original.clone())]);
        let round_tripped = borsh::from_slice::<UndoBlock>(&borsh::to_vec(&u).unwrap()).unwrap();
        assert_eq!(
            borsh::to_vec(&round_tripped.spent[0].coin).unwrap(),
            borsh::to_vec(&original).unwrap()
        );
    }
}
