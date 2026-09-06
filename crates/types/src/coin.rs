//! The UTXO-set entry.
//!
//! A [`Coin`] is a [`TxOut`] plus the two facts a validator cannot recover
//! from the output alone: the height of the block that created it, and whether
//! it came from a coinbase. Storing them here is what makes coinbase-maturity
//! enforcement a local check instead of a walk back through the chain, and
//! what lets an undo record restore a spent output byte-for-byte.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::amount::Amount;
use crate::script::Script;
use crate::tx::TxOut;

/// One spendable output plus the context needed to validate a spend of it and
/// to undo that spend on a reorg (CONTRACT §3).
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
pub struct Coin {
    /// Value of the output.
    pub value: Amount,
    /// Locking script of the output.
    pub script_pubkey: Script,
    /// Height of the block that created the output.
    pub height: u64,
    /// Whether the creating transaction was a coinbase.
    pub is_coinbase: bool,
}

impl Coin {
    /// Build a coin from an output and its creation context.
    pub fn new(out: TxOut, height: u64, is_coinbase: bool) -> Self {
        Coin { value: out.value, script_pubkey: out.script_pubkey, height, is_coinbase }
    }

    /// Turn the coin back into the output it came from.
    ///
    /// Note there is deliberately no `is_mature` helper here: coinbase
    /// maturity is a consensus rule and lives in `ferrum-chain` (CONTRACT
    /// §8.1 rule 7). A rule implemented in two crates is a rule that will one
    /// day be implemented two different ways.
    pub fn to_tx_out(&self) -> TxOut {
        TxOut { value: self.value, script_pubkey: self.script_pubkey.clone() }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn coin(is_coinbase: bool) -> Coin {
        Coin::new(TxOut::new(Amount::from_grains(9), Script::new(vec![0xaa])), 100, is_coinbase)
    }

    #[test]
    fn conversions_round_trip() {
        let out = TxOut::new(Amount::from_grains(9), Script::new(vec![0xaa]));
        let c = Coin::new(out.clone(), 42, true);
        assert_eq!(c.value, out.value);
        assert_eq!(c.script_pubkey, out.script_pubkey);
        assert_eq!(c.height, 42);
        assert!(c.is_coinbase);
        assert_eq!(c.to_tx_out(), out);
    }

    #[test]
    fn borsh_round_trips_and_rejects_a_suffix() {
        let c = coin(true);
        let b = borsh::to_vec(&c).unwrap();
        assert_eq!(borsh::from_slice::<Coin>(&b).unwrap(), c);
        let mut extra = b;
        extra.push(0);
        assert!(borsh::from_slice::<Coin>(&extra).is_err());
    }

    #[test]
    fn borsh_layout_is_value_script_height_flag() {
        let c = Coin::new(TxOut::new(Amount::from_grains(1), Script::EMPTY), 1, false);
        let b = borsh::to_vec(&c).unwrap();
        // 8 value + 4 script length + 0 script + 8 height + 1 bool
        assert_eq!(b.len(), 21);
        assert_eq!(&b[0..8], &1u64.to_le_bytes());
        assert_eq!(&b[8..12], &0u32.to_le_bytes());
        assert_eq!(&b[12..20], &1u64.to_le_bytes());
        assert_eq!(b[20], 0, "false encodes as a zero byte");
    }

    #[test]
    fn borsh_rejects_a_non_canonical_bool() {
        let mut b = borsh::to_vec(&coin(true)).unwrap();
        *b.last_mut().unwrap() = 2;
        assert!(borsh::from_slice::<Coin>(&b).is_err());
    }

    #[test]
    fn serde_json_round_trips() {
        let c = coin(true);
        let j = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<Coin>(&j).unwrap(), c);
        assert!(j.contains("\"is_coinbase\":true"));
        assert!(j.contains("\"script_pubkey\":\"aa\""), "the script is hex: {j}");
    }

    #[test]
    fn a_non_coinbase_coin_records_its_flag() {
        let c = coin(false);
        assert!(!c.is_coinbase);
        assert_eq!(c.height, 100);
    }

    #[test]
    fn default_is_a_zero_valued_non_coinbase() {
        let c = Coin::default();
        assert_eq!(c.value, Amount::ZERO);
        assert!(c.script_pubkey.is_empty());
        assert_eq!(c.height, 0);
        assert!(!c.is_coinbase);
    }
}
