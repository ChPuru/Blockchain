//! The wallet's UTXO cache and the balance it computes from it.
//!
//! **Balances come from the set handed to [`CoinCache::sync`], never from a
//! rescan.** That is CONTRACT §12 and it is also the only design that works:
//! rescanning the chain to answer `getbalance` turns an O(1) question into an
//! O(chain) one, and every wallet that has done it has ended up caching the
//! answer anyway — but with a cache that can silently disagree with the chain.
//! Here the caller (RPC `listunspent`, or the node's own index) owns the
//! authoritative set and the wallet owns nothing but a view of it.
//!
//! # The three buckets
//!
//! | Bucket | Rule |
//! |---|---|
//! | `pending` | `coin.height > tip_height`, or the coin is reserved by a transaction this wallet built and has not seen confirmed |
//! | `immature` | `coin.is_coinbase` and `tip_height - coin.height < coinbase_maturity` |
//! | `confirmed` | everything else — spendable right now |
//!
//! The maturity rule deserves a note. Consensus (CONTRACT §8.1 rule 7) allows
//! spending a coinbase in a block at height `coin.height + maturity` or above.
//! A transaction the wallet builds now lands at `tip_height + 1`, so consensus
//! would already permit `tip_height + 1 >= coin.height + maturity`. This module
//! is deliberately one block more conservative — `tip_height >= coin.height +
//! maturity` — which matches Bitcoin Core's wallet (`GetBlocksToMaturity`
//! counts confirmations, and a coin has one confirmation in the block that
//! created it). Being a block early is a transaction that is rejected until it
//! is not; being a block late costs two minutes.

use std::collections::{BTreeMap, BTreeSet};

use ferrum_types::{Amount, Coin, OutPoint};

use crate::error::WalletError;

/// A wallet balance, split three ways.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Balance {
    /// Spendable right now.
    pub confirmed: Amount,
    /// Coinbase output still inside its maturity window.
    pub immature: Amount,
    /// Not yet confirmed, or committed to an outgoing transaction.
    pub pending: Amount,
}

impl Balance {
    /// An all-zero balance.
    pub const ZERO: Balance =
        Balance { confirmed: Amount::ZERO, immature: Amount::ZERO, pending: Amount::ZERO };

    /// The sum of all three buckets.
    ///
    /// Returns an error rather than saturating: a wallet whose total silently
    /// clamps at `u64::MAX` is a wallet that will one day report a balance
    /// nobody can explain.
    pub fn total(&self) -> Result<Amount, WalletError> {
        self.confirmed
            .checked_add(self.immature)
            .and_then(|v| v.checked_add(self.pending))
            .ok_or(WalletError::AmountOverflow("summing a balance"))
    }

    /// Alias for [`Balance::confirmed`]: what coin selection may draw on.
    pub const fn spendable(&self) -> Amount {
        self.confirmed
    }
}

/// Which bucket one coin falls into.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoinStatus {
    /// Confirmed, mature, unreserved: selectable.
    Confirmed,
    /// A coinbase output still inside its maturity window.
    Immature,
    /// Created above the tip the wallet has seen.
    Pending,
    /// Already committed to a transaction this wallet built.
    Reserved,
}

impl CoinStatus {
    /// True only for [`CoinStatus::Confirmed`].
    pub const fn is_spendable(self) -> bool {
        matches!(self, CoinStatus::Confirmed)
    }
}

/// One entry of the cache, as [`CoinCache::iter_status`] yields it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletCoin {
    /// Where the coin lives.
    pub out_point: OutPoint,
    /// The coin itself.
    pub coin: Coin,
    /// Which bucket it is in at the tip the cache was synced to.
    pub status: CoinStatus,
}

/// The wallet's view of its own unspent outputs.
///
/// A `BTreeMap`, not a `HashMap`: coin selection must be reproducible, and a
/// selection that depends on hash iteration order produces a different
/// transaction on every run, which makes a failure impossible to reproduce
/// from a bug report.
#[derive(Clone, Debug, Default)]
pub struct CoinCache {
    coins: BTreeMap<OutPoint, Coin>,
    reserved: BTreeSet<OutPoint>,
    tip: u64,
}

impl CoinCache {
    /// An empty cache at height zero.
    pub fn new() -> Self {
        CoinCache::default()
    }

    /// Replace the whole set with the one the caller supplies.
    ///
    /// Replacement rather than merge is deliberate: the caller holds the
    /// authoritative UTXO set, and a merge would keep coins alive in the
    /// wallet after the chain has spent them. Reservations for outpoints that
    /// no longer exist are dropped, because a reserved coin that has left the
    /// UTXO set is a transaction that confirmed.
    pub fn sync(&mut self, utxos: Vec<(OutPoint, Coin)>, tip: u64) {
        self.coins = utxos.into_iter().collect();
        self.tip = tip;
        let coins = &self.coins;
        self.reserved.retain(|op| coins.contains_key(op));
    }

    /// The tip height the cache was last synced to.
    pub const fn tip(&self) -> u64 {
        self.tip
    }

    /// How many coins the cache holds.
    pub fn len(&self) -> usize {
        self.coins.len()
    }

    /// True when the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.coins.is_empty()
    }

    /// Look one coin up.
    pub fn get(&self, out_point: &OutPoint) -> Option<&Coin> {
        self.coins.get(out_point)
    }

    /// Every coin, in outpoint order.
    pub fn iter(&self) -> impl Iterator<Item = (&OutPoint, &Coin)> {
        self.coins.iter()
    }

    /// Outpoints currently committed to an unconfirmed outgoing transaction.
    pub const fn reserved(&self) -> &BTreeSet<OutPoint> {
        &self.reserved
    }

    /// Mark outpoints as committed to a transaction this wallet built.
    ///
    /// Without this a second `send` before the first confirms selects the same
    /// coins and produces a double spend that the mempool silently drops —
    /// the user sees one payment vanish with no error anywhere.
    pub fn reserve(&mut self, out_points: &[OutPoint]) {
        for op in out_points {
            self.reserved.insert(*op);
        }
    }

    /// Release a reservation, e.g. after a broadcast failed.
    pub fn unreserve(&mut self, out_points: &[OutPoint]) {
        for op in out_points {
            self.reserved.remove(op);
        }
    }

    /// Drop every reservation.
    pub fn clear_reservations(&mut self) {
        self.reserved.clear();
    }

    /// Classify one coin against a tip height and a maturity rule.
    pub fn status_of(
        &self,
        out_point: &OutPoint,
        coin: &Coin,
        tip_height: u64,
        maturity: u64,
    ) -> CoinStatus {
        if self.reserved.contains(out_point) {
            return CoinStatus::Reserved;
        }
        if coin.height > tip_height {
            return CoinStatus::Pending;
        }
        // `coin.height <= tip_height` here, so the subtraction cannot wrap;
        // `saturating_sub` states that rather than relying on the reader to
        // re-derive it.
        if coin.is_coinbase && tip_height.saturating_sub(coin.height) < maturity {
            return CoinStatus::Immature;
        }
        CoinStatus::Confirmed
    }

    /// Every coin with its bucket, in outpoint order.
    pub fn iter_status(
        &self,
        tip_height: u64,
        maturity: u64,
    ) -> impl Iterator<Item = WalletCoin> + '_ {
        self.coins.iter().map(move |(op, coin)| WalletCoin {
            out_point: *op,
            coin: coin.clone(),
            status: self.status_of(op, coin, tip_height, maturity),
        })
    }

    /// The three-way balance.
    ///
    /// Sums saturate rather than wrapping. A wallet cannot hold more than
    /// `MAX_MONEY`, so a saturation here means the caller handed the cache a
    /// fabricated UTXO set; reporting `u64::MAX` is loud, and wrapping to a
    /// small number would be silent.
    pub fn balance(&self, tip_height: u64, maturity: u64) -> Balance {
        let mut balance = Balance::ZERO;
        for entry in self.iter_status(tip_height, maturity) {
            let value = entry.coin.value;
            match entry.status {
                CoinStatus::Confirmed => {
                    balance.confirmed = balance.confirmed.saturating_add(value);
                }
                CoinStatus::Immature => {
                    balance.immature = balance.immature.saturating_add(value);
                }
                CoinStatus::Pending | CoinStatus::Reserved => {
                    balance.pending = balance.pending.saturating_add(value);
                }
            }
        }
        balance
    }

    /// Every coin coin selection may draw on, in outpoint order.
    pub fn spendable(&self, tip_height: u64, maturity: u64) -> Vec<(OutPoint, Coin)> {
        self.iter_status(tip_height, maturity)
            .filter(|c| c.status.is_spendable())
            .map(|c| (c.out_point, c.coin))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]

    use ferrum_types::{Script, Txid};

    use super::*;

    const MATURITY: u64 = 100;

    fn op(n: u8) -> OutPoint {
        OutPoint::new(Txid::from_bytes([n; 32]), 0)
    }

    fn coin(value: u64, height: u64, is_coinbase: bool) -> Coin {
        Coin {
            value: Amount::from_grains(value),
            script_pubkey: Script::new(vec![0x51]),
            height,
            is_coinbase,
        }
    }

    #[test]
    fn an_empty_cache_has_a_zero_balance() {
        let cache = CoinCache::new();
        assert_eq!(cache.balance(0, MATURITY), Balance::ZERO);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn a_plain_coin_is_confirmed() {
        let mut cache = CoinCache::new();
        cache.sync(vec![(op(1), coin(500, 10, false))], 10);
        let balance = cache.balance(10, MATURITY);
        assert_eq!(balance.confirmed, Amount::from_grains(500));
        assert_eq!(balance.immature, Amount::ZERO);
        assert_eq!(balance.pending, Amount::ZERO);
    }

    #[test]
    fn coinbase_one_block_before_maturity_is_immature() {
        let mut cache = CoinCache::new();
        cache.sync(vec![(op(1), coin(500, 10, true))], 10 + MATURITY - 1);
        let balance = cache.balance(10 + MATURITY - 1, MATURITY);
        assert_eq!(balance.immature, Amount::from_grains(500));
        assert_eq!(balance.confirmed, Amount::ZERO);
    }

    #[test]
    fn coinbase_at_exactly_maturity_blocks_is_confirmed() {
        let mut cache = CoinCache::new();
        let tip = 10 + MATURITY;
        cache.sync(vec![(op(1), coin(500, 10, true))], tip);
        let balance = cache.balance(tip, MATURITY);
        assert_eq!(balance.confirmed, Amount::from_grains(500));
        assert_eq!(balance.immature, Amount::ZERO);
    }

    #[test]
    fn maturity_boundary_is_exactly_one_block_wide() {
        let mut cache = CoinCache::new();
        cache.sync(vec![(op(1), coin(500, 10, true))], 0);
        // Sweep the boundary from both sides and assert the flip happens once.
        for tip in (10 + MATURITY - 3)..=(10 + MATURITY + 3) {
            let status = cache.status_of(&op(1), &coin(500, 10, true), tip, MATURITY);
            let expected =
                if tip >= 10 + MATURITY { CoinStatus::Confirmed } else { CoinStatus::Immature };
            assert_eq!(status, expected, "tip {tip}");
        }
    }

    #[test]
    fn a_non_coinbase_is_never_immature() {
        let cache = CoinCache::new();
        assert_eq!(
            cache.status_of(&op(1), &coin(500, 10, false), 10, MATURITY),
            CoinStatus::Confirmed
        );
    }

    #[test]
    fn a_coin_above_the_tip_is_pending() {
        let mut cache = CoinCache::new();
        cache.sync(vec![(op(1), coin(500, 50, false))], 49);
        let balance = cache.balance(49, MATURITY);
        assert_eq!(balance.pending, Amount::from_grains(500));
        assert_eq!(balance.confirmed, Amount::ZERO);
    }

    #[test]
    fn a_reserved_coin_moves_to_pending_and_out_of_spendable() {
        let mut cache = CoinCache::new();
        cache.sync(vec![(op(1), coin(500, 1, false)), (op(2), coin(700, 1, false))], 10);
        cache.reserve(&[op(1)]);
        let balance = cache.balance(10, MATURITY);
        assert_eq!(balance.pending, Amount::from_grains(500));
        assert_eq!(balance.confirmed, Amount::from_grains(700));
        let spendable = cache.spendable(10, MATURITY);
        assert_eq!(spendable.len(), 1);
        assert_eq!(spendable[0].0, op(2));
    }

    #[test]
    fn unreserve_puts_a_coin_back() {
        let mut cache = CoinCache::new();
        cache.sync(vec![(op(1), coin(500, 1, false))], 10);
        cache.reserve(&[op(1)]);
        cache.unreserve(&[op(1)]);
        assert_eq!(cache.balance(10, MATURITY).confirmed, Amount::from_grains(500));
        assert!(cache.reserved().is_empty());
    }

    #[test]
    fn sync_drops_reservations_for_coins_that_left_the_set() {
        let mut cache = CoinCache::new();
        cache.sync(vec![(op(1), coin(500, 1, false))], 10);
        cache.reserve(&[op(1)]);
        assert_eq!(cache.reserved().len(), 1);
        cache.sync(vec![(op(2), coin(400, 11, false))], 11);
        assert!(cache.reserved().is_empty());
    }

    #[test]
    fn sync_replaces_rather_than_merges() {
        let mut cache = CoinCache::new();
        cache.sync(vec![(op(1), coin(500, 1, false))], 10);
        cache.sync(vec![(op(2), coin(400, 2, false))], 11);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&op(1)).is_none());
        assert_eq!(cache.tip(), 11);
    }

    #[test]
    fn balance_total_sums_all_three_buckets() {
        let mut cache = CoinCache::new();
        cache.sync(
            vec![
                (op(1), coin(100, 1, false)),  // confirmed
                (op(2), coin(200, 5, true)),   // immature
                (op(3), coin(300, 99, false)), // pending
            ],
            50,
        );
        let balance = cache.balance(50, MATURITY);
        assert_eq!(balance.confirmed, Amount::from_grains(100));
        assert_eq!(balance.immature, Amount::from_grains(200));
        assert_eq!(balance.pending, Amount::from_grains(300));
        assert_eq!(balance.total().unwrap(), Amount::from_grains(600));
        assert_eq!(balance.spendable(), Amount::from_grains(100));
    }

    #[test]
    fn balance_total_reports_overflow_instead_of_wrapping() {
        let balance = Balance {
            confirmed: Amount::from_grains(u64::MAX),
            immature: Amount::from_grains(1),
            pending: Amount::ZERO,
        };
        assert!(matches!(balance.total(), Err(WalletError::AmountOverflow(_))));
    }

    #[test]
    fn iteration_is_in_outpoint_order() {
        let mut cache = CoinCache::new();
        cache.sync(
            vec![
                (op(9), coin(1, 1, false)),
                (op(3), coin(1, 1, false)),
                (op(7), coin(1, 1, false)),
            ],
            10,
        );
        let order: Vec<OutPoint> = cache.iter().map(|(op, _)| *op).collect();
        assert_eq!(order, vec![op(3), op(7), op(9)]);
    }

    #[test]
    fn spendable_excludes_immature_and_pending() {
        let mut cache = CoinCache::new();
        cache.sync(
            vec![
                (op(1), coin(100, 1, false)),
                (op(2), coin(200, 5, true)),
                (op(3), coin(300, 99, false)),
            ],
            50,
        );
        let spendable = cache.spendable(50, MATURITY);
        assert_eq!(spendable.len(), 1);
        assert_eq!(spendable[0].0, op(1));
    }

    #[test]
    fn clear_reservations_releases_everything() {
        let mut cache = CoinCache::new();
        cache.sync(vec![(op(1), coin(1, 1, false)), (op(2), coin(1, 1, false))], 5);
        cache.reserve(&[op(1), op(2)]);
        cache.clear_reservations();
        assert!(cache.reserved().is_empty());
    }
}
