//! The read seam between validation and storage, and the in-memory overlay
//! that block validation writes into (CONTRACT §7).
//!
//! [`StateView`] is the *only* thing `ferrum-chain::apply_block` knows about
//! the UTXO set. That is what keeps the determinism seam pure: the validator
//! is handed a reader, never a database, so it cannot open a transaction, take
//! a lock, or observe anything that varies between machines.
//!
//! [`OverlayView`] is the scratch space a block is validated in. It records
//! every spend and every creation in memory and touches nothing on disk. The
//! resulting [`StateDiff`] is what `Store::connect_block` applies — in one
//! transaction, tip last. Validation that wrote directly to the database would
//! have to roll back on every invalid block, and a rollback path that runs
//! only on failure is a rollback path that is never tested.

use std::collections::BTreeMap;
use std::fmt;

use ferrum_types::{Coin, OutPoint};

use crate::error::StorageError;
use crate::undo::UndoBlock;

/// A read-only view of the UTXO set.
///
/// Implemented by [`crate::Store`] (the committed set) and by
/// [`OverlayView`] (the committed set plus the in-flight block's changes).
pub trait StateView: Send + Sync {
    /// The coin at `op`, or `None` if it does not exist or has been spent.
    ///
    /// # Errors
    /// Propagates any storage failure from the backing view.
    fn get_coin(&self, op: &OutPoint) -> Result<Option<Coin>, StorageError>;

    /// Whether `op` is currently unspent.
    ///
    /// # Errors
    /// Propagates any storage failure from the backing view.
    fn has_coin(&self, op: &OutPoint) -> Result<bool, StorageError>;
}

impl<T: StateView + ?Sized> StateView for &T {
    fn get_coin(&self, op: &OutPoint) -> Result<Option<Coin>, StorageError> {
        (**self).get_coin(op)
    }

    fn has_coin(&self, op: &OutPoint) -> Result<bool, StorageError> {
        (**self).has_coin(op)
    }
}

impl<T: StateView + ?Sized> StateView for std::sync::Arc<T> {
    fn get_coin(&self, op: &OutPoint) -> Result<Option<Coin>, StorageError> {
        (**self).get_coin(op)
    }

    fn has_coin(&self, op: &OutPoint) -> Result<bool, StorageError> {
        (**self).has_coin(op)
    }
}

/// An empty view: every lookup misses.
///
/// Useful as the pre-state for genesis and in tests that want a view with no
/// database behind it at all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EmptyView;

impl StateView for EmptyView {
    fn get_coin(&self, _op: &OutPoint) -> Result<Option<Coin>, StorageError> {
        Ok(None)
    }

    fn has_coin(&self, _op: &OutPoint) -> Result<bool, StorageError> {
        Ok(false)
    }
}

/// A `BTreeMap`-backed view, for tests, the reference executor and any caller
/// holding a whole UTXO set in memory.
///
/// `BTreeMap`, never `HashMap`: iteration order is part of the state root.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MapView {
    coins: BTreeMap<OutPoint, Coin>,
}

impl MapView {
    /// An empty map view.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a coin.
    pub fn insert(&mut self, op: OutPoint, coin: Coin) -> Option<Coin> {
        self.coins.insert(op, coin)
    }

    /// Remove a coin.
    pub fn remove(&mut self, op: &OutPoint) -> Option<Coin> {
        self.coins.remove(op)
    }

    /// Number of unspent outputs held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.coins.len()
    }

    /// Whether the view holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.coins.is_empty()
    }

    /// Iterate the coins in `OutPoint` order.
    pub fn iter(&self) -> impl Iterator<Item = (&OutPoint, &Coin)> {
        self.coins.iter()
    }
}

impl FromIterator<(OutPoint, Coin)> for MapView {
    fn from_iter<I: IntoIterator<Item = (OutPoint, Coin)>>(iter: I) -> Self {
        MapView { coins: iter.into_iter().collect() }
    }
}

impl StateView for MapView {
    fn get_coin(&self, op: &OutPoint) -> Result<Option<Coin>, StorageError> {
        Ok(self.coins.get(op).cloned())
    }

    fn has_coin(&self, op: &OutPoint) -> Result<bool, StorageError> {
        Ok(self.coins.contains_key(op))
    }
}

/// The complete effect of one block on the UTXO set.
///
/// `spent` is in the exact order the block's inputs consumed the coins, which
/// is what makes it the undo record verbatim. `created` is in output order,
/// transaction by transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateDiff {
    /// Coins removed, in input order. Becomes the [`UndoBlock`].
    pub spent: Vec<(OutPoint, Coin)>,
    /// Coins added, in `(tx index, vout)` order.
    pub created: Vec<(OutPoint, Coin)>,
}

impl StateDiff {
    /// An empty diff.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The undo record this diff implies.
    #[must_use]
    pub fn undo_block(&self) -> UndoBlock {
        UndoBlock::from_spent(&self.spent)
    }

    /// Whether the diff changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spent.is_empty() && self.created.is_empty()
    }

    /// Net change in the number of unspent outputs, as `(created, spent)`.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        (self.created.len(), self.spent.len())
    }
}

/// An in-memory overlay over a backing [`StateView`].
///
/// Reads fall through to the base view; a key the overlay has marked spent
/// reads back as `None` even though the base still holds it; and nothing
/// reaches the database until [`crate::Store::connect_block`] applies the
/// [`StateDiff`] this overlay produces.
///
/// The `cache` is a `BTreeMap<OutPoint, Option<Coin>>` exactly as CONTRACT §7
/// specifies — `Some` for a coin created in this block, `None` for a coin
/// spent by it. The two ordered vectors alongside it exist because the diff
/// must preserve *input order*, which a map cannot express.
pub struct OverlayView<'a> {
    base: &'a dyn StateView,
    cache: BTreeMap<OutPoint, Option<Coin>>,
    spent_order: Vec<(OutPoint, Coin)>,
    created_order: Vec<(OutPoint, Coin)>,
}

impl fmt::Debug for OverlayView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The base is a trait object with no Debug bound, so it is summarised
        // rather than printed.
        f.debug_struct("OverlayView")
            .field("cached", &self.cache.len())
            .field("spent", &self.spent_order.len())
            .field("created", &self.created_order.len())
            .finish_non_exhaustive()
    }
}

impl<'a> OverlayView<'a> {
    /// Wrap a base view.
    #[must_use]
    pub fn new(base: &'a dyn StateView) -> Self {
        OverlayView {
            base,
            cache: BTreeMap::new(),
            spent_order: Vec::new(),
            created_order: Vec::new(),
        }
    }

    /// Consume `op`, returning the coin that was there.
    ///
    /// Returns `Ok(None)` when the outpoint does not resolve — either it never
    /// existed or this overlay already spent it. The caller turns that into
    /// `MissingInput`, which a mempool reads as "orphan" and a block validator
    /// reads as "invalid".
    ///
    /// # Errors
    /// Propagates a storage failure from the base view.
    pub fn spend(&mut self, op: &OutPoint) -> Result<Option<Coin>, StorageError> {
        let Some(coin) = self.get_coin(op)? else {
            return Ok(None);
        };
        self.cache.insert(*op, None);
        self.spent_order.push((*op, coin.clone()));
        Ok(Some(coin))
    }

    /// Create a coin at `op`.
    ///
    /// The caller is responsible for CONTRACT §8.1 rule 9 (no created outpoint
    /// may already exist); the overlay records what it is told.
    pub fn add(&mut self, op: OutPoint, coin: Coin) {
        self.cache.insert(op, Some(coin.clone()));
        self.created_order.push((op, coin));
    }

    /// Whether this overlay has marked `op` spent.
    #[must_use]
    pub fn is_spent(&self, op: &OutPoint) -> bool {
        matches!(self.cache.get(op), Some(None))
    }

    /// Number of outpoints the overlay has an opinion about.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the overlay has recorded nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// The spends recorded so far, in input order.
    #[must_use]
    pub fn spent(&self) -> &[(OutPoint, Coin)] {
        &self.spent_order
    }

    /// The creations recorded so far, in output order.
    #[must_use]
    pub fn created(&self) -> &[(OutPoint, Coin)] {
        &self.created_order
    }

    /// The diff this overlay accumulated.
    #[must_use]
    pub fn to_diff(&self) -> StateDiff {
        StateDiff { spent: self.spent_order.clone(), created: self.created_order.clone() }
    }

    /// Consume the overlay and take its diff without cloning.
    #[must_use]
    pub fn into_diff(self) -> StateDiff {
        StateDiff { spent: self.spent_order, created: self.created_order }
    }

    /// Forget every recorded change, keeping the base view.
    ///
    /// Used when a transaction fails half-way through and the caller wants the
    /// overlay back at the state it had before the block.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.spent_order.clear();
        self.created_order.clear();
    }
}

impl StateView for OverlayView<'_> {
    fn get_coin(&self, op: &OutPoint) -> Result<Option<Coin>, StorageError> {
        match self.cache.get(op) {
            // Spent in this block: invisible, even though the base still has it.
            Some(None) => Ok(None),
            Some(Some(coin)) => Ok(Some(coin.clone())),
            None => self.base.get_coin(op),
        }
    }

    fn has_coin(&self, op: &OutPoint) -> Result<bool, StorageError> {
        match self.cache.get(op) {
            Some(None) => Ok(false),
            Some(Some(_)) => Ok(true),
            None => self.base.has_coin(op),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ferrum_types::{Amount, Hash32, Script, Txid};

    fn op(n: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid(Hash32::from_bytes([n; 32])), vout)
    }

    fn coin(v: u64) -> Coin {
        Coin {
            value: Amount::from_grains(v),
            script_pubkey: Script::new(vec![0x51]),
            height: 1,
            is_coinbase: false,
        }
    }

    fn base_with(entries: &[(OutPoint, Coin)]) -> MapView {
        entries.iter().cloned().collect()
    }

    #[test]
    fn empty_view_misses_everything() {
        let v = EmptyView;
        assert_eq!(v.get_coin(&op(1, 0)).unwrap(), None);
        assert!(!v.has_coin(&op(1, 0)).unwrap());
    }

    #[test]
    fn map_view_reads_what_it_holds() {
        let mut m = MapView::new();
        assert!(m.is_empty());
        m.insert(op(1, 0), coin(5));
        assert_eq!(m.len(), 1);
        assert_eq!(m.get_coin(&op(1, 0)).unwrap(), Some(coin(5)));
        assert!(m.has_coin(&op(1, 0)).unwrap());
        assert_eq!(m.remove(&op(1, 0)), Some(coin(5)));
        assert!(m.is_empty());
    }

    #[test]
    fn map_view_iterates_in_outpoint_order() {
        let m = base_with(&[(op(3, 0), coin(1)), (op(1, 0), coin(2)), (op(2, 0), coin(3))]);
        let keys: Vec<OutPoint> = m.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, vec![op(1, 0), op(2, 0), op(3, 0)]);
    }

    #[test]
    fn overlay_reads_fall_through_to_the_base() {
        let base = base_with(&[(op(1, 0), coin(7))]);
        let overlay = OverlayView::new(&base);
        assert_eq!(overlay.get_coin(&op(1, 0)).unwrap(), Some(coin(7)));
        assert!(overlay.has_coin(&op(1, 0)).unwrap());
        assert_eq!(overlay.get_coin(&op(2, 0)).unwrap(), None);
    }

    #[test]
    fn a_spent_key_reads_back_as_none() {
        let base = base_with(&[(op(1, 0), coin(7))]);
        let mut overlay = OverlayView::new(&base);
        assert_eq!(overlay.spend(&op(1, 0)).unwrap(), Some(coin(7)));
        assert_eq!(overlay.get_coin(&op(1, 0)).unwrap(), None);
        assert!(!overlay.has_coin(&op(1, 0)).unwrap());
        assert!(overlay.is_spent(&op(1, 0)));
        // The base is untouched.
        assert_eq!(base.get_coin(&op(1, 0)).unwrap(), Some(coin(7)));
    }

    #[test]
    fn spending_twice_returns_none_the_second_time() {
        let base = base_with(&[(op(1, 0), coin(7))]);
        let mut overlay = OverlayView::new(&base);
        assert!(overlay.spend(&op(1, 0)).unwrap().is_some());
        assert!(overlay.spend(&op(1, 0)).unwrap().is_none(), "double spend within a block");
        assert_eq!(overlay.spent().len(), 1, "the second attempt records nothing");
    }

    #[test]
    fn spending_a_missing_outpoint_returns_none() {
        let base = MapView::new();
        let mut overlay = OverlayView::new(&base);
        assert_eq!(overlay.spend(&op(9, 0)).unwrap(), None);
        assert!(overlay.is_empty());
    }

    #[test]
    fn an_added_coin_is_visible_and_spendable_in_the_same_block() {
        let base = MapView::new();
        let mut overlay = OverlayView::new(&base);
        overlay.add(op(5, 1), coin(11));
        assert_eq!(overlay.get_coin(&op(5, 1)).unwrap(), Some(coin(11)));
        assert_eq!(overlay.spend(&op(5, 1)).unwrap(), Some(coin(11)));
        assert_eq!(overlay.get_coin(&op(5, 1)).unwrap(), None);
    }

    #[test]
    fn the_diff_keeps_input_order_not_sorted_order() {
        let base = base_with(&[(op(3, 0), coin(1)), (op(1, 0), coin(2))]);
        let mut overlay = OverlayView::new(&base);
        overlay.spend(&op(3, 0)).unwrap();
        overlay.spend(&op(1, 0)).unwrap();
        overlay.add(op(9, 0), coin(3));
        let diff = overlay.into_diff();
        assert_eq!(diff.spent[0].0, op(3, 0));
        assert_eq!(diff.spent[1].0, op(1, 0));
        assert_eq!(diff.created, vec![(op(9, 0), coin(3))]);
        assert_eq!(diff.counts(), (1, 2));
    }

    #[test]
    fn to_diff_and_into_diff_agree() {
        let base = base_with(&[(op(1, 0), coin(4))]);
        let mut overlay = OverlayView::new(&base);
        overlay.spend(&op(1, 0)).unwrap();
        overlay.add(op(2, 0), coin(4));
        let borrowed = overlay.to_diff();
        assert_eq!(borrowed, overlay.into_diff());
    }

    #[test]
    fn the_diff_becomes_the_undo_record() {
        let base = base_with(&[(op(1, 0), coin(4)), (op(2, 0), coin(5))]);
        let mut overlay = OverlayView::new(&base);
        overlay.spend(&op(2, 0)).unwrap();
        overlay.spend(&op(1, 0)).unwrap();
        let undo = overlay.into_diff().undo_block();
        assert_eq!(undo.len(), 2);
        assert_eq!(undo.spent[0].out_point, op(2, 0));
        assert_eq!(undo.spent[0].coin, coin(5));
    }

    #[test]
    fn clear_forgets_everything_but_keeps_the_base() {
        let base = base_with(&[(op(1, 0), coin(4))]);
        let mut overlay = OverlayView::new(&base);
        overlay.spend(&op(1, 0)).unwrap();
        overlay.add(op(2, 0), coin(1));
        overlay.clear();
        assert!(overlay.is_empty());
        assert_eq!(overlay.get_coin(&op(1, 0)).unwrap(), Some(coin(4)));
        assert_eq!(overlay.get_coin(&op(2, 0)).unwrap(), None);
        assert!(overlay.into_diff().is_empty());
    }

    #[test]
    fn overlays_nest() {
        let base = base_with(&[(op(1, 0), coin(4))]);
        let mut outer = OverlayView::new(&base);
        outer.add(op(2, 0), coin(9));
        let mut inner = OverlayView::new(&outer);
        assert_eq!(inner.get_coin(&op(2, 0)).unwrap(), Some(coin(9)));
        inner.spend(&op(1, 0)).unwrap();
        assert_eq!(inner.get_coin(&op(1, 0)).unwrap(), None);
        // The outer overlay is untouched by the inner one's spend.
        assert_eq!(outer.get_coin(&op(1, 0)).unwrap(), Some(coin(4)));
    }

    #[test]
    fn the_debug_impl_summarises_without_the_base() {
        let base = MapView::new();
        let mut overlay = OverlayView::new(&base);
        overlay.add(op(1, 0), coin(1));
        let text = format!("{overlay:?}");
        assert!(text.contains("OverlayView"), "{text}");
        assert!(text.contains("created"), "{text}");
    }

    #[test]
    fn an_empty_diff_reports_itself_empty() {
        let d = StateDiff::new();
        assert!(d.is_empty());
        assert!(d.undo_block().is_empty());
    }

    #[test]
    fn state_view_is_object_safe_and_blanket_impls_work() {
        let base = base_with(&[(op(1, 0), coin(4))]);
        let dynamic: &dyn StateView = &base;
        assert_eq!(dynamic.get_coin(&op(1, 0)).unwrap(), Some(coin(4)));
        let arced: std::sync::Arc<MapView> = std::sync::Arc::new(base);
        assert!(arced.has_coin(&op(1, 0)).unwrap());
        let by_ref: &MapView = &arced;
        assert!(StateView::has_coin(&by_ref, &op(1, 0)).unwrap());
    }
}
