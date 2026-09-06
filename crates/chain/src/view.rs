//! [`StoreHeaderView`] — the header chain as `ferrum-consensus` sees it.
//!
//! `ferrum-consensus` may depend on `ferrum-types` and `ferrum-crypto` and on
//! nothing else in the workspace (CONTRACT §0.6). That rule is what makes the
//! PoW to BFT swap a configuration change rather than a rewrite: there is no
//! path by which an engine can reach into the state machine or the database.
//!
//! [`HeaderView`] is the seam it reaches storage through, and this file is the
//! implementation. Everything here is a read; nothing mutates.
//!
//! # Errors are not lies
//!
//! Every method of [`HeaderView`] returns an `Option` or a plain value, so a
//! storage failure has nowhere to go. It is logged at `warn` and reported as
//! "not found", which makes the engine reject the header it was asked about
//! rather than accept it. Failing closed is the only safe direction here: a
//! disk error that read as "no difficulty rule applies" would accept any
//! `bits` at all.

use ferrum_storage::Store;
use ferrum_types::{BlockHash, BlockHeader, ChainParams};

use ferrum_consensus::HeaderView;

use crate::validate::median_time_past;

/// A [`HeaderView`] backed by a [`Store`].
///
/// Cheap to construct — it borrows — so a caller makes one per validation
/// rather than holding one across a reorg, where the active chain moves under
/// it.
#[derive(Debug)]
pub struct StoreHeaderView<'a> {
    store: &'a Store,
    params: &'a ChainParams,
}

impl<'a> StoreHeaderView<'a> {
    /// Borrow a store as a header view.
    #[must_use]
    pub fn new(store: &'a Store, params: &'a ChainParams) -> Self {
        StoreHeaderView { store, params }
    }

    /// The store behind this view.
    #[must_use]
    pub fn store(&self) -> &'a Store {
        self.store
    }

    /// The height of the active tip, or `0` on an empty store.
    fn tip_or_default(&self) -> (BlockHash, u64) {
        match self.store.tip() {
            Ok(Some(tip)) => tip,
            Ok(None) => (BlockHash::ZERO, 0),
            Err(e) => {
                tracing::warn!(error = %e, "tip lookup failed; reporting an empty chain");
                (BlockHash::ZERO, 0)
            }
        }
    }
}

impl HeaderView for StoreHeaderView<'_> {
    fn params(&self) -> &ChainParams {
        self.params
    }

    fn header_by_hash(&self, h: &BlockHash) -> Option<BlockHeader> {
        match self.store.get_header(h) {
            Ok(entry) => entry.map(|e| e.header),
            Err(e) => {
                tracing::warn!(hash = %h, error = %e, "header lookup failed");
                None
            }
        }
    }

    fn header_at_height(&self, height: u64) -> Option<BlockHeader> {
        let hash = match self.store.hash_at_height(height) {
            Ok(h) => h?,
            Err(e) => {
                tracing::warn!(height, error = %e, "height lookup failed");
                return None;
            }
        };
        self.header_by_hash(&hash)
    }

    fn height_of(&self, h: &BlockHash) -> Option<u64> {
        match self.store.get_header(h) {
            Ok(entry) => entry.map(|e| e.height),
            Err(e) => {
                tracing::warn!(hash = %h, error = %e, "header lookup failed");
                None
            }
        }
    }

    fn tip(&self) -> (BlockHash, u64) {
        self.tip_or_default()
    }

    fn median_time_past(&self, h: &BlockHash) -> Option<u64> {
        let window = self.header_window(h, self.params.median_time_span)?;
        Some(median_time_past(&window))
    }
}

impl StoreHeaderView<'_> {
    /// The last `span` headers ending at `h`, oldest first.
    ///
    /// Walks `prev_hash` rather than heights, so it works for a header on a
    /// **side branch** as well as on the active chain. That matters: a
    /// candidate block's timestamp is checked against the median of *its own*
    /// ancestors, not against the median of whichever chain happens to be
    /// active when it arrives.
    ///
    /// Returns `None` when `h` itself is unknown, and a short window when the
    /// walk reaches genesis — a chain three blocks long has a three-header
    /// median, which is what makes the rule meaningful from block one.
    #[must_use]
    pub fn header_window(&self, h: &BlockHash, span: usize) -> Option<Vec<BlockHeader>> {
        let mut headers: Vec<BlockHeader> = Vec::with_capacity(span);
        let mut cursor = *h;
        for _ in 0..span {
            let entry = match self.store.get_header(&cursor) {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(hash = %cursor, error = %e, "header walk failed");
                    break;
                }
            };
            let prev = entry.header.prev_hash;
            let at_genesis = entry.height == 0;
            headers.push(entry.header);
            if at_genesis {
                break;
            }
            cursor = prev;
        }
        if headers.is_empty() {
            return None;
        }
        headers.reverse();
        Some(headers)
    }
}
