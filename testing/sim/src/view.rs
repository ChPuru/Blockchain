//! An in-memory [`HeaderView`] over a simulated header chain.
//!
//! [`ferrum_consensus::ConsensusEngine`] reaches storage only through this
//! trait, which is what lets the simulator run an engine with no database at
//! all. The median-time-past calculation is written out here rather than
//! imported from `ferrum-chain`, so that the value the simulator feeds into a
//! [`ferrum_chain::BlockCtx`] is an independent computation from the one
//! production uses; `tests/differential.rs` asserts the two agree.

use std::collections::BTreeMap;

use ferrum_consensus::HeaderView;
use ferrum_types::{BlockHash, BlockHeader, ChainParams};

/// A header chain held in a vector, indexed by height.
#[derive(Debug)]
pub struct SimHeaderView<'a> {
    headers: &'a [BlockHeader],
    heights: &'a BTreeMap<BlockHash, u64>,
    params: &'a ChainParams,
}

impl<'a> SimHeaderView<'a> {
    /// Wrap a chain. `headers[i]` must be the active-chain header at height
    /// `i`, and `heights` its reverse index.
    #[must_use]
    pub fn new(
        headers: &'a [BlockHeader],
        heights: &'a BTreeMap<BlockHash, u64>,
        params: &'a ChainParams,
    ) -> Self {
        SimHeaderView { headers, heights, params }
    }
}

/// The median of the timestamps of the up-to-`span` headers ending at
/// `height`, in **seconds**.
///
/// Written out rather than imported: the whole point of the simulator is that
/// the number it hands to `apply_block` was not produced by the code under
/// test. An even-sized window takes the upper middle element, matching
/// Bitcoin's `GetMedianTimePast` for a truncated window at the start of a
/// chain.
#[must_use]
pub fn median_time_past_of(headers: &[BlockHeader], height: u64, span: usize) -> u64 {
    if headers.is_empty() || span == 0 {
        return 0;
    }
    let end = usize::try_from(height).unwrap_or(usize::MAX).min(headers.len().saturating_sub(1));
    let start = end.saturating_sub(span.saturating_sub(1));
    let mut window: Vec<u64> =
        headers.get(start..=end).unwrap_or_default().iter().map(|h| h.timestamp_s()).collect();
    if window.is_empty() {
        return 0;
    }
    window.sort_unstable();
    window.get(window.len() / 2).copied().unwrap_or(0)
}

impl HeaderView for SimHeaderView<'_> {
    fn params(&self) -> &ChainParams {
        self.params
    }

    fn header_by_hash(&self, h: &BlockHash) -> Option<BlockHeader> {
        let height = self.heights.get(h)?;
        self.header_at_height(*height)
    }

    fn header_at_height(&self, height: u64) -> Option<BlockHeader> {
        self.headers.get(usize::try_from(height).ok()?).copied()
    }

    fn height_of(&self, h: &BlockHash) -> Option<u64> {
        self.heights.get(h).copied()
    }

    fn tip(&self) -> (BlockHash, u64) {
        let height = u64::try_from(self.headers.len().saturating_sub(1)).unwrap_or(0);
        let hash = self.headers.last().map(ferrum_storage::header_hash).unwrap_or(BlockHash::ZERO);
        (hash, height)
    }

    fn median_time_past(&self, h: &BlockHash) -> Option<u64> {
        let height = self.heights.get(h)?;
        Some(median_time_past_of(self.headers, *height, self.params.median_time_span))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_types::{CompactTarget, Hash32};

    use super::*;

    fn header(ts_s: u64) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_hash: BlockHash::ZERO,
            merkle_root: Hash32::ZERO,
            timestamp_ms: ts_s.saturating_mul(1_000),
            bits: CompactTarget(0x207f_ffff),
            nonce: 0,
        }
    }

    #[test]
    fn an_empty_chain_has_a_zero_median() {
        assert_eq!(median_time_past_of(&[], 0, 11), 0);
    }

    #[test]
    fn a_single_header_is_its_own_median() {
        assert_eq!(median_time_past_of(&[header(500)], 0, 11), 500);
    }

    #[test]
    fn the_window_is_capped_at_the_span() {
        let headers: Vec<BlockHeader> = (0..20u64).map(|i| header(i * 100)).collect();
        // Heights 9..=19, timestamps 900..1900, median at index 5 -> 1400.
        assert_eq!(median_time_past_of(&headers, 19, 11), 1_400);
    }

    #[test]
    fn out_of_order_timestamps_are_sorted_before_the_median_is_taken() {
        let headers = vec![header(300), header(100), header(200)];
        assert_eq!(median_time_past_of(&headers, 2, 11), 200);
    }

    #[test]
    fn the_median_agrees_with_the_production_helper() {
        let headers: Vec<BlockHeader> = (0..30u64).map(|i| header(i * 7 % 13 * 100)).collect();
        for height in 0..headers.len() {
            let start = height.saturating_sub(10);
            let window = &headers[start..=height];
            assert_eq!(
                median_time_past_of(&headers, height as u64, 11),
                ferrum_chain::median_time_past(window),
                "height {height}"
            );
        }
    }

    #[test]
    fn a_height_past_the_end_clamps_to_the_tip() {
        let headers: Vec<BlockHeader> = (0..3u64).map(|i| header(i * 10)).collect();
        assert_eq!(median_time_past_of(&headers, 99, 11), median_time_past_of(&headers, 2, 11));
    }
}
