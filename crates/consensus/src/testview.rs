//! An in-memory [`HeaderView`] for this crate's own tests.
//!
//! `ferrum-consensus` may not depend on `ferrum-storage`, so the tests need
//! their own header store. It is deliberately dumb: two `BTreeMap`s and a
//! linear median-time-past walk, so a disagreement with the engine is the
//! engine's fault.

use std::collections::BTreeMap;

use ferrum_types::{BlockHash, BlockHeader, ChainParams, CompactTarget, Hash32};

use crate::engine::{HeaderView, block_hash};

/// Devnet parameters mined at a trivial target: everything `ChainParams::devnet`
/// says, except that `pow_limit` and `genesis_bits` are the pre-2026 devnet
/// values, which accept about half of all header hashes.
///
/// The shipped devnet limit is `0x1e00ffff` — about `2^24` header hashes per
/// block, roughly 1.9 s on one core in release and four times that in the
/// unoptimised test profile. That is deliberate and load-bearing on a real
/// network (a devnet that seals in a microsecond outruns its own gossip), and
/// it is pure overhead here: the tests that use this view seal headers to check
/// that `seal` returns something meeting the target it was handed, that
/// cancellation is honoured, and that `bits` transitions validate — none of
/// which depends on how large the target is.
///
/// Anything asserting on the shipped numbers must take `ChainParams::devnet()`
/// directly instead.
pub(crate) fn easy_devnet_params() -> ChainParams {
    let mut p = ChainParams::devnet();
    let mut limit = [0xffu8; 32];
    limit[0] = 0x7f;
    p.pow_limit = limit;
    p.genesis_bits = CompactTarget(0x207f_ffff);
    p
}

/// A header chain held entirely in memory.
#[derive(Debug)]
pub(crate) struct TestView {
    params: ChainParams,
    by_hash: BTreeMap<BlockHash, (BlockHeader, u64)>,
    by_height: BTreeMap<u64, BlockHash>,
    /// When set, [`HeaderView::median_time_past`] returns `None`, which is how
    /// the "missing context" path is exercised.
    no_median_time_past: bool,
}

impl TestView {
    /// An empty view over a parameter set.
    pub(crate) fn with_params(params: ChainParams) -> Self {
        TestView {
            params,
            by_hash: BTreeMap::new(),
            by_height: BTreeMap::new(),
            no_median_time_past: false,
        }
    }

    /// An empty devnet view, mined at a trivial target.
    ///
    /// See [`easy_devnet_params`]: the shipped devnet `pow_limit` costs ~2^24
    /// hashes per block and nothing reached through this view is about that
    /// number.
    pub(crate) fn devnet() -> Self {
        Self::with_params(easy_devnet_params())
    }

    /// An empty mainnet view.
    pub(crate) fn mainnet() -> Self {
        Self::with_params(ChainParams::mainnet())
    }

    /// Append a header at the next height on the active chain.
    pub(crate) fn push_header(&mut self, header: BlockHeader) -> BlockHeader {
        let height = self.by_height.len() as u64;
        let hash = block_hash(&header);
        self.by_hash.insert(hash, (header, height));
        self.by_height.insert(height, hash);
        header
    }

    /// Append the genesis header this network's parameters describe.
    pub(crate) fn push_genesis(&mut self) -> BlockHeader {
        let header = BlockHeader {
            version: 1,
            prev_hash: BlockHash::from_bytes([0u8; 32]),
            merkle_root: Hash32::ZERO,
            timestamp_ms: self.params.genesis_timestamp_ms,
            bits: self.params.genesis_bits,
            nonce: self.params.genesis_nonce,
        };
        self.push_header(header)
    }

    /// Append a child of the current tip, `delta_ms` later, at the genesis
    /// target. The proof of work is not solved; callers that need a solved
    /// header seal one and push it themselves.
    pub(crate) fn push_child(&mut self, delta_ms: u64) -> BlockHeader {
        let (tip_hash, _) = self.tip();
        let parent = self.header_by_hash(&tip_hash).expect("the tip is always present");
        let header = BlockHeader {
            version: 1,
            prev_hash: tip_hash,
            merkle_root: Hash32::ZERO,
            timestamp_ms: parent.timestamp_ms.saturating_add(delta_ms),
            bits: self.params.genesis_bits,
            nonce: 0,
        };
        self.push_header(header)
    }

    /// Drop the height to hash mapping for `height`, leaving the header itself
    /// reachable by hash. This is what an incomplete index looks like.
    pub(crate) fn forget_height(&mut self, height: u64) {
        self.by_height.remove(&height);
    }

    /// Make [`HeaderView::median_time_past`] report `None`.
    pub(crate) fn suppress_median_time_past(&mut self) {
        self.no_median_time_past = true;
    }
}

impl HeaderView for TestView {
    fn params(&self) -> &ChainParams {
        &self.params
    }

    fn header_by_hash(&self, h: &BlockHash) -> Option<BlockHeader> {
        self.by_hash.get(h).map(|(header, _)| *header)
    }

    fn header_at_height(&self, height: u64) -> Option<BlockHeader> {
        let hash = self.by_height.get(&height)?;
        self.header_by_hash(hash)
    }

    fn height_of(&self, h: &BlockHash) -> Option<u64> {
        self.by_hash.get(h).map(|(_, height)| *height)
    }

    fn tip(&self) -> (BlockHash, u64) {
        match self.by_hash.values().max_by_key(|(_, height)| *height) {
            Some((header, height)) => (block_hash(header), *height),
            None => (BlockHash::from_bytes([0u8; 32]), 0),
        }
    }

    fn median_time_past(&self, h: &BlockHash) -> Option<u64> {
        if self.no_median_time_past {
            return None;
        }
        let mut times = Vec::with_capacity(self.params.median_time_span);
        let mut cursor = *h;
        while times.len() < self.params.median_time_span {
            let header = self.header_by_hash(&cursor)?;
            times.push(header.timestamp_s());
            if header.prev_hash.0.is_zero() {
                break;
            }
            cursor = header.prev_hash;
        }
        times.sort_unstable();
        times.get(times.len() / 2).copied()
    }
}
