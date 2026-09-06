//! [`BlockCtx`] — every piece of ambient information a block needs, passed
//! explicitly.
//!
//! This type is what makes [`crate::apply_block`] a pure function. A validator
//! that reached for the clock, the store or a global would produce a different
//! answer on a different machine, or on the same machine at a different time.
//! Everything it is allowed to know is in here, and it is handed in by the
//! caller (SPEC §8).
//!
//! Note what is deliberately **absent**: `now`. The two-hour future-time bound
//! is the one clock-dependent rule in the protocol and it lives in the node,
//! above the seam, as [`ferrum_consensus::check_future_time`]. Re-validating
//! block 400 must never depend on when you re-validate it.

use ferrum_types::{BlockHeader, ChainParams};

/// The context one block is validated in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockCtx {
    /// The height this block occupies. Genesis is 0.
    pub height: u64,
    /// The header of the block this one builds on.
    ///
    /// At height 0 this field is ignored except that `prev_hash` must be
    /// [`ferrum_types::BlockHash::ZERO`]: genesis has no parent.
    pub prev_header: BlockHeader,
    /// Median time past of the parent, in **seconds**.
    ///
    /// Locktime and `OP_CHECKLOCKTIMEVERIFY` compare against this rather than
    /// against the block's own timestamp: a miner controls its own timestamp
    /// within a two-hour window, but cannot move the median of the last eleven
    /// blocks without controlling most of them.
    pub median_time_past_s: u64,
    /// The consensus parameters in force.
    pub params: ChainParams,
    /// Which engine seals this height: [`ferrum_types::BlockSeal::ENGINE_POW`]
    /// or [`ferrum_types::BlockSeal::ENGINE_BFT`].
    pub engine_id: u8,
}

impl BlockCtx {
    /// Build a context for the child of `prev_header`.
    ///
    /// `height` is the child's height, not the parent's. The engine is chosen
    /// from `params.engine_at(height)`, which is the same dispatch
    /// [`ferrum_consensus::EngineRouter`] performs; pass `engine_id` directly
    /// when a node has pinned an engine with `--consensus`.
    #[must_use]
    pub fn new(
        height: u64,
        prev_header: BlockHeader,
        median_time_past_s: u64,
        params: ChainParams,
    ) -> Self {
        let engine_id = params.engine_at(height);
        BlockCtx { height, prev_header, median_time_past_s, params, engine_id }
    }

    /// The same context with a different engine, for a node that pinned one.
    #[must_use]
    pub fn with_engine(mut self, engine_id: u8) -> Self {
        self.engine_id = engine_id;
        self
    }

    /// Whether this context describes the genesis block.
    ///
    /// Genesis is exempt from proof-of-work validation against a parent it does
    /// not have, from the difficulty transition, and from the median-time-past
    /// bound (SPEC §2).
    #[must_use]
    pub const fn is_genesis(&self) -> bool {
        self.height == 0
    }

    /// Median time past in **milliseconds**, saturating.
    ///
    /// The header's timestamp is milliseconds and the median is seconds; doing
    /// the conversion in one place is what stops a comparison from being made
    /// in mixed units, which is a bug that looks correct for the first 1000
    /// seconds of a chain's life.
    #[must_use]
    pub const fn median_time_past_ms(&self) -> u64 {
        self.median_time_past_s.saturating_mul(1_000)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use ferrum_types::BlockSeal;

    use super::*;

    fn params() -> ChainParams {
        ChainParams::devnet()
    }

    #[test]
    fn new_picks_the_engine_from_the_height() {
        let ctx = BlockCtx::new(5, BlockHeader::default(), 100, params());
        assert_eq!(ctx.engine_id, BlockSeal::ENGINE_POW);
        assert_eq!(ctx.height, 5);
        assert_eq!(ctx.median_time_past_s, 100);
    }

    #[test]
    fn new_honours_a_scheduled_bft_activation() {
        let mut p = params();
        p.bft_activation_height = Some(10);
        assert_eq!(
            BlockCtx::new(9, BlockHeader::default(), 0, p.clone()).engine_id,
            BlockSeal::ENGINE_POW
        );
        assert_eq!(
            BlockCtx::new(10, BlockHeader::default(), 0, p).engine_id,
            BlockSeal::ENGINE_BFT
        );
    }

    #[test]
    fn with_engine_overrides_the_router() {
        let ctx = BlockCtx::new(0, BlockHeader::default(), 0, params())
            .with_engine(BlockSeal::ENGINE_BFT);
        assert_eq!(ctx.engine_id, BlockSeal::ENGINE_BFT);
    }

    #[test]
    fn only_height_zero_is_genesis() {
        assert!(BlockCtx::new(0, BlockHeader::default(), 0, params()).is_genesis());
        assert!(!BlockCtx::new(1, BlockHeader::default(), 0, params()).is_genesis());
    }

    #[test]
    fn median_time_past_converts_to_milliseconds_and_saturates() {
        let ctx = BlockCtx::new(1, BlockHeader::default(), 1_700_000_000, params());
        assert_eq!(ctx.median_time_past_ms(), 1_700_000_000_000);

        let huge = BlockCtx::new(1, BlockHeader::default(), u64::MAX, params());
        assert_eq!(huge.median_time_past_ms(), u64::MAX);
    }
}
