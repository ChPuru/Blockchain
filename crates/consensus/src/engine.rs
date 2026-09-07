//! The engine seam: one trait, two implementations, one dispatcher.
//!
//! The chain layer never names an engine concretely. It asks
//! [`EngineRouter::engine_for_height`] which engine is active and calls the
//! trait. That single indirection is the whole of the PoW to BFT hard fork
//! (SPEC 9.3): no serialised structure changes, no header field changes, no
//! reindex, and history stays valid because every block is validated by the
//! engine that was active at its height.
//!
//! This crate depends on `ferrum-types` and `ferrum-crypto` and on nothing
//! else, which is the rule that keeps the swap a configuration change instead
//! of a rewrite (CONTRACT 0.6). [`HeaderView`] is how the storage layer is
//! reached without depending on it.

use core::sync::atomic::AtomicBool;

use ferrum_crypto::{TAG_HEADER, tagged_hash};
use ferrum_types::{
    Block, BlockHash, BlockHeader, BlockSeal, ChainParams, CompactTarget, Transaction,
};

use crate::bft::BftEngine;
use crate::error::ConsensusError;
use crate::pow::PowEngine;
use crate::target::Work;

/// The block hash: `tagged_hash(TAG_HEADER, header_bytes)` over the canonical
/// 88 bytes (CONTRACT 2.2).
///
/// Uses [`BlockHeader::encode`] rather than `borsh::to_vec` because this is the
/// miner's inner loop — a proptest in `ferrum-types` pins the two together.
pub fn block_hash(header: &BlockHeader) -> BlockHash {
    BlockHash(tagged_hash(TAG_HEADER, &header.encode()))
}

/// The lowest block version this chain accepts.
///
/// Genesis is version 1 and nothing has ever produced a version 0 header, so
/// rejecting it costs nothing and keeps `version` from being a free field an
/// attacker can vary to grind hashes.
pub const MIN_BLOCK_VERSION: u32 = 1;

/// Read-only access to the header chain, supplied by the storage layer.
///
/// Consensus needs heights, ancestors and median time past, but must not
/// depend on `ferrum-storage`; this trait is the seam. Implementations are
/// expected to be cheap — the difficulty rule asks only for the parent's
/// height, and reads its ASERT anchor out of [`ChainParams`] rather than out of
/// the chain, so no engine calls [`HeaderView::header_at_height`] to decide
/// whether a header is valid (CONTRACT 6.3).
pub trait HeaderView: Send + Sync {
    /// The parameter set this chain is validating against.
    fn params(&self) -> &ChainParams;

    /// A header by hash, from anywhere in the tree.
    fn header_by_hash(&self, h: &BlockHash) -> Option<BlockHeader>;

    /// A header by height, on the **active** chain only.
    fn header_at_height(&self, height: u64) -> Option<BlockHeader>;

    /// The height of a known header.
    fn height_of(&self, h: &BlockHash) -> Option<u64>;

    /// The current best tip and its height.
    fn tip(&self) -> (BlockHash, u64);

    /// Median of the last `params().median_time_span` headers ending at `h`,
    /// in **seconds**.
    fn median_time_past(&self, h: &BlockHash) -> Option<u64>;
}

/// A candidate block handed to an engine to be sealed.
///
/// `merkle_root` and `bits` are already fixed by the caller; `nonce` and
/// `timestamp_ms` belong to the engine, which is free to grind both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockTemplate {
    /// The header to seal.
    pub header: BlockHeader,
    /// The transactions the header commits to, coinbase first.
    pub txs: Vec<Transaction>,
    /// The height this block would occupy.
    pub height: u64,
}

impl BlockTemplate {
    /// Build a template.
    pub fn new(header: BlockHeader, txs: Vec<Transaction>, height: u64) -> Self {
        BlockTemplate { header, txs, height }
    }
}

/// One consensus engine.
///
/// Every method is deterministic given its arguments. Nothing here reads a
/// clock: the two-hour future-time bound is [`check_future_time`], which the
/// node calls above the state-transition seam (SPEC 3.2 rule 10).
pub trait ConsensusEngine: Send + Sync + core::fmt::Debug {
    /// Short human name, used in logs and in `getblockchaininfo`.
    fn name(&self) -> &'static str;

    /// The engine's seal identifier: `BlockSeal::ENGINE_POW` or
    /// `BlockSeal::ENGINE_BFT`.
    fn engine_id(&self) -> u8;

    /// Header-only checks: version, parentage, difficulty transition, proof of
    /// work and the timestamp lower bound.
    ///
    /// # Errors
    ///
    /// One variant per rule; see [`ConsensusError`].
    fn validate_header(
        &self,
        h: &BlockHeader,
        parent: &BlockHeader,
        view: &dyn HeaderView,
    ) -> Result<(), ConsensusError>;

    /// Whole-block seal checks. PoW requires an empty seal; BFT requires a
    /// `2f+1` commit over this header's hash.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::WrongEngine`], [`ConsensusError::NonEmptyPowSeal`],
    /// [`ConsensusError::MalformedSeal`] and the commit variants.
    fn validate_seal(&self, block: &Block, view: &dyn HeaderView) -> Result<(), ConsensusError>;

    /// The difficulty target for a child of `parent`.
    ///
    /// A pure function of `(parent_height, parent_timestamp, params)`: it must
    /// not depend on anything else the view holds, or two nodes on two forks
    /// will reject each other's headers forever (CONTRACT 6.3).
    ///
    /// # Errors
    ///
    /// [`ConsensusError::UnknownParent`] when the view does not know `parent`,
    /// and the target-expansion errors for a malformed parameter set.
    fn next_bits(
        &self,
        parent: &BlockHeader,
        view: &dyn HeaderView,
    ) -> Result<CompactTarget, ConsensusError>;

    /// Mine (PoW) or propose and collect votes (BFT).
    ///
    /// Returns `Ok(None)` when `cancel` was raised before a seal was found.
    ///
    /// # Errors
    ///
    /// Engine-specific; a PoW engine fails only on an unusable target.
    fn seal(
        &self,
        tmpl: BlockTemplate,
        cancel: &AtomicBool,
    ) -> Result<Option<Block>, ConsensusError>;

    /// Fork-choice weight contributed by this header. An unparseable `bits`
    /// contributes [`Work::ZERO`], never a panic.
    fn work(&self, h: &BlockHeader) -> Work;

    /// `None` for PoW — nothing is ever final. `Some(h)` for BFT, above which
    /// reorgs are impossible by construction.
    fn finalized_height(&self, view: &dyn HeaderView) -> Option<u64>;
}

/// The one clock-dependent rule, kept out of the pure state transition.
///
/// A block may be timestamped at most `params.max_future_block_time_ms` ahead
/// of the validating node's clock. Re-validating block 400 must never depend on
/// when you re-validate it, which is why this lives here and not inside
/// `apply_block` (SPEC 3.2 rule 10, SPEC 8).
///
/// # Errors
///
/// [`ConsensusError::TimestampTooFarInFuture`].
pub fn check_future_time(
    header: &BlockHeader,
    now_ms: u64,
    params: &ChainParams,
) -> Result<(), ConsensusError> {
    let limit_ms = now_ms.saturating_add(params.max_future_block_time_ms);
    if header.timestamp_ms > limit_ms {
        return Err(ConsensusError::TimestampTooFarInFuture {
            timestamp_ms: header.timestamp_ms,
            limit_ms,
        });
    }
    Ok(())
}

/// Chooses the engine for a height, honouring `params.bft_activation_height`.
///
/// This is the whole of the M10 hard fork: one dispatcher, two engines, no
/// other code changes.
///
/// The router refuses to be built with a BFT activation scheduled but no usable
/// BFT engine, so [`EngineRouter::engine_for_height`] is total.
#[derive(Debug)]
pub struct EngineRouter {
    pow: PowEngine,
    bft: Option<BftEngine>,
    params: ChainParams,
    forced: Option<u8>,
}

impl EngineRouter {
    /// Build a router from a parameter set, constructing the BFT engine when
    /// (and only when) an activation height is scheduled.
    ///
    /// # Errors
    ///
    /// The BFT validator-set errors, when an activation is scheduled but the
    /// configured set cannot form a quorum.
    pub fn new(params: ChainParams) -> Result<Self, ConsensusError> {
        let bft = match params.bft_activation_height {
            Some(_) => Some(BftEngine::new(params.clone(), None)?),
            None => None,
        };
        Ok(EngineRouter { pow: PowEngine::new(params.clone()), bft, params, forced: None })
    }

    /// Build a router from engines the caller already owns — the shape the node
    /// needs when it has loaded a validator key from disk.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::EngineUnavailable`] when `params` schedules a BFT
    /// activation but `bft` is `None`; that combination would silently validate
    /// post-fork blocks under proof of work.
    pub fn with_engines(
        params: ChainParams,
        pow: PowEngine,
        bft: Option<BftEngine>,
    ) -> Result<Self, ConsensusError> {
        if params.bft_activation_height.is_some() && bft.is_none() {
            return Err(ConsensusError::EngineUnavailable);
        }
        Ok(EngineRouter { pow, bft, params, forced: None })
    }

    /// Pin every height to one engine, which is what `chaind --consensus
    /// pow|bft` does (CONTRACT 13.1).
    ///
    /// # Errors
    ///
    /// [`ConsensusError::WrongEngine`] for an unknown engine id, and
    /// [`ConsensusError::EngineUnavailable`] when BFT is forced without a BFT
    /// engine.
    pub fn force_engine(mut self, engine_id: u8) -> Result<Self, ConsensusError> {
        match engine_id {
            BlockSeal::ENGINE_POW => {}
            BlockSeal::ENGINE_BFT if self.bft.is_some() => {}
            BlockSeal::ENGINE_BFT => return Err(ConsensusError::EngineUnavailable),
            other => {
                return Err(ConsensusError::WrongEngine {
                    expected: BlockSeal::ENGINE_POW,
                    actual: other,
                });
            }
        }
        self.forced = Some(engine_id);
        Ok(self)
    }

    /// The engine that seals and validates blocks at `height`.
    pub fn engine_for_height(&self, height: u64) -> &dyn ConsensusEngine {
        let wanted = self.forced.unwrap_or_else(|| self.params.engine_at(height));
        match (wanted, self.bft.as_ref()) {
            (BlockSeal::ENGINE_BFT, Some(bft)) => bft,
            (BlockSeal::ENGINE_BFT, None) => {
                // Unreachable: every constructor rejects this combination. If a
                // future constructor forgets, fail loudly rather than silently
                // validating post-fork blocks under the wrong rules.
                debug_assert!(false, "BFT scheduled without a BFT engine");
                tracing::error!(
                    height,
                    "BFT is active at this height but no BFT engine is configured"
                );
                &self.pow
            }
            _ => &self.pow,
        }
    }

    /// The engine id active at `height`, without dispatching.
    pub fn engine_id_for_height(&self, height: u64) -> u8 {
        self.engine_for_height(height).engine_id()
    }

    /// The proof-of-work engine, always present.
    pub fn pow(&self) -> &PowEngine {
        &self.pow
    }

    /// The BFT engine, present only when an activation is scheduled.
    pub fn bft(&self) -> Option<&BftEngine> {
        self.bft.as_ref()
    }

    /// The parameter set this router dispatches on.
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// The engine pinned by `--consensus`, if any.
    pub fn forced(&self) -> Option<u8> {
        self.forced
    }

    /// The height below which reorgs are impossible, according to the engine
    /// active at the current tip.
    ///
    /// `None` under proof of work: nothing is ever final there, and a
    /// sufficiently long chain can rewrite any depth.
    pub fn finalized_height(&self, view: &dyn HeaderView) -> Option<u64> {
        let (_, tip_height) = view.tip();
        self.engine_for_height(tip_height).finalized_height(view)
    }

    /// Refuse a reorg whose common ancestor lies below the finalized height.
    ///
    /// This is the other half of the BFT promise. A committed block carries
    /// `2f+1` signatures, and by quorum intersection no conflicting block at
    /// that height can ever gather `2f+1` of its own — so a chain that claims
    /// to replace it is either lying or is proof that more than `f` validators
    /// are Byzantine. Either way the correct answer is to refuse, loudly, and
    /// let an operator look; silently rewinding a final block is how a BFT
    /// chain forks.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::ReorgBelowFinalized`].
    pub fn check_reorg(
        &self,
        fork_height: u64,
        view: &dyn HeaderView,
    ) -> Result<(), ConsensusError> {
        match self.finalized_height(view) {
            Some(finalized) if fork_height < finalized => {
                Err(ConsensusError::ReorgBelowFinalized {
                    fork_height,
                    finalized_height: finalized,
                })
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]

    use ferrum_crypto::TAG_TXID;
    use ferrum_types::ValidatorId;

    use super::*;
    use crate::testview::TestView;

    fn header(nonce: u64) -> BlockHeader {
        BlockHeader { nonce, ..BlockHeader::default() }
    }

    fn validators(n: usize) -> Vec<ValidatorId> {
        crate::bft::tests_support::validator_ids(n)
    }

    #[test]
    fn block_hash_is_the_tagged_hash_of_the_eighty_eight_bytes() {
        let h = header(7);
        assert_eq!(block_hash(&h), BlockHash(tagged_hash(TAG_HEADER, &h.encode())));
        assert_ne!(block_hash(&h), block_hash(&header(8)));
        // Domain separation matters: the same bytes under another tag differ.
        assert_ne!(block_hash(&h).0, tagged_hash(TAG_TXID, &h.encode()));
    }

    #[test]
    fn future_time_is_bounded_by_the_parameter() {
        let p = ChainParams::mainnet();
        let now = 1_000_000_000_000u64;
        let ok = BlockHeader { timestamp_ms: now + p.max_future_block_time_ms, ..header(0) };
        assert_eq!(check_future_time(&ok, now, &p), Ok(()));

        let bad = BlockHeader { timestamp_ms: now + p.max_future_block_time_ms + 1, ..header(0) };
        assert_eq!(
            check_future_time(&bad, now, &p),
            Err(ConsensusError::TimestampTooFarInFuture {
                timestamp_ms: bad.timestamp_ms,
                limit_ms: now + p.max_future_block_time_ms,
            })
        );
    }

    #[test]
    fn future_time_saturates_instead_of_overflowing() {
        let p = ChainParams::mainnet();
        let h = BlockHeader { timestamp_ms: u64::MAX, ..header(0) };
        assert_eq!(check_future_time(&h, u64::MAX, &p), Ok(()));
    }

    #[test]
    fn a_pow_only_router_has_no_bft_engine() {
        let r = EngineRouter::new(ChainParams::devnet()).unwrap();
        assert!(r.bft().is_none());
        assert_eq!(r.forced(), None);
        assert_eq!(r.engine_for_height(0).engine_id(), BlockSeal::ENGINE_POW);
        assert_eq!(r.engine_for_height(u64::MAX).engine_id(), BlockSeal::ENGINE_POW);
        assert_eq!(r.engine_for_height(0).name(), "pow");
        assert_eq!(r.params().network, ChainParams::devnet().network);
    }

    #[test]
    fn the_activation_boundary_is_exact() {
        let mut p = ChainParams::devnet();
        p.bft_activation_height = Some(1_000);
        p.bft_validators = validators(4);
        let r = EngineRouter::new(p).unwrap();

        assert_eq!(r.engine_for_height(998).engine_id(), BlockSeal::ENGINE_POW);
        assert_eq!(r.engine_for_height(999).engine_id(), BlockSeal::ENGINE_POW, "h-1 is PoW");
        assert_eq!(r.engine_for_height(1_000).engine_id(), BlockSeal::ENGINE_BFT, "h is BFT");
        assert_eq!(r.engine_for_height(1_001).engine_id(), BlockSeal::ENGINE_BFT);
        assert_eq!(r.engine_for_height(999).name(), "pow");
        assert_eq!(r.engine_for_height(1_000).name(), "bft");
        assert_eq!(r.engine_id_for_height(999), 0);
        assert_eq!(r.engine_id_for_height(1_000), 1);
    }

    #[test]
    fn activation_at_zero_makes_the_whole_chain_bft() {
        let mut p = ChainParams::devnet();
        p.bft_activation_height = Some(0);
        p.bft_validators = validators(4);
        let r = EngineRouter::new(p).unwrap();
        assert_eq!(r.engine_for_height(0).engine_id(), BlockSeal::ENGINE_BFT);
    }

    #[test]
    fn a_scheduled_activation_with_too_few_validators_is_refused() {
        let mut p = ChainParams::devnet();
        p.bft_activation_height = Some(10);
        p.bft_validators = validators(3);
        assert_eq!(
            EngineRouter::new(p).err(),
            Some(ConsensusError::ValidatorSetTooSmall { actual: 3, minimum: 4 })
        );
    }

    #[test]
    fn with_engines_refuses_a_scheduled_fork_without_a_bft_engine() {
        let mut p = ChainParams::devnet();
        p.bft_activation_height = Some(10);
        p.bft_validators = validators(4);
        let pow = PowEngine::new(p.clone());
        assert_eq!(
            EngineRouter::with_engines(p.clone(), pow, None).err(),
            Some(ConsensusError::EngineUnavailable)
        );

        let pow = PowEngine::new(p.clone());
        let bft = BftEngine::new(p.clone(), None).unwrap();
        assert!(EngineRouter::with_engines(p, pow, Some(bft)).is_ok());
    }

    #[test]
    fn forcing_pow_overrides_a_scheduled_activation() {
        let mut p = ChainParams::devnet();
        p.bft_activation_height = Some(10);
        p.bft_validators = validators(4);
        let r = EngineRouter::new(p).unwrap().force_engine(BlockSeal::ENGINE_POW).unwrap();
        assert_eq!(r.forced(), Some(BlockSeal::ENGINE_POW));
        assert_eq!(r.engine_for_height(1_000_000).engine_id(), BlockSeal::ENGINE_POW);
    }

    #[test]
    fn forcing_bft_before_activation_is_allowed_when_an_engine_exists() {
        let mut p = ChainParams::devnet();
        p.bft_activation_height = Some(10);
        p.bft_validators = validators(4);
        let r = EngineRouter::new(p).unwrap().force_engine(BlockSeal::ENGINE_BFT).unwrap();
        assert_eq!(r.engine_for_height(0).engine_id(), BlockSeal::ENGINE_BFT);
    }

    #[test]
    fn forcing_bft_without_an_engine_is_refused() {
        let r = EngineRouter::new(ChainParams::devnet()).unwrap();
        assert_eq!(
            r.force_engine(BlockSeal::ENGINE_BFT).err(),
            Some(ConsensusError::EngineUnavailable)
        );
    }

    #[test]
    fn forcing_an_unknown_engine_is_refused() {
        let r = EngineRouter::new(ChainParams::devnet()).unwrap();
        assert_eq!(
            r.force_engine(9).err(),
            Some(ConsensusError::WrongEngine { expected: BlockSeal::ENGINE_POW, actual: 9 })
        );
    }

    #[test]
    fn a_template_carries_its_height() {
        let t = BlockTemplate::new(header(1), Vec::new(), 42);
        assert_eq!(t.height, 42);
        assert_eq!(t, BlockTemplate { header: header(1), txs: Vec::new(), height: 42 });
    }

    #[test]
    fn the_header_view_trait_is_object_safe() {
        let view = TestView::devnet();
        let dynamic: &dyn HeaderView = &view;
        assert_eq!(dynamic.tip().1, 0);
        assert_eq!(dynamic.params().network, ChainParams::devnet().network);
    }
}
