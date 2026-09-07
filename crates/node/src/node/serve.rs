//! Answering the other side of sync: what this node serves when a peer asks.
//!
//! Every function here is synchronous and reads the store, so callers reach
//! them through `spawn_blocking` (CONTRACT §7).
//!
//! # Caps are applied here as well as on the wire
//!
//! `ferrum-p2p` caps every response at 2000 headers and 64 blocks server-side,
//! whatever the peer asked for (CONTRACT §10.2). This module applies the same
//! caps *before* building the response, so a peer asking for a million headers
//! costs one bounded allocation rather than a large one that is then trimmed.
//! Two layers of the same limit is not redundancy; the outer one protects
//! against a bug in the inner one.

use std::sync::Arc;

use ferrum_chain::ChainManager;
use ferrum_consensus::Work;
use ferrum_p2p::{SyncRequest, SyncResponse};
use ferrum_types::{Block, BlockHash, BlockHeader};

/// Largest header response this node builds.
pub const MAX_HEADERS_SERVED: usize = 2_000;

/// Largest block response this node builds.
pub const MAX_BLOCKS_SERVED: usize = 64;

/// Largest locator this node will walk.
///
/// An exponential locator over a chain of `2^64` blocks is under seventy
/// entries; anything longer is a peer trying to make us do work.
pub const MAX_LOCATOR_ACCEPTED: usize = 128;

/// Answer one inbound sync request.
///
/// Synchronous: it reads the store. Call it from `spawn_blocking`.
#[must_use]
pub fn answer(chain: &Arc<ChainManager>, request: &SyncRequest) -> SyncResponse {
    match request {
        SyncRequest::GetTip => tip_response(chain),
        SyncRequest::GetHeaders { locator, stop, max } => {
            SyncResponse::Headers(headers(chain, locator, stop.as_ref(), *max))
        }
        SyncRequest::GetBlocks { hashes } => {
            let blocks = bodies(chain, hashes);
            if blocks.is_empty() { SyncResponse::NotFound } else { SyncResponse::Blocks(blocks) }
        }
    }
}

/// This node's tip, with the cumulative work behind it.
///
/// Work, not height: a peer choosing whom to sync from must compare the thing
/// fork choice actually uses (SPEC §7.1).
#[must_use]
pub fn tip_response(chain: &Arc<ChainManager>) -> SyncResponse {
    let (hash, height) = chain.tip();
    let work = chain.total_work(&hash).unwrap_or(Work::ZERO);
    SyncResponse::Tip { hash, height, work: work.to_be_bytes() }
}

/// Active-chain headers after the first locator entry we recognise.
#[must_use]
pub fn headers(
    chain: &Arc<ChainManager>,
    locator: &[BlockHash],
    stop: Option<&BlockHash>,
    max: u32,
) -> Vec<BlockHeader> {
    let locator = &locator[..locator.len().min(MAX_LOCATOR_ACCEPTED)];
    let cap = usize::try_from(max).unwrap_or(MAX_HEADERS_SERVED).min(MAX_HEADERS_SERVED);
    let mut out = chain.headers_from(locator, cap);
    if let Some(stop) = stop
        && let Some(index) = out.iter().position(|h| ferrum_storage::header_hash(h) == *stop)
    {
        // Inclusive of the stop hash: a peer that asks to stop at a hash wants
        // that block's header, not everything before it.
        out.truncate(index.saturating_add(1));
    }
    out
}

/// Block bodies we hold, in the order they were asked for.
///
/// A hash we do not have is skipped rather than reported: the asker sees a
/// short answer and re-requests, which is what it would do for a dropped
/// response anyway.
#[must_use]
pub fn bodies(chain: &Arc<ChainManager>, hashes: &[BlockHash]) -> Vec<Block> {
    let mut out = Vec::new();
    for hash in hashes.iter().take(MAX_BLOCKS_SERVED) {
        match chain.store().get_block(hash) {
            Ok(Some(block)) => out.push(block),
            Ok(None) => {}
            Err(e) => tracing::warn!(%hash, error = %e, "could not read a requested block"),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]

    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use ferrum_consensus::EngineRouter;
    use ferrum_mempool::{Mempool, MempoolConfig};
    use ferrum_storage::{Store, StoreConfig};
    use ferrum_types::ChainParams;

    use super::*;
    use crate::miner::{Miner, resolve_payout};
    use crate::node::keys::NodeKey;
    use crate::relay::{Clock, FixedClock, Relay};
    use crate::telemetry::NodeMetrics;

    fn chain_with(blocks: u64) -> Arc<ChainManager> {
        let params = ChainParams::devnet();
        let store = Arc::new(Store::open_in_memory(StoreConfig::default()).unwrap());
        let engines = Arc::new(EngineRouter::new(params.clone()).unwrap());
        let chain = Arc::new(ChainManager::open(store, params.clone(), engines).unwrap());
        chain.init_genesis().unwrap();
        let clock = Arc::new(FixedClock::new(params.genesis_timestamp_ms + 120_000));
        let relay = Arc::new(Relay::new(
            Arc::clone(&chain),
            Arc::new(Mempool::new(MempoolConfig::new(params.clone()))),
            Arc::new(NodeMetrics::new()),
            Arc::clone(&clock) as Arc<dyn Clock>,
        ));
        let payout =
            resolve_payout(None, &NodeKey::from_seed([3u8; 32]), params.network).unwrap();
        let miner = Miner::new(relay, payout);
        for i in 1..=blocks {
            clock.set(params.genesis_timestamp_ms + i * 120_000);
            miner.mine_and_submit(&AtomicBool::new(false)).unwrap().unwrap();
        }
        chain
    }

    #[test]
    fn the_caps_match_the_contract() {
        assert_eq!(MAX_HEADERS_SERVED, 2_000);
        assert_eq!(MAX_BLOCKS_SERVED, 64);
        const { assert!(MAX_LOCATOR_ACCEPTED >= 64) };
    }

    #[test]
    fn a_tip_request_reports_the_hash_height_and_work() {
        let chain = chain_with(3);
        let (hash, height) = chain.tip();
        match answer(&chain, &SyncRequest::GetTip) {
            SyncResponse::Tip { hash: h, height: n, work } => {
                assert_eq!(h, hash);
                assert_eq!(n, height);
                assert_eq!(work, chain.total_work(&hash).unwrap().to_be_bytes());
            }
            other => panic!("expected Tip, got {other:?}"),
        }
    }

    #[test]
    fn headers_start_after_the_locators_fork_point() {
        let chain = chain_with(5);
        let genesis = chain.store().hash_at_height(0).unwrap().unwrap();
        let from_genesis = headers(&chain, &[genesis], None, 100);
        assert_eq!(from_genesis.len(), 5);

        let at_three = chain.store().hash_at_height(3).unwrap().unwrap();
        let from_three = headers(&chain, &[at_three], None, 100);
        assert_eq!(from_three.len(), 2, "only what the asker is missing");
    }

    #[test]
    fn a_request_for_more_than_the_cap_is_trimmed() {
        let chain = chain_with(4);
        let genesis = chain.store().hash_at_height(0).unwrap().unwrap();
        // Ask for four billion; get at most the cap, and here only what exists.
        assert_eq!(headers(&chain, &[genesis], None, u32::MAX).len(), 4);
    }

    #[test]
    fn an_oversized_locator_is_truncated_rather_than_walked() {
        let chain = chain_with(2);
        let genesis = chain.store().hash_at_height(0).unwrap().unwrap();
        let mut locator = vec![BlockHash::ZERO; MAX_LOCATOR_ACCEPTED * 4];
        locator[0] = genesis;
        // The genesis entry survives the truncation, so the answer is still
        // correct — and we walked a bounded list.
        assert_eq!(headers(&chain, &locator, None, 100).len(), 2);
    }

    #[test]
    fn a_stop_hash_ends_the_answer_inclusively() {
        let chain = chain_with(5);
        let genesis = chain.store().hash_at_height(0).unwrap().unwrap();
        let stop = chain.store().hash_at_height(3).unwrap().unwrap();
        let out = headers(&chain, &[genesis], Some(&stop), 100);
        assert_eq!(out.len(), 3);
        assert_eq!(ferrum_storage::header_hash(out.last().unwrap()), stop);
    }

    #[test]
    fn bodies_come_back_in_the_order_asked_for() {
        let chain = chain_with(4);
        let wanted: Vec<BlockHash> = (1..=4u64)
            .map(|h| chain.store().hash_at_height(h).unwrap().unwrap())
            .collect();
        let blocks = bodies(&chain, &wanted);
        assert_eq!(blocks.len(), 4);
        for (block, hash) in blocks.iter().zip(&wanted) {
            assert_eq!(ferrum_storage::header_hash(&block.header), *hash);
        }
    }

    #[test]
    fn an_unknown_body_is_skipped_not_faked() {
        let chain = chain_with(2);
        let known = chain.store().hash_at_height(1).unwrap().unwrap();
        let blocks = bodies(&chain, &[BlockHash::ZERO, known]);
        assert_eq!(blocks.len(), 1);
        assert_eq!(ferrum_storage::header_hash(&blocks[0].header), known);
    }

    #[test]
    fn a_block_request_for_nothing_we_hold_answers_not_found() {
        let chain = chain_with(1);
        let response = answer(&chain, &SyncRequest::GetBlocks { hashes: vec![BlockHash::ZERO] });
        assert!(matches!(response, SyncResponse::NotFound), "{response:?}");
    }

    #[test]
    fn more_block_hashes_than_the_cap_are_trimmed() {
        let chain = chain_with(2);
        let known = chain.store().hash_at_height(1).unwrap().unwrap();
        let hashes = vec![known; MAX_BLOCKS_SERVED * 3];
        assert_eq!(bodies(&chain, &hashes).len(), MAX_BLOCKS_SERVED);
    }
}
