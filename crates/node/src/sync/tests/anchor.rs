#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;

use ferrum_chain::ChainError;
use ferrum_p2p::PeerId;
use ferrum_types::BlockHash;

use super::*;

// ---------------------------------------------------------------------------
// The ASERT anchor, and what a header batch does at a cold start
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_cold_start_validates_a_whole_header_batch() {
    // The ASERT anchor is genesis, built from `ChainParams` (CONTRACT 6.3), so
    // the difficulty rule reads nothing out of the chain but the parent's
    // height. A node at height 0 can therefore validate an entire batch of
    // headers in one pass, without any of them connecting first.
    //
    // This test used to assert the opposite: that only the header at the anchor
    // height validated and the batch stalled there, because the anchor was read
    // through `HeaderView::header_at_height`, which is the *active* chain
    // (CONTRACT 6.4). That stall was the visible, harmless half of a consensus
    // bug whose other half was fatal — two nodes holding different blocks at the
    // anchor height computed different required `bits` for each other's headers,
    // rejected them, and forked permanently. The stall is gone because the
    // fork-dependence is gone.
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 5);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::Honest));
    let sync = manager(&local, Arc::clone(&network));

    let locator = local.chain.locator();
    let headers = network.request_headers(peer, locator, None, HEADERS_PER_REQUEST).await.unwrap();
    assert_eq!(headers.len(), 5);

    let batch = sync.accept_headers(peer, headers).await.unwrap();
    assert_eq!(batch.accepted, 5, "every header validates against the genesis anchor");
    assert_eq!(batch.wanted.len(), batch.accepted, "one body wanted per accepted header");
    assert_eq!(batch.stalled, None, "there is nothing left to stall on");
    assert!(sync.bans().is_empty());
}

#[tokio::test]
async fn a_header_batch_reports_only_the_bodies_we_still_need() {
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 4);
    local.clock.set(base_time() + 4 * 120_000);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::Honest));
    let sync = manager(&local, Arc::clone(&network));
    sync.sync_to_best_peer(&[peer]).await.unwrap();
    assert_eq!(local.chain.tip(), remote.chain.tip());

    // Offer the same headers again: we have every body, so nothing is wanted.
    let headers = network
        .request_headers(
            peer,
            vec![local.chain.store().hash_at_height(0).unwrap().unwrap()],
            None,
            HEADERS_PER_REQUEST,
        )
        .await
        .unwrap();
    let batch = sync.accept_headers(peer, headers).await.unwrap();
    assert!(batch.wanted.is_empty(), "nothing left to download");
    assert_eq!(batch.stalled, None);
}

#[test]
fn only_a_rule_break_is_bannable() {
    use ferrum_consensus::ConsensusError;

    // Ours, not theirs. `MissingHeader` is no longer reachable from the
    // difficulty rule — its anchor is genesis, out of `ChainParams` — but it
    // stays a "we are behind", never-ban verdict for any rule that does need a
    // header off the active chain.
    assert!(!header_failure_is_bannable(&ChainError::Consensus(ConsensusError::MissingHeader(1))));
    assert!(!header_failure_is_bannable(&ChainError::NoTip));
    assert!(!header_failure_is_bannable(&ChainError::Arithmetic("work")));

    // Theirs.
    assert!(header_failure_is_bannable(&ChainError::Consensus(ConsensusError::ZeroTarget)));
    assert!(header_failure_is_bannable(&ChainError::UnknownParent(BlockHash::ZERO)));
    assert!(header_failure_is_bannable(&ChainError::KnownInvalid(BlockHash::ZERO)));
}
