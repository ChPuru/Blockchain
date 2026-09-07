#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;

use ferrum_chain::ChainError;
use ferrum_p2p::PeerId;
use ferrum_types::BlockHash;

use super::*;

// ---------------------------------------------------------------------------
// The ASERT anchor, and what a header batch does when it cannot go further
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_cold_start_stalls_on_the_anchor_and_is_not_a_ban() {
    // `HeaderView::header_at_height` reads the ACTIVE chain (CONTRACT 6.4) and
    // the ASERT anchor is the block at height 1, so a node at height 0 cannot
    // evaluate the difficulty transition above height 1 until block 1 connects.
    // That is a gap in our own state, not misbehaviour by the peer.
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
    assert_eq!(batch.accepted, 1, "only the header at the anchor height validates");
    assert_eq!(batch.wanted.len(), 1);
    assert!(batch.stalled.is_some(), "the batch stops, it does not ban");
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
        .request_headers(peer, vec![local.chain.store().hash_at_height(0).unwrap().unwrap()], None, HEADERS_PER_REQUEST)
        .await
        .unwrap();
    let batch = sync.accept_headers(peer, headers).await.unwrap();
    assert!(batch.wanted.is_empty(), "nothing left to download");
    assert_eq!(batch.stalled, None);
}

#[test]
fn only_a_rule_break_is_bannable() {
    use ferrum_consensus::ConsensusError;

    // Ours, not theirs.
    assert!(!header_failure_is_bannable(&ChainError::Consensus(ConsensusError::MissingHeader(1))));
    assert!(!header_failure_is_bannable(&ChainError::NoTip));
    assert!(!header_failure_is_bannable(&ChainError::Arithmetic("work")));

    // Theirs.
    assert!(header_failure_is_bannable(&ChainError::Consensus(ConsensusError::ZeroTarget)));
    assert!(header_failure_is_bannable(&ChainError::UnknownParent(BlockHash::ZERO)));
    assert!(header_failure_is_bannable(&ChainError::KnownInvalid(BlockHash::ZERO)));
}
