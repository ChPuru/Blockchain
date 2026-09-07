#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;

use ferrum_p2p::PeerId;
use ferrum_types::BlockHash;

use super::*;

// ---------------------------------------------------------------------------
// Misbehaviour
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_peer_serving_an_invalid_header_is_banned_and_disconnected() {
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 4);
    local.clock.set(base_time() + 4 * 120_000);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::ForgedHeader));
    let sync = manager(&local, Arc::clone(&network));

    let e = sync.sync_to_best_peer(&[peer]).await.unwrap_err();
    match &e {
        NodeError::PeerMisbehaved { what, .. } => assert_eq!(*what, "header"),
        other => panic!("expected PeerMisbehaved, got {other}"),
    }
    assert!(e.is_peer_misbehaviour());
    assert!(sync.bans().is_banned(&peer), "SPEC 12: the peer is disconnected");
    assert_eq!(network.disconnects(), vec![peer]);
    assert_eq!(local.chain.tip().1, 0, "nothing from a bad peer reaches the chain");
    assert_eq!(local.relay.metrics().snapshot().peers_disconnected, 1);
}

#[tokio::test]
async fn a_banned_peer_is_never_asked_again() {
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 3);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::Honest));
    let sync = manager(&local, network);
    sync.bans().ban(peer);

    assert!(sync.usable_peers().await.is_empty());
    assert!(sync.best_peer(&[peer]).await.is_none());
}

#[tokio::test]
async fn a_peer_serving_a_block_that_does_not_match_its_header_is_banned() {
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 3);
    local.clock.set(base_time() + 3 * 120_000);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::ForgedBody));
    let sync = manager(&local, Arc::clone(&network));

    // The header still hashes to what we asked for — only the body was
    // tampered with — so this is caught by the merkle-root rule at connect
    // time, and the peer that served it is named.
    let wanted: Vec<BlockHash> =
        (1..=3u64).map(|h| remote.chain.store().hash_at_height(h).unwrap().unwrap()).collect();
    let served = sync.download_window(&[peer], peer, &wanted).await.unwrap();
    assert_eq!(served.len(), 3);
    let e = sync.connect_served(served).await.unwrap_err();
    match &e {
        NodeError::PeerMisbehaved { what, .. } => assert_eq!(*what, "block"),
        other => panic!("expected PeerMisbehaved, got {other}"),
    }
    assert!(sync.bans().is_banned(&peer));
    assert_eq!(network.disconnects(), vec![peer]);
    assert_eq!(local.chain.tip().1, 0);
}

#[tokio::test]
async fn a_full_sync_round_bans_a_peer_that_forges_a_body() {
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 3);
    local.clock.set(base_time() + 3 * 120_000);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::ForgedBody));
    let sync = manager(&local, Arc::clone(&network));

    let e = sync.sync_to_best_peer(&[peer]).await.unwrap_err();
    assert!(e.is_peer_misbehaviour(), "{e}");
    assert!(sync.bans().is_banned(&peer));
}

#[tokio::test]
async fn a_peer_serving_a_block_nobody_asked_for_is_banned() {
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 3);

    let peer = PeerId::random();
    let network = Arc::new(Loopback::new().with(
        peer,
        Arc::clone(&remote.chain),
        Behaviour::UnrequestedBlock,
    ));
    let sync = manager(&local, Arc::clone(&network));

    let wanted: Vec<BlockHash> = vec![remote.chain.store().hash_at_height(1).unwrap().unwrap()];
    let e = sync.download_window(&[peer], peer, &wanted).await.unwrap_err();
    match &e {
        NodeError::PeerMisbehaved { what, reason, .. } => {
            assert_eq!(*what, "block");
            assert!(reason.contains("not requested"), "{reason}");
        }
        other => panic!("expected PeerMisbehaved, got {other}"),
    }
    assert_eq!(network.disconnects(), vec![peer]);
}

#[tokio::test]
async fn connecting_an_invalid_block_from_a_named_peer_bans_it() {
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 2);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::Honest));
    let sync = manager(&local, Arc::clone(&network));

    // A block whose merkle root does not commit to its transactions.
    let hash = remote.chain.store().hash_at_height(1).unwrap().unwrap();
    let mut block = remote.chain.store().get_block(&hash).unwrap().unwrap();
    block.header.merkle_root = ferrum_types::Hash32::from_bytes([9u8; 32]);

    let e = sync.connect_blocks_from(peer, vec![block]).await.unwrap_err();
    assert!(e.is_peer_misbehaviour(), "{e}");
    assert!(sync.bans().is_banned(&peer));
    assert_eq!(network.disconnects(), vec![peer]);
}

#[tokio::test]
async fn our_own_storage_failure_never_bans_a_peer() {
    // A block whose parent we do not have is an orphan, not misbehaviour: it
    // says nothing about the peer, and banning for it would ban every peer
    // that gossips slightly out of order.
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 3);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::Honest));
    let sync = manager(&local, network);

    let hash = remote.chain.store().hash_at_height(3).unwrap().unwrap();
    let orphan = remote.chain.store().get_block(&hash).unwrap().unwrap();
    let connected = sync.connect_blocks_from(peer, vec![orphan]).await.unwrap();
    assert_eq!(connected, 1, "the orphan is held, which counts as handled");
    assert!(!sync.bans().is_banned(&peer));
}
