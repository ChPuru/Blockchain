#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;

use ferrum_p2p::PeerId;
use ferrum_types::ChainParams;

use super::*;

// ---------------------------------------------------------------------------
// The two-hour future-time bound, applied on the sync path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_block_two_hours_ahead_is_refused_and_one_just_inside_is_accepted() {
    let params = ChainParams::devnet();
    let bound = params.max_future_block_time_ms;
    assert_eq!(bound, 7_200_000, "SPEC 3.2 rule 10 is two hours");

    let local = test_node(1);
    let now = base_time();
    local.clock.set(now);

    // One millisecond past the bound.
    let too_far = mine_at(&local, 7, now + bound + 1);
    assert_eq!(too_far.header.timestamp_ms, now + bound + 1);
    let outcome = local.relay.accept_block_at(too_far, now);
    assert_eq!(outcome.verdict, GossipVerdict::Reject);
    assert_eq!(outcome.rejection, Some(crate::relay::BlockRejection::TooFarInFuture));
    assert_eq!(local.chain.tip().1, 0, "the tip must not move");

    // Exactly on the bound: valid.
    let just_inside = mine_at(&local, 7, now + bound);
    assert_eq!(just_inside.header.timestamp_ms, now + bound);
    let hash = ferrum_storage::header_hash(&just_inside.header);
    let outcome = local.relay.accept_block_at(just_inside, now);
    assert_eq!(outcome.verdict, GossipVerdict::Accept);
    assert_eq!(local.chain.tip(), (hash, 1));
}

#[tokio::test]
async fn a_block_refused_for_being_early_is_not_recorded_invalid() {
    // Our clock, not the block, made it unacceptable: in ten minutes it is
    // fine, so nothing may be written against it.
    let local = test_node(1);
    let now = base_time();
    local.clock.set(now);
    let bound = ChainParams::devnet().max_future_block_time_ms;

    let block = mine_at(&local, 7, now + bound + 60_000);
    let hash = ferrum_storage::header_hash(&block.header);
    let outcome = local.relay.accept_block_at(block.clone(), now);
    assert_eq!(outcome.verdict, GossipVerdict::Reject);
    assert!(
        local.chain.store().get_header(&hash).unwrap().is_none(),
        "a future block must leave no record at all"
    );

    // Time passes, and the very same block is now acceptable.
    let outcome = local.relay.accept_block_at(block, now + 60_000);
    assert_eq!(outcome.verdict, GossipVerdict::Accept);
    assert_eq!(local.chain.tip().1, 1);
}

#[tokio::test]
async fn sync_applies_the_future_time_bound_to_downloaded_blocks() {
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 3);

    // The local node's clock is two hours and more behind the blocks it is
    // being offered, so every one of them is in its future.
    local.clock.set(base_time() - ChainParams::devnet().max_future_block_time_ms);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::Honest));
    let sync = manager(&local, Arc::clone(&network));

    let stats = sync.sync_to_best_peer(&[peer]).await.unwrap();
    assert_eq!(stats.blocks, 0, "nothing from the future may connect");
    assert_eq!(local.chain.tip().1, 0);
    assert!(!sync.bans().is_banned(&peer), "a clock skew is not misbehaviour we ban for");

    // Once the clock catches up the same blocks connect, unchanged.
    local.clock.set(base_time() + 3 * 120_000);
    let stats = sync.sync_to_best_peer(&[peer]).await.unwrap();
    assert_eq!(stats.blocks, 3);
    assert_eq!(local.chain.tip(), remote.chain.tip());
}
