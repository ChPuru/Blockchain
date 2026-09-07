#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;

use ferrum_p2p::PeerId;

use super::*;

// ---------------------------------------------------------------------------
// The run loop
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_run_loop_stops_when_the_token_is_cancelled() {
    let local = test_node(1);
    let network = Arc::new(Loopback::new());
    let sync = Arc::new(manager(&local, network));
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let token = CancellationToken::new();
    let handle = tokio::spawn(run(sync, rx, token.clone()));
    token.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(10), handle).await.unwrap().unwrap();
    drop(tx);
}

#[tokio::test]
async fn the_run_loop_syncs_when_hinted() {
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 4);
    local.clock.set(base_time() + 4 * 120_000);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::Honest));
    let sync = Arc::new(manager(&local, network));
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let token = CancellationToken::new();
    let handle = tokio::spawn(run(Arc::clone(&sync), rx, token.clone()));

    tx.send(peer).await.unwrap();
    for _ in 0..POLL_ATTEMPTS {
        if local.chain.tip().1 >= 4 {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    assert_eq!(local.chain.tip(), remote.chain.tip());

    token.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), handle).await;
}
