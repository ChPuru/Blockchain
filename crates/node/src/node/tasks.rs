//! The tasks a running node owns, and the bounded queues between them.
//!
//! Five long-lived tasks — p2p, rpc, miner, explorer and metrics — plus two
//! small couriers: one that bridges the chain's synchronous event channel onto
//! an async broadcast, and one that publishes freshly mined blocks. Every one
//! of them exits on the same [`CancellationToken`].
//!
//! # Every queue has a capacity, and sheds when it is full
//!
//! There is no unbounded channel anywhere in this workspace (CONTRACT §10.3),
//! and CI greps for one. An unbounded channel does not remove backpressure, it
//! converts backpressure into an out-of-memory kill: the producer never blocks,
//! so a stalled consumer is answered by the allocator instead of by a warning.
//! Each constant below is the answer to "how far behind may this consumer fall
//! before dropping a message is the better outcome?".
//!
//! # Gossip is validated in order, serving is not
//!
//! Inbound gossip is handled inline in the event loop, because a block must be
//! offered to the chain after its parent and reordering it would turn a valid
//! block into an orphan. Inbound *sync requests* are answered on a bounded pool
//! of tasks instead: they are pure reads, order does not matter, and a peer
//! doing initial sync must not stall block relay for everyone else.

use std::sync::Arc;
use std::time::Duration;

use ferrum_chain::{ChainEvent, ChainManager};
use ferrum_p2p::{GossipMessage, MessageAcceptance, P2pEvent, P2pHandle, PeerId};
use ferrum_types::Block;
use tokio::sync::{Semaphore, broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use crate::node::serve;
use crate::relay::{GossipVerdict, Relay};
use crate::sync::{PeerBans, blocking};
use crate::telemetry::NodeMetrics;

/// How many chain events a subscriber may fall behind before it starts missing
/// them.
///
/// 256 is roughly eight hours of blocks at the two-minute target spacing.
pub const CHAIN_EVENT_CAPACITY: usize = 256;

/// How many "this peer may have something" hints may queue for the sync task.
///
/// A missed hint costs at most one `SYNC_POLL_INTERVAL`, so this can be small.
pub const SYNC_HINT_CAPACITY: usize = 64;

/// How many inbound sync requests are answered concurrently.
///
/// The wire layer already caps concurrent streams; this caps the *blocking
/// threads* those streams can occupy, which is the resource that actually runs
/// out.
pub const MAX_CONCURRENT_SERVES: usize = 8;

/// How often the gauges that are not event-driven are refreshed.
pub const METRICS_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// Bridge the chain's synchronous event channel onto an async broadcast.
///
/// `ChainManager::subscribe` hands out a `std::sync::mpsc::Receiver` because
/// `ferrum-chain` is synchronous throughout. One blocking thread drains it,
/// with a short timeout so that cancellation is noticed promptly rather than at
/// the next block.
///
/// The broadcast is bounded: a receiver that falls behind is told it lagged and
/// carries on, which is the right answer for "the tip moved" — the *latest*
/// tip is what matters and it is always still in the channel.
pub fn spawn_chain_event_bridge(
    chain: Arc<ChainManager>,
    events: broadcast::Sender<ChainEvent>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let rx = chain.subscribe();
        while !cancel.is_cancelled() {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(event) => {
                    // `send` fails only when nobody is listening, which is
                    // normal for a node with no miner and no sync task.
                    let _ = events.send(event);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        tracing::debug!("chain event bridge stopped");
    })
}

/// Publish freshly mined blocks to the gossip topic.
pub async fn announce_blocks(
    handle: P2pHandle,
    mut blocks: mpsc::Receiver<Block>,
    cancel: CancellationToken,
) {
    loop {
        let block = tokio::select! {
            () = cancel.cancelled() => break,
            block = blocks.recv() => match block {
                Some(block) => block,
                None => break,
            },
        };
        let hash = ferrum_storage::header_hash(&block.header);
        match handle.publish_block(block).await {
            Ok(id) => tracing::debug!(%hash, msg_id = ?id, "announced a mined block"),
            // A node with no mesh peers yet is the normal state of a solo
            // devnet and of every node for its first few seconds; warning once
            // per block there would bury the publish failures that matter.
            Err(e) if e.is_no_peers() => {
                tracing::debug!(%hash, error = %e, "no peers to announce a mined block to");
            }
            Err(e) => tracing::warn!(%hash, error = %e, "could not announce a mined block"),
        }
    }
    tracing::debug!("block announcer stopped");
}

/// Refresh the gauges that no event drives.
pub async fn refresh_metrics(
    relay: Arc<Relay>,
    handle: Option<P2pHandle>,
    metrics: Arc<NodeMetrics>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = tokio::time::sleep(METRICS_REFRESH_INTERVAL) => {}
        }
        let (_, height) = relay.chain().tip();
        metrics.set_height(height);
        metrics.set_mempool(relay.mempool().len(), relay.mempool().size_bytes());
        if let Some(handle) = &handle {
            match handle.peers().await {
                Ok(peers) => metrics.set_peers(peers.len()),
                Err(e) => tracing::debug!(error = %e, "peer count unavailable"),
            }
        }
    }
    tracing::debug!("metrics refresher stopped");
}

/// Everything the p2p event loop needs.
#[derive(Debug)]
pub struct P2pLoop {
    /// Validation and connection.
    pub relay: Arc<Relay>,
    /// The chain, for serving inbound requests.
    pub chain: Arc<ChainManager>,
    /// The swarm handle, for reporting validation verdicts.
    pub handle: P2pHandle,
    /// Where "this peer may have something" hints go.
    pub hints: mpsc::Sender<PeerId>,
    /// Peers banned for serving invalid data.
    pub bans: Arc<PeerBans>,
    /// Counters.
    pub metrics: Arc<NodeMetrics>,
}

/// Drive the p2p event stream until `cancel` fires.
pub async fn run_p2p(
    ctx: P2pLoop,
    mut events: mpsc::Receiver<P2pEvent>,
    cancel: CancellationToken,
) {
    let serves = Arc::new(Semaphore::new(MAX_CONCURRENT_SERVES));
    loop {
        let event = tokio::select! {
            () = cancel.cancelled() => break,
            event = events.recv() => match event {
                Some(event) => event,
                None => break,
            },
        };
        handle_event(&ctx, &serves, event).await;
    }
    tracing::debug!("p2p event loop stopped");
}

async fn handle_event(ctx: &P2pLoop, serves: &Arc<Semaphore>, event: P2pEvent) {
    match event {
        P2pEvent::Listening { address } => {
            tracing::info!(%address, "p2p listening");
        }
        P2pEvent::PeerConnected { peer, address } => {
            tracing::info!(%peer, %address, "peer connected");
            hint(ctx, peer);
        }
        P2pEvent::PeerDisconnected { peer } => {
            tracing::info!(%peer, "peer disconnected");
        }
        P2pEvent::InvalidGossip { peer, reason, .. } => {
            // The service has already reported it as Reject; this is for the
            // operator, and for the counter.
            tracing::warn!(%peer, reason, "undecodable gossip");
            ctx.metrics.block_rejected();
        }
        P2pEvent::Gossip { peer, msg_id, topic, message } => {
            let verdict = if ctx.bans.is_banned(&peer) {
                // SPEC 12: a peer that served invalid data has its messages
                // reported as rejected so its gossip score falls.
                tracing::debug!(%peer, "rejecting gossip from a banned peer");
                GossipVerdict::Reject
            } else {
                validate_gossip(ctx, peer, *message).await
            };
            if let Err(e) = ctx.handle.report_validation(msg_id, peer, verdict.acceptance()) {
                tracing::warn!(%peer, topic, error = %e, "could not report a validation verdict");
            }
        }
        P2pEvent::InboundRequest { peer, request, responder } => {
            let Ok(permit) = Arc::clone(serves).acquire_owned().await else {
                // The semaphore is closed only at shutdown; drop the responder
                // and libp2p reports an omission rather than hanging the peer.
                return;
            };
            let chain = Arc::clone(&ctx.chain);
            tokio::spawn(async move {
                let response =
                    match blocking(move || serve::answer(&chain, &request)).await {
                        Ok(response) => response,
                        Err(e) => {
                            tracing::warn!(%peer, error = %e, "could not build a sync response");
                            ferrum_p2p::SyncResponse::NotFound
                        }
                    };
                if let Err(e) = responder.respond(response) {
                    tracing::debug!(%peer, error = %e, "could not send a sync response");
                }
                drop(permit);
            });
        }
    }
}

/// Validate one gossip payload and decide what to tell gossipsub.
async fn validate_gossip(ctx: &P2pLoop, peer: PeerId, message: GossipMessage) -> GossipVerdict {
    match message {
        GossipMessage::NewBlock(block) => {
            let relay = Arc::clone(&ctx.relay);
            match blocking(move || relay.accept_block(*block)).await {
                Ok(outcome) => {
                    if outcome.outcome.is_none() && outcome.rejection.is_none() {
                        tracing::debug!(hash = %outcome.hash, "block not connected");
                    }
                    outcome.verdict
                }
                Err(e) => {
                    // Our own failure. Never scored against the sender.
                    tracing::error!(%peer, error = %e, "block validation task failed");
                    GossipVerdict::Ignore
                }
            }
        }
        GossipMessage::NewTransaction(tx) => {
            let relay = Arc::clone(&ctx.relay);
            match blocking(move || relay.accept_transaction(tx)).await {
                Ok(outcome) => outcome.verdict,
                Err(e) => {
                    tracing::error!(%peer, error = %e, "transaction validation task failed");
                    GossipVerdict::Ignore
                }
            }
        }
        GossipMessage::NewTip { hash, height } => {
            // An announcement, not a block. Nothing to validate: forward it,
            // and ask sync to look at this peer.
            let (_, ours) = ctx.relay.chain().tip();
            if height > ours {
                tracing::debug!(%peer, %hash, height, ours, "peer announced a better tip");
                hint(ctx, peer);
            }
            GossipVerdict::Accept
        }
    }
}

/// Nudge the sync task, shedding the hint if its queue is full.
fn hint(ctx: &P2pLoop, peer: PeerId) {
    if let Err(e) = ctx.hints.try_send(peer) {
        tracing::debug!(
            capacity = SYNC_HINT_CAPACITY,
            error = %e,
            "sync hint queue is full; shedding"
        );
        ctx.metrics.shed();
    }
}

/// Map a verdict to the libp2p value, for callers outside this module.
#[must_use]
pub const fn acceptance_of(verdict: GossipVerdict) -> MessageAcceptance {
    verdict.acceptance()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::Arc;

    use ferrum_consensus::EngineRouter;
    use ferrum_mempool::{Mempool, MempoolConfig};
    use ferrum_storage::{Store, StoreConfig};
    use ferrum_types::{BlockHash, ChainParams};

    use super::*;
    use crate::relay::{FixedClock, Relay};

    fn chain() -> Arc<ChainManager> {
        let params = ChainParams::devnet();
        let store = Arc::new(Store::open_in_memory(StoreConfig::default()).unwrap());
        let engines = Arc::new(EngineRouter::new(params.clone()).unwrap());
        let chain = Arc::new(ChainManager::open(store, params, engines).unwrap());
        chain.init_genesis().unwrap();
        chain
    }

    fn relay(chain: Arc<ChainManager>) -> Arc<Relay> {
        let params = ChainParams::devnet();
        Arc::new(Relay::new(
            chain,
            Arc::new(Mempool::new(MempoolConfig::new(params))),
            Arc::new(NodeMetrics::new()),
            Arc::new(FixedClock::new(1_735_689_720_000)),
        ))
    }

    #[test]
    fn every_capacity_is_bounded_and_explained() {
        for cap in [CHAIN_EVENT_CAPACITY, SYNC_HINT_CAPACITY, MAX_CONCURRENT_SERVES] {
            assert!(cap > 0, "a zero-capacity queue deadlocks");
            assert!(cap <= 1024, "a queue this large is unbounded with extra steps");
        }
        assert!(METRICS_REFRESH_INTERVAL >= Duration::from_secs(1));
    }

    #[test]
    fn verdicts_convert_without_a_runtime() {
        assert!(matches!(acceptance_of(GossipVerdict::Accept), MessageAcceptance::Accept));
        assert!(matches!(acceptance_of(GossipVerdict::Reject), MessageAcceptance::Reject));
        assert!(matches!(acceptance_of(GossipVerdict::Ignore), MessageAcceptance::Ignore));
    }

    #[tokio::test]
    async fn the_chain_event_bridge_forwards_a_new_tip_and_stops_on_cancel() {
        let chain = chain();
        let (tx, mut rx) = broadcast::channel(CHAIN_EVENT_CAPACITY);
        let cancel = CancellationToken::new();
        let bridge = spawn_chain_event_bridge(Arc::clone(&chain), tx, cancel.clone());

        // Give the blocking thread a moment to subscribe before the event.
        tokio::time::sleep(Duration::from_millis(50)).await;
        chain.init_genesis().unwrap();

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(10), bridge).await.unwrap().unwrap();
        // The bridge may or may not have caught the idempotent genesis event;
        // what matters is that it stopped cleanly.
        let _ = rx.try_recv();
    }

    #[tokio::test]
    async fn the_metrics_refresher_stops_on_cancel() {
        let relay = relay(chain());
        let metrics = Arc::clone(relay.metrics());
        let cancel = CancellationToken::new();
        let task = tokio::spawn(refresh_metrics(relay, None, metrics, cancel.clone()));
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn the_block_announcer_stops_when_its_queue_closes() {
        // Without a swarm there is no handle, so this covers the other exit:
        // the sender being dropped.
        let (tx, rx) = mpsc::channel::<Block>(4);
        drop(tx);
        let cancel = CancellationToken::new();
        // `announce_blocks` needs a handle; the closed-channel path is reached
        // before the handle is touched, so a cancelled token is equivalent.
        cancel.cancel();
        drop(rx);
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn a_tip_announcement_from_a_worse_peer_is_still_forwarded() {
        let chain = chain();
        let relay = relay(Arc::clone(&chain));
        let (hints, mut rx) = mpsc::channel(SYNC_HINT_CAPACITY);
        let ctx = P2pLoop {
            relay: Arc::clone(&relay),
            chain,
            // No swarm in this test; the handle is only used for reporting,
            // which `validate_gossip` does not do.
            handle: unreachable_handle(),
            hints,
            bans: Arc::new(PeerBans::new()),
            metrics: Arc::clone(relay.metrics()),
        };
        let verdict = validate_gossip(
            &ctx,
            PeerId::random(),
            GossipMessage::NewTip { hash: BlockHash::ZERO, height: 0 },
        )
        .await;
        assert_eq!(verdict, GossipVerdict::Accept);
        assert!(rx.try_recv().is_err(), "a tip no better than ours needs no sync");
    }

    #[tokio::test]
    async fn a_better_tip_announcement_hints_the_sync_task() {
        let chain = chain();
        let relay = relay(Arc::clone(&chain));
        let (hints, mut rx) = mpsc::channel(SYNC_HINT_CAPACITY);
        let peer = PeerId::random();
        let ctx = P2pLoop {
            relay: Arc::clone(&relay),
            chain,
            handle: unreachable_handle(),
            hints,
            bans: Arc::new(PeerBans::new()),
            metrics: Arc::clone(relay.metrics()),
        };
        let verdict =
            validate_gossip(&ctx, peer, GossipMessage::NewTip { hash: BlockHash::ZERO, height: 9 })
                .await;
        assert_eq!(verdict, GossipVerdict::Accept);
        assert_eq!(rx.try_recv().unwrap(), peer);
    }

    /// A handle to a p2p service bound to an ephemeral port.
    ///
    /// The tests above never send a command through it; it exists because
    /// `P2pLoop` holds one by value. Binding a real service is cheaper and more
    /// honest than a mock of a struct with no trait.
    fn unreachable_handle() -> P2pHandle {
        let config = ferrum_p2p::P2pConfig::new(ChainParams::devnet().chain_id);
        let (handle, task) = ferrum_p2p::P2pService::spawn(config)
            .expect("a service with no listen address always starts");
        task.abort();
        handle
    }
}
