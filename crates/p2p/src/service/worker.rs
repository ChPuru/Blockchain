//! The swarm task: everything that owns the `libp2p::Swarm`.
//!
//! One task drives the swarm, one bounded command queue feeds it and one
//! bounded event queue drains out of it. Nothing here blocks and nothing here
//! grows without a limit.

mod events;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum_types::{Block, BlockHeader};
use futures::StreamExt;
use libp2p::gossipsub::{MessageAcceptance, TopicHash};
use libp2p::request_response::{OutboundRequestId, ResponseChannel};
use libp2p::swarm::ConnectionId;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder, noise};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use super::{
    EVENT_QUEUE, HandleInner, P2pCommand, P2pEvent, P2pHandle, PeerInfo, RequestId, ShedCounters,
    TipInfo, peer_id_from_multiaddr, reconnect_backoff,
};
use crate::behaviour::FerrumBehaviour;
use crate::config::P2pConfig;
use crate::error::P2pError;
use crate::limits;
use crate::message::{SyncRequest, SyncResponse};

/// Build the swarm, bind the listeners and spawn the event loop.
pub(super) fn spawn(config: P2pConfig) -> Result<(P2pHandle, JoinHandle<()>), P2pError> {
    let mut swarm = build_swarm(&config)?;

    for addr in &config.listen_addrs {
        swarm
            .listen_on(addr.clone())
            .map_err(|e| P2pError::Listen { addr: addr.to_string(), reason: e.to_string() })?;
    }

    let now = Instant::now();
    let mut static_peers = Vec::with_capacity(config.static_peers.len());
    for addr in &config.static_peers {
        let peer_id = peer_id_from_multiaddr(addr);
        if let Some(pid) = peer_id {
            swarm.add_peer_address(pid, addr.clone());
            // A configured peer is always kept in the mesh. With a handful of
            // static peers the mesh can never reach mesh_n_low on its own, and
            // an explicit peer is grafted regardless of degree.
            swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
        }
        static_peers.push(StaticPeer {
            addr: addr.clone(),
            peer_id,
            failures: 0,
            next_attempt: now,
            dialing: None,
            connected_as: None,
        });
    }

    let (command_tx, command_rx) = mpsc::channel(config.command_capacity);
    let (event_tx, event_rx) = mpsc::channel(config.event_capacity);
    let counters = Arc::new(ShedCounters::default());
    let shutdown = Arc::new(AtomicBool::new(false));

    let handle = P2pHandle {
        inner: Arc::new(HandleInner {
            commands: command_tx.clone(),
            events: Mutex::new(Some(event_rx)),
            local_peer_id: *swarm.local_peer_id(),
            counters: Arc::clone(&counters),
            shutdown: Arc::clone(&shutdown),
        }),
    };

    let worker = Worker {
        blocks_topic: config.blocks_topic().hash(),
        txs_topic: config.txs_topic().hash(),
        max_peers: config.max_peers,
        base_backoff: config.reconnect_base_backoff,
        max_backoff: config.reconnect_max_backoff,
        events: event_tx,
        responder_commands: command_tx,
        counters,
        shutdown,
        pending_inbound: BTreeMap::new(),
        pending_outbound: BTreeMap::new(),
        peers: BTreeMap::new(),
        static_peers,
        next_request_id: 0,
    };

    Ok((handle, tokio::spawn(run(worker, swarm, command_rx))))
}

/// TCP + Noise + Yamux, and nothing else.
///
/// The older stream multiplexer that libp2p deprecated for liveness problems is
/// not offered at all: a fallback that is advertised is a fallback that
/// eventually gets negotiated.
fn build_swarm(config: &P2pConfig) -> Result<Swarm<FerrumBehaviour>, P2pError> {
    let yamux = config.yamux_config();
    let idle_timeout = config.idle_connection_timeout;

    let swarm = SwarmBuilder::with_existing_identity(config.keypair.clone())
        .with_tokio()
        .with_tcp(config.tcp_config(), noise::Config::new, move || yamux)
        .map_err(|e| P2pError::Transport(e.to_string()))?
        .with_behaviour(|keypair| {
            FerrumBehaviour::new(keypair, config)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
        })
        .map_err(|e| P2pError::Behaviour(e.to_string()))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(idle_timeout))
        .build();

    Ok(swarm)
}

// ---------------------------------------------------------------------------
// Worker state
// ---------------------------------------------------------------------------

/// What the service remembers about a connected peer.
#[derive(Debug, Default)]
struct PeerRecord {
    address: Option<Multiaddr>,
    agent_version: Option<String>,
    protocol_version: Option<String>,
    last_rtt_ms: Option<u64>,
    connections: u32,
}

/// One entry of the configured static peer list, plus its reconnect state.
#[derive(Debug)]
struct StaticPeer {
    addr: Multiaddr,
    /// Known in advance when the multiaddress carries a `/p2p/` component.
    peer_id: Option<PeerId>,
    failures: u32,
    next_attempt: Instant,
    /// The dial currently in flight, if any.
    dialing: Option<ConnectionId>,
    /// Learned once a dial to a bare address succeeds.
    connected_as: Option<PeerId>,
}

/// An outbound request waiting for its answer.
enum PendingRequest {
    Headers { peer: PeerId, reply: oneshot::Sender<Result<Vec<BlockHeader>, P2pError>> },
    Blocks { peer: PeerId, reply: oneshot::Sender<Result<Vec<Block>, P2pError>> },
    Tip { peer: PeerId, reply: oneshot::Sender<Result<TipInfo, P2pError>> },
}

impl PendingRequest {
    fn peer(&self) -> PeerId {
        match self {
            PendingRequest::Headers { peer, .. }
            | PendingRequest::Blocks { peer, .. }
            | PendingRequest::Tip { peer, .. } => *peer,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            PendingRequest::Headers { .. } => "GetHeaders",
            PendingRequest::Blocks { .. } => "GetBlocks",
            PendingRequest::Tip { .. } => "GetTip",
        }
    }

    fn fail(self, error: P2pError) {
        match self {
            PendingRequest::Headers { reply, .. } => drop(reply.send(Err(error))),
            PendingRequest::Blocks { reply, .. } => drop(reply.send(Err(error))),
            PendingRequest::Tip { reply, .. } => drop(reply.send(Err(error))),
        }
    }

    /// Deliver a response, or fail the request if the peer answered with the
    /// wrong variant. `NotFound` is a legitimate empty answer for a bulk
    /// request but not for a tip query.
    fn fulfil(self, response: SyncResponse) {
        match (self, response) {
            (PendingRequest::Headers { reply, .. }, SyncResponse::Headers(headers)) => {
                drop(reply.send(Ok(headers)));
            }
            (PendingRequest::Headers { reply, .. }, SyncResponse::NotFound) => {
                drop(reply.send(Ok(Vec::new())));
            }
            (PendingRequest::Blocks { reply, .. }, SyncResponse::Blocks(blocks)) => {
                drop(reply.send(Ok(blocks)));
            }
            (PendingRequest::Blocks { reply, .. }, SyncResponse::NotFound) => {
                drop(reply.send(Ok(Vec::new())));
            }
            (PendingRequest::Tip { reply, .. }, SyncResponse::Tip { hash, height, work }) => {
                drop(reply.send(Ok(TipInfo { hash, height, work })));
            }
            (pending, other) => {
                let peer = pending.peer().to_string();
                let expected = pending.kind();
                pending.fail(P2pError::UnexpectedResponse { peer, expected, got: other.kind() });
            }
        }
    }
}

struct Worker {
    blocks_topic: TopicHash,
    txs_topic: TopicHash,
    max_peers: usize,
    base_backoff: Duration,
    max_backoff: Duration,
    events: mpsc::Sender<P2pEvent>,
    responder_commands: mpsc::Sender<P2pCommand>,
    counters: Arc<ShedCounters>,
    shutdown: Arc<AtomicBool>,
    pending_inbound: BTreeMap<RequestId, ResponseChannel<SyncResponse>>,
    pending_outbound: BTreeMap<OutboundRequestId, PendingRequest>,
    peers: BTreeMap<PeerId, PeerRecord>,
    static_peers: Vec<StaticPeer>,
    next_request_id: u64,
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

async fn run(
    mut worker: Worker,
    mut swarm: Swarm<FerrumBehaviour>,
    mut commands: mpsc::Receiver<P2pCommand>,
) {
    let mut ticker = tokio::time::interval(limits::RECONNECT_TICK);
    // A missed tick means the swarm was busy; firing the backlog immediately
    // would dial every static peer at once.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Dial the static peers now rather than after the first tick.
    worker.maintain_static_peers(&mut swarm);

    loop {
        tokio::select! {
            command = commands.recv() => match command {
                None | Some(P2pCommand::Shutdown) => break,
                Some(command) => worker.handle_command(&mut swarm, command),
            },
            event = swarm.select_next_some() => worker.handle_swarm_event(&mut swarm, event),
            _ = ticker.tick() => {
                if worker.shutdown.load(Ordering::Acquire) {
                    break;
                }
                worker.prune_stale_inbound();
                worker.maintain_static_peers(&mut swarm);
            }
        }
    }

    worker.abort_pending();
    tracing::info!("p2p service stopped");
}

impl Worker {
    // ---- queues -----------------------------------------------------------

    /// Try to hand an event to the node. Returns the event when it was shed.
    fn emit_or_return(&self, event: P2pEvent) -> Option<P2pEvent> {
        let kind = event.kind();
        match self.events.try_send(event) {
            Ok(()) => None,
            Err(mpsc::error::TrySendError::Full(event)) => {
                let shed = self.counters.shed_event();
                tracing::warn!(
                    queue = EVENT_QUEUE,
                    event = kind,
                    shed_total = shed,
                    "event queue full; shedding rather than growing it"
                );
                Some(event)
            }
            Err(mpsc::error::TrySendError::Closed(event)) => {
                tracing::debug!(queue = EVENT_QUEUE, event = kind, "no event consumer");
                Some(event)
            }
        }
    }

    fn emit(&self, event: P2pEvent) {
        drop(self.emit_or_return(event));
    }

    fn next_id(&mut self) -> RequestId {
        let id = RequestId::new(self.next_request_id);
        self.next_request_id = self.next_request_id.wrapping_add(1);
        id
    }

    fn is_static(&self, peer: &PeerId) -> bool {
        self.static_peers
            .iter()
            .any(|sp| sp.peer_id == Some(*peer) || sp.connected_as == Some(*peer))
    }

    /// Whether the in-flight request table is full, with the warning and the
    /// counter as a side effect.
    fn outbound_saturated(&self) -> bool {
        if self.pending_outbound.len() >= limits::MAX_PENDING_OUTBOUND_REQUESTS {
            let shed = self.counters.shed_outbound_request();
            tracing::warn!(
                in_flight = self.pending_outbound.len(),
                shed_total = shed,
                "too many sync requests in flight; refusing a new one"
            );
            true
        } else {
            false
        }
    }

    /// Drop parked inbound requests whose peer has given up.
    ///
    /// A response channel closes when libp2p times the inbound request out. The
    /// node may still be holding the matching responder, and without this sweep
    /// the entry would occupy a slot in the bounded table until the node
    /// answered. Run on every reconnect tick, which is cheap: the table holds at
    /// most `MAX_PENDING_INBOUND_REQUESTS` entries.
    fn prune_stale_inbound(&mut self) {
        let before = self.pending_inbound.len();
        self.pending_inbound.retain(|_, channel| channel.is_open());
        let dropped = before.saturating_sub(self.pending_inbound.len());
        if dropped > 0 {
            tracing::debug!(dropped, "reclaimed inbound sync requests the peer abandoned");
        }
    }

    /// Fail everything still waiting when the task stops.
    fn abort_pending(&mut self) {
        let pending = std::mem::take(&mut self.pending_outbound);
        for (_, request) in pending {
            request.fail(P2pError::ServiceStopped);
        }
        // Dropping the response channels makes libp2p report a response
        // omission to each peer rather than leaving their streams open.
        self.pending_inbound.clear();
    }

    // ---- commands ---------------------------------------------------------

    fn handle_command(&mut self, swarm: &mut Swarm<FerrumBehaviour>, command: P2pCommand) {
        match command {
            P2pCommand::Publish { message, reply } => {
                let topic = if message.is_block_topic() {
                    self.blocks_topic.clone()
                } else {
                    self.txs_topic.clone()
                };
                let topic_name = topic.to_string();
                let result =
                    message.encode().and_then(|data| {
                        swarm.behaviour_mut().gossipsub.publish(topic, data).map_err(|e| {
                            P2pError::Publish { topic: topic_name, reason: e.to_string() }
                        })
                    });
                drop(reply.send(result));
            }

            P2pCommand::RequestHeaders { peer, locator, stop, max, reply } => {
                if self.outbound_saturated() {
                    let in_flight = self.pending_outbound.len();
                    drop(reply.send(Err(P2pError::TooManyInFlight { in_flight })));
                    return;
                }
                let request = SyncRequest::GetHeaders { locator, stop, max };
                let id = swarm.behaviour_mut().sync.send_request(&peer, request);
                self.pending_outbound.insert(id, PendingRequest::Headers { peer, reply });
            }

            P2pCommand::RequestBlocks { peer, hashes, reply } => {
                if self.outbound_saturated() {
                    let in_flight = self.pending_outbound.len();
                    drop(reply.send(Err(P2pError::TooManyInFlight { in_flight })));
                    return;
                }
                let id = swarm
                    .behaviour_mut()
                    .sync
                    .send_request(&peer, SyncRequest::GetBlocks { hashes });
                self.pending_outbound.insert(id, PendingRequest::Blocks { peer, reply });
            }

            P2pCommand::RequestTip { peer, reply } => {
                if self.outbound_saturated() {
                    let in_flight = self.pending_outbound.len();
                    drop(reply.send(Err(P2pError::TooManyInFlight { in_flight })));
                    return;
                }
                let id = swarm.behaviour_mut().sync.send_request(&peer, SyncRequest::GetTip);
                self.pending_outbound.insert(id, PendingRequest::Tip { peer, reply });
            }

            P2pCommand::Respond { id, response } => match self.pending_inbound.remove(&id) {
                Some(channel) => {
                    // The caps are applied here, on the way out, so they hold
                    // whatever the peer asked for and whatever the node built.
                    let capped = (*response).capped();
                    let kind = capped.kind();
                    if swarm.behaviour_mut().sync.send_response(channel, capped).is_err() {
                        tracing::debug!(%id, kind, "peer gave up before the response was ready");
                    }
                }
                None => tracing::debug!(%id, "response for an unknown or cancelled request"),
            },

            P2pCommand::CancelResponse { id } => {
                if self.pending_inbound.remove(&id).is_some() {
                    tracing::debug!(%id, "inbound sync request abandoned without an answer");
                }
            }

            P2pCommand::ReportValidation { msg_id, peer, acceptance } => {
                let verdict = acceptance_name(&acceptance);
                let known = swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(&msg_id, &peer, acceptance);
                if known {
                    tracing::trace!(%peer, %msg_id, verdict, "reported gossip validation");
                } else {
                    tracing::debug!(
                        %peer, %msg_id, verdict,
                        "validation reported for a message that already left the cache"
                    );
                }
            }

            P2pCommand::Peers { reply } => {
                let peers = self
                    .peers
                    .iter()
                    .map(|(peer_id, record)| PeerInfo {
                        peer_id: *peer_id,
                        address: record.address.clone(),
                        agent_version: record.agent_version.clone(),
                        protocol_version: record.protocol_version.clone(),
                        last_rtt_ms: record.last_rtt_ms,
                        is_static: self.is_static(peer_id),
                    })
                    .collect();
                drop(reply.send(peers));
            }

            P2pCommand::Dial { addr, reply } => {
                let result = swarm
                    .dial(addr.clone())
                    .map_err(|e| P2pError::Dial { addr: addr.to_string(), reason: e.to_string() });
                drop(reply.send(result));
            }

            P2pCommand::Shutdown => {}
        }
    }

    // ---- static peers -----------------------------------------------------

    /// Redial any static peer that is down and whose backoff has elapsed.
    fn maintain_static_peers(&mut self, swarm: &mut Swarm<FerrumBehaviour>) {
        let now = Instant::now();
        let base = self.base_backoff;
        let max = self.max_backoff;

        for peer in &mut self.static_peers {
            let known = peer.peer_id.or(peer.connected_as);
            if known.is_some_and(|id| swarm.is_connected(&id)) {
                peer.failures = 0;
                peer.dialing = None;
                continue;
            }
            if peer.dialing.is_some() || now < peer.next_attempt {
                continue;
            }

            let opts = DialOpts::from(peer.addr.clone());
            let connection_id = opts.connection_id();
            match swarm.dial(opts) {
                Ok(()) => {
                    peer.dialing = Some(connection_id);
                    tracing::debug!(addr = %peer.addr, "dialling static peer");
                }
                Err(error) => {
                    peer.failures = peer.failures.saturating_add(1);
                    let delay = reconnect_backoff(peer.failures, base, max);
                    peer.next_attempt = now + delay;
                    tracing::warn!(
                        addr = %peer.addr,
                        failures = peer.failures,
                        %error,
                        "static peer dial rejected; backing off"
                    );
                }
            }
        }
    }
}

/// A stable name for a validation verdict, for log lines.
fn acceptance_name(acceptance: &MessageAcceptance) -> &'static str {
    match acceptance {
        MessageAcceptance::Accept => "accept",
        MessageAcceptance::Reject => "reject",
        MessageAcceptance::Ignore => "ignore",
    }
}
