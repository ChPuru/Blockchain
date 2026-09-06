//! The p2p service: a swarm task plus a cloneable handle.
//!
//! This crate is **transport only**. It moves bytes, applies the wire caps and
//! reports gossip validation results; it never decides whether a block is
//! valid, never touches a store and never drives sync. The node owns all of
//! that. The seam is [`P2pEvent`] going out and [`P2pHandle`] coming in.
//!
//! # Backpressure
//!
//! There is exactly one command queue and one event queue, both bounded by
//! constants in [`crate::limits`]. A producer that finds its queue full sheds
//! the message, logs a `tracing::warn!` and bumps a counter in
//! [`ShedCounters`]; nothing in this crate ever grows a queue to make a
//! producer succeed. Shedding a gossip event costs one message that will be
//! re-announced; growing the queue costs the process.
//!
//! # Peer discovery
//!
//! Static list only, with exponential reconnect backoff. No Kademlia, no
//! discv5, no mDNS. See `docs/DECISIONS.md` D6.

mod worker;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum_types::{Block, BlockHash, BlockHeader, Transaction};
use libp2p::gossipsub::{MessageAcceptance, MessageId};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::P2pConfig;
use crate::error::P2pError;
use crate::message::{GossipMessage, SyncRequest, SyncResponse};

/// Name of the handle-to-service command queue, used in log lines and in
/// [`P2pError::QueueFull`].
pub const COMMAND_QUEUE: &str = "p2p-command";

/// Name of the service-to-node event queue.
pub const EVENT_QUEUE: &str = "p2p-event";

// ---------------------------------------------------------------------------
// Shed counters
// ---------------------------------------------------------------------------

/// A snapshot of the load-shedding counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShedCounts {
    /// Events dropped because the node was not draining the event queue.
    pub events: u64,
    /// Commands dropped because the swarm task was not draining the command queue.
    pub commands: u64,
    /// Inbound sync requests dropped because too many were already parked.
    pub inbound_requests: u64,
    /// Outbound sync requests refused because too many were already in flight.
    pub outbound_requests: u64,
}

impl ShedCounts {
    /// Total messages shed across every queue.
    pub fn total(&self) -> u64 {
        self.events
            .saturating_add(self.commands)
            .saturating_add(self.inbound_requests)
            .saturating_add(self.outbound_requests)
    }
}

/// Live load-shedding counters, shared between the handle and the swarm task.
///
/// These are the observable half of the backpressure policy: a queue that is
/// full drops a message and increments one of these, so an operator can see
/// exactly how much was lost instead of watching resident memory climb.
#[derive(Debug, Default)]
pub struct ShedCounters {
    events: AtomicU64,
    commands: AtomicU64,
    inbound_requests: AtomicU64,
    outbound_requests: AtomicU64,
}

impl ShedCounters {
    /// Read all four counters.
    pub fn snapshot(&self) -> ShedCounts {
        ShedCounts {
            events: self.events.load(Ordering::Relaxed),
            commands: self.commands.load(Ordering::Relaxed),
            inbound_requests: self.inbound_requests.load(Ordering::Relaxed),
            outbound_requests: self.outbound_requests.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn shed_event(&self) -> u64 {
        self.events.fetch_add(1, Ordering::Relaxed).saturating_add(1)
    }

    pub(crate) fn shed_command(&self) -> u64 {
        self.commands.fetch_add(1, Ordering::Relaxed).saturating_add(1)
    }

    pub(crate) fn shed_inbound_request(&self) -> u64 {
        self.inbound_requests.fetch_add(1, Ordering::Relaxed).saturating_add(1)
    }

    pub(crate) fn shed_outbound_request(&self) -> u64 {
        self.outbound_requests.fetch_add(1, Ordering::Relaxed).saturating_add(1)
    }
}

// ---------------------------------------------------------------------------
// Public value types
// ---------------------------------------------------------------------------

/// Identifier for one inbound sync request, unique within a running service.
///
/// A local counter rather than libp2p's `InboundRequestId` so the node never
/// has to name a libp2p type, and so the id can be constructed in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(u64);

impl RequestId {
    /// Wrap a raw counter value.
    pub const fn new(value: u64) -> Self {
        RequestId(value)
    }

    /// The raw counter value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A peer's advertised tip, as returned by `GetTip`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TipInfo {
    /// Hash of the peer's best block.
    pub hash: BlockHash,
    /// Height of the peer's best block.
    pub height: u64,
    /// Cumulative work at that tip, big-endian `U256`.
    pub work: [u8; 32],
}

/// What the service knows about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The peer's libp2p identity.
    pub peer_id: PeerId,
    /// The address of the most recent connection to this peer.
    pub address: Option<Multiaddr>,
    /// Agent string from identify, once the exchange has completed.
    pub agent_version: Option<String>,
    /// Protocol version from identify.
    pub protocol_version: Option<String>,
    /// Last round-trip time in milliseconds, from ping. Integer milliseconds
    /// because no float may appear anywhere in this workspace.
    pub last_rtt_ms: Option<u64>,
    /// Whether this peer is in the configured static peer list.
    pub is_static: bool,
}

/// Something the service wants the node to know about.
#[derive(Debug)]
pub enum P2pEvent {
    /// A listen address is live. Emitted once per bound address, and the only
    /// way to learn the port when listening on `/tcp/0`.
    Listening {
        /// The bound address.
        address: Multiaddr,
    },
    /// A peer connection was established.
    PeerConnected {
        /// The peer.
        peer: PeerId,
        /// The address the connection uses.
        address: Multiaddr,
    },
    /// The last connection to a peer closed.
    PeerDisconnected {
        /// The peer.
        peer: PeerId,
    },
    /// A well-formed gossip payload arrived.
    ///
    /// It has **not** been forwarded: gossipsub is in explicit-validation mode,
    /// so the node must call [`P2pHandle::report_validation`] with this
    /// `msg_id` and `peer` exactly once, or the message is neither propagated
    /// nor scored.
    Gossip {
        /// The peer that forwarded the message, which is who gets scored.
        peer: PeerId,
        /// The content-addressed message id.
        msg_id: MessageId,
        /// The topic it arrived on.
        topic: String,
        /// The decoded payload.
        message: Box<GossipMessage>,
    },
    /// A gossip payload that could not be decoded, or arrived on the wrong
    /// topic. The service has already reported it as
    /// [`MessageAcceptance::Reject`]; this event is for the operator's log.
    InvalidGossip {
        /// The peer that forwarded it.
        peer: PeerId,
        /// The message id that was rejected.
        msg_id: MessageId,
        /// The topic it arrived on.
        topic: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A peer asked for headers, blocks or our tip. The node must answer via
    /// the [`SyncResponder`]; dropping it closes the request.
    InboundRequest {
        /// The peer asking.
        peer: PeerId,
        /// The request, already clamped to the sizes we will serve.
        request: SyncRequest,
        /// The one-shot channel for the answer.
        responder: SyncResponder,
    },
}

impl P2pEvent {
    /// A short static name for the variant, for logs and metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            P2pEvent::Listening { .. } => "Listening",
            P2pEvent::PeerConnected { .. } => "PeerConnected",
            P2pEvent::PeerDisconnected { .. } => "PeerDisconnected",
            P2pEvent::Gossip { .. } => "Gossip",
            P2pEvent::InvalidGossip { .. } => "InvalidGossip",
            P2pEvent::InboundRequest { .. } => "InboundRequest",
        }
    }
}

/// The reply channel for one inbound sync request.
///
/// The response is capped again by the service before it goes on the wire, so
/// a node bug cannot exceed the contract's 2000 headers or 64 blocks.
#[derive(Debug)]
pub struct SyncResponder {
    id: RequestId,
    peer: PeerId,
    commands: mpsc::Sender<P2pCommand>,
    counters: Arc<ShedCounters>,
    answered: bool,
}

impl SyncResponder {
    /// The libp2p id of the request being answered.
    pub fn request_id(&self) -> RequestId {
        self.id
    }

    /// The peer waiting for the answer.
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// Send the answer.
    ///
    /// Consumes the responder: a request is answered exactly once.
    pub fn respond(mut self, response: SyncResponse) -> Result<(), P2pError> {
        self.answered = true;
        send_command(
            &self.commands,
            &self.counters,
            P2pCommand::Respond { id: self.id, response: Box::new(response) },
        )
    }
}

impl Drop for SyncResponder {
    fn drop(&mut self) {
        if !self.answered {
            // Free the parked response channel; libp2p will report a
            // ResponseOmission to the peer rather than leaving it hanging.
            let _ = self.commands.try_send(P2pCommand::CancelResponse { id: self.id });
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// A message from a [`P2pHandle`] to the swarm task.
#[derive(Debug)]
pub(crate) enum P2pCommand {
    /// Publish a payload on the topic implied by its variant.
    Publish { message: Box<GossipMessage>, reply: oneshot::Sender<Result<MessageId, P2pError>> },
    /// Ask a peer for headers.
    RequestHeaders {
        peer: PeerId,
        locator: Vec<BlockHash>,
        stop: Option<BlockHash>,
        max: u32,
        reply: oneshot::Sender<Result<Vec<BlockHeader>, P2pError>>,
    },
    /// Ask a peer for block bodies.
    RequestBlocks {
        peer: PeerId,
        hashes: Vec<BlockHash>,
        reply: oneshot::Sender<Result<Vec<Block>, P2pError>>,
    },
    /// Ask a peer for its tip.
    RequestTip { peer: PeerId, reply: oneshot::Sender<Result<TipInfo, P2pError>> },
    /// Answer an inbound request.
    Respond { id: RequestId, response: Box<SyncResponse> },
    /// Abandon an inbound request without answering.
    CancelResponse { id: RequestId },
    /// Feed a validation verdict back into gossipsub scoring.
    ReportValidation { msg_id: MessageId, peer: PeerId, acceptance: MessageAcceptance },
    /// List connected peers.
    Peers { reply: oneshot::Sender<Vec<PeerInfo>> },
    /// Dial an address now, outside the static peer schedule.
    Dial { addr: Multiaddr, reply: oneshot::Sender<Result<(), P2pError>> },
    /// Stop the swarm task.
    Shutdown,
}

impl P2pCommand {
    fn kind(&self) -> &'static str {
        match self {
            P2pCommand::Publish { .. } => "Publish",
            P2pCommand::RequestHeaders { .. } => "RequestHeaders",
            P2pCommand::RequestBlocks { .. } => "RequestBlocks",
            P2pCommand::RequestTip { .. } => "RequestTip",
            P2pCommand::Respond { .. } => "Respond",
            P2pCommand::CancelResponse { .. } => "CancelResponse",
            P2pCommand::ReportValidation { .. } => "ReportValidation",
            P2pCommand::Peers { .. } => "Peers",
            P2pCommand::Dial { .. } => "Dial",
            P2pCommand::Shutdown => "Shutdown",
        }
    }
}

/// Try to enqueue a command, shedding with a warning and a counter when the
/// bounded queue is full.
fn send_command(
    tx: &mpsc::Sender<P2pCommand>,
    counters: &ShedCounters,
    cmd: P2pCommand,
) -> Result<(), P2pError> {
    let kind = cmd.kind();
    match tx.try_send(cmd) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            let shed = counters.shed_command();
            tracing::warn!(
                queue = COMMAND_QUEUE,
                command = kind,
                shed_total = shed,
                "command queue full; shedding rather than growing it"
            );
            Err(P2pError::QueueFull { queue: COMMAND_QUEUE })
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Err(P2pError::ServiceStopped),
    }
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct HandleInner {
    commands: mpsc::Sender<P2pCommand>,
    events: Mutex<Option<mpsc::Receiver<P2pEvent>>>,
    local_peer_id: PeerId,
    counters: Arc<ShedCounters>,
    shutdown: Arc<AtomicBool>,
}

impl Drop for HandleInner {
    fn drop(&mut self) {
        // The last handle going away is a shutdown request. The flag covers the
        // case where the command queue is momentarily full: the swarm task
        // checks it on every reconnect tick.
        self.shutdown.store(true, Ordering::Release);
        let _ = self.commands.try_send(P2pCommand::Shutdown);
    }
}

/// A cloneable handle to a running p2p service.
///
/// Every method is fallible and none of them blocks the caller waiting for
/// queue space: a full queue is a shed message and a typed error, never an
/// unbounded buffer.
#[derive(Debug, Clone)]
pub struct P2pHandle {
    inner: Arc<HandleInner>,
}

impl P2pHandle {
    /// This node's libp2p identity.
    pub fn local_peer_id(&self) -> PeerId {
        self.inner.local_peer_id
    }

    /// Read the load-shedding counters.
    pub fn shed_counts(&self) -> ShedCounts {
        self.inner.counters.snapshot()
    }

    /// Take the event stream.
    ///
    /// The stream is single-consumer by construction: two consumers would each
    /// see half the events, which is never what a caller wants. The second call
    /// returns [`P2pError::EventsAlreadyTaken`].
    pub fn events(&self) -> Result<mpsc::Receiver<P2pEvent>, P2pError> {
        let mut guard = self.inner.events.lock().unwrap_or_else(|e| e.into_inner());
        guard.take().ok_or(P2pError::EventsAlreadyTaken)
    }

    /// Publish a block on `ferrum/{chain_id}/blocks/v1`.
    pub async fn publish_block(&self, block: Block) -> Result<MessageId, P2pError> {
        self.publish(GossipMessage::NewBlock(Box::new(block))).await
    }

    /// Publish a transaction on `ferrum/{chain_id}/txs/v1`.
    pub async fn publish_tx(&self, tx: Transaction) -> Result<MessageId, P2pError> {
        self.publish(GossipMessage::NewTransaction(tx)).await
    }

    /// Announce a new tip on the blocks topic without sending the body.
    pub async fn publish_tip(&self, hash: BlockHash, height: u64) -> Result<MessageId, P2pError> {
        self.publish(GossipMessage::NewTip { hash, height }).await
    }

    /// Publish an already-built gossip payload.
    pub async fn publish(&self, message: GossipMessage) -> Result<MessageId, P2pError> {
        self.request(|reply| P2pCommand::Publish { message: Box::new(message), reply }).await
    }

    /// Ask `peer` for headers after the first locator entry it recognises.
    ///
    /// `max` is advisory: the answering node caps at 2000 headers and this node
    /// caps again on receipt.
    pub async fn request_headers(
        &self,
        peer: PeerId,
        locator: Vec<BlockHash>,
        stop: Option<BlockHash>,
        max: u32,
    ) -> Result<Vec<BlockHeader>, P2pError> {
        self.request(|reply| P2pCommand::RequestHeaders { peer, locator, stop, max, reply }).await
    }

    /// Ask `peer` for block bodies. At most 64 come back, whatever was asked.
    pub async fn request_blocks(
        &self,
        peer: PeerId,
        hashes: Vec<BlockHash>,
    ) -> Result<Vec<Block>, P2pError> {
        self.request(|reply| P2pCommand::RequestBlocks { peer, hashes, reply }).await
    }

    /// Ask `peer` for its current tip.
    pub async fn request_tip(&self, peer: PeerId) -> Result<TipInfo, P2pError> {
        self.request(|reply| P2pCommand::RequestTip { peer, reply }).await
    }

    /// List the currently connected peers.
    pub async fn peers(&self) -> Result<Vec<PeerInfo>, P2pError> {
        let (tx, rx) = oneshot::channel();
        send_command(&self.inner.commands, &self.inner.counters, P2pCommand::Peers { reply: tx })?;
        rx.await.map_err(|_| P2pError::ServiceStopped)
    }

    /// Feed a validation verdict back into gossipsub.
    ///
    /// This is the P4 hookup: [`MessageAcceptance::Reject`] lowers the sending
    /// peer's invalid-message score, which is the cheapest DoS defence
    /// available. Call it exactly once per [`P2pEvent::Gossip`]. Synchronous,
    /// so it can be called from a validation path that is not `async`.
    pub fn report_validation(
        &self,
        msg_id: MessageId,
        peer: PeerId,
        acceptance: MessageAcceptance,
    ) -> Result<(), P2pError> {
        send_command(
            &self.inner.commands,
            &self.inner.counters,
            P2pCommand::ReportValidation { msg_id, peer, acceptance },
        )
    }

    /// Dial an address immediately, outside the static peer schedule.
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), P2pError> {
        self.request(|reply| P2pCommand::Dial { addr, reply }).await
    }

    /// Ask the swarm task to stop. The task drains nothing: in-flight requests
    /// fail with [`P2pError::ServiceStopped`].
    pub fn shutdown(&self) -> Result<(), P2pError> {
        self.inner.shutdown.store(true, Ordering::Release);
        send_command(&self.inner.commands, &self.inner.counters, P2pCommand::Shutdown)
    }

    /// Send a command carrying a one-shot reply and await the answer.
    async fn request<T, F>(&self, make: F) -> Result<T, P2pError>
    where
        F: FnOnce(oneshot::Sender<Result<T, P2pError>>) -> P2pCommand,
    {
        let (tx, rx) = oneshot::channel();
        send_command(&self.inner.commands, &self.inner.counters, make(tx))?;
        rx.await.map_err(|_| P2pError::ServiceStopped)?
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Entry point for the networking stack.
#[derive(Debug)]
pub struct P2pService;

impl P2pService {
    /// Build the swarm, bind the listen addresses and spawn the event loop.
    ///
    /// Must be called from inside a tokio runtime: the TCP transport binds its
    /// listeners eagerly so that a bad listen address is an error here rather
    /// than a silent failure inside a detached task.
    ///
    /// Returns the handle and the task's [`JoinHandle`]. The task runs until
    /// [`P2pHandle::shutdown`] is called or every handle is dropped.
    pub fn spawn(config: P2pConfig) -> Result<(P2pHandle, JoinHandle<()>), P2pError> {
        worker::spawn(config)
    }
}

// ---------------------------------------------------------------------------
// Small pure helpers, kept public because the node reuses them
// ---------------------------------------------------------------------------

/// Exponential reconnect backoff for a static peer.
///
/// `failures = 0` yields `base`, and each further failure doubles it up to
/// `max`. There is deliberately no jitter: this crate takes no RNG dependency,
/// and a static peer list is a handful of addresses, not a herd large enough
/// for synchronised retries to matter.
pub fn reconnect_backoff(failures: u32, base: Duration, max: Duration) -> Duration {
    if failures == 0 {
        return base.min(max);
    }
    // Cap the exponent long before the shift overflows.
    let exponent = failures.min(20);
    let factor = 1u32.checked_shl(exponent).unwrap_or(u32::MAX);
    base.checked_mul(factor).unwrap_or(max).min(max)
}

/// Extract the `PeerId` from the `/p2p/...` component of a multiaddress.
///
/// A static peer entry that carries its peer id can be checked for liveness
/// directly; one that does not is tracked by the connection it was dialled on.
pub fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        Protocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_starts_at_base_and_doubles() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(300);
        assert_eq!(reconnect_backoff(0, base, max), Duration::from_secs(1));
        assert_eq!(reconnect_backoff(1, base, max), Duration::from_secs(2));
        assert_eq!(reconnect_backoff(2, base, max), Duration::from_secs(4));
        assert_eq!(reconnect_backoff(3, base, max), Duration::from_secs(8));
    }

    #[test]
    fn backoff_saturates_at_max_and_never_overflows() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(300);
        assert_eq!(reconnect_backoff(8, base, max), Duration::from_secs(256));
        assert_eq!(reconnect_backoff(9, base, max), max, "512 s is clamped to the ceiling");
        assert_eq!(reconnect_backoff(10, base, max), max);
        assert_eq!(reconnect_backoff(u32::MAX, base, max), max);
        assert_eq!(reconnect_backoff(u32::MAX, Duration::from_secs(3600), max), max);
    }

    #[test]
    fn backoff_is_monotonic() {
        let base = Duration::from_millis(500);
        let max = Duration::from_secs(300);
        let mut previous = Duration::ZERO;
        for failures in 0..40u32 {
            let d = reconnect_backoff(failures, base, max);
            assert!(d >= previous, "backoff went backwards at {failures}");
            assert!(d <= max);
            previous = d;
        }
    }

    #[test]
    fn a_base_above_max_is_clamped() {
        let d = reconnect_backoff(0, Duration::from_secs(10), Duration::from_secs(1));
        assert_eq!(d, Duration::from_secs(1));
    }

    #[test]
    fn peer_id_is_extracted_from_a_multiaddr_that_carries_one() {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer = keypair.public().to_peer_id();
        let addr: Multiaddr =
            format!("/ip4/127.0.0.1/tcp/8655/p2p/{peer}").parse().expect("multiaddr");
        assert_eq!(peer_id_from_multiaddr(&addr), Some(peer));
    }

    #[test]
    fn a_bare_multiaddr_has_no_peer_id() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8655".parse().expect("multiaddr");
        assert_eq!(peer_id_from_multiaddr(&addr), None);
    }

    #[test]
    fn shed_counters_start_at_zero_and_accumulate_per_queue() {
        let counters = ShedCounters::default();
        assert_eq!(counters.snapshot(), ShedCounts::default());
        assert_eq!(counters.snapshot().total(), 0);

        assert_eq!(counters.shed_event(), 1);
        assert_eq!(counters.shed_event(), 2);
        counters.shed_command();
        counters.shed_inbound_request();
        counters.shed_outbound_request();

        let snap = counters.snapshot();
        assert_eq!(snap.events, 2);
        assert_eq!(snap.commands, 1);
        assert_eq!(snap.inbound_requests, 1);
        assert_eq!(snap.outbound_requests, 1);
        assert_eq!(snap.total(), 5);
    }

    #[tokio::test]
    async fn a_full_command_queue_sheds_with_a_typed_error() {
        let (tx, _rx) = mpsc::channel::<P2pCommand>(1);
        let counters = ShedCounters::default();

        // Fill the single slot.
        send_command(&tx, &counters, P2pCommand::Shutdown).expect("first command fits");
        let err =
            send_command(&tx, &counters, P2pCommand::Shutdown).expect_err("a full queue must shed");

        assert!(matches!(err, P2pError::QueueFull { queue } if queue == COMMAND_QUEUE));
        assert_eq!(counters.snapshot().commands, 1);
    }

    #[tokio::test]
    async fn a_closed_command_queue_reports_the_service_as_stopped() {
        let (tx, rx) = mpsc::channel::<P2pCommand>(1);
        drop(rx);
        let err = send_command(&tx, &ShedCounters::default(), P2pCommand::Shutdown)
            .expect_err("a closed queue must report the service as stopped");
        assert!(matches!(err, P2pError::ServiceStopped));
    }

    #[tokio::test]
    async fn an_unanswered_responder_cancels_its_request_on_drop() {
        let (tx, mut rx) = mpsc::channel::<P2pCommand>(4);
        let responder = SyncResponder {
            id: RequestId::new(7),
            peer: PeerId::random(),
            commands: tx,
            counters: Arc::new(ShedCounters::default()),
            answered: false,
        };
        let id = responder.request_id();
        drop(responder);

        match rx.try_recv().expect("a cancel must be queued") {
            P2pCommand::CancelResponse { id: got } => assert_eq!(got, id),
            other => panic!("wrong command: {}", other.kind()),
        }
    }

    #[tokio::test]
    async fn answering_a_responder_sends_the_response_and_no_cancel() {
        let (tx, mut rx) = mpsc::channel::<P2pCommand>(4);
        let responder = SyncResponder {
            id: RequestId::new(7),
            peer: PeerId::random(),
            commands: tx,
            counters: Arc::new(ShedCounters::default()),
            answered: false,
        };
        responder.respond(SyncResponse::NotFound).expect("respond");

        match rx.try_recv().expect("a response must be queued") {
            P2pCommand::Respond { response, .. } => {
                assert_eq!(*response, SyncResponse::NotFound);
            }
            other => panic!("wrong command: {}", other.kind()),
        }
        assert!(rx.try_recv().is_err(), "no cancel may follow a response");
    }

    #[test]
    fn event_kinds_are_stable() {
        let ev = P2pEvent::PeerDisconnected { peer: PeerId::random() };
        assert_eq!(ev.kind(), "PeerDisconnected");
        let ev =
            P2pEvent::Listening { address: "/ip4/127.0.0.1/tcp/1".parse().expect("multiaddr") };
        assert_eq!(ev.kind(), "Listening");
    }

    #[test]
    fn command_kinds_are_stable() {
        assert_eq!(P2pCommand::Shutdown.kind(), "Shutdown");
        assert_eq!(P2pCommand::CancelResponse { id: RequestId::new(7) }.kind(), "CancelResponse");
    }
}
