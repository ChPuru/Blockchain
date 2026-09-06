//! Two nodes, one process, real TCP on `/ip4/127.0.0.1/tcp/0`.
//!
//! These are the tests that would have caught every mistake the unit tests
//! cannot see: a transport that never negotiates, a topic mismatch, a
//! message-id function that makes every relay a fresh message, and a response
//! cap that is only enforced on the request side.
//!
//! Everything here is bounded by an explicit timeout. If a step cannot happen
//! the test fails with a message naming the step, rather than hanging.

use std::time::Duration;

use ferrum_p2p::{
    GossipMessage, Multiaddr, P2pConfig, P2pEvent, P2pHandle, P2pService, PeerId, SyncRequest,
    SyncResponse, limits,
};
use ferrum_types::{
    Amount, Block, BlockHash, BlockHeader, BlockSeal, ChainId, CompactTarget, Hash32, OutPoint,
    Script, Transaction, TxIn, TxOut, Txid,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// Long enough that a loaded Windows CI box still gets there, short enough that
/// a genuine hang fails the run rather than stalling it.
const STEP: Duration = Duration::from_secs(20);

/// How long one publish attempt is given to reach the other node before the
/// test publishes again. Gossipsub needs a subscription exchange first, and
/// there is no event that says "the remote has grafted us".
const PUBLISH_POLL: Duration = Duration::from_millis(250);

/// Publish attempts before the test gives up. 60 x 250 ms = 15 s of trying.
const PUBLISH_ATTEMPTS: u64 = 60;

struct Node {
    handle: P2pHandle,
    events: mpsc::Receiver<P2pEvent>,
    task: JoinHandle<()>,
}

impl Node {
    fn peer_id(&self) -> PeerId {
        self.handle.local_peer_id()
    }

    async fn stop(self) {
        self.handle.shutdown().expect("shutdown must be accepted");
        let _ = timeout(STEP, self.task).await;
    }
}

fn start(config: P2pConfig) -> Node {
    let (handle, task) = P2pService::spawn(config).expect("the service must start");
    let events = handle.events().expect("the event stream must be available");
    Node { handle, events, task }
}

fn listen_config() -> P2pConfig {
    P2pConfig::new(ChainId(3)).with_listen_addr("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
}

/// Wait for the first bound listen address. Listening on `/tcp/0` means this is
/// the only way to learn the port.
async fn listen_addr(node: &mut Node) -> Multiaddr {
    loop {
        let event = timeout(STEP, node.events.recv())
            .await
            .expect("a listen address must be reported")
            .expect("the event stream must stay open");
        if let P2pEvent::Listening { address } = event {
            return address;
        }
    }
}

/// Wait until `node` reports a connection to `expected`.
async fn await_connection(node: &mut Node, expected: PeerId) {
    loop {
        let event = timeout(STEP, node.events.recv())
            .await
            .expect("a connection must be established")
            .expect("the event stream must stay open");
        if let P2pEvent::PeerConnected { peer, .. } = event
            && peer == expected
        {
            return;
        }
    }
}

fn header(nonce: u64) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_hash: BlockHash::from_bytes([0x11; 32]),
        merkle_root: Hash32::from_bytes([0x22; 32]),
        timestamp_ms: 1_700_000_000_000,
        bits: CompactTarget(0x1d00_ffff),
        nonce,
    }
}

fn coinbase(nonce: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint::NULL,
            script_sig: Script::new(vec![0x01, nonce as u8]),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::from_grains(50 * 100_000_000),
            script_pubkey: Script::new(vec![0x51]),
        }],
        lock_time: 0,
    }
}

fn block(nonce: u64) -> Block {
    Block { header: header(nonce), txs: vec![coinbase(nonce)], seal: BlockSeal::POW }
}

fn transaction(seed: u32) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint { txid: Txid::from_bytes([0x33; 32]), vout: seed },
            script_sig: Script::new(vec![0x51]),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::from_grains(1_000),
            script_pubkey: Script::new(vec![0x52]),
        }],
        lock_time: 0,
    }
}

/// Bring up two connected nodes: `b` has `a` in its static peer list.
async fn connected_pair() -> (Node, Node) {
    let mut a = start(listen_config());
    let a_addr = listen_addr(&mut a).await;
    let a_peer = a.peer_id();

    let dial_addr: Multiaddr = format!("{a_addr}/p2p/{a_peer}").parse().expect("multiaddr");
    let mut b = start(listen_config().with_peer(dial_addr));
    let _ = listen_addr(&mut b).await;

    await_connection(&mut b, a_peer).await;
    await_connection(&mut a, b.peer_id()).await;
    (a, b)
}

// ---------------------------------------------------------------------------
// Gossip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_publishes_a_block_and_b_receives_it_over_real_tcp() {
    let (a, mut b) = connected_pair().await;

    let mut received = None;
    for nonce in 0..PUBLISH_ATTEMPTS {
        // Publishing can fail with InsufficientPeers until the subscription
        // exchange has happened; that is a retry, not a test failure. Each
        // attempt uses a different nonce so the content-addressed message id
        // differs and the duplicate cache cannot swallow it.
        let _ = a.handle.publish_block(block(nonce)).await;

        if let Ok(Some(P2pEvent::Gossip { peer, msg_id, topic, message })) =
            timeout(PUBLISH_POLL, b.events.recv()).await
        {
            assert_eq!(peer, a.peer_id(), "the forwarder must be node A");
            assert_eq!(topic, "ferrum/3/blocks/v1");
            // Feed the verdict back so gossipsub can forward and score.
            b.handle
                .report_validation(msg_id, peer, ferrum_p2p::MessageAcceptance::Accept)
                .expect("the verdict must be accepted");
            received = Some(*message);
            break;
        }
    }

    match received.expect("node B must receive a gossiped block") {
        GossipMessage::NewBlock(got) => {
            let nonce = got.header.nonce;
            assert!(nonce < PUBLISH_ATTEMPTS, "unexpected nonce {nonce}");
            assert_eq!(*got, block(nonce), "the block must survive the round trip byte for byte");
        }
        other => panic!("expected a block, got {}", other.kind()),
    }

    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn a_publishes_a_transaction_and_b_receives_it_on_the_tx_topic() {
    let (a, mut b) = connected_pair().await;

    let mut received = None;
    for seed in 0..PUBLISH_ATTEMPTS as u32 {
        let _ = a.handle.publish_tx(transaction(seed)).await;

        if let Ok(Some(P2pEvent::Gossip { topic, message, msg_id, peer })) =
            timeout(PUBLISH_POLL, b.events.recv()).await
        {
            assert_eq!(topic, "ferrum/3/txs/v1", "a transaction must arrive on the tx topic");
            b.handle
                .report_validation(msg_id, peer, ferrum_p2p::MessageAcceptance::Accept)
                .expect("the verdict must be accepted");
            received = Some(*message);
            break;
        }
    }

    match received.expect("node B must receive a gossiped transaction") {
        GossipMessage::NewTransaction(tx) => {
            let seed = tx.inputs[0].prev_out.vout;
            assert_eq!(tx, transaction(seed));
        }
        other => panic!("expected a transaction, got {}", other.kind()),
    }

    a.stop().await;
    b.stop().await;
}

// ---------------------------------------------------------------------------
// Sync request/response and the server-side caps
// ---------------------------------------------------------------------------

/// Answer every inbound request with far more than the caps allow.
///
/// This is the point of the test: the node deliberately over-answers, and the
/// service must still put no more than 2000 headers or 64 blocks on the wire.
fn serve_oversized(mut events: mpsc::Receiver<P2pEvent>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            if let P2pEvent::InboundRequest { request, responder, .. } = event {
                let response = match request {
                    SyncRequest::GetHeaders { .. } => SyncResponse::Headers(
                        (0..(limits::MAX_HEADERS_PER_RESPONSE as u64 + 500)).map(header).collect(),
                    ),
                    SyncRequest::GetBlocks { .. } => SyncResponse::Blocks(
                        (0..(limits::MAX_BLOCKS_PER_RESPONSE as u64 + 200)).map(block).collect(),
                    ),
                    SyncRequest::GetTip => SyncResponse::Tip {
                        hash: BlockHash::from_bytes([0x44; 32]),
                        height: 4_242,
                        work: [0x55; 32],
                    },
                };
                let _ = responder.respond(response);
            }
        }
    })
}

#[tokio::test]
async fn header_responses_are_capped_even_when_the_request_asks_for_more() {
    let (mut a, b) = connected_pair().await;
    let a_events = std::mem::replace(&mut a.events, mpsc::channel(1).1);
    let server = serve_oversized(a_events);

    let headers =
        timeout(STEP, b.handle.request_headers(a.peer_id(), vec![BlockHash::ZERO], None, u32::MAX))
            .await
            .expect("the request must complete")
            .expect("the request must succeed");

    assert_eq!(
        headers.len(),
        limits::MAX_HEADERS_PER_RESPONSE,
        "2000 headers is the cap regardless of the request"
    );
    assert_eq!(headers[0], header(0));

    server.abort();
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn block_responses_are_capped_even_when_the_request_asks_for_more() {
    let (mut a, b) = connected_pair().await;
    let a_events = std::mem::replace(&mut a.events, mpsc::channel(1).1);
    let server = serve_oversized(a_events);

    let wanted = vec![BlockHash::ZERO; limits::MAX_BLOCKS_PER_RESPONSE + 200];
    let blocks = timeout(STEP, b.handle.request_blocks(a.peer_id(), wanted))
        .await
        .expect("the request must complete")
        .expect("the request must succeed");

    assert_eq!(
        blocks.len(),
        limits::MAX_BLOCKS_PER_RESPONSE,
        "64 blocks is the cap regardless of the request"
    );
    assert_eq!(blocks[0], block(0));

    server.abort();
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn a_tip_query_round_trips_over_the_sync_protocol() {
    let (mut a, b) = connected_pair().await;
    let a_events = std::mem::replace(&mut a.events, mpsc::channel(1).1);
    let server = serve_oversized(a_events);

    let tip = timeout(STEP, b.handle.request_tip(a.peer_id()))
        .await
        .expect("the request must complete")
        .expect("the request must succeed");

    assert_eq!(tip.hash, BlockHash::from_bytes([0x44; 32]));
    assert_eq!(tip.height, 4_242);
    assert_eq!(tip.work, [0x55; 32]);

    server.abort();
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn an_abandoned_request_fails_the_caller_rather_than_hanging() {
    let (mut a, b) = connected_pair().await;

    // Node A drops every responder without answering.
    let mut a_events = std::mem::replace(&mut a.events, mpsc::channel(1).1);
    let server = tokio::spawn(async move {
        while let Some(event) = a_events.recv().await {
            if let P2pEvent::InboundRequest { responder, .. } = event {
                drop(responder);
            }
        }
    });

    let result =
        timeout(STEP, b.handle.request_tip(a.peer_id())).await.expect("the request must not hang");
    assert!(result.is_err(), "an unanswered request must surface as an error");

    server.abort();
    a.stop().await;
    b.stop().await;
}

// ---------------------------------------------------------------------------
// Peer bookkeeping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn each_node_lists_the_other_as_a_peer() {
    let (a, b) = connected_pair().await;

    let from_b = timeout(STEP, b.handle.peers())
        .await
        .expect("peers must answer")
        .expect("peers must succeed");
    assert_eq!(from_b.len(), 1);
    assert_eq!(from_b[0].peer_id, a.peer_id());
    assert!(from_b[0].is_static, "A is in B's configured static peer list");
    assert!(from_b[0].address.is_some());

    let from_a = timeout(STEP, a.handle.peers())
        .await
        .expect("peers must answer")
        .expect("peers must succeed");
    assert_eq!(from_a.len(), 1);
    assert_eq!(from_a[0].peer_id, b.peer_id());
    assert!(!from_a[0].is_static, "B dialled in; A has no static peers configured");

    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn nothing_is_shed_on_an_idle_pair() {
    let (a, b) = connected_pair().await;
    assert_eq!(a.handle.shed_counts().total(), 0);
    assert_eq!(b.handle.shed_counts().total(), 0);
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn nodes_on_different_chains_connect_but_never_exchange_gossip() {
    // Same transport, different topic names: chain 1 and chain 2 can complete a
    // Noise handshake and then have nothing to say to each other.
    let mut a = start(
        P2pConfig::new(ChainId(1))
            .with_listen_addr("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr")),
    );
    let a_addr = listen_addr(&mut a).await;
    let a_peer = a.peer_id();

    let dial: Multiaddr = format!("{a_addr}/p2p/{a_peer}").parse().expect("multiaddr");
    let mut b = start(
        P2pConfig::new(ChainId(2))
            .with_listen_addr("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
            .with_peer(dial),
    );
    let _ = listen_addr(&mut b).await;
    await_connection(&mut b, a_peer).await;

    for nonce in 0..8u64 {
        let _ = a.handle.publish_block(block(nonce)).await;
    }

    // Drain for a moment: nothing that arrives may be a gossip payload.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(200), b.events.recv()).await {
            Ok(Some(P2pEvent::Gossip { .. })) => {
                panic!("a chain-2 node must never receive chain-1 gossip")
            }
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => continue,
        }
    }

    a.stop().await;
    b.stop().await;
}
