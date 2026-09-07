//! Headers-first sync, exercised against a second in-process chain.
//!
//! The whole point of the [`SyncNetwork`] seam is that these are real syncs —
//! real headers, real bodies, real `apply_block` — with the socket replaced by
//! a function call. A libp2p round trip would add flakiness and seconds and
//! test nothing about the algorithm.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use ferrum_chain::ChainManager;
use ferrum_consensus::EngineRouter;
use ferrum_mempool::{Mempool, MempoolConfig};
use ferrum_p2p::{P2pError, PeerId, TipInfo};
use ferrum_storage::{Store, StoreConfig};
use ferrum_types::{Block, BlockHash, BlockHeader, ChainParams, CompactTarget, Network};
use parking_lot::Mutex;

use super::*;
use crate::miner::{Miner, resolve_payout};
use crate::node::keys::NodeKey;
use crate::relay::{Clock, FixedClock, Relay};
use crate::telemetry::NodeMetrics;

mod anchor;
mod future_time;
mod misbehaviour;
mod run_loop;

/// How many times a poll loop looks before it gives up.
///
/// A bounded attempt count rather than a wall-clock deadline: `Instant::now` is
/// disallowed workspace-wide by `clippy.toml`, and a test that reaches for a
/// clock is a test somebody will one day copy into code that must not have one.
const POLL_ATTEMPTS: usize = 1_000;

/// How long a poll loop waits between looks: 1000 x 20 ms is twenty seconds.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

// ---------------------------------------------------------------------------
// A node, in process
// ---------------------------------------------------------------------------

struct TestNode {
    chain: Arc<ChainManager>,
    relay: Arc<Relay>,
    clock: Arc<FixedClock>,
}

fn base_time() -> u64 {
    ChainParams::devnet().genesis_timestamp_ms + 120_000
}

fn test_node(seed: u8) -> TestNode {
    let params = ChainParams::devnet();
    let store = Arc::new(Store::open_in_memory(StoreConfig::default()).unwrap());
    let engines = Arc::new(EngineRouter::new(params.clone()).unwrap());
    let chain = Arc::new(ChainManager::open(store, params.clone(), engines).unwrap());
    chain.init_genesis().unwrap();
    let mempool = Arc::new(Mempool::new(MempoolConfig::new(params)));
    let clock = Arc::new(FixedClock::new(base_time()));
    let relay = Arc::new(Relay::new(
        Arc::clone(&chain),
        mempool,
        Arc::new(NodeMetrics::new()),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let _ = seed;
    TestNode { chain, relay, clock }
}

fn miner_for(node: &TestNode, seed: u8) -> Miner {
    let key = NodeKey::from_seed([seed; 32]);
    let payout = resolve_payout(None, &key, Network::Devnet).unwrap();
    Miner::new(Arc::clone(&node.relay), payout)
}

/// Mine `n` blocks onto `node`, advancing its clock one spacing per block.
fn mine_blocks(node: &TestNode, seed: u8, n: u64) {
    let miner = miner_for(node, seed);
    for i in 1..=n {
        node.clock.set(base_time() + i * 120_000);
        let (_, outcome) = miner.mine_and_submit(&AtomicBool::new(false)).unwrap().unwrap();
        assert!(outcome.should_announce(), "{outcome:?}");
    }
}

/// Seal a block on top of `node`'s tip with an explicit timestamp.
fn mine_at(node: &TestNode, seed: u8, timestamp_ms: u64) -> Block {
    let miner = miner_for(node, seed);
    let template = miner.build_template(timestamp_ms).unwrap();
    let engine = node.chain.engines().engine_for_height(template.height);
    engine.seal(template, &AtomicBool::new(false)).unwrap().unwrap()
}

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

/// How a served peer answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behaviour {
    Honest,
    /// Serves a header whose `bits` do not match the difficulty transition.
    ForgedHeader,
    /// Serves a block whose body does not match its header's merkle root.
    ForgedBody,
    /// Serves a block that was never asked for.
    UnrequestedBlock,
    /// Never answers.
    Silent,
}

/// A [`SyncNetwork`] backed by other in-process chains.
#[derive(Debug)]
struct Loopback {
    chains: BTreeMap<PeerId, Arc<ChainManager>>,
    behaviour: BTreeMap<PeerId, Behaviour>,
    disconnected: Mutex<Vec<(PeerId, String)>>,
}

impl Loopback {
    fn new() -> Self {
        Loopback {
            chains: BTreeMap::new(),
            behaviour: BTreeMap::new(),
            disconnected: Mutex::new(Vec::new()),
        }
    }

    fn with(mut self, peer: PeerId, chain: Arc<ChainManager>, behaviour: Behaviour) -> Self {
        self.chains.insert(peer, chain);
        self.behaviour.insert(peer, behaviour);
        self
    }

    fn behaviour(&self, peer: &PeerId) -> Behaviour {
        self.behaviour.get(peer).copied().unwrap_or(Behaviour::Silent)
    }

    fn disconnects(&self) -> Vec<PeerId> {
        self.disconnected.lock().iter().map(|(p, _)| *p).collect()
    }
}

#[async_trait::async_trait]
impl SyncNetwork for Loopback {
    async fn peers(&self) -> Vec<PeerId> {
        self.chains.keys().copied().collect()
    }

    async fn request_tip(&self, peer: PeerId) -> Result<TipInfo, NodeError> {
        if self.behaviour(&peer) == Behaviour::Silent {
            return Err(NodeError::P2p(P2pError::ServiceStopped));
        }
        let chain = self.chains.get(&peer).ok_or(NodeError::P2p(P2pError::ServiceStopped))?;
        let (hash, height) = chain.tip();
        let work = chain.total_work(&hash).unwrap_or(Work::ZERO);
        Ok(TipInfo { hash, height, work: work.to_be_bytes() })
    }

    async fn request_headers(
        &self,
        peer: PeerId,
        locator: Vec<BlockHash>,
        _stop: Option<BlockHash>,
        max: u32,
    ) -> Result<Vec<BlockHeader>, NodeError> {
        let chain = self.chains.get(&peer).ok_or(NodeError::P2p(P2pError::ServiceStopped))?;
        let cap = (max as usize).min(HEADERS_PER_REQUEST as usize);
        let mut headers = chain.headers_from(&locator, cap);
        if self.behaviour(&peer) == Behaviour::ForgedHeader
            && let Some(first) = headers.first_mut()
        {
            // A `bits` field that does not match `next_bits(parent)`. The
            // cheapest possible invalid header, and the one a real attacker
            // would try, because it costs no work to produce.
            first.bits = CompactTarget(0x1d00_ffff);
        }
        Ok(headers)
    }

    async fn request_blocks(
        &self,
        peer: PeerId,
        hashes: Vec<BlockHash>,
    ) -> Result<Vec<Block>, NodeError> {
        let chain = self.chains.get(&peer).ok_or(NodeError::P2p(P2pError::ServiceStopped))?;
        let mut out = Vec::new();
        for hash in hashes.iter().take(BLOCKS_PER_REQUEST) {
            if let Ok(Some(block)) = chain.store().get_block(hash) {
                out.push(block);
            }
        }
        match self.behaviour(&peer) {
            Behaviour::ForgedBody => {
                if let Some(block) = out.first_mut() {
                    // Drop a transaction: the header's merkle root no longer
                    // commits to the body.
                    block.txs.clear();
                }
            }
            Behaviour::UnrequestedBlock => {
                // Exactly as many blocks as were asked for, but the wrong one:
                // a peer that hopes we index by position rather than by hash.
                if let Ok(Some(genesis)) = chain.store().hash_at_height(0)
                    && let Ok(Some(block)) = chain.store().get_block(&genesis)
                    && !hashes.contains(&genesis)
                {
                    out.clear();
                    out.push(block);
                }
            }
            _ => {}
        }
        Ok(out)
    }

    fn disconnect(&self, peer: PeerId, reason: &str) {
        self.disconnected.lock().push((peer, reason.to_owned()));
    }
}

fn manager(local: &TestNode, network: Arc<Loopback>) -> SyncManager {
    SyncManager::new(Arc::clone(&local.relay), network, Arc::new(PeerBans::new()))
}

// ---------------------------------------------------------------------------
// Constants and small pieces
// ---------------------------------------------------------------------------

#[test]
fn the_wire_caps_match_the_contract() {
    // CONTRACT 10.2: 2000 headers, 64 blocks, server-side, regardless of ask.
    assert_eq!(HEADERS_PER_REQUEST, 2_000);
    assert_eq!(BLOCKS_PER_REQUEST, 64);
    assert_eq!(BODY_WINDOW_BLOCKS, BODY_WINDOW_REQUESTS * BLOCKS_PER_REQUEST);
    const { assert!(BODY_WINDOW_REQUESTS >= 1 && BODY_WINDOW_REQUESTS <= 16) };
    const { assert!(MAX_ROUNDS_PER_CALL > 0) };
}

#[test]
fn sync_rounds_report_progress_honestly() {
    assert!(!SyncRound::UpToDate.made_progress());
    assert!(!SyncRound::NoHeaders.made_progress());
    assert!(SyncRound::Progressed { headers: 1, blocks: 1 }.made_progress());
    assert!(!SyncStats::default().made_progress());
    assert!(SyncStats { rounds: 1, headers: 3, blocks: 0 }.made_progress());
}

#[tokio::test]
async fn blocking_reports_a_panicking_task_rather_than_unwinding() {
    let value = blocking(|| 7u32).await.unwrap();
    assert_eq!(value, 7);
    let e = blocking(|| panic!("boom")).await.unwrap_err();
    assert!(matches!(e, NodeError::Task(_)), "{e}");
}

// ---------------------------------------------------------------------------
// Fork choice inputs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_node_knows_when_it_is_behind() {
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 3);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::Honest));
    let sync = manager(&local, Arc::clone(&network));

    let tip = network.request_tip(peer).await.unwrap();
    assert!(sync.is_behind(&tip).unwrap());

    mine_blocks(&local, 1, 3);
    // Equal work is not "behind": fork choice needs strictly greater work.
    let tip = network.request_tip(peer).await.unwrap();
    assert!(!sync.is_behind(&tip).unwrap());
}

#[tokio::test]
async fn the_best_peer_is_the_one_with_the_most_work() {
    let local = test_node(1);
    let short = test_node(2);
    let long = test_node(3);
    mine_blocks(&short, 2, 2);
    mine_blocks(&long, 3, 9);

    let (a, b) = (PeerId::random(), PeerId::random());
    let network = Arc::new(
        Loopback::new()
            .with(a, Arc::clone(&short.chain), Behaviour::Honest)
            .with(b, Arc::clone(&long.chain), Behaviour::Honest),
    );
    let sync = manager(&local, network);
    let (best, tip) = sync.best_peer(&[a, b]).await.unwrap();
    assert_eq!(best, b);
    assert_eq!(tip.height, 9);
}

#[tokio::test]
async fn a_peer_that_is_not_ahead_is_never_chosen() {
    let local = test_node(1);
    mine_blocks(&local, 1, 4);
    let behind = test_node(2);
    mine_blocks(&behind, 2, 2);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&behind.chain), Behaviour::Honest));
    let sync = manager(&local, network);
    assert!(sync.best_peer(&[peer]).await.is_none());
    assert_eq!(sync.sync_to_best_peer(&[peer]).await.unwrap(), SyncStats::default());
}

#[tokio::test]
async fn a_silent_peer_is_skipped_not_banned() {
    let local = test_node(1);
    let peer = PeerId::random();
    let remote = test_node(2);
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::Silent));
    let sync = manager(&local, Arc::clone(&network));
    assert!(sync.best_peer(&[peer]).await.is_none());
    assert!(sync.bans().is_empty(), "not answering is not misbehaviour");
}

// ---------------------------------------------------------------------------
// The two-node sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_nodes_converge_by_headers_first_sync() {
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 12);
    let (remote_tip, remote_height) = remote.chain.tip();
    assert_eq!(remote_height, 12);

    // The local node's clock must be at least as late as the blocks it is
    // about to accept, or the future-time bound refuses them — which is
    // exactly the rule working.
    local.clock.set(base_time() + 12 * 120_000);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::Honest));
    let sync = manager(&local, network);

    let stats = sync.sync_to_best_peer(&[peer]).await.unwrap();
    assert_eq!(stats.blocks, 12, "every body should have connected");
    assert!(stats.headers >= 12);
    assert_eq!(local.chain.tip(), (remote_tip, remote_height));
    assert!(sync.bans().is_empty());
}

#[tokio::test]
async fn syncing_twice_is_a_no_op_the_second_time() {
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 5);
    local.clock.set(base_time() + 5 * 120_000);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::Honest));
    let sync = manager(&local, network);

    assert!(sync.sync_to_best_peer(&[peer]).await.unwrap().made_progress());
    let second = sync.sync_to_best_peer(&[peer]).await.unwrap();
    assert!(!second.made_progress());
    assert_eq!(local.chain.tip(), remote.chain.tip());
}

#[tokio::test]
async fn sync_continues_from_a_partial_chain() {
    // The locator's whole purpose: resume without re-downloading.
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 8);
    local.clock.set(base_time() + 8 * 120_000);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::Honest));
    let sync = manager(&local, Arc::clone(&network));

    // Connect the first three blocks by hand, then sync the rest.
    let mut prefix = Vec::new();
    for height in 1..=3u64 {
        let hash = remote.chain.store().hash_at_height(height).unwrap().unwrap();
        prefix.push(remote.chain.store().get_block(&hash).unwrap().unwrap());
    }
    assert_eq!(sync.connect_blocks(prefix).await.unwrap(), 3);
    assert_eq!(local.chain.tip().1, 3);

    let stats = sync.sync_to_best_peer(&[peer]).await.unwrap();
    assert_eq!(stats.blocks, 5, "only the missing five should be fetched");
    assert_eq!(local.chain.tip(), remote.chain.tip());
}

#[tokio::test]
async fn a_window_larger_than_one_request_is_split_across_peers() {
    let local = test_node(1);
    let remote = test_node(2);
    // More than one BLOCKS_PER_REQUEST chunk, so the round-robin is exercised.
    mine_blocks(&remote, 2, 70);
    local.clock.set(base_time() + 70 * 120_000);

    let (a, b) = (PeerId::random(), PeerId::random());
    let network = Arc::new(
        Loopback::new()
            .with(a, Arc::clone(&remote.chain), Behaviour::Honest)
            .with(b, Arc::clone(&remote.chain), Behaviour::Honest),
    );
    let sync = manager(&local, network);

    let stats = sync.sync_to_best_peer(&[a, b]).await.unwrap();
    assert_eq!(stats.blocks, 70);
    assert_eq!(local.chain.tip(), remote.chain.tip());
}

#[tokio::test]
async fn a_window_download_returns_blocks_in_the_order_asked_for() {
    let local = test_node(1);
    let remote = test_node(2);
    mine_blocks(&remote, 2, 6);

    let peer = PeerId::random();
    let network =
        Arc::new(Loopback::new().with(peer, Arc::clone(&remote.chain), Behaviour::Honest));
    let sync = manager(&local, network);

    let wanted: Vec<BlockHash> = (1..=6u64)
        .map(|h| remote.chain.store().hash_at_height(h).unwrap().unwrap())
        .collect();
    let served = sync.download_window(&[peer], peer, &wanted).await.unwrap();
    assert_eq!(served.len(), 6);
    for (entry, hash) in served.iter().zip(&wanted) {
        assert_eq!(ferrum_storage::header_hash(&entry.block.header), *hash);
        assert_eq!(entry.peer, peer, "attribution must survive the window");
    }
}