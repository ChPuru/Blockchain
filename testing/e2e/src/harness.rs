//! [`TestNet`]: a multi-node Ferrum devnet, in this process, over real TCP.
//!
//! # The shape of a test
//!
//! Spawn, wait for the mesh, drive some blocks, wait for a property, assert.
//! Every wait takes an explicit `Duration` and every failure carries
//! [`TestNet::describe`], so a red CI run says *which* node was where.
//!
//! # Why the harness mines instead of the node
//!
//! [`ferrum_node::Miner`] is started by `chaind --mine` and grinds continuously.
//! That is right for a node and wrong for a test: "mine six blocks on this side
//! of the partition and two on that one" is only an assertion if the harness
//! decides when sealing stops. So every node here starts with mining off and
//! the harness drives [`ferrum_node::Miner::mine_and_submit`] directly — the
//! same call the node's own mining loop makes, through the same
//! [`ferrum_node::Relay`], followed by the same gossip announcement.
//!
//! # Why partitioning restarts nodes
//!
//! `ferrum-p2p` has no "disconnect this peer" command, by design: peers come
//! from a static list, so the way to stop talking to one is to stop listing it.
//! `devnet/partition.sh` therefore restarts each node with a narrower `--peer`
//! set, and so does [`TestNet::partition`]. It is slower than dropping a socket
//! and it is the same code path an operator uses, which is the point.

pub mod config;
pub mod lifecycle;
pub mod mining;
pub mod ports;
pub mod report;
pub mod spend;

use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ferrum_consensus::Work;
use ferrum_crypto::{Address, SecretKey};
use ferrum_node::{Miner, Node};
use ferrum_types::{BlockHash, ChainParams, Hash32, Script};
use tempfile::TempDir;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// How long a poll loop waits between looks.
///
/// Fifty milliseconds is short enough that a convergence that takes 300 ms is
/// not rounded up to a second, and long enough that a sixty-second budget is
/// twelve hundred looks rather than a spin loop.
pub const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A generous default for "the network should have settled by now".
///
/// Sync polls every [`ferrum_node::sync::SYNC_POLL_INTERVAL`] (five seconds),
/// so anything that has to fall back from gossip to sync needs several of those
/// before it is fair to call it a failure.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);

/// How many nodes this process runs at once, across every test in the binary.
///
/// `libtest` runs the tests in one binary on as many threads as the machine has
/// cores, so without a ceiling a suite of ten networks starts forty nodes at
/// once: forty `redb` stores, forty swarms, forty gossipsub heartbeats. What
/// breaks first is not memory but *time* — the mesh takes long enough to form
/// that a generous timeout expires, and the suite fails for a reason that has
/// nothing to do with the chain.
///
/// Eight is enough for two four-node networks to overlap, which keeps the suite
/// wall-clock honest, and small enough that a laptop and a CI runner behave the
/// same way. Networks queue for their nodes rather than competing for them.
pub const MAX_CONCURRENT_NODES: usize = 8;

/// The process-wide budget [`MAX_CONCURRENT_NODES`] describes.
static NODE_BUDGET: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_NODES)));

/// A node in the network, running or not.
///
/// The identity — data directory, p2p port, node key — outlives any particular
/// [`ferrum_node::Node`] instance, which is what makes
/// [`TestNet::restart`] a restart rather than a new node.
struct NodeSlot {
    /// Index in [`TestNet::nodes`], and the node's name in every diagnostic.
    index: usize,
    /// `<root>/node<i>`, preserved across a kill.
    datadir: PathBuf,
    /// The reserved loopback port this node always listens on.
    p2p_port: u16,
    /// The indices this node currently lists as static peers.
    peers: Vec<usize>,
    /// Where this node's coinbases pay, derived from `<datadir>/node.key`.
    address: Address,
    /// The locking script of [`NodeSlot::address`].
    script: Script,
    /// The key that unlocks it, so the harness can spend what the node mined.
    secret: SecretKey,
    /// `None` while the node is killed.
    running: Option<RunningNode>,
}

/// The parts of a running node the harness holds on to.
struct RunningNode {
    /// The node itself.
    node: Node,
    /// A miner over the node's relay, kept across calls so its extra-nonce
    /// keeps advancing and two rounds at one height cannot collide.
    miner: Arc<Miner>,
}

/// A devnet of `n` in-process nodes on loopback.
///
/// Field order is load-bearing: `root` is declared **last** so that the
/// temporary directory is removed after the nodes that live in it, not before.
pub struct TestNet {
    /// The nodes, indexed from zero.
    nodes: Vec<NodeSlot>,
    /// The devnet parameters every node validates against.
    params: ChainParams,
    /// One permit per node, from the process-wide [`NODE_BUDGET`], released
    /// when the network is dropped.
    permits: Vec<OwnedSemaphorePermit>,
    /// The temporary directory holding every node's data directory.
    root: TempDir,
}

impl std::fmt::Debug for TestNet {
    /// Compact and side-effect free: the interesting state needs `await`, and
    /// [`TestNet::describe`] is the thing to print when a test fails.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestNet")
            .field("nodes", &self.nodes.len())
            .field("running", &self.nodes.iter().filter(|n| n.running.is_some()).count())
            .field("network", &self.params.network)
            .field("root", &self.root.path())
            .finish()
    }
}

impl TestNet {
    /// Start `count` devnet nodes on ephemeral ports, wired as a full mesh.
    ///
    /// Every node gets its own temporary data directory, its own node key —
    /// and therefore its own libp2p identity and its own payout address — and
    /// the other `count - 1` nodes as static peers. Mining is off; the harness
    /// drives it.
    ///
    /// This returns as soon as every node's listeners are bound. It does **not**
    /// wait for the mesh: call [`TestNet::await_peers`] when a test needs
    /// gossip to work on its first block.
    ///
    /// # Errors
    ///
    /// When a port cannot be reserved, a data directory cannot be created, or a
    /// node will not start.
    pub async fn spawn(count: usize) -> Result<Self> {
        if count == 0 {
            bail!("a TestNet needs at least one node");
        }
        if count > MAX_CONCURRENT_NODES {
            bail!(
                "a network of {count} nodes exceeds this process's budget of \
                 {MAX_CONCURRENT_NODES}; raise MAX_CONCURRENT_NODES deliberately rather than \
                 letting the network wait for itself"
            );
        }
        config::init_logging();

        // Queue for the node budget before anything is created, so a suite of
        // networks takes turns instead of starving each other's mesh.
        let mut permits = Vec::with_capacity(count);
        for _ in 0..count {
            permits.push(node_permit().await?);
        }

        let root = tempfile::Builder::new()
            .prefix("ferrum-e2e-")
            .tempdir()
            .context("creating the temporary root for the network")?;
        let params = ChainParams::devnet();

        let mut nodes = Vec::with_capacity(count);
        for index in 0..count {
            let datadir = root.path().join(format!("node{index}"));
            std::fs::create_dir_all(&datadir)
                .with_context(|| format!("creating the data directory {}", datadir.display()))?;
            let port = ports::reserve_port()
                .with_context(|| format!("reserving a p2p port for node {index}"))?;
            let peers = (0..count).filter(|j| *j != index).collect();
            nodes.push(NodeSlot::new(index, datadir, port, peers, params.network)?);
        }

        let mut net = TestNet { nodes, params, permits, root };
        for index in 0..count {
            net.start_slot(index).await?;
        }
        Ok(net)
    }

    /// Add one more node, peered to every node already in the network.
    ///
    /// Only the joiner lists the others: an established connection carries
    /// gossip both ways, so nobody has to be restarted for a new node to be
    /// heard. That is the property `late_joiner_syncs_from_genesis` checks —
    /// a chain that needs a manual step to join is a chain nobody joins.
    ///
    /// Returns the new node's index.
    ///
    /// # Errors
    ///
    /// As [`TestNet::spawn`].
    pub async fn join(&mut self) -> Result<usize> {
        let index = self.nodes.len();
        if index >= MAX_CONCURRENT_NODES {
            bail!("joining a {index}-node network exceeds the budget of {MAX_CONCURRENT_NODES}");
        }
        self.permits.push(node_permit().await?);
        let datadir = self.root.path().join(format!("node{index}"));
        std::fs::create_dir_all(&datadir)
            .with_context(|| format!("creating the data directory {}", datadir.display()))?;
        let port = ports::reserve_port()
            .with_context(|| format!("reserving a p2p port for node {index}"))?;
        let peers = (0..index).collect();
        self.nodes.push(NodeSlot::new(index, datadir, port, peers, self.params.network)?);
        self.start_slot(index).await?;
        Ok(index)
    }

    /// How many nodes the network has, running or not.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the network has no nodes. Never true for a network from
    /// [`TestNet::spawn`], which refuses a count of zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The consensus parameters every node in this network validates against.
    #[must_use]
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// The running node at `index`.
    ///
    /// # Errors
    ///
    /// When `index` is out of range or the node is currently killed.
    pub fn node(&self, index: usize) -> Result<&Node> {
        let slot = self.slot(index)?;
        slot.running.as_ref().map(|r| &r.node).ok_or_else(|| anyhow!("node {index} is not running"))
    }

    /// The address node `index` pays its coinbases to.
    ///
    /// # Errors
    ///
    /// When `index` is out of range.
    pub fn address(&self, index: usize) -> Result<Address> {
        Ok(self.slot(index)?.address)
    }

    /// The active tip of node `index`.
    ///
    /// # Errors
    ///
    /// When the node is out of range or not running.
    pub fn tip(&self, index: usize) -> Result<BlockHash> {
        Ok(self.node(index)?.chain().tip().0)
    }

    /// The active height of node `index`.
    ///
    /// # Errors
    ///
    /// As [`TestNet::tip`].
    pub fn height(&self, index: usize) -> Result<u64> {
        Ok(self.node(index)?.chain().tip().1)
    }

    /// Cumulative work at node `index`'s tip — what fork choice actually
    /// compares, and the reason a partition test never asserts on height.
    ///
    /// # Errors
    ///
    /// As [`TestNet::tip`], or when the tip has no stored header.
    pub fn total_work(&self, index: usize) -> Result<Work> {
        let node = self.node(index)?;
        let (hash, _) = node.chain().tip();
        node.chain()
            .total_work(&hash)
            .ok_or_else(|| anyhow!("node {index} has no work recorded for its own tip {hash}"))
    }

    /// The Merkle root over node `index`'s whole UTXO set (CONTRACT §7).
    ///
    /// Two nodes agreeing on a tip hash have agreed on a header chain. Two
    /// nodes agreeing on a state root have agreed on every coin, which is the
    /// assertion a reorg test owes its reader.
    ///
    /// # Errors
    ///
    /// As [`TestNet::tip`], or on a storage failure.
    pub fn state_root(&self, index: usize) -> Result<Hash32> {
        self.node(index)?
            .store()
            .state_root()
            .with_context(|| format!("reading node {index}'s state root"))
    }

    /// Wait until every running node reports the same tip, and return it.
    ///
    /// # Errors
    ///
    /// After `timeout`, with [`TestNet::describe`] in the message.
    pub async fn await_convergence(&self, timeout: Duration) -> Result<BlockHash> {
        let poll = async {
            loop {
                if let Some(tip) = self.converged_tip() {
                    return tip;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        };
        match tokio::time::timeout(timeout, poll).await {
            Ok(tip) => Ok(tip),
            Err(_) => Err(anyhow!(
                "the network did not converge within {timeout:?}\n{}",
                self.describe().await
            )),
        }
    }

    /// The tip every running node shares, or `None` while they disagree.
    ///
    /// Separate from [`TestNet::await_convergence`] so a test can assert that a
    /// partitioned network is *not* converged without waiting for a timeout.
    #[must_use]
    pub fn converged_tip(&self) -> Option<BlockHash> {
        let mut tips = self
            .nodes
            .iter()
            .filter_map(|slot| slot.running.as_ref().map(|running| running.node.chain().tip().0));
        let first = tips.next()?;
        tips.all(|tip| tip == first).then_some(first)
    }

    /// Wait until node `index` is at `height` or beyond.
    ///
    /// # Errors
    ///
    /// After `timeout`, with [`TestNet::describe`] in the message.
    pub async fn await_height(&self, index: usize, height: u64, timeout: Duration) -> Result<u64> {
        let poll = async {
            loop {
                if let Ok(now) = self.height(index)
                    && now >= height
                {
                    return now;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        };
        match tokio::time::timeout(timeout, poll).await {
            Ok(now) => Ok(now),
            Err(_) => Err(anyhow!(
                "node {index} did not reach height {height} within {timeout:?}\n{}",
                self.describe().await
            )),
        }
    }

    /// Wait until every running node has at least `count` connected peers.
    ///
    /// Gossipsub only forwards to peers already in the mesh, so a test that
    /// mines its first block before the mesh exists is testing sync, not
    /// gossip. Both work; knowing which one is being tested is the point.
    ///
    /// # Errors
    ///
    /// After `timeout`, with [`TestNet::describe`] in the message.
    pub async fn await_peer_count(&self, count: usize, timeout: Duration) -> Result<()> {
        let poll = async {
            loop {
                if self.every_node_has_peers(count).await {
                    return;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        };
        match tokio::time::timeout(timeout, poll).await {
            Ok(()) => Ok(()),
            Err(_) => Err(anyhow!(
                "not every node reached {count} peers within {timeout:?}\n{}",
                self.describe().await
            )),
        }
    }

    /// Wait until every running node is connected to every other one.
    ///
    /// # Errors
    ///
    /// As [`TestNet::await_peer_count`].
    pub async fn await_peers(&self, timeout: Duration) -> Result<()> {
        let running = self.nodes.iter().filter(|slot| slot.running.is_some()).count();
        self.await_peer_count(running.saturating_sub(1), timeout).await
    }

    /// Stop every node cleanly and remove the temporary directories.
    ///
    /// Tests call this rather than dropping the network: a graceful stop closes
    /// every `redb` handle before the temporary directory is removed, and
    /// Windows will not delete a file that is still open.
    ///
    /// # Errors
    ///
    /// When a node's final store flush fails, which is the one shutdown failure
    /// worth reporting.
    pub async fn shutdown(mut self) -> Result<()> {
        for index in 0..self.nodes.len() {
            if let Some(running) = self.nodes[index].running.take() {
                drop(running.miner);
                running
                    .node
                    .shutdown()
                    .await
                    .with_context(|| format!("shutting node {index} down"))?;
            }
        }
        Ok(())
    }

    /// Whether every running node reports at least `count` peers.
    async fn every_node_has_peers(&self, count: usize) -> bool {
        for slot in &self.nodes {
            let Some(running) = slot.running.as_ref() else { continue };
            let Some(handle) = running.node.p2p() else { return false };
            match handle.peers().await {
                Ok(peers) if peers.len() >= count => {}
                _ => return false,
            }
        }
        true
    }

    /// The slot at `index`.
    fn slot(&self, index: usize) -> Result<&NodeSlot> {
        self.nodes
            .get(index)
            .ok_or_else(|| anyhow!("node {index} does not exist; the network has {}", self.len()))
    }

    /// The running node and its miner at `index`.
    fn running(&self, index: usize) -> Result<&RunningNode> {
        self.slot(index)?.running.as_ref().ok_or_else(|| anyhow!("node {index} is not running"))
    }
}

/// Take one node's worth of the process-wide budget.
///
/// # Errors
///
/// Only when the semaphore has been closed, which never happens: it is a
/// `static` that lives as long as the process.
async fn node_permit() -> Result<OwnedSemaphorePermit> {
    Arc::clone(&NODE_BUDGET)
        .acquire_owned()
        .await
        .context("the node budget was closed, which a static semaphore never is")
}

impl Drop for TestNet {
    /// Cancel whatever is still running, so the temporary directory has a
    /// chance of being removable.
    ///
    /// A best-effort backstop for a test that panicked before
    /// [`TestNet::shutdown`]: cancellation is synchronous, but the tasks it
    /// wakes are not, so a panicking test may still leave a directory behind.
    /// That is a cosmetic cost paid only on a failure that is already loud.
    fn drop(&mut self) {
        for slot in &mut self.nodes {
            if let Some(running) = slot.running.take() {
                running.node.cancel_token().cancel();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_network_of_one_starts_at_genesis_and_mines() {
        let net = TestNet::spawn(1).await.unwrap();
        assert_eq!(net.len(), 1);
        assert!(!net.is_empty());
        assert_eq!(net.height(0).unwrap(), 0);
        assert_eq!(net.converged_tip(), Some(net.tip(0).unwrap()));

        let before = net.state_root(0).unwrap();
        net.mine_blocks(0, 3).await.unwrap();
        assert_eq!(net.height(0).unwrap(), 3);
        assert_ne!(net.state_root(0).unwrap(), before, "three coinbases changed the UTXO set");
        assert!(net.total_work(0).unwrap() > Work::ZERO);

        net.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn asking_for_a_node_that_does_not_exist_is_an_error_not_a_panic() {
        let net = TestNet::spawn(1).await.unwrap();
        assert!(net.node(7).is_err());
        assert!(net.tip(7).is_err());
        assert!(net.height(7).is_err());
        assert!(net.state_root(7).is_err());
        net.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_network_with_no_nodes_is_refused() {
        assert!(TestNet::spawn(0).await.is_err());
    }
}
