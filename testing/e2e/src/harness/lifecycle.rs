//! Starting, killing, restarting and rewiring nodes.
//!
//! # What "kill" means in one process
//!
//! `devnet/kill.sh` sends SIGKILL. Nothing inside a process can reproduce that
//! exactly, and pretending otherwise would be the worst kind of test. What
//! [`TestNet::kill`] does instead is the closest honest approximation: it
//! cancels the node's [`tokio_util::sync::CancellationToken`] and drops the
//! [`ferrum_node::Node`] **without calling [`ferrum_node::Node::shutdown`]**,
//! so no task is joined, no listener is drained and — the part that matters —
//! **the store is never flushed**.
//!
//! That leaves exactly the property a crash test is about: whatever survives is
//! what `redb` had already committed, and `ferrum-storage` writes the head
//! pointer last inside each block's single write transaction (CONTRACT §7). A
//! node that lost a block across this kill would have lost it across a real one
//! too.
//!
//! What is *not* covered here is a kill landing in the middle of a write. That
//! needs a real process boundary, and it has its own gate: the fifty
//! kill-mid-write restarts of M3 in `ferrum-storage`.
//!
//! # Why a start is retried
//!
//! A restart reuses the node's port and its data directory, and neither is
//! released the instant the previous instance is dropped: the `redb` file lock
//! goes when the last `Arc<Store>` does, which is when the last cancelled task
//! notices. Waiting for the port and retrying the start turns a millisecond of
//! operating-system latency into a wait instead of a flake.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use ferrum_node::config::NODE_KEY_FILE;
use ferrum_node::{Miner, Node, NodeKey, Payout};
use ferrum_types::Network;

use crate::harness::{NodeSlot, RunningNode, TestNet, config, ports};

/// How many times a node start is retried before the failure is reported.
pub const START_ATTEMPTS: usize = 40;

/// How long a retry waits before trying again: 40 × 250 ms is ten seconds.
pub const START_RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// How long a start waits for the previous instance's port to be released.
pub const PORT_RELEASE_TIMEOUT: Duration = Duration::from_secs(15);

impl NodeSlot {
    /// Create a slot and its identity.
    ///
    /// The node key is generated here rather than left to the first
    /// [`Node::start`], because the harness needs the payout address and the
    /// spending key before any node exists — a test spends what a node mined,
    /// and it must be able to build that transaction from outside the node.
    pub(super) fn new(
        index: usize,
        datadir: PathBuf,
        p2p_port: u16,
        peers: Vec<usize>,
        network: Network,
    ) -> Result<Self> {
        let key = NodeKey::load_or_create(&datadir.join(NODE_KEY_FILE))
            .with_context(|| format!("creating the node key for node {index}"))?;
        let address = key
            .mining_address(network)
            .with_context(|| format!("deriving node {index}'s payout address"))?;
        let secret =
            key.mining_secret().with_context(|| format!("deriving node {index}'s payout key"))?;
        let script = address.script_pubkey();
        Ok(NodeSlot { index, datadir, p2p_port, peers, address, script, secret, running: None })
    }

    /// The payout this node's coinbases pay, in the shape the miner wants.
    pub(super) fn payout(&self) -> Payout {
        Payout { address: self.address, script: self.script.clone(), explicit: false }
    }
}

impl TestNet {
    /// Kill node `index`: cancel it and drop it without a flush.
    ///
    /// Killing a node that is already down is a no-op, so a test may call this
    /// twice without guarding.
    ///
    /// # Errors
    ///
    /// When `index` is out of range.
    pub async fn kill(&mut self, index: usize) -> Result<()> {
        let count = self.nodes.len();
        let slot = self
            .nodes
            .get_mut(index)
            .ok_or_else(|| anyhow!("node {index} does not exist; the network has {count}"))?;
        let port = slot.p2p_port;
        let Some(running) = slot.running.take() else {
            return Ok(());
        };

        // Cancel first, then drop. Every task selects on this token, so the
        // last `Arc<Store>` — and with it the `redb` file lock and the p2p
        // listener — goes as soon as they notice. No `shutdown()`, and so no
        // flush: what survives is what was already committed.
        running.node.cancel_token().cancel();
        drop(running);

        // Not an assertion: libp2p may bind where this probe could not, and a
        // start that still fails is retried anyway.
        let _ = ports::await_port_free(port, PORT_RELEASE_TIMEOUT).await;
        Ok(())
    }

    /// Start node `index` again on its own port, with its own data directory.
    ///
    /// The node key survives, so the restarted node keeps its libp2p identity
    /// and its payout address, and its peers reconnect to the address they
    /// already have.
    ///
    /// # Errors
    ///
    /// When `index` is out of range, or when the node will not start within
    /// [`START_ATTEMPTS`] attempts.
    pub async fn restart(&mut self, index: usize) -> Result<()> {
        self.kill(index).await?;
        self.start_slot(index).await
    }

    /// Split the network in two: `a` may talk to `a`, `b` to `b`, and neither
    /// across.
    ///
    /// Every node is restarted with a narrower static peer list — the same
    /// mechanism `devnet/partition.sh` uses, and the reason it needs no
    /// firewall rules and no privileges. Nodes that were killed stay killed;
    /// their peer list is still updated, so a later
    /// [`TestNet::restart`] honours the split.
    ///
    /// # Errors
    ///
    /// When the two sides do not partition the network — see
    /// [`config::partition_groups`] — or when a node will not restart.
    pub async fn partition(&mut self, a: &[usize], b: &[usize]) -> Result<()> {
        let group = config::partition_groups(self.nodes.len(), a, b)?;
        self.rewire(config::peers_within(&group)).await
    }

    /// Restore the full mesh.
    ///
    /// # Errors
    ///
    /// When a node will not restart.
    pub async fn heal(&mut self) -> Result<()> {
        let peers = config::peers_full(self.nodes.len());
        self.rewire(peers).await
    }

    /// Bring every node down, give it a new peer list, and bring back up
    /// exactly the ones that were up.
    ///
    /// All the way down before any of them comes up: a node started against a
    /// peer that has not been rewired yet would form the connection the caller
    /// just asked to remove.
    async fn rewire(&mut self, peers: Vec<Vec<usize>>) -> Result<()> {
        ensure!(
            config::peers_are_valid(self.nodes.len(), &peers),
            "a rewiring must give every node a list of distinct, existing, other nodes: {peers:?}"
        );
        let was_running: Vec<bool> = self.nodes.iter().map(|slot| slot.running.is_some()).collect();

        for index in 0..self.nodes.len() {
            self.kill(index).await?;
        }
        for (index, list) in peers.into_iter().enumerate() {
            self.nodes[index].peers = list;
        }
        for (index, up) in was_running.into_iter().enumerate() {
            if up {
                self.start_slot(index).await?;
            }
        }
        Ok(())
    }

    /// Start the node in slot `index`, retrying while its port or its store is
    /// still held by the instance it is replacing.
    pub(super) async fn start_slot(&mut self, index: usize) -> Result<()> {
        let count = self.nodes.len();
        let slot = self
            .nodes
            .get(index)
            .ok_or_else(|| anyhow!("node {index} does not exist; the network has {count}"))?;
        if slot.running.is_some() {
            bail!("node {index} is already running");
        }

        let mut peer_ports = Vec::with_capacity(slot.peers.len());
        for peer in &slot.peers {
            let peer_slot = self
                .nodes
                .get(*peer)
                .ok_or_else(|| anyhow!("node {index} lists peer {peer}, which does not exist"))?;
            peer_ports.push(peer_slot.p2p_port);
        }
        let config =
            config::node_config(self.params.network, &slot.datadir, slot.p2p_port, &peer_ports)
                .with_context(|| format!("building node {index}'s configuration"))?;
        let payout = slot.payout();
        let port = slot.p2p_port;

        let _ = ports::await_port_free(port, PORT_RELEASE_TIMEOUT).await;
        let node = start_with_retry(config, index).await?;
        let miner = Arc::new(Miner::new(Arc::clone(node.relay()), payout));
        self.nodes[index].running = Some(RunningNode { node, miner });
        Ok(())
    }
}

/// Start a node, retrying a failure that a previous instance could still be
/// causing.
///
/// The two failures worth retrying are the two a restart creates: the `redb`
/// file lock and the p2p listener, both released asynchronously when the last
/// cancelled task drops its `Arc`. Everything else — a datadir belonging to
/// another chain, a malformed configuration — fails the same way on every
/// attempt and is reported after the budget is spent, with the attempt count in
/// the message so the reader knows it was not a one-off.
async fn start_with_retry(config: ferrum_node::NodeConfig, index: usize) -> Result<Node> {
    let mut last: Option<ferrum_node::NodeError> = None;
    for attempt in 0..START_ATTEMPTS {
        match Node::start(config.clone()).await {
            Ok(node) => return Ok(node),
            Err(e) => {
                tracing::debug!(node = index, attempt, error = %e, "node start failed; retrying");
                last = Some(e);
                tokio::time::sleep(START_RETRY_INTERVAL).await;
            }
        }
    }
    let error = last.map_or_else(|| "no attempt was made".to_owned(), |e| e.to_string());
    Err(anyhow!(
        "node {index} did not start in {START_ATTEMPTS} attempts \
         ({:?} apart); last failure: {error}",
        START_RETRY_INTERVAL
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::time::Duration;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_killed_node_keeps_its_identity_and_its_blocks() {
        let mut net = TestNet::spawn(1).await.unwrap();
        let address = net.address(0).unwrap();
        let peer_id = net.node(0).unwrap().local_peer_id();
        net.mine_blocks(0, 4).await.unwrap();
        let tip = net.tip(0).unwrap();
        let root = net.state_root(0).unwrap();

        net.kill(0).await.unwrap();
        assert!(net.node(0).is_err(), "a killed node is not reachable");
        assert!(net.kill(0).await.is_ok(), "killing twice is a no-op");

        net.start_slot(0).await.unwrap();
        assert_eq!(net.tip(0).unwrap(), tip, "a committed block survives a kill");
        assert_eq!(net.state_root(0).unwrap(), root);
        assert_eq!(net.address(0).unwrap(), address, "the node key is in the datadir");
        assert_eq!(net.node(0).unwrap().local_peer_id(), peer_id);

        net.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn starting_a_running_node_is_refused_rather_than_leaking_one() {
        let mut net = TestNet::spawn(1).await.unwrap();
        assert!(net.start_slot(0).await.is_err());
        assert!(net.restart(0).await.is_ok(), "a restart kills first, so it is allowed");
        net.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_partition_rewires_every_node_and_healing_puts_it_back() {
        let mut net = TestNet::spawn(4).await.unwrap();
        net.await_peers(Duration::from_secs(120)).await.unwrap();

        net.partition(&[0, 1], &[2, 3]).await.unwrap();
        net.await_peer_count(1, Duration::from_secs(120)).await.unwrap();
        assert_eq!(net.nodes[0].peers, vec![1]);
        assert_eq!(net.nodes[3].peers, vec![2]);

        net.heal().await.unwrap();
        net.await_peers(Duration::from_secs(120)).await.unwrap();
        assert_eq!(net.nodes[0].peers, vec![1, 2, 3]);

        net.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_partition_that_is_not_a_partition_is_refused_before_anything_restarts() {
        let mut net = TestNet::spawn(2).await.unwrap();
        let tip = net.tip(0).unwrap();
        assert!(net.partition(&[0], &[]).await.is_err());
        assert!(net.partition(&[0, 1], &[1]).await.is_err());
        assert_eq!(net.tip(0).unwrap(), tip, "a refused partition changes nothing");
        assert!(net.node(0).is_ok(), "and restarts nothing");
        net.shutdown().await.unwrap();
    }
}
