//! Turning a slot into a [`ferrum_node::NodeConfig`], and validating a
//! partition topology before anything is restarted.
//!
//! # The configuration is assembled the way `chaind` assembles it
//!
//! Through [`ferrum_node::resolve`] with a [`ferrum_node::CliOverrides`], not
//! by filling a `NodeConfig` in by hand. That is deliberate: the precedence
//! engine is where a network name becomes a `ChainParams` and where a mining
//! address is checked against it, and a harness that bypassed it would be
//! testing a node nobody runs.
//!
//! Three choices differ from `devnet/lib.sh`, each for a reason:
//!
//! - **RPC and explorer bind port zero.** Nothing in the network refers to
//!   them by number, so the kernel may choose, and one fewer reservation is one
//!   fewer race. `Node::rpc_addr()` reports what was actually bound.
//! - **Metrics are off.** The Prometheus exporter installs a *process-global*
//!   recorder; four nodes in one process would fight over it, and the counters
//!   the tests assert on are read from [`ferrum_node::NodeMetrics`] directly.
//! - **The faucet is off.** It is on by default on devnet, and it derives a key
//!   and logs an address at every start. A harness that restarts nodes eight
//!   times per test does not need that.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, bail};
use ferrum_node::config::MapEnv;
use ferrum_node::{CliOverrides, LogFormat, NodeConfig, resolve};
use ferrum_types::Network;

use crate::harness::ports;

/// Build the configuration for one node.
///
/// `peers` are the loopback ports of the nodes this one lists as static peers;
/// `datadir` is preserved across restarts, so the node key — and therefore the
/// libp2p identity and the payout address — is stable.
///
/// # Errors
///
/// [`ferrum_node::ConfigError`] when a value will not parse, which for
/// harness-generated input means a bug in the harness.
pub fn node_config(
    network: Network,
    datadir: &Path,
    p2p_port: u16,
    peers: &[u16],
) -> Result<NodeConfig> {
    let overrides = CliOverrides {
        network: Some(network.to_string()),
        datadir: Some(datadir.to_path_buf()),
        // Ephemeral: no peer, and no test, refers to these by number.
        rpc_listen: Some("127.0.0.1:0".to_owned()),
        explorer_listen: Some("127.0.0.1:0".to_owned()),
        p2p_listen: Some(ports::loopback_multiaddr(p2p_port)),
        peers: Some(peers.iter().copied().map(ports::loopback_multiaddr).collect()),
        // The reverse index, so a test can ask "is this transaction confirmed?"
        // the way the explorer does instead of scanning blocks by hand.
        index: Some(true),
        // Mining is driven by the harness, never ambient. See `harness::mining`.
        mine: Some(false),
        // Off: it derives a key and logs an address on every start, and no test
        // here asks the faucet for anything.
        faucet: Some(false),
        ..Default::default()
    };
    Ok(resolve(&overrides, &MapEnv::new(), None)?)
}

/// Install a tracing subscriber, but only when the operator asked for one.
///
/// A hundred blocks across four nodes is a few thousand `info` lines, which
/// buries the assertion failure a reader came for. `RUST_LOG=ferrum_node=debug
/// cargo test -p ferrum-e2e -- --nocapture` turns them back on.
///
/// Calling this repeatedly is harmless: [`ferrum_node::init_tracing`] reports
/// an already-installed subscriber as `Ok(false)`.
pub fn init_logging() {
    if std::env::var_os("RUST_LOG").is_some() {
        let _ = ferrum_node::init_tracing(LogFormat::Text);
    }
}

/// Check that two index groups really do partition `count` nodes.
///
/// A test that splits `[0, 1] | [2, 3]` of a five-node network, or that lists a
/// node twice, has a bug the harness must not paper over by silently choosing a
/// topology. Returns the group each node belongs to, indexed by node.
///
/// # Errors
///
/// When either side is empty, when a node appears twice, when a node is out of
/// range, or when the two sides do not cover every node.
pub fn partition_groups(count: usize, a: &[usize], b: &[usize]) -> Result<Vec<usize>> {
    if a.is_empty() || b.is_empty() {
        bail!("a partition needs a node on each side; got {a:?} | {b:?}");
    }
    let mut group = vec![usize::MAX; count];
    for (side, members) in [(0usize, a), (1usize, b)] {
        for &index in members {
            if index >= count {
                bail!("node {index} is not in a network of {count}");
            }
            if group[index] != usize::MAX {
                bail!("node {index} appears on both sides of the partition");
            }
            group[index] = side;
        }
    }
    let missing: Vec<usize> = (0..count).filter(|i| group[*i] == usize::MAX).collect();
    if !missing.is_empty() {
        bail!("a partition must place every node; {missing:?} were left out");
    }
    Ok(group)
}

/// The static peer list each node gets under `group`.
///
/// A node lists exactly the other members of its own side, which is how
/// `devnet/partition.sh` splits a network: not with a firewall, but by not
/// telling a node the other half exists.
#[must_use]
pub fn peers_within(group: &[usize]) -> Vec<Vec<usize>> {
    (0..group.len())
        .map(|i| {
            (0..group.len()).filter(|j| *j != i && group[*j] == group[i]).collect::<Vec<usize>>()
        })
        .collect()
}

/// The static peer list each node gets in a full mesh of `count` nodes.
#[must_use]
pub fn peers_full(count: usize) -> Vec<Vec<usize>> {
    (0..count).map(|i| (0..count).filter(|j| *j != i).collect()).collect()
}

/// Whether every index in `peers` is a valid node in a network of `count`.
///
/// Used by the harness's own tests; a peer list that names a node which does
/// not exist would produce a node that quietly never connects.
#[must_use]
pub fn peers_are_valid(count: usize, peers: &[Vec<usize>]) -> bool {
    peers.len() == count
        && peers.iter().enumerate().all(|(i, list)| {
            let unique: BTreeSet<usize> = list.iter().copied().collect();
            unique.len() == list.len() && list.iter().all(|j| *j < count && *j != i)
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_devnet_configuration_lands_on_devnet_parameters() {
        let dir = tempfile::tempdir().unwrap();
        let config = node_config(Network::Devnet, dir.path(), 30_001, &[30_002, 30_003]).unwrap();
        assert_eq!(config.network, Network::Devnet);
        assert_eq!(config.params.chain_id, ferrum_types::ChainId(3));
        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.p2p_listen.to_string(), "/ip4/127.0.0.1/tcp/30001");
        assert_eq!(config.rpc_listen.port(), 0, "the kernel chooses the rpc port");
        assert_eq!(config.explorer_listen.port(), 0);
        assert_eq!(config.metrics_listen, None, "one process, one global recorder");
        assert!(!config.mine, "mining is driven by the harness");
        assert!(!config.faucet);
        assert!(config.index, "the reverse index answers 'is this confirmed?'");
        assert_eq!(config.store_path(), dir.path().join("chain.redb"));
    }

    #[test]
    fn a_node_with_no_peers_is_a_valid_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let config = node_config(Network::Devnet, dir.path(), 30_010, &[]).unwrap();
        assert!(config.peers.is_empty());
    }

    #[test]
    fn a_two_two_split_of_four_nodes_is_accepted() {
        let group = partition_groups(4, &[0, 1], &[2, 3]).unwrap();
        assert_eq!(group, vec![0, 0, 1, 1]);
        let peers = peers_within(&group);
        assert_eq!(peers, vec![vec![1], vec![0], vec![3], vec![2]]);
        assert!(peers_are_valid(4, &peers));
    }

    #[test]
    fn an_uneven_split_is_accepted_because_fork_choice_is_by_work() {
        let group = partition_groups(5, &[0], &[1, 2, 3, 4]).unwrap();
        assert_eq!(group, vec![0, 1, 1, 1, 1]);
        assert_eq!(peers_within(&group)[0], Vec::<usize>::new());
    }

    #[test]
    fn a_partition_that_leaves_a_node_out_is_refused() {
        let e = partition_groups(4, &[0, 1], &[2]).unwrap_err().to_string();
        assert!(e.contains("[3]"), "the message must name the node: {e}");
    }

    #[test]
    fn a_node_on_both_sides_is_refused() {
        let e = partition_groups(3, &[0, 1], &[1, 2]).unwrap_err().to_string();
        assert!(e.contains("both sides"), "{e}");
    }

    #[test]
    fn an_empty_side_and_an_out_of_range_node_are_refused() {
        assert!(partition_groups(2, &[], &[0, 1]).is_err());
        assert!(partition_groups(2, &[0], &[1, 2]).is_err());
    }

    #[test]
    fn a_full_mesh_lists_everybody_but_yourself() {
        assert_eq!(peers_full(3), vec![vec![1, 2], vec![0, 2], vec![0, 1]]);
        assert!(peers_are_valid(3, &peers_full(3)));
        assert_eq!(peers_full(1), vec![Vec::<usize>::new()]);
    }

    #[test]
    fn a_peer_list_naming_itself_or_a_stranger_is_invalid() {
        assert!(!peers_are_valid(2, &[vec![0], vec![0]]), "node 0 must not list itself");
        assert!(!peers_are_valid(2, &[vec![9], vec![0]]), "node 9 does not exist");
        assert!(!peers_are_valid(2, &[vec![1, 1], vec![0]]), "a duplicate peer is a bug");
        assert!(!peers_are_valid(3, &[vec![1], vec![0]]), "one list per node");
    }
}
