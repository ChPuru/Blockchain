//! What a failing test prints.
//!
//! A CI log that says "the network did not converge" costs an afternoon. A CI
//! log that says
//!
//! ```text
//! node 0  up    height 11  tip 9f3c…  work 0x…0b  peers 3  mempool 0  reorgs 0
//! node 1  up    height 11  tip 9f3c…  work 0x…0b  peers 3  mempool 0  reorgs 0
//! node 2  up    height  7  tip 41a8…  work 0x…07  peers 1  mempool 1  reorgs 0
//! node 3  down
//! ```
//!
//! says node 2 never reconnected after the heal, and costs a minute. Every
//! wait in this harness ends its error message with [`TestNet::describe`] for
//! that reason.
//!
//! Nothing here is allowed to fail: a diagnostic that returns `Err` on the path
//! where something has already gone wrong is a diagnostic that reports the
//! wrong failure. Every unreadable field prints as `?` instead.

use ferrum_node::MetricsSnapshot;

use crate::harness::TestNet;

/// How many hex characters of a hash a report shows.
///
/// Sixteen is enough to tell two devnet tips apart at a glance and short enough
/// that four nodes fit on one line each.
pub const HASH_PREFIX: usize = 16;

/// One node's line in a report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeReport {
    /// Index in the network.
    pub index: usize,
    /// Whether the node is running.
    pub running: bool,
    /// Active height, when it could be read.
    pub height: Option<u64>,
    /// Active tip, hex.
    pub tip: Option<String>,
    /// Cumulative work at the tip, hex, big-endian.
    pub work: Option<String>,
    /// Connected peers, when the swarm answered.
    pub peers: Option<usize>,
    /// Transactions in the mempool.
    pub mempool: Option<usize>,
    /// The node's counters, when it is running.
    pub metrics: Option<MetricsSnapshot>,
}

impl std::fmt::Display for NodeReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.running {
            return write!(f, "node {}  down", self.index);
        }
        write!(
            f,
            "node {}  up    height {:>4}  tip {}  work {}  peers {}  mempool {}  \
             reorgs {} (depth {})  rejected {}",
            self.index,
            self.height.map_or_else(|| "?".to_owned(), |h| h.to_string()),
            self.tip.as_deref().unwrap_or("?"),
            self.work.as_deref().unwrap_or("?"),
            self.peers.map_or_else(|| "?".to_owned(), |p| p.to_string()),
            self.mempool.map_or_else(|| "?".to_owned(), |m| m.to_string()),
            self.metrics.as_ref().map_or_else(|| "?".to_owned(), |m| m.reorgs.to_string()),
            self.metrics.as_ref().map_or_else(|| "?".to_owned(), |m| m.reorg_depth.to_string()),
            self.metrics.as_ref().map_or_else(|| "?".to_owned(), |m| m.blocks_rejected.to_string()),
        )
    }
}

/// Shorten a hex string for a report line.
#[must_use]
pub fn short_hex(hex: &str) -> String {
    match hex.char_indices().nth(HASH_PREFIX) {
        Some((cut, _)) => format!("{}…", &hex[..cut]),
        None => hex.to_owned(),
    }
}

impl TestNet {
    /// The counters node `index` has accumulated since it last started.
    ///
    /// Counters live on the [`ferrum_node::Node`], so a restart — and therefore
    /// a [`TestNet::partition`] or [`TestNet::heal`] — zeroes them. That is
    /// usually what a test wants: "did *this* node reorganise after the heal?"
    /// is a question about the instance, not about the slot.
    ///
    /// # Errors
    ///
    /// When the node is not running.
    pub fn metrics(&self, index: usize) -> anyhow::Result<MetricsSnapshot> {
        Ok(self.node(index)?.metrics().snapshot())
    }

    /// Wait until node `index`'s counters satisfy `ready`.
    ///
    /// `what` names the condition, so the timeout message reads
    /// "node 2 did not record a reorg within 60s" rather than "a closure
    /// returned false".
    ///
    /// # Errors
    ///
    /// After `timeout`, with [`TestNet::describe`] in the message.
    pub async fn await_metrics<F>(
        &self,
        index: usize,
        what: &str,
        ready: F,
        timeout: std::time::Duration,
    ) -> anyhow::Result<MetricsSnapshot>
    where
        F: Fn(&MetricsSnapshot) -> bool,
    {
        let poll = async {
            loop {
                if let Ok(snapshot) = self.metrics(index)
                    && ready(&snapshot)
                {
                    return snapshot;
                }
                tokio::time::sleep(crate::harness::POLL_INTERVAL).await;
            }
        };
        match tokio::time::timeout(timeout, poll).await {
            Ok(snapshot) => Ok(snapshot),
            Err(_) => Err(anyhow::anyhow!(
                "node {index} did not {what} within {timeout:?}\n{}",
                self.describe().await
            )),
        }
    }

    /// A one-line-per-node picture of the whole network.
    ///
    /// Never fails: an unreadable field prints as `?`.
    pub async fn report(&self) -> Vec<NodeReport> {
        let mut out = Vec::with_capacity(self.nodes.len());
        for slot in &self.nodes {
            let Some(running) = slot.running.as_ref() else {
                out.push(NodeReport {
                    index: slot.index,
                    running: false,
                    height: None,
                    tip: None,
                    work: None,
                    peers: None,
                    mempool: None,
                    metrics: None,
                });
                continue;
            };
            let node = &running.node;
            let (tip, height) = node.chain().tip();
            let peers = match node.p2p() {
                Some(handle) => handle.peers().await.ok().map(|p| p.len()),
                None => None,
            };
            out.push(NodeReport {
                index: slot.index,
                running: true,
                height: Some(height),
                tip: Some(short_hex(&tip.0.to_hex())),
                work: node
                    .chain()
                    .total_work(&tip)
                    .map(|w| short_hex(&hex::encode(w.to_be_bytes()))),
                peers,
                mempool: Some(node.mempool().len()),
                metrics: Some(node.metrics().snapshot()),
            });
        }
        out
    }

    /// [`TestNet::report`], rendered.
    pub async fn describe(&self) -> String {
        let mut out = String::from("network state:\n");
        for line in self.report().await {
            out.push_str("  ");
            out.push_str(&line.to_string());
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::time::Duration;

    use super::*;

    #[test]
    fn a_hash_is_shortened_to_a_readable_prefix() {
        let hex = "9f3c".repeat(16);
        assert_eq!(short_hex(&hex), "9f3c9f3c9f3c9f3c…");
        assert_eq!(short_hex("abcd"), "abcd", "a short string is left alone");
        assert_eq!(short_hex(""), "");
    }

    #[test]
    fn a_down_node_says_so_and_nothing_else() {
        let report = NodeReport {
            index: 3,
            running: false,
            height: None,
            tip: None,
            work: None,
            peers: None,
            mempool: None,
            metrics: None,
        };
        assert_eq!(report.to_string(), "node 3  down");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_report_names_every_node_and_survives_a_dead_one() {
        let mut net = TestNet::spawn(2).await.unwrap();
        net.await_peers(Duration::from_secs(120)).await.unwrap();
        net.mine_blocks(0, 2).await.unwrap();
        net.await_convergence(Duration::from_secs(120)).await.unwrap();

        let report = net.report().await;
        assert_eq!(report.len(), 2);
        assert!(report.iter().all(|r| r.running));
        assert_eq!(report[0].height, Some(2));
        assert_eq!(report[0].tip, report[1].tip);
        assert_eq!(report[0].peers, Some(1));
        assert_eq!(net.metrics(0).unwrap().blocks_mined, 2);

        net.kill(1).await.unwrap();
        let text = net.describe().await;
        assert!(text.contains("node 0  up"), "{text}");
        assert!(text.contains("node 1  down"), "{text}");
        assert!(net.metrics(1).is_err());

        net.shutdown().await.unwrap();
    }
}
