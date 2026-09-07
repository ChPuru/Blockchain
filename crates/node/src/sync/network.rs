//! The seam between sync and the wire, plus the ban list.
//!
//! [`SyncManager`](super::SyncManager) drives headers-first sync against this
//! trait rather than against [`ferrum_p2p::P2pHandle`] directly. That is not
//! abstraction for its own sake: a headers-first sync bug is a *protocol*
//! bug — a locator that never advances, a window that drops the last chunk, a
//! peer that lies about its tip — and none of those need a TCP socket to
//! reproduce. With this seam the whole algorithm is testable against a second
//! in-process [`ferrum_chain::ChainManager`], deterministically and in
//! milliseconds.
//!
//! # Disconnection
//!
//! SPEC §12 requires that a peer serving an invalid header or block is
//! disconnected and its messages reported as rejected. `ferrum-p2p` 0.1
//! exposes no command to close a connection, so [`PeerBans`] implements the
//! half the node can: a banned peer is never asked for anything again, and
//! every gossip message it sends is reported as
//! [`ferrum_p2p::MessageAcceptance::Reject`], which drives its gossipsub P₄
//! score down until the mesh drops it. When `P2pHandle` grows a `disconnect`,
//! [`P2pNetwork::disconnect`] is the one place that needs to change.

use std::collections::BTreeSet;

use ferrum_p2p::{P2pHandle, PeerId, TipInfo};
use ferrum_types::{Block, BlockHash, BlockHeader};
use parking_lot::Mutex;

use crate::error::NodeError;

/// What sync needs from the network, and nothing more.
#[async_trait::async_trait]
pub trait SyncNetwork: Send + Sync + std::fmt::Debug {
    /// Peers that are currently usable.
    async fn peers(&self) -> Vec<PeerId>;

    /// Ask a peer where its chain ends.
    ///
    /// # Errors
    ///
    /// [`NodeError::P2p`] when the peer does not answer.
    async fn request_tip(&self, peer: PeerId) -> Result<TipInfo, NodeError>;

    /// Ask a peer for headers after the first locator entry it recognises.
    ///
    /// # Errors
    ///
    /// [`NodeError::P2p`] when the peer does not answer.
    async fn request_headers(
        &self,
        peer: PeerId,
        locator: Vec<BlockHash>,
        stop: Option<BlockHash>,
        max: u32,
    ) -> Result<Vec<BlockHeader>, NodeError>;

    /// Ask a peer for block bodies.
    ///
    /// # Errors
    ///
    /// [`NodeError::P2p`] when the peer does not answer.
    async fn request_blocks(
        &self,
        peer: PeerId,
        hashes: Vec<BlockHash>,
    ) -> Result<Vec<Block>, NodeError>;

    /// Stop talking to a peer that served something invalid.
    fn disconnect(&self, peer: PeerId, reason: &str);
}

/// Peers this node refuses to sync from.
///
/// A `BTreeSet`, not a hash set: every collection in this workspace that can
/// influence what a node does is ordered, so a log or a diagnostic dump reads
/// the same on every machine.
#[derive(Debug, Default)]
pub struct PeerBans {
    banned: Mutex<BTreeSet<PeerId>>,
}

impl PeerBans {
    /// An empty ban list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ban a peer. Returns whether it was newly banned.
    pub fn ban(&self, peer: PeerId) -> bool {
        self.banned.lock().insert(peer)
    }

    /// Whether a peer is banned.
    #[must_use]
    pub fn is_banned(&self, peer: &PeerId) -> bool {
        self.banned.lock().contains(peer)
    }

    /// How many peers are banned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.banned.lock().len()
    }

    /// Whether nothing is banned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The banned peers, in a deterministic order.
    #[must_use]
    pub fn snapshot(&self) -> Vec<PeerId> {
        self.banned.lock().iter().copied().collect()
    }

    /// Drop a ban, for an operator who has decided a peer is fine again.
    pub fn unban(&self, peer: &PeerId) -> bool {
        self.banned.lock().remove(peer)
    }

    /// Remove the banned peers from a candidate list.
    #[must_use]
    pub fn filter(&self, peers: Vec<PeerId>) -> Vec<PeerId> {
        let banned = self.banned.lock();
        peers.into_iter().filter(|p| !banned.contains(p)).collect()
    }
}

/// [`SyncNetwork`] over the real swarm.
#[derive(Debug)]
pub struct P2pNetwork {
    handle: P2pHandle,
}

impl P2pNetwork {
    /// Wrap a running p2p service.
    #[must_use]
    pub fn new(handle: P2pHandle) -> Self {
        P2pNetwork { handle }
    }

    /// The handle underneath.
    #[must_use]
    pub fn handle(&self) -> &P2pHandle {
        &self.handle
    }
}

#[async_trait::async_trait]
impl SyncNetwork for P2pNetwork {
    async fn peers(&self) -> Vec<PeerId> {
        match self.handle.peers().await {
            Ok(peers) => peers.into_iter().map(|p| p.peer_id).collect(),
            Err(e) => {
                tracing::warn!(error = %e, "could not list peers");
                Vec::new()
            }
        }
    }

    async fn request_tip(&self, peer: PeerId) -> Result<TipInfo, NodeError> {
        Ok(self.handle.request_tip(peer).await?)
    }

    async fn request_headers(
        &self,
        peer: PeerId,
        locator: Vec<BlockHash>,
        stop: Option<BlockHash>,
        max: u32,
    ) -> Result<Vec<BlockHeader>, NodeError> {
        Ok(self.handle.request_headers(peer, locator, stop, max).await?)
    }

    async fn request_blocks(
        &self,
        peer: PeerId,
        hashes: Vec<BlockHash>,
    ) -> Result<Vec<Block>, NodeError> {
        Ok(self.handle.request_blocks(peer, hashes).await?)
    }

    fn disconnect(&self, peer: PeerId, reason: &str) {
        // `ferrum-p2p` 0.1 has no command to close a connection. The ban list
        // stops us asking this peer for anything, and `relay` reports its
        // gossip as Reject so its P4 score falls until the mesh drops it.
        // See the module docs.
        tracing::warn!(%peer, reason, "peer banned for serving invalid data");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn a_fresh_ban_list_is_empty() {
        let bans = PeerBans::new();
        assert!(bans.is_empty());
        assert_eq!(bans.len(), 0);
        assert!(!bans.is_banned(&peer()));
    }

    #[test]
    fn banning_is_idempotent() {
        let bans = PeerBans::new();
        let p = peer();
        assert!(bans.ban(p), "the first ban is new");
        assert!(!bans.ban(p), "the second is not");
        assert_eq!(bans.len(), 1);
        assert!(bans.is_banned(&p));
    }

    #[test]
    fn a_banned_peer_is_filtered_out_of_a_candidate_list() {
        let bans = PeerBans::new();
        let (good, bad) = (peer(), peer());
        bans.ban(bad);
        let kept = bans.filter(vec![good, bad]);
        assert_eq!(kept, vec![good]);
    }

    #[test]
    fn an_operator_can_lift_a_ban() {
        let bans = PeerBans::new();
        let p = peer();
        bans.ban(p);
        assert!(bans.unban(&p));
        assert!(!bans.unban(&p));
        assert!(!bans.is_banned(&p));
    }

    #[test]
    fn the_snapshot_is_deterministically_ordered() {
        let bans = PeerBans::new();
        let mut peers: Vec<PeerId> = (0..8).map(|_| peer()).collect();
        for p in &peers {
            bans.ban(*p);
        }
        peers.sort();
        assert_eq!(bans.snapshot(), peers);
    }
}
