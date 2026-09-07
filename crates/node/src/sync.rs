//! Headers-first sync, exactly as SPEC §12 describes it.
//!
//! Three phases, in this order, repeated until the chain stops growing:
//!
//! 1. **Header sync.** Send a block locator — the last ten tips, then doubling
//!    gaps back to genesis — and ask for headers. Validate each against its
//!    parent (proof of work, difficulty transition, timestamp) and store it
//!    without a body.
//! 2. **Body download.** Ask for the bodies of the headers we just accepted, in
//!    windows, spread across every usable peer.
//! 3. **Connect.** Validate and connect them in order, applying SPEC §3 in
//!    full.
//!
//! # Why headers first
//!
//! A header is 88 bytes and a block is up to a megabyte. Validating a header
//! chain is cheap and *discarding* one is cheaper still, so a peer feeding a
//! bogus chain costs bandwidth and nothing else. Downloading bodies first would
//! let one peer make this node spend a gigabyte of disk on a fork that dies at
//! the first difficulty check.
//!
//! # Misbehaviour
//!
//! A peer that serves an invalid header or an invalid block is banned: never
//! asked for anything again, and every gossip message it sends is thereafter
//! reported as `Reject` so its gossipsub score falls (SPEC §12). The
//! distinction that matters is between "this is invalid" and "I could not tell":
//! a storage failure on our side must never ban an honest peer, which is why
//! [`crate::relay::block_verdict`] rather than a bare `is_err()` decides.
//!
//! # The two-hour future-time rule applies here too
//!
//! Every block connected by sync goes through [`crate::relay::Relay`], which
//! checks it. A node syncing from genesis at three in the morning must reject a
//! block stamped two hours ahead of *its* clock for the same reason a node
//! receiving that block over gossip does.

pub mod network;
pub mod types;

use std::sync::Arc;
use std::time::Duration;

use ferrum_consensus::Work;
use ferrum_p2p::{PeerId, TipInfo};
use ferrum_storage::{BlockStatus, header_hash};
use ferrum_types::{Block, BlockHash, BlockHeader};
use tokio_util::sync::CancellationToken;

pub use self::network::{P2pNetwork, PeerBans, SyncNetwork};
pub use self::types::{
    HeaderBatch, ServedBlock, SyncRound, SyncStats, header_failure_is_bannable,
};
use crate::error::NodeError;
use crate::relay::{GossipVerdict, Relay};

/// Headers asked for in one request. The server caps at 2000 whatever we ask
/// (CONTRACT §10.2), so asking for more only wastes a field.
pub const HEADERS_PER_REQUEST: u32 = 2_000;

/// Block bodies asked for in one request; also the server-side cap.
pub const BLOCKS_PER_REQUEST: usize = 64;

/// How many body requests are in flight at once.
///
/// Four requests of 64 blocks is up to 256 MB of block in flight at the
/// one-megabyte maximum — enough to keep a fast link busy, small enough that a
/// stalled peer costs a bounded amount of memory. Every window is awaited
/// before the next is issued, so this is a hard ceiling and not an average.
pub const BODY_WINDOW_REQUESTS: usize = 4;

/// Blocks in flight at once: [`BODY_WINDOW_REQUESTS`] × [`BLOCKS_PER_REQUEST`].
pub const BODY_WINDOW_BLOCKS: usize = BODY_WINDOW_REQUESTS * BLOCKS_PER_REQUEST;

/// How often the sync loop looks for work when nothing has happened.
pub const SYNC_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How many header/body rounds one call to [`SyncManager::sync_to_best_peer`]
/// will run before returning to the caller.
///
/// A bound, not a target: without it a peer that always claims a longer chain
/// keeps this task inside one call forever, and the node never checks its
/// cancellation token.
pub const MAX_ROUNDS_PER_CALL: usize = 64;

/// Headers-first sync.
#[derive(Debug)]
pub struct SyncManager {
    relay: Arc<Relay>,
    network: Arc<dyn SyncNetwork>,
    bans: Arc<PeerBans>,
}

impl SyncManager {
    /// Build a sync manager over a relay and a network.
    #[must_use]
    pub fn new(relay: Arc<Relay>, network: Arc<dyn SyncNetwork>, bans: Arc<PeerBans>) -> Self {
        SyncManager { relay, network, bans }
    }

    /// The ban list this manager maintains, shared with the relay.
    #[must_use]
    pub fn bans(&self) -> &Arc<PeerBans> {
        &self.bans
    }

    /// The relay this manager connects blocks through.
    #[must_use]
    pub fn relay(&self) -> &Arc<Relay> {
        &self.relay
    }

    /// Peers worth asking: connected, and not banned.
    pub async fn usable_peers(&self) -> Vec<PeerId> {
        self.bans.filter(self.network.peers().await)
    }

    /// Whether `tip` beats what we already have.
    ///
    /// By cumulative **work**, never by height: a chain of a hundred easy
    /// blocks can be worth less than ten hard ones (SPEC §7.1), and syncing
    /// towards the longer one would be syncing towards the wrong chain.
    ///
    /// # Errors
    ///
    /// Never fails today; the signature leaves room for a store read.
    pub fn is_behind(&self, tip: &TipInfo) -> Result<bool, NodeError> {
        let chain = self.relay.chain();
        let (our_hash, _) = chain.tip();
        let ours = chain.total_work(&our_hash).unwrap_or(Work::ZERO);
        Ok(Work::from_be_bytes(&tip.work) > ours)
    }

    /// Sync from whichever connected peer claims the most work.
    ///
    /// Returns when the best peer has nothing more, when nothing beats our own
    /// tip, or after [`MAX_ROUNDS_PER_CALL`] rounds.
    ///
    /// # Errors
    ///
    /// [`NodeError::PeerMisbehaved`] after banning a peer that served
    /// something invalid, and [`NodeError::Chain`] for a failure of our own.
    pub async fn sync_to_best_peer(&self, peers: &[PeerId]) -> Result<SyncStats, NodeError> {
        let mut stats = SyncStats::default();
        let Some((best, _)) = self.best_peer(peers).await else {
            return Ok(stats);
        };

        for _ in 0..MAX_ROUNDS_PER_CALL {
            let round = self.sync_round(best, peers).await?;
            stats.rounds = stats.rounds.saturating_add(1);
            match round {
                SyncRound::Progressed { headers, blocks } => {
                    stats.headers = stats.headers.saturating_add(headers);
                    stats.blocks = stats.blocks.saturating_add(blocks);
                }
                SyncRound::UpToDate | SyncRound::NoHeaders => break,
            }
        }
        if stats.made_progress() {
            let (hash, height) = self.relay.chain().tip();
            tracing::info!(
                peer = %best,
                headers = stats.headers,
                blocks = stats.blocks,
                height,
                %hash,
                "sync round complete: new tip"
            );
        }
        Ok(stats)
    }

    /// The connected peer with the most work, if any beats us.
    ///
    /// Peers are asked one at a time rather than concurrently: the list is a
    /// static handful (there is no peer discovery), and a sequential probe
    /// keeps the "which peer said what" ordering deterministic in a log.
    pub async fn best_peer(&self, peers: &[PeerId]) -> Option<(PeerId, TipInfo)> {
        let mut best: Option<(PeerId, TipInfo, Work)> = None;
        for peer in peers {
            if self.bans.is_banned(peer) {
                continue;
            }
            let tip = match self.network.request_tip(*peer).await {
                Ok(tip) => tip,
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "peer did not answer GetTip");
                    continue;
                }
            };
            let work = Work::from_be_bytes(&tip.work);
            match self.is_behind(&tip) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    tracing::warn!(error = %e, "could not compare peer work");
                    continue;
                }
            }
            if best.as_ref().is_none_or(|(_, _, w)| work > *w) {
                best = Some((*peer, tip, work));
            }
        }
        best.map(|(p, t, _)| (p, t))
    }

    /// One header batch, its bodies, and the connect pass.
    ///
    /// # Errors
    ///
    /// [`NodeError::PeerMisbehaved`] when `header_peer` serves an invalid
    /// header, or any peer serves an invalid block.
    pub async fn sync_round(
        &self,
        header_peer: PeerId,
        body_peers: &[PeerId],
    ) -> Result<SyncRound, NodeError> {
        // ---- phase 1: headers ---------------------------------------------
        let locator = self.locator().await?;
        let headers = self
            .network
            .request_headers(header_peer, locator, None, HEADERS_PER_REQUEST)
            .await?;
        if headers.is_empty() {
            return Ok(SyncRound::NoHeaders);
        }
        if headers.len() > HEADERS_PER_REQUEST as usize {
            // The server caps at 2000; a peer that ignores its own cap is
            // trying to make us allocate.
            return Err(self.misbehaved(header_peer, "header batch", format!(
                "{} headers, cap is {HEADERS_PER_REQUEST}",
                headers.len()
            )));
        }
        let batch = self.accept_headers(header_peer, headers).await?;
        self.relay.metrics().headers_accepted(batch.accepted);
        if let Some(reason) = &batch.stalled {
            tracing::debug!(peer = %header_peer, reason, "header batch stopped short");
        }

        if batch.wanted.is_empty() {
            // Every header was already known with its body. No progress is
            // possible from this peer without a fresh locator, and the locator
            // only moves when the active chain does.
            return Ok(SyncRound::NoHeaders);
        }

        // ---- phases 2 and 3: bodies, in windows, connected in order --------
        let mut connected = 0usize;
        for window in batch.wanted.chunks(BODY_WINDOW_BLOCKS) {
            let served = self.download_window(body_peers, header_peer, window).await?;
            if served.is_empty() {
                tracing::warn!(
                    peer = %header_peer,
                    wanted = window.len(),
                    "no peer served the bodies for this window"
                );
                break;
            }
            connected = connected.saturating_add(self.connect_served(served).await?);
        }

        Ok(SyncRound::Progressed { headers: batch.accepted, blocks: connected })
    }

    /// The exponential back-off block locator for our active chain.
    async fn locator(&self) -> Result<Vec<BlockHash>, NodeError> {
        let chain = Arc::clone(self.relay.chain());
        blocking(move || chain.locator()).await
    }

    /// Validate and store a batch of headers, reporting those whose bodies we
    /// still need, in chain order.
    ///
    /// Headers are stored **without bodies**, which is the whole point of
    /// headers first: a header chain is cheap to validate and cheap to discard,
    /// so a peer feeding a bogus chain costs bandwidth and nothing else.
    ///
    /// # Errors
    ///
    /// [`NodeError::PeerMisbehaved`], after banning `peer`, when a header
    /// breaks a rule. A header this node merely *cannot evaluate yet* — see
    /// [`header_failure_is_bannable`] — ends the batch instead, with the reason
    /// recorded in [`HeaderBatch::stalled`].
    pub async fn accept_headers(
        &self,
        peer: PeerId,
        headers: Vec<BlockHeader>,
    ) -> Result<HeaderBatch, NodeError> {
        let chain = Arc::clone(self.relay.chain());
        let (batch, bannable): (HeaderBatch, Option<String>) = blocking(move || {
            let mut wanted = Vec::new();
            let mut accepted = 0usize;
            for header in headers {
                let hash = header_hash(&header);
                if let Err(e) = chain.accept_header(header) {
                    let detail = format!("{hash}: {e}");
                    let batch = HeaderBatch { wanted, accepted, stalled: None };
                    if header_failure_is_bannable(&e) {
                        return (batch, Some(detail));
                    }
                    return (HeaderBatch { stalled: Some(detail), ..batch }, None);
                }
                accepted = accepted.saturating_add(1);
                // A header we hold with a body needs nothing further; one we
                // hold header-only, or have just learned, needs its body.
                let have_body = matches!(
                    chain.store().get_header(&hash),
                    Ok(Some(entry))
                        if matches!(entry.status, BlockStatus::HaveData | BlockStatus::Valid)
                );
                if !have_body {
                    wanted.push(hash);
                }
            }
            (HeaderBatch { wanted, accepted, stalled: None }, None)
        })
        .await?;

        match bannable {
            None => Ok(batch),
            Some(reason) => Err(self.misbehaved(peer, "header", reason)),
        }
    }

    /// Fetch one window of bodies, spreading the chunks across `peers`.
    ///
    /// Chunks go out concurrently and are reassembled in the order `hashes`
    /// asked for, because a block may only be connected after its parent.
    ///
    /// # Errors
    ///
    /// [`NodeError::PeerMisbehaved`] when a peer returns a block whose header
    /// does not hash to what was asked for.
    pub async fn download_window(
        &self,
        peers: &[PeerId],
        fallback: PeerId,
        hashes: &[BlockHash],
    ) -> Result<Vec<ServedBlock>, NodeError> {
        let usable: Vec<PeerId> = if peers.is_empty() {
            vec![fallback]
        } else {
            let filtered = self.bans.filter(peers.to_vec());
            if filtered.is_empty() { vec![fallback] } else { filtered }
        };

        let chunks: Vec<(PeerId, Vec<BlockHash>)> = hashes
            .chunks(BLOCKS_PER_REQUEST)
            .enumerate()
            .map(|(i, chunk)| {
                // Round-robin, so a window is genuinely spread rather than all
                // landing on peer zero.
                (usable[i % usable.len()], chunk.to_vec())
            })
            .collect();

        let requests = chunks.into_iter().map(|(peer, chunk)| {
            let network = Arc::clone(&self.network);
            async move {
                let result = network.request_blocks(peer, chunk.clone()).await;
                (peer, chunk, result)
            }
        });
        let answers = futures::future::join_all(requests).await;

        // Index what came back by hash, then walk `hashes` in order. A peer
        // that returns fewer blocks than asked is not misbehaving — it may
        // genuinely not have them — but one that returns a *different* block is.
        let mut by_hash: std::collections::BTreeMap<BlockHash, ServedBlock> =
            std::collections::BTreeMap::new();
        for (peer, chunk, result) in answers {
            match result {
                Ok(blocks) => {
                    if blocks.len() > chunk.len() {
                        return Err(self.misbehaved(
                            peer,
                            "block batch",
                            format!("{} blocks for {} requested", blocks.len(), chunk.len()),
                        ));
                    }
                    for block in blocks {
                        let hash = header_hash(&block.header);
                        if !chunk.contains(&hash) {
                            return Err(self.misbehaved(
                                peer,
                                "block",
                                format!("{hash} was not requested"),
                            ));
                        }
                        by_hash.insert(hash, ServedBlock { peer, block });
                    }
                }
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "block request failed");
                }
            }
        }

        // Stop at the first gap: connecting past a missing parent is not
        // possible, and pretending otherwise turns a slow peer into an orphan
        // storm.
        let mut ordered = Vec::with_capacity(hashes.len());
        for hash in hashes {
            match by_hash.remove(hash) {
                Some(served) => ordered.push(served),
                None => break,
            }
        }
        Ok(ordered)
    }

    /// Connect a window in order, banning whichever peer served an invalid
    /// block.
    ///
    /// # Errors
    ///
    /// [`NodeError::PeerMisbehaved`] after banning the offending peer.
    pub async fn connect_served(&self, served: Vec<ServedBlock>) -> Result<usize, NodeError> {
        let relay = Arc::clone(&self.relay);
        // Boxed: a peer id, a hash and a message together are large enough
        // that returning them by value would make every success path carry
        // the failure path's width.
        let outcome: Result<usize, Box<(PeerId, BlockHash, String)>> = blocking(move || {
            let mut connected = 0usize;
            // One clock reading for the whole window: a block is judged against
            // the time the window started, so a long window cannot make an
            // early block "become" too far in the future halfway through.
            let now_ms = relay.now_ms();
            for ServedBlock { peer, block } in served {
                let result = relay.accept_block_at(block, now_ms);
                if result.verdict == GossipVerdict::Reject {
                    // A block refused only because it is ahead of *our* clock
                    // is not the peer's fault: nothing about the block is
                    // wrong, and in ten minutes it will connect.
                    if result.rejection == Some(crate::relay::BlockRejection::TooFarInFuture) {
                        break;
                    }
                    return Err(Box::new((peer, result.hash, result.error.unwrap_or_default())));
                }
                if result.outcome.is_some() {
                    connected = connected.saturating_add(1);
                }
            }
            Ok(connected)
        })
        .await?;

        match outcome {
            Ok(n) => Ok(n),
            Err(boxed) => {
                let (peer, hash, reason) = *boxed;
                Err(self.misbehaved(peer, "block", format!("{hash}: {reason}")))
            }
        }
    }

    /// Connect blocks in order, through the same path a gossiped block takes.
    ///
    /// # Errors
    ///
    /// Never returns a peer error — the caller does not know which peer served
    /// which block by this point — but stops at the first block that fails.
    /// [`SyncManager::connect_blocks_from`] is the variant that bans.
    pub async fn connect_blocks(&self, blocks: Vec<Block>) -> Result<usize, NodeError> {
        let relay = Arc::clone(&self.relay);
        blocking(move || {
            let mut connected = 0usize;
            // One clock reading for the whole window: a block is judged against
            // the time the window started, so a long window cannot make an
            // early block "become" too far in the future halfway through.
            let now_ms = relay.now_ms();
            for block in blocks {
                let outcome = relay.accept_block_at(block, now_ms);
                if outcome.verdict == GossipVerdict::Reject {
                    tracing::warn!(
                        hash = %outcome.hash,
                        error = outcome.error.unwrap_or_default(),
                        "sync stopped at an invalid block"
                    );
                    break;
                }
                if outcome.outcome.is_some() {
                    connected = connected.saturating_add(1);
                }
            }
            connected
        })
        .await
    }

    /// Connect blocks served by `peer`, banning it if one is invalid.
    ///
    /// # Errors
    ///
    /// [`NodeError::PeerMisbehaved`] after banning `peer`.
    pub async fn connect_blocks_from(
        &self,
        peer: PeerId,
        blocks: Vec<Block>,
    ) -> Result<usize, NodeError> {
        let relay = Arc::clone(&self.relay);
        let outcome: Result<usize, (BlockHash, String)> = blocking(move || {
            let mut connected = 0usize;
            let now_ms = relay.now_ms();
            for block in blocks {
                let result = relay.accept_block_at(block, now_ms);
                if result.verdict == GossipVerdict::Reject {
                    return Err((result.hash, result.error.unwrap_or_default()));
                }
                if result.outcome.is_some() {
                    connected = connected.saturating_add(1);
                }
            }
            Ok(connected)
        })
        .await?;

        match outcome {
            Ok(n) => Ok(n),
            Err((hash, reason)) => {
                Err(self.misbehaved(peer, "block", format!("{hash}: {reason}")))
            }
        }
    }

    /// Ban a peer and build the error that says why.
    fn misbehaved(&self, peer: PeerId, what: &'static str, reason: String) -> NodeError {
        if self.bans.ban(peer) {
            self.relay.metrics().peer_disconnected();
            self.network.disconnect(peer, &reason);
            tracing::warn!(%peer, what, reason, "peer served invalid data; banned");
        }
        NodeError::PeerMisbehaved { peer: peer.to_string(), what, reason }
    }
}

/// Run synchronous, store-touching work off the async runtime.
///
/// `ferrum-storage` is synchronous (CONTRACT §7) and a `redb` call on the async
/// runtime is a two-second p95 latency bug, so every path from an `async fn`
/// into the store goes through here.
///
/// # Errors
///
/// [`NodeError::Task`] when the blocking thread panics or is cancelled.
pub async fn blocking<T, F>(f: F) -> Result<T, NodeError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f).await.map_err(|e| NodeError::task(&e))
}

/// Drive sync until `cancel` fires.
///
/// Wakes on a tick or on a hint that a peer announced a new tip, whichever
/// comes first. The hint channel is bounded by its sender; a missed hint costs
/// at most one [`SYNC_POLL_INTERVAL`].
pub async fn run(
    manager: Arc<SyncManager>,
    mut hints: tokio::sync::mpsc::Receiver<PeerId>,
    cancel: CancellationToken,
) {
    tracing::info!("sync started");
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = tokio::time::sleep(SYNC_POLL_INTERVAL) => {}
            hint = hints.recv() => {
                if hint.is_none() {
                    // Every sender is gone; fall back to the tick.
                    tokio::time::sleep(SYNC_POLL_INTERVAL).await;
                }
            }
        }
        if cancel.is_cancelled() {
            break;
        }

        let peers = manager.usable_peers().await;
        if peers.is_empty() {
            continue;
        }
        match manager.sync_to_best_peer(&peers).await {
            Ok(stats) if stats.made_progress() => {
                tracing::debug!(?stats, "sync made progress");
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "sync round failed"),
        }
    }
    tracing::info!("sync stopped");
}

#[cfg(test)]
mod tests;
