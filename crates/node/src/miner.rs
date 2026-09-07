//! The miner: build a template, seal it, connect it, announce it.
//!
//! # Three properties, each of which costs money to get wrong
//!
//! 1. **Sealing happens on a blocking thread.** `ConsensusEngine::seal` is a
//!    tight hash loop with no `.await` in it; running it on the async runtime
//!    would starve every other task on that worker, including the one that
//!    tells the miner a new tip arrived.
//! 2. **A new tip cancels the round promptly.** `seal` checks a cancellation
//!    flag every few thousand hashes (SPEC §9.1), so raising the flag stops the
//!    round in microseconds. Without this a node keeps grinding a block whose
//!    parent is already stale — burning real electricity on a block nobody will
//!    accept, and doing it again on the next block and the next.
//! 3. **The payout has a default.** Without `--mine-address` the coinbase pays
//!    an address derived from `<datadir>/node.key`, generated on first run
//!    (CONTRACT §13.1). That is what makes `devnet/up.sh` one command rather
//!    than a wallet-setup ritual.
//!
//! The template is built by `ferrum_chain::build_template`, which fully
//! validates every transaction it includes. A miner that grinds a nonce onto an
//! invalid block has burned that electricity for nothing.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use ferrum_chain::ChainEvent;
use ferrum_consensus::{BlockTemplate, ConsensusEngine};
use ferrum_crypto::Address;
use ferrum_types::{Block, Network, Script};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use crate::error::NodeError;
use crate::node::keys::NodeKey;
use crate::relay::{BlockRelayOutcome, Relay};

/// How long the miner waits before retrying after a round it could not even
/// start — no tip yet, or a template that would not build.
///
/// Short enough that a node which has just finished syncing starts mining
/// promptly, long enough that a persistent failure is not a spin loop.
pub const MINER_RETRY_BACKOFF: Duration = Duration::from_millis(250);

/// How many freshly mined blocks may wait to be announced before the miner
/// starts shedding announcements.
///
/// Small on purpose: if the swarm task is this far behind, the tip has already
/// moved and the stale announcements are worth less than the memory
/// (CONTRACT §10.3).
pub const MINED_BLOCK_CAPACITY: usize = 16;

/// The address the coinbase pays, and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    /// The address itself.
    pub address: Address,
    /// The locking script the coinbase output carries.
    pub script: Script,
    /// Whether it came from `--mine-address` rather than from the node key.
    pub explicit: bool,
}

/// Work out where the coinbase pays.
///
/// `configured` is `--mine-address` (or its environment or file equivalent);
/// when it is absent the node mines to its own key, which is the whole reason
/// `node.key` exists.
///
/// # Errors
///
/// [`NodeError::Crypto`] if the node key cannot be derived, and
/// [`NodeError::Config`] if the configured address belongs to another network —
/// though [`crate::config::resolve`] catches that first, so reaching it here
/// means the config was assembled by hand.
pub fn resolve_payout(
    configured: Option<&Address>,
    key: &NodeKey,
    network: Network,
) -> Result<Payout, NodeError> {
    match configured {
        Some(address) => {
            if address.network != network {
                return Err(NodeError::Config(crate::error::ConfigError::AddressNetworkMismatch {
                    address: address.encode(),
                    address_network: address.network.to_string(),
                    network: network.to_string(),
                }));
            }
            Ok(Payout { address: *address, script: address.script_pubkey(), explicit: true })
        }
        None => {
            let address = key.mining_address(network)?;
            Ok(Payout { address, script: address.script_pubkey(), explicit: false })
        }
    }
}

/// The miner.
///
/// Synchronous, like everything it touches. [`run`] is the async wrapper that
/// owns the blocking thread and the cancellation.
#[derive(Debug)]
pub struct Miner {
    relay: Arc<Relay>,
    payout: Payout,
    extra_nonce: AtomicU64,
}

impl Miner {
    /// Build a miner paying `payout`.
    #[must_use]
    pub fn new(relay: Arc<Relay>, payout: Payout) -> Self {
        Miner { relay, payout, extra_nonce: AtomicU64::new(0) }
    }

    /// Where this miner's coinbase pays.
    #[must_use]
    pub fn payout(&self) -> &Payout {
        &self.payout
    }

    /// The relay this miner submits through.
    #[must_use]
    pub fn relay(&self) -> &Arc<Relay> {
        &self.relay
    }

    /// The extra-nonce this miner will use next.
    ///
    /// The coinbase `script_sig` carries it after the BIP-34 height push, so
    /// two rounds at the same height produce different coinbase txids and
    /// therefore a different merkle root — eight bytes of search space that do
    /// not disturb the block's meaning.
    #[must_use]
    pub fn next_extra_nonce(&self) -> u64 {
        self.extra_nonce.fetch_add(1, Ordering::Relaxed)
    }

    /// Assemble a candidate block from the mempool.
    ///
    /// # Errors
    ///
    /// [`NodeError::Chain`] when there is no tip, or when the template will not
    /// fit inside `max_block_size`.
    pub fn build_template(&self, now_ms: u64) -> Result<BlockTemplate, NodeError> {
        let chain = self.relay.chain();
        let params = chain.params();
        let (_, tip_height) = chain.tip();
        let height = tip_height.saturating_add(1);
        let txs = self.relay.mempool().select_for_block(
            params.max_block_size,
            chain.store().as_ref(),
            height,
        );
        let extra_nonce = self.next_extra_nonce();
        Ok(chain.build_template(&self.payout.script, extra_nonce, txs, now_ms)?)
    }

    /// Build a template and grind it until it is sealed or `cancel` is raised.
    ///
    /// Returns `Ok(None)` when the round was cancelled, which is the normal way
    /// a round ends on a busy network.
    ///
    /// # Errors
    ///
    /// [`NodeError::Chain`] from template assembly and [`NodeError::Consensus`]
    /// from an unusable target.
    pub fn mine_once(&self, cancel: &AtomicBool) -> Result<Option<Block>, NodeError> {
        let now_ms = self.relay.now_ms();
        let template = self.build_template(now_ms)?;
        let height = template.height;
        let chain = self.relay.chain();
        let engine: &dyn ConsensusEngine = chain.engines().engine_for_height(height);
        tracing::debug!(
            height,
            txs = template.txs.len(),
            engine = engine.name(),
            "mining a candidate block"
        );
        Ok(engine.seal(template, cancel)?)
    }

    /// Mine a block and offer it to our own chain.
    ///
    /// The block goes through the same [`Relay`] path as a block from the
    /// network — one implementation of "what it means to accept a block",
    /// including the future-time check, so a node whose clock has jumped
    /// forward refuses its own block instead of announcing one its peers will
    /// reject.
    ///
    /// # Errors
    ///
    /// As [`Miner::mine_once`].
    pub fn mine_and_submit(
        &self,
        cancel: &AtomicBool,
    ) -> Result<Option<(Block, BlockRelayOutcome)>, NodeError> {
        let Some(block) = self.mine_once(cancel)? else {
            return Ok(None);
        };
        self.relay.metrics().block_mined();
        let outcome = self.relay.accept_block(block.clone());
        tracing::info!(
            hash = %outcome.hash,
            verdict = outcome.verdict.name(),
            "mined a block"
        );
        Ok(Some((block, outcome)))
    }
}

/// Run the mining loop until `cancel` fires.
///
/// One round at a time: build, seal on a blocking thread, submit, announce.
/// A [`ChainEvent`] from any source — a peer's block, a sync window connecting,
/// our own previous block — raises the round's cancellation flag, so the next
/// round starts from the new tip.
pub async fn run(
    miner: Arc<Miner>,
    mut tips: broadcast::Receiver<ChainEvent>,
    announce: mpsc::Sender<Block>,
    cancel: CancellationToken,
) {
    tracing::info!(
        address = %miner.payout().address.encode(),
        explicit = miner.payout().explicit,
        "miner started"
    );

    while !cancel.is_cancelled() {
        let flag = Arc::new(AtomicBool::new(false));
        let round_miner = Arc::clone(&miner);
        let round_flag = Arc::clone(&flag);
        let mut task =
            tokio::task::spawn_blocking(move || round_miner.mine_and_submit(&round_flag));

        let mut listening = true;
        let joined = loop {
            tokio::select! {
                joined = &mut task => break joined,
                () = cancel.cancelled() => {
                    flag.store(true, Ordering::Release);
                    break (&mut task).await;
                }
                event = tips.recv(), if listening => match event {
                    Ok(_) => {
                        // A new tip: this round's parent is stale. Stop now
                        // rather than finish a block nobody will accept.
                        flag.store(true, Ordering::Release);
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            skipped,
                            "miner fell behind chain events; restarting the round"
                        );
                        flag.store(true, Ordering::Release);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Nothing will ever cancel this round from outside
                        // again; stop polling a closed channel rather than
                        // spinning on it.
                        listening = false;
                    }
                },
            }
        };

        match joined {
            Ok(Ok(Some((block, outcome)))) => {
                if outcome.should_announce()
                    && let Err(e) = announce.try_send(block)
                {
                    // Bounded, so a full queue sheds with a warning rather than
                    // growing (CONTRACT 10.3).
                    tracing::warn!(
                        capacity = MINED_BLOCK_CAPACITY,
                        error = %e,
                        "mined-block announcement queue is full; shedding"
                    );
                    miner.relay().metrics().shed();
                }
            }
            Ok(Ok(None)) => {
                // Cancelled. Straight into the next round against the new tip.
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "mining round failed");
                tokio::time::sleep(MINER_RETRY_BACKOFF).await;
            }
            Err(e) => {
                tracing::error!(error = %e, "the mining thread died");
                tokio::time::sleep(MINER_RETRY_BACKOFF).await;
            }
        }
    }
    tracing::info!("miner stopped");
}

#[cfg(test)]
mod tests;
