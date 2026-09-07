//! Wiring and lifecycle: one runtime, five tasks, one cancellation token.
//!
//! # What a node is
//!
//! ```text
//!                       ┌──────────────┐
//!   gossip in ─────────▶│    relay     │──▶ ChainManager ──▶ Store
//!                       │  (verdicts)  │       ▲   │
//!   sync requests ─────▶│              │       │   └──▶ ChainEvent
//!                       └──────────────┘       │              │
//!                              ▲               │              ▼
//!   peers ──▶ SyncManager ─────┘         Miner ┘        broadcast(256)
//! ```
//!
//! Everything that decides whether a block is real goes through
//! [`crate::relay::Relay`], once. The miner's own block takes the same path a
//! gossiped block takes, which is why a node whose clock has jumped forward
//! refuses its own block instead of announcing one its peers will reject.
//!
//! # Shutdown
//!
//! SIGINT or SIGTERM cancels one [`CancellationToken`]; every task selects on
//! it. Then the listeners are stopped, the tasks joined, and **the store is
//! flushed before the process exits** (CONTRACT §13). `redb` writes the head
//! pointer last inside each block's single write transaction, so an unflushed
//! exit is recoverable — but a flush costs milliseconds and turns "recoverable"
//! into "already correct".
//!
//! # Layout
//!
//! | Module | What it owns |
//! |---|---|
//! | [`keys`] | `<datadir>/node.key`, and the two keys derived from it |
//! | [`adapters`] | the mempool and network faces `ferrum-rpc` needs |
//! | [`serve`] | answering inbound sync requests |
//! | [`tasks`] | the long-lived tasks and the bounded queues between them |

pub mod adapters;
pub mod keys;
pub mod serve;
pub mod tasks;

use std::net::SocketAddr;
use std::sync::Arc;

use ferrum_chain::{ChainEvent, ChainManager};
use ferrum_consensus::{BftEngine, EngineRouter, PowEngine};
use ferrum_crypto::SecretKey;
use ferrum_mempool::Mempool;
use ferrum_p2p::{Multiaddr, P2pHandle, P2pService, PeerId};
use ferrum_rpc::{
    ChainHandle, ExplorerServerHandle, NodeContext, RpcServerHandle, spawn_explorer_server,
    spawn_rpc_server,
};

use crate::faucet::NodeKeyFaucetSource;
use ferrum_storage::Store;
use ferrum_types::Block;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub use self::adapters::{MempoolHandle, NetworkHandle};
pub use self::keys::NodeKey;
pub use self::tasks::{CHAIN_EVENT_CAPACITY, METRICS_REFRESH_INTERVAL, SYNC_HINT_CAPACITY};
use crate::config::NodeConfig;
use crate::error::NodeError;
use crate::miner::{self, MINED_BLOCK_CAPACITY, Miner, resolve_payout};
use crate::relay::{Clock, Relay, SystemClock};
use crate::sync::{P2pNetwork, PeerBans, SyncManager, blocking};
use crate::telemetry::{NodeMetrics, install_metrics_exporter};

/// How long shutdown waits for a task to finish before giving up on it.
///
/// A task still running after this has stopped responding to its cancellation
/// token, and waiting longer only delays the store flush that matters.
pub const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// A running Ferrum node.
///
/// Built by [`Node::start`], stopped by [`Node::shutdown`]. Dropping it without
/// shutting down leaves the tasks running until the runtime itself is dropped,
/// so the binary always calls one or the other.
#[derive(Debug)]
pub struct Node {
    config: NodeConfig,
    store: Arc<Store>,
    chain: Arc<ChainManager>,
    mempool: Arc<Mempool>,
    relay: Arc<Relay>,
    metrics: Arc<NodeMetrics>,
    bans: Arc<PeerBans>,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    events: broadcast::Sender<ChainEvent>,
    p2p: Option<P2pHandle>,
    rpc: Option<RpcServerHandle>,
    explorer: Option<ExplorerServerHandle>,
    local_peer_id: PeerId,
    mining_address: Option<String>,
    faucet_address: Option<String>,
}

impl Node {
    /// Open the store, wire everything up and start every task.
    ///
    /// # Errors
    ///
    /// [`NodeError::Io`] when the data directory or the node key cannot be
    /// created, [`NodeError::Storage`] when the store will not open — which is
    /// usually a datadir belonging to another chain — [`NodeError::Chain`] when
    /// genesis does not match, and [`NodeError::P2p`] or [`NodeError::Rpc`]
    /// when a listener cannot bind.
    pub async fn start(config: NodeConfig) -> Result<Self, NodeError> {
        config.ensure_datadir()?;

        // ---- identity ------------------------------------------------------
        let key = NodeKey::load_or_create(&config.node_key_path())?;
        let local_peer_id = key.peer_id()?;
        let keypair = key.p2p_keypair()?;

        // ---- store and chain ----------------------------------------------
        let store_path = config.store_path();
        let store_config = config.store_config();
        let store: Arc<Store> =
            blocking(move || Store::open(&store_path, store_config)).await??.into();

        let engines = Arc::new(build_engines(&config)?);
        let params = config.params.clone();
        let chain = {
            let store = Arc::clone(&store);
            let engines = Arc::clone(&engines);
            Arc::new(blocking(move || ChainManager::open(store, params, engines)).await??)
        };
        {
            let chain = Arc::clone(&chain);
            blocking(move || chain.init_genesis()).await??;
        }
        let (tip, height) = chain.tip();
        tracing::info!(
            network = %config.network,
            datadir = %config.datadir.display(),
            %tip,
            height,
            %local_peer_id,
            "chain opened"
        );

        // ---- mempool, metrics, relay ---------------------------------------
        let mempool = Arc::new(Mempool::new(config.mempool_config()));
        let metrics = Arc::new(NodeMetrics::new());
        metrics.set_height(height);
        if let Some(addr) = config.metrics_listen {
            // Non-fatal: a node that cannot export metrics is still a node, and
            // refusing to start over a busy port would be worse than the
            // missing dashboard.
            if let Err(e) = install_metrics_exporter(addr) {
                tracing::warn!(error = %e, "metrics exporter not installed");
            }
        }
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let relay = Arc::new(Relay::new(
            Arc::clone(&chain),
            Arc::clone(&mempool),
            Arc::clone(&metrics),
            clock,
        ));

        // ---- channels ------------------------------------------------------
        let cancel = CancellationToken::new();
        // Every `?` from here on happens with tasks already running, and those
        // tasks hold `Arc<Store>` clones — which is to say they hold the `redb`
        // file lock on the data directory. Without this guard a start that
        // fails half way (a listen port already in use is the common one)
        // leaves a blocking thread holding that lock for the life of the
        // process, and every later attempt to start on the same datadir fails
        // too: one transient error becomes a permanent one.
        let mut started = StartGuard::armed(cancel.clone());
        let (events, _) = broadcast::channel::<ChainEvent>(CHAIN_EVENT_CAPACITY);
        let (hints, hint_rx) = mpsc::channel::<PeerId>(SYNC_HINT_CAPACITY);
        let (mined, mined_rx) = mpsc::channel::<Block>(MINED_BLOCK_CAPACITY);
        let bans = Arc::new(PeerBans::new());
        let mut handles: Vec<JoinHandle<()>> = Vec::new();

        handles.push(tasks::spawn_chain_event_bridge(
            Arc::clone(&chain),
            events.clone(),
            cancel.clone(),
        ));

        // ---- p2p, sync, announce -------------------------------------------
        let (handle, listen_addrs) =
            start_p2p(&config, keypair, &relay, &chain, &bans, &hints, &cancel, &mut handles)?;

        let sync = Arc::new(SyncManager::new(
            Arc::clone(&relay),
            Arc::new(P2pNetwork::new(handle.clone())),
            Arc::clone(&bans),
        ));
        handles.push(tokio::spawn(crate::sync::run(sync, hint_rx, cancel.clone())));
        handles.push(tokio::spawn(tasks::announce_blocks(
            handle.clone(),
            mined_rx,
            cancel.clone(),
        )));
        handles.push(tokio::spawn(tasks::refresh_metrics(
            Arc::clone(&relay),
            Some(handle.clone()),
            Arc::clone(&metrics),
            cancel.clone(),
        )));
        let p2p = Some(handle);

        // ---- rpc and explorer ----------------------------------------------
        let mut ctx =
            NodeContext::new(Arc::new(ChainHandle::new(Arc::clone(&chain), config.index)))
                .with_mempool(Arc::new(MempoolHandle::new(Arc::clone(&relay))));
        if let Some(handle) = &p2p {
            ctx = ctx.with_network(Arc::new(NetworkHandle::new(
                handle.clone(),
                ferrum_p2p::PROTOCOL_VERSION.to_owned(),
                listen_addrs.iter().map(Multiaddr::to_string).collect(),
            )));
        }
        // The faucet draws on the node's own key — see `crate::faucet` for why
        // that is the funding source. Without this the `--faucet` flag, the
        // `explorer.faucet` config field and the devnet default all resolve to
        // `true` and then reach nothing, and `POST /api/faucet` answers
        // "faucet disabled" on every network.
        let faucet_address = if config.faucet {
            let source = Arc::new(NodeKeyFaucetSource::new(
                key.mining_secret()?,
                key.mining_address(config.network)?,
                Arc::clone(ctx.chain()),
                config.params.chain_id,
                ferrum_wallet::dust_threshold(config.params.min_relay_fee_per_kb),
                config.params.coinbase_maturity,
                ferrum_rpc::DEFAULT_FAUCET_FEE_RATE,
            ));
            let address = source.address().encode();
            let mut faucet_config = ferrum_rpc::FaucetConfig::default();
            if let Some(amount) = config.faucet_amount {
                faucet_config = faucet_config.with_amount(amount);
            }
            ctx = ctx.with_faucet(Arc::new(ferrum_rpc::Faucet::new(faucet_config, source)));
            tracing::info!(
                address = %address,
                amount = %faucet_config.amount.to_frm_string(),
                "faucet enabled"
            );
            Some(address)
        } else {
            None
        };

        let rpc = Some(spawn_rpc_server(config.rpc_server_config(), ctx.clone()).await?);
        let explorer = Some(spawn_explorer_server(config.explorer_server_config(), ctx).await?);

        // ---- miner ----------------------------------------------------------
        let mining_address = if config.mine {
            let payout = resolve_payout(config.mine_address.as_ref(), &key, config.network)?;
            let address = payout.address.encode();
            let miner = Arc::new(Miner::new(Arc::clone(&relay), payout));
            handles.push(tokio::spawn(miner::run(
                miner,
                events.subscribe(),
                mined,
                cancel.clone(),
            )));
            Some(address)
        } else {
            drop(mined);
            None
        };

        started.disarm();
        Ok(Node {
            config,
            store,
            chain,
            mempool,
            relay,
            metrics,
            bans,
            cancel,
            tasks: handles,
            events,
            p2p,
            rpc,
            explorer,
            local_peer_id,
            mining_address,
            faucet_address,
        })
    }

    /// The configuration this node was started with.
    #[must_use]
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// The chain.
    #[must_use]
    pub fn chain(&self) -> &Arc<ChainManager> {
        &self.chain
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The mempool.
    #[must_use]
    pub fn mempool(&self) -> &Arc<Mempool> {
        &self.mempool
    }

    /// The relay every block and transaction goes through.
    #[must_use]
    pub fn relay(&self) -> &Arc<Relay> {
        &self.relay
    }

    /// The counters.
    #[must_use]
    pub fn metrics(&self) -> &Arc<NodeMetrics> {
        &self.metrics
    }

    /// Peers banned for serving invalid data.
    #[must_use]
    pub fn bans(&self) -> &Arc<PeerBans> {
        &self.bans
    }

    /// The swarm handle, when networking is running.
    #[must_use]
    pub fn p2p(&self) -> Option<&P2pHandle> {
        self.p2p.as_ref()
    }

    /// This node's libp2p identity, stable across restarts.
    #[must_use]
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// The address the miner pays, when mining.
    #[must_use]
    pub fn mining_address(&self) -> Option<&str> {
        self.mining_address.as_deref()
    }

    /// The address the faucet pays from, or `None` when no faucet is served.
    ///
    /// An operator funding a faucet on a node that mines elsewhere needs this
    /// address, so it is reachable rather than only logged.
    #[must_use]
    pub fn faucet_address(&self) -> Option<&str> {
        self.faucet_address.as_deref()
    }

    /// The address the JSON-RPC listener actually bound.
    #[must_use]
    pub fn rpc_addr(&self) -> Option<SocketAddr> {
        self.rpc.as_ref().map(RpcServerHandle::local_addr)
    }

    /// The address the explorer actually bound.
    #[must_use]
    pub fn explorer_addr(&self) -> Option<SocketAddr> {
        self.explorer.as_ref().map(ExplorerServerHandle::local_addr)
    }

    /// Subscribe to chain events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<ChainEvent> {
        self.events.subscribe()
    }

    /// The token every task selects on.
    #[must_use]
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Run until SIGINT, SIGTERM or an external cancellation, then shut down.
    ///
    /// # Errors
    ///
    /// Whatever [`Node::shutdown`] returns.
    pub async fn run(self) -> Result<(), NodeError> {
        let cancel = self.cancel.clone();
        wait_for_shutdown_signal(cancel).await;
        self.shutdown().await
    }

    /// Stop every task, close every listener, and flush the store.
    ///
    /// Idempotent in effect: cancelling an already-cancelled token is a no-op,
    /// and flushing a flushed store is cheap.
    ///
    /// # Errors
    ///
    /// [`NodeError::Storage`] if the final flush fails, which is the one
    /// failure worth reporting: everything else has already been logged and
    /// nothing can be done about it at this point.
    pub async fn shutdown(mut self) -> Result<(), NodeError> {
        tracing::info!("shutting down");
        self.cancel.cancel();

        if let Some(p2p) = &self.p2p
            && let Err(e) = p2p.shutdown()
        {
            tracing::debug!(error = %e, "p2p service was already stopping");
        }
        if let Some(rpc) = self.rpc.take() {
            rpc.stop();
        }
        if let Some(explorer) = self.explorer.take() {
            explorer.stopped().await;
        }

        for task in self.tasks.drain(..) {
            match tokio::time::timeout(SHUTDOWN_GRACE, task).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) if e.is_cancelled() => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "a task ended abnormally"),
                Err(_) => tracing::warn!(
                    grace = ?SHUTDOWN_GRACE,
                    "a task did not stop in time; continuing to the flush"
                ),
            }
        }

        // The store is flushed last and always. `redb` writes the head pointer
        // last inside each block's single write transaction, so an unflushed
        // exit is recoverable — but this turns "recoverable" into "correct".
        let store = Arc::clone(&self.store);
        blocking(move || store.flush()).await??;
        tracing::info!("store flushed; goodbye");
        Ok(())
    }
}

/// Cancels a half-started node's tasks when [`Node::start`] fails part way.
///
/// Armed for the whole of `start` and disarmed only when a `Node` is about to
/// be returned, so the failure path — which is every `?` after the first task
/// is spawned — always cancels. Cancellation is what releases the store: each
/// task drops its `Arc<Store>` when it notices, and the last one to drop
/// releases the `redb` file lock.
struct StartGuard {
    /// The token every task of the half-built node selects on.
    cancel: CancellationToken,
    /// Whether dropping this guard should cancel.
    armed: bool,
}

impl StartGuard {
    /// A guard that will cancel unless it is disarmed.
    fn armed(cancel: CancellationToken) -> Self {
        StartGuard { cancel, armed: true }
    }

    /// The node was built; leave its tasks alone.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StartGuard {
    fn drop(&mut self) {
        if self.armed {
            tracing::warn!("node start-up failed; cancelling the tasks it had already started");
            self.cancel.cancel();
        }
    }
}

/// Build the engine router, honouring `--consensus` and `--validator-key`.
fn build_engines(config: &NodeConfig) -> Result<EngineRouter, NodeError> {
    let params = config.params.clone();
    let bft = if params.bft_activation_height.is_some() || config.validator_key.is_some() {
        let signing_key = match &config.validator_key {
            Some(path) => Some(load_validator_key(path)?),
            None => None,
        };
        Some(BftEngine::new(params.clone(), signing_key)?)
    } else {
        None
    };
    let router = EngineRouter::with_engines(params.clone(), PowEngine::new(params), bft)?;
    match config.consensus {
        Some(choice) => Ok(router.force_engine(choice.engine_id())?),
        None => Ok(router),
    }
}

/// Read a BFT signing key from `--validator-key`.
///
/// Two shapes are accepted, because two tools write this file:
///
/// - **32 hex-encoded bytes**, the same shape as `node.key`, for an operator
///   who generated the scalar directly.
/// - **A BIP-39 mnemonic**, which is what `chain-cli wallet new --output FILE`
///   writes (CONTRACT §13.1) and what `devnet/fork.sh` feeds straight back in.
///   The signing key is then `m/44'/7767'/0'/0/0`, the same path
///   `chain-cli wallet dump-pubkey` reports a public key for, so the validator
///   set in the consensus config matches the keys the nodes actually sign with.
///
/// Guessing between the two is safe: a 64-character hex string is never a valid
/// mnemonic, and a mnemonic is never valid hex.
///
/// # Errors
///
/// [`NodeError::Io`] with an `InvalidData` kind when the file is neither.
fn load_validator_key(path: &std::path::Path) -> Result<SecretKey, NodeError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| NodeError::io(format!("reading the validator key {}", path.display()), e))?;
    parse_validator_key(&text, path)
}

/// [`load_validator_key`] over text already read, so it can be tested without a
/// file.
///
/// # Errors
///
/// [`NodeError::Io`] with an `InvalidData` kind when the text is neither 32 hex
/// bytes nor a valid mnemonic.
pub fn parse_validator_key(text: &str, path: &std::path::Path) -> Result<SecretKey, NodeError> {
    let trimmed = text.trim();
    let hex_body = trimmed.strip_prefix("0x").unwrap_or(trimmed);

    if let Ok(bytes) = hex::decode(hex_body)
        && let Ok(array) = <[u8; 32]>::try_from(bytes.as_slice())
    {
        return Ok(SecretKey::from_bytes(&array)?);
    }

    if let Ok(mnemonic) = ferrum_crypto::Mnemonic::from_phrase(trimmed) {
        let mut seed = mnemonic.to_seed("");
        let key = keys::derive_receive_key(&seed, 0);
        ferrum_crypto::zeroize_seed(&mut seed);
        return key;
    }

    Err(NodeError::io(
        format!("reading the validator key {}", path.display()),
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected 32 hex-encoded bytes or a BIP-39 mnemonic",
        ),
    ))
}

/// Start the swarm and the event loop that drives it.
///
/// Binding happens here rather than inside a detached task, so a listen address
/// that is already in use is a startup error with a message instead of a node
/// that appears healthy and never sees a peer.
#[allow(clippy::too_many_arguments)]
fn start_p2p(
    config: &NodeConfig,
    keypair: ferrum_p2p::Keypair,
    relay: &Arc<Relay>,
    chain: &Arc<ChainManager>,
    bans: &Arc<PeerBans>,
    hints: &mpsc::Sender<PeerId>,
    cancel: &CancellationToken,
    handles: &mut Vec<JoinHandle<()>>,
) -> Result<(P2pHandle, Vec<Multiaddr>), NodeError> {
    let p2p_config = config.p2p_config(keypair);
    let listen_addrs = p2p_config.listen_addrs.clone();
    let (handle, swarm) = P2pService::spawn(p2p_config)?;
    let events = handle.events()?;

    // The swarm task owns itself; wrap it so the node's join list is uniform.
    handles.push(tokio::spawn(async move {
        if let Err(e) = swarm.await {
            tracing::warn!(error = %e, "the swarm task ended abnormally");
        }
    }));

    handles.push(tokio::spawn(tasks::run_p2p(
        tasks::P2pLoop {
            relay: Arc::clone(relay),
            chain: Arc::clone(chain),
            handle: handle.clone(),
            hints: hints.clone(),
            bans: Arc::clone(bans),
            metrics: Arc::clone(relay.metrics()),
        },
        events,
        cancel.clone(),
    )));

    Ok((handle, listen_addrs))
}

/// Wait for SIGINT or SIGTERM, or for someone else to cancel the token.
///
/// Both signals are handled: `Ctrl-C` in a terminal and `systemctl stop` must
/// take the same path, or one of the two skips the store flush.
pub async fn wait_for_shutdown_signal(cancel: CancellationToken) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "SIGTERM handler unavailable; Ctrl-C only");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT"),
                    () = cancel.cancelled() => {}
                }
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT received"),
            _ = term.recv() => tracing::info!("SIGTERM received"),
            () = cancel.cancelled() => {}
        }
    }

    #[cfg(windows)]
    {
        use tokio::signal::windows;
        // `ctrl_close` and `ctrl_shutdown` are the console equivalents of
        // SIGTERM: without them a node closed by its window button skips the
        // store flush.
        let mut close = windows::ctrl_close().ok();
        let mut shutdown = windows::ctrl_shutdown().ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::info!("Ctrl-C received"),
            _ = async {
                match close.as_mut() {
                    Some(s) => { s.recv().await; }
                    None => std::future::pending().await,
                }
            } => tracing::info!("console close received"),
            _ = async {
                match shutdown.as_mut() {
                    Some(s) => { s.recv().await; }
                    None => std::future::pending().await,
                }
            } => tracing::info!("system shutdown received"),
            () = cancel.cancelled() => {}
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::info!("interrupt received"),
            () = cancel.cancelled() => {}
        }
    }
}

#[cfg(test)]
mod tests;
