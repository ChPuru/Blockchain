//! The three seams between this crate and the running node.
//!
//! `ferrum-rpc` never reaches into a `Store`, a `ChainManager`, a mempool or a
//! libp2p swarm directly. It talks to [`ChainProvider`], [`MempoolProvider`]
//! and [`NetworkProvider`], and the node supplies implementations. Three
//! reasons, in order of how much they matter:
//!
//! 1. **Every handler is testable against an in-memory fixture.** The test
//!    suite builds a real store and a real chain, but a handler could equally
//!    be driven by a hand-written stub, and the faucet tests do exactly that.
//! 2. **The JSON shape is a deliberate interface rather than an accident of
//!    internal layout.** A serde `derive` on a consensus struct makes every
//!    field rename a client-breaking change; a DTO layer over a narrow trait
//!    makes it a local edit.
//! 3. **The node owns the lifecycle.** The mempool is shared with the miner and
//!    the gossip handler, the network handle is owned by the p2p task, and the
//!    chain is behind an acceptance mutex. Handing this crate `Arc<dyn Trait>`
//!    keeps all of that where it belongs.
//!
//! # Everything here is synchronous, on purpose
//!
//! `ferrum-storage` is synchronous, so these traits are too — with the single
//! exception of [`NetworkProvider`], which asks a running libp2p task a
//! question over a channel and is therefore `async`. Async handlers reach the
//! synchronous traits through [`crate::context::blocking`], which is
//! `tokio::task::spawn_blocking`. A `redb` read on a Tokio worker thread parks
//! that worker for the duration of the I/O: a two-second p95 latency bug that
//! shows up under load and never in a test.
//!
//! # `MempoolProvider` and `ferrum-mempool`
//!
//! This crate deliberately does **not** depend on `ferrum-mempool`. The node
//! writes a five-line adapter from `ferrum_mempool::Mempool` to
//! [`MempoolProvider`]; in exchange, the RPC surface compiles, tests and
//! evolves independently of mempool internals, and a node that runs without a
//! mempool at all (a pure archive node) wires [`NoMempool`] instead.

use ferrum_consensus::BlockTemplate;
use ferrum_storage::{BlockIndexEntry, TxLocation};
use ferrum_types::{
    Amount, Block, BlockHash, ChainParams, Coin, Hash32, OutPoint, Script, Transaction, Txid,
};

use crate::error::{RpcError, RpcErrorCode};

/// What happened to a block handed to [`ChainProvider::submit_block`].
///
/// Mirrors `ferrum_chain::AcceptOutcome` without leaking it: the counts, not
/// the hash lists, are what a `submitblock` caller can act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// The block became the new tip on top of the old one.
    Extended(BlockHash),
    /// The block won fork choice and the chain reorganised onto it.
    Reorged {
        /// The tip that was abandoned.
        from: BlockHash,
        /// The new tip.
        to: BlockHash,
        /// How many blocks were disconnected.
        disconnected: usize,
        /// How many blocks were connected.
        connected: usize,
    },
    /// Valid, stored, but it did not beat the current tip.
    SideChain(BlockHash),
    /// Already known.
    Duplicate,
    /// Its parent is unknown; it is held, not rejected.
    Orphan,
}

impl SubmitOutcome {
    /// The stable lowercase tag that goes on the wire.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            SubmitOutcome::Extended(_) => "extended",
            SubmitOutcome::Reorged { .. } => "reorged",
            SubmitOutcome::SideChain(_) => "side_chain",
            SubmitOutcome::Duplicate => "duplicate",
            SubmitOutcome::Orphan => "orphan",
        }
    }

    /// Whether the block became part of the active chain.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, SubmitOutcome::Extended(_) | SubmitOutcome::Reorged { .. })
    }

    /// The block's hash, when the outcome names one.
    #[must_use]
    pub const fn hash(&self) -> Option<BlockHash> {
        match self {
            SubmitOutcome::Extended(h) | SubmitOutcome::SideChain(h) => Some(*h),
            SubmitOutcome::Reorged { to, .. } => Some(*to),
            SubmitOutcome::Duplicate | SubmitOutcome::Orphan => None,
        }
    }
}

/// One transaction as the mempool holds it.
///
/// A copy of the fields the RPC surface publishes rather than a re-export of
/// `ferrum_mempool::MempoolEntry`; see the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolTx {
    /// The transaction itself.
    pub tx: Transaction,
    /// Fee paid, in grains.
    pub fee: Amount,
    /// Serialized envelope size, in bytes.
    pub size: usize,
    /// Grains per 1000 bytes.
    pub fee_rate: u64,
    /// The tip height when it was accepted.
    pub added_height: u64,
}

/// A connected peer, flattened for `getpeerinfo`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerSummary {
    /// The peer's libp2p identity, base58.
    pub peer_id: String,
    /// The multiaddr of the most recent connection.
    pub address: Option<String>,
    /// Agent string from identify.
    pub agent_version: Option<String>,
    /// Protocol version from identify.
    pub protocol_version: Option<String>,
    /// Last round-trip time in **integer** milliseconds.
    pub last_rtt_ms: Option<u64>,
    /// Whether the peer is in the configured static list.
    pub is_static: bool,
}

/// What `getnetworkinfo` reports about the local node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkSummary {
    /// The local libp2p identity, base58.
    pub local_peer_id: String,
    /// The protocol version this build speaks.
    pub protocol_version: String,
    /// Addresses the node is listening on.
    pub listen_addresses: Vec<String>,
    /// Number of connected peers.
    pub peer_count: usize,
    /// Messages dropped by the load-shedding queues since start.
    pub shed_total: u64,
}

/// Read and write access to the chain, its store and its engines.
///
/// Implemented by [`crate::adapters::ChainHandle`] over a real
/// `ferrum_chain::ChainManager`; the tests use that same implementation over an
/// in-memory store, so nothing in the handler layer is exercised only by a
/// mock.
pub trait ChainProvider: Send + Sync + std::fmt::Debug + 'static {
    /// The parameters this chain validates against.
    fn params(&self) -> &ChainParams;

    /// The active tip and its height.
    ///
    /// # Errors
    /// Storage failures only; an empty store reports height 0 with the zero
    /// hash rather than an error, because "no genesis yet" is a state the
    /// explorer must be able to render.
    fn tip(&self) -> Result<(BlockHash, u64), RpcError>;

    /// Cumulative work at the tip, big-endian.
    ///
    /// # Errors
    /// Storage failures.
    fn tip_work(&self) -> Result<[u8; 32], RpcError>;

    /// Which engine seals a block at `height` (`BlockSeal::ENGINE_*`).
    fn engine_id_at(&self, height: u64) -> u8;

    /// The height below which reorgs are impossible, if the active engine
    /// provides finality. `None` under proof of work: nothing is ever final.
    fn finalized_height(&self) -> Option<u64>;

    /// Whether the `tx_index`/`addr_index` reverse index is maintained.
    fn index_enabled(&self) -> bool;

    /// A full block by hash.
    ///
    /// # Errors
    /// Storage failures.
    fn block(&self, hash: &BlockHash) -> Result<Option<Block>, RpcError>;

    /// A block's index entry — header, height, work, status, size.
    ///
    /// # Errors
    /// Storage failures.
    fn header_entry(&self, hash: &BlockHash) -> Result<Option<BlockIndexEntry>, RpcError>;

    /// The active-chain hash at `height`.
    ///
    /// # Errors
    /// Storage failures.
    fn hash_at_height(&self, height: u64) -> Result<Option<BlockHash>, RpcError>;

    /// An unspent output.
    ///
    /// # Errors
    /// Storage failures.
    fn coin(&self, out_point: &OutPoint) -> Result<Option<Coin>, RpcError>;

    /// How many entries the UTXO set holds.
    ///
    /// # Errors
    /// Storage failures.
    fn utxo_count(&self) -> Result<u64, RpcError>;

    /// The Merkle root over the whole UTXO set at the tip.
    ///
    /// # Errors
    /// Storage failures.
    fn state_root(&self) -> Result<Hash32, RpcError>;

    /// Where a transaction was confirmed. Needs the reverse index.
    ///
    /// # Errors
    /// [`RpcErrorCode::IndexDisabled`] without the index, storage failures
    /// otherwise.
    fn tx_location(&self, txid: &Txid) -> Result<Option<TxLocation>, RpcError>;

    /// Ascending `(height, txid)` pairs for an address key. Needs the index.
    ///
    /// # Errors
    /// [`RpcErrorCode::IndexDisabled`] without the index, storage failures
    /// otherwise.
    fn address_history(
        &self,
        key: &[u8],
        from_height: u64,
        limit: usize,
    ) -> Result<Vec<(u64, Txid)>, RpcError>;

    /// Every unspent coin locked by one of `scripts`.
    ///
    /// Scans the UTXO set, so it needs no index — which is what lets the faucet
    /// wallet work on a node started without one.
    ///
    /// # Errors
    /// Storage failures.
    fn utxos_for_scripts(&self, scripts: &[Script]) -> Result<Vec<(OutPoint, Coin)>, RpcError>;

    /// Validate and, if it wins fork choice, connect a block.
    ///
    /// # Errors
    /// [`RpcErrorCode::BlockRejected`] when the block breaks a rule.
    fn submit_block(&self, block: Block) -> Result<SubmitOutcome, RpcError>;

    /// Assemble a candidate block paying `payout`.
    ///
    /// # Errors
    /// [`RpcErrorCode::TemplateFailed`] when assembly fails.
    fn build_template(
        &self,
        payout: &Script,
        extra_nonce: u64,
        txs: Vec<Transaction>,
        now_ms: u64,
    ) -> Result<BlockTemplate, RpcError>;
}

/// The transaction pool, as the RPC surface needs it.
pub trait MempoolProvider: Send + Sync + std::fmt::Debug + 'static {
    /// How many transactions are held.
    fn len(&self) -> usize;

    /// Whether the pool is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total serialized size of the pool, in bytes.
    fn size_bytes(&self) -> usize;

    /// The configured byte budget.
    fn max_bytes(&self) -> usize;

    /// The configured floor, in grains per 1000 bytes.
    fn min_fee_rate(&self) -> u64;

    /// Every held transaction id, in a deterministic order.
    fn txids(&self) -> Vec<Txid>;

    /// One held transaction.
    fn get(&self, txid: &Txid) -> Option<MempoolTx>;

    /// Offer a transaction to the pool.
    ///
    /// # Errors
    /// [`RpcErrorCode::TxRejected`] when policy or validation refuses it.
    fn submit(&self, tx: Transaction) -> Result<Txid, RpcError>;

    /// Fee-ordered selection for a block template, respecting dependencies.
    fn select_for_block(&self, max_bytes: usize) -> Vec<Transaction>;

    /// A fee estimate for confirmation within `blocks`, in grains per 1000
    /// bytes.
    ///
    /// The default returns the relay floor, which is the honest answer for a
    /// chain whose blocks are never full: there is no congestion to price.
    fn estimate_fee_rate(&self, _blocks: u64) -> u64 {
        self.min_fee_rate()
    }
}

/// The peer-to-peer service, as the RPC surface needs it.
#[async_trait::async_trait]
pub trait NetworkProvider: Send + Sync + std::fmt::Debug + 'static {
    /// Currently connected peers.
    async fn peers(&self) -> Vec<PeerSummary>;

    /// Local identity and listen addresses.
    async fn network_info(&self) -> NetworkSummary;

    /// Announce a transaction on the gossip topic.
    ///
    /// # Errors
    /// [`RpcErrorCode::NetworkUnavailable`] when the swarm is gone. A failure
    /// here does **not** mean the transaction was rejected: it is already in
    /// the local mempool and will be relayed on the next reconnect.
    async fn broadcast_tx(&self, tx: Transaction) -> Result<(), RpcError>;

    /// Announce a block on the gossip topic.
    ///
    /// # Errors
    /// [`RpcErrorCode::NetworkUnavailable`] when the swarm is gone.
    async fn broadcast_block(&self, block: Block) -> Result<(), RpcError>;
}

/// The mempool of a node that has none.
///
/// Every query answers "empty" and every submission is refused with
/// [`RpcErrorCode::MempoolUnavailable`], which is honest: a node without a
/// mempool cannot relay, and silently accepting a transaction it will never
/// broadcast is worse than saying so.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoMempool;

impl MempoolProvider for NoMempool {
    fn len(&self) -> usize {
        0
    }

    fn size_bytes(&self) -> usize {
        0
    }

    fn max_bytes(&self) -> usize {
        0
    }

    fn min_fee_rate(&self) -> u64 {
        0
    }

    fn txids(&self) -> Vec<Txid> {
        Vec::new()
    }

    fn get(&self, _txid: &Txid) -> Option<MempoolTx> {
        None
    }

    fn submit(&self, _tx: Transaction) -> Result<Txid, RpcError> {
        Err(RpcError::new(
            RpcErrorCode::MempoolUnavailable,
            "this node runs no mempool and cannot relay transactions",
        ))
    }

    fn select_for_block(&self, _max_bytes: usize) -> Vec<Transaction> {
        Vec::new()
    }
}

/// The network of a node that is not connected to one.
///
/// Used by `chaind` before the swarm is up, and by every test that does not
/// care about peers.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoNetwork;

#[async_trait::async_trait]
impl NetworkProvider for NoNetwork {
    async fn peers(&self) -> Vec<PeerSummary> {
        Vec::new()
    }

    async fn network_info(&self) -> NetworkSummary {
        NetworkSummary::default()
    }

    async fn broadcast_tx(&self, _tx: Transaction) -> Result<(), RpcError> {
        Err(RpcError::new(
            RpcErrorCode::NetworkUnavailable,
            "no peer-to-peer service is attached to this node",
        ))
    }

    async fn broadcast_block(&self, _block: Block) -> Result<(), RpcError> {
        Err(RpcError::new(
            RpcErrorCode::NetworkUnavailable,
            "no peer-to-peer service is attached to this node",
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn submit_outcome_tags_are_stable() {
        let h = BlockHash::ZERO;
        assert_eq!(SubmitOutcome::Extended(h).tag(), "extended");
        assert_eq!(
            SubmitOutcome::Reorged { from: h, to: h, disconnected: 1, connected: 2 }.tag(),
            "reorged"
        );
        assert_eq!(SubmitOutcome::SideChain(h).tag(), "side_chain");
        assert_eq!(SubmitOutcome::Duplicate.tag(), "duplicate");
        assert_eq!(SubmitOutcome::Orphan.tag(), "orphan");
    }

    #[test]
    fn only_extended_and_reorged_count_as_accepted() {
        let h = BlockHash::ZERO;
        assert!(SubmitOutcome::Extended(h).is_accepted());
        assert!(SubmitOutcome::Reorged { from: h, to: h, disconnected: 0, connected: 1 }
            .is_accepted());
        assert!(!SubmitOutcome::SideChain(h).is_accepted());
        assert!(!SubmitOutcome::Duplicate.is_accepted());
        assert!(!SubmitOutcome::Orphan.is_accepted());
    }

    #[test]
    fn no_mempool_refuses_rather_than_pretending() {
        let pool = NoMempool;
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.estimate_fee_rate(6), 0);
        let err = pool.submit(Transaction::empty()).unwrap_err();
        assert_eq!(err.code(), RpcErrorCode::MempoolUnavailable);
    }

    #[tokio::test]
    async fn no_network_reports_no_peers_and_refuses_broadcast() {
        let net = NoNetwork;
        assert!(net.peers().await.is_empty());
        assert_eq!(net.network_info().await.peer_count, 0);
        let err = net.broadcast_tx(Transaction::empty()).await.unwrap_err();
        assert_eq!(err.code(), RpcErrorCode::NetworkUnavailable);
    }
}
