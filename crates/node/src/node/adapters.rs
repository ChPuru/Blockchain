//! The node, as the RPC layer sees it.
//!
//! `ferrum-rpc` reaches the node through three traits and never names a
//! `Store`, a `Mempool` or a `P2pHandle`. `ChainHandle` (the chain one) ships
//! with that crate; the other two live here, because they are the only place
//! the mempool's need for a UTXO view and the swarm's asynchrony meet the
//! RPC's synchronous, view-free interface.
//!
//! Everything here is synchronous except the network trait, which is `async`
//! because the swarm is. The RPC layer runs each synchronous call inside
//! `spawn_blocking` (CONTRACT §7), so nothing in this file may `.await`.

use std::sync::Arc;

use ferrum_p2p::P2pHandle;
use ferrum_rpc::{
    MempoolProvider, MempoolTx, NetworkProvider, NetworkSummary, PeerSummary, RpcError,
    RpcErrorCode,
};
use ferrum_types::{Transaction, Txid};

use crate::relay::Relay;

/// The mempool, as `ferrum-rpc` needs it.
///
/// Wraps the [`Relay`] rather than the pool directly: `sendrawtransaction` must
/// take exactly the same path a gossiped transaction takes — same UTXO view,
/// same tip height, same median time past, same metrics — or the two disagree
/// about what is relayable and only one of them is tested.
#[derive(Debug)]
pub struct MempoolHandle {
    relay: Arc<Relay>,
}

impl MempoolHandle {
    /// Wrap a relay.
    #[must_use]
    pub fn new(relay: Arc<Relay>) -> Self {
        MempoolHandle { relay }
    }
}

impl MempoolProvider for MempoolHandle {
    fn len(&self) -> usize {
        self.relay.mempool().len()
    }

    fn size_bytes(&self) -> usize {
        self.relay.mempool().size_bytes()
    }

    fn max_bytes(&self) -> usize {
        self.relay.mempool().config().max_bytes
    }

    fn min_fee_rate(&self) -> u64 {
        self.relay.mempool().config().min_fee_rate
    }

    fn txids(&self) -> Vec<Txid> {
        self.relay.mempool().txids()
    }

    fn get(&self, txid: &Txid) -> Option<MempoolTx> {
        self.relay.mempool().get(txid).map(|e| MempoolTx {
            tx: e.tx,
            fee: e.fee,
            size: e.size,
            fee_rate: e.fee_rate,
            added_height: e.added_height,
        })
    }

    fn submit(&self, tx: Transaction) -> Result<Txid, RpcError> {
        let outcome = self.relay.accept_transaction(tx);
        match outcome.error {
            None => Ok(outcome.txid),
            Some(e) => Err(RpcError::new(RpcErrorCode::TxRejected, e.to_string())),
        }
    }

    fn select_for_block(&self, max_bytes: usize) -> Vec<Transaction> {
        let chain = self.relay.chain();
        let (_, tip_height) = chain.tip();
        self.relay.mempool().select_for_block(
            max_bytes,
            chain.store().as_ref(),
            tip_height.saturating_add(1),
        )
    }
}

/// The swarm, as `ferrum-rpc` needs it.
#[derive(Debug)]
pub struct NetworkHandle {
    handle: P2pHandle,
    protocol_version: String,
    listen_addresses: Vec<String>,
}

impl NetworkHandle {
    /// Wrap a running p2p service.
    #[must_use]
    pub fn new(handle: P2pHandle, protocol_version: String, listen_addresses: Vec<String>) -> Self {
        NetworkHandle { handle, protocol_version, listen_addresses }
    }

    /// The handle underneath.
    #[must_use]
    pub fn handle(&self) -> &P2pHandle {
        &self.handle
    }
}

#[async_trait::async_trait]
impl NetworkProvider for NetworkHandle {
    async fn peers(&self) -> Vec<PeerSummary> {
        match self.handle.peers().await {
            Ok(peers) => peers
                .into_iter()
                .map(|p| PeerSummary {
                    peer_id: p.peer_id.to_string(),
                    address: p.address.map(|a| a.to_string()),
                    agent_version: p.agent_version,
                    protocol_version: p.protocol_version,
                    last_rtt_ms: p.last_rtt_ms,
                    is_static: p.is_static,
                })
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "getpeerinfo could not reach the swarm");
                Vec::new()
            }
        }
    }

    async fn network_info(&self) -> NetworkSummary {
        let peer_count = self.handle.peers().await.map(|p| p.len()).unwrap_or(0);
        NetworkSummary {
            local_peer_id: self.handle.local_peer_id().to_string(),
            protocol_version: self.protocol_version.clone(),
            listen_addresses: self.listen_addresses.clone(),
            peer_count,
            shed_total: self.handle.shed_counts().total(),
        }
    }

    async fn broadcast_tx(&self, tx: Transaction) -> Result<(), RpcError> {
        self.handle.publish_tx(tx).await.map(|_| ()).map_err(|e| {
            RpcError::new(RpcErrorCode::NetworkUnavailable, format!("publish failed: {e}"))
        })
    }

    async fn broadcast_block(&self, block: ferrum_types::Block) -> Result<(), RpcError> {
        self.handle.publish_block(block).await.map(|_| ()).map_err(|e| {
            RpcError::new(RpcErrorCode::NetworkUnavailable, format!("publish failed: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::Arc;

    use ferrum_chain::ChainManager;
    use ferrum_consensus::EngineRouter;
    use ferrum_mempool::{Mempool, MempoolConfig};
    use ferrum_storage::{Store, StoreConfig};
    use ferrum_types::{ChainParams, Transaction};

    use super::*;
    use crate::relay::{FixedClock, Relay};
    use crate::telemetry::NodeMetrics;

    fn handle() -> MempoolHandle {
        let params = ChainParams::devnet();
        let store = Arc::new(Store::open_in_memory(StoreConfig::default()).unwrap());
        let engines = Arc::new(EngineRouter::new(params.clone()).unwrap());
        let chain = Arc::new(ChainManager::open(store, params.clone(), engines).unwrap());
        chain.init_genesis().unwrap();
        let mempool = Arc::new(Mempool::new(MempoolConfig::new(params)));
        let relay = Arc::new(Relay::new(
            chain,
            mempool,
            Arc::new(NodeMetrics::new()),
            Arc::new(FixedClock::new(1_735_689_720_000)),
        ));
        MempoolHandle::new(relay)
    }

    #[test]
    fn an_empty_pool_reports_itself_honestly() {
        let h = handle();
        assert_eq!(h.len(), 0);
        assert!(h.is_empty());
        assert_eq!(h.size_bytes(), 0);
        assert!(h.txids().is_empty());
        assert_eq!(h.min_fee_rate(), ChainParams::devnet().min_relay_fee_per_kb.to_grains());
        assert!(h.max_bytes() > 0);
    }

    #[test]
    fn the_fee_estimate_defaults_to_the_relay_floor() {
        // A chain whose blocks are never full has no congestion to price, and
        // inventing a number would be worse than saying so.
        let h = handle();
        assert_eq!(h.estimate_fee_rate(1), h.min_fee_rate());
        assert_eq!(h.estimate_fee_rate(100), h.min_fee_rate());
    }

    #[test]
    fn submitting_an_unspendable_transaction_is_refused_with_a_stable_code() {
        let h = handle();
        let e = h.submit(Transaction::default()).unwrap_err();
        assert_eq!(e.code(), RpcErrorCode::TxRejected);
    }

    #[test]
    fn selecting_from_an_empty_pool_yields_nothing() {
        assert!(handle().select_for_block(1_000_000).is_empty());
    }
}
