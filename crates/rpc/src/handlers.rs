//! The handler layer: one synchronous function per query, and the async
//! `jsonrpsee` implementation that wraps them.
//!
//! # The shape every method has
//!
//! ```text
//! async fn get_thing(&self, arg) -> RpcResult<Thing> {
//!     let (chain, mempool) = self.ctx.handles();   // clone the Arcs
//!     Ok(blocking(move || thing::build(&*chain, &*mempool, arg)).await?)
//! }
//! ```
//!
//! One `spawn_blocking` per request, not one per storage read: a page that
//! touches thirty coins crosses the thread boundary once. The synchronous
//! function underneath is a plain function over `&dyn ChainProvider`, which is
//! what makes it directly testable without a runtime.
//!
//! # Layout
//!
//! | Module | Methods |
//! |---|---|
//! | [`chain`] | `getblockchaininfo`, `getblockhash`, `getblock`, `getblockheader`, `getstateroot` |
//! | [`tx`] | `getrawtransaction`, `gettxout`, `getmempoolinfo`, `getrawmempool`, `estimatefee` |
//! | [`mining`] | `getblocktemplate`, `submitblock` |
//! | [`address`] | `getbalance`, `listunspent` |
//! | [`explorer`] | the five REST payloads |
//! | [`convert`] | consensus types to DTOs |
//! | [`lookup`] | shared chain lookups |

pub mod address;
pub mod chain;
pub mod convert;
pub mod explorer;
pub mod lookup;
pub mod mining;
pub mod tx;

use jsonrpsee::core::{RpcResult, async_trait};

use crate::api::FerrumRpcServer;
use crate::context::{NodeContext, blocking, now_ms};
use crate::error::{RpcError, parse_hash32};
use crate::types::Grains;
use crate::types::rpc::{
    AddressBalance, BlockHeaderInfo, BlockchainInfo, CoinJson, GetBlockResult,
    GetRawTransactionResult, MempoolInfo, NetworkInfoJson, PeerJson, RawMempoolResult,
    SubmitBlockResult, TemplateJson, UnspentJson,
};

/// The `jsonrpsee` server implementation.
///
/// Holds nothing but a [`NodeContext`], so it is cheap to clone and safe to
/// share between the HTTP and WebSocket listeners.
#[derive(Clone, Debug)]
pub struct FerrumRpcImpl {
    ctx: NodeContext,
}

impl FerrumRpcImpl {
    /// Wrap a node context.
    #[must_use]
    pub fn new(ctx: NodeContext) -> Self {
        FerrumRpcImpl { ctx }
    }

    /// The context underneath.
    #[must_use]
    pub fn context(&self) -> &NodeContext {
        &self.ctx
    }
}

#[async_trait]
impl FerrumRpcServer for FerrumRpcImpl {
    async fn get_blockchain_info(&self) -> RpcResult<BlockchainInfo> {
        let (chain, mempool) = self.ctx.handles();
        Ok(blocking(move || chain::blockchain_info(&*chain, &*mempool)).await?)
    }

    async fn get_block_hash(&self, height: u64) -> RpcResult<String> {
        let chain = std::sync::Arc::clone(self.ctx.chain());
        Ok(blocking(move || chain::block_hash_at(&*chain, height)).await?)
    }

    async fn get_block(&self, hash: String, verbosity: Option<u8>) -> RpcResult<GetBlockResult> {
        let chain = std::sync::Arc::clone(self.ctx.chain());
        let verbosity = verbosity.unwrap_or(1);
        Ok(blocking(move || {
            let hash = ferrum_types::BlockHash(parse_hash32(&hash)?);
            chain::get_block(&*chain, &hash, verbosity)
        })
        .await?)
    }

    async fn get_block_header(&self, hash: String) -> RpcResult<BlockHeaderInfo> {
        let chain = std::sync::Arc::clone(self.ctx.chain());
        Ok(blocking(move || {
            let hash = ferrum_types::BlockHash(parse_hash32(&hash)?);
            chain::get_block_header(&*chain, &hash)
        })
        .await?)
    }

    async fn get_raw_transaction(
        &self,
        txid: String,
        verbose: Option<bool>,
    ) -> RpcResult<GetRawTransactionResult> {
        let (chain, mempool) = self.ctx.handles();
        let verbose = verbose.unwrap_or(false);
        Ok(blocking(move || {
            let txid = ferrum_types::Txid(parse_hash32(&txid)?);
            tx::get_raw_transaction(&*chain, &*mempool, &txid, verbose)
        })
        .await?)
    }

    async fn send_raw_transaction(&self, hex: String) -> RpcResult<String> {
        let mempool = std::sync::Arc::clone(self.ctx.mempool());
        let decoded = blocking(move || {
            let transaction = tx::decode_tx_hex(&hex)?;
            let txid = mempool.submit(transaction.clone())?;
            Ok((txid, transaction))
        })
        .await?;
        let (txid, transaction) = decoded;

        // Relay is best effort. The transaction is already in the local
        // mempool, so a network that is down means "not announced yet", not
        // "rejected" — telling the sender it failed would make them send it
        // again and hit the double-spend rule.
        if let Err(e) = self.ctx.network().broadcast_tx(transaction).await {
            tracing::warn!(txid = %txid, error = %e, "accepted locally but not announced");
        }
        Ok(txid.to_hex())
    }

    async fn get_tx_out(&self, txid: String, vout: u32) -> RpcResult<Option<CoinJson>> {
        let chain = std::sync::Arc::clone(self.ctx.chain());
        Ok(blocking(move || {
            let txid = ferrum_types::Txid(parse_hash32(&txid)?);
            tx::get_tx_out(&*chain, &txid, vout)
        })
        .await?)
    }

    async fn get_block_template(&self, payout_address: String) -> RpcResult<TemplateJson> {
        let (chain, mempool) = self.ctx.handles();
        let now = now_ms();
        Ok(blocking(move || {
            mining::block_template(&*chain, &*mempool, &payout_address, now)
        })
        .await?)
    }

    async fn submit_block(&self, hex: String) -> RpcResult<SubmitBlockResult> {
        let chain = std::sync::Arc::clone(self.ctx.chain());
        let decode_chain = std::sync::Arc::clone(&chain);
        let result = blocking(move || {
            let block = chain::decode_block_hex(&hex)?;
            let announce = block.clone();
            let outcome = mining::submit_block_decoded(&*decode_chain, block)?;
            Ok((outcome, announce))
        })
        .await?;
        let (outcome, block) = result;

        if outcome.accepted
            && let Err(e) = self.ctx.network().broadcast_block(block).await
        {
            tracing::warn!(error = %e, "connected a block but could not announce it");
        }
        Ok(outcome)
    }

    async fn get_mempool_info(&self) -> RpcResult<MempoolInfo> {
        let mempool = std::sync::Arc::clone(self.ctx.mempool());
        Ok(blocking(move || Ok(tx::mempool_info(&*mempool))).await?)
    }

    async fn get_raw_mempool(&self, verbose: Option<bool>) -> RpcResult<RawMempoolResult> {
        let mempool = std::sync::Arc::clone(self.ctx.mempool());
        let verbose = verbose.unwrap_or(false);
        Ok(blocking(move || Ok(tx::raw_mempool(&*mempool, verbose))).await?)
    }

    async fn get_balance(&self, address_str: String) -> RpcResult<AddressBalance> {
        let (chain, mempool) = self.ctx.handles();
        Ok(blocking(move || address::get_balance(&*chain, &*mempool, &address_str)).await?)
    }

    async fn list_unspent(&self, address_str: String) -> RpcResult<Vec<UnspentJson>> {
        let (chain, mempool) = self.ctx.handles();
        Ok(blocking(move || address::list_unspent(&*chain, &*mempool, &address_str)).await?)
    }

    async fn get_state_root(&self, height: Option<u64>) -> RpcResult<String> {
        let chain = std::sync::Arc::clone(self.ctx.chain());
        Ok(blocking(move || chain::state_root(&*chain, height)).await?)
    }

    async fn get_peer_info(&self) -> RpcResult<Vec<PeerJson>> {
        let peers = self.ctx.network().peers().await;
        Ok(peers
            .into_iter()
            .map(|p| PeerJson {
                peer_id: p.peer_id,
                address: p.address,
                agent_version: p.agent_version,
                protocol_version: p.protocol_version,
                last_rtt_ms: p.last_rtt_ms,
                is_static: p.is_static,
            })
            .collect())
    }

    async fn get_network_info(&self) -> RpcResult<NetworkInfoJson> {
        let info = self.ctx.network().network_info().await;
        let params = self.ctx.chain().params();
        Ok(NetworkInfoJson {
            chain: params.network.name().to_owned(),
            chain_id: params.chain_id.0,
            local_peer_id: info.local_peer_id,
            protocol_version: info.protocol_version,
            listen_addresses: info.listen_addresses,
            peer_count: info.peer_count,
            shed_total: info.shed_total,
        })
    }

    async fn estimate_fee(&self, blocks: u64) -> RpcResult<Grains> {
        let mempool = std::sync::Arc::clone(self.ctx.mempool());
        Ok(blocking(move || Ok(tx::estimate_fee(&*mempool, blocks))).await?)
    }
}

/// Convenience: build an `RpcModule` from a context.
///
/// # Errors
/// [`RpcError`] wrapping a `jsonrpsee` registration failure, which can only
/// happen if two methods share a name.
pub fn rpc_module(
    ctx: NodeContext,
) -> Result<jsonrpsee::server::RpcModule<FerrumRpcImpl>, RpcError> {
    Ok(FerrumRpcImpl::new(ctx).into_rpc())
}
