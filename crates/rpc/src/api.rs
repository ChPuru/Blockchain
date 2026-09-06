//! The JSON-RPC 2.0 interface (CONTRACT §11).
//!
//! One method per line of the contract's table, with the contract's names.
//! `jsonrpsee`'s `#[rpc]` macro generates two things from this trait:
//!
//! - `FerrumRpcServer`, which [`crate::handlers::FerrumRpcImpl`] implements and
//!   which turns into an `RpcModule` served over HTTP **and** WebSocket by the
//!   same listener;
//! - `FerrumRpcClient`, a typed client used by `chain-cli` and by this crate's
//!   own tests, so the wire format is exercised end to end rather than asserted
//!   about in the abstract.
//!
//! # Optional parameters
//!
//! Trailing `Option<T>` parameters may be omitted by the caller. `getblock`'s
//! verbosity defaults to `1`, `getrawtransaction`'s `verbose` to `false` and
//! `getstateroot`'s height to the tip — the same defaults a Bitcoin-shaped
//! client already assumes.

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

use crate::types::Grains;
use crate::types::rpc::{
    AddressBalance, BlockHeaderInfo, BlockchainInfo, CoinJson, GetBlockResult,
    GetRawTransactionResult, MempoolInfo, NetworkInfoJson, PeerJson, RawMempoolResult,
    SubmitBlockResult, TemplateJson, UnspentJson,
};

/// Ferrum's JSON-RPC surface.
#[rpc(server, client)]
pub trait FerrumRpc {
    /// Chain identity, tip, difficulty, engine and finality.
    #[method(name = "getblockchaininfo")]
    async fn get_blockchain_info(&self) -> RpcResult<BlockchainInfo>;

    /// The active-chain block hash at `height`.
    #[method(name = "getblockhash")]
    async fn get_block_hash(&self, height: u64) -> RpcResult<String>;

    /// A block. Verbosity `0` is hex, `1` adds transaction ids, `2` decodes
    /// them. Defaults to `1`.
    #[method(name = "getblock")]
    async fn get_block(&self, hash: String, verbosity: Option<u8>) -> RpcResult<GetBlockResult>;

    /// A block header and where it sits.
    #[method(name = "getblockheader")]
    async fn get_block_header(&self, hash: String) -> RpcResult<BlockHeaderInfo>;

    /// A transaction, as hex by default or decoded when `verbose` is set.
    #[method(name = "getrawtransaction")]
    async fn get_raw_transaction(
        &self,
        txid: String,
        verbose: Option<bool>,
    ) -> RpcResult<GetRawTransactionResult>;

    /// Offer a transaction envelope to the mempool and the network. Returns its
    /// id.
    #[method(name = "sendrawtransaction")]
    async fn send_raw_transaction(&self, hex: String) -> RpcResult<String>;

    /// One unspent output, or `null` if it is spent or never existed.
    #[method(name = "gettxout")]
    async fn get_tx_out(&self, txid: String, vout: u32) -> RpcResult<Option<CoinJson>>;

    /// A candidate block paying `payout_address`.
    #[method(name = "getblocktemplate")]
    async fn get_block_template(&self, payout_address: String) -> RpcResult<TemplateJson>;

    /// Submit a sealed block.
    #[method(name = "submitblock")]
    async fn submit_block(&self, hex: String) -> RpcResult<SubmitBlockResult>;

    /// Mempool size, bytes and policy floor.
    #[method(name = "getmempoolinfo")]
    async fn get_mempool_info(&self) -> RpcResult<MempoolInfo>;

    /// Mempool contents: ids, or a map of entries when `verbose` is set.
    #[method(name = "getrawmempool")]
    async fn get_raw_mempool(&self, verbose: Option<bool>) -> RpcResult<RawMempoolResult>;

    /// Confirmed and immature balance for an address. Needs the reverse index.
    #[method(name = "getbalance")]
    async fn get_balance(&self, address: String) -> RpcResult<AddressBalance>;

    /// Unspent outputs paying an address. Needs the reverse index.
    #[method(name = "listunspent")]
    async fn list_unspent(&self, address: String) -> RpcResult<Vec<UnspentJson>>;

    /// The UTXO-set Merkle root. Only the tip's is kept.
    #[method(name = "getstateroot")]
    async fn get_state_root(&self, height: Option<u64>) -> RpcResult<String>;

    /// Connected peers.
    #[method(name = "getpeerinfo")]
    async fn get_peer_info(&self) -> RpcResult<Vec<PeerJson>>;

    /// Local identity, listen addresses and peer count.
    #[method(name = "getnetworkinfo")]
    async fn get_network_info(&self) -> RpcResult<NetworkInfoJson>;

    /// Fee estimate for confirmation within `blocks`, in grains per kB.
    #[method(name = "estimatefee")]
    async fn estimate_fee(&self, blocks: u64) -> RpcResult<Grains>;
}
