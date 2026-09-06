//! `getblockchaininfo`, `getblockhash`, `getblock`, `getblockheader`,
//! `getstateroot`.
//!
//! Every function is synchronous and is called from inside
//! [`crate::context::blocking`].

use borsh::BorshSerialize;
use ferrum_consensus::{Target, compact_to_target};
use ferrum_types::{Block, BlockHash};

use crate::error::{RpcError, RpcErrorCode};
use crate::handlers::convert;
use crate::handlers::lookup;
use crate::provider::{ChainProvider, MempoolProvider};
use crate::types::rpc::{
    BlockHeaderInfo, BlockJson, BlockTxList, BlockchainInfo, GetBlockResult, TransactionJson,
};

/// `getblockchaininfo`.
///
/// # Errors
/// Storage failures, and [`RpcErrorCode::BlockRejected`] if the tip's own
/// `bits` will not expand — which would mean a corrupt database.
pub fn blockchain_info(
    chain: &dyn ChainProvider,
    mempool: &dyn MempoolProvider,
) -> Result<BlockchainInfo, RpcError> {
    let params = chain.params();
    let (tip_hash, tip_height) = chain.tip()?;
    let entry = chain.header_entry(&tip_hash)?;
    let target = match &entry {
        Some(e) => compact_to_target(e.header.bits)?,
        // An empty store has no tip header; reporting the easiest permitted
        // target is the honest answer for "difficulty of nothing".
        None => convert::pow_limit_target(params),
    };
    let total_work =
        entry.as_ref().map_or_else(|| chain.tip_work().unwrap_or([0u8; 32]), |e| e.total_work);

    Ok(BlockchainInfo {
        chain: params.network.name().to_owned(),
        height: tip_height,
        best_hash: tip_hash.to_hex(),
        total_work: hex::encode(total_work),
        difficulty: convert::difficulty_string(target, convert::pow_limit_target(params)),
        engine: convert::engine_name(chain.engine_id_at(tip_height)).to_owned(),
        finalized_height: chain.finalized_height(),
        mempool_size: mempool.len(),
        utxo_count: chain.utxo_count()?,
        chain_id: params.chain_id.0,
        index_enabled: chain.index_enabled(),
    })
}

/// `getblockhash(height)`.
///
/// # Errors
/// [`RpcErrorCode::HeightOutOfRange`] past the tip.
pub fn block_hash_at(chain: &dyn ChainProvider, height: u64) -> Result<String, RpcError> {
    chain.hash_at_height(height)?.map(|h| h.to_hex()).ok_or_else(|| {
        RpcError::new(RpcErrorCode::HeightOutOfRange, format!("no block at height {height}"))
    })
}

/// `getblock(hash, verbosity)`.
///
/// Verbosity `0` returns `borsh(Block)` as hex, `1` returns the block with
/// transaction ids, `2` returns it with fully decoded transactions. Anything
/// above `2` is treated as `2`, which is what every Bitcoin-shaped client
/// expects.
///
/// # Errors
/// [`RpcErrorCode::NotFound`] for an unknown hash.
pub fn get_block(
    chain: &dyn ChainProvider,
    hash: &BlockHash,
    verbosity: u8,
) -> Result<GetBlockResult, RpcError> {
    let block = chain
        .block(hash)?
        .ok_or_else(|| RpcError::not_found(format!("no block body for {}", hash.to_hex())))?;
    if verbosity == 0 {
        return Ok(GetBlockResult::Hex(encode_block_hex(&block)?));
    }
    Ok(GetBlockResult::Verbose(Box::new(block_json(chain, hash, &block, verbosity >= 2)?)))
}

/// `borsh(Block)` as lowercase hex.
///
/// # Errors
/// [`RpcErrorCode::InternalError`] if Borsh refuses to serialise a block the
/// store already holds, which cannot happen and is reported rather than
/// panicked on.
pub fn encode_block_hex(block: &Block) -> Result<String, RpcError> {
    let mut bytes = Vec::with_capacity(block.serialized_size());
    block
        .serialize(&mut bytes)
        .map_err(|e| RpcError::internal(format!("encoding a stored block: {e}")))?;
    Ok(hex::encode(bytes))
}

/// Decode `borsh(Block)` from hex.
///
/// # Errors
/// [`RpcErrorCode::InvalidHex`] or [`RpcErrorCode::DecodeFailed`]. Trailing
/// bytes are rejected: tolerating a suffix is a malleability bug, and
/// `borsh::from_slice` is the only decoder used anywhere in this workspace.
pub fn decode_block_hex(hex_str: &str) -> Result<Block, RpcError> {
    let bytes = crate::error::parse_hex(hex_str)?;
    borsh::from_slice::<Block>(&bytes)
        .map_err(|e| RpcError::new(RpcErrorCode::DecodeFailed, format!("not a block: {e}")))
}

/// The verbose form of a block.
///
/// # Errors
/// Storage failures.
pub fn block_json(
    chain: &dyn ChainProvider,
    hash: &BlockHash,
    block: &Block,
    full_txs: bool,
) -> Result<BlockJson, RpcError> {
    let (entry, active, confirmations) = lookup::block_position(chain, hash)?;
    let next = lookup::next_hash(chain, entry.height, active)?;
    let network = chain.params().network;

    let txs = if full_txs {
        let mut out = Vec::with_capacity(block.txs.len());
        for tx in &block.txs {
            out.push(TransactionJson {
                txid: lookup::txid_of(tx).to_hex(),
                version: tx.version,
                lock_time: tx.lock_time,
                size: tx.serialized_size(),
                coinbase: tx.is_coinbase(),
                value: convert::total_output(tx)?.into(),
                vin: tx.inputs.iter().map(convert::tx_in_json).collect(),
                vout: tx
                    .outputs
                    .iter()
                    .enumerate()
                    .map(|(i, o)| {
                        convert::tx_out_json(u32::try_from(i).unwrap_or(u32::MAX), o, network)
                    })
                    .collect(),
                block_hash: Some(hash.to_hex()),
                height: Some(entry.height),
                confirmations: Some(confirmations),
            });
        }
        BlockTxList::Full(out)
    } else {
        BlockTxList::Ids(block.txs.iter().map(|tx| lookup::txid_of(tx).to_hex()).collect())
    };

    Ok(BlockJson {
        hash: hash.to_hex(),
        height: entry.height,
        size: block.serialized_size(),
        engine: convert::engine_name(entry.seal_engine).to_owned(),
        seal: hex::encode(&block.seal.data),
        total_work: hex::encode(entry.total_work),
        confirmations,
        next_hash: next.map(|h| h.to_hex()),
        header: convert::header_json(&block.header),
        tx_count: block.txs.len(),
        txs,
    })
}

/// `getblockheader(hash)`.
///
/// # Errors
/// [`RpcErrorCode::NotFound`] for an unknown hash.
pub fn get_block_header(
    chain: &dyn ChainProvider,
    hash: &BlockHash,
) -> Result<BlockHeaderInfo, RpcError> {
    let (entry, active, confirmations) = lookup::block_position(chain, hash)?;
    let next = lookup::next_hash(chain, entry.height, active)?;
    let target: Target = compact_to_target(entry.header.bits)?;
    let header = convert::header_json(&entry.header);
    Ok(BlockHeaderInfo {
        hash: header.hash,
        version: header.version,
        prev_hash: header.prev_hash,
        merkle_root: header.merkle_root,
        timestamp_ms: header.timestamp_ms,
        bits: header.bits,
        nonce: header.nonce,
        height: entry.height,
        target: hex::encode(target.to_be_bytes()),
        difficulty: convert::difficulty_string(target, convert::pow_limit_target(chain.params())),
        total_work: hex::encode(entry.total_work),
        confirmations,
        next_hash: next.map(|h| h.to_hex()),
        engine: convert::engine_name(entry.seal_engine).to_owned(),
    })
}

/// `getstateroot(height?)`.
///
/// # Errors
/// [`RpcErrorCode::StateRootUnavailable`] for any height that is not the tip.
///
/// The store keeps one UTXO set, the current one; a historical state root would
/// mean rewinding the chain to that height and rewinding it back, which is a
/// write on a read path. `chain-cli chain reindex` is the honest way to get an
/// old root, and inventing one here would be worse than refusing.
pub fn state_root(chain: &dyn ChainProvider, height: Option<u64>) -> Result<String, RpcError> {
    let (_, tip_height) = chain.tip()?;
    if let Some(requested) = height
        && requested != tip_height
    {
        return Err(RpcError::new(
            RpcErrorCode::StateRootUnavailable,
            format!(
                "the state root is only kept for the tip (height {tip_height}); \
                 {requested} would need a rewind"
            ),
        ));
    }
    Ok(chain.state_root()?.to_hex())
}
