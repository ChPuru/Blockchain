//! The five REST payloads `explorer/index.html` reads.
//!
//! The page is the client and it is already written, so these builders exist to
//! produce exactly the field names it looks for. See
//! [`crate::types::explorer`] for the field-by-field mapping.
//!
//! Every function is synchronous and is called from inside
//! [`crate::context::blocking`].

use ferrum_consensus::compact_to_target;
use ferrum_types::{Amount, Block, BlockHash, OutPoint, Transaction, Txid};

use crate::error::RpcError;
use crate::handlers::address::address_report;
use crate::handlers::convert;
use crate::handlers::lookup::{self, BlockReader, RECENT_BLOCKS, RECENT_TXS};
use crate::provider::{ChainProvider, MempoolProvider};
use crate::types::explorer::{
    AddressResponse, AddressTx, BlockResponse, BlockTxSummary, RecentBlock, RecentTx,
    SearchResponse, StatsResponse, TxInputView, TxOutputView, TxResponse,
};
use crate::types::{Grains, SignedGrains};

/// `GET /api/stats`.
///
/// `peers` is passed in because the peer count is the one figure that comes
/// from the async peer-to-peer service rather than from the store.
///
/// # Errors
/// Storage failures.
pub fn stats(
    chain: &dyn ChainProvider,
    mempool: &dyn MempoolProvider,
    peers: usize,
    faucet_enabled: bool,
) -> Result<StatsResponse, RpcError> {
    let params = chain.params();
    let (tip_hash, tip_height) = chain.tip()?;
    let entry = chain.header_entry(&tip_hash)?;
    let target = match &entry {
        Some(e) => compact_to_target(e.header.bits)?,
        None => convert::pow_limit_target(params),
    };
    let total_work =
        entry.as_ref().map_or_else(|| chain.tip_work().unwrap_or([0u8; 32]), |e| e.total_work);

    let blocks = lookup::recent_blocks(chain, RECENT_BLOCKS)?;
    let recent_blocks = blocks
        .iter()
        .enumerate()
        .map(|(offset, block)| RecentBlock {
            height: tip_height.saturating_sub(u64::try_from(offset).unwrap_or(0)),
            hash: lookup::hash_of(&block.header).to_hex(),
            tx_count: u32::try_from(block.txs.len()).unwrap_or(u32::MAX),
            size: u32::try_from(block.serialized_size()).unwrap_or(u32::MAX),
            timestamp_ms: block.header.timestamp_ms,
        })
        .collect();

    Ok(StatsResponse {
        chain: params.network.name().to_owned(),
        height: tip_height,
        best_hash: tip_hash.to_hex(),
        difficulty: convert::difficulty_string(target, convert::pow_limit_target(params)),
        engine: convert::engine_name(chain.engine_id_at(tip_height)).to_owned(),
        mempool_size: mempool.len(),
        utxo_count: chain.utxo_count()?,
        peers,
        recent_blocks,
        recent_txs: recent_txs(&mut BlockReader::new(chain), mempool, &blocks, tip_height)?,
        faucet_enabled,
        finalized_height: chain.finalized_height(),
        total_work: hex::encode(total_work),
        index_enabled: chain.index_enabled(),
    })
}

/// Mempool transactions first, then the newest confirmed ones.
fn recent_txs(
    reader: &mut BlockReader<'_>,
    mempool: &dyn MempoolProvider,
    blocks: &[Block],
    tip_height: u64,
) -> Result<Vec<RecentTx>, RpcError> {
    let mut out: Vec<RecentTx> = Vec::with_capacity(RECENT_TXS);
    for txid in mempool.txids() {
        if out.len() >= RECENT_TXS {
            return Ok(out);
        }
        let Some(entry) = mempool.get(&txid) else { continue };
        out.push(RecentTx {
            txid: txid.to_hex(),
            value: convert::total_output(&entry.tx)?.into(),
            fee: entry.fee.into(),
            height: None,
        });
    }
    for (offset, block) in blocks.iter().enumerate() {
        let height = tip_height.saturating_sub(u64::try_from(offset).unwrap_or(0));
        for tx in &block.txs {
            if out.len() >= RECENT_TXS {
                return Ok(out);
            }
            out.push(RecentTx {
                txid: lookup::txid_of(tx).to_hex(),
                value: convert::total_output(tx)?.into(),
                fee: tx_fee(reader, tx)?.into(),
                height: Some(height),
            });
        }
    }
    Ok(out)
}

/// A transaction's fee, resolving its funding coins first.
///
/// Zero for a coinbase, and zero on a node without the reverse index, where the
/// funding outputs cannot be found. See
/// [`crate::handlers::convert::transaction_fee`].
fn tx_fee(reader: &mut BlockReader<'_>, tx: &Transaction) -> Result<Amount, RpcError> {
    if tx.is_coinbase() {
        return Ok(Amount::ZERO);
    }
    let prevouts = lookup::resolve_prevouts(reader, tx)?;
    convert::transaction_fee(tx, &prevouts)
}

/// `GET /api/block/:height_or_hash`.
///
/// # Errors
/// [`RpcErrorCode::NotFound`] or [`RpcErrorCode::HeightOutOfRange`] for an
/// unknown block.
pub fn block_view(chain: &dyn ChainProvider, id: &str) -> Result<BlockResponse, RpcError> {
    let hash: BlockHash = lookup::resolve_block_id(chain, id)?;
    let block = chain
        .block(&hash)?
        .ok_or_else(|| RpcError::not_found(format!("no block body for {}", hash.to_hex())))?;
    let (entry, active, confirmations) = lookup::block_position(chain, &hash)?;
    let next = lookup::next_hash(chain, entry.height, active)?;

    // One budget for the whole page. Every input of every transaction here
    // resolves through the tx index, and a full block holds thousands of them.
    let mut reader = BlockReader::new(chain);
    let mut txs = Vec::with_capacity(block.txs.len());
    for tx in &block.txs {
        txs.push(BlockTxSummary {
            txid: lookup::txid_of(tx).to_hex(),
            vin: tx.inputs.len(),
            vout: tx.outputs.len(),
            value: convert::total_output(tx)?.into(),
            fee: tx_fee(&mut reader, tx)?.into(),
            coinbase: tx.is_coinbase(),
        });
    }

    Ok(BlockResponse {
        hash: hash.to_hex(),
        height: entry.height,
        size: block.serialized_size(),
        engine: convert::engine_name(entry.seal_engine).to_owned(),
        total_work: hex::encode(entry.total_work),
        confirmations,
        next_hash: next.map(|h| h.to_hex()),
        header: convert::header_json(&block.header),
        txs,
    })
}

/// `GET /api/tx/:txid`.
///
/// # Errors
/// [`RpcErrorCode::InvalidHash`] for a malformed id,
/// [`RpcErrorCode::IndexDisabled`] on a node without the reverse index that
/// does not have the transaction in its mempool, and
/// [`RpcErrorCode::NotFound`] when it is nowhere.
pub fn tx_view(
    chain: &dyn ChainProvider,
    mempool: &dyn MempoolProvider,
    txid_str: &str,
) -> Result<TxResponse, RpcError> {
    let txid = Txid(crate::error::parse_hash32(txid_str)?);
    let (_, tip_height) = chain.tip()?;

    // One budget for the whole page: the spender scan below runs once per
    // output, and without a shared allowance the cost is outputs x scan.
    let mut reader = BlockReader::new(chain);

    let (tx, confirmed) = match mempool.get(&txid) {
        Some(entry) => (entry.tx, None),
        None => {
            if !chain.index_enabled() {
                return Err(RpcError::index_disabled("the transaction page"));
            }
            let found = lookup::find_transaction(&mut reader, &txid)?
                .ok_or_else(|| RpcError::not_found(format!("no transaction {txid_str}")))?;
            let active = lookup::on_active_chain(chain, &found.block_hash, found.height)?;
            let confirmations = convert::confirmations(tip_height, found.height, active);
            (found.tx, Some((found.block_hash, found.height, confirmations, found.timestamp_ms)))
        }
    };

    let network = chain.params().network;
    let prevouts = lookup::resolve_prevouts(&mut reader, &tx)?;
    let fee = convert::transaction_fee(&tx, &prevouts)?;
    let size = tx.serialized_size();

    let inputs = tx
        .inputs
        .iter()
        .zip(prevouts.iter())
        .map(|(input, coin)| {
            let coinbase = input.prev_out.is_null();
            TxInputView {
                coinbase,
                txid: (!coinbase).then(|| input.prev_out.txid.to_hex()),
                vout: (!coinbase).then_some(input.prev_out.vout),
                value: coin.as_ref().map_or(Grains::ZERO, |c| c.value.into()),
                address: coin
                    .as_ref()
                    .and_then(|c| convert::address_string(&c.script_pubkey, network)),
                script_type: coin.as_ref().map(|c| convert::script_type_name(&c.script_pubkey)),
            }
        })
        .collect();

    let from_height = confirmed.map_or(0, |(_, h, _, _)| h);
    let mut outputs = Vec::with_capacity(tx.outputs.len());
    for (index, output) in tx.outputs.iter().enumerate() {
        let n = u32::try_from(index).unwrap_or(u32::MAX);
        let out_point = OutPoint::new(txid, n);
        // Unspent is answered by the UTXO set, which is authoritative and
        // cheap. Only a *spent* output needs the forward scan, and only that
        // scan can fail to find an answer.
        let spent_by = if chain.coin(&out_point)?.is_some() {
            None
        } else {
            lookup::find_spender(&mut reader, &out_point, &output.script_pubkey, from_height)?
                .map(|t| t.to_hex())
        };
        outputs.push(TxOutputView {
            n,
            value: output.value.into(),
            address: convert::address_string(&output.script_pubkey, network),
            script_type: convert::script_type_name(&output.script_pubkey),
            spent_by,
        });
    }

    Ok(TxResponse {
        txid: txid.to_hex(),
        version: tx.version,
        lock_time: tx.lock_time,
        size,
        coinbase: tx.is_coinbase(),
        value: convert::total_output(&tx)?.into(),
        fee: fee.into(),
        fee_rate: (!tx.is_coinbase()).then(|| convert::fee_rate(fee, size)),
        block_hash: confirmed.map(|(h, _, _, _)| h.to_hex()),
        height: confirmed.map(|(_, h, _, _)| h),
        confirmations: confirmed.map(|(_, _, c, _)| c),
        timestamp_ms: confirmed.map(|(_, _, _, t)| t),
        inputs,
        outputs,
    })
}

/// `GET /api/address/:address`.
///
/// # Errors
/// [`RpcErrorCode::InvalidAddress`] or [`RpcErrorCode::IndexDisabled`].
pub fn address_view(
    chain: &dyn ChainProvider,
    mempool: &dyn MempoolProvider,
    address: &str,
) -> Result<AddressResponse, RpcError> {
    let report = address_report(chain, mempool, address)?;
    let transactions = report
        .history
        .iter()
        .map(|entry| AddressTx {
            txid: entry.txid.to_hex(),
            height: entry.height,
            delta: SignedGrains(entry.delta),
            timestamp_ms: entry.timestamp_ms,
        })
        .collect();
    Ok(AddressResponse {
        script_type: match report.address.payload {
            ferrum_crypto::AddressPayload::PubKeyHash(_) => "p2pkh".to_owned(),
            ferrum_crypto::AddressPayload::ScriptHash(_) => "p2sh".to_owned(),
        },
        address: report.address.encode(),
        confirmed: report.confirmed.into(),
        immature: report.immature.into(),
        pending: report.pending.into(),
        utxo_count: report.utxo_count(),
        tx_count: report.tx_count(),
        transactions,
        complete: report.complete,
    })
}

/// `GET /api/search?q=`.
///
/// A miss is a **success** with both fields `null`: the page renders its own
/// "nothing matches" panel and treats any non-2xx as a server failure. Search
/// is the one route where "I do not know" is a normal answer.
///
/// Order matters. A 64-character hex string can be either a block hash or a
/// transaction id, and the server is the only thing that can tell them apart —
/// which is exactly why the page defers ambiguous input to this route.
///
/// # Errors
/// Storage failures only.
pub fn search(chain: &dyn ChainProvider, query: &str) -> Result<SearchResponse, RpcError> {
    let q = query.trim();
    if q.is_empty() {
        return Ok(SearchResponse::default());
    }

    if let Ok(height) = q.parse::<u64>()
        && chain.hash_at_height(height)?.is_some()
    {
        return Ok(SearchResponse { kind: Some("block".to_owned()), id: Some(height.to_string()) });
    }

    if let Ok(hash) = ferrum_types::Hash32::from_hex(q) {
        if chain.header_entry(&BlockHash(hash))?.is_some() {
            return Ok(SearchResponse { kind: Some("block".to_owned()), id: Some(hash.to_hex()) });
        }
        // `tx_location` reports IndexDisabled without the index; a search that
        // cannot check is a search that found nothing, not a failed request.
        if chain.index_enabled() && chain.tx_location(&Txid(hash))?.is_some() {
            return Ok(SearchResponse { kind: Some("tx".to_owned()), id: Some(hash.to_hex()) });
        }
    }

    if let Ok(address) = convert::parse_address(q, chain.params().network) {
        return Ok(SearchResponse { kind: Some("address".to_owned()), id: Some(address.encode()) });
    }

    Ok(SearchResponse::default())
}
