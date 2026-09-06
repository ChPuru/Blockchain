//! `getrawtransaction`, `sendrawtransaction`, `gettxout`, `getmempoolinfo`,
//! `getrawmempool`, `estimatefee`.
//!
//! Every function is synchronous and is called from inside
//! [`crate::context::blocking`].

use std::collections::BTreeMap;

use ferrum_types::{OutPoint, Transaction, Txid};

use crate::error::{RpcError, RpcErrorCode};
use crate::handlers::convert;
use crate::handlers::lookup;
use crate::provider::{ChainProvider, MempoolProvider};
use crate::types::Grains;
use crate::types::rpc::{
    CoinJson, GetRawTransactionResult, MempoolEntryJson, MempoolInfo, RawMempoolResult,
    TransactionJson,
};

/// Decode a transaction envelope from hex.
///
/// The envelope is `type_byte || borsh(Transaction)`, and the type byte is
/// inside the txid preimage, so a client that strips it computes a different
/// id than the network does.
///
/// # Errors
/// [`RpcErrorCode::InvalidHex`] or [`RpcErrorCode::DecodeFailed`].
pub fn decode_tx_hex(hex_str: &str) -> Result<Transaction, RpcError> {
    let bytes = crate::error::parse_hex(hex_str)?;
    Transaction::decode_envelope(&bytes)
        .map_err(|e| RpcError::new(RpcErrorCode::DecodeFailed, format!("not a transaction: {e}")))
}

/// `getrawtransaction(txid, verbose)`.
///
/// Looks in the mempool first: an unconfirmed transaction someone just sent is
/// the one they are most likely asking about, and it is the cheaper lookup.
///
/// # Errors
/// [`RpcErrorCode::NotFound`] when neither the mempool nor the index has it,
/// and [`RpcErrorCode::IndexDisabled`] when there is no index to consult and
/// the mempool does not have it either.
pub fn get_raw_transaction(
    chain: &dyn ChainProvider,
    mempool: &dyn MempoolProvider,
    txid: &Txid,
    verbose: bool,
) -> Result<GetRawTransactionResult, RpcError> {
    if let Some(entry) = mempool.get(txid) {
        return render_transaction(chain, &entry.tx, None, verbose);
    }
    if !chain.index_enabled() {
        return Err(RpcError::index_disabled("looking a transaction up by id"));
    }
    let found = lookup::find_transaction(chain, txid)?
        .ok_or_else(|| RpcError::not_found(format!("no transaction {}", txid.to_hex())))?;
    let (_, tip_height) = chain.tip()?;
    let active = lookup::on_active_chain(chain, &found.block_hash, found.height)?;
    let confirmations = convert::confirmations(tip_height, found.height, active);
    render_transaction(
        chain,
        &found.tx,
        Some((found.block_hash.to_hex(), found.height, confirmations)),
        verbose,
    )
}

/// Hex or decoded, by verbosity.
fn render_transaction(
    chain: &dyn ChainProvider,
    tx: &Transaction,
    confirmed: Option<(String, u64, u64)>,
    verbose: bool,
) -> Result<GetRawTransactionResult, RpcError> {
    if !verbose {
        return Ok(GetRawTransactionResult::Hex(hex::encode(tx.encode_envelope())));
    }
    let network = chain.params().network;
    let (block_hash, height, confirmations) = match confirmed {
        Some((h, height, conf)) => (Some(h), Some(height), Some(conf)),
        None => (None, None, None),
    };
    Ok(GetRawTransactionResult::Verbose(Box::new(TransactionJson {
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
            .map(|(i, o)| convert::tx_out_json(u32::try_from(i).unwrap_or(u32::MAX), o, network))
            .collect(),
        block_hash,
        height,
        confirmations,
    })))
}

/// `gettxout(txid, vout)`.
///
/// Answers from the UTXO set only, so `null` means "not spendable right now" —
/// either it never existed or it has been spent. That is the question a wallet
/// is actually asking.
///
/// # Errors
/// Storage failures.
pub fn get_tx_out(
    chain: &dyn ChainProvider,
    txid: &Txid,
    vout: u32,
) -> Result<Option<CoinJson>, RpcError> {
    let out_point = OutPoint::new(*txid, vout);
    let Some(coin) = chain.coin(&out_point)? else {
        return Ok(None);
    };
    let (_, tip_height) = chain.tip()?;
    let network = chain.params().network;
    Ok(Some(CoinJson {
        txid: txid.to_hex(),
        vout,
        value: coin.value.into(),
        script_pubkey: coin.script_pubkey.to_hex(),
        script_type: convert::script_type_name(&coin.script_pubkey),
        address: convert::address_string(&coin.script_pubkey, network),
        height: coin.height,
        is_coinbase: coin.is_coinbase,
        confirmations: convert::confirmations(tip_height, coin.height, true),
    }))
}

/// `getmempoolinfo`.
#[must_use]
pub fn mempool_info(mempool: &dyn MempoolProvider) -> MempoolInfo {
    MempoolInfo {
        size: mempool.len(),
        bytes: mempool.size_bytes(),
        max_bytes: mempool.max_bytes(),
        min_fee_rate: mempool.min_fee_rate(),
    }
}

/// `getrawmempool(verbose)`.
#[must_use]
pub fn raw_mempool(mempool: &dyn MempoolProvider, verbose: bool) -> RawMempoolResult {
    if !verbose {
        return RawMempoolResult::Ids(mempool.txids().iter().map(Txid::to_hex).collect());
    }
    let mut map = BTreeMap::new();
    for txid in mempool.txids() {
        if let Some(entry) = mempool.get(&txid) {
            map.insert(
                txid.to_hex(),
                MempoolEntryJson {
                    size: entry.size,
                    fee: entry.fee.into(),
                    fee_rate: entry.fee_rate,
                    height: entry.added_height,
                },
            );
        }
    }
    RawMempoolResult::Verbose(map)
}

/// `estimatefee(blocks)`, in grains per 1000 bytes.
///
/// On a chain whose blocks are never full there is no congestion to price, so
/// the honest floor is the relay minimum. A node with a real estimator
/// overrides [`MempoolProvider::estimate_fee_rate`].
#[must_use]
pub fn estimate_fee(mempool: &dyn MempoolProvider, blocks: u64) -> Grains {
    Grains(ferrum_types::Amount::from_grains(mempool.estimate_fee_rate(blocks)))
}
