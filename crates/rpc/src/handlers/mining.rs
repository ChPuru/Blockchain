//! `getblocktemplate` and `submitblock`.
//!
//! Every function is synchronous and is called from inside
//! [`crate::context::blocking`].

use ferrum_consensus::compact_to_target;
use ferrum_types::{Amount, Block, BlockSeal, Script};

use crate::error::{RpcError, RpcErrorCode};
use crate::handlers::convert;
use crate::provider::{ChainProvider, MempoolProvider};
use crate::types::rpc::{SubmitBlockResult, TemplateJson};

/// How many bytes of the block budget the template may fill with mempool
/// transactions.
///
/// One per-cent headroom below `max_block_size` covers the coinbase, whose
/// exact size depends on the payout script and the extra-nonce, and which is
/// added *after* selection. Handing the selector the full budget and then
/// discovering the coinbase does not fit means throwing the whole template
/// away.
pub const TEMPLATE_HEADROOM_DIVISOR: usize = 100;

/// `getblocktemplate(payout_address)`.
///
/// # Errors
/// [`RpcErrorCode::InvalidAddress`] for a payout address from another network,
/// and [`RpcErrorCode::TemplateFailed`] when assembly fails.
pub fn block_template(
    chain: &dyn ChainProvider,
    mempool: &dyn MempoolProvider,
    payout_address: &str,
    now_ms: u64,
) -> Result<TemplateJson, RpcError> {
    let params = chain.params();
    let address = convert::parse_address(payout_address, params.network)?;
    let payout: Script = address.script_pubkey();

    let budget =
        params.max_block_size.saturating_sub(params.max_block_size / TEMPLATE_HEADROOM_DIVISOR);
    let txs = mempool.select_for_block(budget);

    // The extra-nonce widens the coinbase search space so that two miners
    // asking for a template in the same millisecond do not grind the identical
    // header. The timestamp is a fine source for it: it is already in the
    // header, and a collision only costs duplicated work, never correctness.
    let template = chain.build_template(&payout, now_ms, txs, now_ms)?;

    let coinbase = template
        .txs
        .first()
        .ok_or_else(|| RpcError::new(RpcErrorCode::TemplateFailed, "template has no coinbase"))?;
    let coinbase_value = convert::total_output(coinbase)?;
    let subsidy = params.block_subsidy(template.height);
    let total_fees = coinbase_value.checked_sub(subsidy).unwrap_or(Amount::ZERO);

    let target = compact_to_target(template.header.bits)?;
    let block = Block::new(template.header, template.txs.clone(), BlockSeal::POW);
    let engine = chain.engine_id_at(template.height);

    Ok(TemplateJson {
        height: template.height,
        prev_hash: block.header.prev_hash.to_hex(),
        version: block.header.version,
        bits: block.header.bits.to_u32(),
        target: hex::encode(target.to_be_bytes()),
        timestamp_ms: block.header.timestamp_ms,
        merkle_root: block.header.merkle_root.to_hex(),
        header_hex: hex::encode(block.header.encode()),
        transactions: block.txs.iter().map(|tx| hex::encode(tx.encode_envelope())).collect(),
        coinbase_value: coinbase_value.into(),
        total_fees: total_fees.into(),
        size: block.serialized_size(),
        engine: convert::engine_name(engine).to_owned(),
    })
}

/// `submitblock(hex)`.
///
/// Reports *why* a block did not become the tip rather than collapsing every
/// non-acceptance into "false". A miner whose block lost fork choice and a
/// miner whose block was invalid need to do different things.
///
/// # Errors
/// [`RpcErrorCode::DecodeFailed`] for a malformed block, and
/// [`RpcErrorCode::BlockRejected`] when a consensus rule refuses it.
pub fn submit_block(
    chain: &dyn ChainProvider,
    hex_str: &str,
) -> Result<SubmitBlockResult, RpcError> {
    let block = crate::handlers::chain::decode_block_hex(hex_str)?;
    submit_block_decoded(chain, block)
}

/// [`submit_block`] for a block that is already decoded.
///
/// Split out so the async handler can decode once, keep a copy to announce, and
/// still submit through the same path.
///
/// # Errors
/// [`RpcErrorCode::BlockRejected`] when a consensus rule refuses it.
pub fn submit_block_decoded(
    chain: &dyn ChainProvider,
    block: Block,
) -> Result<SubmitBlockResult, RpcError> {
    let outcome = chain.submit_block(block)?;
    Ok(SubmitBlockResult {
        accepted: outcome.is_accepted(),
        outcome: outcome.tag().to_owned(),
        hash: outcome.hash().map(|h| h.to_hex()),
    })
}
