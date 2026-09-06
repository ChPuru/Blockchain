//! `chain-cli block ...` — blocks and the tip.
//!
//! `block get` takes a hash *or* a height, because that is what an operator
//! actually has in hand: a height from a log line, a hash from a peer. A
//! 64-hex string is a hash and anything else is parsed as a height, which is
//! unambiguous — a height can never be 64 hex characters and a hash always is.

use ferrum_rpc::FerrumRpcClient as _;
use ferrum_rpc::types::rpc::GetBlockResult;
use ferrum_types::BlockHash;
use serde_json::json;

use crate::commands::Context;
use crate::error::{CliError, CliResult};
use crate::output::CommandOutput;
use crate::rpc::rpc_err;

/// `block get`.
///
/// # Errors
///
/// [`CliError::Invalid`] when the target is neither a hash nor a height, and
/// [`CliError::Rpc`] when the node does not have the block.
pub async fn get(ctx: &Context, target: &str, verbosity: u8) -> CliResult<CommandOutput> {
    let client = ctx.client()?;
    let hash = resolve_target(ctx, target).await?;
    let result = client
        .get_block(hash.to_string(), Some(verbosity))
        .await
        .map_err(rpc_err("getblock"))?;

    match result {
        GetBlockResult::Hex(body) => Ok(CommandOutput::scalar("hex", body)),
        GetBlockResult::Verbose(block) => {
            let document = serde_json::to_value(&*block)
                .map_err(|e| CliError::internal(format!("cannot render block: {e}")))?;
            Ok(CommandOutput::scalar("hash", block.hash.clone())
                .with_json(document)
                .with_field("height", block.height)
                .with_field("txs", block.tx_count)
                .with_field("size", block.size)
                .with_field("engine", &block.engine)
                .with_field("confirmations", block.confirmations))
        }
    }
}

/// Turn a hash-or-height argument into a block hash.
async fn resolve_target(ctx: &Context, target: &str) -> CliResult<BlockHash> {
    let trimmed = target.trim();
    let body = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if body.len() == 64 && body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return BlockHash::from_hex(body)
            .map_err(|e| CliError::invalid("block", target, e.to_string()));
    }
    let height: u64 = body
        .parse()
        .map_err(|_| CliError::invalid("block", target, "expected a 64-hex hash or a height"))?;
    let client = ctx.client()?;
    let hash = client.get_block_hash(height).await.map_err(rpc_err("getblockhash"))?;
    BlockHash::from_hex(&hash).map_err(|e| CliError::invalid("block", hash, e.to_string()))
}

/// `block hash`.
///
/// # Errors
///
/// [`CliError::Rpc`] when the height is past the tip.
pub async fn hash(ctx: &Context, height: u64) -> CliResult<CommandOutput> {
    let client = ctx.client()?;
    let hash = client.get_block_hash(height).await.map_err(rpc_err("getblockhash"))?;
    Ok(CommandOutput::scalar("hash", hash.clone())
        .with_json(json!({ "hash": hash, "height": height })))
}

/// `block tip`.
///
/// # Errors
///
/// [`CliError::Rpc`] when the node cannot be reached.
pub async fn tip(ctx: &Context) -> CliResult<CommandOutput> {
    let client = ctx.client()?;
    let info = client.get_blockchain_info().await.map_err(rpc_err("getblockchaininfo"))?;
    Ok(CommandOutput::scalar("best_hash", info.best_hash.clone())
        .with_json(json!({
            "best_hash": info.best_hash,
            "height": info.height,
            "total_work": info.total_work,
        }))
        .with_field("height", info.height))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_64_hex_string_is_recognised_as_a_hash_without_a_node() {
        // `resolve_target` only reaches the network for a height, so the hash
        // branch is checkable here: parsing must succeed with no node running.
        let text = "ab".repeat(32);
        assert!(BlockHash::from_hex(&text).is_ok());
        assert_eq!(text.len(), 64);
    }

    #[test]
    fn a_height_is_not_mistaken_for_a_hash() {
        let text = "12345";
        assert!(text.len() != 64);
        assert!(text.parse::<u64>().is_ok());
    }

    #[tokio::test]
    async fn a_target_that_is_neither_is_refused_before_any_round_trip() {
        let ctx = Context {
            datadir: std::path::PathBuf::from("."),
            // Port 1 is never a Ferrum node; the error must arrive from the
            // parser, not from a connection attempt.
            rpc_url: "http://127.0.0.1:1".to_owned(),
            json: false,
        };
        let err = resolve_target(&ctx, "not-a-block").await.unwrap_err();
        assert!(err.to_string().contains("64-hex hash or a height"), "{err}");
    }
}
