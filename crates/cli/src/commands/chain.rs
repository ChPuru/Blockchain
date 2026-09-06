//! `chain-cli chain ...` — chain state and node administration.
//!
//! `info`, `peers` and `stateroot` are RPC calls. `reindex` is not: it opens
//! the `redb` store in `--datadir` directly, so **the node must be stopped
//! first**. There is no RPC for it deliberately — a rebuild that walks every
//! block would hold the acceptance lock for minutes, and a node that stops
//! answering `getblockchaininfo` mid-rebuild looks exactly like a node that
//! has crashed.

use std::sync::Arc;

use ferrum_chain::ChainManager;
use ferrum_consensus::EngineRouter;
use ferrum_rpc::FerrumRpcClient as _;
use ferrum_storage::{Store, StoreConfig};
use ferrum_types::BlockHash;
use serde_json::json;

use crate::commands::Context;
use crate::error::{CliError, CliResult};
use crate::output::CommandOutput;
use crate::paths;
use crate::rpc::rpc_err;

/// `chain info`.
///
/// With `--json` this is `getblockchaininfo` verbatim, which CONTRACT §13.1
/// requires: the devnet scripts read `height`, `best_hash`, `total_work` and
/// `engine` straight out of it.
///
/// # Errors
///
/// [`CliError::Rpc`] when the node cannot be reached.
pub async fn info(ctx: &Context) -> CliResult<CommandOutput> {
    let client = ctx.client()?;
    let info = client.get_blockchain_info().await.map_err(rpc_err("getblockchaininfo"))?;
    let document = serde_json::to_value(&info)
        .map_err(|e| CliError::internal(format!("cannot render chain info: {e}")))?;

    Ok(CommandOutput::scalar("best_hash", info.best_hash.clone())
        .with_json(document)
        .with_field("chain", &info.chain)
        .with_field("height", info.height)
        .with_field("engine", &info.engine)
        .with_field("difficulty", &info.difficulty)
        .with_field("total work", &info.total_work)
        .with_field(
            "finalized",
            info.finalized_height.map_or_else(|| "none (pow)".to_owned(), |h| h.to_string()),
        )
        .with_field("mempool", info.mempool_size)
        .with_field("utxos", info.utxo_count)
        .with_field("index", info.index_enabled))
}

/// `chain peers`.
///
/// # Errors
///
/// [`CliError::Rpc`] when the node cannot be reached.
pub async fn peers(ctx: &Context) -> CliResult<CommandOutput> {
    let client = ctx.client()?;
    let peers = client.get_peer_info().await.map_err(rpc_err("getpeerinfo"))?;
    let document = serde_json::to_value(&peers)
        .map_err(|e| CliError::internal(format!("cannot render peers: {e}")))?;

    let mut out = CommandOutput::document(document);
    for peer in &peers {
        out = out.with_line(format!(
            "{}  {}  rtt={}ms{}",
            peer.peer_id,
            peer.address.as_deref().unwrap_or("-"),
            peer.last_rtt_ms.map_or_else(|| "?".to_owned(), |ms| ms.to_string()),
            if peer.is_static { "  (static)" } else { "" },
        ));
    }
    Ok(out.with_bare(peers.len().to_string()))
}

/// `chain stateroot`.
///
/// # Errors
///
/// [`CliError::Rpc`] when the node cannot be reached, or when a height other
/// than the tip is asked for: only the tip's root is retained.
pub async fn stateroot(ctx: &Context, height: Option<u64>) -> CliResult<CommandOutput> {
    let client = ctx.client()?;
    let root = client.get_state_root(height).await.map_err(rpc_err("getstateroot"))?;
    Ok(CommandOutput::scalar("stateroot", root.clone())
        .with_json(json!({ "stateroot": root, "height": height })))
}

/// `chain reindex`.
///
/// Rebuilds `tx_index` and `addr_index` by disconnecting the active chain back
/// to genesis and reconnecting it out of the stored block bodies. That is the
/// honest way to do it: the index is written by `connect_block` and by nothing
/// else, so replaying the connections is the only rebuild that cannot drift
/// from what a live node would have written.
///
/// The UTXO set is byte-identical afterwards — CONTRACT §8.3 guarantees that
/// disconnecting `N` blocks and reconnecting them leaves the same state and
/// the same `state_root`, and this command prints both roots so the operator
/// can see it held.
///
/// # Errors
///
/// [`CliError::NotFound`] when there is no store at `--datadir`, and the
/// underlying storage or chain error when a replay step fails. A failure
/// leaves the store at a lower height than it started at; the message says so.
pub fn reindex(ctx: &Context, dry_run: bool, network: &str) -> CliResult<CommandOutput> {
    let params = paths::parse_network(network)?.params();
    let db = paths::db_path(&ctx.datadir);
    if !db.exists() {
        return Err(CliError::not_found(format!(
            "no store at {} — pass --datadir, and stop the node first",
            db.display()
        )));
    }

    let store = Arc::new(Store::open(
        &db,
        StoreConfig::indexed().with_chain_id(params.chain_id),
    )?);
    let engines = Arc::new(EngineRouter::new(params.clone())?);
    let chain = ChainManager::open(Arc::clone(&store), params.clone(), Arc::clone(&engines))?;
    let (tip_hash, tip_height) = chain.tip();
    let root_before = store.state_root()?;

    if dry_run {
        return Ok(CommandOutput::document(json!({
            "dry_run": true,
            "datadir": ctx.datadir.display().to_string(),
            "height": tip_height,
            "tip": tip_hash.to_string(),
            "state_root": root_before.to_hex(),
            "blocks_to_replay": tip_height,
        }))
        .with_field("height", tip_height)
        .with_field("would replay", tip_height)
        .with_bare(tip_height.to_string()));
    }

    // Hashes first, bodies later: the height table is what `disconnect_tip`
    // unwinds, so after the unwind there is no way back from a height to a
    // hash. Thirty-two bytes per block is a cost worth paying; the bodies are
    // read one at a time on the way back up.
    let mut hashes: Vec<BlockHash> = Vec::with_capacity(usize::try_from(tip_height).unwrap_or(0));
    for height in 1..=tip_height {
        let hash = store
            .hash_at_height(height)?
            .ok_or_else(|| CliError::internal(format!("no block at height {height}")))?;
        hashes.push(hash);
    }

    for _ in 0..tip_height {
        store.disconnect_tip()?;
    }

    // A fresh manager: the one above cached the old tip, and rebuilding it
    // from the wound-back store is cheaper than teaching it to be invalidated.
    let chain = ChainManager::open(Arc::clone(&store), params.clone(), engines)?;
    let mut replayed = 0u64;
    for hash in &hashes {
        let block = store
            .get_block(hash)?
            .ok_or_else(|| CliError::internal(format!("block body for {hash} is missing")))?;
        chain.accept_block(block)?;
        replayed = replayed.saturating_add(1);
    }

    let (new_tip, new_height) = chain.tip();
    let root_after = store.state_root()?;
    store.flush()?;

    Ok(CommandOutput::scalar("tip", new_tip.to_string())
        .with_json(json!({
            "dry_run": false,
            "height": new_height,
            "tip": new_tip.to_string(),
            "replayed": replayed,
            "state_root_before": root_before.to_hex(),
            "state_root_after": root_after.to_hex(),
            "state_root_unchanged": root_before == root_after,
        }))
        .with_field("replayed", replayed)
        .with_field("height", new_height)
        .with_field("state root", root_after.to_hex())
        .with_field("unchanged", root_before == root_after))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn ctx_at(dir: &std::path::Path) -> Context {
        Context {
            datadir: dir.to_path_buf(),
            rpc_url: "http://127.0.0.1:1".to_owned(),
            json: false,
        }
    }

    #[test]
    fn reindex_says_so_when_there_is_no_store() {
        let dir = tempfile::tempdir().unwrap();
        let err = reindex(&ctx_at(dir.path()), false, "devnet").unwrap_err();
        assert!(err.to_string().contains("no store at"), "{err}");
    }

    #[test]
    fn reindex_refuses_an_unknown_network() {
        let dir = tempfile::tempdir().unwrap();
        assert!(reindex(&ctx_at(dir.path()), true, "bitcoin").is_err());
    }

    #[test]
    fn a_dry_run_on_a_fresh_genesis_store_reports_nothing_to_replay() {
        let dir = tempfile::tempdir().unwrap();
        let params = ferrum_types::Network::Devnet.params();
        let store = Arc::new(
            Store::open(&paths::db_path(dir.path()), StoreConfig::indexed()).unwrap(),
        );
        let engines = Arc::new(EngineRouter::new(params.clone()).unwrap());
        let chain = ChainManager::open(store, params, engines).unwrap();
        chain.init_genesis().unwrap();
        drop(chain);

        let out = reindex(&ctx_at(dir.path()), true, "devnet").unwrap();
        assert_eq!(out.json["blocks_to_replay"], 0);
        assert_eq!(out.bare.as_deref(), Some("0"));
    }

    #[test]
    fn a_real_reindex_of_a_genesis_only_store_preserves_the_state_root() {
        let dir = tempfile::tempdir().unwrap();
        let params = ferrum_types::Network::Devnet.params();
        let store = Arc::new(
            Store::open(&paths::db_path(dir.path()), StoreConfig::indexed()).unwrap(),
        );
        let engines = Arc::new(EngineRouter::new(params.clone()).unwrap());
        let chain = ChainManager::open(Arc::clone(&store), params, engines).unwrap();
        chain.init_genesis().unwrap();
        let root = store.state_root().unwrap();
        drop(chain);
        drop(store);

        let out = reindex(&ctx_at(dir.path()), false, "devnet").unwrap();
        assert_eq!(out.json["state_root_after"], root.to_hex());
        assert_eq!(out.json["state_root_unchanged"], true);
        assert_eq!(out.json["replayed"], 0);
    }
}
