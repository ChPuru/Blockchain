//! Two nodes agreeing, and a node that turns up late.
//!
//! These are the two cheapest questions a multi-node chain has to answer, and
//! the second one is the one that quietly stops being true. A network converges
//! from the day it is written; a network stays *joinable* only for as long as
//! nothing has broken headers-first sync, and nobody notices that until a
//! stranger tries — which on a public chain is a launch, not a test run.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use anyhow::{Context, Result};
use ferrum_e2e::harness::TestNet;
use ferrum_rpc::FerrumRpcClient;
use jsonrpsee::http_client::HttpClientBuilder;

/// Overall budget for `two_nodes_converge`.
///
/// A backstop, not a target: every wait inside has its own timeout and prints
/// the whole network when it expires. This one only catches a hang.
const CONVERGE_BUDGET: Duration = Duration::from_secs(240);

/// Overall budget for `late_joiner_syncs_from_genesis`, which mines thirty
/// blocks and then syncs a fourth node from zero.
const JOINER_BUDGET: Duration = Duration::from_secs(300);

/// How long a two-node network is given to notice each other.
const MESH_TIMEOUT: Duration = Duration::from_secs(90);

/// How long the chain is given to agree.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_converge() -> Result<()> {
    tokio::time::timeout(CONVERGE_BUDGET, two_nodes_converge_body())
        .await
        .context("two_nodes_converge exceeded its overall budget")?
}

async fn two_nodes_converge_body() -> Result<()> {
    let net = TestNet::spawn(2).await?;
    net.await_peers(MESH_TIMEOUT).await?;

    // Node A mines. Node B is told nothing and asked for nothing.
    let mined = net.mine_blocks(0, 5).await?;
    let tip = net.await_convergence(SETTLE_TIMEOUT).await?;

    assert_eq!(tip, mined[4], "the network converged on the block node A sealed last");
    assert_eq!(net.height(0)?, 5);
    assert_eq!(net.height(1)?, 5, "node B reached the same height");
    assert_eq!(net.tip(1)?, tip, "and the same tip");
    assert_eq!(
        net.state_root(1)?,
        net.state_root(0)?,
        "agreeing on a tip is not the same as agreeing on the coins; both must hold"
    );
    assert_eq!(net.total_work(1)?, net.total_work(0)?);

    // The same claim, over the wire this time: a test that only reads the
    // in-process handles cannot catch a JSON-RPC surface that has drifted, and
    // `devnet/ci-e2e.sh` asks the chain exactly this question with `curl`.
    let addr = net.node(1)?.rpc_addr().context("node B bound no JSON-RPC listener")?;
    let client = HttpClientBuilder::default().build(format!("http://{addr}"))?;
    let info = client.get_blockchain_info().await?;
    assert_eq!(info.chain, "devnet");
    assert_eq!(info.height, 5);
    assert_eq!(info.best_hash, tip.0.to_hex());
    assert_eq!(info.engine, "pow");
    assert_eq!(info.finalized_height, None, "under proof of work nothing is final");

    net.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_joiner_syncs_from_genesis() -> Result<()> {
    tokio::time::timeout(JOINER_BUDGET, late_joiner_body())
        .await
        .context("late_joiner_syncs_from_genesis exceeded its overall budget")?
}

async fn late_joiner_body() -> Result<()> {
    const HISTORY: usize = 30;

    let mut net = TestNet::spawn(3).await?;
    net.await_peers(MESH_TIMEOUT).await?;
    net.mine_blocks(0, HISTORY).await?;
    let tip = net.await_convergence(SETTLE_TIMEOUT).await?;
    let root = net.state_root(0)?;

    // A fourth node, started now, knowing only where the others listen. No
    // snapshot, no checkpoint, no operator step: this is what a stranger does.
    let joiner = net.join().await?;
    assert_eq!(joiner, 3);
    assert_eq!(net.height(joiner)?, 0, "the joiner starts at genesis");

    let converged = net.await_convergence(SETTLE_TIMEOUT).await?;
    assert_eq!(converged, tip, "the network did not move; the joiner came to it");
    assert_eq!(net.height(joiner)?, u64::try_from(HISTORY)?);
    assert_eq!(net.tip(joiner)?, tip);
    assert_eq!(
        net.state_root(joiner)?,
        root,
        "a joiner that reached the right tip with the wrong UTXO set has not synced"
    );

    // It really walked the chain: every block body is on its disk, not just the
    // headers it needed to pick a tip.
    let store = net.node(joiner)?.store();
    for height in 0..=u64::try_from(HISTORY)? {
        let hash = store
            .hash_at_height(height)?
            .with_context(|| format!("the joiner has no block at height {height}"))?;
        assert!(
            store.get_block(&hash)?.is_some(),
            "the joiner has header {hash} at height {height} but not its body"
        );
    }

    net.shutdown().await
}
