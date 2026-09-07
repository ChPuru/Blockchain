//! What a node does when something goes wrong: it is killed without warning,
//! and it is handed a block a peer had no business sending.
//!
//! Both are about the same property — a node that survives an insult without
//! losing state and without believing a lie. The first is `devnet/kill.sh`
//! followed by `devnet/up.sh`; the second is the case the shell devnet cannot
//! stage at all, because forging a block needs a miner you control.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use anyhow::{Context, Result};
use ferrum_e2e::harness::TestNet;
use ferrum_node::GossipVerdict;
use ferrum_node::relay::BlockRejection;

/// Overall budget for `restart_preserves_chain`.
const RESTART_BUDGET: Duration = Duration::from_secs(300);

/// Overall budget for `invalid_block_is_rejected_and_peer_scored`.
const INVALID_BUDGET: Duration = Duration::from_secs(240);

/// How long the mesh is given to form.
const MESH_TIMEOUT: Duration = Duration::from_secs(90);

/// How long the chain is given to agree.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(180);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_preserves_chain() -> Result<()> {
    tokio::time::timeout(RESTART_BUDGET, restart_body())
        .await
        .context("restart_preserves_chain exceeded its overall budget")?
}

async fn restart_body() -> Result<()> {
    /// Blocks mined while the victim is watching.
    const BEFORE: usize = 10;
    /// Blocks mined while the victim is dead, which it has to catch up on.
    const WHILE_DOWN: usize = 5;

    let mut net = TestNet::spawn(2).await?;
    net.await_peers(MESH_TIMEOUT).await?;
    net.mine_blocks(0, BEFORE).await?;
    net.await_convergence(SETTLE_TIMEOUT).await?;

    let before_height = net.height(1)?;
    let before_tip = net.tip(1)?;
    let before_root = net.state_root(1)?;
    assert_eq!(before_height, u64::try_from(BEFORE)?);

    // Killed, not shut down: the cancellation token is raised and the node is
    // dropped without `Node::shutdown`, so nothing flushes. Whatever survives
    // is what `redb` had already committed — head pointer last, inside each
    // block's single write transaction (CONTRACT §7).
    net.kill(1).await?;
    net.mine_blocks(0, WHILE_DOWN).await?;
    assert_eq!(net.height(0)?, u64::try_from(BEFORE + WHILE_DOWN)?);

    net.restart(1).await?;

    // Nothing was lost. Stated as a prefix rather than an equality on purpose:
    // the restarted node starts syncing the moment it reconnects, so asserting
    // "the height is still exactly ten" would be racing its own recovery. What
    // must hold — and what a lost block would break — is that the chain it had
    // before the kill is still its own history.
    let recovered = net.height(1)?;
    assert!(
        recovered >= before_height,
        "a hard kill lost blocks: height {before_height} became {recovered}\n{}",
        net.describe().await
    );
    assert_eq!(
        net.node(1)?.store().hash_at_height(before_height)?,
        Some(before_tip),
        "the block that was the tip before the kill is no longer at its own height"
    );
    if recovered == before_height {
        assert_eq!(net.state_root(1)?, before_root, "the UTXO set came back unchanged");
        assert_eq!(net.tip(1)?, before_tip);
    }

    // And it rejoins: no operator step, no reindex, no resync flag.
    net.await_peers(MESH_TIMEOUT).await?;
    let tip = net.await_convergence(SETTLE_TIMEOUT).await?;
    assert_eq!(net.height(1)?, u64::try_from(BEFORE + WHILE_DOWN)?);
    assert_eq!(net.tip(1)?, tip);
    assert_eq!(net.state_root(1)?, net.state_root(0)?);

    // Every block it missed is on its disk, bodies included.
    let store = net.node(1)?.store();
    for height in 0..=net.height(1)? {
        let hash = store
            .hash_at_height(height)?
            .with_context(|| format!("no block at height {height} after recovery"))?;
        assert!(store.get_block(&hash)?.is_some(), "missing the body of {hash}");
    }

    net.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_block_is_rejected_and_peer_scored() -> Result<()> {
    tokio::time::timeout(INVALID_BUDGET, invalid_block_body())
        .await
        .context("invalid_block_is_rejected_and_peer_scored exceeded its overall budget")?
}

async fn invalid_block_body() -> Result<()> {
    let net = TestNet::spawn(2).await?;
    net.await_peers(MESH_TIMEOUT).await?;
    net.mine_blocks(0, 3).await?;
    let honest_tip = net.await_convergence(SETTLE_TIMEOUT).await?;

    // Node 1 builds a block on the shared tip and corrupts its merkle root,
    // then re-seals it. The proof of work is genuine, so the victim cannot
    // dismiss it on the target check: rule 3 — `compute_merkle_root(txs) ==
    // header.merkle_root` (SPEC §3.1) — is the only rule it breaks, which is
    // the only way this test can be about rule 3.
    let forged = net.forge_bad_merkle_block(1)?;
    assert_eq!(forged.header.prev_hash, honest_tip, "the forgery builds on the real tip");
    let before = net.metrics(0)?;

    net.announce(1, forged.clone()).await?;

    let after = net
        .await_metrics(
            0,
            "reject the forged block",
            |m| m.blocks_rejected > before.blocks_rejected,
            SETTLE_TIMEOUT,
        )
        .await?;
    assert_eq!(after.blocks_accepted, before.blocks_accepted, "and accepted nothing");

    // The victim kept its tip.
    assert_eq!(net.tip(0)?, honest_tip, "a rejected block must not move the tip");
    assert_eq!(net.height(0)?, 3);
    assert_eq!(net.state_root(0)?, net.state_root(1)?, "and must not touch the UTXO set");

    // The verdict that becomes gossipsub's P4 invalid-message score. Offered
    // directly this time, because the value the relay returns is what the p2p
    // layer feeds back to the sender and it is not observable from outside the
    // node. A block already judged invalid is refused the same way the second
    // time, which is what makes this assertion deterministic.
    let outcome = net.node(0)?.relay().accept_block(forged);
    assert_eq!(
        outcome.verdict,
        GossipVerdict::Reject,
        "a consensus-invalid block must lower the sender's score, not be ignored"
    );
    assert_eq!(outcome.rejection, Some(BlockRejection::Invalid));

    // And it is still a node: it mines, its peer takes the block, both agree.
    net.mine_blocks(0, 1).await?;
    let tip = net.await_convergence(SETTLE_TIMEOUT).await?;
    assert_eq!(net.height(0)?, 4);
    assert_eq!(net.height(1)?, 4, "the peer that sent the forgery is not banned from gossip");
    assert_eq!(net.tip(1)?, tip);

    net.shutdown().await
}
