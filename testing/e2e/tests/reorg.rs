//! Split a network, let both halves build, heal it, and require the loser to
//! give up its coins as well as its tip.
//!
//! This is the test the rest of the suite exists to make possible. Everything a
//! blockchain is for lives in it: fork choice by cumulative work rather than by
//! height, a reorg that disconnects real blocks and reconnects other ones, undo
//! records that restore the exact UTXO entries the losing branch spent, and a
//! network that finds all of that on its own with nobody telling it which side
//! won.
//!
//! # Why the assertion is on the UTXO set and not on the tip
//!
//! Two nodes reporting the same tip hash have agreed on a *header chain*. They
//! have said nothing about coins. A reorg that rewound the headers but left a
//! spent output in the UTXO set — or restored a coin at the wrong height, so
//! its maturity is wrong — produces exactly the same tip and a chain that
//! disagrees with itself the first time someone spends. `state_root` is the
//! Merkle root over every outpoint and coin in the set (CONTRACT §7), so
//! comparing it is comparing the whole of what a reorg is supposed to fix.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use anyhow::{Context, Result};
use ferrum_e2e::harness::TestNet;

/// Overall budget. A backstop for a hang: every wait inside prints the whole
/// network when its own timeout expires.
const BUDGET: Duration = Duration::from_secs(420);

/// How long the mesh is given to form, before and after the split.
const MESH_TIMEOUT: Duration = Duration::from_secs(90);

/// How long the chain is given to agree.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(180);

/// Blocks mined before the split, shared by both branches.
const COMMON: usize = 5;

/// Blocks the winning half mines while the network is split.
const WINNER_BLOCKS: usize = 6;

/// Blocks the losing half mines. Fewer, so it has strictly less work — and
/// deliberately not zero, so the loser really does have a branch to abandon.
const LOSER_BLOCKS: usize = 2;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partition_then_heal_reorgs() -> Result<()> {
    tokio::time::timeout(BUDGET, body())
        .await
        .context("partition_then_heal_reorgs exceeded its overall budget")?
}

#[allow(clippy::too_many_lines)]
async fn body() -> Result<()> {
    let mut net = TestNet::spawn(4).await?;
    net.await_peers(MESH_TIMEOUT).await?;

    // ---- a shared history everybody agrees on --------------------------
    net.mine_blocks(0, COMMON).await?;
    let fork_point = net.await_convergence(SETTLE_TIMEOUT).await?;
    let fork_height = u64::try_from(COMMON)?;
    assert_eq!(net.height(3)?, fork_height);

    // ---- split 2 | 2 ---------------------------------------------------
    net.partition(&[0, 1], &[2, 3]).await?;
    net.await_peer_count(1, MESH_TIMEOUT).await?;

    net.mine_blocks(0, WINNER_BLOCKS).await?;
    net.mine_blocks(2, LOSER_BLOCKS).await?;

    // Each half agrees with itself...
    let winner_height = fork_height + u64::try_from(WINNER_BLOCKS)?;
    let loser_height = fork_height + u64::try_from(LOSER_BLOCKS)?;
    net.await_height(1, winner_height, SETTLE_TIMEOUT).await?;
    net.await_height(3, loser_height, SETTLE_TIMEOUT).await?;

    let winning_tip = net.tip(0)?;
    let losing_tip = net.tip(2)?;
    assert_eq!(net.tip(1)?, winning_tip, "the winning half agrees with itself");
    assert_eq!(net.tip(3)?, losing_tip, "and so does the losing half");
    assert_ne!(winning_tip, losing_tip, "a partition that did not fork proves nothing");

    // ...and the split is real: neither half has heard of the other's blocks.
    assert!(
        net.node(2)?.store().get_header(&winning_tip)?.is_none(),
        "the losing half must not already know the winning branch"
    );

    // Fork choice is by work, so that is what the test compares. The heights
    // happen to agree with it here, and a test that asserted on height would
    // pass on a chain whose fork choice was wrong.
    let winner_work = net.total_work(0)?;
    let loser_work = net.total_work(2)?;
    assert!(
        winner_work > loser_work,
        "the six-block branch must carry more work than the two-block one: \
         {winner_work:?} vs {loser_work:?}"
    );

    // The block the loser is about to lose, so the assertion afterwards can be
    // about *that* block rather than about a height.
    let doomed = net
        .node(2)?
        .store()
        .hash_at_height(fork_height + 1)?
        .context("the losing half has no block after the fork point")?;

    // ---- heal ----------------------------------------------------------
    net.heal().await?;
    net.await_peers(MESH_TIMEOUT).await?;

    let tip = net.await_convergence(SETTLE_TIMEOUT).await?;
    assert_eq!(tip, winning_tip, "the network converged on the branch with more work");

    let root = net.state_root(0)?;
    for index in 0..net.len() {
        assert_eq!(net.tip(index)?, winning_tip, "node {index} is on the winning tip");
        assert_eq!(net.height(index)?, winner_height);
        assert_eq!(net.total_work(index)?, winner_work);
        assert_eq!(
            net.state_root(index)?,
            root,
            "node {index} reached the winning tip with a different UTXO set, which is \
             the reorg failing quietly\n{}",
            net.describe().await
        );
    }

    // The losing half really reorganised: it recorded one, and the block it
    // mined is stored but no longer on the active chain.
    for loser in [2usize, 3] {
        let metrics = net
            .await_metrics(loser, "record a reorganisation", |m| m.reorgs >= 1, SETTLE_TIMEOUT)
            .await?;
        assert_eq!(
            metrics.reorg_depth,
            u64::try_from(LOSER_BLOCKS)?,
            "node {loser} should have disconnected exactly its own branch"
        );
    }

    let store = net.node(2)?.store();
    assert!(
        store.get_header(&doomed)?.is_some(),
        "a disconnected block is kept, not deleted: it may yet win"
    );
    assert_eq!(
        store.hash_at_height(fork_height + 1)?,
        net.node(0)?.store().hash_at_height(fork_height + 1)?,
        "the active chain above the fork point is now the winner's"
    );
    assert_ne!(store.hash_at_height(fork_height + 1)?, Some(doomed));
    assert_eq!(
        store.hash_at_height(fork_height)?,
        Some(fork_point),
        "everything below the fork point is untouched"
    );

    net.shutdown().await
}
