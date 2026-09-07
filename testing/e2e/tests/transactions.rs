//! Money crossing the network, and money surviving a reorganisation.
//!
//! Both tests spend a real coinbase with a real BIP-340 signature, which means
//! both have to mine past `coinbase_maturity` first — eleven blocks on devnet,
//! where the window is 10, against a hundred and one on mainnet. The *rule* is
//! not negotiable and is not relaxed here: it is the same comparison in the
//! same `apply_block`, exercised at both boundaries, and it is precisely the
//! rule a reorg exists to protect. Only the constant is smaller, because
//! devnet's blocks now cost real proof of work and a hundred-block warm-up
//! would make these tests a hashing benchmark instead of a network test.
//!
//! # Why the second test is the interesting one
//!
//! A transaction that propagates is a network working. A transaction that comes
//! *back* from a block that was undone is the mempool and the reorg agreeing
//! with each other, and it is the failure mode that silently destroys money: if
//! a reorg drops a confirmed transaction and nobody re-queues it, the payment
//! simply never happened and the sender has a receipt saying otherwise.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use anyhow::{Context, Result};
use ferrum_e2e::harness::TestNet;
use ferrum_types::{Amount, COIN};

/// Overall budget for `transaction_propagates`: three nodes, and a hundred and
/// one blocks that all three have to validate.
const PROPAGATE_BUDGET: Duration = Duration::from_secs(600);

/// Overall budget for `mempool_survives_reorg`.
const REORG_BUDGET: Duration = Duration::from_secs(600);

/// How long the mesh is given to form.
const MESH_TIMEOUT: Duration = Duration::from_secs(90);

/// How long the chain is given to agree, including the maturity run.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(300);

/// How long one transaction is given to cross the network.
const RELAY_TIMEOUT: Duration = Duration::from_secs(120);

/// What the tests send: one whole FRM, comfortably above the dust threshold and
/// well inside a single fifty-FRM coinbase.
const PAYMENT: Amount = Amount::from_grains(COIN);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transaction_propagates() -> Result<()> {
    tokio::time::timeout(PROPAGATE_BUDGET, propagate_body())
        .await
        .context("transaction_propagates exceeded its overall budget")?
}

async fn propagate_body() -> Result<()> {
    let net = TestNet::spawn(3).await?;
    net.await_peers(MESH_TIMEOUT).await?;

    // Node 1 mines until its first coinbase is spendable, and the other two
    // follow it there.
    let height = net.mine_to_maturity(0).await?;
    net.await_convergence(SETTLE_TIMEOUT).await?;
    assert_eq!(height, net.params().coinbase_maturity + 1);
    assert!(net.spendable_balance(0)? > Amount::ZERO);

    // Submitted to node 1, paying node 3.
    let payee = net.address(2)?;
    let tx = net.build_payment(0, &payee, PAYMENT)?;
    let txid = net.submit_transaction(0, tx).await?;
    assert!(net.mempool_contains(0, &txid)?, "the node it was submitted to kept it");

    // It reaches the other two by gossip, unasked.
    net.await_in_mempool(1, &txid, RELAY_TIMEOUT).await?;
    net.await_in_mempool(2, &txid, RELAY_TIMEOUT).await?;
    assert_eq!(net.confirmed_in(2, &txid)?, None, "in the pool is not in a block");

    // Mined by node 2, which is not the node that was asked to send it.
    let block = net.mine_one(1).await?;
    net.await_convergence(SETTLE_TIMEOUT).await?;

    // And node 3 sees it confirmed, in the block node 2 built, at the height
    // everybody agrees on.
    let location = net.await_confirmed(2, &txid, RELAY_TIMEOUT).await?;
    assert_eq!(location.block_hash, block, "confirmed in the block node 2 mined");
    assert!(location.index > 0, "a payment is never the coinbase");
    assert_eq!(net.height(2)?, height + 1);
    assert!(!net.mempool_contains(2, &txid)?, "a confirmed transaction leaves the pool");

    // The payee really owns the coin: it is in node 3's UTXO set under node
    // 3's own script, which is what "paid" means.
    assert!(
        net.spendable_coins(2)?.iter().any(|(op, _)| op.txid == txid),
        "the payee's UTXO set has no output from {txid}"
    );

    // Every node agrees on every coin, not merely on the tip.
    let root = net.state_root(0)?;
    for index in 0..net.len() {
        assert_eq!(net.state_root(index)?, root, "node {index} disagrees about the coins");
    }

    net.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mempool_survives_reorg() -> Result<()> {
    tokio::time::timeout(REORG_BUDGET, mempool_reorg_body())
        .await
        .context("mempool_survives_reorg exceeded its overall budget")?
}

async fn mempool_reorg_body() -> Result<()> {
    /// Blocks the winning side mines while the network is split. More than the
    /// one block the losing side mines, so the losing side's block — and the
    /// transaction in it — is undone.
    const WINNER_BLOCKS: usize = 4;

    let mut net = TestNet::spawn(2).await?;
    net.await_peers(MESH_TIMEOUT).await?;
    let matured = net.mine_to_maturity(0).await?;
    net.await_convergence(SETTLE_TIMEOUT).await?;

    // Node 0 will win; node 1 will lose. The payment is built from node 0's
    // coins — it holds the only mature ones — but it is submitted to node 1,
    // so it is confirmed only on the branch that is about to be abandoned.
    let payee = net.address(1)?;
    let tx = net.build_payment(0, &payee, PAYMENT)?;

    net.partition(&[0], &[1]).await?;

    let txid = net.submit_transaction(1, tx).await?;
    let doomed = net.mine_one(1).await?;
    let location = net.await_confirmed(1, &txid, RELAY_TIMEOUT).await?;
    assert_eq!(location.block_hash, doomed, "confirmed on the branch that will lose");
    assert!(!net.mempool_contains(1, &txid)?);

    // The other side, which never heard of the transaction, builds more work.
    net.mine_blocks(0, WINNER_BLOCKS).await?;
    assert!(!net.mempool_contains(0, &txid)?, "the winning side never saw it");
    assert_eq!(net.confirmed_in(0, &txid)?, None);
    assert!(net.total_work(0)? > net.total_work(1)?);
    let winning_tip = net.tip(0)?;

    // ---- heal ----------------------------------------------------------
    net.heal().await?;
    net.await_peers(MESH_TIMEOUT).await?;
    let tip = net.await_convergence(SETTLE_TIMEOUT).await?;
    assert_eq!(tip, winning_tip, "the network took the branch with more work");
    assert_eq!(net.height(1)?, matured + u64::try_from(WINNER_BLOCKS)?);

    // The transaction was in a block and now is not. It must be back in the
    // pool of the node that lost it — `Mempool::reconcile_reorg` re-adding the
    // transactions of every disconnected block (CONTRACT §9) — and it must not
    // still be reported as confirmed.
    net.await_in_mempool(1, &txid, RELAY_TIMEOUT).await?;
    assert_eq!(
        net.confirmed_in(1, &txid)?,
        None,
        "a transaction whose block was disconnected is not confirmed any more"
    );
    assert_eq!(
        net.node(1)?.store().get_coin(&ferrum_types::OutPoint { txid, vout: 0 })?,
        None,
        "and its outputs are not in the UTXO set"
    );

    // And it is mineable again: the same transaction, in a block on the branch
    // that won, seen by the node that never had it in its pool.
    let reborn = net.mine_one(1).await?;
    net.await_convergence(SETTLE_TIMEOUT).await?;
    let again = net.await_confirmed(0, &txid, RELAY_TIMEOUT).await?;
    assert_eq!(again.block_hash, reborn, "re-confirmed in the newly mined block");
    assert_ne!(again.block_hash, doomed, "and not in the block that was undone");
    assert!(!net.mempool_contains(1, &txid)?);
    assert_eq!(net.state_root(0)?, net.state_root(1)?);

    net.shutdown().await
}
