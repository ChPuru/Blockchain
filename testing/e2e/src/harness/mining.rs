//! Driven sealing: exactly the blocks a test asks for, on exactly the node it
//! asks, announced exactly the way the node's own miner announces them.
//!
//! # The path a harness-mined block takes
//!
//! [`ferrum_node::Miner::mine_and_submit`] builds a template from the node's
//! mempool, seals it, and offers it to the node's own [`ferrum_node::Relay`] —
//! the same relay a gossiped block goes through, including the two-hour
//! future-time rule. Then the harness publishes it on the blocks topic, which
//! is what `ferrum_node::node::tasks::announce_blocks` does for the node's own
//! miner. Nothing here is a shortcut past validation: a block this harness
//! produces is a block every node in the network judges for itself.
//!
//! Sealing runs on a blocking thread, for the reason the node's miner does:
//! `ConsensusEngine::seal` is a tight hash loop with no `.await` in it, and on
//! devnet it is over in a microsecond — but a loop with no yield point on an
//! async worker is a bug that only shows up when the target gets harder.
//!
//! # Forged blocks
//!
//! [`TestNet::forge_bad_merkle_block`] exists so a test can feed a node
//! something a peer could really send. It corrupts the merkle root and then
//! **re-seals**, so the proof of work is valid and the merkle-root rule is the
//! only rule the block breaks. A block with a corrupted root and a stale nonce
//! would usually fail the target check first, and the test would pass while
//! asserting nothing about rule 3.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result, anyhow, bail};
use ferrum_chain::AcceptOutcome;
use ferrum_consensus::BlockTemplate;
use ferrum_types::{Block, BlockHash, Hash32};

use crate::harness::TestNet;

impl TestNet {
    /// Seal `count` blocks on node `index` and announce each one.
    ///
    /// Blocks are mined one at a time, each on top of the last, and each is
    /// required to extend the active chain: a block that came back as an
    /// orphan or a side chain means the node's tip moved underneath the miner,
    /// which in a harness that owns all the mining is a bug worth failing on
    /// rather than retrying past.
    ///
    /// Returns the hashes in the order they were sealed.
    ///
    /// # Errors
    ///
    /// When the node is not running, when a round produces no block, or when a
    /// sealed block does not extend the chain.
    pub async fn mine_blocks(&self, index: usize, count: usize) -> Result<Vec<BlockHash>> {
        let mut hashes = Vec::with_capacity(count);
        for _ in 0..count {
            hashes.push(self.mine_one(index).await?);
        }
        Ok(hashes)
    }

    /// Seal exactly one block on node `index`.
    ///
    /// # Errors
    ///
    /// As [`TestNet::mine_blocks`].
    pub async fn mine_one(&self, index: usize) -> Result<BlockHash> {
        let miner = Arc::clone(&self.running(index)?.miner);
        let mined = tokio::task::spawn_blocking(move || {
            // Never cancelled: the harness decides when a round ends, and a
            // round that ends early would silently mine fewer blocks than the
            // test asked for.
            miner.mine_and_submit(&AtomicBool::new(false))
        })
        .await
        .with_context(|| format!("the sealing thread for node {index} panicked"))?
        .with_context(|| format!("node {index} could not seal a block"))?;

        let Some((block, outcome)) = mined else {
            bail!("node {index}'s mining round was cancelled, which the harness never asks for");
        };
        match &outcome.outcome {
            Some(AcceptOutcome::Extended(hash)) => {
                let hash = *hash;
                self.announce(index, block).await?;
                Ok(hash)
            }
            other => bail!(
                "node {index} sealed {} on parent {} but its own chain answered {other:?}{}",
                outcome.hash,
                block.header.prev_hash,
                outcome.error.as_ref().map_or_else(String::new, |e| format!(": {e}"))
            ),
        }
    }

    /// Publish a block on the blocks topic from node `index`.
    ///
    /// A publish that finds no mesh peer is not an error: a node whose peers
    /// have not finished their gossipsub handshake is the normal state of a
    /// network in its first second, and the peers will pick the block up
    /// through headers-first sync instead. Every other publish failure is
    /// reported, because it means the swarm is gone.
    ///
    /// # Errors
    ///
    /// When the node is not running, has no p2p service, or the publish failed
    /// for a reason other than having nobody to publish to.
    pub async fn announce(&self, index: usize, block: Block) -> Result<()> {
        let node = self.node(index)?;
        let handle = node
            .p2p()
            .ok_or_else(|| anyhow!("node {index} has no p2p service to announce through"))?;
        match handle.publish_block(block).await {
            Ok(_) => Ok(()),
            Err(e) if e.is_no_peers() => {
                tracing::debug!(node = index, "no mesh peers yet; the block will travel by sync");
                Ok(())
            }
            Err(e) => Err(anyhow!("node {index} could not announce a block: {e}")),
        }
    }

    /// Build a block that is valid in every way except its merkle root.
    ///
    /// The template comes from node `index`'s own miner, so the block is a
    /// legitimate successor to that node's tip: right parent, right `bits`,
    /// right height in the coinbase. Then one byte of the merkle root is
    /// flipped and the block is re-sealed, so it carries valid proof of work
    /// for the corrupted header.
    ///
    /// It is never offered to the node that built it. Feed it to a *peer* with
    /// [`TestNet::announce`] and watch that peer refuse it.
    ///
    /// # Errors
    ///
    /// When the node is not running, when no template can be built, or when
    /// sealing fails.
    pub fn forge_bad_merkle_block(&self, index: usize) -> Result<Block> {
        let running = self.running(index)?;
        let node = &running.node;
        let template = running
            .miner
            .build_template(node.relay().now_ms())
            .with_context(|| format!("building a template on node {index}"))?;

        let mut header = template.header;
        let mut bytes = *header.merkle_root.as_bytes();
        // Flip the top byte rather than zeroing the root: a zero root is also
        // what an empty transaction list produces, and a test should not be
        // able to pass by rejecting the wrong thing.
        bytes[0] ^= 0xff;
        header.merkle_root = Hash32::from_bytes(bytes);

        let height = template.height;
        let engine = node.chain().engines().engine_for_height(height);
        let forged = engine
            .seal(BlockTemplate { header, txs: template.txs, height }, &AtomicBool::new(false))
            .with_context(|| format!("sealing a forged block at height {height}"))?
            .ok_or_else(|| anyhow!("sealing a forged block was cancelled"))?;
        Ok(forged)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_chain::compute_merkle_root;
    use ferrum_consensus::{ConsensusEngine, HeaderView, PowEngine};
    use ferrum_node::GossipVerdict;
    use ferrum_node::relay::BlockRejection;
    use ferrum_storage::header_hash;
    use ferrum_types::ChainParams;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mining_extends_the_chain_one_block_at_a_time() {
        let net = TestNet::spawn(1).await.unwrap();
        let hashes = net.mine_blocks(0, 5).await.unwrap();
        assert_eq!(hashes.len(), 5);
        assert_eq!(net.height(0).unwrap(), 5);
        assert_eq!(net.tip(0).unwrap(), hashes[4]);

        let store = net.node(0).unwrap().store();
        for (i, hash) in hashes.iter().enumerate() {
            let height = u64::try_from(i).unwrap() + 1;
            assert_eq!(store.hash_at_height(height).unwrap(), Some(*hash));
        }
        net.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mining_on_a_node_that_is_down_is_an_error() {
        let mut net = TestNet::spawn(1).await.unwrap();
        net.kill(0).await.unwrap();
        assert!(net.mine_one(0).await.is_err());
        assert!(net.forge_bad_merkle_block(0).is_err());
        net.shutdown().await.unwrap();
    }

    /// The deterministic half of `invalid_block_is_rejected_and_peer_scored`:
    /// no network, no timing, just the verdict the relay reaches — which is
    /// the value that becomes gossipsub's P4 invalid-message score.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_forged_block_has_valid_work_and_is_rejected_as_consensus_invalid() {
        let net = TestNet::spawn(1).await.unwrap();
        net.mine_blocks(0, 2).await.unwrap();

        let forged = net.forge_bad_merkle_block(0).unwrap();
        assert_ne!(
            forged.header.merkle_root,
            compute_merkle_root(&forged.txs),
            "the forged root must not match the transactions"
        );

        // The proof of work is real: the header check passes and only the
        // merkle rule fails, which is what makes this a test of rule 3.
        let node = net.node(0).unwrap();
        let params = ChainParams::devnet();
        let engine = PowEngine::new(params.clone());
        let view = ferrum_chain::StoreHeaderView::new(node.store(), &params);
        let parent = view.header_by_hash(&forged.header.prev_hash).unwrap();
        assert!(
            engine.validate_header(&forged.header, &parent, &view).is_ok(),
            "the forged header must satisfy the target, or the test proves nothing"
        );

        let before = net.tip(0).unwrap();
        let outcome = node.relay().accept_block(forged.clone());
        assert_eq!(outcome.hash, header_hash(&forged.header));
        assert_eq!(outcome.verdict, GossipVerdict::Reject, "the sender must be scored down");
        assert_eq!(outcome.rejection, Some(BlockRejection::Invalid));
        assert_eq!(net.tip(0).unwrap(), before, "the tip did not move");

        // And the node is still a node.
        net.mine_one(0).await.unwrap();
        assert_eq!(net.height(0).unwrap(), 3);
        net.shutdown().await.unwrap();
    }
}
