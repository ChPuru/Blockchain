//! **Attack:** a reorganisation deeper than the mempool can remember.
//!
//! When a branch wins, every transaction in the blocks that came off is
//! suddenly unconfirmed again. SPEC §7.2 step 5 says the mempool re-adds them,
//! drops those now invalid, and evicts anything double-spent by the new chain.
//! But a mempool is a bounded cache — CONTRACT §9 gives it `max_bytes`,
//! `max_orphans` and `expiry_blocks` — so past some depth it simply cannot hold
//! what came off. That is not a bug, and the point of this scenario is to
//! prove what must remain true when it happens:
//!
//! * the **UTXO set** is restored exactly, from the undo records, so the coins
//!   those forgotten transactions spent are unspent again and their owners
//!   have lost nothing;
//! * the resulting state is **identical to a replay of the winning branch from
//!   genesis** — the reorganisation path and the from-scratch path agree, which
//!   is the property that makes undo records trustworthy (SPEC §7.3);
//! * nothing from the abandoned branch survives in the state.
//!
//! A mempool that forgot a transaction costs its sender a rebroadcast. A UTXO
//! set that forgot to undo a spend costs everyone the chain.
//!
//! **Red:** the pre-reorganisation state root is *not* the post-reorganisation
//! one, and a naive implementation that skipped the undo records would leave
//! the abandoned branch's spends applied — shown by comparing against the
//! independently replayed branch.
//! **Green:** after a reorganisation deeper than the modelled mempool memory,
//! the store matches the from-genesis replay byte for byte.

use std::collections::BTreeMap;

use ferrum_types::{Amount, Block, ChainParams, Transaction, Txid};

use crate::chain_builder::{BlockPlan, ChainBuilder, TxPlan};
use crate::error::SimError;
use crate::keys::Lock;
use crate::node::SimNode;

/// How many blocks of disconnected history the modelled mempool remembers.
///
/// A stand-in for CONTRACT §9's bounded pool. The number is small on purpose:
/// the scenario is about what happens *past* the horizon, and a realistic
/// horizon would make the fixture hundreds of blocks long for no extra signal.
pub const MEMPOOL_REORG_MEMORY: usize = 4;

/// Devnet with a short coinbase maturity.
///
/// Maturity is orthogonal to reorganisation, and a hundred-block warm-up in
/// every fixture would make this scenario slow without making it stronger.
#[must_use]
pub fn short_maturity_params() -> ChainParams {
    let mut params = crate::sim_params();
    params.coinbase_maturity = 5;
    params
}

/// A mempool that remembers only the most recent `memory` disconnected blocks.
#[derive(Clone, Debug, Default)]
pub struct SimMempool {
    entries: BTreeMap<Txid, Transaction>,
    forgotten: Vec<Txid>,
}

impl SimMempool {
    /// An empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Re-add the transactions from `disconnected`, keeping only those from the
    /// `memory` shallowest blocks and recording the rest as forgotten.
    ///
    /// `disconnected` is tip-first, which is the order a reorganisation
    /// produces and therefore the order in which a bounded pool fills up.
    pub fn reconcile(&mut self, disconnected: &[Block], memory: usize) {
        for (depth, block) in disconnected.iter().enumerate() {
            for tx in block.txs.iter().skip(1) {
                let id = ferrum_storage::txid(tx);
                if depth < memory {
                    self.entries.insert(id, tx.clone());
                } else {
                    self.forgotten.push(id);
                }
            }
        }
    }

    /// How many transactions the pool holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The transactions the pool could not keep.
    #[must_use]
    pub fn forgotten(&self) -> &[Txid] {
        &self.forgotten
    }

    /// Whether the pool holds `id`.
    #[must_use]
    pub fn holds(&self, id: &Txid) -> bool {
        self.entries.contains_key(id)
    }
}

/// The chains this scenario runs on: an honest one with real spends, and a
/// longer branch forked below all of them.
#[derive(Debug)]
pub struct ReorgFixture {
    /// The node under test, holding the honest chain.
    pub node: SimNode,
    /// The honest chain's blocks, genesis first.
    pub honest: Vec<Block>,
    /// The winning branch's blocks, in order.
    pub branch: Vec<Block>,
    /// The height the two chains diverge at.
    pub fork_height: u64,
    /// Outpoints the honest chain spent whose *creating* block is at or below
    /// the fork point.
    ///
    /// Only these can be checked after the reorganisation: a coin created
    /// **above** the fork point disappears with its block, so it is neither
    /// spent nor unspent afterwards — it never existed on the winning chain.
    pub spent_only_on_honest: Vec<ferrum_types::OutPoint>,
}

/// Build the fixture: an honest chain that spends coins, and a longer branch
/// forked below every one of those spends.
///
/// # Errors
///
/// [`SimError`] if a block cannot be built or is rejected.
pub fn build_fixture(
    seed: u64,
    warmup: usize,
    payments: usize,
    branch_extra: usize,
) -> Result<ReorgFixture, SimError> {
    let params = short_maturity_params();
    let node = SimNode::open(params.clone())?;
    let mut chain = ChainBuilder::new(params, seed)?;

    // Warm up past maturity so there is something to spend.
    for _ in 0..warmup {
        let block = chain.build_block(&BlockPlan::default())?;
        chain.connect(&block);
        node.accept_expecting_extension(block)?;
    }
    let fork_height = chain.height();

    // Then a run of blocks that each spend a matured coinbase.
    let mut spent = Vec::new();
    for _ in 0..payments {
        let height = chain.height().saturating_add(1);
        let coins = chain.take_mature(1, height);
        let txs = if coins.is_empty() {
            Vec::new()
        } else {
            // Only coins that exist on both sides of the fork point are
            // meaningful after the reorganisation.
            if coins[0].coin.height <= fork_height {
                spent.push(coins[0].out_point);
            }
            vec![chain.build_tx(&TxPlan::sweep(
                coins,
                Lock::P2pkh { key: 3 },
                Amount::from_grains(5_000),
            ))?]
        };
        let block = chain.build_block(&BlockPlan::with_txs(txs))?;
        chain.connect(&block);
        node.accept_expecting_extension(block)?;
    }

    // A branch from below every payment, long enough to win.
    let mut fork = chain.fork_at(fork_height)?;
    fork.set_extra_nonce(0xfeed_0001);
    let mut branch = Vec::with_capacity(payments + branch_extra);
    for _ in 0..payments.saturating_add(branch_extra) {
        let block = fork.build_block(&BlockPlan::default())?;
        fork.connect(&block);
        branch.push(block);
    }

    Ok(ReorgFixture {
        node,
        honest: chain.blocks().to_vec(),
        branch,
        fork_height,
        spent_only_on_honest: spent,
    })
}

/// Replay `blocks` into a brand-new node, so the result owes nothing to any
/// undo record.
///
/// # Errors
///
/// [`SimError`] if a block is rejected.
pub fn replay_into_fresh_node(
    params: ChainParams,
    prefix: &[Block],
    branch: &[Block],
) -> Result<SimNode, SimError> {
    let node = SimNode::open(params)?;
    for block in prefix.iter().skip(1) {
        node.accept_expecting_extension(block.clone())?;
    }
    for block in branch {
        node.accept_expecting_extension(block.clone())?;
    }
    Ok(node)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_chain::AcceptOutcome;

    use super::*;

    const WARMUP: usize = 8;
    const PAYMENTS: usize = 10;
    const BRANCH_EXTRA: usize = 3;

    fn fixture(seed: u64) -> ReorgFixture {
        build_fixture(seed, WARMUP, PAYMENTS, BRANCH_EXTRA).unwrap()
    }

    // ---- red -----------------------------------------------------------

    #[test]
    fn the_reorganisation_is_deeper_than_the_mempool_can_remember() {
        let f = fixture(81);
        let mut pool = SimMempool::new();
        let mut depth = 0usize;

        for block in &f.branch {
            if let Ok(AcceptOutcome::Reorged { disconnected, .. }) = f.node.accept(block.clone()) {
                depth = disconnected.len();
                let bodies: Vec<Block> = disconnected
                    .iter()
                    .map(|h| f.node.store().get_block(h).unwrap().expect("body stored"))
                    .collect();
                pool.reconcile(&bodies, MEMPOOL_REORG_MEMORY);
            }
        }

        assert!(
            depth > MEMPOOL_REORG_MEMORY,
            "the fixture must reorganise past the pool's horizon, depth {depth}"
        );
        assert!(
            !pool.forgotten().is_empty(),
            "a reorganisation past the horizon must drop transactions"
        );
        assert_eq!(
            pool.len(),
            MEMPOOL_REORG_MEMORY,
            "the pool keeps exactly what fits and no more"
        );
    }

    #[test]
    fn the_state_root_changes_across_the_reorganisation() {
        // If it did not, the "green" assertion below would be vacuous.
        let f = fixture(82);
        let before = f.node.state_root().unwrap();
        for block in &f.branch {
            let _ = f.node.accept(block.clone());
        }
        assert_ne!(before, f.node.state_root().unwrap());
    }

    #[test]
    fn the_abandoned_branchs_payments_leave_no_trace() {
        let f = fixture(83);
        // The payment outputs that are still unspent on the honest chain.
        // Some payments spend an earlier payment's output, so not every one
        // is live; those that are must all be gone afterwards.
        let live: Vec<Txid> = f
            .honest
            .iter()
            .skip(f.fork_height as usize + 1)
            .flat_map(|b| b.txs.iter().skip(1))
            .map(ferrum_storage::txid)
            .filter(|id| f.node.coin_at(&ferrum_types::OutPoint::new(*id, 0)).unwrap().is_some())
            .collect();
        assert!(live.len() > 5, "the fixture must create real payment outputs, saw {}", live.len());

        for block in &f.branch {
            let _ = f.node.accept(block.clone());
        }

        for id in &live {
            assert!(
                f.node.coin_at(&ferrum_types::OutPoint::new(*id, 0)).unwrap().is_none(),
                "an abandoned branch's outputs must not survive"
            );
        }
    }

    // ---- green ---------------------------------------------------------

    #[test]
    fn every_coin_the_abandoned_branch_spent_is_unspent_again() {
        let f = fixture(84);
        for op in &f.spent_only_on_honest {
            assert!(f.node.coin_at(op).unwrap().is_none(), "spent before the reorganisation");
        }
        for block in &f.branch {
            let _ = f.node.accept(block.clone());
        }
        for op in &f.spent_only_on_honest {
            assert!(
                f.node.coin_at(op).unwrap().is_some(),
                "the undo record must return {op} to the UTXO set"
            );
        }
    }

    #[test]
    fn the_reorganised_store_equals_a_replay_of_the_branch_from_genesis() {
        // The guaranteed property of SPEC §7.3, and the reason undo records
        // can be trusted: the incremental path and the from-scratch path
        // produce the same bytes.
        let f = fixture(85);
        for block in &f.branch {
            let _ = f.node.accept(block.clone());
        }

        let prefix: Vec<Block> =
            f.honest.iter().take(f.fork_height as usize + 1).cloned().collect();
        let fresh = replay_into_fresh_node(short_maturity_params(), &prefix, &f.branch).unwrap();

        assert_eq!(f.node.tip(), fresh.tip(), "same tip");
        assert_eq!(f.node.state_root().unwrap(), fresh.state_root().unwrap(), "same state root");
        assert_eq!(
            f.node.utxo_snapshot().unwrap(),
            fresh.utxo_snapshot().unwrap(),
            "byte-identical UTXO set"
        );
        assert_eq!(f.node.utxo_count().unwrap(), fresh.utxo_count().unwrap());
    }

    #[test]
    fn a_forgotten_transaction_costs_nobody_a_coin() {
        // The mempool's horizon is a convenience question, not a safety one:
        // whatever it drops, the money is back in the UTXO set and can be
        // spent again by its owner.
        let f = fixture(86);
        let mut pool = SimMempool::new();
        for block in &f.branch {
            if let Ok(AcceptOutcome::Reorged { disconnected, .. }) = f.node.accept(block.clone()) {
                let bodies: Vec<Block> = disconnected
                    .iter()
                    .map(|h| f.node.store().get_block(h).unwrap().expect("body stored"))
                    .collect();
                pool.reconcile(&bodies, MEMPOOL_REORG_MEMORY);
            }
        }
        assert!(!pool.forgotten().is_empty());
        let restored = f
            .spent_only_on_honest
            .iter()
            .filter(|op| f.node.coin_at(op).unwrap().is_some())
            .count();
        assert_eq!(
            restored,
            f.spent_only_on_honest.len(),
            "every input of every forgotten transaction is spendable again"
        );
    }

    #[test]
    fn the_mempool_model_keeps_the_shallowest_blocks() {
        // A sanity check on the model itself, so a failure above is a failure
        // of the chain rather than of the stand-in.
        let f = fixture(87);
        let disconnected: Vec<Block> =
            f.honest.iter().skip(f.fork_height as usize + 1).rev().cloned().collect();
        let mut pool = SimMempool::new();
        pool.reconcile(&disconnected, MEMPOOL_REORG_MEMORY);
        for (depth, block) in disconnected.iter().enumerate() {
            for tx in block.txs.iter().skip(1) {
                let id = ferrum_storage::txid(tx);
                assert_eq!(
                    pool.holds(&id),
                    depth < MEMPOOL_REORG_MEMORY,
                    "block at depth {depth} kept the wrong side of the horizon"
                );
            }
        }
    }
}
