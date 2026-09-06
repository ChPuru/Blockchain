//! A store-backed chain, for the scenarios that are about *acceptance* rather
//! than about one block.
//!
//! [`crate::ChainBuilder`] answers "is this block valid?"; [`SimNode`] answers
//! "what does a node do with it?" — fork choice, reorganisation, undo records
//! and the orphan pool. The two are deliberately separate: most adversarial
//! cases need only the pure seam, and a database in every fixture would make
//! them slower and harder to read.

use std::sync::Arc;

use ferrum_chain::{AcceptOutcome, ChainError, ChainManager};
use ferrum_consensus::EngineRouter;
use ferrum_storage::{Store, StoreConfig, UtxoBytes, header_hash};
use ferrum_types::{Block, BlockHash, ChainParams, Coin, Hash32, OutPoint};

use crate::error::SimError;

/// A real [`Store`], [`EngineRouter`] and [`ChainManager`] over an in-memory
/// database.
#[derive(Debug)]
pub struct SimNode {
    store: Arc<Store>,
    engines: Arc<EngineRouter>,
    chain: ChainManager,
    params: ChainParams,
}

impl SimNode {
    /// Open a node on `params` with genesis already connected.
    ///
    /// # Errors
    ///
    /// [`SimError::Storage`], [`SimError::Consensus`] or [`SimError::Chain`]
    /// if the store, router or manager cannot be opened.
    pub fn open(params: ChainParams) -> Result<Self, SimError> {
        let store =
            Arc::new(Store::open_in_memory(StoreConfig::default().with_chain_id(params.chain_id))?);
        let engines = Arc::new(EngineRouter::new(params.clone())?);
        let chain = ChainManager::open(Arc::clone(&store), params.clone(), Arc::clone(&engines))?;
        chain.init_genesis()?;
        Ok(SimNode { store, engines, chain, params })
    }

    /// A devnet node.
    ///
    /// # Errors
    ///
    /// As [`SimNode::open`].
    pub fn devnet() -> Result<Self, SimError> {
        Self::open(ChainParams::devnet())
    }

    /// The manager under test.
    #[must_use]
    pub fn chain(&self) -> &ChainManager {
        &self.chain
    }

    /// The store behind it.
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The engine router.
    #[must_use]
    pub fn engines(&self) -> &Arc<EngineRouter> {
        &self.engines
    }

    /// The parameters in force.
    #[must_use]
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// The active tip.
    #[must_use]
    pub fn tip(&self) -> (BlockHash, u64) {
        self.chain.tip()
    }

    /// Offer a block to the node.
    ///
    /// # Errors
    ///
    /// Whatever [`ChainManager::accept_block`] reports; an unknown parent is
    /// [`AcceptOutcome::Orphan`], not an error.
    pub fn accept(&self, block: Block) -> Result<AcceptOutcome, ChainError> {
        self.chain.accept_block(block)
    }

    /// Offer a block and require that it extends the tip.
    ///
    /// # Errors
    ///
    /// [`SimError::Chain`] on rejection, and [`SimError::Fixture`] when the
    /// block was accepted but did not become the tip.
    pub fn accept_expecting_extension(&self, block: Block) -> Result<BlockHash, SimError> {
        let hash = header_hash(&block.header);
        let outcome = self.accept(block)?;
        if outcome != AcceptOutcome::Extended(hash) {
            return Err(SimError::fixture(format!("expected an extension, got {outcome:?}")));
        }
        Ok(hash)
    }

    /// The UTXO-set state root.
    ///
    /// # Errors
    ///
    /// [`SimError::Storage`] on a read failure.
    pub fn state_root(&self) -> Result<Hash32, SimError> {
        Ok(self.store.state_root()?)
    }

    /// The whole UTXO set as raw table bytes, for byte-identity assertions.
    ///
    /// # Errors
    ///
    /// [`SimError::Storage`] on a read failure.
    pub fn utxo_snapshot(&self) -> Result<UtxoBytes, SimError> {
        Ok(self.store.utxo_snapshot()?)
    }

    /// How many unspent outputs the store holds.
    ///
    /// # Errors
    ///
    /// [`SimError::Storage`] on a read failure.
    pub fn utxo_count(&self) -> Result<u64, SimError> {
        Ok(self.store.utxo_count()?)
    }

    /// The coin at `op`, if unspent.
    ///
    /// # Errors
    ///
    /// [`SimError::Storage`] on a read failure.
    pub fn coin_at(&self, op: &OutPoint) -> Result<Option<Coin>, SimError> {
        Ok(self.store.get_coin(op)?)
    }

    /// Whether the store has a body for `hash`.
    ///
    /// # Errors
    ///
    /// [`SimError::Storage`] on a read failure.
    pub fn has_block(&self, hash: &BlockHash) -> Result<bool, SimError> {
        Ok(self.store.get_block(hash)?.is_some())
    }
}
