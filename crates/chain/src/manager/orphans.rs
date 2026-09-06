//! Blocks whose parent is not yet known.
//!
//! An orphan is a *distinct outcome* from an invalid block (SPEC §3.2 rule 6):
//! it may be perfectly valid and simply have arrived before its parent, so it
//! is held rather than rejected and its sender is not penalised.
//!
//! It is also free to mint — anyone can hash a header naming a parent that will
//! never exist — so the pool is capped and load-sheds with a warning instead of
//! growing. An unbounded orphan pool is a memory-exhaustion vector reachable by
//! any peer.

use std::collections::{BTreeMap, BTreeSet};

use ferrum_types::{Block, BlockHash};

/// How many blocks whose parent is unknown the manager will hold.
pub const MAX_ORPHAN_BLOCKS: usize = 64;

/// A bounded pool of parentless blocks, indexed by the parent they wait for.
///
/// `BTreeMap`/`BTreeSet`, never the hashed variants: this sits on the block
/// acceptance path, and iteration order must never influence which block a node
/// connects first.
#[derive(Debug, Default)]
pub struct OrphanPool {
    blocks: BTreeMap<BlockHash, Block>,
    by_parent: BTreeMap<BlockHash, BTreeSet<BlockHash>>,
}

impl OrphanPool {
    /// An empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `block` until its parent arrives.
    ///
    /// A full pool drops the newcomer rather than evicting an older orphan: the
    /// blocks already held are the ones whose parents are most likely to turn
    /// up next.
    pub fn insert(&mut self, hash: BlockHash, block: Block) {
        if self.blocks.contains_key(&hash) {
            return;
        }
        if self.blocks.len() >= MAX_ORPHAN_BLOCKS {
            tracing::warn!(
                hash = %hash,
                held = self.blocks.len(),
                capacity = MAX_ORPHAN_BLOCKS,
                "orphan pool is full; dropping the block"
            );
            return;
        }
        let parent = block.header.prev_hash;
        self.by_parent.entry(parent).or_default().insert(hash);
        self.blocks.insert(hash, block);
    }

    /// Remove and return every orphan waiting on `parent`.
    pub fn take_children_of(&mut self, parent: &BlockHash) -> Vec<Block> {
        let Some(children) = self.by_parent.remove(parent) else {
            return Vec::new();
        };
        children.into_iter().filter_map(|h| self.blocks.remove(&h)).collect()
    }

    /// How many orphans are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}
