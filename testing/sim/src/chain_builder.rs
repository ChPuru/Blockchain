//! A deterministic block and transaction factory.
//!
//! Everything the simulator validates is produced here, and everything
//! produced here is a pure function of `(ChainParams, seed)`. There is no
//! clock — timestamps advance by `target_spacing_ms` unless a scenario says
//! otherwise — no randomness beyond an explicitly seeded [`XorShift64`], and no
//! database. Two runs of the same fixture produce byte-identical blocks, which
//! is what makes the golden state-root file in `golden/` maintainable and what
//! makes a scenario failure reproducible.
//!
//! # What the builder is *not*
//!
//! It is not a validator. [`ChainBuilder::connect`] absorbs a block into the
//! simulator's bookkeeping without checking a single consensus rule, precisely
//! so that it can absorb deliberately invalid blocks and so that the
//! differential test compares two validators rather than a validator against
//! itself.

use std::collections::BTreeMap;

use ferrum_chain::{BlockCtx, build_coinbase_script_sig};
use ferrum_consensus::{ConsensusEngine, PowEngine, Target, compact_to_target, hash_meets_target};
use ferrum_storage::{MapView, header_hash, txid};
use ferrum_types::{
    Amount, Block, BlockHash, BlockHeader, BlockSeal, ChainParams, Coin, CompactTarget, Hash32,
    OutPoint, Script, Transaction, TxIn, TxOut, Txid,
};

use crate::error::SimError;
use crate::keys::{DEFAULT_KEYRING_SIZE, KeyRing, Lock};
use crate::prng::XorShift64;
use crate::sign::unlock;
use crate::view::{SimHeaderView, median_time_past_of};

/// How many nonces the harness will try before giving up on a block.
///
/// The devnet `pow_limit` accepts roughly half of all hashes, so a legitimate
/// block is found in a handful of tries. A budget exists only so that a
/// scenario which asks for an unreachable target fails with a clear error
/// instead of hanging a CI job.
pub const MINING_ATTEMPT_BUDGET: u64 = 1 << 22;

mod plan;

pub use crate::chain_builder::plan::{BlockPlan, DEFAULT_SEQUENCE, SpendableCoin, TxPlan};

/// The deterministic chain factory.
#[derive(Debug)]
pub struct ChainBuilder {
    params: ChainParams,
    engine: PowEngine,
    keys: KeyRing,
    rng: XorShift64,
    seed: u64,
    headers: Vec<BlockHeader>,
    heights: BTreeMap<BlockHash, u64>,
    blocks: Vec<Block>,
    utxo: BTreeMap<OutPoint, Coin>,
    locks: BTreeMap<OutPoint, Lock>,
    spendable: Vec<SpendableCoin>,
    extra_nonce: u64,
}

impl ChainBuilder {
    /// A chain holding nothing but genesis.
    ///
    /// # Errors
    ///
    /// [`SimError::Fixture`] if the deterministic keyring cannot be derived.
    pub fn new(params: ChainParams, seed: u64) -> Result<Self, SimError> {
        let engine = PowEngine::new(params.clone());
        let mut builder = ChainBuilder {
            engine,
            keys: KeyRing::deterministic(DEFAULT_KEYRING_SIZE)?,
            rng: XorShift64::new(seed),
            seed,
            headers: Vec::new(),
            heights: BTreeMap::new(),
            blocks: Vec::new(),
            utxo: BTreeMap::new(),
            locks: BTreeMap::new(),
            spendable: Vec::new(),
            extra_nonce: 0,
            params,
        };
        let genesis = ferrum_chain::genesis_block(&builder.params);
        builder.connect(&genesis);
        Ok(builder)
    }

    /// A devnet chain, the network every scenario uses.
    ///
    /// # Errors
    ///
    /// As [`ChainBuilder::new`].
    pub fn devnet(seed: u64) -> Result<Self, SimError> {
        Self::new(ChainParams::devnet(), seed)
    }

    // ---- accessors ----------------------------------------------------

    /// The parameters in force.
    #[must_use]
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// The deterministic keyring.
    #[must_use]
    pub fn keys(&self) -> &KeyRing {
        &self.keys
    }

    /// The seeded generator, for a scenario that wants its own draws.
    pub fn rng(&mut self) -> &mut XorShift64 {
        &mut self.rng
    }

    /// The active chain's headers, indexed by height.
    #[must_use]
    pub fn headers(&self) -> &[BlockHeader] {
        &self.headers
    }

    /// Every block on the active chain, genesis first.
    #[must_use]
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// The current UTXO set.
    #[must_use]
    pub fn utxo(&self) -> &BTreeMap<OutPoint, Coin> {
        &self.utxo
    }

    /// The UTXO set as a [`ferrum_storage::StateView`].
    #[must_use]
    pub fn state_view(&self) -> MapView {
        self.utxo.iter().map(|(op, coin)| (*op, coin.clone())).collect()
    }

    /// The coins the factory knows how to spend.
    #[must_use]
    pub fn spendable(&self) -> &[SpendableCoin] {
        &self.spendable
    }

    /// The height of the tip.
    #[must_use]
    pub fn height(&self) -> u64 {
        u64::try_from(self.headers.len().saturating_sub(1)).unwrap_or(0)
    }

    /// The tip header.
    ///
    /// # Errors
    ///
    /// [`SimError::Fixture`] on an empty chain, which cannot occur after
    /// [`ChainBuilder::new`].
    pub fn tip_header(&self) -> Result<BlockHeader, SimError> {
        self.headers.last().copied().ok_or_else(|| SimError::fixture("empty chain"))
    }

    /// The tip's hash.
    ///
    /// # Errors
    ///
    /// As [`ChainBuilder::tip_header`].
    pub fn tip_hash(&self) -> Result<BlockHash, SimError> {
        Ok(header_hash(&self.tip_header()?))
    }

    /// A [`ferrum_consensus::HeaderView`] over the active chain.
    #[must_use]
    pub fn header_view(&self) -> SimHeaderView<'_> {
        SimHeaderView::new(&self.headers, &self.heights, &self.params)
    }

    /// Median time past at `height`, in seconds.
    #[must_use]
    pub fn median_time_past(&self, height: u64) -> u64 {
        median_time_past_of(&self.headers, height, self.params.median_time_span)
    }

    /// Set the value mixed into every later coinbase `script_sig`.
    ///
    /// Two branches that pay the same address at the same height would
    /// otherwise build byte-identical coinbase transactions, hence identical
    /// txids. Distinguishing them is what a real miner's extra-nonce does.
    pub fn set_extra_nonce(&mut self, nonce: u64) {
        self.extra_nonce = nonce;
    }

    // ---- context ------------------------------------------------------

    /// The [`BlockCtx`] for a block at `height` whose parent is `parent`.
    ///
    /// # Errors
    ///
    /// [`SimError::Fixture`] when the parent is not on the active chain.
    pub fn ctx_for(&self, height: u64, parent: &BlockHeader) -> Result<BlockCtx, SimError> {
        let parent_height = height.checked_sub(1);
        let mtp = match parent_height {
            Some(h) => self.median_time_past(h),
            // Genesis has no parent and is exempt from the median-time rule.
            None => 0,
        };
        Ok(BlockCtx::new(height, *parent, mtp, self.params.clone()))
    }

    /// The context for the next block on the active chain.
    ///
    /// # Errors
    ///
    /// As [`ChainBuilder::tip_header`].
    pub fn next_ctx(&self) -> Result<BlockCtx, SimError> {
        let parent = self.tip_header()?;
        self.ctx_for(self.height().saturating_add(1), &parent)
    }

    /// The target a child of the tip must meet.
    ///
    /// # Errors
    ///
    /// [`SimError::Consensus`] when ASERT cannot produce a target.
    pub fn next_bits(&self) -> Result<CompactTarget, SimError> {
        let parent = self.tip_header()?;
        Ok(self.engine.next_bits(&parent, &self.header_view())?)
    }

    // ---- transaction construction -------------------------------------

    /// Build and sign a transaction.
    ///
    /// The transaction is assembled with empty `script_sig`s first, because
    /// the sighash commits to every prevout, sequence and output; only then is
    /// each input signed and filled in.
    ///
    /// # Errors
    ///
    /// [`SimError::Script`] when a script or sighash cannot be built, and
    /// [`SimError::Fixture`] for an input the harness cannot unlock.
    pub fn build_tx(&mut self, plan: &TxPlan) -> Result<Transaction, SimError> {
        let mut outputs = Vec::with_capacity(plan.outputs.len());
        for (lock, value) in &plan.outputs {
            outputs.push(TxOut::new(*value, lock.script_pubkey(&self.keys)?));
        }
        let mut tx = Transaction {
            version: plan.version,
            inputs: plan
                .inputs
                .iter()
                .map(|c| TxIn {
                    prev_out: c.out_point,
                    script_sig: Script::EMPTY,
                    sequence: plan.sequence,
                })
                .collect(),
            outputs,
            lock_time: plan.lock_time,
        };
        for (index, spendable) in plan.inputs.iter().enumerate() {
            let script_sig = unlock(
                &tx,
                index,
                &spendable.lock,
                spendable.coin.value,
                self.params.chain_id,
                &self.keys,
                plan.sighash_type,
            )?;
            if let Some(input) = tx.inputs.get_mut(index) {
                input.script_sig = script_sig;
            }
        }
        self.remember_locks(&tx, &plan.outputs);
        Ok(tx)
    }

    /// Record the lock of every output a transaction creates, so that the
    /// coin can be spent again later.
    fn remember_locks(&mut self, tx: &Transaction, outputs: &[(Lock, Amount)]) {
        let id = txid(tx);
        for (vout, (lock, _)) in outputs.iter().enumerate() {
            let op = OutPoint::new(id, u32::try_from(vout).unwrap_or(u32::MAX));
            self.locks.insert(op, lock.clone());
        }
    }

    /// Take up to `n` mature, spendable coins out of the pool.
    ///
    /// Removing them means two fixtures built in the same block cannot
    /// accidentally spend the same coin, which would look like a
    /// double-spend bug in the validator rather than in the harness.
    pub fn take_mature(&mut self, n: usize, height: u64) -> Vec<SpendableCoin> {
        let maturity = self.params.coinbase_maturity;
        let mut taken = Vec::with_capacity(n);
        let mut kept = Vec::with_capacity(self.spendable.len());
        for coin in std::mem::take(&mut self.spendable) {
            if taken.len() < n && coin.is_mature(height, maturity) && coin.lock.is_spendable() {
                taken.push(coin);
            } else {
                kept.push(coin);
            }
        }
        self.spendable = kept;
        taken
    }

    /// Look at, without removing, the mature spendable coins at `height`.
    #[must_use]
    pub fn mature(&self, height: u64) -> Vec<SpendableCoin> {
        let maturity = self.params.coinbase_maturity;
        self.spendable
            .iter()
            .filter(|c| c.is_mature(height, maturity) && c.lock.is_spendable())
            .cloned()
            .collect()
    }

    // ---- block construction -------------------------------------------

    /// The coinbase for `height`, claiming `value`.
    ///
    /// # Errors
    ///
    /// [`SimError::Validation`] when the `script_sig` falls outside the
    /// 2..=100 byte window, and [`SimError::Script`] for a bad payout script.
    pub fn build_coinbase(
        &self,
        height: u64,
        value: Amount,
        payout: &Lock,
        extra: Option<&[u8]>,
    ) -> Result<Transaction, SimError> {
        let default_extra = self.extra_nonce.to_le_bytes();
        let extra = extra.unwrap_or(&default_extra);
        let script_sig = build_coinbase_script_sig(height, extra)?;
        Ok(Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(script_sig)],
            outputs: vec![TxOut::new(value, payout.script_pubkey(&self.keys)?)],
            lock_time: 0,
        })
    }

    /// The fees a set of transactions pays, resolved against the current UTXO
    /// set plus the outputs those same transactions create.
    ///
    /// Best-effort: an input that does not resolve contributes nothing, which
    /// is what a deliberately invalid fixture needs.
    #[must_use]
    pub fn fees_of(&self, txs: &[Transaction]) -> Amount {
        let mut in_flight: BTreeMap<OutPoint, Amount> = BTreeMap::new();
        let mut fees = Amount::ZERO;
        for tx in txs {
            let mut inputs = Amount::ZERO;
            for input in &tx.inputs {
                let value = self
                    .utxo
                    .get(&input.prev_out)
                    .map(|c| c.value)
                    .or_else(|| in_flight.get(&input.prev_out).copied())
                    .unwrap_or(Amount::ZERO);
                inputs = inputs.saturating_add(value);
            }
            let outputs = tx.total_output().unwrap_or(Amount::ZERO);
            fees = fees.saturating_add(inputs.saturating_sub(outputs));
            let id = txid(tx);
            for (vout, out) in tx.outputs.iter().enumerate() {
                in_flight
                    .insert(OutPoint::new(id, u32::try_from(vout).unwrap_or(u32::MAX)), out.value);
            }
        }
        fees
    }

    /// Assemble a block from a plan, grinding proof of work unless told not to.
    ///
    /// # Errors
    ///
    /// [`SimError::MiningBudgetExhausted`] when no nonce inside the budget
    /// meets the target, plus anything [`ChainBuilder::build_coinbase`] can
    /// raise.
    pub fn build_block(&mut self, plan: &BlockPlan) -> Result<Block, SimError> {
        let parent = self.tip_header()?;
        let height = plan.height.unwrap_or_else(|| self.height().saturating_add(1));
        let prev_hash = plan.prev_hash.unwrap_or_else(|| header_hash(&parent));
        let bits = match plan.bits {
            Some(b) => b,
            None => self.next_bits()?,
        };
        let timestamp_ms = plan
            .timestamp_ms
            .unwrap_or_else(|| parent.timestamp_ms.saturating_add(self.params.target_spacing_ms));

        let coinbase = match &plan.coinbase {
            Some(cb) => cb.clone(),
            None => {
                let subsidy = self.params.block_subsidy(height);
                let fees = self.fees_of(&plan.txs);
                let value = subsidy
                    .saturating_add(fees)
                    .saturating_add(Amount::from_grains(plan.coinbase_bonus))
                    .saturating_sub(Amount::from_grains(plan.coinbase_burn));
                let payout = plan.payout.clone().unwrap_or(Lock::P2pkh { key: 0 });
                let cb =
                    self.build_coinbase(height, value, &payout, plan.coinbase_extra.as_deref())?;
                self.remember_locks(&cb, &[(payout, value)]);
                cb
            }
        };

        let mut txs = Vec::with_capacity(plan.txs.len().saturating_add(1));
        txs.push(coinbase);
        txs.extend(plan.txs.iter().cloned());

        let merkle_root =
            plan.merkle_root.unwrap_or_else(|| ferrum_chain::compute_merkle_root(&txs));
        let mut header = BlockHeader {
            version: plan.version.unwrap_or(1),
            prev_hash,
            merkle_root,
            timestamp_ms,
            bits,
            nonce: 0,
        };
        if plan.grind {
            self.grind(&mut header)?;
        }
        Ok(Block::new(header, txs, plan.seal.clone().unwrap_or(BlockSeal::POW)))
    }

    /// Find a nonce whose header hash meets the header's own target.
    ///
    /// # Errors
    ///
    /// [`SimError::MiningBudgetExhausted`] after [`MINING_ATTEMPT_BUDGET`]
    /// tries, and [`SimError::Consensus`] for a target that cannot be
    /// expanded.
    pub fn grind(&self, header: &mut BlockHeader) -> Result<(), SimError> {
        let target: Target = compact_to_target(header.bits)?;
        for attempt in 0..MINING_ATTEMPT_BUDGET {
            if hash_meets_target(&header_hash(header), target) {
                return Ok(());
            }
            header.nonce = attempt.saturating_add(1);
        }
        Err(SimError::MiningBudgetExhausted(MINING_ATTEMPT_BUDGET))
    }

    /// Build a block carrying `txs` and add it to the chain.
    ///
    /// # Errors
    ///
    /// As [`ChainBuilder::build_block`].
    pub fn mine(&mut self, txs: Vec<Transaction>) -> Result<Block, SimError> {
        let block = self.build_block(&BlockPlan::with_txs(txs))?;
        self.connect(&block);
        Ok(block)
    }

    /// Mine `n` blocks with no transactions in them.
    ///
    /// # Errors
    ///
    /// As [`ChainBuilder::build_block`].
    pub fn advance(&mut self, n: usize) -> Result<(), SimError> {
        for _ in 0..n {
            self.mine(Vec::new())?;
        }
        Ok(())
    }

    /// Absorb a block into the simulator's bookkeeping.
    ///
    /// **No validation happens here.** The builder must be able to hold an
    /// invalid block so that scenarios can extend one, and so that the
    /// differential test compares two validators rather than a validator
    /// against itself.
    pub fn connect(&mut self, block: &Block) {
        let height = u64::try_from(self.headers.len()).unwrap_or(0);
        self.headers.push(block.header);
        self.heights.insert(header_hash(&block.header), height);
        self.blocks.push(block.clone());

        for (index, tx) in block.txs.iter().enumerate() {
            let is_coinbase = index == 0;
            if !is_coinbase {
                for input in &tx.inputs {
                    self.utxo.remove(&input.prev_out);
                    self.spendable.retain(|c| c.out_point != input.prev_out);
                }
            }
            let id = txid(tx);
            for (vout, out) in tx.outputs.iter().enumerate() {
                let op = OutPoint::new(id, u32::try_from(vout).unwrap_or(u32::MAX));
                let coin = Coin {
                    value: out.value,
                    script_pubkey: out.script_pubkey.clone(),
                    height,
                    is_coinbase,
                };
                self.utxo.insert(op, coin.clone());
                if let Some(lock) = self.locks.get(&op).filter(|l| l.is_spendable()) {
                    self.spendable.push(SpendableCoin { out_point: op, coin, lock: lock.clone() });
                }
            }
        }
    }

    /// A copy of this chain truncated to `height`, ready to be extended along
    /// a different branch.
    ///
    /// # Errors
    ///
    /// As [`ChainBuilder::new`].
    pub fn fork_at(&self, height: u64) -> Result<ChainBuilder, SimError> {
        let mut fork = ChainBuilder::new(self.params.clone(), self.seed)?;
        fork.locks = self.locks.clone();
        fork.extra_nonce = self.extra_nonce;
        let keep = usize::try_from(height).unwrap_or(usize::MAX);
        for block in self.blocks.iter().skip(1).take(keep) {
            fork.connect(block);
        }
        Ok(fork)
    }

    /// The state root of the current UTXO set.
    ///
    /// # Errors
    ///
    /// [`SimError::Storage`] if a coin cannot be Borsh-encoded.
    pub fn state_root(&self) -> Result<Hash32, SimError> {
        Ok(ferrum_storage::state_root_of(self.utxo.iter())?)
    }

    /// The txid of a transaction, for a scenario that wants to name one.
    #[must_use]
    pub fn txid_of(tx: &Transaction) -> Txid {
        txid(tx)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_chain::apply_block;

    use super::*;

    fn devnet() -> ChainBuilder {
        ChainBuilder::devnet(XorShift64::SCENARIO_SEED).unwrap()
    }

    #[test]
    fn a_fresh_chain_holds_only_genesis() {
        let b = devnet();
        assert_eq!(b.height(), 0);
        assert_eq!(b.blocks().len(), 1);
        assert_eq!(b.tip_hash().unwrap(), ferrum_chain::genesis_hash(b.params()));
        // The genesis output is an OP_RETURN, so it is in the UTXO set but is
        // not spendable.
        assert_eq!(b.utxo().len(), 1);
        assert!(b.spendable().is_empty());
    }

    #[test]
    fn mined_blocks_are_accepted_by_the_production_validator() {
        let mut b = devnet();
        for _ in 0..5 {
            let ctx = b.next_ctx().unwrap();
            let pre = b.state_view();
            let block = b.build_block(&BlockPlan::default()).unwrap();
            apply_block(&pre, &block, &ctx).expect("the harness must build valid blocks");
            b.connect(&block);
        }
        assert_eq!(b.height(), 5);
    }

    #[test]
    fn the_builder_is_reproducible_from_its_seed() {
        let mut a = devnet();
        let mut b = devnet();
        a.advance(6).unwrap();
        b.advance(6).unwrap();
        assert_eq!(a.tip_hash().unwrap(), b.tip_hash().unwrap());
        assert_eq!(a.state_root().unwrap(), b.state_root().unwrap());
    }

    #[test]
    fn coinbase_outputs_become_spendable_only_after_maturity() {
        let mut b = devnet();
        b.advance(3).unwrap();
        assert!(b.mature(3).is_empty(), "nothing matures within three blocks");
        assert_eq!(b.spendable().len(), 3);
        // The coinbase of block 1 matures at height 101, block 2's at 102,
        // block 3's at 103.
        assert_eq!(b.mature(101).len(), 1);
        assert_eq!(b.mature(102).len(), 2);
        assert_eq!(b.mature(103).len(), 3);
    }

    #[test]
    fn a_fork_reproduces_the_prefix_exactly() {
        let mut b = devnet();
        b.advance(8).unwrap();
        let fork = b.fork_at(4).unwrap();
        assert_eq!(fork.height(), 4);
        assert_eq!(fork.tip_hash().unwrap(), header_hash(&b.headers()[4]));
        let mut prefix: ChainBuilder = devnet();
        prefix.advance(4).unwrap();
        assert_eq!(fork.state_root().unwrap(), prefix.state_root().unwrap());
    }

    #[test]
    fn a_spent_coin_leaves_the_pool() {
        let mut b = devnet();
        b.advance(usize::try_from(b.params().coinbase_maturity).unwrap() + 2).unwrap();
        let height = b.height() + 1;
        let coins = b.take_mature(1, height);
        assert_eq!(coins.len(), 1);
        let before = b.spendable().len();
        let plan = TxPlan::sweep(coins, Lock::P2pkh { key: 3 }, Amount::from_grains(1_000));
        let tx = b.build_tx(&plan).unwrap();
        b.mine(vec![tx]).unwrap();
        // One coin left the pool, one coinbase and one payment joined it.
        assert_eq!(b.spendable().len(), before + 2);
    }

    #[test]
    fn the_extra_nonce_distinguishes_two_coinbases_at_one_height() {
        let mut a = devnet();
        let mut c = devnet();
        c.set_extra_nonce(7);
        let block_a = a.build_block(&BlockPlan::default()).unwrap();
        let block_c = c.build_block(&BlockPlan::default()).unwrap();
        assert_ne!(txid(&block_a.txs[0]), txid(&block_c.txs[0]));
    }
}
