//! Test fixtures: a devnet miner small enough to read.
//!
//! Two levels are offered, and most tests want the cheaper one.
//!
//! - [`block_of`] and friends build a *self-contained* block against a
//!   `MapView` pre-state. Nothing touches a database, so an adversarial test
//!   reads as "here is the block, here is the rule it breaks".
//! - [`TestChain`] runs a real [`Store`] with a real [`ChainManager`], for the
//!   tests that are about acceptance, reorganisation and fork choice.
//!
//! # Mining cost, and why these fixtures do not pay it
//!
//! Devnet's shipped `pow_limit` is `0x1e00ffff` — about `2^24` header hashes
//! per block, roughly 1.9 s on one core in release and 7.8 s in the unoptimised
//! test profile. That is deliberate: a devnet that seals a block in a
//! microsecond outruns its own gossip and cannot converge (see
//! `ChainParams::devnet`). It is also a cost these fixtures have no reason to
//! pay. Measured on the machine devnet was tuned on: `cargo test -p ferrum-chain
//! --lib` takes **633 s** when these fixtures mine at the shipped limit and
//! **1.1 s** when they do not, and every one of those 632 seconds re-proves the
//! same thing — that BLAKE3 still works.
//!
//! So [`devnet`] and [`devnet_with`] apply [`trivial_pow`]: the same devnet
//! parameter set, mined at the pre-2026 devnet target, which accepts about half
//! of all header hashes. Nothing these fixtures exist to check depends on the
//! absolute target. Acceptance, undo and fork choice compare
//! `work(target) = 2^256 / (target + 1)`, which is scale-free, so a branch 60x
//! harder than its base still out-works a longer one.
//!
//! A test that *is* about the shipped numbers — the published genesis hash, the
//! `pow_limit` clamp, `bits` validation — must therefore take
//! `ChainParams::devnet()` directly and not go through these helpers.
//! `genesis_tests` does exactly that.

use std::sync::Arc;

use ferrum_consensus::{
    EngineRouter, HeaderView, PowEngine, Target, compact_to_target, hash_meets_target,
};
use ferrum_storage::{MapView, OverlayView, StateView, Store, StoreConfig, header_hash, txid};
use ferrum_types::{
    Amount, Block, BlockHash, BlockHeader, BlockSeal, ChainParams, Coin, CompactTarget, Hash32,
    OutPoint, Script, Transaction, TxIn, TxOut,
};

use crate::ctx::BlockCtx;
use crate::error::ChainError;
use crate::manager::{AcceptOutcome, ChainManager};
use crate::validate::{build_coinbase_script_sig, compute_merkle_root};
use crate::view::StoreHeaderView;

/// Devnet parameters for a fixture: the shipped set, mined at a trivial
/// target. See the module docs, and [`trivial_pow`] for what is relaxed.
pub fn devnet() -> ChainParams {
    devnet_with(|_| {})
}

/// Mine at a trivial target: the pre-2026 devnet limit, `0x207fffff`, which
/// accepts about half of all header hashes.
///
/// [`devnet_with`] applies this for you; it is public so that a fixture built
/// from `ChainParams` some other way can opt in explicitly, and so that the
/// reason has a name. Fork choice compares
/// `work(target) = 2^256 / (target + 1)`, so a branch whose blocks are 60x
/// harder than their base outweighs a longer branch by the same ratio whatever
/// the base is — the absolute target only decides how long the test takes.
///
/// Do **not** reach for this in a test that is about the `pow_limit` itself,
/// about `bits` validation, or about the published devnet genesis hash.
pub fn trivial_pow(p: &mut ChainParams) {
    let mut limit = [0xffu8; 32];
    limit[0] = 0x7f;
    p.pow_limit = limit;
    p.genesis_bits = CompactTarget(0x207f_ffff);
}

/// Devnet parameters with a tweak applied, for tests that need a shorter
/// maturity or a faster difficulty controller.
///
/// [`trivial_pow`] is applied first, so a caller that wants the shipped target
/// back can ask for it explicitly.
pub fn devnet_with(f: impl FnOnce(&mut ChainParams)) -> ChainParams {
    let mut p = ChainParams::devnet();
    trivial_pow(&mut p);
    f(&mut p);
    p
}

/// `OP_1`: a locking script anyone satisfies with an empty `script_sig`.
///
/// Real coins are locked with P2PKH; these tests are about block rules, and a
/// signature per input would make every fixture about key management instead.
pub fn any_spend_script() -> Script {
    Script::new(vec![0x51])
}

/// `OP_RETURN`: provably unspendable.
pub fn burn_script() -> Script {
    Script::new(vec![0x6a])
}

/// A coinbase paying `value` to [`any_spend_script`].
pub fn coinbase(height: u64, value: Amount, extra: &[u8]) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn::coinbase(
            build_coinbase_script_sig(height, extra).expect("extra fits the script_sig window"),
        )],
        outputs: vec![TxOut::new(value, any_spend_script())],
        lock_time: 0,
    }
}

/// A coinbase with an arbitrary `script_sig`, for the BIP-34 tests.
pub fn coinbase_with_script_sig(script_sig: Script, value: Amount) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn::coinbase(script_sig)],
        outputs: vec![TxOut::new(value, any_spend_script())],
        lock_time: 0,
    }
}

/// A transaction spending `inputs` with an empty `script_sig` into `outputs`.
pub fn spend(inputs: &[OutPoint], outputs: &[(Amount, Script)]) -> Transaction {
    Transaction {
        version: 1,
        inputs: inputs.iter().map(|op| TxIn::new(*op, Script::EMPTY)).collect(),
        outputs: outputs.iter().map(|(v, s)| TxOut::new(*v, s.clone())).collect(),
        lock_time: 0,
    }
}

/// The outpoint of `tx`'s output `vout`.
pub fn out_point(tx: &Transaction, vout: u32) -> OutPoint {
    OutPoint::new(txid(tx), vout)
}

/// A coin, for building a `MapView` pre-state by hand.
pub fn coin(value: Amount, height: u64, is_coinbase: bool) -> Coin {
    Coin {
        value: Amount::from_grains(value.to_grains()),
        script_pubkey: any_spend_script(),
        height,
        is_coinbase,
    }
}

/// Grind `nonce` until the header meets its own target.
///
/// Devnet's limit accepts about half of all hashes, so this loop runs a couple
/// of times; a harder `bits` costs proportionally more, which the fork-choice
/// tests rely on.
pub fn seal_pow(mut header: BlockHeader) -> BlockHeader {
    let target = compact_to_target(header.bits).expect("test bits expand");
    loop {
        if hash_meets_target(&header_hash(&header), target) {
            return header;
        }
        PowEngine::advance_search(&mut header);
    }
}

/// Build and seal a block over an explicit parent hash.
///
/// `bits` defaults to the network's genesis target, which is what
/// `apply_block` needs: it checks the target is expandable and no easier than
/// `pow_limit`, and leaves `bits == next_bits(parent)` to the manager.
pub fn block_of(
    txs: Vec<Transaction>,
    prev_hash: BlockHash,
    timestamp_ms: u64,
    bits: CompactTarget,
) -> Block {
    let header = seal_pow(BlockHeader {
        version: 1,
        prev_hash,
        merkle_root: compute_merkle_root(&txs),
        timestamp_ms,
        bits,
        nonce: 0,
    });
    Block::new(header, txs, BlockSeal::POW)
}

/// Re-seal a block after its transactions or header were mutated.
///
/// Recomputes the merkle root and grinds a fresh nonce, so a test can change
/// one thing and still hand `apply_block` a block that fails for exactly that
/// reason instead of for a stale merkle root.
pub fn reseal(mut block: Block) -> Block {
    block.header.merkle_root = compute_merkle_root(&block.txs);
    block.header.nonce = 0;
    block.header = seal_pow(block.header);
    block
}

/// A parent header for the hand-built blocks, at the given timestamp.
pub fn parent_header(timestamp_ms: u64, params: &ChainParams) -> BlockHeader {
    seal_pow(BlockHeader {
        version: 1,
        prev_hash: BlockHash::ZERO,
        merkle_root: Hash32::ZERO,
        timestamp_ms,
        bits: params.genesis_bits,
        nonce: 0,
    })
}

/// A context for a block at `height` on top of `prev`.
pub fn ctx_at(height: u64, prev: &BlockHeader, mtp_s: u64, params: &ChainParams) -> BlockCtx {
    BlockCtx::new(height, *prev, mtp_s, params.clone())
}

/// A pre-state holding the listed coins.
pub fn map_view(entries: &[(OutPoint, Coin)]) -> MapView {
    entries.iter().cloned().collect()
}

/// A whole devnet chain: store, engines and manager, with genesis initialised.
pub struct TestChain {
    /// The store the chain writes to.
    pub store: Arc<Store>,
    /// The parameters in force.
    pub params: ChainParams,
    /// The engine router.
    pub engines: Arc<EngineRouter>,
    /// The manager under test.
    pub chain: ChainManager,
}

impl std::fmt::Debug for TestChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestChain").field("tip", &self.chain.tip()).finish_non_exhaustive()
    }
}

impl TestChain {
    /// A fresh in-memory devnet chain with genesis connected.
    pub fn new() -> Self {
        Self::with_params(devnet())
    }

    /// A fresh in-memory chain on custom parameters, with genesis connected.
    pub fn with_params(params: ChainParams) -> Self {
        let store = Arc::new(
            Store::open_in_memory(StoreConfig::default().with_chain_id(params.chain_id))
                .expect("in-memory store opens"),
        );
        let engines = Arc::new(EngineRouter::new(params.clone()).expect("router builds"));
        let chain = ChainManager::open(Arc::clone(&store), params.clone(), Arc::clone(&engines))
            .expect("manager opens");
        chain.init_genesis().expect("genesis initialises");
        TestChain { store, params, engines, chain }
    }

    /// The active tip.
    pub fn tip(&self) -> (BlockHash, u64) {
        self.chain.tip()
    }

    /// The header of a stored block.
    pub fn header(&self, hash: &BlockHash) -> BlockHeader {
        self.store.get_header(hash).expect("read").expect("known block").header
    }

    /// The height of a stored block.
    pub fn height_of(&self, hash: &BlockHash) -> u64 {
        self.store.get_header(hash).expect("read").expect("known block").height
    }

    /// Build a valid block on top of `parent`, paying `subsidy + fees` to
    /// [`any_spend_script`].
    ///
    /// `bits` comes from the engine, so the block satisfies the difficulty
    /// transition the manager will check. `timestamp_ms` is pushed above the
    /// parent's median time past when the caller asks for something older.
    pub fn mine_on(
        &self,
        parent: &BlockHash,
        txs: Vec<Transaction>,
        timestamp_ms: u64,
        extra_nonce: u64,
    ) -> Block {
        let entry = self.store.get_header(parent).expect("read").expect("known parent");
        let height = entry.height.saturating_add(1);
        let view = StoreHeaderView::new(&self.store, &self.params);
        let engine = self.engines.engine_for_height(height);
        let bits = engine.next_bits(&entry.header, &view).expect("next_bits");
        let mtp_s = view.median_time_past(parent).unwrap_or(0);
        let timestamp_ms = timestamp_ms.max(mtp_s.saturating_mul(1_000).saturating_add(1));

        let fees = self.fees_of(&txs, height);
        let reward = self.params.block_subsidy(height).checked_add(fees).expect("reward fits");
        let mut all = vec![coinbase(height, reward, &extra_nonce.to_le_bytes())];
        all.extend(txs);
        block_of(all, *parent, timestamp_ms, bits)
    }

    /// Mine one block on the current tip, one spacing after the tip's stamp.
    pub fn mine(&self, txs: Vec<Transaction>) -> Block {
        let (tip, _) = self.tip();
        let stamp = self.header(&tip).timestamp_ms.saturating_add(self.params.target_spacing_ms);
        self.mine_on(&tip, txs, stamp, 0)
    }

    /// Mine and accept `n` empty blocks, returning their hashes in order.
    pub fn extend(&self, n: usize) -> Vec<BlockHash> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let block = self.mine(Vec::new());
            let hash = header_hash(&block.header);
            let outcome = self.chain.accept_block(block).expect("block accepts");
            assert_eq!(outcome, AcceptOutcome::Extended(hash), "expected a straight extension");
            out.push(hash);
        }
        out
    }

    /// Accept a block, returning the outcome.
    pub fn accept(&self, block: Block) -> Result<AcceptOutcome, ChainError> {
        self.chain.accept_block(block)
    }

    /// The coin at `op`, if unspent.
    pub fn coin_at(&self, op: &OutPoint) -> Option<Coin> {
        self.store.get_coin(op).expect("read")
    }

    /// The spendable coinbase output of the block at `height`.
    pub fn coinbase_out(&self, height: u64) -> OutPoint {
        let hash = self.store.hash_at_height(height).expect("read").expect("height on chain");
        let block = self.store.get_block(&hash).expect("read").expect("body stored");
        let cb = block.coinbase().expect("coinbase present");
        out_point(cb, 0)
    }

    /// Total fees the given transactions pay, resolving in-block dependencies.
    fn fees_of(&self, txs: &[Transaction], height: u64) -> Amount {
        let base: &dyn StateView = self.store.as_ref();
        let mut overlay = OverlayView::new(base);
        let mut fees = Amount::ZERO;
        for tx in txs {
            let mut inputs = Amount::ZERO;
            for input in &tx.inputs {
                if let Some(c) = overlay.get_coin(&input.prev_out).expect("read") {
                    inputs = inputs.checked_add(c.value).expect("input sum fits");
                }
            }
            let outputs = tx.total_output().unwrap_or(Amount::ZERO);
            fees = fees.checked_add(inputs.saturating_sub(outputs)).expect("fee sum fits");
            for input in &tx.inputs {
                let _ = overlay.spend(&input.prev_out).expect("read");
            }
            let id = txid(tx);
            for (vout, out) in tx.outputs.iter().enumerate() {
                let index = u32::try_from(vout).expect("vout fits");
                overlay.add(OutPoint::new(id, index), Coin::new(out.clone(), height, false));
            }
        }
        fees
    }

    /// The whole UTXO set as raw bytes, for byte-identity assertions.
    pub fn utxo_snapshot(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.store.utxo_snapshot().expect("snapshot")
    }

    /// The UTXO-set Merkle root.
    pub fn state_root(&self) -> Hash32 {
        self.store.state_root().expect("state root")
    }

    /// The target the engine would require for a child of `parent`.
    pub fn target_for_child_of(&self, parent: &BlockHash) -> Target {
        let entry = self.store.get_header(parent).expect("read").expect("known parent");
        let view = StoreHeaderView::new(&self.store, &self.params);
        let engine = self.engines.engine_for_height(entry.height.saturating_add(1));
        let bits = engine.next_bits(&entry.header, &view).expect("next_bits");
        compact_to_target(bits).expect("target expands")
    }
}
