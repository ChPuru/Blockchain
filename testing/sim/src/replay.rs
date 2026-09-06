//! The determinism replay harness and its golden state-root file
//! (CONTRACT §14, SPEC §8).
//!
//! `apply_block` is a pure function of `(pre-state, block, context)`. "Pure"
//! is easy to assert and hard to keep, because every non-deterministic
//! construct that could break it — a clock, a `HashMap` iteration, a float —
//! produces a *plausible* answer rather than an obvious failure. So the
//! property is pinned to a file instead: replay a fixed block sequence,
//! compute the UTXO-set state root after every block, and compare the whole
//! sequence against `golden/state_roots.json`.
//!
//! The gate runs in debug **and** release, because `overflow-checks` and
//! optimisation level are exactly the sort of thing that changes an answer
//! that was never deterministic in the first place.
//!
//! # Regenerating the golden file
//!
//! The file is created automatically when it is absent, so a fresh checkout
//! bootstraps itself. When it is present and disagrees, the test **fails** —
//! it never rewrites. A state root that changed without a deliberate consensus
//! change is a chain split that has not happened yet; deleting the file to
//! make the test green is deleting the alarm rather than the fire.

use std::path::{Path, PathBuf};

use ferrum_chain::{BlockCtx, ValidationError, apply_block};
use ferrum_storage::{MapView, StateDiff, StateView};
use ferrum_types::{Amount, Block, BlockHeader, ChainParams, Coin, Hash32, OutPoint};
use serde::{Deserialize, Serialize};

use crate::chain_builder::{ChainBuilder, TxPlan};
use crate::error::SimError;
use crate::keys::Lock;
use crate::prng::XorShift64;
use crate::view::median_time_past_of;

/// The name of the golden file inside `testing/sim/golden/`.
pub const GOLDEN_FILE_NAME: &str = "state_roots.json";

/// How many blocks the committed golden sequence covers.
///
/// Past `coinbase_maturity` by a wide enough margin that the tail of the
/// sequence exercises real spends rather than empty blocks.
pub const GOLDEN_BLOCK_COUNT: usize = 140;

/// The seed the golden sequence is generated from.
pub const GOLDEN_SEED: u64 = 0x0f1e_2d3c_4b5a_6978;

/// The signature every state transition under test shares.
pub type Executor = fn(&dyn StateView, &Block, &BlockCtx) -> Result<StateDiff, ValidationError>;

/// A recorded block sequence and the parameters it was produced under.
#[derive(Clone, Debug)]
pub struct RecordedChain {
    /// The consensus parameters the blocks were built for.
    pub params: ChainParams,
    /// Every block, genesis first.
    pub blocks: Vec<Block>,
    /// The seed the fixture generator ran from.
    pub seed: u64,
}

impl RecordedChain {
    /// Generate a devnet chain of `blocks` blocks from `seed`.
    ///
    /// The workload is deliberately varied: plain coinbases while the first
    /// hundred mature, then multi-input sweeps, P2PKH and P2PK payments, bare
    /// and P2SH multisig spends, absolute timelocks and burns. A sequence of
    /// empty blocks would pin nothing but the subsidy schedule.
    ///
    /// # Errors
    ///
    /// [`SimError`] if the fixture generator cannot build a block.
    pub fn generate(seed: u64, blocks: usize) -> Result<Self, SimError> {
        let mut chain = ChainBuilder::devnet(seed)?;
        generate_workload(&mut chain, blocks)?;
        Ok(RecordedChain {
            params: chain.params().clone(),
            blocks: chain.blocks().to_vec(),
            seed,
        })
    }

    /// The committed golden sequence.
    ///
    /// # Errors
    ///
    /// As [`RecordedChain::generate`].
    pub fn golden() -> Result<Self, SimError> {
        Self::generate(GOLDEN_SEED, GOLDEN_BLOCK_COUNT)
    }

    /// The state-root sequence this chain produces under `executor`.
    ///
    /// # Errors
    ///
    /// [`SimError::Validation`] if any recorded block fails to apply, which
    /// means the recording and the validator disagree.
    pub fn state_roots(&self, executor: Executor) -> Result<Vec<Hash32>, SimError> {
        replay_state_roots(&self.params, &self.blocks, executor)
    }

    /// How many blocks were recorded, genesis included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether nothing was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// Fill `chain` up to `blocks` blocks with a varied, deterministic workload.
///
/// # Errors
///
/// [`SimError`] if a block cannot be built.
pub fn generate_workload(chain: &mut ChainBuilder, blocks: usize) -> Result<(), SimError> {
    let mut rng = XorShift64::new(chain.params().chain_id.to_u32().into());
    while chain.blocks().len() < blocks {
        let height = chain.height().saturating_add(1);
        let txs = plan_transactions(chain, &mut rng, height)?;
        chain.mine(txs)?;
    }
    Ok(())
}

/// Choose and build the transactions for one block.
fn plan_transactions(
    chain: &mut ChainBuilder,
    rng: &mut XorShift64,
    height: u64,
) -> Result<Vec<ferrum_types::Transaction>, SimError> {
    let available = chain.mature(height).len();
    if available == 0 {
        return Ok(Vec::new());
    }
    let wanted = rng.below_usize(3.min(available)).saturating_add(1);
    let mut txs = Vec::with_capacity(wanted);
    for _ in 0..wanted {
        // A multi-input transaction whenever there is enough to feed one:
        // single-input spends never exercise the input-sum rules.
        let inputs_wanted = usize::try_from(rng.range(1, 3)).unwrap_or(1);
        let coins = chain.take_mature(inputs_wanted, height);
        if coins.is_empty() {
            break;
        }
        let total = coins.iter().fold(Amount::ZERO, |a, c| a.saturating_add(c.coin.value));
        let fee = Amount::from_grains(rng.range(1_000, 50_000));
        let payable = total.saturating_sub(fee);
        if payable.is_zero() {
            break;
        }
        let plan = match rng.below(6) {
            0 => TxPlan::sweep(coins, Lock::P2pkh { key: 1 }, fee),
            1 => TxPlan::sweep(coins, Lock::P2pk { key: 2 }, fee),
            2 => TxPlan::sweep(coins, Lock::Multisig { k: 2, keys: vec![3, 4, 5] }, fee),
            3 => TxPlan::sweep(coins, Lock::P2shMultisig { k: 2, keys: vec![6, 7, 8] }, fee),
            4 => {
                // An absolute timelock that is already satisfied at this
                // height, so the coin stays spendable later in the run.
                let locktime = u32::try_from(height.saturating_sub(1)).unwrap_or(0);
                TxPlan::sweep(coins, Lock::CltvP2pkh { key: 9, locktime }, fee)
            }
            _ => {
                // Two outputs, so `created` is not always length one.
                let half = payable
                    .checked_div_u64(2)
                    .unwrap_or(Amount::ZERO);
                let rest = payable.saturating_sub(half);
                TxPlan {
                    inputs: coins,
                    outputs: vec![
                        (Lock::P2pkh { key: 10 }, half),
                        (Lock::P2pkh { key: 11 }, rest),
                    ],
                    ..TxPlan::default()
                }
            }
        };
        // A CLTV output can only be spent by a transaction whose own
        // `lock_time` reaches the script's, so the sweep that *creates* one
        // still uses the default locktime; the spend of it sets one.
        let plan = adjust_for_timelocks(plan, height);
        txs.push(chain.build_tx(&plan)?);
    }
    Ok(txs)
}

/// A transaction spending a CLTV output must carry a `lock_time` that has
/// reached the script's and a non-final sequence.
fn adjust_for_timelocks(mut plan: TxPlan, height: u64) -> TxPlan {
    let required = plan
        .inputs
        .iter()
        .filter_map(|c| match c.lock {
            Lock::CltvP2pkh { locktime, .. } => Some(locktime),
            _ => None,
        })
        .max();
    if let Some(locktime) = required {
        plan.lock_time = locktime.max(u32::try_from(height.saturating_sub(1)).unwrap_or(0));
    }
    plan
}

/// Replay `blocks` under `executor`, returning the state root after each one.
///
/// The state root is the sorted binary Merkle over the whole UTXO set
/// (CONTRACT §7). It is not consensus state — no header commits to it — but it
/// lets two executors compare their entire view of the chain in 32 bytes,
/// which is precisely what a determinism harness needs.
///
/// # Errors
///
/// [`SimError::Validation`] if a block fails to apply, and
/// [`SimError::Storage`] if a coin cannot be encoded for the root.
pub fn replay_state_roots(
    params: &ChainParams,
    blocks: &[Block],
    executor: Executor,
) -> Result<Vec<Hash32>, SimError> {
    let mut utxo: std::collections::BTreeMap<OutPoint, Coin> = std::collections::BTreeMap::new();
    let mut headers: Vec<BlockHeader> = Vec::with_capacity(blocks.len());
    let mut roots = Vec::with_capacity(blocks.len());

    for (index, block) in blocks.iter().enumerate() {
        let height = u64::try_from(index).unwrap_or(0);
        let parent = headers.last().copied().unwrap_or_default();
        let mtp = match height.checked_sub(1) {
            Some(h) => median_time_past_of(&headers, h, params.median_time_span),
            None => 0,
        };
        let ctx = BlockCtx::new(height, parent, mtp, params.clone());
        let pre: MapView = utxo.iter().map(|(op, coin)| (*op, coin.clone())).collect();

        let diff = executor(&pre, block, &ctx)?;
        for (op, _) in &diff.spent {
            utxo.remove(op);
        }
        for (op, coin) in &diff.created {
            utxo.insert(*op, coin.clone());
        }

        roots.push(ferrum_storage::state_root_of(utxo.iter())?);
        headers.push(block.header);
    }
    Ok(roots)
}

/// Replay under the production executor.
///
/// # Errors
///
/// As [`replay_state_roots`].
pub fn replay_production(params: &ChainParams, blocks: &[Block]) -> Result<Vec<Hash32>, SimError> {
    replay_state_roots(params, blocks, apply_block)
}

/// Replay under the reference executor.
///
/// # Errors
///
/// As [`replay_state_roots`].
pub fn replay_reference(params: &ChainParams, blocks: &[Block]) -> Result<Vec<Hash32>, SimError> {
    replay_state_roots(params, blocks, crate::reference::apply_block_reference)
}

// ---------------------------------------------------------------------------
// The golden file
// ---------------------------------------------------------------------------

/// The recorded state-root sequence, as it is committed to the repository.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoldenRoots {
    /// The network the sequence was produced on.
    pub network: String,
    /// The fixture seed.
    pub seed: u64,
    /// How many blocks were replayed, genesis included.
    pub blocks: usize,
    /// The genesis block hash, so a parameter change is caught immediately.
    pub genesis: String,
    /// The final block hash.
    pub tip: String,
    /// The state root after each block, in order.
    pub state_roots: Vec<String>,
}

impl GoldenRoots {
    /// Build a golden record from a replayed chain.
    ///
    /// # Errors
    ///
    /// [`SimError::Fixture`] when the chain has no blocks.
    pub fn from_chain(chain: &RecordedChain, roots: &[Hash32]) -> Result<Self, SimError> {
        let genesis = chain
            .blocks
            .first()
            .map(|b| ferrum_storage::header_hash(&b.header))
            .ok_or_else(|| SimError::fixture("cannot record an empty chain"))?;
        let tip = chain
            .blocks
            .last()
            .map(|b| ferrum_storage::header_hash(&b.header))
            .ok_or_else(|| SimError::fixture("cannot record an empty chain"))?;
        Ok(GoldenRoots {
            network: chain.params.network.name().to_owned(),
            seed: chain.seed,
            blocks: chain.blocks.len(),
            genesis: genesis.0.to_hex(),
            tip: tip.0.to_hex(),
            state_roots: roots.iter().map(Hash32::to_hex).collect(),
        })
    }

    /// Read a golden file, or `None` when it does not exist.
    ///
    /// # Errors
    ///
    /// [`SimError::Golden`] on an unreadable or malformed file.
    pub fn load(path: &Path) -> Result<Option<Self>, SimError> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).map(Some).map_err(|e| SimError::Golden {
                path: path.display().to_string(),
                detail: format!("malformed: {e}"),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SimError::Golden {
                path: path.display().to_string(),
                detail: e.to_string(),
            }),
        }
    }

    /// Write this record, creating the directory if needed.
    ///
    /// # Errors
    ///
    /// [`SimError::Golden`] on any filesystem or serialisation failure.
    pub fn store(&self, path: &Path) -> Result<(), SimError> {
        let fail = |detail: String| SimError::Golden {
            path: path.display().to_string(),
            detail,
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| fail(e.to_string()))?;
        }
        let mut text =
            serde_json::to_string_pretty(self).map_err(|e| fail(e.to_string()))?;
        text.push('\n');
        std::fs::write(path, text).map_err(|e| fail(e.to_string()))
    }

    /// Compare this record against a freshly replayed one.
    ///
    /// # Errors
    ///
    /// [`SimError::GoldenLengthMismatch`] or [`SimError::GoldenMismatch`],
    /// naming the first index that differs.
    pub fn compare(&self, actual: &GoldenRoots) -> Result<(), SimError> {
        if self.state_roots.len() != actual.state_roots.len() {
            return Err(SimError::GoldenLengthMismatch {
                expected: self.state_roots.len(),
                actual: actual.state_roots.len(),
            });
        }
        if self.genesis != actual.genesis {
            return Err(SimError::GoldenMismatch {
                index: 0,
                expected: format!("genesis {}", self.genesis),
                actual: format!("genesis {}", actual.genesis),
            });
        }
        for (index, (expected, got)) in
            self.state_roots.iter().zip(actual.state_roots.iter()).enumerate()
        {
            if expected != got {
                return Err(SimError::GoldenMismatch {
                    index,
                    expected: expected.clone(),
                    actual: got.clone(),
                });
            }
        }
        if self.tip != actual.tip {
            return Err(SimError::GoldenMismatch {
                index: self.state_roots.len().saturating_sub(1),
                expected: format!("tip {}", self.tip),
                actual: format!("tip {}", actual.tip),
            });
        }
        Ok(())
    }
}

/// What [`check_or_create_golden`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoldenOutcome {
    /// The file was absent and has been written.
    Created,
    /// The file was present and matched.
    Matched,
}

/// The path of the committed golden file.
#[must_use]
pub fn golden_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("golden").join(GOLDEN_FILE_NAME)
}

/// Compare `current` against the golden file, writing it if it is absent.
///
/// # Errors
///
/// [`SimError::GoldenMismatch`] when the file exists and differs. It is never
/// overwritten: a changed state root is a consensus change, and the test's job
/// is to say so.
pub fn check_or_create_golden(
    path: &Path,
    current: &GoldenRoots,
) -> Result<GoldenOutcome, SimError> {
    match GoldenRoots::load(path)? {
        Some(recorded) => {
            recorded.compare(current)?;
            Ok(GoldenOutcome::Matched)
        }
        None => {
            current.store(path)?;
            Ok(GoldenOutcome::Created)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn small_chain() -> RecordedChain {
        RecordedChain::generate(GOLDEN_SEED, 12).unwrap()
    }

    #[test]
    fn a_recorded_chain_replays_under_both_executors_identically() {
        let chain = small_chain();
        let production = chain.state_roots(apply_block).unwrap();
        let reference = chain.state_roots(crate::reference::apply_block_reference).unwrap();
        assert_eq!(production, reference);
        assert_eq!(production.len(), chain.len());
    }

    #[test]
    fn replaying_twice_gives_the_same_sequence() {
        let a = small_chain();
        let b = small_chain();
        assert_eq!(a.state_roots(apply_block).unwrap(), b.state_roots(apply_block).unwrap());
    }

    #[test]
    fn the_state_root_changes_whenever_the_utxo_set_does() {
        let chain = RecordedChain::generate(GOLDEN_SEED, 6).unwrap();
        let roots = chain.state_roots(apply_block).unwrap();
        // Every block here creates a coinbase output, so no two consecutive
        // roots may repeat.
        for pair in roots.windows(2) {
            assert_ne!(pair[0], pair[1]);
        }
    }

    #[test]
    fn a_golden_record_round_trips_through_json() {
        let chain = small_chain();
        let roots = chain.state_roots(apply_block).unwrap();
        let record = GoldenRoots::from_chain(&chain, &roots).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join(GOLDEN_FILE_NAME);
        assert_eq!(check_or_create_golden(&path, &record).unwrap(), GoldenOutcome::Created);
        assert_eq!(check_or_create_golden(&path, &record).unwrap(), GoldenOutcome::Matched);
        assert_eq!(GoldenRoots::load(&path).unwrap().unwrap(), record);
    }

    #[test]
    fn a_changed_state_root_fails_loudly_and_does_not_rewrite() {
        let chain = small_chain();
        let roots = chain.state_roots(apply_block).unwrap();
        let record = GoldenRoots::from_chain(&chain, &roots).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(GOLDEN_FILE_NAME);
        check_or_create_golden(&path, &record).unwrap();

        let mut tampered = record.clone();
        tampered.state_roots[3] = Hash32::ZERO.to_hex();
        let err = check_or_create_golden(&path, &tampered).unwrap_err();
        match err {
            SimError::GoldenMismatch { index, .. } => assert_eq!(index, 3),
            other => panic!("expected a golden mismatch, got {other}"),
        }
        // The file on disk is untouched: the alarm does not silence itself.
        assert_eq!(GoldenRoots::load(&path).unwrap().unwrap(), record);
    }

    #[test]
    fn a_shorter_replay_is_reported_as_a_length_mismatch() {
        let chain = small_chain();
        let roots = chain.state_roots(apply_block).unwrap();
        let record = GoldenRoots::from_chain(&chain, &roots).unwrap();
        let mut short = record.clone();
        short.state_roots.pop();
        let err = record.compare(&short).unwrap_err();
        assert!(matches!(err, SimError::GoldenLengthMismatch { .. }));
    }

    #[test]
    fn a_different_genesis_is_caught_before_any_state_root() {
        let chain = small_chain();
        let roots = chain.state_roots(apply_block).unwrap();
        let record = GoldenRoots::from_chain(&chain, &roots).unwrap();
        let mut other = record.clone();
        other.genesis = Hash32::ZERO.to_hex();
        let err = record.compare(&other).unwrap_err();
        match err {
            SimError::GoldenMismatch { index, .. } => assert_eq!(index, 0),
            other => panic!("expected a genesis mismatch, got {other}"),
        }
    }

    #[test]
    fn the_workload_actually_moves_money() {
        let chain = RecordedChain::generate(GOLDEN_SEED, GOLDEN_BLOCK_COUNT).unwrap();
        let spends: usize = chain.blocks.iter().map(|b| b.txs.len().saturating_sub(1)).sum();
        assert!(spends > 10, "the golden workload must exercise real spends, saw {spends}");
    }
}
