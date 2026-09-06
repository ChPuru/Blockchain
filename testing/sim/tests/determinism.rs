//! The determinism gate: `cargo test -p ferrum-sim --test determinism`.
//!
//! CI runs this in **debug and release**, because `overflow-checks`,
//! `opt-level` and `lto` are exactly the sort of thing that changes an answer
//! which was never deterministic in the first place. Both profiles must
//! produce the same state-root sequence, and both must match the file
//! committed at `testing/sim/golden/state_roots.json`.
//!
//! # What is being pinned
//!
//! `apply_block` is a pure function of `(pre-state, block, context)` (SPEC §8).
//! "Pure" is easy to assert and hard to keep: every construct that could break
//! it — a clock, a `HashMap` iteration, a float — produces a *plausible* answer
//! rather than an obvious failure, so a reviewer cannot see the difference. The
//! property is therefore pinned to a file. Replay a fixed block sequence,
//! compute the UTXO-set state root after every block, and compare the whole
//! sequence, byte for byte.
//!
//! # If this test fails
//!
//! A state root that changed without a deliberate consensus change is a chain
//! split that has not happened yet. The file is **never** rewritten to make the
//! test green; that is deleting the alarm rather than the fire. Find the change,
//! and only when it is intended and understood, delete
//! `golden/state_roots.json` so the next run regenerates it — and say so in the
//! commit message.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use ferrum_chain::apply_block;
use ferrum_sim::replay::{
    GOLDEN_BLOCK_COUNT, GOLDEN_SEED, GoldenOutcome, GoldenRoots, RecordedChain,
    check_or_create_golden, golden_path, replay_production, replay_reference,
};
use ferrum_sim::{XorShift64, apply_block_reference};
use ferrum_types::{Amount, Coin, Hash32, OutPoint};

/// Replay the golden chain and return its record.
fn golden_record() -> (RecordedChain, GoldenRoots) {
    let chain = RecordedChain::golden().expect("the golden chain builds");
    let roots = chain.state_roots(apply_block).expect("every golden block applies");
    let record = GoldenRoots::from_chain(&chain, &roots).expect("the record builds");
    (chain, record)
}

#[test]
fn the_state_root_sequence_matches_the_golden_file() {
    let (chain, record) = golden_record();
    assert_eq!(record.blocks, chain.len());
    assert_eq!(record.blocks, GOLDEN_BLOCK_COUNT);
    assert_eq!(record.seed, GOLDEN_SEED);

    let path = golden_path();
    match check_or_create_golden(&path, &record) {
        Ok(GoldenOutcome::Matched) => {}
        Ok(GoldenOutcome::Created) => {
            // A fresh checkout bootstraps itself; the file is committed from
            // then on and the branch above is the one that runs in CI.
            assert!(path.exists(), "the golden file must have been written");
        }
        Err(e) => panic!(
            "the determinism gate fired.\n{e}\n\
             This is a consensus change. Do not regenerate the file to silence it: \
             find what changed in the state transition first."
        ),
    }
    assert!(path.exists(), "golden/state_roots.json must exist after this test");
}

#[test]
fn the_golden_file_on_disk_still_parses_and_still_matches() {
    // Separate from the test above so that a corrupted or hand-edited file is
    // reported as such rather than as a mismatch.
    let path = golden_path();
    let (_, record) = golden_record();
    if let Some(stored) = GoldenRoots::load(&path).expect("the golden file parses") {
        assert_eq!(stored.network, "devnet");
        assert_eq!(stored.state_roots.len(), stored.blocks);
        stored.compare(&record).expect("the stored sequence must match this run");
    }
}

#[test]
fn the_reference_executor_produces_the_same_sequence() {
    // Two independent implementations of the state transition, one golden
    // sequence. If only production were replayed, the file would pin whatever
    // production happens to do, including a bug.
    let chain = RecordedChain::golden().unwrap();
    let production = replay_production(&chain.params, &chain.blocks).unwrap();
    let reference = replay_reference(&chain.params, &chain.blocks).unwrap();
    assert_eq!(production, reference, "the two executors must agree at every height");
    assert_eq!(production.len(), GOLDEN_BLOCK_COUNT);
}

#[test]
fn replaying_the_same_blocks_twice_gives_the_same_sequence() {
    let chain = RecordedChain::golden().unwrap();
    let first = chain.state_roots(apply_block).unwrap();
    let second = chain.state_roots(apply_block).unwrap();
    assert_eq!(first, second);
    let third = chain.state_roots(apply_block_reference).unwrap();
    assert_eq!(first, third);
}

#[test]
fn regenerating_the_chain_from_its_seed_gives_the_same_blocks() {
    // The fixture generator is as much a part of the gate as the executor: a
    // non-deterministic builder would produce a new "golden" sequence on every
    // run and the file could never be committed.
    let a = RecordedChain::generate(GOLDEN_SEED, GOLDEN_BLOCK_COUNT).unwrap();
    let b = RecordedChain::generate(GOLDEN_SEED, GOLDEN_BLOCK_COUNT).unwrap();
    assert_eq!(a.blocks.len(), b.blocks.len());
    for (i, (x, y)) in a.blocks.iter().zip(b.blocks.iter()).enumerate() {
        assert_eq!(
            borsh::to_vec(x).unwrap(),
            borsh::to_vec(y).unwrap(),
            "block {i} differs between two runs of the same seed"
        );
    }
}

#[test]
fn the_state_root_does_not_depend_on_enumeration_order() {
    // The root is defined over `borsh(OutPoint)` byte order, so the caller may
    // hand the entries over in any order at all. A `HashMap` in the executor
    // would break this quietly, on some machines only.
    let chain = RecordedChain::golden().unwrap();
    let mut utxo: BTreeMap<OutPoint, Coin> = BTreeMap::new();
    for block in &chain.blocks {
        for tx in &block.txs {
            for input in &tx.inputs {
                utxo.remove(&input.prev_out);
            }
            let id = ferrum_storage::txid(tx);
            for (vout, out) in tx.outputs.iter().enumerate() {
                utxo.insert(
                    OutPoint::new(id, u32::try_from(vout).unwrap()),
                    Coin {
                        value: out.value,
                        script_pubkey: out.script_pubkey.clone(),
                        height: 0,
                        is_coinbase: false,
                    },
                );
            }
        }
    }
    let ordered = ferrum_storage::state_root_of(utxo.iter()).unwrap();

    let mut shuffled: Vec<(&OutPoint, &Coin)> = utxo.iter().collect();
    let mut rng = XorShift64::new(0xabcd_ef01);
    for i in (1..shuffled.len()).rev() {
        let j = rng.below_usize(i + 1);
        shuffled.swap(i, j);
    }
    assert_eq!(ordered, ferrum_storage::state_root_of(shuffled).unwrap());
}

#[test]
fn one_changed_grain_changes_the_state_root() {
    // If it did not, the gate above would pass through any amount of drift.
    let chain = RecordedChain::golden().unwrap();
    let roots = chain.state_roots(apply_block).unwrap();
    let last = *roots.last().unwrap();

    let mut utxo: BTreeMap<OutPoint, Coin> = BTreeMap::new();
    let coinbase = chain.blocks.first().unwrap().coinbase().unwrap();
    let op = OutPoint::new(ferrum_storage::txid(coinbase), 0);
    utxo.insert(
        op,
        Coin {
            value: Amount::from_grains(1),
            script_pubkey: coinbase.outputs[0].script_pubkey.clone(),
            height: 0,
            is_coinbase: true,
        },
    );
    let one = ferrum_storage::state_root_of(utxo.iter()).unwrap();
    if let Some(coin) = utxo.get_mut(&op) {
        coin.value = Amount::from_grains(2);
    }
    let two = ferrum_storage::state_root_of(utxo.iter()).unwrap();
    assert_ne!(one, two, "a one-grain difference must change the root");
    assert_ne!(one, last);
    assert_ne!(one, Hash32::ZERO);
}

#[test]
fn the_sequence_is_the_same_in_debug_and_in_release() {
    // This test cannot run two profiles at once. What it can do is state the
    // contract and make the profile visible in the output, so that a CI job
    // running it twice is comparing two runs of the *same* assertion rather
    // than two different ones.
    let (_, record) = golden_record();
    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    println!("determinism gate: {} blocks under the {profile} profile", record.blocks);
    match check_or_create_golden(&golden_path(), &record) {
        Ok(_) => {}
        Err(e) => panic!("the {profile} profile disagrees with the golden file: {e}"),
    }
    // Overflow checks are on in both profiles for this workspace, so a
    // saturating step cannot behave differently between them.
    assert!(record.blocks > 0);
}
