//! Crash consistency (M3): fifty restarts, each interrupted at a different
//! point, and the store must come back mutually consistent every time.
//!
//! The property under test is the one the whole design of
//! [`crate::Store::connect_block`] exists to give:
//!
//! > **The tip never points at a height whose diff was not fully applied.**
//!
//! Two things are exercised. First, the ordinary case: connect *n* blocks,
//! drop the `Store` without a graceful close, reopen, and check that the tip,
//! the `height` table and the UTXO set all describe the same prefix of the
//! chain. Second, the interesting case: perform every write a block implies
//! and then *fail to commit*, which is what a power cut between the first page
//! write and `fsync` looks like. The reopened store must show no trace of that
//! block — not a stray coin, not a height entry, and above all not a tip.

use std::collections::BTreeMap;

use ferrum_types::{Coin, OutPoint};
use tempfile::TempDir;

use crate::store::{Store, StoreConfig};
use crate::tests::fixtures::{Built, ChainBuilder};

/// The UTXO set that connecting `built[..n]` must produce.
fn expected_utxo(built: &[Built]) -> BTreeMap<OutPoint, Coin> {
    let mut set = BTreeMap::new();
    for blk in built {
        for (op, coin) in &blk.diff.created {
            set.insert(*op, coin.clone());
        }
        for (op, _) in &blk.diff.spent {
            set.remove(op);
        }
    }
    set
}

/// Assert that a reopened store describes exactly `built[..n]`.
fn assert_consistent(store: &Store, built: &[Built], n: usize) {
    let applied = &built[..n];
    match applied.last() {
        None => {
            assert_eq!(store.tip().unwrap(), None);
            assert_eq!(store.utxo_count().unwrap(), 0);
        }
        Some(last) => {
            assert_eq!(store.tip().unwrap(), Some((last.hash, last.height)));
        }
    }

    // Every height at or below the tip resolves, and nothing above it does.
    for blk in applied {
        assert_eq!(
            store.hash_at_height(blk.height).unwrap(),
            Some(blk.hash),
            "height {}",
            blk.height
        );
        assert!(store.get_block(&blk.hash).unwrap().is_some());
        assert!(store.get_undo(&blk.hash).unwrap().is_some());
    }
    assert_eq!(store.hash_at_height(n as u64).unwrap(), None, "a height above the tip resolved");

    // The UTXO set is exactly the one those blocks imply — the check that
    // catches a tip that ran ahead of its diff.
    let expected = expected_utxo(applied);
    let actual: BTreeMap<OutPoint, Coin> =
        store.iter_utxos().unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(actual, expected, "UTXO set disagrees with the first {n} blocks");
    assert_eq!(store.utxo_count().unwrap(), expected.len() as u64);
    assert_eq!(
        store.state_root().unwrap(),
        crate::state_root::state_root_of(expected.iter()).unwrap()
    );
}

#[test]
fn fifty_interrupted_restarts_all_come_back_consistent() {
    const ROUNDS: usize = 50;
    const CHAIN: usize = 12;

    for round in 0..ROUNDS {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ferrum.redb");

        let mut builder = ChainBuilder::new();
        let built = builder.build(CHAIN);
        // A different interruption point every round, walking the whole chain.
        let n = round % (CHAIN + 1);

        {
            let store = Store::open(&path, StoreConfig::default()).unwrap();
            for blk in &built[..n] {
                store
                    .connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block)
                    .unwrap();
            }

            // Every third round, additionally start the *next* block, write
            // everything it implies, and die before the commit.
            if round % 3 == 2 && n < CHAIN {
                let next = &built[n];
                store
                    .connect_block_then_crash(
                        &next.hash,
                        next.height,
                        &next.entry,
                        &next.diff,
                        &next.block,
                    )
                    .unwrap();
            }
            // No flush, no close: the `Store` is simply dropped.
        }

        let reopened = Store::open(&path, StoreConfig::default()).unwrap();
        assert_consistent(&reopened, &built, n);

        // The uncommitted block left nothing at all behind.
        if round % 3 == 2 && n < CHAIN {
            let ghost = &built[n];
            assert_eq!(reopened.get_block(&ghost.hash).unwrap(), None, "round {round}");
            assert_eq!(reopened.get_undo(&ghost.hash).unwrap(), None, "round {round}");
            assert_eq!(reopened.hash_at_height(ghost.height).unwrap(), None, "round {round}");
            for (op, _) in &ghost.diff.created {
                assert_eq!(reopened.get_coin(op).unwrap(), None, "round {round}");
            }
        }

        // And the store is still usable: the next block connects normally.
        if n < CHAIN {
            let next = &built[n];
            reopened
                .connect_block(&next.hash, next.height, &next.entry, &next.diff, &next.block)
                .unwrap();
            assert_consistent(&reopened, &built, n + 1);
        }
    }
}

#[test]
fn an_uncommitted_block_never_moves_the_tip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ferrum.redb");
    let mut builder = ChainBuilder::new();
    let built = builder.build(5);

    let store = Store::open(&path, StoreConfig::default()).unwrap();
    for blk in &built[..3] {
        store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let before = store.utxo_snapshot().unwrap();
    let tip = store.tip().unwrap();

    store
        .connect_block_then_crash(
            &built[3].hash,
            built[3].height,
            &built[3].entry,
            &built[3].diff,
            &built[3].block,
        )
        .unwrap();

    // Even without reopening, the aborted transaction is invisible.
    assert_eq!(store.tip().unwrap(), tip);
    assert_eq!(store.utxo_snapshot().unwrap(), before);
    drop(store);

    let reopened = Store::open(&path, StoreConfig::default()).unwrap();
    assert_eq!(reopened.tip().unwrap(), tip);
    assert_eq!(reopened.utxo_snapshot().unwrap(), before);
    assert_consistent(&reopened, &built, 3);
}

#[test]
fn a_disconnect_interrupted_by_a_drop_leaves_the_committed_state() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ferrum.redb");
    let mut builder = ChainBuilder::new();
    let built = builder.build(8);

    {
        let store = Store::open(&path, StoreConfig::default()).unwrap();
        for blk in &built {
            store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
        }
        for _ in 0..3 {
            store.disconnect_tip().unwrap();
        }
        // Dropped mid-life, with three commits behind it.
    }

    let reopened = Store::open(&path, StoreConfig::default()).unwrap();
    assert_consistent(&reopened, &built, 5);
}

#[test]
fn reopening_repeatedly_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ferrum.redb");
    let mut builder = ChainBuilder::new();
    let built = builder.build(6);

    {
        let store = Store::open(&path, StoreConfig::default()).unwrap();
        for blk in &built {
            store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
        }
    }
    let mut roots = Vec::new();
    for _ in 0..5 {
        let store = Store::open(&path, StoreConfig::default()).unwrap();
        assert_consistent(&store, &built, 6);
        roots.push(store.state_root().unwrap());
    }
    assert!(roots.windows(2).all(|w| w[0] == w[1]));
}
