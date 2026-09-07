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
//! block — not a stray coin, not a height entry, not an index row, and above
//! all not a tip.
//!
//! # The crash is injected into `connect_block` itself
//!
//! [`Store::connect_block_then_crash`] arms a hook inside
//! [`crate::Store::connect_block`] and then calls it; it does not re-implement
//! the writes. A hand-copied twin would only ever prove that redb rolls back
//! *the twin*, and a twin drifts: the one this replaced wrote neither the
//! transaction index nor `meta.engine`, so a `connect_block` that had started
//! committing in two transactions — block, undo and height first, UTXO and tip
//! second — would have left a store whose tip lagged its UTXO set while every
//! round here still passed.
//!
//! For the same reason half the rounds run with the reverse index on. The
//! index writes (`tx_index`, `addr_index` and `meta.index_height`) happen only
//! in that mode, and a crash has to leave no trace of them either — which is
//! also the only crash coverage the `--index` write path gets.

use std::collections::BTreeMap;

use ferrum_types::{Coin, OutPoint};
use tempfile::TempDir;

use crate::store::{Store, StoreConfig};
use crate::tables::txid;
use crate::tests::fixtures::{Built, ChainBuilder};

/// The configuration round `round` opens its store with.
///
/// Odd rounds carry the reverse index, so the rounds that also crash
/// (`round % 3 == 2`) cover both write paths: 5, 11, 17 … are indexed *and*
/// interrupted.
fn config_for(round: usize) -> StoreConfig {
    if round % 2 == 1 { StoreConfig::indexed() } else { StoreConfig::default() }
}

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

    // On an indexed store the reverse index is part of the same transaction,
    // so it describes the same prefix: `index_height` tracks the tip and every
    // transaction of every applied block is locatable.
    if store.is_indexed() {
        assert_eq!(store.index_height().unwrap(), applied.last().map(|b| b.height));
        for blk in applied {
            for (i, tx) in blk.block.txs.iter().enumerate() {
                let loc = store.tx_location(&txid(tx)).unwrap().expect("an indexed transaction");
                assert_eq!((loc.block_hash, loc.index), (blk.hash, i as u32));
            }
        }
    }
}

#[test]
fn fifty_interrupted_restarts_all_come_back_consistent() {
    const ROUNDS: usize = 50;
    const CHAIN: usize = 12;

    for round in 0..ROUNDS {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ferrum.redb");
        let cfg = config_for(round);

        let mut builder = ChainBuilder::new();
        let built = builder.build(CHAIN);
        // A different interruption point every round, walking the whole chain.
        let n = round % (CHAIN + 1);

        {
            let store = Store::open(&path, cfg.clone()).unwrap();
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

        let reopened = Store::open(&path, cfg).unwrap();
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
            // Nor in the tables only the indexed path writes.
            if reopened.is_indexed() {
                for tx in &ghost.block.txs {
                    assert_eq!(
                        reopened.tx_location(&txid(tx)).unwrap(),
                        None,
                        "round {round}: an aborted block left an index row"
                    );
                }
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

    // Indexed: this is the configuration a node run with `--index` uses, and
    // it is the one whose write sequence is longest.
    let store = Store::open(&path, StoreConfig::indexed()).unwrap();
    for blk in &built[..3] {
        store.connect_block(&blk.hash, blk.height, &blk.entry, &blk.diff, &blk.block).unwrap();
    }
    let before = store.utxo_snapshot().unwrap();
    let tip = store.tip().unwrap();
    let engine = store.engine().unwrap();

    // Give the block that will not commit a different seal engine, so
    // `meta.engine` — a write the old hand-copied crash twin did not make at
    // all — has an observable value to leak if it ever escapes the aborted
    // transaction.
    let mut ghost = built[3].clone();
    ghost.entry.seal_engine = 1;
    assert_ne!(Some(ghost.entry.seal_engine), engine, "the ghost must differ from the tip");

    store
        .connect_block_then_crash(
            &ghost.hash,
            ghost.height,
            &ghost.entry,
            &ghost.diff,
            &ghost.block,
        )
        .unwrap();

    // Even without reopening, the aborted transaction is invisible.
    assert_eq!(store.tip().unwrap(), tip);
    assert_eq!(store.utxo_snapshot().unwrap(), before);
    assert_eq!(store.engine().unwrap(), engine);
    assert_eq!(store.index_height().unwrap(), Some(2));
    for tx in &ghost.block.txs {
        assert_eq!(store.tx_location(&txid(tx)).unwrap(), None);
    }
    drop(store);

    let reopened = Store::open(&path, StoreConfig::indexed()).unwrap();
    assert_eq!(reopened.tip().unwrap(), tip);
    assert_eq!(reopened.utxo_snapshot().unwrap(), before);
    assert_eq!(reopened.engine().unwrap(), engine, "the aborted block's engine survived");
    assert_consistent(&reopened, &built, 3);

    // And the interrupted block connects normally afterwards.
    let next = &built[3];
    reopened.connect_block(&next.hash, next.height, &next.entry, &next.diff, &next.block).unwrap();
    assert_consistent(&reopened, &built, 4);
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
