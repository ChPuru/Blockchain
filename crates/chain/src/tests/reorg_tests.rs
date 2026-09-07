//! SPEC §7: fork choice by work, and reorganisation that is all-or-nothing.

use ferrum_storage::{BlockStatus, header_hash};
use ferrum_types::{Amount, BlockHash, ChainParams, Hash32};

use crate::error::{ChainError, ValidationError};
use crate::manager::AcceptOutcome;
use crate::reorg::{ReorgPlan, connect_tip_block, execute_reorg, plan_reorg};
use crate::tests::support::{
    TestChain, any_spend_script, coinbase, devnet_with, out_point, reseal, spend,
};

fn amount(v: u64) -> Amount {
    Amount::from_grains(v)
}

/// Devnet with a half-life short enough that a fast branch is visibly harder.
///
/// The tests below mine a side branch one second per block and rely on ASERT
/// answering with a target several times harder each time, so that four blocks
/// out-work eight. What produces that is the *ratio* `spacing / half-life`, not
/// either number alone: at the shipped devnet spacing of 5 s, a half-life of
/// half a spacing puts a 1 s block 2.5 half-lives ahead of schedule, which is
/// the same 3x work margin the old 120 s / 60 s pairing gave.
///
/// `devnet_with` mines at a trivial base target, which is what keeps this
/// affordable: these blocks land at up to 90x the base difficulty, and at
/// devnet's shipped limit a single one of them would be ~2^30 hashes — minutes,
/// to assert a ratio that does not depend on the absolute target at all.
fn fast_difficulty() -> ChainParams {
    devnet_with(|p| {
        p.asert_halflife_s = i64::try_from(p.target_spacing_s()).unwrap() / 2;
        p.coinbase_maturity = 1;
    })
}

#[test]
fn disconnecting_and_reconnecting_restores_the_utxo_set_byte_for_byte() {
    let t = TestChain::with_params(devnet_with(|p| p.coinbase_maturity = 1));
    t.extend(3);

    // Spend a matured coinbase so the undo records carry real work, not just
    // creations: a reorg that only ever added coins would never exercise them.
    let funded = t.coinbase_out(1);
    let value = t.coin_at(&funded).unwrap().value;
    let payment =
        spend(&[funded], &[(value.checked_sub(amount(5_000)).unwrap(), any_spend_script())]);
    let block = t.mine(vec![payment]);
    t.accept(block).unwrap();
    t.extend(2);

    let before_root = t.state_root();
    let before_utxos = t.utxo_snapshot();
    let (before_tip, before_height) = t.tip();

    // Peel four blocks off, remembering them tip-first.
    let mut removed: Vec<BlockHash> = Vec::new();
    for _ in 0..4 {
        removed.push(t.store.disconnect_tip().unwrap());
    }
    assert_eq!(t.tip().1, before_height, "the cache is stale until refreshed");
    assert_eq!(t.store.tip().unwrap().unwrap().1, before_height - 4);
    assert_ne!(t.state_root(), before_root, "the state really did change");

    // Put them back, oldest first.
    for hash in removed.iter().rev() {
        connect_tip_block(&t.store, &t.params, &t.engines, hash).unwrap();
    }

    assert_eq!(t.store.tip().unwrap(), Some((before_tip, before_height)));
    assert_eq!(t.state_root(), before_root, "the state root must be identical");
    assert_eq!(t.utxo_snapshot(), before_utxos, "the UTXO set must be byte-identical");
}

#[test]
fn a_reorg_leaves_the_same_state_as_mining_the_winning_branch_directly() {
    /// A state root plus the raw UTXO table, so two runs can be compared byte
    /// for byte rather than only by root.
    type Snapshot = ([u8; 32], Vec<(Vec<u8>, Vec<u8>)>);

    let params = fast_difficulty();
    let build = |reorg: bool| -> Snapshot {
        let t = TestChain::with_params(params.clone());
        let main = t.extend(1);
        let base_ms = t.header(&main[0]).timestamp_ms;
        if reorg {
            // Mine a losing branch first, then replace it.
            t.extend(2);
        }
        let b2 = t.mine_on(&main[0], Vec::new(), base_ms + 1_000, 1);
        let b2_hash = header_hash(&b2.header);
        t.accept(b2).unwrap();
        let b3 = t.mine_on(&b2_hash, Vec::new(), base_ms + 2_000, 2);
        t.accept(b3).unwrap();
        (t.state_root().to_bytes(), t.utxo_snapshot())
    };
    let (direct_root, direct_utxos) = build(false);
    let (reorged_root, reorged_utxos) = build(true);
    assert_eq!(direct_root, reorged_root, "a reorg must equal a replay of the winner");
    assert_eq!(direct_utxos, reorged_utxos);
}

#[test]
fn a_short_heavy_chain_beats_a_long_light_one() {
    let t = TestChain::with_params(fast_difficulty());
    let main = t.extend(7);
    assert_eq!(t.tip().1, 7);
    let base_ms = t.header(&main[0]).timestamp_ms;
    let light_work = t.chain.total_work(&main[6]).unwrap();

    // Three blocks, each mined one second after the last: ASERT drives the
    // target down hard, so they are worth many of the on-schedule ones.
    let b2 = t.mine_on(&main[0], Vec::new(), base_ms + 1_000, 101);
    let b2_hash = header_hash(&b2.header);
    assert_eq!(t.accept(b2).unwrap(), AcceptOutcome::SideChain(b2_hash));

    let b3 = t.mine_on(&b2_hash, Vec::new(), base_ms + 2_000, 102);
    let b3_hash = header_hash(&b3.header);
    assert_eq!(t.accept(b3).unwrap(), AcceptOutcome::SideChain(b3_hash));

    let b4 = t.mine_on(&b3_hash, Vec::new(), base_ms + 3_000, 103);
    let b4_hash = header_hash(&b4.header);
    assert!(
        matches!(t.accept(b4).unwrap(), AcceptOutcome::Reorged { .. }),
        "four blocks of work must beat eight blocks of height"
    );

    let (tip, height) = t.tip();
    assert_eq!(tip, b4_hash);
    assert_eq!(height, 4, "the winning chain is three blocks shorter");
    assert!(t.chain.total_work(&b4_hash).unwrap() > light_work);
}

#[test]
fn a_failed_reorg_leaves_the_original_tip_untouched() {
    let t = TestChain::with_params(fast_difficulty());
    let main = t.extend(4);
    let base_ms = t.header(&main[0]).timestamp_ms;
    let before_root = t.state_root();
    let before_utxos = t.utxo_snapshot();
    let before_tip = t.tip();

    let b2 = t.mine_on(&main[0], Vec::new(), base_ms + 1_000, 201);
    let b2_hash = header_hash(&b2.header);
    assert_eq!(t.accept(b2).unwrap(), AcceptOutcome::SideChain(b2_hash));

    // Heavy enough to trigger the reorg, but its coinbase claims one grain too
    // much, so the *second* connect fails after the first has been applied.
    let mut b3 = t.mine_on(&b2_hash, Vec::new(), base_ms + 2_000, 202);
    let over = t.params.block_subsidy(3).checked_add(amount(1)).unwrap();
    b3.txs[0] = coinbase(3, over, b"greedy");
    let b3 = reseal(b3);
    let b3_hash = header_hash(&b3.header);

    match t.accept(b3) {
        Err(ChainError::Validation(ValidationError::CoinbaseOverpayment { .. })) => {}
        other => panic!("expected the reorg to fail on the coinbase, got {other:?}"),
    }

    assert_eq!(t.store.tip().unwrap(), Some(before_tip));
    assert_eq!(t.state_root(), before_root, "a failed reorg changes nothing");
    assert_eq!(t.utxo_snapshot(), before_utxos);
    assert_eq!(
        t.store.get_header(&b3_hash).unwrap().unwrap().status,
        BlockStatus::Invalid,
        "the branch that failed is remembered as invalid"
    );
}

#[test]
fn the_manager_recovers_and_keeps_extending_after_a_failed_reorg() {
    let t = TestChain::with_params(fast_difficulty());
    let main = t.extend(4);
    let base_ms = t.header(&main[0]).timestamp_ms;

    let b2 = t.mine_on(&main[0], Vec::new(), base_ms + 1_000, 211);
    let b2_hash = header_hash(&b2.header);
    t.accept(b2).unwrap();
    let mut b3 = t.mine_on(&b2_hash, Vec::new(), base_ms + 2_000, 212);
    b3.txs[0] = coinbase(3, t.params.block_subsidy(3).checked_add(amount(1)).unwrap(), b"x");
    let b3 = reseal(b3);
    assert!(t.accept(b3).is_err());

    // The original chain still accepts new blocks.
    let next = t.mine(Vec::new());
    let hash = header_hash(&next.header);
    assert_eq!(t.accept(next).unwrap(), AcceptOutcome::Extended(hash));
    assert_eq!(t.tip(), (hash, 5));
}

#[test]
fn plan_reorg_finds_the_fork_point() {
    let t = TestChain::new();
    let main = t.extend(3);
    let fork = t.mine_on(&main[0], Vec::new(), 0, 55);
    let fork_hash = header_hash(&fork.header);
    t.accept(fork).unwrap();

    let plan = plan_reorg(&t.store, &main[2], &fork_hash).unwrap();
    assert_eq!(plan.fork_hash, main[0]);
    assert_eq!(plan.fork_height, 1);
    assert_eq!(plan.disconnect, vec![main[2], main[1]]);
    assert_eq!(plan.connect, vec![fork_hash]);
    assert_eq!(plan.depth(), 2);
    assert!(!plan.is_fast_forward());
}

#[test]
fn plan_reorg_of_a_straight_extension_disconnects_nothing() {
    let t = TestChain::new();
    let main = t.extend(3);
    let plan = plan_reorg(&t.store, &main[0], &main[2]).unwrap();
    assert!(plan.is_fast_forward());
    assert_eq!(plan.fork_hash, main[0]);
    assert_eq!(plan.connect, vec![main[1], main[2]]);
}

#[test]
fn plan_reorg_to_the_same_tip_is_empty() {
    let t = TestChain::new();
    let main = t.extend(2);
    let plan = plan_reorg(&t.store, &main[1], &main[1]).unwrap();
    assert!(plan.disconnect.is_empty());
    assert!(plan.connect.is_empty());
    assert_eq!(plan.fork_hash, main[1]);
}

#[test]
fn plan_reorg_reports_a_hash_it_does_not_know() {
    let t = TestChain::new();
    let main = t.extend(1);
    let unknown = BlockHash(Hash32::from_bytes([0xee; 32]));
    assert!(matches!(
        plan_reorg(&t.store, &main[0], &unknown),
        Err(ChainError::MissingHeaderEntry(h)) if h == unknown
    ));
}

#[test]
fn a_reorg_re_exposes_the_coins_the_losing_branch_had_spent() {
    let t = TestChain::with_params(fast_difficulty());
    let main = t.extend(2);
    let base_ms = t.header(&main[0]).timestamp_ms;

    // Height 3 on the main branch spends the coinbase of height 1.
    let funded = t.coinbase_out(1);
    let value = t.coin_at(&funded).unwrap().value;
    let payment =
        spend(&[funded], &[(value.checked_sub(amount(1_000)).unwrap(), any_spend_script())]);
    let spending_block = t.mine(vec![payment.clone()]);
    t.accept(spending_block).unwrap();
    assert!(t.coin_at(&funded).is_none());
    assert!(t.coin_at(&out_point(&payment, 0)).is_some());

    // A heavier branch from height 1 that never saw the payment.
    let b2 = t.mine_on(&main[0], Vec::new(), base_ms + 1_000, 221);
    let b2_hash = header_hash(&b2.header);
    t.accept(b2).unwrap();
    let b3 = t.mine_on(&b2_hash, Vec::new(), base_ms + 2_000, 222);
    let b3_hash = header_hash(&b3.header);
    t.accept(b3).unwrap();
    let b4 = t.mine_on(&b3_hash, Vec::new(), base_ms + 3_000, 223);
    t.accept(b4).unwrap();

    assert!(t.coin_at(&funded).is_some(), "the undo record put the coin back");
    assert!(t.coin_at(&out_point(&payment, 0)).is_none(), "its child is gone");
}

#[test]
fn connect_tip_block_refuses_a_block_it_has_no_body_for() {
    let t = TestChain::new();
    let block = t.mine(Vec::new());
    let hash = header_hash(&block.header);
    t.chain.accept_header(block.header).unwrap();
    assert!(matches!(
        connect_tip_block(&t.store, &t.params, &t.engines, &hash),
        Err(ChainError::MissingBlockBody(h)) if h == hash
    ));
}

#[test]
fn a_reorg_onto_a_branch_whose_bodies_are_missing_is_deferred_not_condemned() {
    // Headers-first sync stores headers long before the bodies behind them, so
    // a heavier branch is routinely known as headers with only some bodies in
    // hand. Gossip can then deliver the *tip's* body first. Treating the
    // resulting `MissingBlockBody` as a verdict about the branch marks the whole
    // honest chain `Invalid` — permanently, inherited by every later block, and
    // every peer serving it gets banned.
    let t = TestChain::with_params(fast_difficulty());
    let main = t.extend(2);
    let base_ms = t.header(&main[0]).timestamp_ms;

    let b2 = t.mine_on(&main[0], Vec::new(), base_ms + 1_000, 301);
    let b2_hash = header_hash(&b2.header);
    t.chain.accept_header(b2.header).unwrap();

    let b3 = t.mine_on(&b2_hash, Vec::new(), base_ms + 2_000, 302);
    let b3_hash = header_hash(&b3.header);

    let before_tip = t.tip();
    let before_root = t.state_root();
    match t.accept(b3.clone()) {
        Err(ChainError::MissingBlockBody(h)) if h == b2_hash => {}
        other => panic!("expected the reorg to defer on the missing body, got {other:?}"),
    }

    for (name, hash) in [("the missing block", b2_hash), ("the branch tip", b3_hash)] {
        assert_ne!(
            t.store.get_header(&hash).unwrap().unwrap().status,
            BlockStatus::Invalid,
            "{name} is not invalid; its body simply has not arrived"
        );
    }
    assert_eq!(t.tip(), before_tip, "nothing was disconnected");
    assert_eq!(t.state_root(), before_root);

    // And the retry works: once the gap is filled, re-offering the branch tip
    // adopts it. A stored-but-unconnected block that wins fork choice must be
    // reconsidered rather than dismissed as a duplicate, or the node sits one
    // block below the network until someone happens to gossip it again.
    t.accept(b2).unwrap();
    match t.accept(b3).unwrap() {
        AcceptOutcome::Extended(h) if h == b3_hash => {}
        AcceptOutcome::Reorged { to, .. } if to == b3_hash => {}
        other => panic!("the stored branch tip must be reconsidered, got {other:?}"),
    }
    assert_eq!(t.tip(), (b3_hash, 3), "the heavier branch wins once its bodies are all present");
}

#[test]
fn a_disconnect_that_fails_part_way_puts_the_blocks_back() {
    // Every `disconnect_tip` is its own committed transaction, so a failure on
    // the Nth leaves N-1 blocks off the active chain. The store is then at a
    // state no chain ever had, and the next honest block is rejected with
    // `NonContiguousConnect` — which used to be recorded as *the block's* fault.
    let t = TestChain::new();
    let main = t.extend(3);
    let before_tip = t.store.tip().unwrap().unwrap();
    let before_root = t.state_root();
    let before_utxos = t.utxo_snapshot();

    // A plan that walks one block past genesis. Genesis cannot be disconnected,
    // so the fourth call fails after three have already been committed.
    let genesis = t.store.hash_at_height(0).unwrap().unwrap();
    let plan = ReorgPlan {
        fork_hash: genesis,
        fork_height: 0,
        disconnect: vec![main[2], main[1], main[0], genesis],
        connect: Vec::new(),
    };

    match execute_reorg(&t.store, &t.params, &t.engines, &plan) {
        Err(ChainError::Storage(_)) => {}
        other => panic!("expected the disconnect to fail, got {other:?}"),
    }

    assert_eq!(t.store.tip().unwrap(), Some(before_tip), "the chain is back where it started");
    assert_eq!(t.state_root(), before_root, "and so is the UTXO set");
    assert_eq!(t.utxo_snapshot(), before_utxos);
}

#[test]
fn a_reorg_that_cannot_connect_for_a_storage_reason_leaves_the_branch_alone() {
    // The verdict recorded on a failed connect must depend on *why* it failed.
    // `is_consensus_verdict` draws that line, and only a rule the block itself
    // broke may write the permanent, inherited `Invalid`.
    use ferrum_storage::StorageError;

    use crate::error::ValidationError;
    use crate::reorg::is_consensus_verdict;

    assert!(is_consensus_verdict(&ChainError::Validation(ValidationError::EmptyBlock)));
    assert!(!is_consensus_verdict(&ChainError::Storage(StorageError::NoTip)));
    assert!(!is_consensus_verdict(&ChainError::MissingBlockBody(BlockHash::ZERO)));
    assert!(!is_consensus_verdict(&ChainError::Arithmetic("cumulative work")));
}
