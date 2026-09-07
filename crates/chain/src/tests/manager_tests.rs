//! CONTRACT §8.2: acceptance outcomes, sync helpers and events.

use std::sync::Arc;

use ferrum_consensus::{ConsensusError, EngineRouter};
use ferrum_storage::{BlockIndexEntry, BlockStatus, Store, StoreConfig, header_hash};
use ferrum_types::{Amount, BlockHash, ChainParams, CompactTarget, Hash32};

use crate::error::{ChainError, ValidationError};
use crate::genesis::genesis_hash;
use crate::manager::{AcceptOutcome, ChainEvent, ChainManager};
use crate::tests::support::{TestChain, coinbase, devnet_with, reseal, spend};

fn amount(v: u64) -> Amount {
    Amount::from_grains(v)
}

/// Devnet with a difficulty controller fast enough that a short branch can
/// out-work a long one inside a test.
///
/// What makes a one-second block heavy is the ratio `spacing / half-life`, not
/// either number alone. Half a spacing puts such a block 2.5 half-lives ahead
/// of schedule and therefore ~5.7x harder than an on-schedule one, which is the
/// margin these tests were written against. Pinning 60 s here instead would
/// silently shrink that margin to 1% at devnet's 5 s spacing — still passing,
/// but no longer testing anything.
fn fast_difficulty() -> ChainParams {
    devnet_with(|p| p.asert_halflife_s = i64::try_from(p.target_spacing_s()).unwrap() / 2)
}

#[test]
fn init_genesis_sets_the_tip_and_is_idempotent() {
    let t = TestChain::new();
    let g = genesis_hash(&t.params);
    assert_eq!(t.tip(), (g, 0));
    assert_eq!(t.chain.init_genesis().unwrap(), g);
    assert_eq!(t.tip(), (g, 0));
    assert_eq!(t.store.utxo_count().unwrap(), 1);
}

#[test]
fn init_genesis_refuses_a_datadir_from_another_network() {
    let store = Arc::new(Store::open_in_memory(StoreConfig::default()).unwrap());
    let devnet = ChainParams::devnet();
    let engines = Arc::new(EngineRouter::new(devnet.clone()).unwrap());
    let chain = ChainManager::open(Arc::clone(&store), devnet.clone(), engines).unwrap();
    chain.init_genesis().unwrap();

    let testnet = ChainParams::testnet();
    let other_engines = Arc::new(EngineRouter::new(testnet.clone()).unwrap());
    let other = ChainManager::open(Arc::clone(&store), testnet.clone(), other_engines).unwrap();
    match other.init_genesis() {
        Err(ChainError::GenesisMismatch { expected, actual }) => {
            assert_eq!(expected, genesis_hash(&testnet));
            assert_eq!(actual, genesis_hash(&devnet));
        }
        other => panic!("expected a genesis mismatch, got {other:?}"),
    }
}

#[test]
fn a_block_on_the_tip_extends_the_chain() {
    let t = TestChain::new();
    let block = t.mine(Vec::new());
    let hash = header_hash(&block.header);
    assert_eq!(t.accept(block).unwrap(), AcceptOutcome::Extended(hash));
    assert_eq!(t.tip(), (hash, 1));
}

#[test]
fn a_block_offered_twice_is_a_duplicate() {
    let t = TestChain::new();
    let block = t.mine(Vec::new());
    t.accept(block.clone()).unwrap();
    assert_eq!(t.accept(block).unwrap(), AcceptOutcome::Duplicate);
}

#[test]
fn a_block_whose_parent_is_unknown_is_an_orphan_and_is_held() {
    let t = TestChain::new();
    let hashes = t.extend(1);
    // Build a block on a parent the chain knows, then re-point it at nothing.
    let mut block = t.mine_on(&hashes[0], Vec::new(), 0, 9);
    block.header.prev_hash = BlockHash(Hash32::from_bytes([0x5a; 32]));
    let block = reseal(block);
    assert_eq!(t.accept(block).unwrap(), AcceptOutcome::Orphan);
    assert_eq!(t.chain.orphan_count(), 1, "orphans are held, not banned");
}

#[test]
fn a_held_orphan_connects_once_its_parent_arrives() {
    // Build the two blocks on a donor chain, then feed them to a fresh one
    // out of order: the child arrives before the parent exists.
    let donor = TestChain::new();
    let first = donor.mine(Vec::new());
    let first_hash = header_hash(&first.header);
    donor.accept(first.clone()).unwrap();
    let second = donor.mine(Vec::new());
    let second_hash = header_hash(&second.header);

    let t = TestChain::new();
    assert_eq!(t.accept(second).unwrap(), AcceptOutcome::Orphan);
    assert_eq!(t.accept(first).unwrap(), AcceptOutcome::Extended(first_hash));

    let drained = t.chain.accept_orphan_descendants(&first_hash).unwrap();
    assert_eq!(drained, vec![(second_hash, AcceptOutcome::Extended(second_hash))]);
    assert_eq!(t.tip(), (second_hash, 2));
    assert_eq!(t.chain.orphan_count(), 0);
}

#[test]
fn a_lighter_branch_is_kept_as_a_side_chain() {
    let t = TestChain::new();
    let main = t.extend(3);
    // Fork from height 1. Every branch shares the ASERT anchor whatever it
    // forks from, because the anchor is genesis (CONTRACT §6.3).
    let fork = t.mine_on(&main[0], Vec::new(), 0, 77);
    let fork_hash = header_hash(&fork.header);
    assert_eq!(t.accept(fork).unwrap(), AcceptOutcome::SideChain(fork_hash));
    assert_eq!(t.tip().0, main[2], "the active tip does not move");
    assert_eq!(t.height_of(&fork_hash), 2);
}

#[test]
fn a_heavier_branch_takes_over() {
    let t = TestChain::with_params(fast_difficulty());
    let main = t.extend(3);
    let base_ms = t.header(&main[0]).timestamp_ms;

    // Fast blocks are harder blocks: each is worth several of the on-schedule
    // ones, so this branch out-works the longer chain.
    let b2 = t.mine_on(&main[0], Vec::new(), base_ms + 1_000, 1);
    let b2_hash = header_hash(&b2.header);
    assert_eq!(t.accept(b2).unwrap(), AcceptOutcome::SideChain(b2_hash));

    let b3 = t.mine_on(&b2_hash, Vec::new(), base_ms + 2_000, 2);
    let b3_hash = header_hash(&b3.header);
    match t.accept(b3).unwrap() {
        AcceptOutcome::Reorged { from, to, disconnected, connected } => {
            assert_eq!(from, main[2]);
            assert_eq!(to, b3_hash);
            assert_eq!(disconnected, vec![main[2], main[1]], "tip first");
            assert_eq!(connected, vec![b2_hash, b3_hash], "ancestor first");
        }
        other => panic!("expected a reorg, got {other:?}"),
    }
    assert_eq!(t.tip(), (b3_hash, 3));
}

#[test]
fn accept_header_records_a_header_only_entry() {
    let t = TestChain::new();
    let block = t.mine(Vec::new());
    let hash = header_hash(&block.header);
    t.chain.accept_header(block.header).unwrap();
    let entry = t.store.get_header(&hash).unwrap().unwrap();
    assert_eq!(entry.status, BlockStatus::HeaderOnly);
    assert_eq!(entry.height, 1);
    assert_eq!(t.tip().1, 0, "a header alone does not move the tip");
}

#[test]
fn accept_header_is_idempotent_and_needs_a_parent() {
    let t = TestChain::new();
    let block = t.mine(Vec::new());
    t.chain.accept_header(block.header).unwrap();
    t.chain.accept_header(block.header).unwrap();

    let mut orphan = block;
    orphan.header.prev_hash = BlockHash(Hash32::from_bytes([0x11; 32]));
    let orphan = reseal(orphan);
    assert!(matches!(t.chain.accept_header(orphan.header), Err(ChainError::UnknownParent(_))));
}

#[test]
fn a_body_arriving_after_its_header_still_connects() {
    let t = TestChain::new();
    let block = t.mine(Vec::new());
    let hash = header_hash(&block.header);
    t.chain.accept_header(block.header).unwrap();
    assert_eq!(t.accept(block).unwrap(), AcceptOutcome::Extended(hash));
    assert_eq!(t.store.get_header(&hash).unwrap().unwrap().status, BlockStatus::Valid);
}

#[test]
fn an_invalid_block_is_remembered_as_invalid() {
    let t = TestChain::new();
    let mut block = t.mine(Vec::new());
    let over = t.params.block_subsidy(1).checked_add(amount(1)).unwrap();
    block.txs[0] = coinbase(1, over, b"greedy");
    let block = reseal(block);
    let hash = header_hash(&block.header);

    match t.accept(block.clone()) {
        Err(ChainError::Validation(ValidationError::CoinbaseOverpayment { .. })) => {}
        other => panic!("expected an overpayment rejection, got {other:?}"),
    }
    assert_eq!(t.store.get_header(&hash).unwrap().unwrap().status, BlockStatus::Invalid);
    assert!(matches!(t.accept(block), Err(ChainError::KnownInvalid(h)) if h == hash));
    assert_eq!(t.tip().1, 0, "the tip never moved");
}

#[test]
fn a_block_whose_bits_are_wrong_is_rejected_by_the_engine() {
    let t = TestChain::new();
    let mut block = t.mine(Vec::new());
    let required = block.header.bits;
    // A *harder* target than the rule demands. Over-paying difficulty is just
    // as invalid as under-paying: there is exactly one correct target per
    // parent, or a miner could pick whichever one suits its fork.
    let harder = CompactTarget(0x1f00_ffff);
    block.header.bits = harder;
    let block = reseal(block);
    match t.accept(block) {
        Err(ChainError::Consensus(ConsensusError::BadDifficultyTransition {
            expected,
            actual,
        })) => {
            assert_eq!(expected, required);
            assert_eq!(actual, harder);
        }
        other => panic!("expected a difficulty-transition rejection, got {other:?}"),
    }
}

#[test]
fn an_equal_work_tie_is_broken_by_the_lower_block_hash() {
    let t = TestChain::new();
    // Two siblings on the same parent: identical bits, so identical work.
    let a = t.mine_on(&t.tip().0, Vec::new(), 0, 1);
    let b = t.mine_on(&t.tip().0, Vec::new(), 0, 2);
    let (a_hash, b_hash) = (header_hash(&a.header), header_hash(&b.header));
    assert_ne!(a_hash, b_hash);
    let (loser, winner, loser_hash, winner_hash) =
        if a_hash < b_hash { (b, a, b_hash, a_hash) } else { (a, b, a_hash, b_hash) };

    assert_eq!(t.accept(loser).unwrap(), AcceptOutcome::Extended(loser_hash));
    // First-seen does not decide: the lower hash does, so two nodes that saw
    // these in opposite orders still agree.
    assert!(matches!(t.accept(winner).unwrap(), AcceptOutcome::Reorged { .. }));
    assert_eq!(t.tip(), (winner_hash, 1));
}

#[test]
fn the_losing_sibling_is_never_adopted_when_it_arrives_second() {
    let t = TestChain::new();
    let a = t.mine_on(&t.tip().0, Vec::new(), 0, 3);
    let b = t.mine_on(&t.tip().0, Vec::new(), 0, 4);
    let (a_hash, b_hash) = (header_hash(&a.header), header_hash(&b.header));
    let (winner, loser, winner_hash, loser_hash) =
        if a_hash < b_hash { (a, b, a_hash, b_hash) } else { (b, a, b_hash, a_hash) };
    assert_eq!(t.accept(winner).unwrap(), AcceptOutcome::Extended(winner_hash));
    assert_eq!(t.accept(loser).unwrap(), AcceptOutcome::SideChain(loser_hash));
    assert_eq!(t.tip(), (winner_hash, 1));
}

#[test]
fn total_work_grows_with_every_block() {
    let t = TestChain::new();
    let hashes = t.extend(3);
    let g = genesis_hash(&t.params);
    let mut previous = t.chain.total_work(&g).unwrap();
    for h in hashes {
        let work = t.chain.total_work(&h).unwrap();
        assert!(work > previous, "cumulative work must strictly increase");
        previous = work;
    }
    assert_eq!(t.chain.total_work(&BlockHash(Hash32::from_bytes([0; 32]))), None);
}

#[test]
fn the_locator_starts_at_the_tip_and_ends_at_genesis() {
    let t = TestChain::new();
    let hashes = t.extend(25);
    let locator = t.chain.locator();
    assert_eq!(locator.first(), Some(&hashes[24]));
    assert_eq!(locator.last(), Some(&genesis_hash(&t.params)));
    assert!(locator.len() < 26, "the back-off must be sub-linear, got {}", locator.len());
    assert!(locator.len() >= 11);
}

#[test]
fn the_locator_steps_one_at_a_time_for_the_first_ten() {
    let t = TestChain::new();
    let hashes = t.extend(20);
    let locator = t.chain.locator();
    for (i, hash) in locator.iter().take(10).enumerate() {
        assert_eq!(*hash, hashes[19 - i], "entry {i} must be one block back");
    }
}

#[test]
fn the_locator_of_a_bare_genesis_chain_is_genesis() {
    let t = TestChain::new();
    assert_eq!(t.chain.locator(), vec![genesis_hash(&t.params)]);
}

#[test]
fn find_fork_point_picks_the_newest_shared_block() {
    let t = TestChain::new();
    let hashes = t.extend(5);
    assert_eq!(t.chain.find_fork_point(&t.chain.locator()), Some((hashes[4], 5)));

    let g = genesis_hash(&t.params);
    assert_eq!(t.chain.find_fork_point(&[g]), Some((g, 0)));
    assert_eq!(t.chain.find_fork_point(&[]), None);
}

#[test]
fn headers_from_walks_forward_from_the_fork_point() {
    let t = TestChain::new();
    let hashes = t.extend(5);
    let g = genesis_hash(&t.params);

    let all = t.chain.headers_from(&[g], 100);
    assert_eq!(all.len(), 5);
    assert_eq!(header_hash(&all[0]), hashes[0]);
    assert_eq!(header_hash(&all[4]), hashes[4]);

    let capped = t.chain.headers_from(&[g], 2);
    assert_eq!(capped.len(), 2, "the server-side cap is honoured");

    let from_tip = t.chain.headers_from(&[hashes[4]], 100);
    assert!(from_tip.is_empty(), "nothing follows the tip");
}

#[test]
fn a_subscriber_hears_about_a_new_tip() {
    let t = TestChain::new();
    let events = t.chain.subscribe();
    let hashes = t.extend(1);
    match events.try_recv().unwrap() {
        ChainEvent::NewTip { hash, height, .. } => {
            assert_eq!(hash, hashes[0]);
            assert_eq!(height, 1);
        }
        other => panic!("expected a new tip, got {other:?}"),
    }
}

#[test]
fn a_subscriber_hears_about_a_reorg() {
    let t = TestChain::with_params(fast_difficulty());
    let main = t.extend(3);
    let base_ms = t.header(&main[0]).timestamp_ms;
    let events = t.chain.subscribe();

    let b2 = t.mine_on(&main[0], Vec::new(), base_ms + 1_000, 1);
    let b2_hash = header_hash(&b2.header);
    t.accept(b2).unwrap();
    let b3 = t.mine_on(&b2_hash, Vec::new(), base_ms + 2_000, 2);
    t.accept(b3).unwrap();

    let first = events.try_recv().unwrap();
    match first {
        ChainEvent::Reorg { from, disconnected, connected, .. } => {
            assert_eq!(from, main[2]);
            assert_eq!(disconnected.len(), 2);
            assert_eq!(connected.len(), 2);
        }
        other => panic!("expected a reorg event, got {other:?}"),
    }
    assert!(matches!(events.try_recv().unwrap(), ChainEvent::NewTip { .. }));
}

#[test]
fn a_dropped_subscriber_is_forgotten() {
    let t = TestChain::new();
    let events = t.chain.subscribe();
    drop(events);
    t.extend(2);
    assert_eq!(t.tip().1, 2, "a dead subscriber must not stop the chain");
}

#[test]
fn coins_become_spendable_after_maturity() {
    let t = TestChain::with_params(devnet_with(|p| p.coinbase_maturity = 1));
    t.extend(2);
    let funded = t.coinbase_out(1);
    let value = t.coin_at(&funded).unwrap().value;
    let payment = spend(
        &[funded],
        &[(value.checked_sub(amount(1_000)).unwrap(), crate::tests::support::any_spend_script())],
    );
    let block = t.mine(vec![payment.clone()]);
    let hash = header_hash(&block.header);
    assert_eq!(t.accept(block).unwrap(), AcceptOutcome::Extended(hash));
    assert!(t.coin_at(&funded).is_none(), "the coin was consumed");
    assert!(t.coin_at(&crate::tests::support::out_point(&payment, 0)).is_some());
}

#[test]
fn an_immature_coinbase_cannot_be_spent() {
    let t = TestChain::new();
    t.extend(2);
    let funded = t.coinbase_out(1);
    let value = t.coin_at(&funded).unwrap().value;
    let payment = spend(
        &[funded],
        &[(value.checked_sub(amount(1_000)).unwrap(), crate::tests::support::any_spend_script())],
    );
    let block = t.mine(vec![payment]);
    match t.accept(block) {
        Err(ChainError::Validation(ValidationError::ImmatureCoinbaseSpend {
            maturity, ..
        })) => {
            // Read the window off the parameters. Devnet's is 10 and mainnet's
            // is 100; what this test is about is that the rule fires at all,
            // and pinning the number here only makes it rot when devnet is
            // retuned.
            assert_eq!(maturity, t.params.coinbase_maturity);
        }
        other => panic!("expected an immaturity rejection, got {other:?}"),
    }
}

#[test]
fn the_manager_exposes_what_it_was_built_with() {
    let t = TestChain::new();
    assert_eq!(t.chain.params().network, t.params.network);
    assert_eq!(t.chain.store().utxo_count().unwrap(), 1);
    assert_eq!(t.chain.engines().params().network, t.params.network);
}

#[test]
fn a_storage_failure_does_not_condemn_the_block_or_leave_a_stale_tip() {
    // `BlockStatus::Invalid` is permanent, inherited by every descendant, and
    // bans the peers that serve them. Only a rule the block broke may write it.
    // Here the block is perfectly valid and the *store* is the problem: the tip
    // moved underneath the cache, which is exactly the state a reorg that failed
    // part-way leaves behind.
    let t = TestChain::new();
    let main = t.extend(3);

    t.store.disconnect_tip().unwrap();
    assert_eq!(t.tip().1, 3, "the cache still names the old tip");
    assert_eq!(t.store.tip().unwrap().unwrap().1, 2, "the store does not");

    let stamp = t.header(&main[2]).timestamp_ms + t.params.target_spacing_ms;
    let next = t.mine_on(&main[2], Vec::new(), stamp, 9);
    let hash = header_hash(&next.header);

    match t.accept(next) {
        Err(ChainError::Storage(_)) => {}
        other => panic!("expected the connect to fail on the tip mismatch, got {other:?}"),
    }

    assert_ne!(
        t.store.get_header(&hash).unwrap().unwrap().status,
        BlockStatus::Invalid,
        "the store failed, the block did not"
    );
    assert_eq!(
        t.tip(),
        (main[1], 2),
        "the cache must not go on claiming a tip the store does not have"
    );

    // Because nothing was condemned, the node recovers on its own.
    let stamp = t.header(&main[1]).timestamp_ms + t.params.target_spacing_ms;
    let again = t.mine_on(&main[1], Vec::new(), stamp, 10);
    let again_hash = header_hash(&again.header);
    assert_eq!(t.accept(again).unwrap(), AcceptOutcome::Extended(again_hash));
}

#[test]
fn a_status_claiming_a_body_the_store_lacks_is_repaired_not_ignored() {
    // The state a crash between the two writes leaves if the header is written
    // first: the index says `HaveData`, the `blocks` table has nothing. Sync
    // computes "do I still need this body?" from that byte, so it never asks
    // again, and gossip is answered with `Duplicate` — the node can never
    // connect the block. Re-offering it has to repair the store.
    let t = TestChain::new();
    let block = t.mine(Vec::new());
    let hash = header_hash(&block.header);

    t.chain.accept_header(block.header).unwrap();
    let stored = t.store.get_header(&hash).unwrap().unwrap();
    t.store
        .store_header(&BlockIndexEntry { status: BlockStatus::HaveData, ..stored })
        .unwrap();
    assert!(t.store.get_block(&hash).unwrap().is_none(), "no body, by construction");

    assert_eq!(t.accept(block).unwrap(), AcceptOutcome::Extended(hash));
    assert!(t.store.get_block(&hash).unwrap().is_some(), "the body was written after all");
    assert_eq!(t.tip(), (hash, 1));
    let repaired = t.store.get_header(&hash).unwrap().unwrap();
    assert_eq!(repaired.tx_count, 1, "and the index entry describes the body it now has");
    assert!(repaired.size > 0);
}

#[test]
fn a_stored_block_that_does_not_win_is_still_reported_as_a_duplicate() {
    // Re-running fork choice for a stored block must not change what a caller
    // is told about one that loses: the node's gossip verdict maps `Duplicate`
    // to "ignore, do not forward", and a losing side-chain block re-offered by
    // three peers is not three new blocks.
    let t = TestChain::new();
    let main = t.extend(2);
    let genesis = t.store.hash_at_height(0).unwrap().unwrap();
    let base_ms = t.header(&genesis).timestamp_ms;

    // A branch off genesis: one block against the chain's two, so it loses on
    // cumulative work outright rather than on the hash tiebreak.
    let side = t.mine_on(&genesis, Vec::new(), base_ms + t.params.target_spacing_ms, 402);
    let side_hash = header_hash(&side.header);
    assert_eq!(t.accept(side.clone()).unwrap(), AcceptOutcome::SideChain(side_hash));
    assert_eq!(t.accept(side).unwrap(), AcceptOutcome::Duplicate, "offered twice, still a duplicate");
    assert_eq!(t.tip().0, main[1], "and the tip did not move");
}
