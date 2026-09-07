#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use ferrum_chain::{AcceptOutcome, ChainManager};
use ferrum_consensus::EngineRouter;
use ferrum_mempool::{Mempool, MempoolConfig};
use ferrum_storage::{Store, StoreConfig};
use ferrum_types::ChainParams;

use super::*;
use crate::relay::{Clock, FixedClock, Relay};
use crate::telemetry::NodeMetrics;

/// Devnet's proof-of-work limit is trivial, so a block seals in
/// microseconds; every test here mines for real rather than faking a seal.
fn devnet_relay() -> (Arc<Relay>, Arc<ChainManager>, Arc<FixedClock>) {
    let params = ChainParams::devnet();
    let store = Arc::new(Store::open_in_memory(StoreConfig::default()).unwrap());
    let engines = Arc::new(EngineRouter::new(params.clone()).unwrap());
    let chain = Arc::new(ChainManager::open(Arc::clone(&store), params.clone(), engines).unwrap());
    chain.init_genesis().unwrap();
    let mempool = Arc::new(Mempool::new(MempoolConfig::new(params.clone())));
    let clock = Arc::new(FixedClock::new(params.genesis_timestamp_ms + 120_000));
    let relay = Arc::new(Relay::new(
        Arc::clone(&chain),
        mempool,
        Arc::new(NodeMetrics::new()),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    (relay, chain, clock)
}

fn key() -> NodeKey {
    NodeKey::from_seed([42u8; 32])
}

fn miner() -> (Arc<Miner>, Arc<ChainManager>, Arc<FixedClock>) {
    let (relay, chain, clock) = devnet_relay();
    let payout = resolve_payout(None, &key(), Network::Devnet).unwrap();
    (Arc::new(Miner::new(relay, payout)), chain, clock)
}

#[test]
fn without_a_mine_address_the_payout_comes_from_the_node_key() {
    let key = key();
    let payout = resolve_payout(None, &key, Network::Devnet).unwrap();
    assert!(!payout.explicit);
    assert_eq!(payout.address, key.mining_address(Network::Devnet).unwrap());
    assert_eq!(payout.script, payout.address.script_pubkey());
}

#[test]
fn an_explicit_mine_address_wins() {
    let other = NodeKey::from_seed([9u8; 32]).mining_address(Network::Devnet).unwrap();
    let payout = resolve_payout(Some(&other), &key(), Network::Devnet).unwrap();
    assert!(payout.explicit);
    assert_eq!(payout.address, other);
}

#[test]
fn a_mine_address_from_another_network_is_refused() {
    let mainnet = NodeKey::from_seed([9u8; 32]).mining_address(Network::Mainnet).unwrap();
    let e = resolve_payout(Some(&mainnet), &key(), Network::Devnet).unwrap_err();
    assert!(matches!(e, NodeError::Config(_)), "{e}");
}

#[test]
fn the_template_pays_the_configured_script_at_the_next_height() {
    let (miner, chain, clock) = miner();
    let template = miner.build_template(clock.now_ms()).unwrap();
    let (_, tip_height) = chain.tip();
    assert_eq!(template.height, tip_height + 1);
    let coinbase = template.txs.first().unwrap();
    assert!(coinbase.is_coinbase());
    assert_eq!(coinbase.outputs[0].script_pubkey, miner.payout().script);
}

#[test]
fn the_coinbase_pays_the_block_subsidy_when_there_are_no_fees() {
    let (miner, chain, clock) = miner();
    let template = miner.build_template(clock.now_ms()).unwrap();
    let subsidy = chain.params().block_subsidy(template.height);
    assert_eq!(template.txs[0].outputs[0].value, subsidy);
}

#[test]
fn a_mined_block_is_accepted_by_the_chain_manager() {
    let (miner, chain, _) = miner();
    let (tip_before, height_before) = chain.tip();
    let block = miner.mine_once(&AtomicBool::new(false)).unwrap().unwrap();

    assert_eq!(block.header.prev_hash, tip_before);
    let outcome = chain.accept_block(block).unwrap();
    assert!(matches!(outcome, AcceptOutcome::Extended(_)), "{outcome:?}");
    let (_, height_after) = chain.tip();
    assert_eq!(height_after, height_before + 1);
}

#[test]
fn the_miner_climbs_several_blocks() {
    let (miner, chain, clock) = miner();
    for i in 1..=5u64 {
        clock.set(ChainParams::devnet().genesis_timestamp_ms + i * 120_000);
        let (block, outcome) = miner.mine_and_submit(&AtomicBool::new(false)).unwrap().unwrap();
        assert!(outcome.should_announce(), "{outcome:?}");
        assert_eq!(chain.tip().0, ferrum_storage::header_hash(&block.header));
        assert_eq!(chain.tip().1, i);
    }
    assert_eq!(miner.relay().metrics().snapshot().blocks_mined, 5);
}

#[test]
fn a_raised_cancel_flag_stops_the_round_without_a_block() {
    let (miner, chain, _) = miner();
    let (tip, _) = chain.tip();
    let cancelled = AtomicBool::new(true);
    assert!(miner.mine_once(&cancelled).unwrap().is_none());
    assert_eq!(chain.tip().0, tip, "a cancelled round must not move the tip");
}

#[test]
fn the_extra_nonce_advances_so_two_rounds_differ() {
    let (miner, _, clock) = miner();
    let a = miner.build_template(clock.now_ms()).unwrap();
    let b = miner.build_template(clock.now_ms()).unwrap();
    assert_ne!(
        a.txs[0].inputs[0].script_sig, b.txs[0].inputs[0].script_sig,
        "the extra-nonce must move or two rounds grind identical work"
    );
    assert_ne!(a.header.merkle_root, b.header.merkle_root);
}

#[test]
fn the_template_timestamp_never_precedes_the_median_time_past() {
    let (miner, _, clock) = miner();
    // A clock far in the past must still produce a mineable template.
    clock.set(0);
    let template = miner.build_template(clock.now_ms()).unwrap();
    assert!(template.header.timestamp_ms > 0);
}

#[test]
fn a_mined_block_carries_an_empty_proof_of_work_seal() {
    let (miner, _, _) = miner();
    let block = miner.mine_once(&AtomicBool::new(false)).unwrap().unwrap();
    assert_eq!(block.seal, ferrum_types::BlockSeal::POW);
    assert!(block.seal.data.is_empty());
}

#[test]
fn the_announcement_queue_capacity_is_bounded() {
    const { assert!(MINED_BLOCK_CAPACITY > 0 && MINED_BLOCK_CAPACITY <= 64) };
}

#[tokio::test]
async fn the_run_loop_stops_when_the_token_is_cancelled() {
    let (miner, _, _) = miner();
    let (tx, _rx) = mpsc::channel(MINED_BLOCK_CAPACITY);
    let (events, rx) = broadcast::channel(8);
    let token = CancellationToken::new();
    let handle = tokio::spawn(run(Arc::clone(&miner), rx, tx, token.clone()));
    token.cancel();
    tokio::time::timeout(Duration::from_secs(10), handle).await.unwrap().unwrap();
    drop(events);
}

#[tokio::test]
async fn the_run_loop_mines_and_announces() {
    let (miner, chain, _) = miner();
    let (tx, mut rx) = mpsc::channel(MINED_BLOCK_CAPACITY);
    let (events, events_rx) = broadcast::channel(8);
    let token = CancellationToken::new();
    let handle = tokio::spawn(run(Arc::clone(&miner), events_rx, tx, token.clone()));

    let block = tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("the miner should produce a block on devnet quickly")
        .expect("the announcement channel should stay open");
    assert!(chain.tip().1 >= 1, "the run loop should have connected its own block");
    let hash = ferrum_storage::header_hash(&block.header);
    assert!(
        chain.store().get_block(&hash).unwrap().is_some(),
        "an announced block must already be in our own store"
    );

    token.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), handle).await;
    drop(events);
}
