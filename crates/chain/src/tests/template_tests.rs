//! CONTRACT §8.2: `build_template` produces a block that will validate.

use ferrum_consensus::{HeaderView, compact_to_target, hash_meets_target};
use ferrum_storage::header_hash;
use ferrum_types::{Amount, Block, BlockSeal, OutPoint, Script, Txid};

use crate::error::ChainError;
use crate::manager::AcceptOutcome;
use crate::template::{block_size_of, build_coinbase, tx_body_size};
use crate::tests::support::{
    TestChain, any_spend_script, coinbase, devnet, devnet_with, out_point, seal_pow, spend,
};
use crate::validate::{check_coinbase_script_sig, compute_merkle_root};
use crate::view::StoreHeaderView;

fn amount(v: u64) -> Amount {
    Amount::from_grains(v)
}

fn payout() -> Script {
    any_spend_script()
}

#[test]
fn the_incremental_size_matches_the_encoder() {
    let txs = vec![
        coinbase(1, amount(50), b"n"),
        spend(&[OutPoint::new(Txid::ZERO, 0)], &[(amount(1), any_spend_script())]),
    ];
    let block = Block::new(
        crate::tests::support::block_of(txs.clone(), Default::default(), 1, devnet().genesis_bits)
            .header,
        txs.clone(),
        BlockSeal::POW,
    );
    assert_eq!(block_size_of(&txs), block.serialized_size());
    assert_eq!(tx_body_size(&txs[0]), txs[0].serialized_size() - 1);
}

#[test]
fn a_template_on_genesis_has_height_one_and_names_the_tip() {
    let t = TestChain::new();
    let (tip, _) = t.tip();
    let tmpl = t.chain.build_template(&payout(), 0, Vec::new(), 0).unwrap();
    assert_eq!(tmpl.height, 1);
    assert_eq!(tmpl.header.prev_hash, tip);
    assert_eq!(tmpl.txs.len(), 1);
    assert!(tmpl.txs[0].is_coinbase());
}

#[test]
fn the_template_merkle_root_commits_to_its_transactions() {
    let t = TestChain::new();
    let tmpl = t.chain.build_template(&payout(), 7, Vec::new(), 0).unwrap();
    assert_eq!(tmpl.header.merkle_root, compute_merkle_root(&tmpl.txs));
}

#[test]
fn the_template_coinbase_pays_exactly_the_subsidy_when_there_are_no_fees() {
    let t = TestChain::new();
    let tmpl = t.chain.build_template(&payout(), 0, Vec::new(), 0).unwrap();
    assert_eq!(tmpl.txs[0].total_output().unwrap(), t.params.block_subsidy(1));
    assert_eq!(check_coinbase_script_sig(&tmpl.txs[0].inputs[0].script_sig, 1), Ok(()));
}

#[test]
fn the_template_coinbase_pays_the_subsidy_plus_every_fee() {
    let t = TestChain::with_params(devnet_with(|p| p.coinbase_maturity = 1));
    t.extend(2);
    let funded = t.coinbase_out(1);
    let value = t.coin_at(&funded).unwrap().value;
    let fee = amount(7_500);
    let tx = spend(&[funded], &[(value.checked_sub(fee).unwrap(), any_spend_script())]);

    let tmpl = t.chain.build_template(&payout(), 0, vec![tx.clone()], 0).unwrap();
    assert_eq!(tmpl.txs.len(), 2);
    assert_eq!(
        tmpl.txs[0].total_output().unwrap(),
        t.params.block_subsidy(3).checked_add(fee).unwrap()
    );
    assert_eq!(tmpl.txs[1], tx);
}

#[test]
fn a_sealed_template_is_accepted_by_the_chain() {
    let t = TestChain::with_params(devnet_with(|p| p.coinbase_maturity = 1));
    t.extend(2);
    let funded = t.coinbase_out(1);
    let value = t.coin_at(&funded).unwrap().value;
    let tx = spend(&[funded], &[(value.checked_sub(amount(2_000)).unwrap(), any_spend_script())]);

    let now = t.header(&t.tip().0).timestamp_ms + t.params.target_spacing_ms;
    let tmpl = t.chain.build_template(&payout(), 42, vec![tx.clone()], now).unwrap();
    let block = Block::new(seal_pow(tmpl.header), tmpl.txs, BlockSeal::POW);
    let hash = header_hash(&block.header);
    assert_eq!(t.accept(block).unwrap(), AcceptOutcome::Extended(hash));
    assert!(t.coin_at(&out_point(&tx, 0)).is_some());
}

#[test]
fn the_template_asks_for_the_difficulty_the_engine_requires() {
    let t = TestChain::new();
    t.extend(3);
    let (tip, _) = t.tip();
    let tmpl = t.chain.build_template(&payout(), 0, Vec::new(), 0).unwrap();
    let view = StoreHeaderView::new(&t.store, &t.params);
    let engine = t.engines.engine_for_height(tmpl.height);
    assert_eq!(tmpl.header.bits, engine.next_bits(&t.header(&tip), &view).unwrap());
    assert_eq!(compact_to_target(tmpl.header.bits).unwrap(), t.target_for_child_of(&tip));
}

#[test]
fn the_template_timestamp_is_above_the_median_time_past() {
    let t = TestChain::new();
    t.extend(5);
    let (tip, _) = t.tip();
    let view = StoreHeaderView::new(&t.store, &t.params);
    let mtp = view.median_time_past(&tip).unwrap();
    // Even when the node's clock is at zero, the stamp must clear the median.
    let tmpl = t.chain.build_template(&payout(), 0, Vec::new(), 0).unwrap();
    assert!(tmpl.header.timestamp_ms > mtp * 1_000);
}

#[test]
fn the_template_honours_a_later_wall_clock() {
    let t = TestChain::new();
    let now = 2_000_000_000_000;
    let tmpl = t.chain.build_template(&payout(), 0, Vec::new(), now).unwrap();
    assert_eq!(tmpl.header.timestamp_ms, now);
}

#[test]
fn the_template_drops_a_transaction_whose_inputs_do_not_exist() {
    let t = TestChain::new();
    let ghost = spend(&[OutPoint::new(Txid::ZERO, 3)], &[(amount(1), any_spend_script())]);
    let tmpl = t.chain.build_template(&payout(), 0, vec![ghost], 0).unwrap();
    assert_eq!(tmpl.txs.len(), 1, "only the coinbase survives");
}

#[test]
fn the_template_drops_a_transaction_it_cannot_unlock() {
    let t = TestChain::with_params(devnet_with(|p| p.coinbase_maturity = 1));
    t.extend(2);
    let funded = t.coinbase_out(1);
    let mut bad = spend(&[funded], &[(amount(1), any_spend_script())]);
    bad.inputs[0].script_sig = Script::new(vec![0x00]); // pushes false: clean stack fails
    let tmpl = t.chain.build_template(&payout(), 0, vec![bad], 0).unwrap();
    assert_eq!(tmpl.txs.len(), 1);
}

#[test]
fn the_template_drops_an_immature_coinbase_spend() {
    let t = TestChain::new();
    t.extend(2);
    let funded = t.coinbase_out(1);
    let value = t.coin_at(&funded).unwrap().value;
    let early = spend(&[funded], &[(value.checked_sub(amount(1)).unwrap(), any_spend_script())]);
    let tmpl = t.chain.build_template(&payout(), 0, vec![early], 0).unwrap();
    assert_eq!(tmpl.txs.len(), 1, "maturity is 100 blocks");
}

#[test]
fn the_template_refuses_a_second_coinbase() {
    let t = TestChain::new();
    let tmpl =
        t.chain.build_template(&payout(), 0, vec![coinbase(1, amount(1), b"sneaky")], 0).unwrap();
    assert_eq!(tmpl.txs.len(), 1);
}

#[test]
fn the_template_respects_the_block_size_limit() {
    // A limit that fits the coinbase and nothing else.
    let t = TestChain::with_params(devnet_with(|p| {
        p.coinbase_maturity = 1;
        p.max_block_size = 260;
    }));
    t.extend(2);
    let funded = t.coinbase_out(1);
    let value = t.coin_at(&funded).unwrap().value;
    let big_script = Script::new(vec![0x51; 400]);
    let fat = spend(&[funded], &[(value.checked_sub(amount(1)).unwrap(), big_script)]);

    let tmpl = t.chain.build_template(&payout(), 0, vec![fat], 0).unwrap();
    assert_eq!(tmpl.txs.len(), 1, "the fat transaction does not fit");
    let block = Block::new(tmpl.header, tmpl.txs, BlockSeal::POW);
    assert!(block.serialized_size() <= 260);
}

#[test]
fn a_template_cannot_be_built_before_genesis() {
    use std::sync::Arc;

    use ferrum_consensus::EngineRouter;
    use ferrum_storage::{Store, StoreConfig};

    use crate::manager::ChainManager;

    let params = devnet();
    let store = Arc::new(Store::open_in_memory(StoreConfig::default()).unwrap());
    let engines = Arc::new(EngineRouter::new(params.clone()).unwrap());
    let chain = ChainManager::open(store, params, engines).unwrap();
    assert!(matches!(chain.build_template(&payout(), 0, Vec::new(), 0), Err(ChainError::NoTip)));
}

#[test]
fn a_template_coinbase_is_unique_per_height_and_extra_nonce() {
    let a = build_coinbase(1, amount(50), &payout(), 0).unwrap();
    let b = build_coinbase(1, amount(50), &payout(), 1).unwrap();
    let c = build_coinbase(2, amount(50), &payout(), 0).unwrap();
    assert_ne!(a, b, "the extra-nonce gives the miner search space");
    assert_ne!(a, c, "the height push makes coinbase txids unique per height");
    assert_eq!(check_coinbase_script_sig(&a.inputs[0].script_sig, 1), Ok(()));
}

#[test]
fn a_sealed_template_meets_its_own_target() {
    let t = TestChain::new();
    let tmpl = t.chain.build_template(&payout(), 0, Vec::new(), 0).unwrap();
    let target = compact_to_target(tmpl.header.bits).unwrap();
    let sealed = seal_pow(tmpl.header);
    assert!(hash_meets_target(&header_hash(&sealed), target));
}

#[test]
fn consecutive_templates_track_the_tip() {
    let t = TestChain::new();
    for expected in 1..4u64 {
        let tmpl = t.chain.build_template(&payout(), 0, Vec::new(), 0).unwrap();
        assert_eq!(tmpl.height, expected);
        let block = Block::new(seal_pow(tmpl.header), tmpl.txs, BlockSeal::POW);
        t.accept(block).unwrap();
    }
    assert_eq!(t.tip().1, 3);
}
