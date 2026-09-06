//! SPEC §3.2, §3.3 and §4.2: `apply_block`, the determinism seam.
//!
//! Every test here builds a block by hand against a `MapView` pre-state and
//! asserts the *exact* [`ValidationError`]. A test that only asserted
//! "rejected" would keep passing once the block started being rejected for the
//! wrong reason.

use ferrum_consensus::{ConsensusError, compact_to_target, hash_meets_target};
use ferrum_storage::{EmptyView, MapView, StateView, header_hash, txid};
use ferrum_types::{
    Amount, Block, BlockHash, BlockHeader, BlockSeal, ChainParams, CompactTarget, Hash32, OutPoint,
    Script, Transaction, TxIn, TxOut, Txid,
};

use crate::apply::apply_block;
use crate::ctx::BlockCtx;
use crate::error::ValidationError;
use crate::genesis::genesis_block;
use crate::tests::support::{
    any_spend_script, block_of, coin, coinbase, ctx_at, devnet, devnet_with, map_view, out_point,
    parent_header, reseal, spend,
};

const PARENT_MS: u64 = 1_700_000_000_000;
const BLOCK_MS: u64 = PARENT_MS + 120_000;
const MTP_S: u64 = PARENT_MS / 1_000;

fn amount(v: u64) -> Amount {
    Amount::from_grains(v)
}

/// A parent header, its hash and a context for its child at height 1.
fn scene(params: &ChainParams) -> (BlockHeader, BlockHash, BlockCtx) {
    let parent = parent_header(PARENT_MS, params);
    let hash = header_hash(&parent);
    let ctx = ctx_at(1, &parent, MTP_S, params);
    (parent, hash, ctx)
}

fn block_with(txs: Vec<Transaction>, prev: BlockHash, params: &ChainParams) -> Block {
    block_of(txs, prev, BLOCK_MS, params.genesis_bits)
}

/// Grind the nonce until the header *fails* its own target.
fn break_pow(mut block: Block, params: &ChainParams) -> Block {
    let target = compact_to_target(params.genesis_bits).unwrap();
    loop {
        if !hash_meets_target(&header_hash(&block.header), target) {
            return block;
        }
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
}

// ------------------------------------------------------------- happy paths

#[test]
fn a_minimal_block_applies_and_creates_the_coinbase_output() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let cb = coinbase(1, params.block_subsidy(1), b"n");
    let block = block_with(vec![cb.clone()], prev, &params);

    let diff = apply_block(&EmptyView, &block, &ctx).unwrap();
    assert!(diff.spent.is_empty());
    assert_eq!(diff.created.len(), 1);
    assert_eq!(diff.created[0].0, out_point(&cb, 0));
    assert_eq!(diff.created[0].1.value, params.block_subsidy(1));
    assert!(diff.created[0].1.is_coinbase);
    assert_eq!(diff.created[0].1.height, 1);
}

#[test]
fn applying_the_same_block_twice_gives_the_same_diff() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let block = block_with(vec![coinbase(1, params.block_subsidy(1), b"n")], prev, &params);
    let a = apply_block(&EmptyView, &block, &ctx).unwrap();
    let b = apply_block(&EmptyView, &block, &ctx).unwrap();
    assert_eq!(a, b, "the seam must be a pure function");
}

#[test]
fn a_block_that_spends_and_pays_a_fee_applies() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([11; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(1_000), 0, false))]);

    let tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    let reward = params.block_subsidy(1).checked_add(amount(100)).unwrap();
    let cb = coinbase(1, reward, b"n");
    let block = block_with(vec![cb.clone(), tx.clone()], prev, &params);

    let diff = apply_block(&pre, &block, &ctx).unwrap();
    assert_eq!(diff.spent, vec![(funded, coin(amount(1_000), 0, false))]);
    assert_eq!(diff.created.len(), 2);
    assert_eq!(diff.created[0].0, out_point(&cb, 0), "the coinbase's outputs come first");
    assert_eq!(diff.created[1].0, out_point(&tx, 0));
}

#[test]
fn a_coinbase_may_claim_less_than_it_is_owed() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let cb = coinbase(1, amount(1), b"n");
    let block = block_with(vec![cb], prev, &params);
    assert!(apply_block(&EmptyView, &block, &ctx).is_ok(), "under-claiming burns the rest");
}

#[test]
fn a_transaction_may_spend_an_output_created_earlier_in_the_same_block() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([12; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(1_000), 0, false))]);

    let first = spend(&[funded], &[(amount(900), any_spend_script())]);
    let second = spend(&[out_point(&first, 0)], &[(amount(800), any_spend_script())]);
    let reward = params.block_subsidy(1).checked_add(amount(200)).unwrap();
    let block = block_with(vec![coinbase(1, reward, b"n"), first, second], prev, &params);

    let diff = apply_block(&pre, &block, &ctx).unwrap();
    assert_eq!(diff.spent.len(), 2, "both spends are recorded, in input order");
}

#[test]
fn a_transaction_may_not_spend_an_output_created_later_in_the_same_block() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([13; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(1_000), 0, false))]);

    let producer = spend(&[funded], &[(amount(900), any_spend_script())]);
    let consumer = spend(&[out_point(&producer, 0)], &[(amount(800), any_spend_script())]);
    // Deliberately the wrong way round: the consumer comes first.
    let reward = params.block_subsidy(1).checked_add(amount(200)).unwrap();
    let block =
        block_with(vec![coinbase(1, reward, b"n"), consumer.clone(), producer], prev, &params);

    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::MissingInput { tx_index: 1, out_point: consumer.inputs[0].prev_out })
    );
}

// ------------------------------------------------------- context-free rules

#[test]
fn an_oversized_block_is_rejected_by_the_seam() {
    let params = devnet_with(|p| p.max_block_size = 10);
    let (_, prev, mut ctx) = scene(&params);
    ctx.params = params.clone();
    let block = block_with(vec![coinbase(1, amount(1), b"n")], prev, &params);
    assert!(matches!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::BlockTooLarge { .. })
    ));
}

#[test]
fn a_merkle_root_mismatch_is_rejected_by_the_seam() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let mut block = block_with(vec![coinbase(1, amount(1), b"n")], prev, &params);
    block.header.merkle_root = Hash32::from_bytes([1; 32]);
    assert!(matches!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::MerkleRootMismatch { .. })
    ));
}

#[test]
fn a_duplicate_txid_inside_a_block_is_rejected_by_the_seam() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([14; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(1_000), 0, false))]);
    let tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    let block =
        block_with(vec![coinbase(1, amount(1), b"n"), tx.clone(), tx.clone()], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::DuplicateTransaction { txid: txid(&tx) })
    );
}

// ------------------------------------------------------------ header rules

#[test]
fn a_block_naming_the_wrong_parent_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let wrong = BlockHash(Hash32::from_bytes([0xab; 32]));
    let block = block_with(vec![coinbase(1, amount(1), b"n")], wrong, &params);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::Header(ConsensusError::WrongParent { expected: prev, actual: wrong }))
    );
}

#[test]
fn a_version_zero_block_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let mut block = block_with(vec![coinbase(1, amount(1), b"n")], prev, &params);
    block.header.version = 0;
    let block = reseal(block);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::Header(ConsensusError::BadVersion(0)))
    );
}

#[test]
fn a_timestamp_at_the_median_time_past_is_rejected() {
    let params = devnet();
    let (parent, prev, _) = scene(&params);
    let ctx = ctx_at(1, &parent, MTP_S, &params);
    let mut block = block_with(vec![coinbase(1, amount(1), b"n")], prev, &params);
    block.header.timestamp_ms = MTP_S * 1_000;
    let block = reseal(block);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::Header(ConsensusError::TimestampTooOld {
            timestamp_ms: MTP_S * 1_000,
            median_time_past_ms: MTP_S * 1_000,
        })),
        "equality is rejected, or a miner could freeze the clock"
    );
}

#[test]
fn a_timestamp_below_the_median_time_past_is_rejected() {
    let params = devnet();
    let (parent, prev, _) = scene(&params);
    let ctx = ctx_at(1, &parent, MTP_S, &params);
    let mut block = block_with(vec![coinbase(1, amount(1), b"n")], prev, &params);
    block.header.timestamp_ms = 1;
    let block = reseal(block);
    assert!(matches!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::Header(ConsensusError::TimestampTooOld { .. }))
    ));
}

#[test]
fn a_header_that_does_not_meet_its_target_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let block = break_pow(block_with(vec![coinbase(1, amount(1), b"n")], prev, &params), &params);
    assert!(matches!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::Header(ConsensusError::InsufficientWork { .. }))
    ));
}

#[test]
fn a_target_easier_than_the_pow_limit_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    // Exponent 0x21 with mantissa 0x00ffff expands to nearly 2^256, far above
    // devnet's already generous limit.
    let block =
        block_of(vec![coinbase(1, amount(1), b"n")], prev, BLOCK_MS, CompactTarget(0x2100_ffff));
    assert!(matches!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::Header(ConsensusError::TargetAbovePowLimit { .. }))
    ));
}

#[test]
fn a_negative_compact_target_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let mut block = block_with(vec![coinbase(1, amount(1), b"n")], prev, &params);
    block.header.bits = CompactTarget(0x2080_0000);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::Header(ConsensusError::NegativeTarget(0x2080_0000)))
    );
}

// -------------------------------------------------------------- seal rules

#[test]
fn a_seal_naming_the_wrong_engine_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let mut block = block_with(vec![coinbase(1, amount(1), b"n")], prev, &params);
    block.seal = BlockSeal { engine: BlockSeal::ENGINE_BFT, data: Vec::new() };
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::Seal(ConsensusError::WrongEngine {
            expected: BlockSeal::ENGINE_POW,
            actual: BlockSeal::ENGINE_BFT,
        }))
    );
}

#[test]
fn a_proof_of_work_seal_carrying_a_payload_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let mut block = block_with(vec![coinbase(1, amount(1), b"n")], prev, &params);
    block.seal = BlockSeal { engine: BlockSeal::ENGINE_POW, data: vec![1, 2, 3] };
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::Seal(ConsensusError::NonEmptyPowSeal(3)))
    );
}

// ----------------------------------------------------------------- genesis

#[test]
fn genesis_is_exempt_from_proof_of_work_and_the_median_time() {
    let params = devnet();
    let ctx = BlockCtx::new(0, BlockHeader::default(), u64::MAX, params.clone());
    let mut block = genesis_block(&params);
    // A nonce that does not meet the target, and a timestamp far below the
    // (impossible) median: genesis is judged on neither.
    block.header.nonce = 0xdead_beef;
    let diff = apply_block(&EmptyView, &block, &ctx).unwrap();
    assert_eq!(diff.created.len(), 1);
}

#[test]
fn a_genesis_block_with_a_parent_is_rejected() {
    let params = devnet();
    let ctx = BlockCtx::new(0, BlockHeader::default(), 0, params.clone());
    let mut block = genesis_block(&params);
    block.header.prev_hash = BlockHash(Hash32::from_bytes([1; 32]));
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::Header(ConsensusError::WrongParent {
            expected: BlockHash::ZERO,
            actual: BlockHash(Hash32::from_bytes([1; 32])),
        }))
    );
}

#[test]
fn the_genesis_coinbase_must_still_commit_to_height_zero() {
    let params = devnet();
    let ctx = BlockCtx::new(0, BlockHeader::default(), 0, params.clone());
    let mut block = genesis_block(&params);
    block.txs[0] = coinbase(1, amount(1), b"wrong height");
    let block = reseal(block);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::CoinbaseHeightMismatch { expected: 0, found: vec![0x01] })
    );
}

// --------------------------------------------------------------- structure

#[test]
fn the_seam_has_no_opinion_about_a_block_from_the_future() {
    // The two-hour future-time bound is the only clock-dependent rule and it
    // lives in the node. Re-validating a historical block must never depend on
    // when you re-validate it, so the seam accepts any timestamp above the
    // median.
    let params = devnet();
    let (parent, prev, ctx) = scene(&params);
    let mut block = block_with(vec![coinbase(1, amount(1), b"n")], prev, &params);
    block.header.timestamp_ms = u64::MAX / 2;
    let block = reseal(block);
    assert!(apply_block(&EmptyView, &block, &ctx).is_ok());
    assert_eq!(header_hash(&parent), prev);
}

#[test]
fn the_diff_records_spends_in_input_order() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let a = OutPoint::new(Txid(Hash32::from_bytes([0xf0; 32])), 0);
    let b = OutPoint::new(Txid(Hash32::from_bytes([0x0f; 32])), 0);
    let pre = map_view(&[(a, coin(amount(500), 0, false)), (b, coin(amount(500), 0, false))]);
    // `a` sorts after `b`, so an accidental sort would swap them.
    let tx = spend(&[a, b], &[(amount(900), any_spend_script())]);
    let reward = params.block_subsidy(1).checked_add(amount(100)).unwrap();
    let block = block_with(vec![coinbase(1, reward, b"n"), tx], prev, &params);
    let diff = apply_block(&pre, &block, &ctx).unwrap();
    assert_eq!(diff.spent[0].0, a);
    assert_eq!(diff.spent[1].0, b);
}

#[test]
fn a_state_view_failure_is_not_a_consensus_verdict() {
    let e = ValidationError::View { detail: "disk on fire".to_owned() };
    assert!(e.is_transient());
    assert!(!ValidationError::EmptyBlock.is_transient());
    assert!(
        ValidationError::MissingInput { tx_index: 1, out_point: OutPoint::NULL }.is_missing_input()
    );
}

#[test]
fn an_empty_pre_state_reads_as_missing_everywhere() {
    let empty = MapView::new();
    assert!(!empty.has_coin(&OutPoint::NULL).unwrap());
    let cb = coinbase(1, amount(1), b"n");
    assert!(!cb.outputs.is_empty());
    assert_eq!(TxIn::coinbase(Script::new(vec![0, 0])).prev_out, OutPoint::NULL);
    assert_eq!(TxOut::new(amount(1), any_spend_script()).value, amount(1));
}
