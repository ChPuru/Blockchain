//! Every JSON-RPC method, against the in-memory chain fixture.
//!
//! The synchronous handler functions are called directly where that is enough,
//! and through the async `FerrumRpcServer` implementation where the point is
//! the wiring — the `spawn_blocking` hop, the optional-parameter defaults and
//! the JSON shape.

use std::sync::Arc;

use ferrum_storage::txid;
use ferrum_types::{Amount, Transaction};

use crate::api::FerrumRpcServer;
use crate::error::RpcErrorCode;
use crate::handlers::{FerrumRpcImpl, chain, mining, tx};
use crate::provider::MempoolProvider;
use crate::tests::fixture::{Fixture, StubMempool, address};
use crate::types::rpc::{BlockTxList, GetBlockResult, GetRawTransactionResult, RawMempoolResult};

fn server(f: &Fixture) -> FerrumRpcImpl {
    FerrumRpcImpl::new(f.context())
}

// ------------------------------------------------------------ chain metadata

#[tokio::test]
async fn getblockchaininfo_reports_the_tip() {
    let f = Fixture::build(3, false);
    let info = server(&f).get_blockchain_info().await.unwrap();
    assert_eq!(info.chain, "devnet");
    assert_eq!(info.height, 3);
    assert_eq!(info.best_hash, f.tip_hash().to_hex());
    assert_eq!(info.engine, "pow");
    assert_eq!(info.chain_id, 3);
    assert!(info.index_enabled);
    // Genesis's single unspendable output plus one coinbase per block.
    assert_eq!(info.utxo_count, 4);
}

#[tokio::test]
async fn proof_of_work_never_reports_finality() {
    let f = Fixture::build(2, false);
    let info = server(&f).get_blockchain_info().await.unwrap();
    assert_eq!(info.finalized_height, None, "nothing is ever final under PoW");
}

#[tokio::test]
async fn difficulty_is_a_string_with_three_places() {
    let f = Fixture::build(1, false);
    let info = server(&f).get_blockchain_info().await.unwrap();
    let (whole, fraction) = info.difficulty.split_once('.').expect("a decimal point");
    assert!(whole.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(fraction.len(), 3, "difficulty is {}", info.difficulty);
}

#[tokio::test]
async fn getblockhash_walks_the_active_chain() {
    let f = Fixture::build(3, false);
    for (offset, expected) in f.blocks.iter().enumerate() {
        let height = u64::try_from(offset).unwrap() + 1;
        let hash = server(&f).get_block_hash(height).await.unwrap();
        assert_eq!(hash, expected.to_hex());
    }
}

#[tokio::test]
async fn getblockhash_past_the_tip_is_height_out_of_range() {
    let f = Fixture::build(1, false);
    let err = server(&f).get_block_hash(99).await.unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::HeightOutOfRange.code());
}

// --------------------------------------------------------------------- blocks

#[tokio::test]
async fn getblock_verbosity_zero_round_trips_through_borsh() {
    let f = Fixture::build(1, false);
    let hash = f.blocks[0];
    let result = server(&f).get_block(hash.to_hex(), Some(0)).await.unwrap();
    let GetBlockResult::Hex(hex_str) = result else {
        panic!("verbosity 0 must return hex");
    };
    let decoded = chain::decode_block_hex(&hex_str).unwrap();
    assert_eq!(ferrum_storage::header_hash(&decoded.header), hash);
}

#[tokio::test]
async fn getblock_defaults_to_transaction_ids() {
    let f = Fixture::build(1, false);
    let result = server(&f).get_block(f.blocks[0].to_hex(), None).await.unwrap();
    let GetBlockResult::Verbose(block) = result else {
        panic!("the default verbosity must be verbose");
    };
    assert_eq!(block.height, 1);
    assert_eq!(block.tx_count, 1);
    assert!(matches!(block.txs, BlockTxList::Ids(_)));
    assert_eq!(block.engine, "pow");
    assert_eq!(block.seal, "", "a proof-of-work seal is empty");
}

#[tokio::test]
async fn getblock_verbosity_two_decodes_transactions() {
    let f = Fixture::build(1, false);
    let result = server(&f).get_block(f.blocks[0].to_hex(), Some(2)).await.unwrap();
    let GetBlockResult::Verbose(block) = result else { panic!("expected an object") };
    let BlockTxList::Full(txs) = block.txs else { panic!("expected decoded transactions") };
    assert_eq!(txs.len(), 1);
    assert!(txs[0].coinbase);
    assert_eq!(txs[0].vin.len(), 1);
    assert!(txs[0].vin[0].coinbase);
    assert_eq!(txs[0].confirmations, Some(1));
}

#[tokio::test]
async fn getblock_links_forward_and_counts_confirmations() {
    let f = Fixture::build(3, false);
    let result = server(&f).get_block(f.blocks[0].to_hex(), Some(1)).await.unwrap();
    let GetBlockResult::Verbose(block) = result else { panic!("expected an object") };
    assert_eq!(block.confirmations, 3);
    assert_eq!(block.next_hash, Some(f.blocks[1].to_hex()));

    let tip = server(&f).get_block(f.tip_hash().to_hex(), Some(1)).await.unwrap();
    let GetBlockResult::Verbose(tip) = tip else { panic!("expected an object") };
    assert_eq!(tip.confirmations, 1);
    assert_eq!(tip.next_hash, None);
}

#[tokio::test]
async fn getblock_with_an_unknown_hash_is_not_found() {
    let f = Fixture::build(1, false);
    let err = server(&f).get_block("11".repeat(32), Some(1)).await.unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::NotFound.code());
}

#[tokio::test]
async fn getblock_with_a_malformed_hash_is_invalid_hash() {
    let f = Fixture::build(1, false);
    let err = server(&f).get_block("zzz".to_owned(), Some(1)).await.unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::InvalidHash.code());
}

#[tokio::test]
async fn getblockheader_carries_target_work_and_engine() {
    let f = Fixture::build(2, false);
    let header = server(&f).get_block_header(f.blocks[0].to_hex()).await.unwrap();
    assert_eq!(header.height, 1);
    assert_eq!(header.target.len(), 64);
    assert_eq!(header.total_work.len(), 64);
    assert_eq!(header.engine, "pow");
    assert_eq!(header.confirmations, 2);
    assert_eq!(header.hash, f.blocks[0].to_hex());
}

#[tokio::test]
async fn a_header_serialises_its_nonce_as_a_string() {
    let f = Fixture::build(1, false);
    let header = server(&f).get_block_header(f.blocks[0].to_hex()).await.unwrap();
    let json = serde_json::to_value(&header).unwrap();
    assert!(json["nonce"].is_string(), "a u64 nonce would round as a JSON number");
    assert!(json["bits"].is_number(), "the explorer bit-shifts `bits`");
}

// --------------------------------------------------------------- transactions

#[tokio::test]
async fn getrawtransaction_returns_a_decodable_envelope() {
    let f = Fixture::build(2, true);
    let id = f.spend_txid.unwrap();
    let result = server(&f).get_raw_transaction(id.to_hex(), None).await.unwrap();
    let GetRawTransactionResult::Hex(hex_str) = result else { panic!("expected hex") };
    let decoded = tx::decode_tx_hex(&hex_str).unwrap();
    assert_eq!(txid(&decoded), id);
}

#[tokio::test]
async fn getrawtransaction_verbose_reports_where_it_confirmed() {
    let f = Fixture::build(2, true);
    let id = f.spend_txid.unwrap();
    let result = server(&f).get_raw_transaction(id.to_hex(), Some(true)).await.unwrap();
    let GetRawTransactionResult::Verbose(json) = result else { panic!("expected an object") };
    assert_eq!(json.txid, id.to_hex());
    assert!(!json.coinbase);
    assert_eq!(json.height, Some(3));
    assert_eq!(json.confirmations, Some(1));
    assert_eq!(json.vin.len(), 1);
    assert_eq!(json.vout.len(), 1);
    assert_eq!(json.vout[0].script_type, "p2pkh");
    assert_eq!(json.vout[0].address, Some(f.recipient.encode()));
}

#[tokio::test]
async fn getrawtransaction_finds_a_mempool_entry_before_the_index() {
    let f = Fixture::build(1, false);
    let pending = Transaction::empty();
    let id = f.mempool.insert(pending, Amount::from_grains(500), 1);
    let result = server(&f).get_raw_transaction(id.to_hex(), Some(true)).await.unwrap();
    let GetRawTransactionResult::Verbose(json) = result else { panic!("expected an object") };
    assert_eq!(json.block_hash, None, "a mempool entry has no block");
    assert_eq!(json.confirmations, None);
}

#[tokio::test]
async fn getrawtransaction_for_an_unknown_id_is_not_found() {
    let f = Fixture::build(1, false);
    let err = server(&f).get_raw_transaction("22".repeat(32), None).await.unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::NotFound.code());
}

#[tokio::test]
async fn getrawtransaction_without_an_index_says_so() {
    let f = Fixture::build_with_index(1, false, false);
    let err = server(&f).get_raw_transaction("33".repeat(32), None).await.unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::IndexDisabled.code());
}

#[tokio::test]
async fn sendrawtransaction_returns_the_txid_and_announces_it() {
    let f = Fixture::build(1, false);
    let raw = hex::encode(Transaction::empty().encode_envelope());
    let id = server(&f).send_raw_transaction(raw).await.unwrap();
    assert_eq!(id, txid(&Transaction::empty()).to_hex());
    assert_eq!(f.mempool.len(), 1);
    assert_eq!(f.network.broadcast_count(), 1, "an accepted transaction is relayed");
}

#[tokio::test]
async fn sendrawtransaction_reports_a_mempool_refusal_as_tx_rejected() {
    let f = Fixture::build(1, false);
    f.mempool.reject_with("fee rate below the relay floor");
    let raw = hex::encode(Transaction::empty().encode_envelope());
    let err = server(&f).send_raw_transaction(raw).await.unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::TxRejected.code());
    assert!(err.message().contains("relay floor"));
}

#[tokio::test]
async fn sendrawtransaction_rejects_malformed_hex_before_the_mempool_sees_it() {
    let f = Fixture::build(1, false);
    let err = server(&f).send_raw_transaction("nothex".to_owned()).await.unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::InvalidHex.code());
    assert_eq!(f.mempool.len(), 0);
}

#[tokio::test]
async fn sendrawtransaction_rejects_well_formed_hex_that_is_not_a_transaction() {
    let f = Fixture::build(1, false);
    let err = server(&f).send_raw_transaction("00ff".to_owned()).await.unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::DecodeFailed.code());
}

// ---------------------------------------------------------------------- coins

#[tokio::test]
async fn gettxout_returns_an_unspent_coinbase_output() {
    let f = Fixture::build(2, false);
    let block = f.block(&f.blocks[0]);
    let coinbase_id = txid(&block.txs[0]);
    let coin = server(&f).get_tx_out(coinbase_id.to_hex(), 0).await.unwrap().unwrap();
    assert!(coin.is_coinbase);
    assert_eq!(coin.height, 1);
    assert_eq!(coin.confirmations, 2);
    assert_eq!(coin.address, Some(f.miner.encode()));
    assert_eq!(coin.value.to_grains(), 50 * ferrum_types::COIN);
}

#[tokio::test]
async fn gettxout_returns_null_for_a_spent_output() {
    let f = Fixture::build(2, true);
    let block = f.block(&f.blocks[0]);
    let coinbase_id = txid(&block.txs[0]);
    let coin = server(&f).get_tx_out(coinbase_id.to_hex(), 0).await.unwrap();
    assert!(coin.is_none(), "the fixture's spend consumed this output");
}

#[tokio::test]
async fn gettxout_amounts_are_json_strings() {
    let f = Fixture::build(1, false);
    let block = f.block(&f.blocks[0]);
    let id = txid(&block.txs[0]);
    let coin = server(&f).get_tx_out(id.to_hex(), 0).await.unwrap().unwrap();
    let json = serde_json::to_value(&coin).unwrap();
    assert_eq!(json["value"], serde_json::json!("5000000000"));
}

// -------------------------------------------------------------------- mempool

#[tokio::test]
async fn getmempoolinfo_reports_size_bytes_and_the_floor() {
    let f = Fixture::build(1, false);
    f.mempool.insert(Transaction::empty(), Amount::from_grains(7), 1);
    let info = server(&f).get_mempool_info().await.unwrap();
    assert_eq!(info.size, 1);
    assert!(info.bytes > 0);
    assert_eq!(info.min_fee_rate, 1_000);
    assert_eq!(info.max_bytes, 8 * 1024 * 1024);
}

#[tokio::test]
async fn getrawmempool_lists_ids_by_default_and_entries_when_verbose() {
    let f = Fixture::build(1, false);
    let id = f.mempool.insert(Transaction::empty(), Amount::from_grains(7), 4);
    let RawMempoolResult::Ids(ids) = server(&f).get_raw_mempool(None).await.unwrap() else {
        panic!("the default must be a list of ids");
    };
    assert_eq!(ids, vec![id.to_hex()]);

    let RawMempoolResult::Verbose(map) = server(&f).get_raw_mempool(Some(true)).await.unwrap()
    else {
        panic!("verbose must be a map");
    };
    let entry = map.get(&id.to_hex()).unwrap();
    assert_eq!(entry.fee.to_grains(), 7);
    assert_eq!(entry.height, 4);
}

#[tokio::test]
async fn estimatefee_falls_back_to_the_relay_floor() {
    let f = Fixture::build(1, false);
    let fee = server(&f).estimate_fee(6).await.unwrap();
    assert_eq!(fee.to_grains(), 1_000);
    let json = serde_json::to_value(fee).unwrap();
    assert!(json.is_string(), "a fee is an amount, so it is a string");
}

// --------------------------------------------------------------------- mining

#[tokio::test]
async fn getblocktemplate_builds_on_the_tip() {
    let f = Fixture::build(2, false);
    let template = server(&f).get_block_template(f.miner.encode()).await.unwrap();
    assert_eq!(template.height, 3);
    assert_eq!(template.prev_hash, f.tip_hash().to_hex());
    assert_eq!(template.header_hex.len(), ferrum_types::HEADER_SIZE * 2);
    assert_eq!(template.transactions.len(), 1, "an empty mempool means coinbase only");
    assert_eq!(template.coinbase_value.to_grains(), 50 * ferrum_types::COIN);
    assert_eq!(template.total_fees.to_grains(), 0);
    assert_eq!(template.engine, "pow");
}

#[tokio::test]
async fn getblocktemplate_refuses_a_foreign_address() {
    let f = Fixture::build(1, false);
    let (_, public) = crate::tests::fixture::key(9);
    let mainnet = ferrum_crypto::Address::p2pkh(ferrum_types::Network::Mainnet, &public);
    let err = server(&f).get_block_template(mainnet.encode()).await.unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::InvalidAddress.code());
}

#[tokio::test]
async fn a_template_can_be_sealed_and_submitted() {
    let f = Fixture::build(2, false);
    let template = server(&f).get_block_template(f.miner.encode()).await.unwrap();

    // Rebuild the block exactly as a miner would: decode the header, decode
    // every transaction envelope, grind, submit.
    let header_bytes = hex::decode(&template.header_hex).unwrap();
    let header = ferrum_types::BlockHeader::from_bytes(
        &<[u8; ferrum_types::HEADER_SIZE]>::try_from(header_bytes.as_slice()).unwrap(),
    );
    let txs: Vec<Transaction> =
        template.transactions.iter().map(|hexed| tx::decode_tx_hex(hexed).unwrap()).collect();
    let sealed = crate::tests::fixture::seal(header);
    let block = ferrum_types::Block::new(sealed, txs, ferrum_types::BlockSeal::POW);
    let raw = chain::encode_block_hex(&block).unwrap();

    let outcome = server(&f).submit_block(raw).await.unwrap();
    assert!(outcome.accepted, "outcome was {}", outcome.outcome);
    assert_eq!(outcome.outcome, "extended");
    assert_eq!(f.tip_height(), 3);
    assert_eq!(f.network.broadcast_count(), 1, "a connected block is announced");
}

#[tokio::test]
async fn submitblock_reports_a_duplicate_rather_than_failing() {
    let f = Fixture::build(2, false);
    let block = f.block(&f.blocks[1]);
    let raw = chain::encode_block_hex(&block).unwrap();
    let outcome = server(&f).submit_block(raw).await.unwrap();
    assert!(!outcome.accepted);
    assert_eq!(outcome.outcome, "duplicate");
}

#[tokio::test]
async fn submitblock_rejects_a_block_that_breaks_a_rule() {
    let f = Fixture::build(2, false);
    let mut block = f.chain.mine_to(&f.miner.script_pubkey(), Vec::new(), 5);
    // Claim one grain more than the subsidy: SPEC §3.3 rule 13.
    let value = block.txs[0].outputs[0].value;
    block.txs[0].outputs[0].value = value.checked_add(Amount::ONE_GRAIN).unwrap();
    block.header.merkle_root = ferrum_chain::compute_merkle_root(&block.txs);
    block.header.nonce = 0;
    block.header = crate::tests::fixture::seal(block.header);

    let raw = chain::encode_block_hex(&block).unwrap();
    let err = server(&f).submit_block(raw).await.unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::BlockRejected.code());
}

#[tokio::test]
async fn submitblock_rejects_hex_that_is_not_a_block() {
    let f = Fixture::build(1, false);
    let err = server(&f).submit_block("deadbeef".to_owned()).await.unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::DecodeFailed.code());
}

// ---------------------------------------------------------------- state root

#[tokio::test]
async fn getstateroot_returns_the_tip_root() {
    let f = Fixture::build(2, false);
    let root = server(&f).get_state_root(None).await.unwrap();
    assert_eq!(root, f.state_root());
    let at_tip = server(&f).get_state_root(Some(f.tip_height())).await.unwrap();
    assert_eq!(at_tip, root);
}

#[tokio::test]
async fn getstateroot_refuses_a_historical_height() {
    let f = Fixture::build(3, false);
    let err = server(&f).get_state_root(Some(1)).await.unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::StateRootUnavailable.code());
}

#[tokio::test]
async fn the_state_root_changes_when_the_chain_does() {
    let f = Fixture::build(1, false);
    let before = server(&f).get_state_root(None).await.unwrap();
    f.chain.mine_and_connect(&f.miner.script_pubkey(), Vec::new(), 77);
    let after = server(&f).get_state_root(None).await.unwrap();
    assert_ne!(before, after);
}

// -------------------------------------------------------------------- network

#[tokio::test]
async fn getpeerinfo_flattens_the_peer_list() {
    let f = Fixture::build(1, false);
    let peers = server(&f).get_peer_info().await.unwrap();
    assert_eq!(peers.len(), 3);
    assert!(peers[0].is_static);
    assert_eq!(peers[0].last_rtt_ms, Some(12));
}

#[tokio::test]
async fn getnetworkinfo_names_the_chain_and_the_local_peer() {
    let f = Fixture::build(1, false);
    let info = server(&f).get_network_info().await.unwrap();
    assert_eq!(info.chain, "devnet");
    assert_eq!(info.chain_id, 3);
    assert_eq!(info.peer_count, 3);
    assert_eq!(info.local_peer_id, "12D3KooWStubLocal");
}

#[tokio::test]
async fn a_node_without_a_network_still_answers_getpeerinfo() {
    let f = Fixture::build(1, false);
    let ctx =
        crate::context::NodeContext::new(f.provider()).with_mempool(Arc::new(StubMempool::new()));
    let peers = FerrumRpcImpl::new(ctx).get_peer_info().await.unwrap();
    assert!(peers.is_empty());
}

// ------------------------------------------------------------- direct handlers

#[test]
fn a_template_headroom_leaves_room_for_the_coinbase() {
    // The selector is handed less than the block budget so that the coinbase,
    // which is added afterwards, always fits.
    assert_eq!(mining::TEMPLATE_HEADROOM_DIVISOR, 100);
    let params = crate::tests::fixture::params();
    let budget = params.max_block_size - params.max_block_size / 100;
    assert!(budget < params.max_block_size);
    assert!(params.max_block_size - budget > 1_000, "headroom must exceed a coinbase");
}

#[test]
fn the_synchronous_handlers_work_without_a_runtime() {
    // Every handler under `handlers::` is a plain function, which is what makes
    // the `spawn_blocking` boundary a one-line wrapper rather than a rewrite.
    let f = Fixture::build(2, false);
    let chain_provider = f.provider();
    let mempool = StubMempool::new();
    let info = chain::blockchain_info(&*chain_provider, &mempool).unwrap();
    assert_eq!(info.height, 2);
    let hash = chain::block_hash_at(&*chain_provider, 1).unwrap();
    assert_eq!(hash, f.blocks[0].to_hex());
}

#[test]
fn an_unknown_address_has_no_balance_rather_than_an_error() {
    let f = Fixture::build(2, false);
    let chain_provider = f.provider();
    let stranger = address(200);
    let balance = crate::handlers::address::get_balance(
        &*chain_provider,
        &StubMempool::new(),
        &stranger.encode(),
    )
    .unwrap();
    assert_eq!(balance.confirmed.to_grains(), 0);
    assert_eq!(balance.utxo_count, 0);
}

// ------------------------------------------------------------ the whole loop

#[tokio::test]
async fn a_signed_spend_travels_from_sendrawtransaction_to_a_block() {
    // The one test that exercises the path a wallet actually takes: sign a
    // real transaction against a mature coinbase, relay it, see it in the
    // mempool, mine it, and read it back out of the chain.
    let f = Fixture::build(3, false);
    let first = f.block(&f.blocks[0]);
    let prevout = crate::tests::fixture::coinbase_output(&first, 1);
    let value = prevout.1.value.checked_sub(Amount::from_grains(5_000)).unwrap();
    let signed = crate::tests::fixture::spend_p2pkh(
        prevout,
        &f.miner_key,
        &f.recipient.script_pubkey(),
        value,
        f.chain.params.chain_id,
    );
    let expected = txid(&signed);

    let raw = hex::encode(signed.encode_envelope());
    let returned = server(&f).send_raw_transaction(raw).await.unwrap();
    assert_eq!(returned, expected.to_hex());
    assert_eq!(f.mempool.len(), 1);

    // Mine it, and the RPC layer should now find it in the chain rather than
    // in the pool.
    f.chain.mine_and_connect(&f.miner.script_pubkey(), vec![signed], 1_234);
    let confirmed = crate::handlers::lookup::find_transaction(&*f.provider(), &expected)
        .unwrap()
        .expect("the mined transaction is indexed");
    assert_eq!(confirmed.height, 4);
    assert_eq!(confirmed.tx.outputs[0].value, value);
}

#[test]
fn a_bare_test_chain_starts_at_genesis() {
    let chain = crate::tests::fixture::TestChain::new();
    let (hash, height) = chain.tip();
    assert_eq!(height, 0);
    let header = chain.header(&hash);
    assert_eq!(header.prev_hash, ferrum_types::BlockHash::ZERO);
    assert_eq!(header.version, 1);
}
