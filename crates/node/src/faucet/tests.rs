#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;

use ferrum_chain::ChainManager;
use ferrum_consensus::EngineRouter;
use ferrum_mempool::{Mempool, MempoolConfig};
use ferrum_rpc::{ChainHandle, ChainProvider, RpcErrorCode};
use ferrum_storage::{Store, StoreConfig};
use ferrum_types::{ChainParams, Network};
use ferrum_wallet::dust_threshold;

use super::*;
use crate::miner::{Miner, resolve_payout};
use crate::node::keys::NodeKey;
use crate::relay::{Clock, FixedClock, Relay};
use crate::telemetry::NodeMetrics;

/// The node key every test here mines and pays from.
fn node_key() -> NodeKey {
    NodeKey::from_seed([42u8; 32])
}

/// A devnet chain with `blocks` mined to the node key's address.
///
/// Devnet's proof-of-work limit is trivial, so these seal in microseconds and
/// the tests mine for real rather than faking a seal.
fn chain_with(blocks: u64) -> (Arc<ChainManager>, Arc<dyn ChainProvider>) {
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
    let payout = resolve_payout(None, &node_key(), Network::Devnet).unwrap();
    let miner = Miner::new(Arc::clone(&relay), payout);
    let flag = std::sync::atomic::AtomicBool::new(false);
    let mut now = params.genesis_timestamp_ms + 120_000;
    for _ in 0..blocks {
        now += params.target_spacing_ms;
        clock.set(now);
        miner.mine_and_submit(&flag).unwrap().expect("devnet seals immediately");
    }
    let provider: Arc<dyn ChainProvider> = Arc::new(ChainHandle::new(Arc::clone(&chain), false));
    (chain, provider)
}

fn source(chain: Arc<dyn ChainProvider>) -> NodeKeyFaucetSource {
    let params = ChainParams::devnet();
    let key = node_key();
    NodeKeyFaucetSource::new(
        key.mining_secret().unwrap(),
        key.mining_address(Network::Devnet).unwrap(),
        chain,
        params.chain_id,
        dust_threshold(params.min_relay_fee_per_kb),
        params.coinbase_maturity,
        ferrum_rpc::DEFAULT_FAUCET_FEE_RATE,
    )
}

fn recipient() -> Address {
    NodeKey::from_seed([7u8; 32]).mining_address(Network::Devnet).unwrap()
}

#[test]
fn the_faucet_pays_from_the_node_key_address() {
    let (_, provider) = chain_with(1);
    let src = source(provider);
    assert_eq!(*src.address(), node_key().mining_address(Network::Devnet).unwrap());
}

#[test]
fn an_empty_chain_is_drained_not_a_crash() {
    let (_, provider) = chain_with(0);
    let src = source(provider);
    let err = src.build_payment(&recipient(), Amount::from_grains(100_000_000)).unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::FaucetDrained);
}

#[test]
fn immature_coinbases_are_drained_rather_than_spent() {
    // Ten blocks on a hundred-block maturity window: the key holds ten
    // coinbases and not one of them is spendable. Building anyway would make a
    // transaction the mempool rejects, which is a worse answer than "empty".
    let (_, provider) = chain_with(10);
    let src = source(provider);
    let err = src.build_payment(&recipient(), Amount::from_grains(100_000_000)).unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::FaucetDrained);
    assert!(err.to_string().contains("mature"), "the message names the reason: {err}");
}

#[test]
fn the_maturity_boundary_matches_consensus() {
    let coin = Coin {
        value: Amount::from_grains(1),
        script_pubkey: Script::new(vec![0x51]),
        height: 10,
        is_coinbase: true,
    };
    // Consensus lets a coinbase be spent in the block at `height + maturity`,
    // and the faucet's payment lands in the block after the tip.
    assert!(!NodeKeyFaucetSource::is_spendable(&coin, 108, 100));
    assert!(NodeKeyFaucetSource::is_spendable(&coin, 109, 100), "spent in block 110 = 10 + 100");
    assert!(NodeKeyFaucetSource::is_spendable(&coin, 110, 100));

    let ordinary = Coin { is_coinbase: false, ..coin };
    assert!(NodeKeyFaucetSource::is_spendable(&ordinary, 0, 100), "only coinbases mature");
}

#[test]
fn a_matured_chain_builds_a_signed_payment() {
    let params = ChainParams::devnet();
    let (_, provider) = chain_with(params.coinbase_maturity + 2);
    let src = source(Arc::clone(&provider));
    let to = recipient();
    let amount = Amount::from_grains(100_000_000);

    let tx = src.build_payment(&to, amount).unwrap();
    assert!(!tx.is_coinbase());
    assert!(!tx.inputs.is_empty());

    // It pays the requested amount to the requested address.
    let paid = tx
        .outputs
        .iter()
        .filter(|o| o.script_pubkey == to.script_pubkey())
        .map(|o| o.value.to_grains())
        .sum::<u64>();
    assert_eq!(paid, amount.to_grains());

    // Change, when there is any, comes back to the faucet rather than leaking
    // to the miner as fee.
    let change =
        tx.outputs.iter().filter(|o| o.script_pubkey == src.address().script_pubkey()).count();
    assert!(change <= 1);

    // Every input is signed and verifies through the real interpreter against
    // the coins it spends — signing is not merely "did not error".
    let prevouts: Vec<Coin> = tx
        .inputs
        .iter()
        .map(|i| provider.coin(&i.prev_out).unwrap().expect("input is unspent"))
        .collect();
    ferrum_wallet::verify_signed(&tx, &prevouts, params.chain_id).unwrap();
    assert!(tx.inputs.iter().all(|i| !i.script_sig.is_empty()));
}

#[test]
fn a_payment_signed_for_devnet_does_not_verify_on_mainnet() {
    // The sighash commits to the chain id (CONTRACT §5.5), so a faucet
    // transaction cannot be replayed onto another network.
    let params = ChainParams::devnet();
    let (_, provider) = chain_with(params.coinbase_maturity + 2);
    let src = source(Arc::clone(&provider));
    let tx = src.build_payment(&recipient(), Amount::from_grains(100_000_000)).unwrap();
    let prevouts: Vec<Coin> =
        tx.inputs.iter().map(|i| provider.coin(&i.prev_out).unwrap().unwrap()).collect();
    assert!(ferrum_wallet::verify_signed(&tx, &prevouts, ChainParams::mainnet().chain_id).is_err());
}

#[test]
fn a_request_beyond_the_balance_is_drained_not_a_short_payment() {
    let params = ChainParams::devnet();
    let (_, provider) = chain_with(params.coinbase_maturity + 1);
    let src = source(provider);
    // One mature coinbase is 50 FRM; ask for far more.
    let err = src
        .build_payment(&recipient(), Amount::from_grains(1_000_000 * ferrum_types::COIN))
        .unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::FaucetDrained);
}

#[test]
fn an_address_from_another_network_is_refused() {
    let params = ChainParams::devnet();
    let (_, provider) = chain_with(params.coinbase_maturity + 2);
    let src = source(provider);
    let mainnet_address = NodeKey::from_seed([7u8; 32]).mining_address(Network::Mainnet).unwrap();
    let err = src.build_payment(&mainnet_address, Amount::from_grains(100_000_000)).unwrap_err();
    assert_eq!(err.code(), RpcErrorCode::InvalidAddress);
}

#[test]
fn debug_never_prints_key_material() {
    let (_, provider) = chain_with(0);
    let src = source(provider);
    let rendered = format!("{src:?}");
    let secret = hex::encode(node_key().mining_secret().unwrap().to_bytes());
    assert!(!rendered.contains(&secret), "the secret key leaked into Debug: {rendered}");
    assert!(rendered.contains(&src.address().encode()));
}
