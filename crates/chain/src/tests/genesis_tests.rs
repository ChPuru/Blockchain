//! SPEC §2: genesis is computed, never trusted.

use ferrum_crypto::merkle_leaf;
use ferrum_script::{ExecCtx, ScriptLimits, verify};
use ferrum_storage::{EmptyView, header_hash, txid};
use ferrum_types::{Amount, BlockHash, BlockSeal, ChainParams, Network, Script, Transaction};

use crate::apply::apply_block;
use crate::ctx::BlockCtx;
use crate::genesis::{
    GENESIS_MESSAGE_PREFIX, GENESIS_VERSION, genesis_block, genesis_coinbase, genesis_commitment,
    genesis_hash, genesis_header, genesis_message, genesis_script_pubkey,
};
use crate::tests::support::devnet_with;
use crate::validate::{
    COINBASE_SCRIPT_SIG_MAX, COINBASE_SCRIPT_SIG_MIN, check_block_sanity,
    check_coinbase_script_sig, compute_merkle_root,
};

fn all_networks() -> [ChainParams; 3] {
    [ChainParams::mainnet(), ChainParams::testnet(), ChainParams::devnet()]
}

#[test]
fn the_genesis_header_has_the_shape_the_spec_gives() {
    for params in all_networks() {
        let h = genesis_header(&params);
        assert_eq!(h.version, GENESIS_VERSION);
        assert_eq!(h.prev_hash, BlockHash::ZERO);
        assert_eq!(h.timestamp_ms, params.genesis_timestamp_ms);
        assert_eq!(h.bits, params.genesis_bits);
        assert_eq!(h.nonce, params.genesis_nonce);
    }
}

#[test]
fn the_genesis_merkle_root_is_the_coinbase_leaf() {
    let params = ChainParams::devnet();
    let cb = genesis_coinbase(&params);
    assert_eq!(genesis_header(&params).merkle_root, merkle_leaf(txid(&cb).as_bytes()));
}

#[test]
fn the_genesis_block_carries_one_coinbase_and_a_proof_of_work_seal() {
    let block = genesis_block(&ChainParams::devnet());
    assert_eq!(block.txs.len(), 1);
    assert!(block.txs[0].is_coinbase());
    assert_eq!(block.seal, BlockSeal::POW);
    assert_eq!(block.coinbase(), Some(&block.txs[0]));
}

#[test]
fn the_genesis_coinbase_commits_to_height_zero() {
    for params in all_networks() {
        let cb = genesis_coinbase(&params);
        let sig = &cb.inputs[0].script_sig;
        assert!(sig.len() >= COINBASE_SCRIPT_SIG_MIN);
        assert!(sig.len() <= COINBASE_SCRIPT_SIG_MAX);
        assert_eq!(check_coinbase_script_sig(sig, 0), Ok(()));
    }
}

#[test]
fn the_genesis_message_names_the_network() {
    assert_eq!(
        genesis_message(&ChainParams::mainnet()),
        format!("{GENESIS_MESSAGE_PREFIX} mainnet")
    );
    assert_eq!(genesis_message(&ChainParams::devnet()), format!("{GENESIS_MESSAGE_PREFIX} devnet"));
    let cb = genesis_coinbase(&ChainParams::devnet());
    let sig = cb.inputs[0].script_sig.as_bytes().to_vec();
    let text = String::from_utf8_lossy(&sig);
    assert!(text.contains("devnet"), "{text}");
}

#[test]
fn the_genesis_output_is_provably_unspendable() {
    let params = ChainParams::devnet();
    let cb = genesis_coinbase(&params);
    let script = &cb.outputs[0].script_pubkey;
    assert_eq!(script.as_bytes()[0], 0x6a, "OP_RETURN");

    // Nothing satisfies it, so the genesis subsidy can never move.
    let spender = Transaction::empty();
    let ctx = ExecCtx {
        chain_id: params.chain_id,
        tx: &spender,
        input_index: 0,
        input_value: cb.outputs[0].value,
        block_height: 1,
        block_mtp_s: 0,
        limits: ScriptLimits::CONSENSUS,
    };
    assert!(verify(&Script::EMPTY, script, &ctx).is_err());
}

#[test]
fn the_genesis_output_claims_exactly_the_first_subsidy() {
    for params in all_networks() {
        let cb = genesis_coinbase(&params);
        assert_eq!(cb.outputs[0].value, params.block_subsidy(0));
        assert_eq!(cb.outputs[0].value, Amount::from_grains(5_000_000_000));
    }
}

#[test]
fn each_network_has_its_own_genesis_hash() {
    let m = genesis_hash(&ChainParams::mainnet());
    let t = genesis_hash(&ChainParams::testnet());
    let d = genesis_hash(&ChainParams::devnet());
    assert_ne!(m, t, "mainnet and testnet differ only in identity, so genesis must carry it");
    assert_ne!(m, d);
    assert_ne!(t, d);
}

#[test]
fn the_commitment_moves_when_any_consensus_parameter_moves() {
    let base = ChainParams::devnet();
    let baseline = genesis_commitment(&base);
    let mutations: [fn(&mut ChainParams); 6] = [
        |p| p.halving_interval = 1,
        |p| p.coinbase_maturity = 7,
        |p| p.max_block_size = 2_000_000,
        |p| p.target_spacing_ms = 60_000,
        |p| p.asert_halflife_s = 60,
        |p| p.genesis_nonce = 1,
    ];
    for mutate in mutations {
        let changed = devnet_with(mutate);
        assert_ne!(genesis_commitment(&changed), baseline);
        assert_ne!(genesis_hash(&changed), genesis_hash(&base));
    }
}

#[test]
fn genesis_is_deterministic() {
    let params = ChainParams::devnet();
    assert_eq!(genesis_block(&params), genesis_block(&params));
    assert_eq!(genesis_hash(&params), header_hash(&genesis_block(&params).header));
    assert_eq!(genesis_script_pubkey(&params), genesis_script_pubkey(&ChainParams::devnet()));
}

#[test]
fn the_genesis_block_passes_context_free_sanity() {
    for params in all_networks() {
        assert_eq!(check_block_sanity(&genesis_block(&params), &params), Ok(()));
        assert_eq!(
            compute_merkle_root(&genesis_block(&params).txs),
            genesis_header(&params).merkle_root
        );
    }
}

#[test]
fn applying_genesis_creates_exactly_one_unspendable_coin() {
    for params in all_networks() {
        let block = genesis_block(&params);
        let ctx = BlockCtx::new(0, genesis_header(&params), 0, params.clone());
        let diff = apply_block(&EmptyView, &block, &ctx).unwrap();
        assert!(diff.spent.is_empty());
        assert_eq!(diff.created.len(), 1);
        assert!(diff.created[0].1.is_coinbase);
        assert_eq!(diff.created[0].1.height, 0);
    }
}

#[test]
fn a_network_name_round_trips_through_its_parameters() {
    for network in Network::ALL {
        let params = network.params();
        assert!(genesis_message(&params).ends_with(network.name()));
    }
}
