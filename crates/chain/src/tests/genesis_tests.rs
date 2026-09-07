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
        // Mutate a clone of the shipped set rather than going through
        // `tests::support::devnet_with`, which also relaxes `pow_limit` and
        // `genesis_bits`: this test must fail when a mutation does nothing, and
        // it cannot do that if the helper has already moved the commitment.
        let mut changed = base.clone();
        mutate(&mut changed);
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

/// The genesis hashes and merkle roots published in `README.md` and
/// `docs/RUNNING.md` §4.
///
/// Those documents tell an operator to compare their node's computed genesis
/// against these values before believing they are on the network they think
/// they are on. A parameter change that moves a hash and leaves the documents
/// behind turns that instruction into a lie, and nothing else in the tree
/// catches it — so this test is the tripwire. If it fails, either the change
/// was not intended or the two documents need the new value.
///
/// **Mainnet and testnet are frozen.** Their networks are published; a change
/// to either line here is a change to a live chain, not a test fixture. Devnet
/// moves whenever its parameters move, which is the point of
/// `genesis_commitment`.
#[test]
fn the_published_genesis_hashes_are_these() {
    let expected = [
        (
            ChainParams::mainnet(),
            "6bfa4fee9e522a6071b5d7d04fc400144d9f519ba95b78d37346f7c597c4436c",
            "9967df4f7957e4bb8b629dc5cbe60411c3ec4058f88a3136e832805ddd409405",
        ),
        (
            ChainParams::testnet(),
            "9edeafc16709d76a957c0b11587881cb0161dd19069fc25025fbdc4b4ff6e516",
            "c63d0a3f08a4dd8d451c70ab01ab5f9fccb8e9b44fdb538a6a1cf56e1f6e8650",
        ),
        (
            ChainParams::devnet(),
            "9167643790fc744081aa3656d33a4e02fc122b729198716563b2ee60db428444",
            "8fedad9c3ec385af18086c5cb8596f6aa7c017886c40289688a311eacd40030a",
        ),
    ];
    for (params, hash, merkle) in expected {
        assert_eq!(
            genesis_hash(&params).to_hex(),
            hash,
            "{} genesis hash moved; update README.md and docs/RUNNING.md §4",
            params.network
        );
        assert_eq!(
            genesis_header(&params).merkle_root.to_hex(),
            merkle,
            "{} genesis merkle root moved; update docs/RUNNING.md §4",
            params.network
        );
    }
}
