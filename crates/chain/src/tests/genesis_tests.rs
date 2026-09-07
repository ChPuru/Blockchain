//! SPEC §2: genesis is computed, never trusted.

use ferrum_crypto::merkle_leaf;
use ferrum_script::{ExecCtx, ScriptLimits, verify};
use ferrum_storage::{EmptyView, header_hash, txid};
use ferrum_types::{
    Amount, BlockHash, BlockSeal, ChainParams, Network, Script, Transaction, ValidatorId,
};

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
        input_height: Some(0),
        input_mtp_s: Some(0),
        block_height: 1,
        block_mtp_s: 0,
        sighash_cache: None,
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
    let mutations: [fn(&mut ChainParams); 8] = [
        |p| p.halving_interval = 1,
        |p| p.coinbase_maturity = 7,
        |p| p.max_block_size = 2_000_000,
        |p| p.target_spacing_ms = 60_000,
        |p| p.asert_halflife_s = 60,
        |p| p.genesis_nonce = 1,
        // The fork schedule decides which engine validates every block at and
        // above the activation height. Two nodes that disagree about it fork
        // permanently, so it must not be possible for them to share a genesis.
        |p| p.bft_activation_height = Some(500_000),
        |p| p.bft_validators = vec![ValidatorId::from_bytes([1; 32])],
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
fn the_commitment_pins_the_validator_order() {
    // `validators.rs`: "the order of `ChainParams::bft_validators` is
    // consensus-critical: reordering the list is a hard fork" — the proposer
    // schedule and every commit signature index are positional. Two operators
    // whose files list the same keys in different orders must therefore fail to
    // share a genesis, not discover it at the first commit.
    let a = ValidatorId::from_bytes([0xaa; 32]);
    let b = ValidatorId::from_bytes([0xbb; 32]);

    let mut forward = ChainParams::devnet();
    forward.bft_activation_height = Some(10);
    forward.bft_validators = vec![a, b];

    let mut reversed = forward.clone();
    reversed.bft_validators = vec![b, a];

    assert_ne!(genesis_commitment(&forward), genesis_commitment(&reversed));
    assert_ne!(genesis_hash(&forward), genesis_hash(&reversed));

    // And a set that is a prefix of another is not the same set either.
    let mut shorter = forward.clone();
    shorter.bft_validators = vec![a];
    assert_ne!(genesis_commitment(&forward), genesis_commitment(&shorter));
}

#[test]
fn a_scheduled_activation_is_not_the_same_chain_as_no_activation() {
    // `None` must not encode as any reachable height: a node with no BFT
    // schedule and a node that activates BFT at height 0 are different chains.
    let none = ChainParams::devnet();
    for activation in [0u64, 1, 500_000, u64::MAX] {
        let mut scheduled = none.clone();
        scheduled.bft_activation_height = Some(activation);
        assert_ne!(
            genesis_commitment(&scheduled),
            genesis_commitment(&none),
            "activation at {activation} must not collide with no activation"
        );
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
            "8bfd7dc0fc73ed481b3891f433aee3f50f14a847a6de66ccbf2af3f4942ce229",
            "42dc1be3c6357b0ca832e5b5865ce1d4005ef6f8316cd8246884b9278d2d42c4",
        ),
        (
            ChainParams::testnet(),
            "0271729260045601a991075df86e689acf74eec3aaa930b64513ada36ef18440",
            "a689d3978bcd0c2c0fa4d4d2b1cedb22efdbde5eda1d935b2f2d8eea987c2ff5",
        ),
        (
            ChainParams::devnet(),
            "7747ccde4c1bae8d7f91913e9bcf2f5288c19a54ba0444ed7d21c49f9715008f",
            "db335655845805ab6351958c5dedfe3e0ec8f3e94745b1716fc42e425a135654",
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

