//! Panic freedom.
//!
//! CONTRACT §5.4: *"The interpreter must never panic on any input."* The script
//! VM is the largest surface in the project reachable by unauthenticated bytes,
//! so this file throws ten thousand random scripts and random initial stacks at
//! it and asserts only one thing — that it returns.
//!
//! `testing/fuzz/fuzz_targets/script.rs` runs the same shape indefinitely; this
//! is the version that runs on every `cargo test`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

mod common;

use ferrum_script::{
    ExecCtx, ScriptLimits, disassemble, eval, is_p2sh, is_push_only, parse, templates, verify,
};
use ferrum_types::{Amount, ChainId, OutPoint, Script, Transaction, TxIn, TxOut, Txid};
use proptest::prelude::*;

/// A transaction shaped like something a peer might actually send.
fn arb_tx() -> impl Strategy<Value = Transaction> {
    (
        any::<u32>(),
        prop::collection::vec((any::<[u8; 32]>(), any::<u32>(), any::<u32>()), 1..4),
        prop::collection::vec((any::<u64>(), prop::collection::vec(any::<u8>(), 0..40)), 0..4),
        any::<u32>(),
    )
        .prop_map(|(version, inputs, outputs, lock_time)| Transaction {
            version,
            inputs: inputs
                .into_iter()
                .map(|(txid, vout, sequence)| TxIn {
                    prev_out: OutPoint::new(Txid::from_bytes(txid), vout),
                    script_sig: Script::EMPTY,
                    sequence,
                })
                .collect(),
            outputs: outputs
                .into_iter()
                .map(|(value, script)| TxOut::new(Amount::from_grains(value), Script::new(script)))
                .collect(),
            lock_time,
        })
}

/// Random bytes, plus a bias towards opcodes that are interesting to the VM so
/// that pure noise does not spend every case on `InvalidOpcode`.
fn arb_script() -> impl Strategy<Value = Vec<u8>> {
    let interesting: Vec<u8> = vec![
        0x00, 0x01, 0x02, 0x4b, 0x4c, 0x4d, 0x4f, 0x51, 0x52, 0x53, 0x60, 0x61, 0x63, 0x64, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b,
        0x7c, 0x7d, 0x82, 0x87, 0x88, 0x8b, 0x8c, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x9a, 0x9b,
        0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa9, 0xaa, 0xac,
        0xad, 0xae, 0xaf, 0xb1, 0xb2,
    ];
    prop_oneof![
        3 => prop::collection::vec(prop::sample::select(interesting), 0..60),
        1 => prop::collection::vec(any::<u8>(), 0..200),
    ]
}

/// Random stacks, including oversized elements and deep stacks.
fn arb_stack() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 0..70), 0..8)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// The headline requirement: `eval` over random scripts and random initial
    /// stacks returns, always.
    #[test]
    fn eval_never_panics(
        script in arb_script(),
        stack in arb_stack(),
        tx in arb_tx(),
        index in 0usize..4,
        value in any::<u64>(),
        height in any::<u64>(),
        mtp in any::<u64>(),
        // The coin's age is `u64` arithmetic on values a caller derives from
        // chain data, and the relative-locktime rules add a 16-bit lock to it,
        // so `None` and both extremes belong in the fuzzed surface.
        coin_height in prop::option::of(any::<u64>()),
        coin_mtp in prop::option::of(any::<u64>()),
    ) {
        let ctx = ExecCtx {
            chain_id: ChainId::DEVNET,
            tx: &tx,
            input_index: index,
            input_value: Amount::from_grains(value),
            input_height: coin_height,
            input_mtp_s: coin_mtp,
            block_height: height,
            block_mtp_s: mtp,
            sighash_cache: None,
            limits: ScriptLimits::CONSENSUS,
        };
        let _ = eval(&Script::new(script), stack, &ctx);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// `verify` over two random scripts.
    #[test]
    fn verify_never_panics(
        sig in arb_script(),
        pubkey in arb_script(),
        tx in arb_tx(),
    ) {
        let ctx = ExecCtx {
            input_value: Amount::from_grains(1_000),
            ..ExecCtx::new(ChainId::MAINNET, &tx, 0)
        };
        let _ = verify(&Script::new(sig), &Script::new(pubkey), &ctx);
    }

    /// A random `script_sig` against a real P2SH output, which is the path that
    /// re-enters the interpreter with attacker-chosen bytes.
    #[test]
    fn p2sh_never_panics(sig in arb_script(), redeem in arb_script(), tx in arb_tx()) {
        let script_pubkey = templates::p2sh_of(&Script::new(redeem.clone()));
        let mut unlock = sig;
        if let Ok(push) = ferrum_script::opcode::encode_push(&redeem) {
            unlock.extend_from_slice(&push);
        }
        // With a caller-supplied sighash cache, which is the shape a validating
        // caller uses and a different path through the machine's construction.
        let cache = ferrum_script::SighashCache::new(&tx);
        let ctx = ExecCtx {
            input_value: Amount::from_grains(1_000),
            sighash_cache: Some(&cache),
            ..ExecCtx::new(ChainId::MAINNET, &tx, 0)
        };
        let _ = verify(&Script::new(unlock), &script_pubkey, &ctx);
    }

    /// Every pure function on a script, over the same random bytes.
    #[test]
    fn the_pure_helpers_never_panic(bytes in arb_script()) {
        let s = Script::new(bytes);
        let _ = parse(&s);
        let _ = is_push_only(&s);
        let _ = is_p2sh(&s);
        let _ = disassemble(&s);
        let _ = templates::classify(&s);
    }

    /// Tightened limits must not open a panic that the consensus table hides.
    #[test]
    fn tight_limits_never_panic(
        script in arb_script(),
        stack in arb_stack(),
        max_script_size in 0usize..40,
        max_stack_size in 0usize..8,
        max_element_size in 0usize..8,
        max_ops in 0u32..8,
        max_pubkeys in 0usize..4,
        max_num_size in 0usize..6,
    ) {
        let tx = common::dummy_tx();
        let ctx = ExecCtx {
            limits: ScriptLimits {
                max_script_size,
                max_stack_size,
                max_element_size,
                max_ops,
                max_pubkeys_per_multisig: max_pubkeys,
                max_num_size,
            },
            ..common::ctx_for(&tx, ChainId::DEVNET)
        };
        let _ = eval(&Script::new(script), stack, &ctx);
    }
}
