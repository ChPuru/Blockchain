//! Fuzz the script virtual machine.
//!
//! The VM is the largest attack surface in the chain: an attacker chooses both
//! the locking script (by paying to it) and the unlocking script (by spending
//! it), so both inputs here are fully adversarial.
//!
//! The property is simple and absolute: **the interpreter must never panic on
//! any input.** A panic inside block validation is a remote crash of every node
//! that validates the block, and on a chain small enough to have no security
//! budget that is the whole network. Failure must always be a typed
//! `ScriptError`, never an unwrap, an index out of bounds, or an arithmetic
//! overflow.
//!
//! The hard limits — 1000-byte scripts, 100-deep stack, 520-byte elements, 201
//! operations, no loops — are what make this tractable: execution is statically
//! bounded, so there is no need for gas metering and no way to build an
//! unbounded loop out of valid opcodes.
//!
//! The execution context is fuzzed too, in the narrow places where a script can
//! observe it: the block height and median time past that `OP_CHECKLOCKTIMEVERIFY`
//! reads, and the spent coin's height and median time past that
//! `OP_CHECKSEQUENCEVERIFY` measures a BIP-68 relative locktime against. Those
//! are `u64` arithmetic on attacker-influenced values, so they belong in the
//! fuzzed surface rather than pinned to one constant.

#![no_main]

use ferrum_script::{ExecCtx, ScriptLimits, SighashCache};
use ferrum_types::{Amount, ChainId, OutPoint, Script, Transaction, TxIn, TxOut, Txid};
use libfuzzer_sys::fuzz_target;

/// A fixed, valid transaction to hang the execution context on. The transaction
/// is not what is being fuzzed — the scripts are — so keeping it constant makes
/// crashes reproduce from the script bytes alone.
fn fixture_tx(script_sig: Script, sequence: u32) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint { txid: Txid::ZERO, vout: 0 },
            script_sig,
            sequence,
        }],
        outputs: vec![TxOut {
            value: Amount::from_grains(50_000),
            script_pubkey: Script::new(vec![0x51]), // OP_1
        }],
        lock_time: 0,
    }
}

/// Four bytes of the input, little-endian, or zero when they are not there.
fn u32_at(data: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    for (i, slot) in buf.iter_mut().enumerate() {
        *slot = data.get(offset.wrapping_add(i)).copied().unwrap_or(0);
    }
    u32::from_le_bytes(buf)
}

fuzz_target!(|data: &[u8]| {
    // Split the input so the fuzzer controls both scripts independently. A
    // single-script target would never explore the interaction between the
    // unlocking stack and the locking script, which is where P2SH lives.
    if data.len() < 2 {
        return;
    }
    let split = usize::from(data[0]) * data.len() / 256;
    let (sig_bytes, pk_bytes) = data[1..].split_at(split.min(data.len().saturating_sub(1)));

    let script_sig = Script::new(sig_bytes.to_vec());
    let script_pubkey = Script::new(pk_bytes.to_vec());

    // Parsing and disassembly are reachable from the RPC and the explorer, so
    // they are adversarial input too.
    let _ = ferrum_script::parse(&script_sig);
    let _ = ferrum_script::parse(&script_pubkey);
    let _ = ferrum_script::disassemble(&script_pubkey);
    let _ = ferrum_script::is_push_only(&script_sig);
    let _ = ferrum_script::templates::classify(&script_pubkey);

    // The context a timelock opcode can see, taken from the input: the coin's
    // age drives every branch of the BIP-68 comparison, including the ones that
    // add a 16-bit relative lock to a `u64` near its maximum.
    let sequence = u32_at(data, 0);
    let block_height = u64::from(u32_at(data, 4));
    let coin_height = u64::from(u32_at(data, 8));
    let block_mtp_s = u64::from(u32_at(data, 12));
    let coin_mtp_s = u64::from(u32_at(data, 16));

    let tx = fixture_tx(script_sig.clone(), sequence);
    let cache = SighashCache::new(&tx);
    let ctx = ExecCtx {
        chain_id: ChainId(3),
        tx: &tx,
        input_index: 0,
        input_value: Amount::from_grains(100_000),
        input_height: Some(coin_height),
        input_mtp_s: Some(coin_mtp_s),
        block_height,
        block_mtp_s,
        sighash_cache: Some(&cache),
        limits: ScriptLimits::default(),
    };

    // The whole point: this may return Err, but it must never panic and must
    // always terminate. There are no backwards jumps in the opcode table, so a
    // hang here would itself be a bug worth finding.
    let _ = ferrum_script::verify(&script_sig, &script_pubkey, &ctx);

    // Standalone evaluation, as exposed by `chain-cli script eval`.
    let _ = ferrum_script::eval(&script_pubkey, Vec::new(), &ctx);

    // The same scripts against a context that cannot say how old the coin is:
    // a different set of branches through the relative-locktime rules, and the
    // shape every non-validating caller (the CLI, a wallet self-check) uses.
    let bare =
        ExecCtx { input_value: Amount::from_grains(100_000), ..ExecCtx::new(ChainId(3), &tx, 0) };
    let _ = ferrum_script::verify(&script_sig, &script_pubkey, &bare);
    let _ = ferrum_script::eval(&script_pubkey, Vec::new(), &bare);
});
