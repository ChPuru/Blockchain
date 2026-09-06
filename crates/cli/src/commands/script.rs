//! `chain-cli script ...` — the virtual machine, offline.
//!
//! Milestone M2 is "`chain-cli script eval` runs P2PKH, 2-of-3 multisig and a
//! CLTV timelock; limits reject oversized scripts". Nothing here talks to a
//! node: evaluating a script, disassembling one and building the standard
//! templates are pure functions of their arguments, and making M2 depend on a
//! running chain would defeat the point of the milestone.
//!
//! # Two evaluation modes
//!
//! | Flags | What runs |
//! |---|---|
//! | `--script-sig` + `--script-pubkey` | [`ferrum_script::verify`] — the whole consensus path: push-only `script_sig`, P2SH redeem, clean stack |
//! | `--script` (+ `--stack`) | [`ferrum_script::eval`] — one script over a starting stack, no clean-stack rule |
//!
//! The first is what a node does to an input; the second is what a template
//! author wants while working one out. Both apply every limit in CONTRACT
//! §5.1, so an oversized script is rejected in either mode.
//!
//! # Why a transaction is needed for a signature check
//!
//! `OP_CHECKSIG` verifies against the BIP-143-shaped sighash of CONTRACT §5.5,
//! which commits to the chain id, the spending transaction, the input index
//! and **the value being spent**. `--tx`, `--input-index`, `--input-value` and
//! `--network` supply exactly those. Without `--tx` the evaluator still runs;
//! any signature check simply fails, which is the honest answer rather than a
//! pretend success.

use ferrum_crypto::{Address, PublicKey};
use ferrum_script::templates;
use ferrum_script::{ExecCtx, cast_to_bool, disassemble, eval, parse, verify};
use ferrum_types::{Amount, Script, Transaction};
use serde_json::json;

use crate::cli::{ScriptCmd, ScriptEvalArgs};
use crate::error::{CliError, CliResult};
use crate::output::CommandOutput;
use crate::paths::parse_network;

/// Run a `script` subcommand.
///
/// # Errors
///
/// [`CliError::Invalid`] for malformed hex or an impossible template, and
/// [`CliError::Script`] when the virtual machine refuses the script.
pub fn run(cmd: ScriptCmd) -> CliResult<CommandOutput> {
    match cmd {
        ScriptCmd::Eval(args) => eval_script(&args),
        ScriptCmd::Disassemble { hex } => disassemble_script(&hex),
        ScriptCmd::BuildP2pkh { pubkey, hash160, address } => {
            build_p2pkh(pubkey.as_deref(), hash160.as_deref(), address.as_deref())
        }
        ScriptCmd::BuildMultisig { threshold, pubkeys } => build_multisig(threshold, &pubkeys),
        ScriptCmd::BuildHtlc { hash, receiver, timeout, refund } => {
            build_htlc(&hash, &receiver, timeout, &refund)
        }
    }
}

/// Decode a hex string into a [`Script`].
fn script_from_hex(what: &'static str, hex_text: &str) -> CliResult<Script> {
    Script::from_hex(hex_text.trim())
        .map_err(|e| CliError::invalid(what, hex_text, e.to_string()))
}

/// Decode a hex string into a fixed-size array.
fn bytes20(what: &'static str, hex_text: &str) -> CliResult<[u8; 20]> {
    let raw = hex::decode(hex_text.trim().trim_start_matches("0x"))
        .map_err(|e| CliError::invalid(what, hex_text, e.to_string()))?;
    raw.try_into()
        .map_err(|_| CliError::invalid(what, hex_text, "expected 20 bytes (40 hex characters)"))
}

/// Decode a 64-hex x-only public key.
fn public_key(what: &'static str, hex_text: &str) -> CliResult<PublicKey> {
    let raw = hex::decode(hex_text.trim().trim_start_matches("0x"))
        .map_err(|e| CliError::invalid(what, hex_text, e.to_string()))?;
    let array: [u8; 32] = raw
        .try_into()
        .map_err(|_| CliError::invalid(what, hex_text, "expected 32 bytes (64 hex characters)"))?;
    PublicKey::from_bytes(&array).map_err(|e| CliError::invalid(what, hex_text, e.to_string()))
}

/// `script eval`.
fn eval_script(args: &ScriptEvalArgs) -> CliResult<CommandOutput> {
    let network = parse_network(&args.network)?;
    let chain_id = network.chain_id();
    let input_value = Amount::from_frm_str(&args.input_value)
        .map_err(|e| CliError::invalid("--input-value", &args.input_value, e.to_string()))?;

    // A signature check needs a transaction. Without one, an empty transaction
    // stands in: every limit and every non-signature opcode still runs, and a
    // signature check fails rather than pretending to pass.
    let tx: Transaction = match &args.tx {
        Some(hex_text) => {
            let raw = hex::decode(hex_text.trim().trim_start_matches("0x"))
                .map_err(|e| CliError::invalid("--tx", hex_text, e.to_string()))?;
            Transaction::decode_envelope(&raw)
                .map_err(|e| CliError::invalid("--tx", hex_text, e.to_string()))?
        }
        None => Transaction::empty(),
    };

    let ctx = ExecCtx {
        input_value,
        block_height: args.height,
        block_mtp_s: args.mtp,
        ..ExecCtx::new(chain_id, &tx, args.input_index)
    };

    match (&args.script_pubkey, &args.script) {
        (Some(pubkey_hex), _) => {
            let script_pubkey = script_from_hex("--script-pubkey", pubkey_hex)?;
            let sig_hex = args.script_sig.as_deref().unwrap_or("");
            let script_sig = script_from_hex("--script-sig", sig_hex)?;
            let result = verify(&script_sig, &script_pubkey, &ctx);
            Ok(verify_output(&result))
        }
        (None, Some(script_hex)) => {
            let script = script_from_hex("--script", script_hex)?;
            let mut initial = Vec::with_capacity(args.stack.len());
            for element in &args.stack {
                initial.push(
                    hex::decode(element.trim().trim_start_matches("0x"))
                        .map_err(|e| CliError::invalid("--stack", element, e.to_string()))?,
                );
            }
            let result = eval(&script, initial, &ctx);
            Ok(eval_output(&result))
        }
        (None, None) => Err(CliError::invalid(
            "script eval",
            "<nothing>",
            "pass --script, or --script-sig together with --script-pubkey",
        )),
    }
}

/// Render the result of the full consensus path.
fn verify_output(
    result: &Result<ferrum_script::ExecStats, ferrum_script::ScriptError>,
) -> CommandOutput {
    match result {
        Ok(stats) => CommandOutput::scalar("success", "true")
            .with_json(json!({
                "mode": "verify",
                "success": true,
                "ops": stats.ops,
                "max_stack": stats.max_stack,
                "sig_checks": stats.sig_checks,
            }))
            .with_field("ops", stats.ops)
            .with_field("max stack", stats.max_stack)
            .with_field("sig checks", stats.sig_checks),
        Err(e) => CommandOutput::scalar("success", "false")
            .with_json(json!({ "mode": "verify", "success": false, "error": e.to_string() }))
            .with_field("error", e),
    }
}

/// Render the result of a standalone evaluation.
fn eval_output(result: &Result<ferrum_script::Stack, ferrum_script::ScriptError>) -> CommandOutput {
    match result {
        Ok(stack) => {
            let truthy = stack.last().is_some_and(|top| cast_to_bool(top));
            let elements: Vec<String> = stack.iter().map(hex::encode).collect();
            let mut out = CommandOutput::scalar("success", truthy.to_string()).with_json(json!({
                "mode": "eval",
                "success": truthy,
                "stack": elements,
            }));
            for (depth, element) in stack.iter().enumerate().rev() {
                out = out.with_line(format!("[{depth}] {}", hex::encode(element)));
            }
            out
        }
        Err(e) => CommandOutput::scalar("success", "false")
            .with_json(json!({ "mode": "eval", "success": false, "error": e.to_string() }))
            .with_field("error", e),
    }
}

/// `script disassemble`.
fn disassemble_script(hex_text: &str) -> CliResult<CommandOutput> {
    let script = script_from_hex("script", hex_text)?;
    let text = disassemble(&script);
    // `parse` is the strict reader; `disassemble` never fails, so a script the
    // parser rejects still renders and the error is reported alongside it.
    let parse_error = parse(&script).err().map(|e| e.to_string());
    let kind = templates::classify(&script);

    let mut out = CommandOutput::scalar("disassembly", text.clone()).with_json(json!({
        "disassembly": text,
        "script_type": format!("{kind:?}"),
        "size": script.len(),
        "parse_error": parse_error,
    }));
    out = out.with_field("type", format!("{kind:?}")).with_field("size", script.len());
    if let Some(error) = parse_error {
        out = out.with_field("parse error", error);
    }
    Ok(out)
}

/// Build a [`CommandOutput`] for a freshly built script.
fn script_output(script: &Script) -> CommandOutput {
    let kind = templates::classify(script);
    CommandOutput::scalar("script", script.to_hex())
        .with_json(json!({
            "script": script.to_hex(),
            "script_type": format!("{kind:?}"),
            "size": script.len(),
            "disassembly": disassemble(script),
        }))
        .with_field("type", format!("{kind:?}"))
        .with_field("size", script.len())
        .with_field("asm", disassemble(script))
}

/// `script build-p2pkh`.
fn build_p2pkh(
    pubkey: Option<&str>,
    hash160: Option<&str>,
    address: Option<&str>,
) -> CliResult<CommandOutput> {
    let pkh: [u8; 20] = match (pubkey, hash160, address) {
        (Some(hex_key), _, _) => {
            let key = public_key("--pubkey", hex_key)?;
            ferrum_crypto::hash160(key.as_bytes())
        }
        (None, Some(hex_hash), _) => bytes20("--hash160", hex_hash)?,
        (None, None, Some(text)) => {
            let decoded = Address::decode(text)
                .map_err(|e| CliError::invalid("--address", text, e.to_string()))?;
            match decoded.payload {
                ferrum_crypto::AddressPayload::PubKeyHash(pkh) => pkh,
                ferrum_crypto::AddressPayload::ScriptHash(_) => {
                    return Err(CliError::invalid(
                        "--address",
                        text,
                        "this is a script address; p2pkh needs a public-key hash",
                    ));
                }
            }
        }
        (None, None, None) => {
            return Err(CliError::invalid(
                "script build-p2pkh",
                "<nothing>",
                "pass one of --pubkey, --hash160 or --address",
            ));
        }
    };
    Ok(script_output(&templates::p2pkh(&pkh)))
}

/// `script build-multisig`.
fn build_multisig(threshold: u8, pubkeys: &[String]) -> CliResult<CommandOutput> {
    let mut keys = Vec::with_capacity(pubkeys.len());
    for text in pubkeys {
        keys.push(public_key("--pubkey", text)?);
    }
    let script = templates::multisig(threshold, &keys)?;
    Ok(script_output(&script))
}

/// `script build-htlc`.
fn build_htlc(
    hash: &str,
    receiver: &str,
    timeout: u32,
    refund: &str,
) -> CliResult<CommandOutput> {
    let script = templates::htlc(
        &bytes20("--hash", hash)?,
        &bytes20("--receiver", receiver)?,
        timeout,
        &bytes20("--refund", refund)?,
    );
    Ok(script_output(&script))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::cli::{ChainCli, Command};
    use clap::Parser as _;

    fn run_args(argv: &[&str]) -> CliResult<CommandOutput> {
        let mut full = vec!["chain-cli"];
        full.extend_from_slice(argv);
        let cli = ChainCli::try_parse_from(full).unwrap();
        match cli.command {
            Command::Script(cmd) => run(cmd),
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn op_1_evaluates_to_true() {
        let out = run_args(&["script", "eval", "--script", "51"]).unwrap();
        assert_eq!(out.bare.as_deref(), Some("true"));
    }

    #[test]
    fn op_0_evaluates_to_false() {
        let out = run_args(&["script", "eval", "--script", "00"]).unwrap();
        assert_eq!(out.bare.as_deref(), Some("false"));
    }

    #[test]
    fn arithmetic_runs_over_a_supplied_stack() {
        // OP_ADD over 2 and 3, pushed as stack elements, leaves 5.
        let out =
            run_args(&["script", "eval", "--script", "93", "--stack", "02", "--stack", "03"])
                .unwrap();
        assert_eq!(out.json["stack"], serde_json::json!(["05"]));
    }

    #[test]
    fn an_oversized_script_is_rejected_by_the_limits() {
        // 1001 bytes of OP_NOP: one over MAX_SCRIPT_SIZE.
        let oversized = "61".repeat(ferrum_script::MAX_SCRIPT_SIZE + 1);
        let out = run_args(&["script", "eval", "--script", &oversized]).unwrap();
        assert_eq!(out.bare.as_deref(), Some("false"));
        assert!(out.json["error"].as_str().unwrap_or_default().contains("too large"));
    }

    #[test]
    fn eval_needs_something_to_evaluate() {
        assert!(run_args(&["script", "eval"]).is_err());
    }

    #[test]
    fn build_p2pkh_from_a_hash_classifies_as_p2pkh() {
        let out =
            run_args(&["script", "build-p2pkh", "--hash160", &"11".repeat(20)]).unwrap();
        assert_eq!(out.json["script_type"], "P2PKH");
        assert_eq!(out.json["size"], 25);
    }

    #[test]
    fn build_p2pkh_rejects_a_short_hash() {
        assert!(run_args(&["script", "build-p2pkh", "--hash160", "1122"]).is_err());
    }

    #[test]
    fn build_htlc_classifies_as_an_htlc() {
        let out = run_args(&[
            "script",
            "build-htlc",
            "--hash",
            &"aa".repeat(20),
            "--receiver",
            &"bb".repeat(20),
            "--timeout",
            "500",
            "--refund",
            &"cc".repeat(20),
        ])
        .unwrap();
        assert_eq!(out.json["script_type"], "Htlc");
    }

    #[test]
    fn disassembly_names_the_opcodes() {
        let out = run_args(&["script", "disassemble", "76a914"]).unwrap();
        let text = out.json["disassembly"].as_str().unwrap_or_default();
        assert!(text.contains("OP_DUP"), "{text}");
        assert!(text.contains("OP_HASH160"), "{text}");
    }

    #[test]
    fn a_truncated_push_still_disassembles_and_reports_why() {
        let out = run_args(&["script", "disassemble", "4c"]).unwrap();
        assert!(!out.json["parse_error"].is_null());
    }
}
