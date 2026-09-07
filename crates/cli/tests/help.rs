//! `--help` for every binary, every group and every subcommand.
//!
//! Not busywork: `--help` is the only place clap's derive output is checked
//! end to end. A conflicting flag, a duplicate short option or a `required`
//! that can never be satisfied is a *runtime* panic in clap, so a subcommand
//! whose help is never rendered is a subcommand nobody has proved parses at
//! all. CONTRACT §13.1 names each of these; if one disappears, the devnet
//! scripts stop working, and this is where that is caught.

use assert_cmd::Command;
use predicates::str::contains;

/// Every `chain-cli` invocation whose `--help` must succeed.
const CHAIN_CLI_HELP: &[&[&str]] = &[
    &["--help"],
    &["wallet", "--help"],
    &["wallet", "new", "--help"],
    &["wallet", "restore", "--help"],
    &["wallet", "address", "--help"],
    &["wallet", "balance", "--help"],
    &["wallet", "send", "--help"],
    &["wallet", "list-unspent", "--help"],
    &["wallet", "dump-seed", "--help"],
    &["wallet", "dump-pubkey", "--help"],
    &["tx", "--help"],
    &["tx", "decode", "--help"],
    &["tx", "send", "--help"],
    &["tx", "get", "--help"],
    &["block", "--help"],
    &["block", "get", "--help"],
    &["block", "hash", "--help"],
    &["block", "tip", "--help"],
    &["script", "--help"],
    &["script", "eval", "--help"],
    &["script", "disassemble", "--help"],
    &["script", "build-p2pkh", "--help"],
    &["script", "build-multisig", "--help"],
    &["script", "build-htlc", "--help"],
    &["chain", "--help"],
    &["chain", "info", "--help"],
    &["chain", "peers", "--help"],
    &["chain", "stateroot", "--help"],
    &["chain", "reindex", "--help"],
    &["genesis", "--help"],
    &["genesis", "mine", "--help"],
    &["faucet", "--help"],
    &["faucet", "request", "--help"],
];

fn cli() -> Command {
    Command::cargo_bin("chain-cli").expect("chain-cli is a bin target of this crate")
}

fn daemon() -> Command {
    Command::cargo_bin("chaind").expect("chaind is a bin target of this crate")
}

#[test]
fn every_chain_cli_subcommand_renders_its_help() {
    for argv in CHAIN_CLI_HELP {
        cli().args(*argv).assert().success().stdout(contains("Usage")).stdout(contains("--help"));
    }
}

#[test]
fn the_help_lists_all_seven_command_groups() {
    cli()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("wallet"))
        .stdout(contains("tx"))
        .stdout(contains("block"))
        .stdout(contains("script"))
        .stdout(contains("chain"))
        .stdout(contains("genesis"))
        .stdout(contains("faucet"));
}

#[test]
fn the_two_global_flags_are_documented_at_the_top_level() {
    cli()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("--datadir"))
        .stdout(contains("--rpc"))
        .stdout(contains("--json"));
}

#[test]
fn wallet_new_documents_output_and_offers_no_passphrase_flag() {
    let assert = cli().args(["wallet", "new", "--help"]).assert().success();
    let text = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(text.contains("--output"), "{text}");
    assert!(text.contains("--passphrase-file"), "{text}");
    // A passphrase in the argument vector is readable by every other process.
    assert!(!text.contains("--passphrase "), "{text}");
    assert!(!text.contains("--passphrase <"), "{text}");
}

#[test]
fn chaind_renders_its_help_with_every_contract_flag() {
    let assert = daemon().arg("--help").assert().success();
    let text = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    for flag in [
        "--network",
        "--datadir",
        "--rpc-listen",
        "--p2p-listen",
        "--explorer-listen",
        "--metrics-listen",
        "--peer",
        "--mine",
        "--mine-address",
        "--index",
        "--consensus",
        "--consensus-config",
        "--validator-key",
        "--log-format",
        "--config",
    ] {
        assert!(text.contains(flag), "chaind --help does not mention {flag}\n{text}");
    }
}

#[test]
fn both_binaries_report_a_version() {
    cli().arg("--version").assert().success().stdout(contains("chain-cli"));
    daemon().arg("--version").assert().success().stdout(contains("chaind"));
}

#[test]
fn an_unknown_subcommand_fails_with_a_message_on_stderr() {
    let assert = cli().arg("teleport").assert().failure();
    assert!(assert.get_output().stdout.is_empty(), "nothing may reach stdout on failure");
    assert!(!assert.get_output().stderr.is_empty());
}

#[test]
fn an_unknown_flag_fails_rather_than_being_ignored() {
    cli().args(["chain", "info", "--not-a-flag"]).assert().failure();
    daemon().arg("--not-a-flag").assert().failure();
}
