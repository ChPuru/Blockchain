//! Parser tests for the `chain-cli` command tree.
//!
//! These assert the *shape* CONTRACT §13.1 fixes and that the devnet
//! scripts' exact invocations parse, so a flag rename cannot pass review
//! without a failing test.

#![allow(clippy::unwrap_used)]

use super::*;
use clap::CommandFactory as _;

#[test]
fn the_command_tree_is_internally_consistent() {
    ChainCli::command().debug_assert();
}

#[test]
fn the_globals_are_accepted_before_the_subcommand() {
    let cli = ChainCli::try_parse_from([
        "chain-cli",
        "--datadir",
        "D:/devnet/node1",
        "--rpc",
        "http://127.0.0.1:8646",
        "wallet",
        "address",
    ])
    .unwrap();
    assert_eq!(cli.datadir.as_deref(), Some(std::path::Path::new("D:/devnet/node1")));
    assert_eq!(cli.rpc.as_deref(), Some("http://127.0.0.1:8646"));
    assert!(matches!(cli.command, Command::Wallet(WalletCmd::Address { new: false, .. })));
}

#[test]
fn the_globals_are_also_accepted_after_the_subcommand() {
    let cli =
        ChainCli::try_parse_from(["chain-cli", "chain", "info", "--json"]).unwrap();
    assert!(cli.json);
}

#[test]
fn there_is_no_passphrase_flag_anywhere() {
    // A passphrase in the argument vector is readable by every other
    // process on the machine. If this ever parses, that protection is gone.
    let attempt = ChainCli::try_parse_from([
        "chain-cli",
        "wallet",
        "new",
        "--passphrase",
        "hunter2",
    ]);
    assert!(attempt.is_err());
}

#[test]
fn wallet_new_takes_an_output_file() {
    let cli =
        ChainCli::try_parse_from(["chain-cli", "wallet", "new", "--output", "v.key"]).unwrap();
    match cli.command {
        Command::Wallet(WalletCmd::New { output, words, .. }) => {
            assert_eq!(output.as_deref(), Some(std::path::Path::new("v.key")));
            assert_eq!(words, 12);
        }
        other => panic!("parsed as {other:?}"),
    }
}

#[test]
fn dump_pubkey_requires_a_key_file() {
    assert!(ChainCli::try_parse_from(["chain-cli", "wallet", "dump-pubkey"]).is_err());
    assert!(
        ChainCli::try_parse_from(["chain-cli", "wallet", "dump-pubkey", "--key", "v.key"])
            .is_ok()
    );
}

#[test]
fn script_eval_refuses_both_modes_at_once() {
    let attempt = ChainCli::try_parse_from([
        "chain-cli",
        "script",
        "eval",
        "--script",
        "51",
        "--script-pubkey",
        "51",
        "--script-sig",
        "00",
    ]);
    assert!(attempt.is_err());
}

#[test]
fn build_multisig_takes_repeated_pubkeys() {
    let cli = ChainCli::try_parse_from([
        "chain-cli",
        "script",
        "build-multisig",
        "-k",
        "2",
        "--pubkey",
        "aa",
        "--pubkey",
        "bb",
        "--pubkey",
        "cc",
    ])
    .unwrap();
    match cli.command {
        Command::Script(ScriptCmd::BuildMultisig { threshold, pubkeys }) => {
            assert_eq!(threshold, 2);
            assert_eq!(pubkeys, vec!["aa", "bb", "cc"]);
        }
        other => panic!("parsed as {other:?}"),
    }
}

#[test]
fn genesis_mine_takes_the_three_documented_flags() {
    let cli = ChainCli::try_parse_from([
        "chain-cli",
        "genesis",
        "mine",
        "--network",
        "mainnet",
        "--message",
        "hello",
        "--timestamp",
        "1757203200000",
    ])
    .unwrap();
    match cli.command {
        Command::Genesis(GenesisCmd::Mine { network, message, timestamp, .. }) => {
            assert_eq!(network, "mainnet");
            assert_eq!(message.as_deref(), Some("hello"));
            assert_eq!(timestamp, Some(1_757_203_200_000));
        }
        other => panic!("parsed as {other:?}"),
    }
}

#[test]
fn wallet_send_matches_the_devnet_invocation() {
    // devnet/ci-e2e.sh: wallet send --to "$addr" --amount 1.0
    let cli = ChainCli::try_parse_from([
        "chain-cli",
        "--rpc",
        "http://127.0.0.1:8645",
        "wallet",
        "send",
        "--to",
        "rfer1qexample",
        "--amount",
        "1.0",
    ])
    .unwrap();
    match cli.command {
        Command::Wallet(WalletCmd::Send { to, amount, fee_rate, .. }) => {
            assert_eq!(to, "rfer1qexample");
            assert_eq!(amount, "1.0");
            assert_eq!(fee_rate, 1_000);
        }
        other => panic!("parsed as {other:?}"),
    }
}

