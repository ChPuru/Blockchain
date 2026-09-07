//! Wallet lifecycle through the real binary: create, restore, and the exact
//! output shape the devnet scripts parse.
//!
//! Two properties matter more than the rest and are asserted directly:
//!
//! - **`wallet address` prints exactly one line.** `devnet/ci-e2e.sh` reads it
//!   with `| tail -1`; a second line of context would make the address the
//!   second-to-last and the payment would go to whatever the last line said.
//! - **`wallet new --output FILE` keeps the mnemonic off stdout.** The address
//!   is on stdout and the secret is in the file, so the same command can be
//!   piped and scripted without the seed ending up in a log.

use std::path::Path;

use assert_cmd::Command;

/// A node endpoint nothing is listening on, so the tests never depend on a
/// running chain and never accidentally talk to a real one.
const NO_NODE: &str = "http://127.0.0.1:1";

fn cli(datadir: &Path) -> Command {
    let mut command =
        Command::cargo_bin("chain-cli").expect("chain-cli is a bin target of this crate");
    command
        .arg("--datadir")
        .arg(datadir)
        .arg("--rpc")
        .arg(NO_NODE)
        // Belt and braces: an inherited FERRUM_DATADIR must not redirect a
        // test at the developer's real wallet.
        .env("FERRUM_DATADIR", datadir);
    command
}

fn stdout_of(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).to_string()
}

fn stderr_of(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stderr).to_string()
}

#[test]
fn wallet_new_prints_the_address_last_and_the_mnemonic_to_stderr() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let assert = cli(dir.path()).args(["wallet", "new", "--network", "devnet"]).assert().success();

    let out = stdout_of(&assert);
    let address = out.lines().next_back().unwrap_or_default();
    assert!(address.starts_with("rfer1"), "the last line must be a devnet address: {out}");

    let err = stderr_of(&assert);
    assert!(err.contains("mnemonic:"), "the mnemonic belongs on stderr: {err}");
    assert!(!out.contains("mnemonic"), "the mnemonic must never reach stdout: {out}");
}

#[test]
fn wallet_address_prints_exactly_one_line() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let assert = cli(dir.path()).args(["wallet", "address"]).assert().success();
    let out = stdout_of(&assert);
    assert_eq!(out.lines().count(), 1, "wallet address must print one line, got: {out:?}");
    assert!(out.trim().starts_with("rfer1"), "{out}");
}

#[test]
fn wallet_address_is_stable_across_calls_and_new_issues_a_different_one() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let first = stdout_of(&cli(dir.path()).args(["wallet", "address"]).assert().success());
    let again = stdout_of(&cli(dir.path()).args(["wallet", "address"]).assert().success());
    assert_eq!(first, again, "the current address must not rotate on every read");

    let fresh = stdout_of(&cli(dir.path()).args(["wallet", "address", "--new"]).assert().success());
    assert_ne!(first, fresh, "--new must issue a different address");
}

#[test]
fn a_wallet_round_trips_through_new_and_restore() {
    let source = tempfile::tempdir().expect("a temporary directory");
    let target = tempfile::tempdir().expect("a temporary directory");
    let seed_file = source.path().join("seed.txt");

    let created = cli(source.path())
        .args(["wallet", "new", "--network", "devnet", "--output"])
        .arg(&seed_file)
        .assert()
        .success();
    let created_out = stdout_of(&created);
    let original = created_out.lines().next_back().unwrap_or_default().trim().to_owned();
    assert!(original.starts_with("rfer1"), "{created_out}");

    // The secret went to the file, not to stdout.
    let phrase = std::fs::read_to_string(&seed_file).expect("the output file exists");
    assert!(phrase.split_whitespace().count() >= 12, "{phrase}");
    for word in phrase.split_whitespace() {
        assert!(
            !created_out.contains(word) || word == original,
            "a mnemonic word reached stdout: {created_out}"
        );
    }

    let restored = cli(target.path())
        .args(["wallet", "restore", "--network", "devnet", "--mnemonic-file"])
        .arg(&seed_file)
        .assert()
        .success();
    let restored_out = stdout_of(&restored);
    assert_eq!(
        restored_out.lines().next_back().unwrap_or_default().trim(),
        original,
        "the same mnemonic must derive the same first address"
    );
}

#[test]
fn wallet_new_refuses_to_overwrite_without_force() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    cli(dir.path()).args(["wallet", "new"]).assert().success();

    let second = cli(dir.path()).args(["wallet", "new"]).assert().failure();
    assert!(second.get_output().stdout.is_empty(), "nothing may reach stdout on failure");
    assert!(stderr_of(&second).contains("--force"), "{}", stderr_of(&second));

    cli(dir.path()).args(["wallet", "new", "--force"]).assert().success();
}

#[test]
fn a_passphrase_file_is_honoured_on_create_and_on_open() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let pass = dir.path().join("pass.txt");
    std::fs::write(&pass, b"correct horse battery staple\n").expect("write the passphrase");

    let created =
        cli(dir.path()).args(["wallet", "new", "--passphrase-file"]).arg(&pass).assert().success();
    let created_out = stdout_of(&created);
    let address = created_out.lines().next_back().unwrap_or_default().trim().to_owned();

    // Reopening with the same file works...
    let reopened = cli(dir.path())
        .args(["wallet", "address", "--passphrase-file"])
        .arg(&pass)
        .assert()
        .success();
    assert_eq!(stdout_of(&reopened).trim(), address);

    // ...and with the wrong passphrase it fails rather than silently creating
    // a second wallet.
    let wrong = dir.path().join("wrong.txt");
    std::fs::write(&wrong, b"hunter2\n").expect("write the wrong passphrase");
    let failed = cli(dir.path())
        .args(["wallet", "address", "--passphrase-file"])
        .arg(&wrong)
        .assert()
        .failure();
    assert!(failed.get_output().stdout.is_empty());
}

#[test]
fn dump_pubkey_prints_64_hex_characters_as_its_last_line() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let key_file = dir.path().join("validator.key");

    // Exactly what devnet/fork.sh does.
    cli(dir.path()).args(["wallet", "new", "--output"]).arg(&key_file).assert().success();
    let assert =
        cli(dir.path()).args(["wallet", "dump-pubkey", "--key"]).arg(&key_file).assert().success();

    let out = stdout_of(&assert);
    let last = out.lines().next_back().unwrap_or_default();
    assert_eq!(last.len(), 64, "expected a 64-hex x-only key, got {last:?}");
    assert!(last.bytes().all(|b| b.is_ascii_hexdigit()), "{last}");
}

#[test]
fn dump_pubkey_also_reads_a_raw_hex_key_file() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let key_file = dir.path().join("raw.key");
    std::fs::write(&key_file, format!("{}\n", "11".repeat(32))).expect("write the key");

    let assert =
        cli(dir.path()).args(["wallet", "dump-pubkey", "--key"]).arg(&key_file).assert().success();
    let last = stdout_of(&assert).lines().next_back().unwrap_or_default().to_owned();
    assert_eq!(last.len(), 64);
}

#[test]
fn dump_pubkey_on_a_missing_file_fails_with_a_message() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let assert =
        cli(dir.path()).args(["wallet", "dump-pubkey", "--key", "nowhere.key"]).assert().failure();
    assert!(assert.get_output().stdout.is_empty());
    assert!(!assert.get_output().stderr.is_empty());
}

#[test]
fn dump_seed_prints_the_mnemonic_as_its_last_line() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let seed_file = dir.path().join("seed.txt");
    cli(dir.path()).args(["wallet", "new", "--output"]).arg(&seed_file).assert().success();

    let assert = cli(dir.path()).args(["wallet", "dump-seed"]).assert().success();
    let printed = stdout_of(&assert).trim().to_owned();
    let from_file = std::fs::read_to_string(&seed_file).expect("the output file exists");
    assert_eq!(printed, from_file.trim());
}

#[test]
fn a_command_that_needs_a_node_fails_cleanly_when_there_is_none() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    cli(dir.path()).args(["wallet", "new"]).assert().success();

    let assert = cli(dir.path()).args(["wallet", "balance"]).assert().failure();
    assert!(assert.get_output().stdout.is_empty(), "nothing may reach stdout on failure");
    let err = stderr_of(&assert);
    assert!(err.starts_with("error:"), "{err}");
}

#[test]
fn wallet_send_refuses_a_malformed_address_before_touching_the_network() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let assert = cli(dir.path())
        .args(["wallet", "send", "--to", "not-an-address", "--amount", "1.0"])
        .assert()
        .failure();
    assert!(stderr_of(&assert).contains("--to"), "{}", stderr_of(&assert));
}

#[test]
fn wallet_send_refuses_a_malformed_amount() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let assert = cli(dir.path())
        .args(["wallet", "send", "--to", "rfer1qexample", "--amount", "1.2.3"])
        .assert()
        .failure();
    assert!(!assert.get_output().stderr.is_empty());
}
