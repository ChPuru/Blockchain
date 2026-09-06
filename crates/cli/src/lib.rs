//! Ferrum's two command-line binaries: `chaind` (the node) and `chain-cli`
//! (wallet and admin).
//!
//! This crate is CONTRACT §13 and, exactly, §13.1. The binaries themselves are
//! thin — argument parsing and a call into here — so that everything they do
//! is reachable from a unit test rather than only from a spawned process.
//!
//! # Five things worth knowing before reading further
//!
//! 1. **The last line of stdout is the value.** `devnet/lib.sh`,
//!    `devnet/fork.sh` and `devnet/ci-e2e.sh` all parse this CLI with
//!    `| tail -1`. Commands therefore never print directly: they return a
//!    [`output::CommandOutput`], and one function decides between the human
//!    rendering (context lines, then the bare value last) and `--json`.
//! 2. **A passphrase is never an argument.** There is no `--passphrase` flag
//!    anywhere, because the argument vector of a running process is readable
//!    by every other process on the machine. See [`passphrase`].
//! 3. **`script` needs no node.** Milestone M2 — "`chain-cli script eval` runs
//!    P2PKH, 2-of-3 multisig and a CLTV timelock" — is a property of the
//!    virtual machine, so the command is a pure function of its arguments.
//! 4. **Every storage call in `chaind` crosses `spawn_blocking`.**
//!    `ferrum-storage` is synchronous; a `redb` read on a Tokio worker parks
//!    that worker and becomes a two-second p95 latency bug under load. The
//!    node runtime in [`node`] routes through
//!    [`node::runtime::blocking`] and the RPC layer through
//!    `ferrum_rpc::context::blocking`.
//! 5. **No queue is unbounded.** Every channel in [`node`] has a capacity
//!    constant in [`node::limits`] and sheds with a `tracing::warn!` when it is
//!    full (CONTRACT §10.3).
//!
//! # Layout
//!
//! | Module | What it owns |
//! |---|---|
//! | [`cli`] | the `chain-cli` clap tree |
//! | [`commands`] | one module per command group |
//! | [`output`] | the "bare value last, or `--json`" rendering rule |
//! | [`passphrase`] | where a passphrase may come from, and where it may not |
//! | [`keyfile`] | the key files `devnet/fork.sh` passes between commands |
//! | [`paths`] | the datadir layout |
//! | [`rpc`] | the typed JSON-RPC client |
//! | [`http`] | a deliberately tiny POST, for the REST faucet |
//! | [`node`] | `chaind`: configuration, wiring, mining and shutdown |

#![warn(missing_docs)]

pub mod cli;
pub mod commands;
pub mod error;
pub mod http;
pub mod keyfile;
pub mod node;
pub mod output;
pub mod passphrase;
pub mod paths;
pub mod rpc;

pub use crate::cli::{ChainCli, Command};
pub use crate::commands::{Context, dispatch};
pub use crate::error::{CliError, CliResult};
pub use crate::output::CommandOutput;
pub use crate::passphrase::PassphraseSource;

/// Print an error to stderr in the shape both binaries use, and return the
/// exit code.
///
/// Errors go to **stderr** and nothing goes to stdout, because stdout is what
/// `| tail -1` is reading. The whole `source` chain is printed: "wrong
/// passphrase" alone does not say which keystore, and "connection refused"
/// alone does not say which node.
#[must_use]
pub fn report(error: &CliError) -> i32 {
    eprintln!("error: {error}");
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reporting_an_error_yields_a_failing_exit_code() {
        assert_eq!(report(&CliError::internal("boom")), 1);
    }
}
