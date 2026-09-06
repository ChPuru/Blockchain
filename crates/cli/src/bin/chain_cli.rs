//! `chain-cli` — the Ferrum wallet and admin client.
//!
//! Thin on purpose: parse, dispatch, print, exit. Everything it does lives in
//! `ferrum_cli` so it is reachable from a unit test rather than only from a
//! spawned process.

use clap::Parser as _;
use ferrum_cli::{ChainCli, report};

fn main() -> std::process::ExitCode {
    let cli = ChainCli::parse();
    let json = cli.json;

    // A current-thread runtime: this process makes a handful of JSON-RPC calls
    // and then exits. A multi-threaded pool would spin up one worker per core
    // to do nothing, which is measurable on the startup of a command that is
    // often run in a shell loop.
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("error: cannot start the async runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(ferrum_cli::dispatch(cli)) {
        Ok(output) => {
            if let Err(e) = output.print(json) {
                eprintln!("error: cannot render the result: {e}");
                return std::process::ExitCode::FAILURE;
            }
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            let _ = report(&e);
            std::process::ExitCode::FAILURE
        }
    }
}
