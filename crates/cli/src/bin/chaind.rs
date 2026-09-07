//! `chaind` — the Ferrum node.
//!
//! Parse, resolve, run. Everything the process actually does lives in
//! `ferrum_cli::daemon` and, under that, in `ferrum-node`, so the node runtime
//! is reachable from a test rather than only from a spawned process.

use clap::Parser as _;
use ferrum_cli::{ChaindArgs, report};

fn main() -> std::process::ExitCode {
    let args = ChaindArgs::parse();

    // One multi-threaded runtime for the whole node: the swarm, both HTTP
    // listeners, the miner and the chain-event bridge all live on it, and the
    // blocking pool underneath is where every `redb` call and every sealing
    // loop actually runs.
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("error: cannot start the async runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(ferrum_cli::daemon::run(args)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            let _ = report(&e);
            std::process::ExitCode::FAILURE
        }
    }
}
