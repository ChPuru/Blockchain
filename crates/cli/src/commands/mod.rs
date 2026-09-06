//! The `chain-cli` command implementations and the dispatcher over them.
//!
//! Each command is a plain function that returns a [`CommandOutput`] rather
//! than printing. That is what keeps "the bare value is the last line of
//! stdout" (CONTRACT §13.1) a property of one function — [`CommandOutput::print`]
//! — instead of a convention every command has to remember, and it is what
//! makes the commands testable without capturing a process's stdout.

pub mod block;
pub mod chain;
pub mod faucet;
pub mod genesis;
pub mod script;
pub mod tx;
pub mod wallet;

use std::path::PathBuf;

use ferrum_rpc::FerrumRpcClient as _;
use ferrum_types::Network;
use jsonrpsee::http_client::HttpClient;

use crate::cli::{
    BlockCmd, ChainCli, ChainCmd, Command, FaucetCmd, GenesisCmd, ScriptCmd, TxCmd, WalletCmd,
};
use crate::error::CliResult;
use crate::output::CommandOutput;
use crate::{paths, rpc};

/// What every command is handed: where the files are, and which node to ask.
#[derive(Clone, Debug)]
pub struct Context {
    /// The resolved datadir. Never `None` — the default is filled in early so
    /// no command has to think about it.
    pub datadir: PathBuf,
    /// The resolved JSON-RPC endpoint.
    pub rpc_url: String,
    /// Whether `--json` was given.
    pub json: bool,
}

impl Context {
    /// Build a context from the parsed globals.
    #[must_use]
    pub fn from_cli(cli: &ChainCli) -> Self {
        Context {
            datadir: paths::resolve_datadir(cli.datadir.as_deref()),
            rpc_url: rpc::resolve_url(cli.rpc.as_deref()),
            json: cli.json,
        }
    }

    /// A JSON-RPC client for [`Context::rpc_url`].
    ///
    /// # Errors
    ///
    /// [`crate::error::CliError::RpcConnect`] when the endpoint is unusable.
    pub fn client(&self) -> CliResult<HttpClient> {
        rpc::connect(&self.rpc_url)
    }

    /// Ask the node which network it is on, if it answers at all.
    ///
    /// Used only to pick the network for a wallet created implicitly. A node
    /// that is down is not an error here: the caller falls back to devnet,
    /// which is the network someone running `chain-cli` with no configuration
    /// is overwhelmingly likely to be on.
    pub async fn probe_network(&self) -> Option<Network> {
        let client = self.client().ok()?;
        let info = client.get_blockchain_info().await.ok()?;
        paths::parse_network(&info.chain).ok()
    }
}

/// Run one parsed command.
///
/// # Errors
///
/// Whatever the command returns. `main` prints it to stderr and exits
/// non-zero; nothing reaches stdout on a failure.
pub async fn dispatch(cli: ChainCli) -> CliResult<CommandOutput> {
    let ctx = Context::from_cli(&cli);
    match cli.command {
        Command::Wallet(cmd) => wallet_command(&ctx, cmd).await,
        Command::Tx(cmd) => tx_command(&ctx, cmd).await,
        Command::Block(cmd) => block_command(&ctx, cmd).await,
        Command::Script(cmd) => script::run(cmd),
        Command::Chain(cmd) => chain_command(&ctx, cmd).await,
        Command::Genesis(GenesisCmd::Mine {
            network,
            message,
            timestamp,
            bits,
            start_nonce,
            max_tries,
        }) => genesis::mine(
            &network,
            message.as_deref(),
            timestamp,
            bits.as_deref(),
            start_nonce,
            max_tries,
        ),
        Command::Faucet(FaucetCmd::Request { address, explorer, passphrase }) => {
            faucet::request(&ctx, address.as_deref(), &explorer, &passphrase.source()).await
        }
    }
}

/// Dispatch inside `wallet`.
async fn wallet_command(ctx: &Context, cmd: WalletCmd) -> CliResult<CommandOutput> {
    match cmd {
        WalletCmd::New { output, words, network, force, passphrase } => {
            wallet::new(ctx, output.as_deref(), words, &network, force, &passphrase.source()).await
        }
        WalletCmd::Restore { mnemonic_file, network, force, passphrase } => {
            wallet::restore(ctx, mnemonic_file.as_deref(), &network, force, &passphrase.source())
        }
        WalletCmd::Address { new, passphrase } => {
            wallet::address(ctx, new, &passphrase.source()).await
        }
        WalletCmd::Balance { passphrase } => wallet::balance(ctx, &passphrase.source()).await,
        WalletCmd::Send { to, amount, fee_rate, dry_run, passphrase } => {
            wallet::send(ctx, &to, &amount, fee_rate, dry_run, &passphrase.source()).await
        }
        WalletCmd::ListUnspent { passphrase } => {
            wallet::list_unspent(ctx, &passphrase.source()).await
        }
        WalletCmd::DumpSeed { passphrase } => wallet::dump_seed(ctx, &passphrase.source()).await,
        WalletCmd::DumpPubkey { key, network } => wallet::dump_pubkey(&key, &network),
    }
}

/// Dispatch inside `tx`.
async fn tx_command(ctx: &Context, cmd: TxCmd) -> CliResult<CommandOutput> {
    match cmd {
        TxCmd::Decode { hex } => tx::decode(&hex),
        TxCmd::Send { hex } => tx::send(ctx, &hex).await,
        TxCmd::Get { txid, raw } => tx::get(ctx, &txid, raw).await,
    }
}

/// Dispatch inside `block`.
async fn block_command(ctx: &Context, cmd: BlockCmd) -> CliResult<CommandOutput> {
    match cmd {
        BlockCmd::Get { target, verbosity } => block::get(ctx, &target, verbosity).await,
        BlockCmd::Hash { height } => block::hash(ctx, height).await,
        BlockCmd::Tip => block::tip(ctx).await,
    }
}

/// Dispatch inside `chain`.
async fn chain_command(ctx: &Context, cmd: ChainCmd) -> CliResult<CommandOutput> {
    match cmd {
        ChainCmd::Info => chain::info(ctx).await,
        ChainCmd::Peers => chain::peers(ctx).await,
        ChainCmd::Stateroot { height } => chain::stateroot(ctx, height).await,
        ChainCmd::Reindex { dry_run, network } => chain::reindex(ctx, dry_run, &network),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use clap::Parser as _;

    #[test]
    fn the_context_fills_in_both_defaults() {
        let cli = ChainCli::try_parse_from(["chain-cli", "chain", "info"]).unwrap();
        let ctx = Context::from_cli(&cli);
        assert!(!ctx.datadir.as_os_str().is_empty());
        assert!(ctx.rpc_url.starts_with("http://"));
        assert!(!ctx.json);
    }

    #[test]
    fn explicit_globals_reach_the_context() {
        let cli = ChainCli::try_parse_from([
            "chain-cli",
            "--datadir",
            "D:/x",
            "--rpc",
            "http://1.2.3.4:1",
            "--json",
            "chain",
            "info",
        ])
        .unwrap();
        let ctx = Context::from_cli(&cli);
        assert_eq!(ctx.datadir, std::path::Path::new("D:/x"));
        assert_eq!(ctx.rpc_url, "http://1.2.3.4:1");
        assert!(ctx.json);
    }
}
