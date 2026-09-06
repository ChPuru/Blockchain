//! The `chaind` command line, exactly as CONTRACT §13.1 fixes it.
//!
//! Every flag is an `Option`, with **no clap default**. That is deliberate:
//! CONTRACT §13 sets the precedence at *CLI flag > environment variable
//! (`FERRUM_*`) > config file > network default*, and a clap default would make
//! every unset flag indistinguishable from an explicitly-set one, so the config
//! file could never win anything. The defaults live in
//! [`crate::node::config::NodeConfig::resolve`], which is where the precedence
//! is implemented and tested.
//!
//! `env = "FERRUM_*"` on each flag is what gives the middle rung of that
//! ladder; clap already prefers an explicit argument to the environment.

use std::path::PathBuf;

use clap::Parser;

/// `chaind` — the Ferrum node.
#[derive(Debug, Default, Parser)]
#[command(
    name = "chaind",
    version,
    about = "Ferrum node: validation, mining, peer-to-peer, JSON-RPC and the explorer",
    long_about = "Precedence for every setting: CLI flag > environment (FERRUM_*) > \
                  config file > network default."
)]
pub struct ChaindArgs {
    /// TOML configuration file. Lowest precedence after network defaults.
    #[arg(long, value_name = "FILE", env = "FERRUM_CONFIG")]
    pub config: Option<PathBuf>,

    /// Which network's `ChainParams` to validate against.
    #[arg(long, value_name = "NAME", env = "FERRUM_NETWORK")]
    pub network: Option<String>,

    /// Store, keystore and node key all live here.
    #[arg(long, value_name = "DIR", env = crate::paths::DATADIR_ENV)]
    pub datadir: Option<PathBuf>,

    /// JSON-RPC listen address. Default `127.0.0.1:8645`.
    #[arg(long, value_name = "IP:PORT", env = "FERRUM_RPC_LISTEN")]
    pub rpc_listen: Option<String>,

    /// libp2p listen address. Default `/ip4/0.0.0.0/tcp/8655`.
    #[arg(long, value_name = "MULTIADDR", env = "FERRUM_P2P_LISTEN")]
    pub p2p_listen: Option<String>,

    /// Explorer REST and static-page listen address. Default `127.0.0.1:8665`.
    #[arg(long, value_name = "IP:PORT", env = "FERRUM_EXPLORER_LISTEN")]
    pub explorer_listen: Option<String>,

    /// Prometheus listen address. Off unless given.
    #[arg(long, value_name = "IP:PORT", env = "FERRUM_METRICS_LISTEN")]
    pub metrics_listen: Option<String>,

    /// A static peer. Repeatable.
    #[arg(long = "peer", value_name = "MULTIADDR", num_args = 1..)]
    pub peers: Vec<String>,

    /// Start the miner.
    #[arg(long)]
    pub mine: bool,

    /// Pay the coinbase here.
    ///
    /// Optional by contract: without it the node mines to an address derived
    /// from `<datadir>/node.key`, generating that file on first run, so a
    /// devnet is startable with no wallet setup at all.
    #[arg(long, value_name = "ADDR", env = "FERRUM_MINE_ADDRESS")]
    pub mine_address: Option<String>,

    /// Maintain the transaction and address reverse index.
    #[arg(long)]
    pub index: bool,

    /// Force a consensus engine, overriding the height-based router.
    #[arg(long, value_name = "pow|bft", env = "FERRUM_CONSENSUS")]
    pub consensus: Option<String>,

    /// TOML with `bft_activation_height` and `bft_validators`.
    #[arg(long, value_name = "FILE", env = "FERRUM_CONSENSUS_CONFIG")]
    pub consensus_config: Option<PathBuf>,

    /// BFT signing key: 64 hex characters, or a BIP-39 phrase.
    #[arg(long, value_name = "FILE", env = "FERRUM_VALIDATOR_KEY")]
    pub validator_key: Option<PathBuf>,

    /// Log format. Default `text`.
    #[arg(long, value_name = "text|json", env = "FERRUM_LOG_FORMAT")]
    pub log_format: Option<String>,

    /// Print the resolved configuration and exit without touching the store.
    ///
    /// Not in the contract's table; additive, and the cheapest way to answer
    /// "which of my four sources of configuration won?".
    #[arg(long)]
    pub print_config: bool,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn the_command_tree_is_internally_consistent() {
        ChaindArgs::command().debug_assert();
    }

    #[test]
    fn the_devnet_invocation_parses_exactly() {
        // This is `start_node` from devnet/lib.sh, flag for flag.
        let args = ChaindArgs::try_parse_from([
            "chaind",
            "--network",
            "devnet",
            "--datadir",
            "D:/devnet/node1",
            "--rpc-listen",
            "127.0.0.1:8645",
            "--p2p-listen",
            "/ip4/127.0.0.1/tcp/8655",
            "--explorer-listen",
            "127.0.0.1:8665",
            "--metrics-listen",
            "127.0.0.1:9100",
            "--index",
            "--log-format",
            "text",
            "--peer",
            "/ip4/127.0.0.1/tcp/8656",
            "--peer",
            "/ip4/127.0.0.1/tcp/8657",
            "--mine",
        ])
        .unwrap();

        assert_eq!(args.network.as_deref(), Some("devnet"));
        assert_eq!(args.rpc_listen.as_deref(), Some("127.0.0.1:8645"));
        assert_eq!(args.explorer_listen.as_deref(), Some("127.0.0.1:8665"));
        assert_eq!(args.metrics_listen.as_deref(), Some("127.0.0.1:9100"));
        assert_eq!(args.peers.len(), 2);
        assert!(args.index);
        assert!(args.mine);
        assert!(args.mine_address.is_none());
    }

    #[test]
    fn the_fork_rehearsal_invocation_parses_exactly() {
        // This is the restart loop in devnet/fork.sh.
        let args = ChaindArgs::try_parse_from([
            "chaind",
            "--network",
            "devnet",
            "--datadir",
            "D:/devnet/node1",
            "--rpc-listen",
            "127.0.0.1:8645",
            "--p2p-listen",
            "/ip4/127.0.0.1/tcp/8655",
            "--explorer-listen",
            "127.0.0.1:8665",
            "--index",
            "--mine",
            "--consensus-config",
            "D:/devnet/node1/fork.toml",
            "--validator-key",
            "D:/devnet/node1/validator.key",
            "--peer",
            "/ip4/127.0.0.1/tcp/8656",
        ])
        .unwrap();

        assert!(args.consensus_config.is_some());
        assert!(args.validator_key.is_some());
    }

    #[test]
    fn nothing_carries_a_clap_default() {
        // A clap default would make "unset" and "set to the default" the same
        // thing, and the config file could then never win.
        let args = ChaindArgs::try_parse_from(["chaind"]).unwrap();
        assert!(args.network.is_none());
        assert!(args.datadir.is_none());
        assert!(args.rpc_listen.is_none());
        assert!(args.p2p_listen.is_none());
        assert!(args.explorer_listen.is_none());
        assert!(args.log_format.is_none());
        assert!(args.peers.is_empty());
        assert!(!args.mine);
        assert!(!args.index);
    }

    #[test]
    fn the_consensus_flag_takes_pow_or_bft() {
        let args = ChaindArgs::try_parse_from(["chaind", "--consensus", "bft"]).unwrap();
        assert_eq!(args.consensus.as_deref(), Some("bft"));
    }
}
