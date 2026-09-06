//! The `chaind` command line, and the layer-neutral override struct it becomes.
//!
//! Two types on purpose. [`NodeArgs`] is the `clap` surface and matches
//! CONTRACT §13.1 flag for flag, because `devnet/*.sh` and CI already call it.
//! [`CliOverrides`] is a plain struct of `Option`s with no `clap` in it, so the
//! precedence engine — and its tests — never has to build a fake argv.
//!
//! Note what is *not* here: `#[arg(env = ...)]`. Letting `clap` read the
//! environment would fold two layers into one and make "CLI beats env"
//! untestable, which is precisely the rule operators trip over.

use std::path::PathBuf;

use clap::Parser;

/// Configuration values supplied on the command line.
///
/// Every field is `Option`: `None` means "this layer said nothing", which is
/// what lets the environment, the file and then the network default answer in
/// turn.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CliOverrides {
    /// `--config`
    pub config: Option<PathBuf>,
    /// `--network`
    pub network: Option<String>,
    /// `--datadir`
    pub datadir: Option<PathBuf>,
    /// `--rpc-listen`
    pub rpc_listen: Option<String>,
    /// `--p2p-listen`
    pub p2p_listen: Option<String>,
    /// `--explorer-listen`
    pub explorer_listen: Option<String>,
    /// `--metrics-listen`
    pub metrics_listen: Option<String>,
    /// `--peer`, repeatable.
    pub peers: Option<Vec<String>>,
    /// `--mine`
    pub mine: Option<bool>,
    /// `--mine-address`
    pub mine_address: Option<String>,
    /// `--index`
    pub index: Option<bool>,
    /// `--consensus`
    pub consensus: Option<String>,
    /// `--consensus-config`
    pub consensus_config: Option<PathBuf>,
    /// `--validator-key`
    pub validator_key: Option<PathBuf>,
    /// `--log-format`
    pub log_format: Option<String>,
    /// `--faucet`
    pub faucet: Option<bool>,
}

/// The `chaind` command line, exactly as CONTRACT §13.1 specifies it.
#[derive(Clone, Debug, Default, Parser)]
#[command(
    name = "chaind",
    version,
    about = "Ferrum node: validation, sync, mining, RPC and the explorer"
)]
pub struct NodeArgs {
    /// TOML config file. Lowest precedence except the network defaults.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Which network's consensus parameters to use.
    #[arg(long, value_name = "mainnet|testnet|devnet")]
    pub network: Option<String>,

    /// Store, keystore and node key live here.
    #[arg(long, value_name = "DIR")]
    pub datadir: Option<PathBuf>,

    /// JSON-RPC listen address.
    #[arg(long, value_name = "IP:PORT")]
    pub rpc_listen: Option<String>,

    /// p2p listen multiaddr.
    #[arg(long, value_name = "MULTIADDR")]
    pub p2p_listen: Option<String>,

    /// Explorer REST and static-page listen address.
    #[arg(long, value_name = "IP:PORT")]
    pub explorer_listen: Option<String>,

    /// Prometheus listen address. Omit to leave metrics off.
    #[arg(long, value_name = "IP:PORT")]
    pub metrics_listen: Option<String>,

    /// A static peer. Repeatable; Ferrum has no peer discovery by design.
    #[arg(long = "peer", value_name = "MULTIADDR")]
    pub peer: Vec<String>,

    /// Start the miner.
    ///
    /// A presence flag, so it can only switch mining **on**. To turn a
    /// configured miner off, remove it from the config file or the
    /// environment; a flag that silently disabled a configured miner would be
    /// a footgun in a systemd unit.
    #[arg(long)]
    pub mine: bool,

    /// The address the coinbase pays.
    ///
    /// Optional. Without it the node mines to an address derived from
    /// `<datadir>/node.key`, generating that key on first run, so a devnet
    /// starts with no wallet setup (CONTRACT §13.1).
    #[arg(long, value_name = "ADDR")]
    pub mine_address: Option<String>,

    /// Maintain the transaction and address reverse index.
    #[arg(long)]
    pub index: bool,

    /// Force a consensus engine, overriding the height-based router.
    #[arg(long, value_name = "pow|bft")]
    pub consensus: Option<String>,

    /// TOML file carrying `bft_activation_height` and `bft_validators`.
    #[arg(long, value_name = "FILE")]
    pub consensus_config: Option<PathBuf>,

    /// BFT signing key.
    #[arg(long, value_name = "FILE")]
    pub validator_key: Option<PathBuf>,

    /// Log format.
    #[arg(long, value_name = "text|json")]
    pub log_format: Option<String>,

    /// Serve `POST /api/faucet` from the explorer.
    #[arg(long)]
    pub faucet: bool,
}

impl NodeArgs {
    /// Project the parsed command line onto the layer-neutral override struct.
    ///
    /// The three presence flags become `Some(true)` or `None`, never
    /// `Some(false)`: a flag that was not passed is silence, not a decision.
    #[must_use]
    pub fn overrides(&self) -> CliOverrides {
        CliOverrides {
            config: self.config.clone(),
            network: self.network.clone(),
            datadir: self.datadir.clone(),
            rpc_listen: self.rpc_listen.clone(),
            p2p_listen: self.p2p_listen.clone(),
            explorer_listen: self.explorer_listen.clone(),
            metrics_listen: self.metrics_listen.clone(),
            peers: if self.peer.is_empty() { None } else { Some(self.peer.clone()) },
            mine: if self.mine { Some(true) } else { None },
            mine_address: self.mine_address.clone(),
            index: if self.index { Some(true) } else { None },
            consensus: self.consensus.clone(),
            consensus_config: self.consensus_config.clone(),
            validator_key: self.validator_key.clone(),
            log_format: self.log_format.clone(),
            faucet: if self.faucet { Some(true) } else { None },
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use clap::CommandFactory;

    use super::*;

    fn parse(args: &[&str]) -> NodeArgs {
        let mut argv = vec!["chaind"];
        argv.extend_from_slice(args);
        NodeArgs::try_parse_from(argv).unwrap()
    }

    #[test]
    fn the_clap_surface_is_internally_consistent() {
        NodeArgs::command().debug_assert();
    }

    #[test]
    fn the_devnet_command_line_parses() {
        // Exactly what devnet/lib.sh start_node builds.
        let args = parse(&[
            "--network",
            "devnet",
            "--datadir",
            "/tmp/node1",
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
        ]);
        let o = args.overrides();
        assert_eq!(o.network.as_deref(), Some("devnet"));
        assert_eq!(o.datadir, Some(PathBuf::from("/tmp/node1")));
        assert_eq!(o.rpc_listen.as_deref(), Some("127.0.0.1:8645"));
        assert_eq!(o.p2p_listen.as_deref(), Some("/ip4/127.0.0.1/tcp/8655"));
        assert_eq!(o.explorer_listen.as_deref(), Some("127.0.0.1:8665"));
        assert_eq!(o.metrics_listen.as_deref(), Some("127.0.0.1:9100"));
        assert_eq!(o.peers.as_ref().map(Vec::len), Some(2));
        assert_eq!(o.mine, Some(true));
        assert_eq!(o.index, Some(true));
        assert_eq!(o.log_format.as_deref(), Some("text"));
        assert_eq!(o.mine_address, None, "no --mine-address: the node key answers");
    }

    #[test]
    fn an_absent_presence_flag_is_silence_not_false() {
        let o = parse(&[]).overrides();
        assert_eq!(o.mine, None);
        assert_eq!(o.index, None);
        assert_eq!(o.faucet, None);
        assert_eq!(o, CliOverrides::default());
    }

    #[test]
    fn an_empty_peer_list_is_none_so_lower_layers_can_answer() {
        assert_eq!(parse(&[]).overrides().peers, None);
        assert_eq!(
            parse(&["--peer", "/ip4/1.2.3.4/tcp/8655"]).overrides().peers,
            Some(vec!["/ip4/1.2.3.4/tcp/8655".to_owned()])
        );
    }

    #[test]
    fn every_contract_flag_exists() {
        // CONTRACT 13.1 is a table, not a suggestion: if a flag is missing the
        // devnet scripts cannot run.
        for flag in [
            "config",
            "network",
            "datadir",
            "rpc-listen",
            "p2p-listen",
            "explorer-listen",
            "metrics-listen",
            "peer",
            "mine",
            "mine-address",
            "index",
            "consensus",
            "consensus-config",
            "validator-key",
            "log-format",
        ] {
            let found = NodeArgs::command()
                .get_arguments()
                .any(|a| a.get_long() == Some(flag));
            assert!(found, "chaind is missing --{flag}");
        }
    }

    #[test]
    fn an_unknown_flag_is_an_error() {
        assert!(NodeArgs::try_parse_from(["chaind", "--not-a-flag"]).is_err());
    }

    #[test]
    fn consensus_and_validator_key_round_trip() {
        let o = parse(&[
            "--consensus",
            "bft",
            "--consensus-config",
            "/etc/ferrum/consensus.toml",
            "--validator-key",
            "/etc/ferrum/validator.key",
        ])
        .overrides();
        assert_eq!(o.consensus.as_deref(), Some("bft"));
        assert_eq!(o.consensus_config, Some(PathBuf::from("/etc/ferrum/consensus.toml")));
        assert_eq!(o.validator_key, Some(PathBuf::from("/etc/ferrum/validator.key")));
    }
}
