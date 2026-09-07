//! `chaind`: parse the arguments, resolve them, run the node.
//!
//! Deliberately thin. Everything a node *is* — the store, the chain, the
//! swarm, the relay, the miner, both listeners, the shutdown path — lives in
//! `ferrum-node`, and this module is the seam between an argument vector and
//! [`ferrum_node::Node`]. CONTRACT §13 pairs the two crates that way, and the
//! reason is worth stating: a node runtime that can only be started by
//! spawning a process is a node runtime nobody can write a test against.
//! `ferrum-node` can be driven from a test; `chaind` is what a human types.
//!
//! The one thing added here is `--print-config`. Four layers decide every
//! setting — CLI flag, `FERRUM_*`, config file, network default — and the
//! first question an operator asks when a node binds the wrong port is "which
//! layer won?". `ferrum_node::NodeConfig` records that per field in
//! [`ferrum_node::NodeConfig::source_of`], so answering it costs one flag.

use clap::Parser;
use ferrum_crypto::Address;
use ferrum_node::config::field;
use ferrum_node::{EngineChoice, Node, NodeArgs, NodeConfig, resolve_from_process};
use serde_json::{Map, Value, json};

use crate::error::{CliError, CliResult};

/// The `chaind` command line.
///
/// [`NodeArgs`] is flattened in rather than restated, so the flags CONTRACT
/// §13.1 fixes have exactly one definition, in the crate that consumes them.
#[derive(Debug, Parser)]
#[command(
    name = "chaind",
    version,
    about = "Ferrum node: validation, sync, mining, JSON-RPC and the explorer",
    long_about = "Precedence for every setting: CLI flag > environment (FERRUM_*) > \
                  config file > network default.\n\
                  Run with --print-config to see which of the four decided each one."
)]
pub struct ChaindArgs {
    /// Every flag CONTRACT §13.1 defines.
    #[command(flatten)]
    pub node: NodeArgs,

    /// Resolve the configuration, print it as JSON with the layer that decided
    /// each field, and exit without touching the store.
    #[arg(long)]
    pub print_config: bool,
}

/// Resolve the command line into a node configuration.
///
/// # Errors
///
/// [`CliError::Config`] for an unknown network, an unparseable listen address,
/// a malformed config file or a validator key that is not a point on the
/// curve.
pub fn resolve(args: &ChaindArgs) -> CliResult<NodeConfig> {
    resolve_from_process(&args.node).map_err(|e| CliError::Config(Box::new(e)))
}

/// The resolved configuration as JSON, with the deciding layer for each field.
///
/// Field names are the ones `RUNNING.md` §3 uses for the config file, so the
/// output can be read straight against the file that produced it.
#[must_use]
pub fn describe(config: &NodeConfig) -> Value {
    let mut out = Map::new();
    let mut put = |key: &str, value: Value| {
        out.insert(key.to_owned(), value);
    };

    put("network", json!(config.network.name()));
    put("chain_id", json!(config.params.chain_id.to_u32()));
    put("datadir", json!(config.datadir.display().to_string()));
    put("config_path", json!(config.config_path.as_ref().map(|p| p.display().to_string())));
    put("rpc_listen", json!(config.rpc_listen.to_string()));
    put("rpc_ws", json!(config.rpc_ws));
    put("p2p_listen", json!(config.p2p_listen.to_string()));
    put("explorer_listen", json!(config.explorer_listen.to_string()));
    put("metrics_listen", json!(config.metrics_listen.map(|a| a.to_string())));
    put("peers", json!(config.peers.iter().map(ToString::to_string).collect::<Vec<_>>()));
    put("mine", json!(config.mine));
    put("mine_address", json!(config.mine_address.as_ref().map(Address::encode)));
    put("mining_threads", json!(config.mining_threads));
    put("index", json!(config.index));
    put("consensus", json!(config.consensus.map(EngineChoice::as_str)));
    put(
        "consensus_config",
        json!(config.consensus_config.as_ref().map(|p| p.display().to_string())),
    );
    put("validator_key", json!(config.validator_key.as_ref().map(|p| p.display().to_string())));
    put("log_format", json!(config.log_format.as_str()));
    put("faucet", json!(config.faucet));
    put("bft_activation_height", json!(config.params.bft_activation_height));
    put("bft_validators", json!(config.params.bft_validators.len()));
    put("store_path", json!(config.store_path().display().to_string()));
    put("node_key_path", json!(config.node_key_path().display().to_string()));

    // Which of the four layers decided each field. This is the whole reason
    // `--print-config` exists: "why is it listening there?" has one answer and
    // it is in the resolver, not in the operator's memory of what they typed.
    let mut sources = Map::new();
    for name in [
        field::NETWORK,
        field::DATADIR,
        field::RPC_LISTEN,
        field::P2P_LISTEN,
        field::PEERS,
        field::EXPLORER_LISTEN,
        field::METRICS_LISTEN,
        field::MINE,
        field::MINE_ADDRESS,
        field::INDEX,
        field::LOG_FORMAT,
        field::CONSENSUS,
    ] {
        sources.insert(name.to_owned(), json!(config.source_of(name).to_string()));
    }
    put("sources", Value::Object(sources));

    Value::Object(out)
}

/// Resolve, start the logger, and run the node until it is signalled.
///
/// # Errors
///
/// [`CliError::Config`] when the configuration will not resolve, and
/// [`CliError::Node`] when the node will not start — an unusable datadir, a
/// store belonging to another chain, a listen address already in use.
pub async fn run(args: ChaindArgs) -> CliResult<()> {
    let config = resolve(&args)?;

    // Logging before anything else that can fail: a startup error the operator
    // cannot see is a startup error they cannot fix. `init_tracing` reports
    // `Ok(false)` when a subscriber already exists rather than failing, which
    // is what makes this callable from a test binary.
    ferrum_node::init_tracing(config.log_format).map_err(|e| CliError::Node(Box::new(e)))?;

    if args.print_config {
        let text = serde_json::to_string_pretty(&describe(&config))
            .map_err(|e| CliError::internal(format!("cannot render the configuration: {e}")))?;
        println!("{text}");
        return Ok(());
    }

    let node = Node::start(config).await.map_err(|e| CliError::Node(Box::new(e)))?;
    if let Some(addr) = node.rpc_addr() {
        tracing::info!(%addr, "json-rpc listening");
    }
    if let Some(addr) = node.explorer_addr() {
        tracing::info!(%addr, "explorer listening");
    }
    if let Some(address) = node.mining_address() {
        tracing::info!(%address, "mining");
    }
    node.run().await.map_err(|e| CliError::Node(Box::new(e)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use clap::CommandFactory as _;

    fn args(argv: &[&str]) -> ChaindArgs {
        let mut full = vec!["chaind"];
        full.extend_from_slice(argv);
        ChaindArgs::try_parse_from(full).unwrap()
    }

    #[test]
    fn the_command_tree_is_internally_consistent() {
        ChaindArgs::command().debug_assert();
    }

    #[test]
    fn the_devnet_invocation_parses_flag_for_flag() {
        // `start_node` from devnet/lib.sh, verbatim.
        let parsed = args(&[
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
        ]);
        assert_eq!(parsed.node.network.as_deref(), Some("devnet"));
        assert_eq!(parsed.node.peer.len(), 2);
        assert!(parsed.node.mine);
        assert!(parsed.node.index);
        assert!(parsed.node.mine_address.is_none());
        assert!(!parsed.print_config);
    }

    #[test]
    fn the_fork_rehearsal_invocation_parses_flag_for_flag() {
        // The restart loop in devnet/fork.sh.
        let parsed = args(&[
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
        ]);
        assert!(parsed.node.consensus_config.is_some());
        assert!(parsed.node.validator_key.is_some());
    }

    #[test]
    fn resolving_nothing_gives_the_contract_defaults() {
        let config = resolve(&args(&[])).unwrap();
        assert_eq!(config.rpc_listen.to_string(), "127.0.0.1:8645");
        assert_eq!(config.p2p_listen.to_string(), "/ip4/0.0.0.0/tcp/8655");
        assert_eq!(config.explorer_listen.to_string(), "127.0.0.1:8665");
        assert!(config.metrics_listen.is_none());
    }

    #[test]
    fn describe_reports_every_field_and_where_it_came_from() {
        let dir = tempfile::tempdir().unwrap();
        let config =
            resolve(&args(&["--network", "devnet", "--datadir", dir.path().to_str().unwrap()]))
                .unwrap();
        let described = describe(&config);
        assert_eq!(described["network"], "devnet");
        assert_eq!(described["chain_id"], 3);
        assert_eq!(described["sources"]["network"], "flag");
        assert_eq!(described["sources"]["datadir"], "flag");
        // Untouched fields fall through to the network default.
        assert_eq!(described["sources"]["rpc.listen"], "network default");
        assert!(described["store_path"].as_str().unwrap_or_default().ends_with("chain.redb"));
        assert!(described["node_key_path"].as_str().unwrap_or_default().ends_with("node.key"));
    }

    #[test]
    fn an_unknown_network_is_refused_by_name() {
        let err = resolve(&args(&["--network", "bitcoin"])).unwrap_err();
        assert!(err.to_string().contains("network"), "{err}");
    }

    #[test]
    fn an_unusable_listen_address_is_refused_by_name() {
        let err = resolve(&args(&["--rpc-listen", "localhost"])).unwrap_err();
        assert!(err.to_string().contains("rpc-listen"), "{err}");
    }

    #[test]
    fn a_cli_flag_beats_a_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ferrum.toml");
        std::fs::write(&path, "network = \"testnet\"\n[rpc]\nlisten = \"127.0.0.1:19999\"\n")
            .unwrap();

        let from_file = resolve(&args(&["--config", path.to_str().unwrap()])).unwrap();
        assert_eq!(from_file.network.name(), "testnet");
        assert_eq!(from_file.rpc_listen.port(), 19_999);

        let overridden = resolve(&args(&[
            "--config",
            path.to_str().unwrap(),
            "--network",
            "devnet",
            "--rpc-listen",
            "127.0.0.1:18888",
        ]))
        .unwrap();
        assert_eq!(overridden.network.name(), "devnet");
        assert_eq!(overridden.rpc_listen.port(), 18_888);
        assert_eq!(describe(&overridden)["sources"]["rpc.listen"], "flag");
    }
}
