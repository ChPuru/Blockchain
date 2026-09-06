//! The precedence engine: **CLI flag → `FERRUM_*` → config file → network
//! default**, applied one field at a time.
//!
//! Two properties are worth stating, because both are easy to get wrong and
//! neither shows up until an operator is on a call at midnight:
//!
//! 1. **Precedence is per field, not per layer.** A config file that sets
//!    `[rpc] listen` and a `--metrics-listen` flag must both take effect.
//! 2. **A layer that says nothing is silence, not `false`.** `--mine` absent
//!    does not disable a miner the config file enabled; only an explicit
//!    `enabled = false` does.
//!
//! Resolution is a pure function of its three arguments: it reads no file and
//! no process environment of its own. [`resolve_from_process`] is the one place
//! that does the I/O, so every rule above is testable with a `MapEnv` and a
//! `ConfigFile` literal.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use ferrum_crypto::Address;
use ferrum_p2p::Multiaddr;
use ferrum_types::{Amount, ChainParams, Network};

use crate::config::env::{
    ENV_CONFIG, ENV_CONSENSUS, ENV_CONSENSUS_CONFIG, ENV_DATADIR, ENV_EXPLORER_LISTEN, ENV_FAUCET,
    ENV_INDEX, ENV_LOG_FORMAT, ENV_METRICS_LISTEN, ENV_MINE, ENV_MINE_ADDRESS, ENV_NETWORK,
    ENV_P2P_LISTEN, ENV_PEERS, ENV_RPC_LISTEN, ENV_RPC_WS, ENV_VALIDATOR_KEY, Env, ProcessEnv,
    parse_bool, split_list,
};
use crate::config::file::{ConfigFile, ConsensusFile};
use crate::config::{CliOverrides, EngineChoice, LogFormat, NodeArgs, NodeConfig, field};
use crate::error::{ConfigError, ValueSource};

/// The default JSON-RPC port for node 1 of any network (CONTRACT §13.1).
pub const DEFAULT_RPC_PORT: u16 = 8645;
/// The default p2p port.
pub const DEFAULT_P2P_PORT: u16 = 8655;
/// The default explorer port.
pub const DEFAULT_EXPLORER_PORT: u16 = 8665;
/// The default Prometheus port, used only when metrics are switched on.
pub const DEFAULT_METRICS_PORT: u16 = 9100;

/// The bottom layer: what a network is worth defaulting to.
///
/// A real layer rather than a handful of literals scattered through
/// [`resolve`], so that "which layer decided this?" has an answer for every
/// field and a network can differ from its siblings without a new `if`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkDefaults {
    /// The network these defaults belong to.
    pub network: Network,
    /// `data/<network>`, relative to the working directory.
    pub datadir: PathBuf,
    /// Loopback by default: the RPC surface includes `submitblock`.
    pub rpc_listen: SocketAddr,
    /// WebSocket upgrades allowed on the RPC port.
    pub rpc_ws: bool,
    /// All interfaces: peers have to be able to reach the node.
    pub p2p_listen: Multiaddr,
    /// Loopback; put a reverse proxy in front to expose it.
    pub explorer_listen: SocketAddr,
    /// Off. Metrics are opt-in because the endpoint is unauthenticated.
    pub metrics_listen: Option<SocketAddr>,
    /// Mining off.
    pub mine: bool,
    /// One sealing thread.
    pub mining_threads: usize,
    /// Reverse index off: it is not consensus state and it costs disk.
    pub index: bool,
    /// Text logs.
    pub log_format: LogFormat,
    /// Faucet on for devnet only.
    pub faucet: bool,
}

impl NetworkDefaults {
    /// The defaults for one network.
    ///
    /// # Panics
    ///
    /// Never: the multiaddr and socket-address literals are compile-time
    /// constants of this crate, and the `expect` documents that.
    #[must_use]
    pub fn for_network(network: Network) -> Self {
        let p2p_listen = format!("/ip4/0.0.0.0/tcp/{DEFAULT_P2P_PORT}")
            .parse()
            .expect("the default p2p multiaddr literal is well formed");
        NetworkDefaults {
            network,
            // Relative, and per network, so two networks started from the same
            // shell never share a store. `docs/RUNNING.md` uses the same shape.
            datadir: PathBuf::from("data").join(network.to_string()),
            rpc_listen: SocketAddr::from(([127, 0, 0, 1], DEFAULT_RPC_PORT)),
            rpc_ws: true,
            p2p_listen,
            explorer_listen: SocketAddr::from(([127, 0, 0, 1], DEFAULT_EXPLORER_PORT)),
            metrics_listen: None,
            mine: false,
            mining_threads: 1,
            index: false,
            log_format: LogFormat::Text,
            // A devnet exists to be poked at; a public network's faucet is a
            // deliberate decision, never a default.
            faucet: matches!(network, Network::Devnet),
        }
    }
}

/// Which network the node is on, resolved before anything else.
///
/// It comes first because it selects the bottom layer: every other default is a
/// function of it.
fn resolve_network(
    cli: &CliOverrides,
    env: &dyn Env,
    file: Option<&ConfigFile>,
    sources: &mut BTreeMap<&'static str, ValueSource>,
) -> Result<Network, ConfigError> {
    let layers: [(ValueSource, Option<String>); 3] = [
        (ValueSource::Cli, cli.network.clone()),
        (ValueSource::Env, env.get(ENV_NETWORK)),
        (ValueSource::File, file.and_then(|f| f.network.clone())),
    ];
    for (layer, value) in layers {
        if let Some(text) = value {
            let network =
                Network::from_str(&text).map_err(|_| ConfigError::UnknownNetwork(text.clone()))?;
            sources.insert(field::NETWORK, layer);
            return Ok(network);
        }
    }
    sources.insert(field::NETWORK, ValueSource::Default);
    // Mainnet, as Bitcoin Core does: a node that silently joins a test network
    // when the operator meant the real one is the more expensive mistake.
    Ok(Network::Mainnet)
}

/// One field's worth of precedence.
///
/// Each layer has already been parsed into `Option<T>`, so this is only the
/// ordering rule — which is exactly the part that must not be re-implemented
/// sixteen times.
fn pick<T>(
    name: &'static str,
    sources: &mut BTreeMap<&'static str, ValueSource>,
    cli: Option<T>,
    env: Option<T>,
    file: Option<T>,
    default: T,
) -> T {
    let (layer, value) = match (cli, env, file) {
        (Some(v), _, _) => (ValueSource::Cli, v),
        (None, Some(v), _) => (ValueSource::Env, v),
        (None, None, Some(v)) => (ValueSource::File, v),
        (None, None, None) => (ValueSource::Default, default),
    };
    sources.insert(name, layer);
    value
}

/// Parse an optional string with `f`, tagging a failure with its layer.
fn parse_opt<T, F>(
    layer: ValueSource,
    key: &str,
    expected: &'static str,
    value: Option<String>,
    f: F,
) -> Result<Option<T>, ConfigError>
where
    F: FnOnce(&str) -> Option<T>,
{
    match value {
        None => Ok(None),
        Some(text) => match f(text.trim()) {
            Some(v) => Ok(Some(v)),
            None => {
                Err(ConfigError::Invalid { layer, key: key.to_owned(), value: text, expected })
            }
        },
    }
}

fn socket(s: &str) -> Option<SocketAddr> {
    s.parse().ok()
}

fn multiaddr(s: &str) -> Option<Multiaddr> {
    s.parse().ok()
}

/// Resolve a full configuration from the three upper layers.
///
/// Pure: no file is read and no process environment is consulted. The config
/// file, if there is one, has already been loaded by the caller — see
/// [`resolve_from_process`].
///
/// # Errors
///
/// [`ConfigError::UnknownNetwork`] for a bad network name,
/// [`ConfigError::Invalid`] for any value that will not parse, naming the layer
/// that supplied it, and [`ConfigError::AddressNetworkMismatch`] for a mining
/// address belonging to another chain.
pub fn resolve(
    cli: &CliOverrides,
    env: &dyn Env,
    file: Option<&ConfigFile>,
) -> Result<NodeConfig, ConfigError> {
    let mut sources: BTreeMap<&'static str, ValueSource> = BTreeMap::new();
    let network = resolve_network(cli, env, file, &mut sources)?;
    let defaults = NetworkDefaults::for_network(network);

    // ---- datadir -----------------------------------------------------------
    let datadir = pick(
        field::DATADIR,
        &mut sources,
        cli.datadir.clone(),
        env.get(ENV_DATADIR).map(PathBuf::from),
        file.and_then(|f| f.datadir.clone()),
        defaults.datadir.clone(),
    );

    // ---- rpc ---------------------------------------------------------------
    let rpc_listen = pick(
        field::RPC_LISTEN,
        &mut sources,
        parse_opt(ValueSource::Cli, "--rpc-listen", SOCKET, cli.rpc_listen.clone(), socket)?,
        parse_opt(ValueSource::Env, ENV_RPC_LISTEN, SOCKET, env.get(ENV_RPC_LISTEN), socket)?,
        parse_opt(
            ValueSource::File,
            "rpc.listen",
            SOCKET,
            file.and_then(|f| f.rpc.listen.clone()),
            socket,
        )?,
        defaults.rpc_listen,
    );
    let rpc_ws = pick(
        field::RPC_WS,
        &mut sources,
        None,
        parse_opt(ValueSource::Env, ENV_RPC_WS, BOOL, env.get(ENV_RPC_WS), parse_bool)?,
        file.and_then(|f| f.rpc.ws),
        defaults.rpc_ws,
    );

    // ---- p2p ---------------------------------------------------------------
    let p2p_listen = pick(
        field::P2P_LISTEN,
        &mut sources,
        parse_opt(ValueSource::Cli, "--p2p-listen", MULTIADDR, cli.p2p_listen.clone(), multiaddr)?,
        parse_opt(ValueSource::Env, ENV_P2P_LISTEN, MULTIADDR, env.get(ENV_P2P_LISTEN), multiaddr)?,
        parse_opt(
            ValueSource::File,
            "p2p.listen",
            MULTIADDR,
            file.and_then(|f| f.p2p.listen.clone()),
            multiaddr,
        )?,
        defaults.p2p_listen.clone(),
    );

    let cli_peers = parse_peers(ValueSource::Cli, "--peer", cli.peers.clone())?;
    let env_peers = parse_peers(
        ValueSource::Env,
        ENV_PEERS,
        env.get(ENV_PEERS)
            .map(|v| split_list(&v).into_iter().map(str::to_owned).collect::<Vec<_>>()),
    )?;
    let file_peers =
        parse_peers(ValueSource::File, "p2p.peers", file.and_then(|f| f.p2p.peers.clone()))?;
    let peers = pick(field::PEERS, &mut sources, cli_peers, env_peers, file_peers, Vec::new());

    // ---- explorer ----------------------------------------------------------
    let explorer_listen = pick(
        field::EXPLORER_LISTEN,
        &mut sources,
        parse_opt(
            ValueSource::Cli,
            "--explorer-listen",
            SOCKET,
            cli.explorer_listen.clone(),
            socket,
        )?,
        parse_opt(
            ValueSource::Env,
            ENV_EXPLORER_LISTEN,
            SOCKET,
            env.get(ENV_EXPLORER_LISTEN),
            socket,
        )?,
        parse_opt(
            ValueSource::File,
            "explorer.listen",
            SOCKET,
            file.and_then(|f| f.explorer.listen.clone()),
            socket,
        )?,
        defaults.explorer_listen,
    );
    let faucet = pick(
        field::FAUCET,
        &mut sources,
        cli.faucet,
        parse_opt(ValueSource::Env, ENV_FAUCET, BOOL, env.get(ENV_FAUCET), parse_bool)?,
        file.and_then(|f| f.explorer.faucet),
        defaults.faucet,
    );
    let faucet_amount = parse_opt(
        ValueSource::File,
        "explorer.faucet_amount",
        "decimal FRM amount",
        file.and_then(|f| f.explorer.faucet_amount.clone()),
        |s| Amount::from_frm_str(s).ok(),
    )?;
    if faucet_amount.is_some() {
        sources.insert(field::FAUCET_AMOUNT, ValueSource::File);
    } else {
        sources.insert(field::FAUCET_AMOUNT, ValueSource::Default);
    }

    // ---- telemetry ---------------------------------------------------------
    let metrics_listen = pick(
        field::METRICS_LISTEN,
        &mut sources,
        parse_opt(ValueSource::Cli, "--metrics-listen", SOCKET, cli.metrics_listen.clone(), socket)?
            .map(Some),
        parse_opt(
            ValueSource::Env,
            ENV_METRICS_LISTEN,
            SOCKET,
            env.get(ENV_METRICS_LISTEN),
            socket,
        )?
        .map(Some),
        parse_opt(
            ValueSource::File,
            "telemetry.metrics",
            SOCKET,
            file.and_then(|f| f.telemetry.metrics.clone()),
            socket,
        )?
        .map(Some),
        defaults.metrics_listen,
    );
    let log_format = pick(
        field::LOG_FORMAT,
        &mut sources,
        parse_opt(ValueSource::Cli, "--log-format", FORMAT, cli.log_format.clone(), LogFormat::parse)?,
        parse_opt(ValueSource::Env, ENV_LOG_FORMAT, FORMAT, env.get(ENV_LOG_FORMAT), LogFormat::parse)?,
        parse_opt(
            ValueSource::File,
            "telemetry.log_format",
            FORMAT,
            file.and_then(|f| f.telemetry.log_format.clone()),
            LogFormat::parse,
        )?,
        defaults.log_format,
    );

    // ---- mining ------------------------------------------------------------
    let mine = pick(
        field::MINE,
        &mut sources,
        cli.mine,
        parse_opt(ValueSource::Env, ENV_MINE, BOOL, env.get(ENV_MINE), parse_bool)?,
        file.and_then(|f| f.mining.enabled),
        defaults.mine,
    );
    let mine_address_text: Option<String> = pick(
        field::MINE_ADDRESS,
        &mut sources,
        cli.mine_address.clone().map(Some),
        env.get(ENV_MINE_ADDRESS).map(Some),
        file.and_then(|f| f.mining.address.clone()).map(Some),
        None,
    );
    let mine_address = match mine_address_text {
        None => None,
        Some(text) => {
            let address = Address::decode(&text)
                .map_err(|source| ConfigError::Address { address: text.clone(), source })?;
            if address.network != network {
                return Err(ConfigError::AddressNetworkMismatch {
                    address: text,
                    address_network: address.network.to_string(),
                    network: network.to_string(),
                });
            }
            Some(address)
        }
    };
    let mining_threads = pick(
        field::MINING_THREADS,
        &mut sources,
        None,
        None,
        // A thread count of zero is a typo, not "no threads"; fall through to
        // the default rather than starting a miner that never hashes.
        file.and_then(|f| f.mining.threads).filter(|n| *n > 0),
        defaults.mining_threads,
    );

    // ---- index -------------------------------------------------------------
    let index = pick(
        field::INDEX,
        &mut sources,
        cli.index,
        parse_opt(ValueSource::Env, ENV_INDEX, BOOL, env.get(ENV_INDEX), parse_bool)?,
        file.and_then(|f| f.index.transactions),
        defaults.index,
    );

    // ---- consensus ---------------------------------------------------------
    let consensus = pick(
        field::CONSENSUS,
        &mut sources,
        parse_opt(ValueSource::Cli, "--consensus", ENGINE, cli.consensus.clone(), EngineChoice::parse)?
            .map(Some),
        parse_opt(ValueSource::Env, ENV_CONSENSUS, ENGINE, env.get(ENV_CONSENSUS), EngineChoice::parse)?
            .map(Some),
        parse_opt(
            ValueSource::File,
            "consensus.engine",
            ENGINE,
            file.and_then(|f| f.consensus.engine.clone()),
            EngineChoice::parse,
        )?
        .map(Some),
        None,
    );
    let consensus_config = pick(
        field::CONSENSUS_CONFIG,
        &mut sources,
        cli.consensus_config.clone().map(Some),
        env.get(ENV_CONSENSUS_CONFIG).map(|v| Some(PathBuf::from(v))),
        file.and_then(|f| f.consensus.config.clone()).map(Some),
        None,
    );
    let validator_key = pick(
        field::VALIDATOR_KEY,
        &mut sources,
        cli.validator_key.clone().map(Some),
        env.get(ENV_VALIDATOR_KEY).map(|v| Some(PathBuf::from(v))),
        file.and_then(|f| f.consensus.validator_key.clone()).map(Some),
        None,
    );

    let params = ChainParams::by_name(&network.to_string())
        .map_err(|_| ConfigError::UnknownNetwork(network.to_string()))?;

    Ok(NodeConfig {
        network,
        params,
        datadir,
        config_path: None,
        rpc_listen,
        rpc_ws,
        p2p_listen,
        peers,
        explorer_listen,
        metrics_listen,
        mine,
        mine_address,
        mining_threads,
        index,
        consensus,
        consensus_config,
        validator_key,
        log_format,
        faucet,
        faucet_amount,
        sources,
    })
}

const SOCKET: &str = "ip:port socket address";
const MULTIADDR: &str = "libp2p multiaddr";
const BOOL: &str = "boolean (1/0, true/false, yes/no, on/off)";
const FORMAT: &str = "log format (text|json)";
const ENGINE: &str = "consensus engine (pow|bft)";

/// Parse a list of multiaddrs, tagging failures with their layer.
fn parse_peers(
    layer: ValueSource,
    key: &str,
    values: Option<Vec<String>>,
) -> Result<Option<Vec<Multiaddr>>, ConfigError> {
    let Some(values) = values else {
        return Ok(None);
    };
    if values.is_empty() {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let addr = value.trim().parse::<Multiaddr>().map_err(|_| ConfigError::Invalid {
            layer,
            key: key.to_owned(),
            value: value.clone(),
            expected: MULTIADDR,
        })?;
        out.push(addr);
    }
    Ok(Some(out))
}

/// Fold a `--consensus-config` file into an already-resolved configuration.
///
/// This is the M10 fork schedule and nothing else: an activation height and a
/// validator set. It is applied after resolution because it is *consensus*
/// data, kept in its own file so it can be distributed and diffed alone.
///
/// # Errors
///
/// [`ConfigError::ValidatorKey`] when a validator entry is not 32 hex bytes.
pub fn apply_consensus_file(
    config: &mut NodeConfig,
    consensus: &ConsensusFile,
) -> Result<(), ConfigError> {
    let validators = consensus.validators()?;
    if let Some(height) = consensus.bft_activation_height {
        config.params.bft_activation_height = Some(height);
    }
    if !validators.is_empty() {
        config.params.bft_validators = validators;
    }
    Ok(())
}

/// Resolve from a real command line and the real process environment.
///
/// This is the one function in the module that performs I/O: it reads the
/// config file named by `--config` or `FERRUM_CONFIG`, and the consensus file
/// named by `--consensus-config`.
///
/// # Errors
///
/// Everything [`resolve`] can return, plus [`ConfigError::ReadFile`] and
/// [`ConfigError::ParseFile`].
pub fn resolve_from_process(args: &NodeArgs) -> Result<NodeConfig, ConfigError> {
    let cli = args.overrides();
    let env = ProcessEnv;
    let config_path = cli.config.clone().or_else(|| env.get(ENV_CONFIG).map(PathBuf::from));
    let file = match &config_path {
        Some(path) => Some(ConfigFile::load(path)?),
        None => None,
    };
    let mut config = resolve(&cli, &env, file.as_ref())?;
    config.config_path = config_path;
    if let Some(path) = config.consensus_config.clone() {
        let consensus = ConsensusFile::load(&path)?;
        apply_consensus_file(&mut config, &consensus)?;
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_crypto::{PublicKey, SecretKey};

    use super::*;
    use crate::config::MapEnv;
    use crate::config::file::{
        ConsensusSection, ExplorerSection, IndexSection, MiningSection, P2pSection, RpcSection,
        TelemetrySection,
    };

    fn devnet_address() -> (Address, String) {
        let sk = SecretKey::from_bytes(&[7u8; 32]).unwrap();
        let pk: PublicKey = sk.public_key();
        let address = Address::p2pkh(Network::Devnet, &pk);
        let text = address.encode();
        (address, text)
    }

    fn cfg(cli: CliOverrides, env: MapEnv, file: Option<ConfigFile>) -> NodeConfig {
        resolve(&cli, &env, file.as_ref()).unwrap()
    }

    // ---------------------------------------------------------------- defaults

    #[test]
    fn with_nothing_set_every_field_is_a_network_default() {
        let c = cfg(CliOverrides::default(), MapEnv::new(), None);
        assert_eq!(c.network, Network::Mainnet);
        assert_eq!(c.rpc_listen, SocketAddr::from(([127, 0, 0, 1], 8645)));
        assert_eq!(c.explorer_listen, SocketAddr::from(([127, 0, 0, 1], 8665)));
        assert_eq!(c.p2p_listen.to_string(), "/ip4/0.0.0.0/tcp/8655");
        assert_eq!(c.metrics_listen, None);
        assert!(!c.mine);
        assert!(!c.index);
        assert_eq!(c.log_format, LogFormat::Text);
        assert_eq!(c.source_of(field::RPC_LISTEN), ValueSource::Default);
    }

    #[test]
    fn the_default_ports_are_the_ones_the_devnet_scripts_assume() {
        assert_eq!(DEFAULT_RPC_PORT, 8645);
        assert_eq!(DEFAULT_P2P_PORT, 8655);
        assert_eq!(DEFAULT_EXPLORER_PORT, 8665);
        assert_eq!(DEFAULT_METRICS_PORT, 9100);
    }

    #[test]
    fn the_datadir_default_is_per_network() {
        for network in [Network::Mainnet, Network::Testnet, Network::Devnet] {
            let d = NetworkDefaults::for_network(network);
            assert_eq!(d.datadir, PathBuf::from("data").join(network.to_string()));
        }
    }

    #[test]
    fn the_faucet_defaults_on_for_devnet_only() {
        assert!(NetworkDefaults::for_network(Network::Devnet).faucet);
        assert!(!NetworkDefaults::for_network(Network::Mainnet).faucet);
        assert!(!NetworkDefaults::for_network(Network::Testnet).faucet);
    }

    // ------------------------------------------------------------- precedence

    #[test]
    fn the_cli_beats_the_environment() {
        let c = cfg(
            CliOverrides { rpc_listen: Some("127.0.0.1:1111".to_owned()), ..Default::default() },
            MapEnv::new().with(ENV_RPC_LISTEN, "127.0.0.1:2222"),
            None,
        );
        assert_eq!(c.rpc_listen.port(), 1111);
        assert_eq!(c.source_of(field::RPC_LISTEN), ValueSource::Cli);
    }

    #[test]
    fn the_environment_beats_the_config_file() {
        let file = ConfigFile {
            rpc: RpcSection { listen: Some("127.0.0.1:3333".to_owned()), ws: None },
            ..Default::default()
        };
        let c = cfg(
            CliOverrides::default(),
            MapEnv::new().with(ENV_RPC_LISTEN, "127.0.0.1:2222"),
            Some(file),
        );
        assert_eq!(c.rpc_listen.port(), 2222);
        assert_eq!(c.source_of(field::RPC_LISTEN), ValueSource::Env);
    }

    #[test]
    fn the_config_file_beats_the_network_default() {
        let file = ConfigFile {
            rpc: RpcSection { listen: Some("127.0.0.1:3333".to_owned()), ws: None },
            ..Default::default()
        };
        let c = cfg(CliOverrides::default(), MapEnv::new(), Some(file));
        assert_eq!(c.rpc_listen.port(), 3333);
        assert_eq!(c.source_of(field::RPC_LISTEN), ValueSource::File);
    }

    #[test]
    fn the_full_chain_holds_for_one_field() {
        let file = ConfigFile {
            rpc: RpcSection { listen: Some("127.0.0.1:3333".to_owned()), ws: None },
            ..Default::default()
        };
        let env = MapEnv::new().with(ENV_RPC_LISTEN, "127.0.0.1:2222");
        let cli = CliOverrides { rpc_listen: Some("127.0.0.1:1111".to_owned()), ..Default::default() };

        assert_eq!(cfg(cli.clone(), env.clone(), Some(file.clone())).rpc_listen.port(), 1111);
        assert_eq!(
            cfg(CliOverrides::default(), env, Some(file.clone())).rpc_listen.port(),
            2222
        );
        assert_eq!(
            cfg(CliOverrides::default(), MapEnv::new(), Some(file)).rpc_listen.port(),
            3333
        );
        assert_eq!(cfg(CliOverrides::default(), MapEnv::new(), None).rpc_listen.port(), 8645);
    }

    #[test]
    fn precedence_is_per_field_not_per_layer() {
        // The file sets the explorer; the flag sets metrics. Both must survive.
        let file = ConfigFile {
            explorer: ExplorerSection {
                listen: Some("0.0.0.0:9999".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };
        let c = cfg(
            CliOverrides { metrics_listen: Some("127.0.0.1:9100".to_owned()), ..Default::default() },
            MapEnv::new(),
            Some(file),
        );
        assert_eq!(c.explorer_listen.port(), 9999);
        assert_eq!(c.metrics_listen.map(|a| a.port()), Some(9100));
        assert_eq!(c.source_of(field::EXPLORER_LISTEN), ValueSource::File);
        assert_eq!(c.source_of(field::METRICS_LISTEN), ValueSource::Cli);
    }

    #[test]
    fn the_network_itself_follows_the_same_precedence() {
        let file = ConfigFile { network: Some("mainnet".to_owned()), ..Default::default() };
        assert_eq!(
            cfg(CliOverrides::default(), MapEnv::new(), Some(file.clone())).network,
            Network::Mainnet
        );
        assert_eq!(
            cfg(CliOverrides::default(), MapEnv::new().with(ENV_NETWORK, "testnet"), Some(file.clone()))
                .network,
            Network::Testnet
        );
        assert_eq!(
            cfg(
                CliOverrides { network: Some("devnet".to_owned()), ..Default::default() },
                MapEnv::new().with(ENV_NETWORK, "testnet"),
                Some(file)
            )
            .network,
            Network::Devnet
        );
    }

    #[test]
    fn the_network_selects_the_parameter_set() {
        let c = cfg(
            CliOverrides { network: Some("devnet".to_owned()), ..Default::default() },
            MapEnv::new(),
            None,
        );
        assert_eq!(c.params, ChainParams::devnet());
        assert_eq!(c.params.chain_id, Network::Devnet.chain_id());
    }

    #[test]
    fn an_absent_mine_flag_does_not_disable_a_configured_miner() {
        let file = ConfigFile {
            mining: MiningSection { enabled: Some(true), ..Default::default() },
            ..Default::default()
        };
        let c = cfg(CliOverrides::default(), MapEnv::new(), Some(file));
        assert!(c.mine, "silence from the flag layer must not override the file");
        assert_eq!(c.source_of(field::MINE), ValueSource::File);
    }

    #[test]
    fn an_explicit_false_in_the_file_does_disable_the_miner() {
        let file = ConfigFile {
            mining: MiningSection { enabled: Some(false), ..Default::default() },
            ..Default::default()
        };
        let c = cfg(CliOverrides::default(), MapEnv::new(), Some(file));
        assert!(!c.mine);
    }

    #[test]
    fn the_environment_can_switch_mining_off_against_the_file() {
        let file = ConfigFile {
            mining: MiningSection { enabled: Some(true), ..Default::default() },
            ..Default::default()
        };
        let c = cfg(CliOverrides::default(), MapEnv::new().with(ENV_MINE, "0"), Some(file));
        assert!(!c.mine);
        assert_eq!(c.source_of(field::MINE), ValueSource::Env);
    }

    #[test]
    fn the_index_flag_follows_the_same_rule() {
        let file = ConfigFile {
            index: IndexSection { transactions: Some(true) },
            ..Default::default()
        };
        assert!(cfg(CliOverrides::default(), MapEnv::new(), Some(file.clone())).index);
        assert!(!cfg(CliOverrides::default(), MapEnv::new().with(ENV_INDEX, "false"), Some(file)).index);
        assert!(cfg(CliOverrides { index: Some(true), ..Default::default() }, MapEnv::new(), None).index);
    }

    #[test]
    fn peers_come_from_exactly_one_layer_never_a_merge() {
        // Merging peer lists across layers would make "remove a peer" impossible.
        let file = ConfigFile {
            p2p: P2pSection {
                listen: None,
                peers: Some(vec![
                    "/ip4/10.0.0.2/tcp/8655".to_owned(),
                    "/ip4/10.0.0.3/tcp/8655".to_owned(),
                ]),
            },
            ..Default::default()
        };
        let c = cfg(
            CliOverrides { peers: Some(vec!["/ip4/127.0.0.1/tcp/8656".to_owned()]), ..Default::default() },
            MapEnv::new(),
            Some(file),
        );
        assert_eq!(c.peers.len(), 1);
        assert_eq!(c.peers[0].to_string(), "/ip4/127.0.0.1/tcp/8656");
    }

    #[test]
    fn peers_can_come_from_a_comma_separated_environment_variable() {
        let c = cfg(
            CliOverrides::default(),
            MapEnv::new().with(ENV_PEERS, "/ip4/10.0.0.2/tcp/8655, /ip4/10.0.0.3/tcp/8655"),
            None,
        );
        assert_eq!(c.peers.len(), 2);
        assert_eq!(c.source_of(field::PEERS), ValueSource::Env);
    }

    #[test]
    fn the_log_format_follows_precedence() {
        let file = ConfigFile {
            telemetry: TelemetrySection { metrics: None, log_format: Some("json".to_owned()) },
            ..Default::default()
        };
        assert_eq!(
            cfg(CliOverrides::default(), MapEnv::new(), Some(file.clone())).log_format,
            LogFormat::Json
        );
        assert_eq!(
            cfg(
                CliOverrides { log_format: Some("text".to_owned()), ..Default::default() },
                MapEnv::new(),
                Some(file)
            )
            .log_format,
            LogFormat::Text
        );
    }

    #[test]
    fn metrics_stay_off_unless_a_listen_address_is_given() {
        assert_eq!(cfg(CliOverrides::default(), MapEnv::new(), None).metrics_listen, None);
        let c = cfg(
            CliOverrides::default(),
            MapEnv::new().with(ENV_METRICS_LISTEN, "127.0.0.1:9100"),
            None,
        );
        assert_eq!(c.metrics_listen.map(|a| a.port()), Some(9100));
    }

    #[test]
    fn the_forced_engine_follows_precedence() {
        let file = ConfigFile {
            consensus: ConsensusSection { engine: Some("pow".to_owned()), ..Default::default() },
            ..Default::default()
        };
        assert_eq!(
            cfg(CliOverrides::default(), MapEnv::new(), Some(file.clone())).consensus,
            Some(EngineChoice::Pow)
        );
        assert_eq!(
            cfg(
                CliOverrides { consensus: Some("bft".to_owned()), ..Default::default() },
                MapEnv::new(),
                Some(file)
            )
            .consensus,
            Some(EngineChoice::Bft)
        );
        assert_eq!(cfg(CliOverrides::default(), MapEnv::new(), None).consensus, None);
    }

    // ------------------------------------------------------------- rejections

    #[test]
    fn a_bad_socket_address_names_the_layer_that_supplied_it() {
        let e = resolve(
            &CliOverrides::default(),
            &MapEnv::new().with(ENV_RPC_LISTEN, "not-an-address"),
            None,
        )
        .unwrap_err();
        match e {
            ConfigError::Invalid { layer, key, .. } => {
                assert_eq!(layer, ValueSource::Env);
                assert_eq!(key, ENV_RPC_LISTEN);
            }
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn a_bad_multiaddr_from_the_command_line_names_the_flag() {
        let e = resolve(
            &CliOverrides { p2p_listen: Some("127.0.0.1:8655".to_owned()), ..Default::default() },
            &MapEnv::new(),
            None,
        )
        .unwrap_err();
        match e {
            ConfigError::Invalid { layer, key, .. } => {
                assert_eq!(layer, ValueSource::Cli);
                assert_eq!(key, "--p2p-listen");
            }
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn an_unknown_network_is_refused() {
        let e = resolve(
            &CliOverrides { network: Some("mainet".to_owned()), ..Default::default() },
            &MapEnv::new(),
            None,
        )
        .unwrap_err();
        assert!(matches!(e, ConfigError::UnknownNetwork(_)), "{e}");
    }

    #[test]
    fn a_boolean_typo_is_refused_rather_than_read_as_false() {
        let e =
            resolve(&CliOverrides::default(), &MapEnv::new().with(ENV_MINE, "maybe"), None)
                .unwrap_err();
        assert!(matches!(e, ConfigError::Invalid { .. }), "{e}");
    }

    #[test]
    fn a_mine_address_for_another_network_is_refused() {
        let (_, text) = devnet_address();
        let e = resolve(
            &CliOverrides { network: Some("mainnet".to_owned()), mine_address: Some(text), ..Default::default() },
            &MapEnv::new(),
            None,
        )
        .unwrap_err();
        assert!(matches!(e, ConfigError::AddressNetworkMismatch { .. }), "{e}");
    }

    #[test]
    fn a_mine_address_for_this_network_is_accepted() {
        let (address, text) = devnet_address();
        let c = cfg(
            CliOverrides {
                network: Some("devnet".to_owned()),
                mine_address: Some(text),
                ..Default::default()
            },
            MapEnv::new(),
            None,
        );
        assert_eq!(c.mine_address, Some(address));
    }

    #[test]
    fn an_undecodable_mine_address_is_refused() {
        let e = resolve(
            &CliOverrides {
                network: Some("devnet".to_owned()),
                mine_address: Some("not-an-address".to_owned()),
                ..Default::default()
            },
            &MapEnv::new(),
            None,
        )
        .unwrap_err();
        assert!(matches!(e, ConfigError::Address { .. }), "{e}");
    }

    #[test]
    fn no_mine_address_means_derive_one_from_the_node_key() {
        let c = cfg(
            CliOverrides { network: Some("devnet".to_owned()), mine: Some(true), ..Default::default() },
            MapEnv::new(),
            None,
        );
        assert!(c.mine);
        assert_eq!(c.mine_address, None, "a devnet must start with no wallet setup");
    }

    // -------------------------------------------------------- consensus file

    #[test]
    fn a_consensus_file_schedules_the_fork() {
        let mut c = cfg(CliOverrides::default(), MapEnv::new(), None);
        assert_eq!(c.params.bft_activation_height, None);
        let consensus = ConsensusFile {
            bft_activation_height: Some(50_000),
            bft_validators: vec!["ab".repeat(32); 4],
        };
        apply_consensus_file(&mut c, &consensus).unwrap();
        assert_eq!(c.params.bft_activation_height, Some(50_000));
        assert_eq!(c.params.bft_validators.len(), 4);
    }

    #[test]
    fn an_empty_consensus_file_changes_nothing() {
        let mut c = cfg(CliOverrides::default(), MapEnv::new(), None);
        let before = c.params.clone();
        apply_consensus_file(&mut c, &ConsensusFile::default()).unwrap();
        assert_eq!(c.params, before);
    }

    #[test]
    fn the_faucet_amount_is_parsed_as_an_integer_count_of_grains() {
        let file = ConfigFile {
            explorer: ExplorerSection {
                faucet_amount: Some("1.5".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };
        let c = cfg(CliOverrides::default(), MapEnv::new(), Some(file));
        assert_eq!(c.faucet_amount, Some(Amount::from_grains(150_000_000)));
    }

    #[test]
    fn a_malformed_faucet_amount_is_refused() {
        let file = ConfigFile {
            explorer: ExplorerSection {
                faucet_amount: Some("one and a half".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };
        let e = resolve(&CliOverrides::default(), &MapEnv::new(), Some(&file)).unwrap_err();
        assert!(matches!(e, ConfigError::Invalid { .. }), "{e}");
    }
}
