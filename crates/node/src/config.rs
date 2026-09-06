//! What this node is: [`NodeConfig`], and the four layers that produce it.
//!
//! # Precedence
//!
//! **CLI flag → environment variable (`FERRUM_*`) → config file → network
//! default**, applied *per field*, highest first (CONTRACT §13, RUNNING §3).
//! Per field matters: a config file that sets `[rpc] listen` and a
//! `--metrics-listen` flag must both take effect, and an implementation that
//! picks a whole layer and ignores the rest silently loses one of them.
//!
//! This is the rule operators trip over, so it is tested one field at a time in
//! [`resolve`] rather than assumed.
//!
//! # Layout
//!
//! | Module | What it owns |
//! |---|---|
//! | [`args`] | the `clap` surface and the layer-neutral [`args::CliOverrides`] |
//! | [`env`] | the `FERRUM_*` names and the testable [`env::Env`] seam |
//! | [`file`] | the TOML shape, with unknown fields rejected |
//! | [`resolve`] | the precedence engine and the network defaults |

pub mod args;
pub mod env;
pub mod file;
pub mod resolve;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use ferrum_crypto::Address;
use ferrum_mempool::MempoolConfig;
use ferrum_p2p::{Keypair, Multiaddr, P2pConfig};
use ferrum_rpc::{ExplorerServerConfig, RpcServerConfig};
use ferrum_storage::StoreConfig;
use ferrum_types::{Amount, BlockSeal, ChainParams, Network};

pub use self::args::{CliOverrides, NodeArgs};
pub use self::env::{Env, MapEnv, ProcessEnv};
pub use self::file::{ConfigFile, ConsensusFile};
pub use self::resolve::{NetworkDefaults, resolve, resolve_from_process};
use crate::error::ValueSource;

/// How log lines are rendered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogFormat {
    /// Human-readable lines, the default. `devnet/heal.sh` greps these.
    #[default]
    Text,
    /// One JSON object per line, for a log collector.
    Json,
}

impl LogFormat {
    /// The spelling used on the command line and in the config file.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            LogFormat::Text => "text",
            LogFormat::Json => "json",
        }
    }

    /// Parse a spelling, case-insensitively.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "text" | "plain" => Some(LogFormat::Text),
            "json" => Some(LogFormat::Json),
            _ => None,
        }
    }
}

impl std::fmt::Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An engine pinned by `--consensus`, overriding the height-based router.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EngineChoice {
    /// Proof of work.
    Pow,
    /// Tendermint-shaped permissioned BFT.
    Bft,
}

impl EngineChoice {
    /// The spelling used on the command line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            EngineChoice::Pow => "pow",
            EngineChoice::Bft => "bft",
        }
    }

    /// The `BlockSeal::ENGINE_*` identifier.
    #[must_use]
    pub const fn engine_id(self) -> u8 {
        match self {
            EngineChoice::Pow => BlockSeal::ENGINE_POW,
            EngineChoice::Bft => BlockSeal::ENGINE_BFT,
        }
    }

    /// Parse a spelling, case-insensitively.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "pow" | "proof-of-work" => Some(EngineChoice::Pow),
            "bft" | "tendermint" => Some(EngineChoice::Bft),
            _ => None,
        }
    }
}

impl std::fmt::Display for EngineChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Field names used as keys in [`NodeConfig::sources`].
///
/// String keys rather than an enum so that `chaind --dump-config` can print a
/// table an operator can read without a legend.
pub mod field {
    /// `network`
    pub const NETWORK: &str = "network";
    /// `datadir`
    pub const DATADIR: &str = "datadir";
    /// `rpc.listen`
    pub const RPC_LISTEN: &str = "rpc.listen";
    /// `rpc.ws`
    pub const RPC_WS: &str = "rpc.ws";
    /// `p2p.listen`
    pub const P2P_LISTEN: &str = "p2p.listen";
    /// `p2p.peers`
    pub const PEERS: &str = "p2p.peers";
    /// `explorer.listen`
    pub const EXPLORER_LISTEN: &str = "explorer.listen";
    /// `explorer.faucet`
    pub const FAUCET: &str = "explorer.faucet";
    /// `explorer.faucet_amount`
    pub const FAUCET_AMOUNT: &str = "explorer.faucet_amount";
    /// `telemetry.metrics`
    pub const METRICS_LISTEN: &str = "telemetry.metrics";
    /// `telemetry.log_format`
    pub const LOG_FORMAT: &str = "telemetry.log_format";
    /// `mining.enabled`
    pub const MINE: &str = "mining.enabled";
    /// `mining.address`
    pub const MINE_ADDRESS: &str = "mining.address";
    /// `mining.threads`
    pub const MINING_THREADS: &str = "mining.threads";
    /// `index.transactions`
    pub const INDEX: &str = "index.transactions";
    /// `consensus.engine`
    pub const CONSENSUS: &str = "consensus.engine";
    /// `consensus.config`
    pub const CONSENSUS_CONFIG: &str = "consensus.config";
    /// `consensus.validator_key`
    pub const VALIDATOR_KEY: &str = "consensus.validator_key";
}

/// The file inside the data directory that holds the redb database.
pub const STORE_FILE: &str = "chain.redb";

/// The file inside the data directory that holds the node's own key.
///
/// One 32-byte seed, from which both the libp2p network identity and the
/// default mining key are derived down separate BIP-32 paths (CONTRACT §13.1).
pub const NODE_KEY_FILE: &str = "node.key";

/// A fully resolved node configuration.
///
/// Everything is decided here: no later code re-reads the environment, and no
/// later code guesses a default. That is what makes a misconfiguration a
/// startup error with a message instead of a surprise at block 3000.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeConfig {
    /// Which network this node validates for.
    pub network: Network,
    /// The consensus parameters, including any BFT schedule loaded from
    /// `--consensus-config`.
    pub params: ChainParams,
    /// Where the store, node key and keystore live.
    pub datadir: PathBuf,
    /// The config file that was read, if any.
    pub config_path: Option<PathBuf>,
    /// JSON-RPC listen address.
    pub rpc_listen: SocketAddr,
    /// Whether the JSON-RPC listener accepts WebSocket upgrades.
    pub rpc_ws: bool,
    /// p2p listen multiaddr.
    pub p2p_listen: Multiaddr,
    /// Static peers, in the order given.
    pub peers: Vec<Multiaddr>,
    /// Explorer REST and static-page listen address.
    pub explorer_listen: SocketAddr,
    /// Prometheus listen address. `None` means metrics are off.
    pub metrics_listen: Option<SocketAddr>,
    /// Whether to run the miner.
    pub mine: bool,
    /// The address the coinbase pays. `None` means "derive it from the node
    /// key", which is what makes a devnet startable with no wallet.
    pub mine_address: Option<Address>,
    /// How many sealing threads the miner runs.
    pub mining_threads: usize,
    /// Whether to maintain the transaction and address reverse index.
    pub index: bool,
    /// An engine pinned by `--consensus`.
    pub consensus: Option<EngineChoice>,
    /// The consensus parameter file, if one was named.
    pub consensus_config: Option<PathBuf>,
    /// The BFT signing key, if one was named.
    pub validator_key: Option<PathBuf>,
    /// How log lines are rendered.
    pub log_format: LogFormat,
    /// Whether the explorer serves the faucet.
    pub faucet: bool,
    /// The faucet payout.
    pub faucet_amount: Option<Amount>,
    /// Which layer decided each field. Keys are the constants in [`field`].
    pub sources: BTreeMap<&'static str, ValueSource>,
}

impl NodeConfig {
    /// The redb database path.
    #[must_use]
    pub fn store_path(&self) -> PathBuf {
        self.datadir.join(STORE_FILE)
    }

    /// The node key path, `<datadir>/node.key`.
    #[must_use]
    pub fn node_key_path(&self) -> PathBuf {
        self.datadir.join(NODE_KEY_FILE)
    }

    /// Which layer decided `field`, or [`ValueSource::Default`] if the field is
    /// unknown to the resolver.
    #[must_use]
    pub fn source_of(&self, field: &str) -> ValueSource {
        self.sources.get(field).copied().unwrap_or(ValueSource::Default)
    }

    /// The storage configuration this node opens its store with.
    #[must_use]
    pub fn store_config(&self) -> StoreConfig {
        StoreConfig {
            index_transactions: self.index,
            chain_id: Some(self.params.chain_id),
            cache_size_bytes: None,
        }
    }

    /// The mempool configuration, taking its relay floor from the params.
    #[must_use]
    pub fn mempool_config(&self) -> MempoolConfig {
        MempoolConfig::new(self.params.clone())
    }

    /// The p2p configuration, with the node's persisted network identity.
    #[must_use]
    pub fn p2p_config(&self, keypair: Keypair) -> P2pConfig {
        let mut cfg = P2pConfig::new(self.params.chain_id)
            .with_keypair(keypair)
            .with_listen_addr(self.p2p_listen.clone());
        cfg.static_peers = self.peers.clone();
        cfg
    }

    /// The JSON-RPC listener configuration.
    #[must_use]
    pub fn rpc_server_config(&self) -> RpcServerConfig {
        RpcServerConfig { websocket: self.rpc_ws, ..RpcServerConfig::at(self.rpc_listen) }
    }

    /// The explorer listener configuration.
    #[must_use]
    pub fn explorer_server_config(&self) -> ExplorerServerConfig {
        ExplorerServerConfig::at(self.explorer_listen)
    }

    /// Create the data directory if it does not exist.
    ///
    /// # Errors
    ///
    /// [`crate::NodeError::Io`] naming the directory that could not be created.
    pub fn ensure_datadir(&self) -> Result<(), crate::NodeError> {
        ensure_dir(&self.datadir)
    }
}

/// Create `dir` and its parents, reporting the path on failure.
///
/// # Errors
///
/// [`crate::NodeError::Io`] naming the directory.
pub fn ensure_dir(dir: &Path) -> Result<(), crate::NodeError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| crate::NodeError::io(format!("creating the data directory {}", dir.display()), e))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn log_formats_round_trip_through_their_spelling() {
        for f in [LogFormat::Text, LogFormat::Json] {
            assert_eq!(LogFormat::parse(f.as_str()), Some(f));
            assert_eq!(f.to_string(), f.as_str());
        }
        assert_eq!(LogFormat::parse("JSON"), Some(LogFormat::Json));
        assert_eq!(LogFormat::parse(" text "), Some(LogFormat::Text));
        assert_eq!(LogFormat::parse("yaml"), None);
        assert_eq!(LogFormat::default(), LogFormat::Text);
    }

    #[test]
    fn engine_choices_map_to_the_contract_seal_ids() {
        assert_eq!(EngineChoice::Pow.engine_id(), BlockSeal::ENGINE_POW);
        assert_eq!(EngineChoice::Bft.engine_id(), BlockSeal::ENGINE_BFT);
        assert_eq!(EngineChoice::parse("POW"), Some(EngineChoice::Pow));
        assert_eq!(EngineChoice::parse("bft"), Some(EngineChoice::Bft));
        assert_eq!(EngineChoice::parse("raft"), None);
    }

    #[test]
    fn paths_hang_off_the_datadir() {
        let cfg = resolve::resolve(
            &CliOverrides { datadir: Some(PathBuf::from("/srv/ferrum")), ..Default::default() },
            &MapEnv::new(),
            None,
        )
        .unwrap();
        assert_eq!(cfg.store_path(), PathBuf::from("/srv/ferrum").join(STORE_FILE));
        assert_eq!(cfg.node_key_path(), PathBuf::from("/srv/ferrum").join(NODE_KEY_FILE));
    }

    #[test]
    fn the_store_config_follows_the_index_flag_and_binds_the_chain_id() {
        let cfg = resolve::resolve(
            &CliOverrides { index: Some(true), ..Default::default() },
            &MapEnv::new(),
            None,
        )
        .unwrap();
        let store = cfg.store_config();
        assert!(store.index_transactions);
        assert_eq!(store.chain_id, Some(cfg.params.chain_id));
    }

    #[test]
    fn the_p2p_config_carries_the_listen_address_and_the_peers() {
        let cfg = resolve::resolve(
            &CliOverrides {
                p2p_listen: Some("/ip4/127.0.0.1/tcp/9999".to_owned()),
                peers: Some(vec!["/ip4/10.0.0.2/tcp/8655".to_owned()]),
                ..Default::default()
            },
            &MapEnv::new(),
            None,
        )
        .unwrap();
        let p2p = cfg.p2p_config(Keypair::generate_ed25519());
        assert_eq!(p2p.listen_addrs.len(), 1);
        assert_eq!(p2p.static_peers.len(), 1);
        assert_eq!(p2p.chain_id, cfg.params.chain_id);
    }

    #[test]
    fn the_rpc_config_honours_the_websocket_switch() {
        let cfg = resolve::resolve(&CliOverrides::default(), &MapEnv::new(), None).unwrap();
        assert!(cfg.rpc_server_config().websocket);
        let file = ConfigFile { rpc: file::RpcSection { ws: Some(false), ..Default::default() }, ..Default::default() };
        let cfg = resolve::resolve(&CliOverrides::default(), &MapEnv::new(), Some(&file)).unwrap();
        assert!(!cfg.rpc_server_config().websocket);
    }
}
