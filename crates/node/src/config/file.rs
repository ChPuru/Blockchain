//! The TOML config file, exactly as `docs/RUNNING.md` §3 documents it.
//!
//! Every field is optional, because the file is only one of four layers and a
//! field it omits is answered by the network default. Unknown fields are
//! **rejected**: a mistyped `[minning]` section that is silently ignored gives
//! an operator a node that does not mine and a config file that says it does.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::ConfigError;

/// The whole config file.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    /// `mainnet` | `testnet` | `devnet`.
    pub network: Option<String>,
    /// Where the store, node key and keystore live.
    pub datadir: Option<PathBuf>,
    /// `[p2p]`.
    #[serde(default)]
    pub p2p: P2pSection,
    /// `[rpc]`.
    #[serde(default)]
    pub rpc: RpcSection,
    /// `[explorer]`.
    #[serde(default)]
    pub explorer: ExplorerSection,
    /// `[mining]`.
    #[serde(default)]
    pub mining: MiningSection,
    /// `[index]`.
    #[serde(default)]
    pub index: IndexSection,
    /// `[telemetry]`.
    #[serde(default)]
    pub telemetry: TelemetrySection,
    /// `[consensus]`.
    #[serde(default)]
    pub consensus: ConsensusSection,
}

/// `[p2p]`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct P2pSection {
    /// Listen multiaddr, for example `/ip4/0.0.0.0/tcp/8655`.
    pub listen: Option<String>,
    /// The static peer list. Ferrum has no peer discovery by design.
    pub peers: Option<Vec<String>>,
}

/// `[rpc]`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RpcSection {
    /// `ip:port` to bind the JSON-RPC listener to.
    pub listen: Option<String>,
    /// Whether to accept WebSocket upgrades on the same port.
    pub ws: Option<bool>,
}

/// `[explorer]`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExplorerSection {
    /// `ip:port` for the REST surface and the static page.
    pub listen: Option<String>,
    /// Whether `POST /api/faucet` is served.
    pub faucet: Option<bool>,
    /// Faucet payout, in FRM, as a decimal **string**.
    ///
    /// A string and not a float: a TOML float is a `f64`, and no monetary
    /// value in this workspace is ever carried by one.
    pub faucet_amount: Option<String>,
}

/// `[mining]`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MiningSection {
    /// Whether to run the miner.
    pub enabled: Option<bool>,
    /// The bech32m address the coinbase pays.
    pub address: Option<String>,
    /// How many sealing threads to run.
    pub threads: Option<usize>,
}

/// `[index]`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IndexSection {
    /// Maintain `tx_index` and `addr_index`. Not consensus state.
    pub transactions: Option<bool>,
}

/// `[telemetry]`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySection {
    /// `ip:port` for the Prometheus scrape endpoint. Absent means off.
    pub metrics: Option<String>,
    /// `text` | `json`.
    pub log_format: Option<String>,
}

/// `[consensus]`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusSection {
    /// Force an engine: `pow` | `bft`.
    pub engine: Option<String>,
    /// Path to the consensus parameter file ([`ConsensusFile`]).
    pub config: Option<PathBuf>,
    /// Path to the BFT signing key.
    pub validator_key: Option<PathBuf>,
}

impl ConfigFile {
    /// Parse a config file from TOML text.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ParseFile`] for malformed TOML, a field of the wrong
    /// type, or an unknown field.
    pub fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        toml::from_str(text)
            .map_err(|source| ConfigError::ParseFile { path: path.to_path_buf(), source })
    }

    /// Read and parse a config file.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ReadFile`] when the file cannot be read and
    /// [`ConfigError::ParseFile`] when it cannot be parsed.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|source| ConfigError::ReadFile { path: path.to_path_buf(), source })?;
        ConfigFile::parse(&text, path)
    }
}

/// The `--consensus-config` file: what the M10 fork is scheduled as.
///
/// Separate from [`ConfigFile`] because it is *consensus* data. Everything in
/// it changes which blocks are valid, so it is kept in its own file that can be
/// distributed and diffed on its own.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusFile {
    /// Height at and above which the BFT engine validates.
    pub bft_activation_height: Option<u64>,
    /// The permissioned validator set, each a 64-character hex x-only key.
    #[serde(default)]
    pub bft_validators: Vec<String>,
}

impl ConsensusFile {
    /// Parse from TOML text.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ParseFile`] as [`ConfigFile::parse`].
    pub fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        toml::from_str(text)
            .map_err(|source| ConfigError::ParseFile { path: path.to_path_buf(), source })
    }

    /// Read and parse the file.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ReadFile`] and [`ConfigError::ParseFile`].
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|source| ConfigError::ReadFile { path: path.to_path_buf(), source })?;
        ConsensusFile::parse(&text, path)
    }

    /// Decode the validator set into [`ferrum_types::ValidatorId`]s.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ValidatorKey`] when an entry is not 32 hex-encoded
    /// bytes.
    pub fn validators(&self) -> Result<Vec<ferrum_types::ValidatorId>, ConfigError> {
        let mut out = Vec::with_capacity(self.bft_validators.len());
        for entry in &self.bft_validators {
            let trimmed = entry.strip_prefix("0x").unwrap_or(entry);
            let bytes = hex::decode(trimmed)
                .map_err(|_| ConfigError::ValidatorKey(entry.clone()))?;
            let array: [u8; 32] =
                bytes.try_into().map_err(|_| ConfigError::ValidatorKey(entry.clone()))?;
            out.push(ferrum_types::ValidatorId(array));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn p() -> PathBuf {
        PathBuf::from("ferrum.toml")
    }

    #[test]
    fn the_documented_example_parses() {
        // Verbatim from docs/RUNNING.md section 3.
        let text = r#"
network  = "devnet"
datadir  = "./data"

[p2p]
listen   = "/ip4/0.0.0.0/tcp/8655"
peers    = ["/ip4/10.0.0.2/tcp/8655", "/ip4/10.0.0.3/tcp/8655"]

[rpc]
listen   = "127.0.0.1:8645"
ws       = true

[explorer]
listen   = "0.0.0.0:8665"
faucet   = true
faucet_amount = "1.0"

[mining]
enabled  = false
address  = "fer1qexample"
threads  = 4

[index]
transactions = true

[telemetry]
metrics  = "127.0.0.1:9100"
log_format = "json"
"#;
        let cfg = ConfigFile::parse(text, &p()).unwrap();
        assert_eq!(cfg.network.as_deref(), Some("devnet"));
        assert_eq!(cfg.datadir, Some(PathBuf::from("./data")));
        assert_eq!(cfg.p2p.peers.as_ref().map(Vec::len), Some(2));
        assert_eq!(cfg.rpc.ws, Some(true));
        assert_eq!(cfg.explorer.faucet_amount.as_deref(), Some("1.0"));
        assert_eq!(cfg.mining.threads, Some(4));
        assert_eq!(cfg.index.transactions, Some(true));
        assert_eq!(cfg.telemetry.log_format.as_deref(), Some("json"));
    }

    #[test]
    fn an_empty_file_is_valid_and_sets_nothing() {
        let cfg = ConfigFile::parse("", &p()).unwrap();
        assert_eq!(cfg, ConfigFile::default());
    }

    #[test]
    fn an_unknown_field_is_rejected_rather_than_ignored() {
        let e = ConfigFile::parse("netwrok = \"devnet\"\n", &p()).unwrap_err();
        assert!(matches!(e, ConfigError::ParseFile { .. }), "{e}");
    }

    #[test]
    fn an_unknown_section_is_rejected() {
        let e = ConfigFile::parse("[minning]\nenabled = true\n", &p()).unwrap_err();
        assert!(matches!(e, ConfigError::ParseFile { .. }), "{e}");
    }

    #[test]
    fn a_field_of_the_wrong_type_is_rejected() {
        let e = ConfigFile::parse("[rpc]\nws = \"yes\"\n", &p()).unwrap_err();
        assert!(matches!(e, ConfigError::ParseFile { .. }), "{e}");
    }

    #[test]
    fn reading_a_missing_file_names_the_path() {
        let e = ConfigFile::load(Path::new("definitely-not-here.toml")).unwrap_err();
        match e {
            ConfigError::ReadFile { path, .. } => {
                assert_eq!(path, PathBuf::from("definitely-not-here.toml"));
            }
            other => panic!("expected ReadFile, got {other}"),
        }
    }

    #[test]
    fn a_consensus_file_decodes_its_validator_set() {
        let key = "ab".repeat(32);
        let text = format!("bft_activation_height = 50000\nbft_validators = [\"{key}\"]\n");
        let cfg = ConsensusFile::parse(&text, &p()).unwrap();
        assert_eq!(cfg.bft_activation_height, Some(50_000));
        let validators = cfg.validators().unwrap();
        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0].0, [0xabu8; 32]);
    }

    #[test]
    fn a_short_validator_key_is_rejected() {
        let cfg = ConsensusFile::parse("bft_validators = [\"abcd\"]\n", &p()).unwrap();
        assert!(matches!(cfg.validators(), Err(ConfigError::ValidatorKey(_))));
    }

    #[test]
    fn a_non_hex_validator_key_is_rejected() {
        let cfg = ConsensusFile::parse("bft_validators = [\"zz\"]\n", &p()).unwrap();
        assert!(matches!(cfg.validators(), Err(ConfigError::ValidatorKey(_))));
    }
}
