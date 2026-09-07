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
    /// A string and not a TOML float: a TOML float is a 64-bit binary float,
    /// and no monetary value in this workspace is ever carried by one.
    /// Parsed with `Amount::from_frm_str`, which is an integer-only parse.
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
            let bytes =
                hex::decode(trimmed).map_err(|_| ConfigError::ValidatorKey(entry.clone()))?;
            let array: [u8; 32] =
                bytes.try_into().map_err(|_| ConfigError::ValidatorKey(entry.clone()))?;
            out.push(ferrum_types::ValidatorId(array));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
