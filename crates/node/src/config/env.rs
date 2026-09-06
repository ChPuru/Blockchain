//! The `FERRUM_*` environment layer, and the seam that makes it testable.
//!
//! Reading `std::env::var` directly would make every precedence test mutate
//! process-global state, and `std::env::set_var` is neither thread-safe nor
//! ordered against the other tests in the same binary. So the environment is a
//! trait: production passes [`ProcessEnv`], tests pass a [`MapEnv`], and the
//! resolution code cannot tell the difference.

use std::collections::BTreeMap;

/// The environment, as configuration resolution sees it.
pub trait Env: std::fmt::Debug {
    /// The value of one variable, or `None` when it is unset or empty.
    ///
    /// An empty string counts as unset. `FERRUM_MINE_ADDRESS=` in a systemd
    /// unit file means "I did not set this", never "mine to the empty
    /// address".
    fn get(&self, key: &str) -> Option<String>;
}

/// The real process environment.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|v| !v.is_empty())
    }
}

/// A fixed environment, for tests and for `chaind --dump-config`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MapEnv {
    vars: BTreeMap<String, String>,
}

impl MapEnv {
    /// An empty environment.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set one variable, builder style.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.vars.insert(key.into(), value.into());
        self
    }

    /// Build from pairs.
    #[must_use]
    pub fn from_pairs<K: Into<String>, V: Into<String>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        let mut vars = BTreeMap::new();
        for (k, v) in pairs {
            vars.insert(k.into(), v.into());
        }
        MapEnv { vars }
    }
}

impl Env for MapEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.vars.get(key).filter(|v| !v.is_empty()).cloned()
    }
}

/// The prefix every Ferrum environment variable carries.
pub const ENV_PREFIX: &str = "FERRUM_";

/// Which network's [`ferrum_types::ChainParams`] to validate against.
pub const ENV_NETWORK: &str = "FERRUM_NETWORK";
/// The data directory holding the store, the node key and the keystore.
pub const ENV_DATADIR: &str = "FERRUM_DATADIR";
/// Path to the TOML config file.
pub const ENV_CONFIG: &str = "FERRUM_CONFIG";
/// JSON-RPC listen address, `ip:port`.
pub const ENV_RPC_LISTEN: &str = "FERRUM_RPC_LISTEN";
/// Whether the JSON-RPC listener accepts WebSocket upgrades.
pub const ENV_RPC_WS: &str = "FERRUM_RPC_WS";
/// p2p listen address, a multiaddr.
pub const ENV_P2P_LISTEN: &str = "FERRUM_P2P_LISTEN";
/// Comma-separated static peer multiaddrs.
pub const ENV_PEERS: &str = "FERRUM_PEERS";
/// Explorer REST listen address, `ip:port`.
pub const ENV_EXPLORER_LISTEN: &str = "FERRUM_EXPLORER_LISTEN";
/// Prometheus listen address, `ip:port`. Unset means metrics are off.
pub const ENV_METRICS_LISTEN: &str = "FERRUM_METRICS_LISTEN";
/// Whether to run the miner.
pub const ENV_MINE: &str = "FERRUM_MINE";
/// The address the miner pays.
pub const ENV_MINE_ADDRESS: &str = "FERRUM_MINE_ADDRESS";
/// Whether to maintain the transaction and address reverse index.
pub const ENV_INDEX: &str = "FERRUM_INDEX";
/// Force a consensus engine: `pow` or `bft`.
pub const ENV_CONSENSUS: &str = "FERRUM_CONSENSUS";
/// Path to the TOML file carrying `bft_activation_height` and validators.
pub const ENV_CONSENSUS_CONFIG: &str = "FERRUM_CONSENSUS_CONFIG";
/// Path to the BFT signing key.
pub const ENV_VALIDATOR_KEY: &str = "FERRUM_VALIDATOR_KEY";
/// Log format: `text` or `json`.
pub const ENV_LOG_FORMAT: &str = "FERRUM_LOG_FORMAT";
/// Whether the explorer serves the faucet.
pub const ENV_FAUCET: &str = "FERRUM_FAUCET";

/// Every variable the node reads, in the order it is documented.
///
/// A test asserts each one starts with [`ENV_PREFIX`]: a variable named
/// `RPC_LISTEN` would collide with half the software on a shared host.
pub const ALL_ENV_VARS: &[&str] = &[
    ENV_NETWORK,
    ENV_DATADIR,
    ENV_CONFIG,
    ENV_RPC_LISTEN,
    ENV_RPC_WS,
    ENV_P2P_LISTEN,
    ENV_PEERS,
    ENV_EXPLORER_LISTEN,
    ENV_METRICS_LISTEN,
    ENV_MINE,
    ENV_MINE_ADDRESS,
    ENV_INDEX,
    ENV_CONSENSUS,
    ENV_CONSENSUS_CONFIG,
    ENV_VALIDATOR_KEY,
    ENV_LOG_FORMAT,
    ENV_FAUCET,
];

/// Parse a boolean the way an operator writes one.
///
/// Deliberately a closed set: `FERRUM_MINE=maybe` is a typo, and silently
/// treating it as false gives a node that quietly never mines.
#[must_use]
pub fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Split a comma- or whitespace-separated list, dropping empty entries.
#[must_use]
pub fn split_list(value: &str) -> Vec<&str> {
    value.split([',', ' ', '\t', '\n']).map(str::trim).filter(|s| !s.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn every_variable_carries_the_ferrum_prefix() {
        for name in ALL_ENV_VARS {
            assert!(name.starts_with(ENV_PREFIX), "{name} would collide with unrelated software");
        }
    }

    #[test]
    fn variable_names_are_distinct() {
        let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
        for name in ALL_ENV_VARS {
            assert!(seen.insert(name, ()).is_none(), "{name} is listed twice");
        }
        assert_eq!(seen.len(), ALL_ENV_VARS.len());
    }

    #[test]
    fn an_empty_value_reads_as_unset() {
        let env = MapEnv::new().with(ENV_MINE_ADDRESS, "");
        assert_eq!(env.get(ENV_MINE_ADDRESS), None);
        assert_eq!(ProcessEnv.get("FERRUM_A_VARIABLE_THAT_IS_NOT_SET"), None);
    }

    #[test]
    fn booleans_accept_the_usual_spellings_and_reject_typos() {
        for yes in ["1", "true", "TRUE", "Yes", " on "] {
            assert_eq!(parse_bool(yes), Some(true), "{yes}");
        }
        for no in ["0", "false", "NO", "Off"] {
            assert_eq!(parse_bool(no), Some(false), "{no}");
        }
        for bad in ["maybe", "", "2", "t"] {
            assert_eq!(parse_bool(bad), None, "{bad}");
        }
    }

    #[test]
    fn lists_split_on_commas_and_whitespace() {
        assert_eq!(split_list("a,b , c"), vec!["a", "b", "c"]);
        assert_eq!(split_list("  "), Vec::<&str>::new());
        assert_eq!(split_list("solo"), vec!["solo"]);
        assert_eq!(split_list("a,,b"), vec!["a", "b"]);
    }

    #[test]
    fn a_map_env_answers_what_it_was_given() {
        let env = MapEnv::from_pairs([(ENV_NETWORK, "devnet"), (ENV_MINE, "1")]);
        assert_eq!(env.get(ENV_NETWORK).as_deref(), Some("devnet"));
        assert_eq!(env.get(ENV_MINE).as_deref(), Some("1"));
        assert_eq!(env.get(ENV_DATADIR), None);
    }
}
