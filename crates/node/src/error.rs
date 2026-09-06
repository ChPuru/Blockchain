//! Every way the node can fail, named.
//!
//! Two enums rather than one. [`ConfigError`] is everything that can go wrong
//! *before* a single byte of chain state is touched — a bad flag, an
//! unparseable TOML file, an address for the wrong network — and it is the only
//! error an operator sees on a normal bad start. [`NodeError`] is everything
//! that can go wrong once the node is running.
//!
//! Keeping them apart is not tidiness: a configuration failure must exit with a
//! message an operator can act on without reading a stack of `From` conversions
//! from six other crates.

use std::path::PathBuf;

use ferrum_chain::ChainError;
use ferrum_consensus::ConsensusError;
use ferrum_crypto::CryptoError;
use ferrum_mempool::MempoolError;
use ferrum_p2p::P2pError;
use ferrum_rpc::RpcError;
use ferrum_storage::StorageError;
use ferrum_types::TypeError;
use ferrum_wallet::WalletError;

/// A failure while working out what this node is supposed to be.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The network name is not one of the three.
    #[error("unknown network {0:?}: expected mainnet, testnet or devnet")]
    UnknownNetwork(String),

    /// A value could not be parsed into the type the field needs.
    ///
    /// `source` names where the value came from — the flag, the environment
    /// variable or the config file — because "invalid listen address" without
    /// that is a twenty-minute hunt.
    #[error("{layer} {key} = {value:?} is not a valid {expected}")]
    Invalid {
        /// Which layer supplied the value.
        layer: ValueSource,
        /// The field name as that layer spells it.
        key: String,
        /// What was supplied.
        value: String,
        /// What was needed.
        expected: &'static str,
    },

    /// The config file could not be read.
    #[error("could not read the config file {path}")]
    ReadFile {
        /// The path that failed.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// The config file is not valid TOML, or has a field of the wrong type.
    #[error("could not parse the config file {path}: {source}")]
    ParseFile {
        /// The path that failed.
        path: PathBuf,
        /// The underlying parse failure.
        #[source]
        source: toml::de::Error,
    },

    /// `--mine-address` named an address on a different network.
    ///
    /// Mining to a mainnet address on devnet would silently pay a coinbase
    /// nobody can spend, so it is refused at startup rather than after a
    /// hundred blocks.
    #[error("mine address {address} is a {address_network} address but this node is on {network}")]
    AddressNetworkMismatch {
        /// The address as supplied.
        address: String,
        /// The network it encodes for.
        address_network: String,
        /// The network this node runs.
        network: String,
    },

    /// An address string could not be decoded at all.
    #[error("mine address {address:?} could not be decoded")]
    Address {
        /// The address as supplied.
        address: String,
        /// The decoding failure.
        #[source]
        source: CryptoError,
    },

    /// A validator key in the consensus config is not 32 hex-encoded bytes.
    #[error("validator key {0:?} is not 64 hex characters")]
    ValidatorKey(String),
}

/// Where a configuration value came from. Highest precedence first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValueSource {
    /// A command-line flag.
    Cli,
    /// A `FERRUM_*` environment variable.
    Env,
    /// The TOML config file.
    File,
    /// The network's built-in default.
    Default,
}

impl ValueSource {
    /// The word used in error messages and in `--dump-config` output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            ValueSource::Cli => "flag",
            ValueSource::Env => "environment variable",
            ValueSource::File => "config file field",
            ValueSource::Default => "network default",
        }
    }
}

impl std::fmt::Display for ValueSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A failure in a running node.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NodeError {
    /// The node could not be configured.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// The chain refused a block, a header or a template.
    #[error(transparent)]
    Chain(#[from] ChainError),

    /// The store failed.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// A consensus rule was broken outside `apply_block`.
    #[error(transparent)]
    Consensus(#[from] ConsensusError),

    /// The mempool refused a transaction.
    #[error(transparent)]
    Mempool(#[from] MempoolError),

    /// The networking stack failed.
    #[error(transparent)]
    P2p(#[from] P2pError),

    /// A key operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// A wallet or keychain operation failed.
    #[error(transparent)]
    Wallet(#[from] WalletError),

    /// A type could not be parsed or encoded.
    #[error(transparent)]
    Types(#[from] TypeError),

    /// An RPC or explorer listener failed.
    #[error(transparent)]
    Rpc(#[from] RpcError),

    /// A file operation failed, with the path that failed.
    ///
    /// `std::io::Error` alone does not say *which* file, and the answer is
    /// almost always the whole diagnosis.
    #[error("{context}: {source}")]
    Io {
        /// What was being attempted, including the path.
        context: String,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// The tracing subscriber or the metrics recorder could not be installed.
    #[error("telemetry: {0}")]
    Telemetry(String),

    /// A peer served something invalid and has been disconnected.
    #[error("peer {peer} served an invalid {what}: {reason}")]
    PeerMisbehaved {
        /// The peer, base58.
        peer: String,
        /// What it served: `header`, `block` or `transaction`.
        what: &'static str,
        /// Why it was rejected.
        reason: String,
    },

    /// A sync round could not be completed.
    #[error("sync: {0}")]
    Sync(String),

    /// A `spawn_blocking` task panicked or was cancelled.
    ///
    /// Every storage call from an `async fn` goes through `spawn_blocking`
    /// (CONTRACT §7), so this is the one place a panic in synchronous code
    /// surfaces as a value.
    #[error("background task failed: {0}")]
    Task(String),

    /// The node is shutting down and cannot service the request.
    #[error("the node is shutting down")]
    ShuttingDown,
}

impl NodeError {
    /// Wrap an I/O failure with the path that caused it.
    #[must_use]
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        NodeError::Io { context: context.into(), source }
    }

    /// Turn a `JoinError` from `spawn_blocking` into a typed failure.
    #[must_use]
    pub fn task(e: &tokio::task::JoinError) -> Self {
        NodeError::Task(e.to_string())
    }

    /// Whether this failure means the peer that caused it should be dropped.
    ///
    /// Serving an invalid header or block is misbehaviour (SPEC §12); a storage
    /// failure on our side is not, and disconnecting an honest peer because our
    /// own disk is full would turn a local fault into an isolation event.
    #[must_use]
    pub const fn is_peer_misbehaviour(&self) -> bool {
        matches!(self, NodeError::PeerMisbehaved { .. })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn value_sources_order_by_precedence() {
        assert!(ValueSource::Cli < ValueSource::Env);
        assert!(ValueSource::Env < ValueSource::File);
        assert!(ValueSource::File < ValueSource::Default);
    }

    #[test]
    fn value_source_labels_name_the_layer() {
        assert_eq!(ValueSource::Cli.to_string(), "flag");
        assert_eq!(ValueSource::Env.to_string(), "environment variable");
        assert_eq!(ValueSource::File.to_string(), "config file field");
        assert_eq!(ValueSource::Default.to_string(), "network default");
    }

    #[test]
    fn an_invalid_value_names_its_layer_and_its_key() {
        let e = ConfigError::Invalid {
            layer: ValueSource::Env,
            key: "FERRUM_RPC_LISTEN".to_owned(),
            value: "nope".to_owned(),
            expected: "ip:port socket address",
        };
        let text = e.to_string();
        assert!(text.contains("environment variable"), "{text}");
        assert!(text.contains("FERRUM_RPC_LISTEN"), "{text}");
        assert!(text.contains("nope"), "{text}");
    }

    #[test]
    fn io_errors_carry_the_path() {
        let e = NodeError::io(
            "reading /data/node.key",
            std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        );
        assert!(e.to_string().contains("/data/node.key"));
    }

    #[test]
    fn only_peer_misbehaviour_disconnects_a_peer() {
        let bad = NodeError::PeerMisbehaved {
            peer: "12D3Koo".to_owned(),
            what: "header",
            reason: "bad pow".to_owned(),
        };
        assert!(bad.is_peer_misbehaviour());
        assert!(!NodeError::ShuttingDown.is_peer_misbehaviour());
        assert!(!NodeError::Sync("timeout".to_owned()).is_peer_misbehaviour());
    }
}
