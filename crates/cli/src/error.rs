//! The one error type both binaries return.
//!
//! Every failure path ends here, and `main` turns it into a message on
//! **stderr** and a non-zero exit code (CONTRACT §13.1). Nothing is printed to
//! stdout on failure: the devnet scripts read stdout with `| tail -1`, and a
//! diagnostic on that stream would be parsed as the value.

use std::path::PathBuf;

/// Anything that can go wrong in `chaind` or `chain-cli`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CliError {
    /// A file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// An I/O failure with no path worth naming (a terminal read, mostly).
    #[error("i/o error: {0}")]
    BareIo(#[from] std::io::Error),

    /// A command-line or config-file value did not parse.
    #[error("invalid {what}: {value} ({reason})")]
    Invalid {
        /// The name of the thing being parsed, e.g. `--amount`.
        what: &'static str,
        /// What the user supplied.
        value: String,
        /// Why it was refused.
        reason: String,
    },

    /// The user asked for something that is not there.
    #[error("{0}")]
    NotFound(String),

    /// A TOML config file did not parse.
    #[error("{path}: {source}")]
    Toml {
        /// The config file.
        path: PathBuf,
        /// The parse failure.
        #[source]
        source: toml::de::Error,
    },

    /// The node answered, but with an error.
    #[error("rpc call `{method}` failed: {source}")]
    Rpc {
        /// The JSON-RPC method that failed.
        method: &'static str,
        /// The transport or server error.
        #[source]
        source: jsonrpsee::core::ClientError,
    },

    /// The node could not be reached at all.
    #[error("cannot reach a node at {url}: {source}")]
    RpcConnect {
        /// The endpoint that was tried.
        url: String,
        /// Why the connection failed.
        #[source]
        source: jsonrpsee::core::ClientError,
    },

    /// A wallet operation failed.
    #[error(transparent)]
    Wallet(#[from] ferrum_wallet::WalletError),

    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] ferrum_crypto::CryptoError),

    /// A script failed to build, parse or evaluate.
    #[error(transparent)]
    Script(#[from] ferrum_script::ScriptError),

    /// A consensus type refused a value.
    #[error(transparent)]
    Types(#[from] ferrum_types::TypeError),

    /// The store refused an operation.
    #[error(transparent)]
    Storage(#[from] ferrum_storage::StorageError),

    /// The chain refused an operation.
    #[error(transparent)]
    Chain(#[from] ferrum_chain::ChainError),

    /// A consensus rule or engine refused an operation.
    #[error(transparent)]
    Consensus(#[from] ferrum_consensus::ConsensusError),

    /// The RPC or explorer listener could not be started.
    #[error(transparent)]
    Server(#[from] ferrum_rpc::RpcError),

    /// `chaind`'s configuration would not resolve.
    ///
    /// Boxed: `ConfigError` names a field, a layer and a value, and is far
    /// larger than every other variant. An unboxed one would make `CliError`
    /// — and therefore every `CliResult` in the crate — pay for it on the
    /// success path too.
    #[error(transparent)]
    Config(Box<ferrum_node::ConfigError>),

    /// The node would not start, or failed while running.
    #[error(transparent)]
    Node(Box<ferrum_node::NodeError>),

    /// Something that should not happen, reported rather than panicked on.
    #[error("{0}")]
    Internal(String),
}

impl CliError {
    /// An [`CliError::Invalid`] for a flag value.
    pub fn invalid(
        what: &'static str,
        value: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        CliError::Invalid { what, value: value.into(), reason: reason.into() }
    }

    /// An [`CliError::Io`] that names the path it happened to.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        CliError::Io { path: path.into(), source }
    }

    /// A [`CliError::NotFound`].
    pub fn not_found(what: impl Into<String>) -> Self {
        CliError::NotFound(what.into())
    }

    /// A [`CliError::Internal`].
    pub fn internal(what: impl Into<String>) -> Self {
        CliError::Internal(what.into())
    }
}

/// The result type every command returns.
pub type CliResult<T> = Result<T, CliError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_names_the_flag_and_the_reason() {
        let e = CliError::invalid("--amount", "1.2.3", "too many decimal points");
        let text = e.to_string();
        assert!(text.contains("--amount"), "{text}");
        assert!(text.contains("1.2.3"), "{text}");
        assert!(text.contains("too many decimal points"), "{text}");
    }

    #[test]
    fn io_errors_name_the_path() {
        let e = CliError::io("C:/nope/wallet.json", std::io::Error::other("boom"));
        assert!(e.to_string().contains("wallet.json"));
    }
}
