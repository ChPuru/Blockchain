//! Where the CLI and the node keep their files.
//!
//! One datadir holds everything a node instance owns: the `redb` store, the
//! libp2p identity, the wallet keystore and any BFT validator key. That is what
//! `devnet/lib.sh` assumes when it gives each node its own `--datadir`, and it
//! is what makes "delete the directory" a complete reset.

use std::path::{Path, PathBuf};

use ferrum_types::Network;

use crate::error::{CliError, CliResult};

/// The `redb` database file inside a datadir.
///
/// Re-exported from `ferrum-node` rather than restated. `chain reindex` opens
/// this file directly, and a second spelling of the name would mean the
/// rebuild silently operated on a store the node never writes.
pub const DB_FILE: &str = ferrum_node::config::STORE_FILE;

/// The encrypted wallet keystore inside a datadir.
pub const WALLET_FILE: &str = "wallet.json";

/// The node's own key inside a datadir.
///
/// CONTRACT §13.1: without `--mine-address`, `chaind` mines to an address
/// derived from this file, generating it on first run, so a devnet is
/// startable with no wallet setup at all. The name comes from `ferrum-node`,
/// which is what creates it.
pub const NODE_KEY_FILE: &str = ferrum_node::config::NODE_KEY_FILE;

/// The environment variable that overrides the default datadir.
pub const DATADIR_ENV: &str = "FERRUM_DATADIR";

/// The datadir to use when neither `--datadir` nor `FERRUM_DATADIR` is set.
///
/// The platform's user data directory (`%APPDATA%\ferrum` on Windows,
/// `~/.local/share/ferrum` on Linux, `~/Library/Application Support/ferrum` on
/// macOS), falling back to `./.ferrum` on a system that has no such notion. A
/// fallback rather than an error: a CLI that cannot run because a directory
/// service is unavailable is worse than one that writes to the working
/// directory and says so.
#[must_use]
pub fn default_datadir() -> PathBuf {
    if let Some(from_env) = std::env::var_os(DATADIR_ENV)
        && !from_env.is_empty()
    {
        return PathBuf::from(from_env);
    }
    directories::ProjectDirs::from("", "", "ferrum")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".ferrum"))
}

/// Resolve the datadir: the flag if given, otherwise [`default_datadir`].
///
/// A per-network subdirectory is **not** appended. `devnet/lib.sh` passes an
/// explicit path per node and then looks for `node.key` and `validator.key`
/// directly inside it; inserting a network segment would break every one of
/// those paths.
#[must_use]
pub fn resolve_datadir(flag: Option<&Path>) -> PathBuf {
    flag.map_or_else(default_datadir, Path::to_path_buf)
}

/// Create `dir` and every missing parent.
///
/// # Errors
///
/// [`CliError::Io`] naming the directory that could not be created.
pub fn ensure_dir(dir: &Path) -> CliResult<()> {
    std::fs::create_dir_all(dir).map_err(|e| CliError::io(dir, e))
}

/// The store path inside `datadir`.
#[must_use]
pub fn db_path(datadir: &Path) -> PathBuf {
    datadir.join(DB_FILE)
}

/// The wallet keystore path inside `datadir`.
#[must_use]
pub fn wallet_path(datadir: &Path) -> PathBuf {
    datadir.join(WALLET_FILE)
}

/// The libp2p identity path inside `datadir`.
#[must_use]
pub fn node_key_path(datadir: &Path) -> PathBuf {
    datadir.join(NODE_KEY_FILE)
}

/// Parse a network name the way `--network` accepts it.
///
/// # Errors
///
/// [`CliError::Invalid`] listing the three names that are valid.
pub fn parse_network(name: &str) -> CliResult<Network> {
    match name.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "main" => Ok(Network::Mainnet),
        "testnet" | "test" => Ok(Network::Testnet),
        "devnet" | "dev" | "regtest" => Ok(Network::Devnet),
        other => Err(CliError::invalid("--network", other, "expected mainnet, testnet or devnet")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_three_network_names_parse_and_nothing_else_does() {
        assert_eq!(parse_network("mainnet").unwrap(), Network::Mainnet);
        assert_eq!(parse_network("TestNet").unwrap(), Network::Testnet);
        assert_eq!(parse_network(" devnet ").unwrap(), Network::Devnet);
        assert!(parse_network("bitcoin").is_err());
    }

    #[test]
    fn an_explicit_datadir_wins_over_the_default() {
        let explicit = PathBuf::from("D:/somewhere/node3");
        assert_eq!(resolve_datadir(Some(&explicit)), explicit);
    }

    #[test]
    fn the_file_layout_is_flat_inside_the_datadir() {
        let dir = Path::new("d");
        assert_eq!(db_path(dir), Path::new("d").join(DB_FILE));
        assert_eq!(wallet_path(dir), Path::new("d").join(WALLET_FILE));
        assert_eq!(node_key_path(dir), Path::new("d").join(NODE_KEY_FILE));
    }
}
