//! `<datadir>/node.key`: the one secret a node needs in order to start.
//!
//! CONTRACT §13.1 requires that `chaind --mine` works with no `--mine-address`
//! and no wallet, mining to an address derived from a key the node generates on
//! first run. That is what makes `devnet/up.sh` a single command instead of a
//! setup ritual.
//!
//! # One seed, two keys, two paths
//!
//! The file holds **one 32-byte seed**, hex-encoded. Two independent keys are
//! derived from it down separate BIP-32 paths:
//!
//! | Path | Key | Used for |
//! |---|---|---|
//! | `m/44'/7767'/0'/0/0` | BIP-340 secp256k1 | the default coinbase payout address |
//! | `m/44'/7767'/1'/0/0` | Ed25519, seeded from the derived secret | the libp2p network identity |
//!
//! Deriving rather than reusing matters. Signing with the same scalar under two
//! different signature schemes is the kind of shortcut that is fine until
//! someone finds a cross-protocol relation between them, and there is no reason
//! to take the risk when a derivation path costs one HMAC.
//!
//! The network identity in particular must be *stable across restarts*: it is
//! the `PeerId` other operators put in their static peer lists (there is no
//! peer discovery), so regenerating it on every start would silently break
//! everyone else's config.

use std::path::Path;

use ferrum_crypto::{Address, DerivationPath, ExtendedKey, PublicKey, SecretKey};
use ferrum_p2p::{Keypair, PeerId};
use ferrum_types::Network;
use zeroize::Zeroize;

use crate::error::NodeError;

/// Length of the seed stored in `node.key`.
pub const NODE_KEY_SEED_LEN: usize = 32;

/// BIP-44 account used for the node's default mining key.
pub const MINING_ACCOUNT: u32 = 0;

/// BIP-44 account used for the node's libp2p network identity.
///
/// A different account from the mining key so the two secrets are independent;
/// see the module docs.
pub const NETWORK_ACCOUNT: u32 = 1;

/// The node's own key material.
///
/// Zeroized on drop. The seed never leaves this type except as hex on its way
/// to `node.key`, and the derived secrets are zeroized as soon as they have
/// produced a public key.
pub struct NodeKey {
    seed: [u8; NODE_KEY_SEED_LEN],
}

impl std::fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the seed. A node key in a log is a node key on a pastebin.
        f.debug_struct("NodeKey").field("seed", &"<redacted>").finish()
    }
}

impl Drop for NodeKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl NodeKey {
    /// Wrap an existing seed.
    #[must_use]
    pub fn from_seed(seed: [u8; NODE_KEY_SEED_LEN]) -> Self {
        NodeKey { seed }
    }

    /// Generate a fresh seed from the operating system's entropy source.
    #[must_use]
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; NODE_KEY_SEED_LEN];
        // The OS CSPRNG, not a seeded one: this key is a long-lived identity.
        rand::rngs::OsRng.fill_bytes(&mut seed);
        NodeKey { seed }
    }

    /// Read `path`, generating and writing a new key if it does not exist.
    ///
    /// The generate-on-first-run behaviour is the contract's, not a
    /// convenience: a devnet must be startable with no wallet setup.
    ///
    /// # Errors
    ///
    /// [`NodeError::Io`] naming the file, and [`NodeError::Io`] with an
    /// `InvalidData` kind when the file exists but does not hold 32 hex-encoded
    /// bytes — refusing is right, because overwriting it would change this
    /// node's `PeerId` and break every peer that lists it.
    pub fn load_or_create(path: &Path) -> Result<Self, NodeError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text, path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = NodeKey::generate();
                key.write(path)?;
                tracing::info!(path = %path.display(), "generated a new node key");
                Ok(key)
            }
            Err(e) => Err(NodeError::io(format!("reading {}", path.display()), e)),
        }
    }

    /// Parse the hex contents of a `node.key` file.
    ///
    /// # Errors
    ///
    /// [`NodeError::Io`] with `InvalidData` when the text is not exactly 32
    /// hex-encoded bytes.
    pub fn parse(text: &str, path: &Path) -> Result<Self, NodeError> {
        let trimmed = text.trim();
        let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        let bytes = hex::decode(trimmed).map_err(|e| {
            NodeError::io(
                format!("{} is not hex", path.display()),
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
            )
        })?;
        let seed: [u8; NODE_KEY_SEED_LEN] = bytes.as_slice().try_into().map_err(|_| {
            NodeError::io(
                format!("{} holds {} bytes", path.display(), bytes.len()),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("a node key is exactly {NODE_KEY_SEED_LEN} bytes"),
                ),
            )
        })?;
        Ok(NodeKey { seed })
    }

    /// Write the key to `path`, creating the parent directory if needed.
    ///
    /// On Unix the file is created with mode `0600`. Windows has no equivalent
    /// one-liner and the datadir's own ACL is the protection there; saying so
    /// is better than pretending the call is portable.
    ///
    /// # Errors
    ///
    /// [`NodeError::Io`] naming the file.
    pub fn write(&self, path: &Path) -> Result<(), NodeError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| NodeError::io(format!("creating {}", parent.display()), e))?;
        }
        let mut text = self.to_hex();
        text.push('\n');
        std::fs::write(path, text.as_bytes())
            .map_err(|e| NodeError::io(format!("writing {}", path.display()), e))?;
        text.zeroize();
        set_owner_only(path)?;
        Ok(())
    }

    /// The seed as lowercase hex, which is exactly the file's contents.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.seed)
    }

    /// The secret key at `m/44'/7767'/account'/0/0`.
    fn derive(&self, account: u32) -> Result<SecretKey, NodeError> {
        derive_receive_key(&self.seed, account)
    }

    /// The key the coinbase pays when `--mine-address` is absent.
    ///
    /// # Errors
    ///
    /// [`NodeError::Crypto`] if derivation fails, which needs a seed the
    /// HMAC maps outside the curve order — a once-in-2^127 event.
    pub fn mining_secret(&self) -> Result<SecretKey, NodeError> {
        self.derive(MINING_ACCOUNT)
    }

    /// The public key of [`NodeKey::mining_secret`].
    ///
    /// # Errors
    ///
    /// As [`NodeKey::mining_secret`].
    pub fn mining_public(&self) -> Result<PublicKey, NodeError> {
        Ok(self.mining_secret()?.public_key())
    }

    /// The P2PKH address the coinbase pays on `network`.
    ///
    /// # Errors
    ///
    /// As [`NodeKey::mining_secret`].
    pub fn mining_address(&self, network: Network) -> Result<Address, NodeError> {
        Ok(Address::p2pkh(network, &self.mining_public()?))
    }

    /// The libp2p identity, stable for the life of the key file.
    ///
    /// # Errors
    ///
    /// [`NodeError::Crypto`] on a derivation failure, and [`NodeError::P2p`]
    /// if the derived bytes are not a usable Ed25519 secret.
    pub fn p2p_keypair(&self) -> Result<Keypair, NodeError> {
        let secret = self.derive(NETWORK_ACCOUNT)?;
        let mut bytes = secret.to_bytes();
        let result = Keypair::ed25519_from_bytes(bytes).map_err(|e| {
            NodeError::Telemetry(format!("node key is not a usable network identity: {e}"))
        });
        bytes.zeroize();
        result
    }

    /// The `PeerId` other operators put in their static peer lists.
    ///
    /// # Errors
    ///
    /// As [`NodeKey::p2p_keypair`].
    pub fn peer_id(&self) -> Result<PeerId, NodeError> {
        Ok(self.p2p_keypair()?.public().to_peer_id())
    }
}

/// The receive key at `m/44'/7767'/account'/0/0` over an arbitrary seed.
///
/// The same path `ferrum_wallet::HdKeychain::receive(account, 0)` uses, so a
/// key file written as a BIP-39 mnemonic by `chain-cli wallet new --output`
/// resolves to the key `chain-cli wallet dump-pubkey` reports for it. That
/// agreement is what makes `devnet/fork.sh` work: it generates a validator key
/// with one command and reads its public key with another.
///
/// # Errors
///
/// [`NodeError::Crypto`] when the seed is outside the 16..=64 byte range BIP-32
/// allows, or when derivation lands outside the curve order.
pub fn derive_receive_key(seed: &[u8], account: u32) -> Result<SecretKey, NodeError> {
    let path = DerivationPath::ferrum(account, 0, 0)?;
    Ok(ExtendedKey::master_from_seed(seed)?.derive_path(&path)?.secret_key())
}

/// Restrict a key file to its owner where the platform supports it.
#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), NodeError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| NodeError::io(format!("restricting {}", path.display()), e))
}

/// Windows has no `chmod`; the data directory's ACL is the protection.
#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<(), NodeError> {
    Ok(())
}

#[cfg(test)]
mod tests;
