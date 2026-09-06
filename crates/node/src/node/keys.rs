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

    /// The BIP-32 master key over this seed.
    fn master(&self) -> Result<ExtendedKey, NodeError> {
        Ok(ExtendedKey::master_from_seed(&self.seed)?)
    }

    /// The secret key at `m/44'/7767'/account'/0/0`.
    fn derive(&self, account: u32) -> Result<SecretKey, NodeError> {
        let path = DerivationPath::ferrum(account, 0, 0)?;
        Ok(self.master()?.derive_path(&path)?.secret_key())
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
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn seed(byte: u8) -> NodeKey {
        NodeKey::from_seed([byte; NODE_KEY_SEED_LEN])
    }

    #[test]
    fn a_generated_key_is_thirty_two_bytes_of_hex() {
        let key = NodeKey::generate();
        let hex = key.to_hex();
        assert_eq!(hex.len(), NODE_KEY_SEED_LEN * 2);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn two_generated_keys_differ() {
        assert_ne!(NodeKey::generate().to_hex(), NodeKey::generate().to_hex());
    }

    #[test]
    fn the_key_file_is_created_on_first_run_and_reused_after() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        assert!(!path.exists());

        let first = NodeKey::load_or_create(&path).unwrap();
        assert!(path.exists(), "a devnet must start with no wallet setup");
        let second = NodeKey::load_or_create(&path).unwrap();
        assert_eq!(first.to_hex(), second.to_hex(), "the identity must survive a restart");
    }

    #[test]
    fn the_peer_id_is_stable_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let a = NodeKey::load_or_create(&path).unwrap().peer_id().unwrap();
        let b = NodeKey::load_or_create(&path).unwrap().peer_id().unwrap();
        assert_eq!(a, b, "a changing PeerId silently breaks every peer's static list");
    }

    #[test]
    fn the_file_is_hex_with_a_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let key = seed(0xab);
        key.write(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, format!("{}\n", "ab".repeat(32)));
    }

    #[test]
    fn writing_creates_the_data_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deep").join("nested").join("node.key");
        seed(1).write(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn a_key_file_with_a_0x_prefix_or_whitespace_still_parses() {
        let path = Path::new("node.key");
        let hex = "cd".repeat(32);
        assert_eq!(NodeKey::parse(&format!("  {hex}\n"), path).unwrap().to_hex(), hex);
        assert_eq!(NodeKey::parse(&format!("0x{hex}"), path).unwrap().to_hex(), hex);
    }

    #[test]
    fn a_short_key_file_is_refused_rather_than_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        std::fs::write(&path, "abcd\n").unwrap();
        let e = NodeKey::load_or_create(&path).unwrap_err();
        assert!(matches!(e, NodeError::Io { .. }), "{e}");
        // The file must survive: overwriting it would change the PeerId.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "abcd\n");
    }

    #[test]
    fn a_non_hex_key_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        std::fs::write(&path, "not hex at all").unwrap();
        assert!(NodeKey::load_or_create(&path).is_err());
    }

    #[test]
    fn derivation_is_deterministic_for_a_seed() {
        let a = seed(9).mining_address(Network::Devnet).unwrap();
        let b = seed(9).mining_address(Network::Devnet).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, seed(10).mining_address(Network::Devnet).unwrap());
    }

    #[test]
    fn the_mining_address_encodes_for_the_network_asked_for() {
        let key = seed(3);
        let dev = key.mining_address(Network::Devnet).unwrap();
        let main = key.mining_address(Network::Mainnet).unwrap();
        assert_eq!(dev.network, Network::Devnet);
        assert_eq!(main.network, Network::Mainnet);
        assert!(dev.encode().starts_with("rfer"));
        assert!(main.encode().starts_with("fer"));
        // Same key, so the payload is identical; only the network differs.
        assert_eq!(dev.payload, main.payload);
    }

    #[test]
    fn the_mining_key_and_the_network_key_are_independent() {
        let key = seed(5);
        let mining = key.mining_secret().unwrap().to_bytes();
        let network = key.derive(NETWORK_ACCOUNT).unwrap().to_bytes();
        assert_ne!(mining, network, "one scalar must not sign under two schemes");
        assert_ne!(mining, key.seed, "the seed itself is never a signing key");
    }

    #[test]
    fn the_mining_address_round_trips_through_its_encoding() {
        let address = seed(11).mining_address(Network::Devnet).unwrap();
        assert_eq!(Address::decode(&address.encode()).unwrap(), address);
    }

    #[test]
    fn debug_never_prints_the_seed() {
        let text = format!("{:?}", seed(0x7f));
        assert!(text.contains("redacted"), "{text}");
        assert!(!text.contains("7f7f"), "{text}");
    }

    #[test]
    fn a_key_pays_to_its_own_script_pubkey() {
        let key = seed(21);
        let address = key.mining_address(Network::Devnet).unwrap();
        let script = address.script_pubkey();
        assert!(!script.is_empty());
        assert_eq!(script, Address::decode(&address.encode()).unwrap().script_pubkey());
    }
}
