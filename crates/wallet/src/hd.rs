//! BIP-32/44 derivation, layered over `ferrum-crypto`.
//!
//! The wallet's tree is `m/44'/7767'/account'/change/index`, exactly the path
//! CONTRACT §12 names. `7767` is Ferrum's self-assigned SLIP-44-style coin
//! type and lives in [`ferrum_crypto::COIN_TYPE`].
//!
//! Two conventions this module fixes, both borrowed from BIP-44 because
//! deviating buys nothing:
//!
//! - **`change = 0` is the receive chain, `change = 1` is the change chain.**
//!   Keeping change on its own branch means a wallet restored from a mnemonic
//!   can scan the two chains independently, and it keeps a change address from
//!   being handed out as a receive address.
//! - **The account level is hardened, the last two levels are not.** That is
//!   what allows an account-level extended *public* key to enumerate every
//!   address without exposing a single private key. This wallet does not ship
//!   watch-only mode, but the derivation must not foreclose it.
//!
//! Nothing here caches a private key beyond the call that asked for one:
//! [`DerivedKey`] owns a [`SecretKey`], and both it and the [`ExtendedKey`]
//! inside [`HdKeychain`] zeroize on drop.

use std::fmt;

use ferrum_crypto::{
    Address, DerivationPath, ExtendedKey, Mnemonic, PublicKey, SecretKey, hash160,
};
use ferrum_types::{Network, Script};

use crate::error::WalletError;

/// The account index every command-line operation uses.
///
/// Multi-account support is a UI feature, not a protocol feature; the
/// derivation already carries the account level so adding it later changes no
/// stored data.
pub const DEFAULT_ACCOUNT: u32 = 0;

/// BIP-44 `change` value for addresses handed out to payers.
pub const RECEIVE_CHAIN: u32 = 0;

/// BIP-44 `change` value for addresses the wallet pays itself.
pub const CHANGE_CHAIN: u32 = 1;

/// How far past the highest issued index the wallet still recognises its own
/// outputs.
///
/// BIP-44 says 20. The number matters: a wallet that only recognises the
/// indices it has issued loses coins sent to an address a *different* copy of
/// the same seed handed out. Twenty spare keys per chain cost about a
/// millisecond to derive and close that hole.
pub const ADDRESS_GAP_LIMIT: u32 = 20;

/// The highest index BIP-32 non-hardened derivation allows.
pub const MAX_ADDRESS_INDEX: u32 = 0x7fff_ffff;

/// One derived key and everything the wallet needs to use it.
///
/// `Debug` redacts the secret. A private key in a log line is a stolen wallet,
/// and the one place that ever happens is a `{:?}` someone added while
/// debugging.
#[derive(Clone)]
pub struct DerivedKey {
    path: DerivationPath,
    secret: SecretKey,
    public: PublicKey,
    address: Address,
}

impl DerivedKey {
    /// The BIP-32 path this key was derived at.
    pub fn path(&self) -> &DerivationPath {
        &self.path
    }

    /// The private key. Keep it on the stack and let it drop.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    /// The x-only public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The P2PKH address this key controls.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// `hash160(x_only_pubkey)`, the 20 bytes inside the address.
    pub fn pubkey_hash(&self) -> [u8; 20] {
        hash160(self.public.as_bytes())
    }

    /// The locking script that pays this key.
    pub fn script_pubkey(&self) -> Script {
        self.address.script_pubkey()
    }
}

impl fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedKey")
            .field("path", &self.path.to_string())
            .field("public", &self.public)
            .field("address", &self.address.encode())
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The master key of one wallet, plus the network its addresses belong to.
///
/// Cloneable so a caller can hand a copy to a signing routine without holding
/// a borrow across a mutation; every clone zeroizes independently.
#[derive(Clone)]
pub struct HdKeychain {
    master: ExtendedKey,
    network: Network,
}

impl HdKeychain {
    /// Build a keychain from a BIP-39 seed.
    ///
    /// The seed must be 16 to 64 bytes; the caller should zeroize it as soon
    /// as this returns, which is what [`HdKeychain::from_mnemonic`] does.
    pub fn from_seed(seed: &[u8], network: Network) -> Result<Self, WalletError> {
        Ok(HdKeychain { master: ExtendedKey::master_from_seed(seed)?, network })
    }

    /// Build a keychain from a mnemonic and its optional BIP-39 passphrase.
    ///
    /// The intermediate 64-byte seed is zeroized before this returns: it is
    /// equivalent to the mnemonic and must not be left on the stack.
    pub fn from_mnemonic(
        mnemonic: &Mnemonic,
        seed_passphrase: &str,
        network: Network,
    ) -> Result<Self, WalletError> {
        let mut seed = mnemonic.to_seed(seed_passphrase);
        let result = HdKeychain::from_seed(&seed, network);
        ferrum_crypto::zeroize_seed(&mut seed);
        result
    }

    /// Which network this keychain's addresses encode for.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The account-level extended key `m/44'/7767'/account'`.
    pub fn account_key(&self, account: u32) -> Result<ExtendedKey, WalletError> {
        let path = DerivationPath::ferrum_account(account)?;
        Ok(self.master.derive_path(&path)?)
    }

    /// Derive `m/44'/7767'/account'/change/index`.
    pub fn derive(&self, account: u32, change: u32, index: u32) -> Result<DerivedKey, WalletError> {
        if index > MAX_ADDRESS_INDEX {
            return Err(WalletError::AddressIndexOutOfRange(index));
        }
        let path = DerivationPath::ferrum(account, change, index)?;
        let key = self.master.derive_path(&path)?;
        let secret = key.secret_key();
        let public = key.public_key();
        let address = Address::p2pkh(self.network, &public);
        Ok(DerivedKey { path, secret, public, address })
    }

    /// Derive a receive address (`change = 0`).
    pub fn receive(&self, account: u32, index: u32) -> Result<DerivedKey, WalletError> {
        self.derive(account, RECEIVE_CHAIN, index)
    }

    /// Derive a change address (`change = 1`).
    pub fn change(&self, account: u32, index: u32) -> Result<DerivedKey, WalletError> {
        self.derive(account, CHANGE_CHAIN, index)
    }

    /// The address at a path, without keeping the private key around.
    pub fn address(&self, account: u32, change: u32, index: u32) -> Result<Address, WalletError> {
        Ok(*self.derive(account, change, index)?.address())
    }
}

impl fmt::Debug for HdKeychain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HdKeychain")
            .field("network", &self.network)
            .field("master", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_crypto::Mnemonic;

    use super::*;

    fn keychain() -> HdKeychain {
        let mnemonic = Mnemonic::from_entropy(&[0x11u8; 32]).unwrap();
        HdKeychain::from_mnemonic(&mnemonic, "", Network::Devnet).unwrap()
    }

    #[test]
    fn derivation_path_is_the_contract_path() {
        let key = keychain().receive(0, 5).unwrap();
        assert_eq!(key.path().to_string(), "m/44'/7767'/0'/0/5");
    }

    #[test]
    fn change_chain_is_index_one() {
        let key = keychain().change(0, 5).unwrap();
        assert_eq!(key.path().to_string(), "m/44'/7767'/0'/1/5");
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = keychain().receive(0, 3).unwrap();
        let b = keychain().receive(0, 3).unwrap();
        assert_eq!(a.address(), b.address());
        assert_eq!(a.secret_key().to_bytes(), b.secret_key().to_bytes());
    }

    #[test]
    fn different_indices_give_different_addresses() {
        let chain = keychain();
        let a = chain.receive(0, 0).unwrap();
        let b = chain.receive(0, 1).unwrap();
        assert_ne!(a.address(), b.address());
    }

    #[test]
    fn receive_and_change_chains_do_not_collide() {
        let chain = keychain();
        assert_ne!(chain.receive(0, 0).unwrap().address(), chain.change(0, 0).unwrap().address());
    }

    #[test]
    fn different_accounts_give_different_addresses() {
        let chain = keychain();
        assert_ne!(chain.receive(0, 0).unwrap().address(), chain.receive(1, 0).unwrap().address());
    }

    #[test]
    fn address_encodes_for_the_keychain_network() {
        for network in Network::ALL {
            let mnemonic = Mnemonic::from_entropy(&[0x22u8; 16]).unwrap();
            let chain = HdKeychain::from_mnemonic(&mnemonic, "", network).unwrap();
            let address = chain.address(0, 0, 0).unwrap();
            assert_eq!(address.network, network);
            assert!(address.encode().starts_with(network.bech32_hrp()));
        }
    }

    #[test]
    fn script_pubkey_commits_to_the_pubkey_hash() {
        let key = keychain().receive(0, 0).unwrap();
        let expected = ferrum_script::templates::p2pkh(&key.pubkey_hash());
        assert_eq!(key.script_pubkey(), expected);
    }

    #[test]
    fn a_bip39_passphrase_changes_the_whole_tree() {
        let mnemonic = Mnemonic::from_entropy(&[0x33u8; 16]).unwrap();
        let plain = HdKeychain::from_mnemonic(&mnemonic, "", Network::Devnet).unwrap();
        let salted = HdKeychain::from_mnemonic(&mnemonic, "hunter2", Network::Devnet).unwrap();
        assert_ne!(plain.address(0, 0, 0).unwrap(), salted.address(0, 0, 0).unwrap());
    }

    #[test]
    fn index_beyond_the_hardened_bit_is_rejected() {
        let err = keychain().receive(0, 0x8000_0000).unwrap_err();
        assert!(matches!(err, WalletError::AddressIndexOutOfRange(0x8000_0000)));
    }

    #[test]
    fn debug_never_prints_key_material() {
        let key = keychain().receive(0, 0).unwrap();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains(&hex::encode(key.secret_key().to_bytes())));

        let rendered = format!("{:?}", keychain());
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn a_short_seed_is_rejected() {
        assert!(HdKeychain::from_seed(&[0u8; 4], Network::Devnet).is_err());
    }

    #[test]
    fn account_key_is_the_hardened_prefix() {
        let chain = keychain();
        let account = chain.account_key(0).unwrap();
        assert_eq!(account.depth(), 3);
    }
}
