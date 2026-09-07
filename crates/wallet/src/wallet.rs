//! The [`Wallet`] itself: CONTRACT §12's surface, assembled from the modules
//! around it.
//!
//! # What a `Wallet` is
//!
//! An encrypted keystore, an HD keychain derived from the mnemonic inside it,
//! and a cache of the wallet's own unspent outputs. It never talks to a node,
//! a database or a network: [`Wallet::sync`] is handed a UTXO set by whoever
//! has one, and everything else is a pure function of that plus the keys.
//!
//! That is deliberate. A wallet with its own chain access has two sources of
//! truth about the same coins, and the day they disagree is the day someone
//! loses money. Here there is exactly one, and it belongs to the caller.
//!
//! # Address issuance
//!
//! [`Wallet::new_address`] walks `m/44'/7767'/0'/0/i` and **persists `i`
//! before returning the address**. Persisting after handing the address out
//! would leave a window in which a crash makes the wallet re-issue an address
//! it has already given to a payer, which merges two payments into one
//! identity and is exactly the privacy leak HD wallets exist to avoid. The
//! index lives inside the keystore's authenticated metadata, so it cannot be
//! rolled back by editing the file either.
//!
//! # The gap limit
//!
//! The wallet recognises outputs paid to any index up to
//! [`ADDRESS_GAP_LIMIT`] beyond the highest it has issued, on both the receive
//! and the change chain. Without that, a coin sent to an address handed out by
//! a *different* copy of the same seed is invisible — the classic "my
//! restored wallet shows zero" failure.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use ferrum_crypto::{Address, Mnemonic, SecretKey};
use ferrum_script::sighash::SigHashType;
use ferrum_types::{ChainId, ChainParams, Coin, Network, OutPoint, Script, Transaction};
use rand_core::CryptoRngCore;

use crate::build::{BuildParams, SendRequest, TxPlan, plan_transaction};
use crate::coins::{Balance, CoinCache, WalletCoin};
use crate::error::WalletError;
use crate::fee::dust_threshold;
use crate::hd::{ADDRESS_GAP_LIMIT, CHANGE_CHAIN, HdKeychain, RECEIVE_CHAIN};
use crate::keystore::{Keystore, KeystoreParams, WalletMeta};
use crate::sign::{sign_transaction, verify_signed};

/// Where a recognised script sits in the derivation tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyLocation {
    /// BIP-44 account index.
    pub account: u32,
    /// `0` for the receive chain, `1` for the change chain.
    pub change: u32,
    /// Address index.
    pub index: u32,
}

/// An HD wallet over an encrypted keystore.
pub struct Wallet {
    keystore: Keystore,
    keychain: HdKeychain,
    params: ChainParams,
    coins: CoinCache,
    /// Locking script → where its key lives. `BTreeMap` because every lookup
    /// order in this crate is deterministic by construction.
    scripts: BTreeMap<Script, KeyLocation>,
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("network", &self.network())
            .field("path", &self.keystore.path())
            .field("meta", &self.keystore.meta())
            .field("coins", &self.coins.len())
            .field("secrets", &"<redacted>")
            .finish()
    }
}

impl Wallet {
    // ---------------------------------------------------------------- lifecycle

    /// Create a new wallet, returning it alongside the mnemonic the user must
    /// write down.
    ///
    /// The mnemonic is returned *by value* and is the only copy outside the
    /// encrypted file; it zeroizes when the caller drops it.
    pub fn create(
        path: &Path,
        network: Network,
        passphrase: &str,
        words: usize,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, Mnemonic), WalletError> {
        Wallet::create_with_params(path, network, passphrase, words, KeystoreParams::default(), rng)
    }

    /// [`Wallet::create`] with an explicit KDF work factor.
    ///
    /// Exists so tests do not pay 210 000 PBKDF2 iterations per wallet. The
    /// floor in [`crate::keystore::MIN_PBKDF2_ITERATIONS`] still applies, so
    /// this cannot be used to write a keystore with no work factor at all.
    pub fn create_with_params(
        path: &Path,
        network: Network,
        passphrase: &str,
        words: usize,
        keystore_params: KeystoreParams,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, Mnemonic), WalletError> {
        let mnemonic = Mnemonic::generate(words, rng)?;
        let keystore = Keystore::create(
            path,
            network,
            &mnemonic,
            passphrase,
            WalletMeta::default(),
            keystore_params,
            rng,
        )?;
        let wallet = Wallet::from_keystore(keystore)?;
        Ok((wallet, mnemonic))
    }

    /// Restore a wallet from a mnemonic.
    ///
    /// Takes no RNG because CONTRACT §12 declares none, so the salt and nonce
    /// come from the operating system's CSPRNG. Deriving them from the
    /// mnemonic instead would make two keystores of the same seed
    /// byte-identical, which leaks that they are the same wallet to anyone who
    /// sees both files.
    pub fn restore(
        path: &Path,
        network: Network,
        mnemonic: &Mnemonic,
        passphrase: &str,
    ) -> Result<Self, WalletError> {
        Wallet::restore_with_params(path, network, mnemonic, passphrase, KeystoreParams::default())
    }

    /// [`Wallet::restore`] with an explicit KDF work factor.
    pub fn restore_with_params(
        path: &Path,
        network: Network,
        mnemonic: &Mnemonic,
        passphrase: &str,
        keystore_params: KeystoreParams,
    ) -> Result<Self, WalletError> {
        let keystore = Keystore::create(
            path,
            network,
            mnemonic,
            passphrase,
            WalletMeta::default(),
            keystore_params,
            &mut rand_core::OsRng,
        )?;
        Wallet::from_keystore(keystore)
    }

    /// Open an existing wallet.
    pub fn open(path: &Path, passphrase: &str) -> Result<Self, WalletError> {
        Wallet::from_keystore(Keystore::open(path, passphrase)?)
    }

    fn from_keystore(keystore: Keystore) -> Result<Self, WalletError> {
        let network = keystore.network();
        let keychain = HdKeychain::from_mnemonic(keystore.mnemonic(), "", network)?;
        let mut wallet = Wallet {
            keystore,
            keychain,
            params: network.params(),
            coins: CoinCache::new(),
            scripts: BTreeMap::new(),
        };
        wallet.rebuild_script_index()?;
        Ok(wallet)
    }

    /// Re-derive the script → key-location index from the persisted metadata.
    ///
    /// Covers `0..next + ADDRESS_GAP_LIMIT` on both chains, so a coin paid to
    /// an address this copy of the wallet has not itself issued is still
    /// recognised.
    fn rebuild_script_index(&mut self) -> Result<(), WalletError> {
        let meta = self.keystore.meta();
        self.scripts.clear();
        for (chain, next) in
            [(RECEIVE_CHAIN, meta.next_receive_index), (CHANGE_CHAIN, meta.next_change_index)]
        {
            let horizon = next.saturating_add(ADDRESS_GAP_LIMIT);
            for index in 0..=horizon {
                let key = self.keychain.derive(meta.account, chain, index)?;
                self.scripts.insert(
                    key.script_pubkey(),
                    KeyLocation { account: meta.account, change: chain, index },
                );
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------ getters

    /// Which network this wallet's addresses belong to.
    pub fn network(&self) -> Network {
        self.keystore.network()
    }

    /// The chain parameters for [`Wallet::network`].
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// The chain id signatures from this wallet commit to.
    pub fn chain_id(&self) -> ChainId {
        self.params.chain_id
    }

    /// The encrypted keystore behind this wallet.
    pub fn keystore(&self) -> &Keystore {
        &self.keystore
    }

    /// The mnemonic, for `chain-cli wallet dump-seed`.
    pub fn mnemonic(&self) -> &Mnemonic {
        self.keystore.mnemonic()
    }

    /// The dust threshold for this network: `3 * min_relay_fee_per_kb`.
    pub fn dust_threshold(&self) -> ferrum_types::Amount {
        dust_threshold(self.params.min_relay_fee_per_kb)
    }

    /// The wallet's UTXO cache.
    pub fn coins(&self) -> &CoinCache {
        &self.coins
    }

    /// Where a locking script sits in the derivation tree, if it is ours.
    pub fn locate_script(&self, script: &Script) -> Option<KeyLocation> {
        self.scripts.get(script).copied()
    }

    // ---------------------------------------------------------------- addresses

    /// Derive the next unused receive address and persist the index.
    ///
    /// The index is written to the keystore *before* the address is returned,
    /// so a crash can only ever skip an address, never re-issue one.
    pub fn new_address(&mut self) -> Result<Address, WalletError> {
        let mut meta = self.keystore.meta();
        let index = meta.next_receive_index;
        let key = self.keychain.derive(meta.account, RECEIVE_CHAIN, index)?;
        meta.next_receive_index =
            index.checked_add(1).ok_or(WalletError::AddressIndexOutOfRange(index))?;
        self.keystore.set_meta(meta)?;
        self.rebuild_script_index()?;
        Ok(*key.address())
    }

    /// Derive the next unused change address and persist the index.
    pub fn new_change_address(&mut self) -> Result<Address, WalletError> {
        let meta = self.keystore.meta();
        let key = self.keychain.derive(meta.account, CHANGE_CHAIN, meta.next_change_index)?;
        self.retire_change_index()?;
        Ok(*key.address())
    }

    /// Move `next_change_index` past the index a build has just paid to.
    ///
    /// [`Wallet::change_addresses`] reports `0..next_change_index`, so an
    /// index that has been paid but not retired is a change output no caller
    /// ever asks the node about. Persisting the increment *before* the
    /// transaction is broadcast is the same ordering [`Wallet::new_address`]
    /// uses, and for the same reason: a crash may skip an index, never reuse
    /// one.
    fn retire_change_index(&mut self) -> Result<(), WalletError> {
        let mut meta = self.keystore.meta();
        let index = meta.next_change_index;
        meta.next_change_index =
            index.checked_add(1).ok_or(WalletError::AddressIndexOutOfRange(index))?;
        self.keystore.set_meta(meta)?;
        self.rebuild_script_index()
    }

    /// Every receive address this wallet has issued, in index order.
    pub fn addresses(&self) -> Vec<Address> {
        let meta = self.keystore.meta();
        (0..meta.next_receive_index)
            .filter_map(|index| {
                self.keychain.derive(meta.account, RECEIVE_CHAIN, index).ok().map(|k| *k.address())
            })
            .collect()
    }

    /// Every change address this wallet has issued, in index order.
    ///
    /// Callers build their "which scripts do I ask the node about" list out of
    /// this plus [`Wallet::addresses`] (`chain-cli`'s `sync_from_node`, the
    /// RPC faucet's `WalletFaucetSource::scripts`), so an index this wallet
    /// has paid change to and *not* reported here is money it can never see
    /// again. [`Wallet::send`] retires the index it spends to for exactly that
    /// reason.
    pub fn change_addresses(&self) -> Vec<Address> {
        let meta = self.keystore.meta();
        (0..meta.next_change_index)
            .filter_map(|index| {
                self.keychain.derive(meta.account, CHANGE_CHAIN, index).ok().map(|k| *k.address())
            })
            .collect()
    }

    /// The change address a build will use when the request does not name one.
    ///
    /// The *current* change index rather than a fresh one: `build_transaction`
    /// takes `&self` in CONTRACT §12 and so cannot persist an increment. Call
    /// [`Wallet::new_change_address`] to rotate it.
    pub fn current_change_address(&self) -> Result<Address, WalletError> {
        let meta = self.keystore.meta();
        Ok(*self.keychain.derive(meta.account, CHANGE_CHAIN, meta.next_change_index)?.address())
    }

    /// The private key for a locking script this wallet controls.
    pub fn secret_for_script(&self, script: &Script) -> Option<SecretKey> {
        let location = self.locate_script(script)?;
        self.keychain
            .derive(location.account, location.change, location.index)
            .ok()
            .map(|k| k.secret_key().clone())
    }

    // -------------------------------------------------------------------- coins

    /// Replace the wallet's view of its unspent outputs.
    ///
    /// Coins whose locking script this wallet does not control are dropped: a
    /// caller that hands over the whole chain's UTXO set gets a correct
    /// balance rather than the chain's total supply.
    pub fn sync(&mut self, utxos: Vec<(OutPoint, Coin)>, tip: u64) {
        let total = utxos.len();
        let mine: Vec<(OutPoint, Coin)> = utxos
            .into_iter()
            .filter(|(_, coin)| self.scripts.contains_key(&coin.script_pubkey))
            .collect();
        let ignored = total.saturating_sub(mine.len());
        if ignored > 0 {
            tracing::debug!(
                ignored,
                kept = mine.len(),
                tip,
                "sync dropped coins this wallet cannot spend"
            );
        }
        self.coins.sync(mine, tip);
    }

    /// The three-way balance at `tip_height`.
    pub fn balance(&self, tip_height: u64, maturity: u64) -> Balance {
        self.coins.balance(tip_height, maturity)
    }

    /// The balance using this network's `coinbase_maturity`.
    pub fn balance_at(&self, tip_height: u64) -> Balance {
        self.coins.balance(tip_height, self.params.coinbase_maturity)
    }

    /// Every coin with its bucket, for `listunspent`-style output.
    pub fn list_coins(&self, tip_height: u64) -> Vec<WalletCoin> {
        self.coins.iter_status(tip_height, self.params.coinbase_maturity).collect()
    }

    /// Coins coin selection may draw on at `tip_height`.
    pub fn spendable_coins(&self, tip_height: u64) -> Vec<(OutPoint, Coin)> {
        self.coins.spendable(tip_height, self.params.coinbase_maturity)
    }

    /// Mark outpoints as committed to a broadcast transaction.
    pub fn reserve(&mut self, out_points: &[OutPoint]) {
        self.coins.reserve(out_points);
    }

    /// Release a reservation, e.g. after a failed broadcast.
    pub fn unreserve(&mut self, out_points: &[OutPoint]) {
        self.coins.unreserve(out_points);
    }

    // ----------------------------------------------------------------- building

    /// Plan a transaction: select coins, size it, and assemble it unsigned.
    ///
    /// The richer sibling of [`Wallet::build_transaction`] — it also returns
    /// the prevouts, the fee, the change and the size, which is what a caller
    /// needs in order to sign and to show the user what they are about to
    /// send.
    pub fn plan_transaction(
        &self,
        req: &SendRequest,
        tip_height: u64,
    ) -> Result<TxPlan, WalletError> {
        for (address, _) in &req.outputs {
            self.check_network(address)?;
        }
        let change_address = match req.change_to {
            Some(address) => {
                self.check_network(&address)?;
                address
            }
            None => self.current_change_address()?,
        };
        let candidates = self.spendable_coins(tip_height);
        let params = BuildParams::at_tip(self.dust_threshold(), tip_height);
        plan_transaction(&candidates, req, &change_address, &params)
    }

    /// Build an unsigned transaction paying `req`.
    pub fn build_transaction(
        &self,
        req: &SendRequest,
        tip_height: u64,
    ) -> Result<Transaction, WalletError> {
        Ok(self.plan_transaction(req, tip_height)?.tx)
    }

    /// Sign every input of `tx` with `SIGHASH_ALL`.
    ///
    /// `prevouts` must line up with `tx.inputs`. The signature commits to
    /// `chain_id`, so a transaction signed for one network cannot be replayed
    /// on another.
    pub fn sign_transaction(
        &self,
        tx: &mut Transaction,
        prevouts: &[Coin],
        chain_id: ChainId,
    ) -> Result<(), WalletError> {
        self.sign_transaction_with(tx, prevouts, chain_id, SigHashType::ALL)
    }

    /// [`Wallet::sign_transaction`] with an explicit sighash type.
    pub fn sign_transaction_with(
        &self,
        tx: &mut Transaction,
        prevouts: &[Coin],
        chain_id: ChainId,
        sighash_type: SigHashType,
    ) -> Result<(), WalletError> {
        sign_transaction(tx, prevouts, chain_id, sighash_type, |script| {
            self.secret_for_script(script)
        })
    }

    /// Verify a signed transaction against its prevouts.
    pub fn verify_transaction(
        &self,
        tx: &Transaction,
        prevouts: &[Coin],
        chain_id: ChainId,
    ) -> Result<(), WalletError> {
        verify_signed(tx, prevouts, chain_id)
    }

    /// Plan, sign, verify and reserve in one call.
    ///
    /// The reservation is what stops a second `send` before the first confirms
    /// from selecting the same coins and producing a double spend that the
    /// mempool drops silently.
    ///
    /// # Change
    ///
    /// When the plan pays change to this wallet's own change chain, the index
    /// it used is retired here, before
    /// the caller can broadcast. That does two things:
    ///
    /// * the coin lands on an address [`Wallet::change_addresses`] reports, so
    ///   the next sync actually asks the node about it, and
    /// * the next `send` builds against a fresh index instead of paying every
    ///   transaction's change to one address and linking the whole history.
    pub fn send(&mut self, req: &SendRequest, tip_height: u64) -> Result<TxPlan, WalletError> {
        let mut plan = self.plan_transaction(req, tip_height)?;
        let prevouts = plan.prevouts();
        let chain_id = self.chain_id();
        self.sign_transaction(&mut plan.tx, &prevouts, chain_id)?;
        if plan.change.is_some() {
            let ours = self.current_change_address()?;
            // `change_to: None` means "the wallet's own change chain", and a
            // caller naming that same address explicitly means the same thing.
            if req.change_to.unwrap_or(ours) == ours {
                self.retire_change_index()?;
            }
        }
        self.coins.reserve(&plan.out_points());
        Ok(plan)
    }

    fn check_network(&self, address: &Address) -> Result<(), WalletError> {
        if address.network == self.network() {
            return Ok(());
        }
        Err(WalletError::NetworkMismatch {
            found: address.network.name(),
            expected: self.network().name(),
        })
    }
}
