//! The devnet faucet: a rate limiter, a payment source, and a refusal that is
//! polite rather than fatal.
//!
//! # Two windows, because one is not enough
//!
//! Limiting per **address** stops the obvious abuse and nothing else: addresses
//! are free. Limiting per **client IP** costs an attacker something real.
//! Neither is sufficient alone, both are cheap, and the faucet applies both.
//! Everything is in memory and bounded: [`FaucetConfig::max_tracked`] caps the
//! table and evicts the oldest entry rather than growing, because a faucet that
//! can be made to allocate is a faucet that can be used to kill the node.
//!
//! # A quota is spent only on a payment that was actually made
//!
//! The limiter records the attempt *before* building the payment — so two
//! simultaneous requests cannot both pass the check — and rolls the record back
//! if the payment fails. Someone who asks while the wallet is empty has not
//! used their turn.
//!
//! # An empty wallet is an answer, not a panic
//!
//! Every failure here becomes an [`crate::error::RpcErrorCode`] and an HTTP
//! status the explorer renders as "Faucet declined: …". There is no `unwrap`
//! on this path and no way for a drained wallet to take the node down with it.

use std::collections::BTreeMap;
use std::sync::Arc;

use ferrum_crypto::Address;
use ferrum_types::{Amount, Script, Transaction};
use ferrum_wallet::{SendRequest, Wallet, WalletError};
use parking_lot::Mutex;

use crate::context::{Clock, SystemClock};
use crate::error::{RpcError, RpcErrorCode};
use crate::provider::ChainProvider;

/// Default amount a request dispenses: 1 FRM.
pub const DEFAULT_FAUCET_AMOUNT: Amount = Amount::from_grains(ferrum_types::COIN);

/// Default per-address window: 24 hours.
pub const DEFAULT_ADDRESS_WINDOW_MS: u64 = 24 * 60 * 60 * 1_000;

/// Default per-IP window: 1 hour.
pub const DEFAULT_IP_WINDOW_MS: u64 = 60 * 60 * 1_000;

/// Default number of grants one IP may take inside its window.
pub const DEFAULT_IP_ALLOWANCE: u32 = 5;

/// Default number of distinct keys the limiter remembers.
///
/// At roughly 64 bytes an entry this is a few megabytes, and it is a hard
/// ceiling: the oldest entry is evicted rather than the table growing.
pub const DEFAULT_MAX_TRACKED: usize = 20_000;

/// Default fee rate the faucet pays, in grains per 1000 bytes.
pub const DEFAULT_FAUCET_FEE_RATE: u64 = 1_000;

/// How the faucet is configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaucetConfig {
    /// What one grant pays.
    pub amount: Amount,
    /// How long an address must wait between grants.
    pub address_window_ms: u64,
    /// The window an IP's allowance is counted over.
    pub ip_window_ms: u64,
    /// How many grants one IP may take inside `ip_window_ms`.
    pub ip_allowance: u32,
    /// How many distinct keys the limiter remembers before evicting.
    pub max_tracked: usize,
    /// Fee rate the payment pays, grains per 1000 bytes.
    pub fee_rate: u64,
}

impl Default for FaucetConfig {
    fn default() -> Self {
        FaucetConfig {
            amount: DEFAULT_FAUCET_AMOUNT,
            address_window_ms: DEFAULT_ADDRESS_WINDOW_MS,
            ip_window_ms: DEFAULT_IP_WINDOW_MS,
            ip_allowance: DEFAULT_IP_ALLOWANCE,
            max_tracked: DEFAULT_MAX_TRACKED,
            fee_rate: DEFAULT_FAUCET_FEE_RATE,
        }
    }
}

impl FaucetConfig {
    /// Set the amount one grant pays.
    #[must_use]
    pub const fn with_amount(mut self, amount: Amount) -> Self {
        self.amount = amount;
        self
    }

    /// Set the per-address window.
    #[must_use]
    pub const fn with_address_window_ms(mut self, ms: u64) -> Self {
        self.address_window_ms = ms;
        self
    }

    /// Set the per-IP window and allowance.
    #[must_use]
    pub const fn with_ip_limit(mut self, window_ms: u64, allowance: u32) -> Self {
        self.ip_window_ms = window_ms;
        self.ip_allowance = allowance;
        self
    }
}

/// Where faucet payments come from.
///
/// Implemented by [`WalletFaucetSource`] over a real `ferrum-wallet`, and by a
/// stub in the tests. Synchronous: it is reached from
/// [`crate::context::blocking`].
pub trait FaucetSource: Send + Sync + std::fmt::Debug + 'static {
    /// Build and sign a payment of `amount` to `to`.
    ///
    /// # Errors
    /// [`RpcErrorCode::FaucetDrained`] when the wallet cannot fund it, and
    /// [`RpcErrorCode::FaucetFailed`] for anything else.
    fn build_payment(&self, to: &Address, amount: Amount) -> Result<Transaction, RpcError>;
}

/// One key's recent grants, newest last.
type Hits = Vec<u64>;

/// A bounded sliding-window counter over string keys.
#[derive(Debug, Default)]
struct RateLimiter {
    hits: BTreeMap<String, Hits>,
}

impl RateLimiter {
    /// Record a hit if the key is under its allowance, else report when it may
    /// try again.
    ///
    /// Returns `Ok(())` having already recorded the grant, so two concurrent
    /// requests cannot both pass; [`RateLimiter::rollback`] undoes it when the
    /// payment fails.
    fn take(
        &mut self,
        key: &str,
        now_ms: u64,
        window_ms: u64,
        allowance: u32,
        max_tracked: usize,
    ) -> Result<(), u64> {
        let entry = self.hits.entry(key.to_owned()).or_default();
        // Compare ages rather than a `now - window` cutoff. A saturating
        // subtraction clamps to zero, so with a clock near the epoch — which
        // is exactly what an injected test clock is — every hit would look
        // older than the window and the limiter would never limit anything.
        entry.retain(|t| now_ms.saturating_sub(*t) < window_ms);
        let used = u32::try_from(entry.len()).unwrap_or(u32::MAX);
        if used >= allowance {
            // The oldest hit still inside the window is the one that has to
            // age out before another is allowed.
            let oldest = entry.first().copied().unwrap_or(now_ms);
            let ready_at = oldest.saturating_add(window_ms);
            return Err(ready_at.saturating_sub(now_ms));
        }
        entry.push(now_ms);
        self.evict(max_tracked);
        Ok(())
    }

    /// Undo the most recent [`RateLimiter::take`] for a key.
    fn rollback(&mut self, key: &str, now_ms: u64) {
        if let Some(entry) = self.hits.get_mut(key) {
            if let Some(position) = entry.iter().rposition(|t| *t == now_ms) {
                entry.remove(position);
            }
            if entry.is_empty() {
                self.hits.remove(key);
            }
        }
    }

    /// Drop empty keys, then the least recently used ones, until the table
    /// fits.
    fn evict(&mut self, max_tracked: usize) {
        self.hits.retain(|_, hits| !hits.is_empty());
        while self.hits.len() > max_tracked {
            let Some(stalest) = self
                .hits
                .iter()
                .min_by_key(|(_, hits)| hits.last().copied().unwrap_or(0))
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.hits.remove(&stalest);
            tracing::warn!(
                tracked = self.hits.len(),
                "faucet rate-limit table full; evicting the least recent entry"
            );
        }
    }

    /// How many keys are being tracked. For tests and metrics.
    fn tracked(&self) -> usize {
        self.hits.len()
    }
}

/// The faucet: limits, a payment source and a clock.
#[derive(Debug)]
pub struct Faucet {
    config: FaucetConfig,
    source: Arc<dyn FaucetSource>,
    clock: Arc<dyn Clock>,
    limiter: Mutex<RateLimiter>,
}

impl Faucet {
    /// A faucet on the system clock.
    #[must_use]
    pub fn new(config: FaucetConfig, source: Arc<dyn FaucetSource>) -> Self {
        Faucet::with_clock(config, source, Arc::new(SystemClock))
    }

    /// A faucet on an injected clock, so the window can be tested without
    /// sleeping.
    #[must_use]
    pub fn with_clock(
        config: FaucetConfig,
        source: Arc<dyn FaucetSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Faucet { config, source, clock, limiter: Mutex::new(RateLimiter::default()) }
    }

    /// How this faucet is configured.
    #[must_use]
    pub const fn config(&self) -> &FaucetConfig {
        &self.config
    }

    /// How many keys the limiter is currently tracking.
    #[must_use]
    pub fn tracked_keys(&self) -> usize {
        self.limiter.lock().tracked()
    }

    /// Check the limits, build the payment, and spend the quota only if it
    /// worked.
    ///
    /// `client` is whatever the transport can attest to about the caller — a
    /// peer IP, or a proxy-supplied one. It is opaque here.
    ///
    /// # Errors
    /// [`RpcErrorCode::FaucetRateLimited`] when either window is exhausted,
    /// [`RpcErrorCode::FaucetDrained`] when the wallet cannot fund the
    /// payment, [`RpcErrorCode::FaucetFailed`] otherwise.
    pub fn dispense(&self, to: &Address, client: &str) -> Result<Transaction, RpcError> {
        let now = self.clock.now_ms();
        let address_key = format!("addr:{}", to.encode());
        let ip_key = format!("ip:{client}");

        {
            let mut limiter = self.limiter.lock();
            if let Err(wait_ms) = limiter.take(
                &address_key,
                now,
                self.config.address_window_ms,
                1,
                self.config.max_tracked,
            ) {
                return Err(rate_limited("this address", wait_ms));
            }
            if let Err(wait_ms) = limiter.take(
                &ip_key,
                now,
                self.config.ip_window_ms,
                self.config.ip_allowance,
                self.config.max_tracked,
            ) {
                limiter.rollback(&address_key, now);
                return Err(rate_limited("this client", wait_ms));
            }
        }

        match self.source.build_payment(to, self.config.amount) {
            Ok(tx) => Ok(tx),
            Err(e) => {
                let mut limiter = self.limiter.lock();
                limiter.rollback(&address_key, now);
                limiter.rollback(&ip_key, now);
                Err(e)
            }
        }
    }
}

/// The refusal message, with the wait rounded up to whole seconds.
fn rate_limited(who: &str, wait_ms: u64) -> RpcError {
    let seconds = wait_ms.saturating_add(999) / 1_000;
    RpcError::new(
        RpcErrorCode::FaucetRateLimited,
        format!("{who} has already been served; try again in {seconds}s"),
    )
}

/// A [`FaucetSource`] backed by a real wallet and the node's UTXO set.
///
/// The wallet's coin cache is refreshed from the chain on every request rather
/// than kept in step by a subscription. A faucet serves a request every few
/// minutes at most, the wallet holds a handful of addresses, and one scan is
/// far simpler than a second copy of the UTXO set that can drift out of date
/// and sign a double spend.
#[derive(Debug)]
pub struct WalletFaucetSource {
    wallet: Arc<Mutex<Wallet>>,
    chain: Arc<dyn ChainProvider>,
    fee_rate: u64,
}

impl WalletFaucetSource {
    /// Wrap a wallet and the chain it draws from.
    #[must_use]
    pub fn new(wallet: Arc<Mutex<Wallet>>, chain: Arc<dyn ChainProvider>, fee_rate: u64) -> Self {
        WalletFaucetSource { wallet, chain, fee_rate }
    }

    /// Every locking script the wallet can spend.
    fn scripts(wallet: &Wallet) -> Vec<Script> {
        wallet
            .addresses()
            .iter()
            .chain(wallet.change_addresses().iter())
            .map(Address::script_pubkey)
            .collect()
    }
}

impl FaucetSource for WalletFaucetSource {
    fn build_payment(&self, to: &Address, amount: Amount) -> Result<Transaction, RpcError> {
        let (_, tip_height) = self.chain.tip()?;
        let mut wallet = self.wallet.lock();
        let scripts = Self::scripts(&wallet);
        let utxos = self.chain.utxos_for_scripts(&scripts)?;
        if utxos.is_empty() {
            return Err(drained("the faucet wallet holds no coins"));
        }
        wallet.sync(utxos, tip_height);

        let request = SendRequest::to(*to, amount, self.fee_rate);
        let plan = wallet.send(&request, tip_height).map_err(map_wallet_error)?;
        Ok(plan.tx)
    }
}

/// A funding shortfall is [`RpcErrorCode::FaucetDrained`]; everything else is
/// [`RpcErrorCode::FaucetFailed`].
///
/// The distinction is what lets the explorer say "the faucet is empty, come
/// back after the next block" instead of "something went wrong".
fn map_wallet_error(e: WalletError) -> RpcError {
    match e {
        WalletError::InsufficientFunds { available, required } => drained(format!(
            "the faucet wallet has {available} grains available and needs {required}"
        )),
        WalletError::NetworkMismatch { found, expected } => RpcError::new(
            RpcErrorCode::InvalidAddress,
            format!("that is a {found} address; this faucet pays {expected}"),
        ),
        WalletError::DustOutput { .. } => RpcError::new(
            RpcErrorCode::FaucetFailed,
            "the configured faucet amount is below the dust threshold",
        ),
        other => RpcError::new(RpcErrorCode::FaucetFailed, other.to_string()),
    }
}

/// A drained-wallet refusal.
fn drained(detail: impl Into<String>) -> RpcError {
    RpcError::new(RpcErrorCode::FaucetDrained, detail)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_crypto::{PublicKey, SecretKey};
    use ferrum_types::Network;

    use super::*;

    /// A clock the test drives by hand.
    #[derive(Debug, Default)]
    struct ManualClock(Mutex<u64>);

    impl ManualClock {
        fn advance(&self, ms: u64) {
            *self.0.lock() += ms;
        }
    }

    impl Clock for ManualClock {
        fn now_ms(&self) -> u64 {
            *self.0.lock()
        }
    }

    /// A source that always succeeds, and counts how often it was asked.
    #[derive(Debug, Default)]
    struct CountingSource(Mutex<u32>);

    impl FaucetSource for CountingSource {
        fn build_payment(&self, _to: &Address, _amount: Amount) -> Result<Transaction, RpcError> {
            *self.0.lock() += 1;
            Ok(Transaction::empty())
        }
    }

    /// A source that is always empty.
    #[derive(Debug)]
    struct EmptySource;

    impl FaucetSource for EmptySource {
        fn build_payment(&self, _to: &Address, _amount: Amount) -> Result<Transaction, RpcError> {
            Err(drained("nothing to send"))
        }
    }

    fn address(byte: u8) -> Address {
        let secret = SecretKey::from_bytes(&[byte; 32]).unwrap();
        let public: PublicKey = secret.public_key();
        Address::p2pkh(Network::Devnet, &public)
    }

    fn faucet(source: Arc<dyn FaucetSource>, clock: Arc<ManualClock>) -> Faucet {
        Faucet::with_clock(
            FaucetConfig::default().with_ip_limit(60_000, 3).with_address_window_ms(600_000),
            source,
            clock,
        )
    }

    #[test]
    fn a_first_request_is_served() {
        let clock = Arc::new(ManualClock::default());
        let f = faucet(Arc::new(CountingSource::default()), Arc::clone(&clock));
        assert!(f.dispense(&address(1), "10.0.0.1").is_ok());
    }

    #[test]
    fn the_same_address_is_refused_inside_its_window() {
        let clock = Arc::new(ManualClock::default());
        let f = faucet(Arc::new(CountingSource::default()), Arc::clone(&clock));
        let a = address(2);
        assert!(f.dispense(&a, "10.0.0.1").is_ok());
        let err = f.dispense(&a, "10.0.0.2").unwrap_err();
        assert_eq!(err.code(), RpcErrorCode::FaucetRateLimited);
        assert!(err.detail().contains("address"));
    }

    #[test]
    fn the_address_window_expires() {
        let clock = Arc::new(ManualClock::default());
        let f = faucet(Arc::new(CountingSource::default()), Arc::clone(&clock));
        let a = address(3);
        assert!(f.dispense(&a, "10.0.0.1").is_ok());
        clock.advance(600_001);
        assert!(f.dispense(&a, "10.0.0.1").is_ok(), "the window should have expired");
    }

    #[test]
    fn one_client_ip_is_capped_across_addresses() {
        let clock = Arc::new(ManualClock::default());
        let f = faucet(Arc::new(CountingSource::default()), Arc::clone(&clock));
        for i in 0..3u8 {
            assert!(f.dispense(&address(10 + i), "10.0.0.9").is_ok(), "grant {i}");
        }
        let err = f.dispense(&address(20), "10.0.0.9").unwrap_err();
        assert_eq!(err.code(), RpcErrorCode::FaucetRateLimited);
        assert!(err.detail().contains("client"));
    }

    #[test]
    fn a_different_client_is_unaffected() {
        let clock = Arc::new(ManualClock::default());
        let f = faucet(Arc::new(CountingSource::default()), Arc::clone(&clock));
        for i in 0..3u8 {
            assert!(f.dispense(&address(30 + i), "10.0.0.9").is_ok());
        }
        assert!(f.dispense(&address(40), "10.0.0.10").is_ok());
    }

    #[test]
    fn an_empty_wallet_refuses_politely_and_does_not_spend_the_quota() {
        let clock = Arc::new(ManualClock::default());
        let f = faucet(Arc::new(EmptySource), Arc::clone(&clock));
        let a = address(4);
        let err = f.dispense(&a, "10.0.0.1").unwrap_err();
        assert_eq!(err.code(), RpcErrorCode::FaucetDrained);
        // The failed attempt must not have consumed the address's turn.
        let again = f.dispense(&a, "10.0.0.1").unwrap_err();
        assert_eq!(again.code(), RpcErrorCode::FaucetDrained, "quota was spent on a failure");
        assert_eq!(f.tracked_keys(), 0, "a rolled-back key leaves nothing behind");
    }

    #[test]
    fn the_refusal_says_how_long_to_wait() {
        let clock = Arc::new(ManualClock::default());
        let f = faucet(Arc::new(CountingSource::default()), Arc::clone(&clock));
        let a = address(5);
        assert!(f.dispense(&a, "10.0.0.1").is_ok());
        clock.advance(100_000);
        let err = f.dispense(&a, "10.0.0.1").unwrap_err();
        // 600_000 ms window, 100_000 elapsed, so 500 seconds remain.
        assert!(err.detail().contains("500s"), "{}", err.detail());
    }

    #[test]
    fn the_tracking_table_is_bounded() {
        let clock = Arc::new(ManualClock::default());
        let config = FaucetConfig::default()
            .with_ip_limit(60_000, 1_000)
            .with_address_window_ms(600_000);
        let config = FaucetConfig { max_tracked: 4, ..config };
        let f = Faucet::with_clock(
            config,
            Arc::new(CountingSource::default()),
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        for i in 0..50u8 {
            clock.advance(1);
            assert!(f.dispense(&address(i.saturating_add(1)), "10.0.0.1").is_ok());
        }
        assert!(f.tracked_keys() <= 4, "tracked {} keys", f.tracked_keys());
    }

    #[test]
    fn the_default_grant_is_one_frm() {
        assert_eq!(FaucetConfig::default().amount, Amount::from_grains(100_000_000));
    }

    #[test]
    fn wallet_shortfalls_become_drained_not_failed() {
        let err = map_wallet_error(WalletError::InsufficientFunds {
            available: 1,
            required: 10,
        });
        assert_eq!(err.code(), RpcErrorCode::FaucetDrained);
        assert!(err.detail().contains('1'));
    }
}
