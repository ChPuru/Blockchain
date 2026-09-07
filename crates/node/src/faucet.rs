//! Funding the devnet faucet from the node's own key.
//!
//! `ferrum-rpc` owns the faucet itself — the rate limiting, the REST handler
//! and the [`FaucetSource`] trait. What it cannot own is *where the money comes
//! from*, because that is a node-level decision. This module answers it.
//!
//! # Why the node key and not a separate wallet
//!
//! Without `--mine-address` the node already mines to an address derived from
//! `<datadir>/node.key`, generated on first run, so that "a devnet must be
//! startable with no wallet setup" (CONTRACT §13.1). The faucet draws from that
//! same key. `chaind --mine --faucet` is therefore self-funding with no
//! keystore, no passphrase and no operator step — the same property the mining
//! default was written for, applied to the thing that hands the coins out.
//!
//! A node given an explicit `--mine-address` sends its rewards elsewhere. The
//! faucet still draws from the node key, so it starts empty and reports
//! [`RpcErrorCode::FaucetDrained`] until someone funds that address. Reporting
//! "empty" is right; quietly paying from wherever the miner happened to point
//! would make the faucet spend coins the operator had earmarked.
//!
//! # Maturity is applied here
//!
//! Every coin this key holds on a mining node is a coinbase, so nearly all of
//! them are inside the maturity window on a young chain. Filtering them out
//! before coin selection is what turns "the faucet built a transaction the
//! mempool then rejected" into an honest "the faucet has nothing spendable
//! yet".

use std::sync::Arc;

use ferrum_crypto::{Address, SecretKey};
use ferrum_rpc::{ChainProvider, FaucetSource, RpcError, RpcErrorCode};
use ferrum_script::SigHashType;
use ferrum_types::{Amount, ChainId, Coin, OutPoint, Script, Transaction};
use ferrum_wallet::{BuildParams, SendRequest, WalletError, plan_transaction, sign_transaction};

/// A [`FaucetSource`] that spends the coins paid to the node's own key.
///
/// Holds the secret, so it is deliberately not `Clone` and its [`Debug`] never
/// prints key material.
pub struct NodeKeyFaucetSource {
    secret: SecretKey,
    address: Address,
    script: Script,
    chain: Arc<dyn ChainProvider>,
    chain_id: ChainId,
    dust_threshold: Amount,
    coinbase_maturity: u64,
    fee_rate: u64,
}

impl std::fmt::Debug for NodeKeyFaucetSource {
    /// Never prints the secret. The address is public information and is the
    /// field an operator actually needs when reading a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeKeyFaucetSource")
            .field("address", &self.address.encode())
            .field("fee_rate", &self.fee_rate)
            .finish_non_exhaustive()
    }
}

impl NodeKeyFaucetSource {
    /// Build a source over `secret`, which must be the key for `address`.
    #[must_use]
    pub fn new(
        secret: SecretKey,
        address: Address,
        chain: Arc<dyn ChainProvider>,
        chain_id: ChainId,
        dust_threshold: Amount,
        coinbase_maturity: u64,
        fee_rate: u64,
    ) -> Self {
        let script = address.script_pubkey();
        NodeKeyFaucetSource {
            secret,
            address,
            script,
            chain,
            chain_id,
            dust_threshold,
            coinbase_maturity,
            fee_rate,
        }
    }

    /// The address the faucet pays from, for logs and for funding it by hand.
    #[must_use]
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Whether a coin can be spent at `tip_height`.
    ///
    /// Consensus (CONTRACT §8.1) allows a coinbase at `coin.height + maturity`;
    /// this uses the same boundary rather than the explorer's more conservative
    /// one, because a transaction built here is going straight into a block.
    fn is_spendable(coin: &Coin, tip_height: u64, maturity: u64) -> bool {
        if !coin.is_coinbase {
            return true;
        }
        // The payment lands in the *next* block, so that is the height the
        // maturity rule will be evaluated at.
        tip_height.saturating_add(1) >= coin.height.saturating_add(maturity)
    }

    /// Coins this key can spend right now, in outpoint order.
    fn spendable(&self, tip_height: u64) -> Result<Vec<(OutPoint, Coin)>, RpcError> {
        let utxos = self.chain.utxos_for_scripts(std::slice::from_ref(&self.script))?;
        Ok(utxos
            .into_iter()
            .filter(|(_, coin)| Self::is_spendable(coin, tip_height, self.coinbase_maturity))
            .collect())
    }
}

impl FaucetSource for NodeKeyFaucetSource {
    fn build_payment(&self, to: &Address, amount: Amount) -> Result<Transaction, RpcError> {
        let (_, tip_height) = self.chain.tip()?;
        let candidates = self.spendable(tip_height)?;
        if candidates.is_empty() {
            return Err(RpcError::new(
                RpcErrorCode::FaucetDrained,
                format!(
                    "the faucet key {} holds no spendable coins yet; \
                     coinbase outputs mature after {} blocks",
                    self.address.encode(),
                    self.coinbase_maturity
                ),
            ));
        }

        let request = SendRequest::to(*to, amount, self.fee_rate);
        let params = BuildParams::at_tip(self.dust_threshold, tip_height);
        // Change returns to the faucet's own address, so the faucet refills
        // itself from its own change instead of leaking the remainder to fees.
        let plan = plan_transaction(&candidates, &request, &self.address, &params)
            .map_err(map_wallet_error)?;

        let prevouts = plan.prevouts();
        let mut tx = plan.tx;
        let want = self.script.clone();
        let secret = self.secret.clone();
        sign_transaction(&mut tx, &prevouts, self.chain_id, SigHashType::ALL, |script| {
            // One key, one script. Anything else is a coin selection bug, and
            // `sign_transaction` turns the `None` into a typed error rather
            // than signing something it cannot unlock.
            (*script == want).then(|| secret.clone())
        })
        .map_err(map_wallet_error)?;
        Ok(tx)
    }
}

/// A funding shortfall is [`RpcErrorCode::FaucetDrained`]; everything else is
/// [`RpcErrorCode::FaucetFailed`].
///
/// The same split `ferrum_rpc::WalletFaucetSource` makes, so the explorer can
/// say "the faucet is empty, come back after the next block" rather than
/// "something went wrong" whichever source a node runs.
fn map_wallet_error(e: WalletError) -> RpcError {
    match e {
        WalletError::InsufficientFunds { available, required } => RpcError::new(
            RpcErrorCode::FaucetDrained,
            format!("the faucet has {available} grains available and needs {required}"),
        ),
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

#[cfg(test)]
mod tests;
