//! Spending what a node mined: real coin selection, a real BIP-340 signature,
//! and the same relay-then-gossip path `sendrawtransaction` takes.
//!
//! # Why the harness holds the keys
//!
//! Without `--mine-address` a node pays its coinbases to an address derived
//! from `<datadir>/node.key` (CONTRACT §13.1), which is what makes a devnet
//! startable with no wallet. The harness derives that same key when it creates
//! the slot, so it can build a payment out of a node's own rewards without a
//! keystore, a passphrase or an RPC round trip. That is `ferrum-node`'s faucet
//! trick, used for the same reason.
//!
//! # Maturity is applied here, not discovered later
//!
//! Every coin a mining node holds on a young chain is a coinbase, and a
//! coinbase is unspendable for `coinbase_maturity` blocks — 100, on devnet as
//! on mainnet. Filtering immature coins out *before* selection turns "the
//! transaction was built and then the mempool refused it" into an honest
//! "there is nothing spendable yet", which is a far better failure message at
//! two in the morning.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ferrum_script::SigHashType;
use ferrum_types::{Amount, Coin, OutPoint, Transaction, Txid};
use ferrum_wallet::{BuildParams, SendRequest, dust_threshold, plan_transaction, sign_transaction};

use crate::harness::{POLL_INTERVAL, TestNet};

/// The fee rate the harness pays, in grains per 1000 bytes.
///
/// Twice devnet's `min_relay_fee_per_kb`, so a transaction clears the relay
/// floor with room to spare. A test that failed because it paid exactly the
/// minimum and lost a rounding argument would be a test about arithmetic, not
/// about propagation.
pub const HARNESS_FEE_RATE: u64 = 2_000;

impl TestNet {
    /// The coins node `index` mined that it could spend in the next block.
    ///
    /// In ascending outpoint order, because that is the order `iter_utxos`
    /// walks and a deterministic selection makes a failing test reproducible.
    ///
    /// # Errors
    ///
    /// When the node is not running, or on a storage failure.
    pub fn spendable_coins(&self, index: usize) -> Result<Vec<(OutPoint, Coin)>> {
        let slot = self.slot(index)?;
        let node = self.node(index)?;
        let (_, tip_height) = node.chain().tip();
        // The payment lands in the *next* block, so that is the height the
        // maturity rule will be evaluated at.
        let spend_height = tip_height.saturating_add(1);
        let maturity = self.params.coinbase_maturity;

        let mut coins = Vec::new();
        for entry in node.store().iter_utxos().context("opening a UTXO snapshot")? {
            let (out_point, coin) = entry.context("decoding a UTXO")?;
            if coin.script_pubkey != slot.script {
                continue;
            }
            if coin.is_coinbase && spend_height < coin.height.saturating_add(maturity) {
                continue;
            }
            coins.push((out_point, coin));
        }
        Ok(coins)
    }

    /// Mine on node `index` until its first coinbase is spendable.
    ///
    /// `coinbase_maturity + 1` blocks, which is 101 on every Ferrum network
    /// including devnet: maturity is a *consensus* rule and a devnet that
    /// relaxed it would stop being evidence about mainnet. Sealing is trivial
    /// here, so the cost is a hundred `redb` commits, not a hundred nonces.
    ///
    /// Returns the height reached.
    ///
    /// # Errors
    ///
    /// As [`TestNet::mine_blocks`].
    pub async fn mine_to_maturity(&self, index: usize) -> Result<u64> {
        let blocks = usize::try_from(self.params.coinbase_maturity)
            .context("this platform cannot count to the coinbase maturity")?
            .saturating_add(1);
        let already = usize::try_from(self.node(index)?.chain().tip().1).unwrap_or(usize::MAX);
        self.mine_blocks(index, blocks.saturating_sub(already)).await?;
        Ok(self.node(index)?.chain().tip().1)
    }

    /// The confirmed, mature balance node `index` holds in its own key.
    ///
    /// # Errors
    ///
    /// As [`TestNet::spendable_coins`], or when the sum overflows — which needs
    /// more coins than there is money.
    pub fn spendable_balance(&self, index: usize) -> Result<Amount> {
        let mut total = Amount::ZERO;
        for (_, coin) in self.spendable_coins(index)? {
            total = total
                .checked_add(coin.value)
                .ok_or_else(|| anyhow!("node {index}'s spendable balance overflowed"))?;
        }
        Ok(total)
    }

    /// Build a signed payment of `amount` from node `from`'s coins.
    ///
    /// Change returns to the payer's own address, exactly as the node's faucet
    /// does, so a test can spend from the same node twice.
    ///
    /// # Errors
    ///
    /// When the node is not running, when it has nothing mature to spend, or
    /// when planning or signing fails.
    pub fn build_payment(
        &self,
        from: usize,
        to: &ferrum_crypto::Address,
        amount: Amount,
    ) -> Result<Transaction> {
        let slot = self.slot(from)?;
        let (_, tip_height) = self.node(from)?.chain().tip();
        let candidates = self.spendable_coins(from)?;
        if candidates.is_empty() {
            bail!(
                "node {from} has no mature coins to spend at height {tip_height}; \
                 a coinbase matures after {} blocks",
                self.params.coinbase_maturity
            );
        }

        let request = SendRequest::to(*to, amount, HARNESS_FEE_RATE);
        let params =
            BuildParams::at_tip(dust_threshold(self.params.min_relay_fee_per_kb), tip_height);
        let plan =
            plan_transaction(&candidates, &request, &slot.address, &params).with_context(|| {
                format!("planning a payment of {} from node {from}", amount.to_frm_string())
            })?;

        let prevouts = plan.prevouts();
        let mut tx = plan.tx;
        let want = slot.script.clone();
        let secret = slot.secret.clone();
        sign_transaction(&mut tx, &prevouts, self.params.chain_id, SigHashType::ALL, |script| {
            // One key, one script. Returning `None` for anything else makes a
            // coin-selection bug a typed error instead of a signature over an
            // input this key cannot unlock.
            (*script == want).then(|| secret.clone())
        })
        .context("signing the payment")?;
        Ok(tx)
    }

    /// Offer a transaction to node `index` and gossip it onwards.
    ///
    /// Both halves of what `sendrawtransaction` does: the mempool decides, and
    /// only an accepted transaction is relayed. A transaction the node refuses
    /// is an error here rather than a silent no-op, because a test that
    /// submitted a transaction nobody kept would go on to wait for a
    /// confirmation that can never come.
    ///
    /// # Errors
    ///
    /// When the node is not running or its mempool refused the transaction.
    pub async fn submit_transaction(&self, index: usize, tx: Transaction) -> Result<Txid> {
        let node = self.node(index)?;
        let relay = std::sync::Arc::clone(node.relay());
        let offered = tx.clone();
        let outcome = tokio::task::spawn_blocking(move || relay.accept_transaction(offered))
            .await
            .with_context(|| format!("node {index}'s mempool task panicked"))?;

        if !outcome.should_relay() {
            let reason = outcome
                .error
                .as_ref()
                .map_or_else(|| format!("{:?}", outcome.result), ToString::to_string);
            bail!("node {index} refused transaction {}: {reason}", outcome.txid);
        }

        let handle = node
            .p2p()
            .ok_or_else(|| anyhow!("node {index} has no p2p service to relay through"))?;
        match handle.publish_tx(tx).await {
            Ok(_) => {}
            Err(e) if e.is_no_peers() => {
                tracing::debug!(node = index, "no mesh peers yet; the transaction was not relayed");
            }
            Err(e) => bail!("node {index} could not relay a transaction: {e}"),
        }
        Ok(outcome.txid)
    }

    /// Whether node `index` is holding `txid` in its mempool.
    ///
    /// # Errors
    ///
    /// When the node is not running.
    pub fn mempool_contains(&self, index: usize, txid: &Txid) -> Result<bool> {
        Ok(self.node(index)?.mempool().contains(txid))
    }

    /// Where node `index` has `txid` confirmed, or `None` if it does not.
    ///
    /// Reads the reverse index the harness switches on for every node, which is
    /// the same question the explorer's `/api/tx/:txid` asks.
    ///
    /// # Errors
    ///
    /// When the node is not running, or on a storage failure.
    pub fn confirmed_in(
        &self,
        index: usize,
        txid: &Txid,
    ) -> Result<Option<ferrum_storage::TxLocation>> {
        self.node(index)?
            .store()
            .tx_location(txid)
            .with_context(|| format!("reading node {index}'s transaction index"))
    }

    /// Wait until node `index` holds `txid` in its mempool.
    ///
    /// # Errors
    ///
    /// After `timeout`, with [`TestNet::describe`] in the message.
    pub async fn await_in_mempool(
        &self,
        index: usize,
        txid: &Txid,
        timeout: Duration,
    ) -> Result<()> {
        let poll = async {
            while !self.mempool_contains(index, txid).unwrap_or(false) {
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        };
        match tokio::time::timeout(timeout, poll).await {
            Ok(()) => Ok(()),
            Err(_) => Err(anyhow!(
                "node {index} did not see transaction {txid} within {timeout:?}\n{}",
                self.describe().await
            )),
        }
    }

    /// Wait until node `index` has `txid` in a block on its active chain.
    ///
    /// # Errors
    ///
    /// After `timeout`, with [`TestNet::describe`] in the message.
    pub async fn await_confirmed(
        &self,
        index: usize,
        txid: &Txid,
        timeout: Duration,
    ) -> Result<ferrum_storage::TxLocation> {
        let poll = async {
            loop {
                if let Ok(Some(location)) = self.confirmed_in(index, txid) {
                    return location;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        };
        match tokio::time::timeout(timeout, poll).await {
            Ok(location) => Ok(location),
            Err(_) => Err(anyhow!(
                "node {index} did not confirm transaction {txid} within {timeout:?}\n{}",
                self.describe().await
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_types::COIN;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn coins_stay_immature_until_the_maturity_window_has_passed() {
        let net = TestNet::spawn(1).await.unwrap();
        let maturity = net.params().coinbase_maturity;

        net.mine_blocks(0, 4).await.unwrap();
        assert!(net.spendable_coins(0).unwrap().is_empty(), "four blocks is not {maturity}");
        assert_eq!(net.spendable_balance(0).unwrap(), Amount::ZERO);
        let refused = net
            .build_payment(0, &net.address(0).unwrap(), Amount::from_grains(COIN))
            .unwrap_err()
            .to_string();
        assert!(refused.contains("no mature coins"), "{refused}");

        net.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_matured_coinbase_can_be_spent_and_confirmed_on_the_same_node() {
        let net = TestNet::spawn(1).await.unwrap();
        let maturity = net.params().coinbase_maturity;
        net.mine_blocks(0, usize::try_from(maturity).unwrap() + 1).await.unwrap();

        // At tip height 101 a payment lands at 102, and the maturity rule is
        // `height >= coin.height + 100`, so heights 1 and 2 have matured.
        let coins = net.spendable_coins(0).unwrap();
        assert_eq!(coins.len(), 2, "the coinbases of heights 1 and 2 have matured");
        assert!(net.spendable_balance(0).unwrap() > Amount::ZERO);

        let txid = {
            let tx =
                net.build_payment(0, &net.address(0).unwrap(), Amount::from_grains(COIN)).unwrap();
            net.submit_transaction(0, tx).await.unwrap()
        };
        assert!(net.mempool_contains(0, &txid).unwrap());
        assert_eq!(net.confirmed_in(0, &txid).unwrap(), None, "not confirmed until it is mined");

        net.mine_one(0).await.unwrap();
        let location = net.await_confirmed(0, &txid, Duration::from_secs(10)).await.unwrap();
        assert_eq!(location.block_hash, net.tip(0).unwrap());
        assert!(location.index > 0, "a payment is never the coinbase");
        assert!(!net.mempool_contains(0, &txid).unwrap(), "a confirmed tx leaves the pool");

        net.shutdown().await.unwrap();
    }
}
