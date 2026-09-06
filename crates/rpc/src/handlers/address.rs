//! Address queries: `getbalance`, `listunspent` and the explorer's address
//! page.
//!
//! All three read the same [`AddressReport`], so a balance and a history can
//! never disagree about the same address.
//!
//! # These queries need the reverse index
//!
//! There is no address-to-UTXO table in the consensus state — the UTXO set is
//! keyed by outpoint, as it must be. The `addr_index` table maps an address key
//! to every transaction that touched it, and that is what makes an address
//! query a bounded lookup rather than a full scan of the UTXO set. A node
//! started without `--index` reports [`crate::error::RpcErrorCode::IndexDisabled`],
//! which is the contract's answer (`[index required]`, CONTRACT §11).
//!
//! # Maturity
//!
//! A coinbase output counts as `immature` while `tip_height - coin.height <
//! coinbase_maturity`. Consensus (SPEC §4.2) would already allow spending it in
//! the block at `coin.height + maturity`, which is one block earlier; matching
//! the wallet's more conservative rule keeps the explorer and the wallet from
//! showing different numbers for the same coins.

use std::collections::{BTreeMap, BTreeSet};

use ferrum_crypto::Address;
use ferrum_types::{Amount, Coin, OutPoint, Txid};

use crate::error::RpcError;
use crate::handlers::convert;
use crate::handlers::lookup::{self, ADDRESS_HISTORY_LIMIT};
use crate::provider::{ChainProvider, MempoolProvider};
use crate::types::rpc::{AddressBalance, UnspentJson};

/// One transaction in an address's history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressHistoryEntry {
    /// The transaction.
    pub txid: Txid,
    /// The confirming height, or `None` for a mempool transaction.
    pub height: Option<u64>,
    /// Net change to this address, in grains. Signed, held wide enough that
    /// the difference of two `u64` grain counts can never wrap.
    pub delta: i128,
    /// The confirming block's timestamp, Unix milliseconds.
    pub timestamp_ms: Option<u64>,
}

/// Everything the three address queries need, gathered once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressReport {
    /// The address, canonically decoded.
    pub address: Address,
    /// Its `addr_index` key: the raw 20- or 32-byte payload.
    pub key: Vec<u8>,
    /// Spendable now.
    pub confirmed: Amount,
    /// Coinbase outputs still inside the maturity window.
    pub immature: Amount,
    /// Credits sitting in the mempool.
    pub pending: Amount,
    /// Unspent outputs paying this address, ascending by outpoint.
    pub utxos: Vec<(OutPoint, Coin)>,
    /// History, newest first.
    pub history: Vec<AddressHistoryEntry>,
}

impl AddressReport {
    /// How many unspent outputs back the balance.
    #[must_use]
    pub fn utxo_count(&self) -> u64 {
        u64::try_from(self.utxos.len()).unwrap_or(u64::MAX)
    }

    /// How many transactions touched this address.
    #[must_use]
    pub fn tx_count(&self) -> u64 {
        u64::try_from(self.history.len()).unwrap_or(u64::MAX)
    }
}

/// Gather everything known about an address.
///
/// # Errors
/// [`crate::error::RpcErrorCode::InvalidAddress`] for an address from another
/// network, [`crate::error::RpcErrorCode::IndexDisabled`] without the reverse
/// index, and storage failures otherwise.
pub fn address_report(
    chain: &dyn ChainProvider,
    mempool: &dyn MempoolProvider,
    address_str: &str,
) -> Result<AddressReport, RpcError> {
    let params = chain.params();
    let address = convert::parse_address(address_str, params.network)?;
    let key = convert::address_index_key(&address);
    let (_, tip_height) = chain.tip()?;

    // The index stores one row per (address key, height, position), so a
    // transaction that pays the same address twice appears once. Deduplicate
    // anyway: a transaction that both spends from and pays to the address is
    // filed under both its input and its output scripts.
    let mut seen: BTreeSet<Txid> = BTreeSet::new();
    let mut ordered: Vec<(u64, Txid)> = Vec::new();
    for (height, txid) in chain.address_history(&key, 0, ADDRESS_HISTORY_LIMIT)? {
        if seen.insert(txid) {
            ordered.push((height, txid));
        }
    }

    let mut utxos: BTreeMap<OutPoint, Coin> = BTreeMap::new();
    let mut history: Vec<AddressHistoryEntry> = Vec::with_capacity(ordered.len());

    for (height, txid) in ordered {
        let Some(found) = lookup::find_transaction(chain, &txid)? else {
            // The index named a transaction the store no longer holds. That
            // happens transiently during a reorg; skipping it beats failing
            // the whole page.
            tracing::debug!(txid = %txid, "address index names a transaction the store lacks");
            continue;
        };
        let mut received = Amount::ZERO;
        for (vout, output) in found.tx.outputs.iter().enumerate() {
            if !convert::script_pays_key(&output.script_pubkey, &key) {
                continue;
            }
            received = received
                .checked_add(output.value)
                .ok_or_else(|| RpcError::overflow("address credits"))?;
            let out_point =
                OutPoint::new(found.txid, u32::try_from(vout).unwrap_or(u32::MAX));
            if let Some(coin) = chain.coin(&out_point)? {
                utxos.insert(out_point, coin);
            }
        }

        let mut sent = Amount::ZERO;
        for coin in lookup::resolve_prevouts(chain, &found.tx)?.into_iter().flatten() {
            if !convert::script_pays_key(&coin.script_pubkey, &key) {
                continue;
            }
            sent =
                sent.checked_add(coin.value).ok_or_else(|| RpcError::overflow("address debits"))?;
        }

        history.push(AddressHistoryEntry {
            txid: found.txid,
            height: Some(height),
            delta: i128::from(received.to_grains()) - i128::from(sent.to_grains()),
            timestamp_ms: Some(found.timestamp_ms),
        });
    }

    // Newest first, which is the order the explorer renders.
    history.reverse();

    // Mempool credits. A mempool transaction has no height, and the explorer
    // renders it with a "pending" pill.
    let mut pending = Amount::ZERO;
    for txid in mempool.txids() {
        let Some(entry) = mempool.get(&txid) else { continue };
        let mut received = Amount::ZERO;
        for output in &entry.tx.outputs {
            if convert::script_pays_key(&output.script_pubkey, &key) {
                received = received
                    .checked_add(output.value)
                    .ok_or_else(|| RpcError::overflow("pending credits"))?;
            }
        }
        if received.is_zero() {
            continue;
        }
        pending =
            pending.checked_add(received).ok_or_else(|| RpcError::overflow("pending balance"))?;
        history.insert(
            0,
            AddressHistoryEntry {
                txid,
                height: None,
                delta: i128::from(received.to_grains()),
                timestamp_ms: None,
            },
        );
    }

    let mut confirmed = Amount::ZERO;
    let mut immature = Amount::ZERO;
    for coin in utxos.values() {
        let bucket = if is_immature(coin, tip_height, params.coinbase_maturity) {
            &mut immature
        } else {
            &mut confirmed
        };
        *bucket =
            bucket.checked_add(coin.value).ok_or_else(|| RpcError::overflow("address balance"))?;
    }

    Ok(AddressReport {
        address,
        key,
        confirmed,
        immature,
        pending,
        utxos: utxos.into_iter().collect(),
        history,
    })
}

/// Whether a coinbase output is still inside its maturity window.
///
/// See the module documentation for why this is one block more conservative
/// than consensus.
#[must_use]
pub fn is_immature(coin: &Coin, tip_height: u64, maturity: u64) -> bool {
    coin.is_coinbase && tip_height.saturating_sub(coin.height) < maturity
}

/// `getbalance(address)`.
///
/// # Errors
/// As [`address_report`].
pub fn get_balance(
    chain: &dyn ChainProvider,
    mempool: &dyn MempoolProvider,
    address: &str,
) -> Result<AddressBalance, RpcError> {
    let report = address_report(chain, mempool, address)?;
    Ok(AddressBalance {
        confirmed: report.confirmed.into(),
        immature: report.immature.into(),
        utxo_count: report.utxo_count(),
    })
}

/// `listunspent(address)`.
///
/// # Errors
/// As [`address_report`].
pub fn list_unspent(
    chain: &dyn ChainProvider,
    mempool: &dyn MempoolProvider,
    address: &str,
) -> Result<Vec<UnspentJson>, RpcError> {
    let report = address_report(chain, mempool, address)?;
    Ok(report
        .utxos
        .iter()
        .map(|(out_point, coin)| UnspentJson {
            outpoint: convert::outpoint_string(out_point),
            value: coin.value.into(),
            height: coin.height,
            script: coin.script_pubkey.to_hex(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_types::Script;

    use super::*;

    fn coinbase_coin(height: u64) -> Coin {
        Coin {
            value: Amount::from_grains(1),
            script_pubkey: Script::new(vec![0x51]),
            height,
            is_coinbase: true,
        }
    }

    #[test]
    fn a_coinbase_is_immature_until_the_window_passes() {
        let coin = coinbase_coin(10);
        assert!(is_immature(&coin, 10, 100));
        assert!(is_immature(&coin, 109, 100));
        assert!(!is_immature(&coin, 110, 100));
    }

    #[test]
    fn a_normal_output_is_never_immature() {
        let coin = Coin { is_coinbase: false, ..coinbase_coin(10) };
        assert!(!is_immature(&coin, 10, 100));
    }
}
