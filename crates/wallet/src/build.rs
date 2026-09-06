//! Turning a [`SendRequest`] into an unsigned [`Transaction`].
//!
//! The order of operations here is the whole point:
//!
//! 1. price every candidate coin at the requested fee rate,
//! 2. **size the transaction as it will look once signed**,
//! 3. select coins against that size,
//! 4. assemble, and
//! 5. re-derive the size from the assembled skeleton and refuse to continue if
//!    it disagrees with what selection was told.
//!
//! Step 2 is the one wallets get wrong. Sizing the unsigned skeleton
//! underestimates by 99 bytes per input — the signature and public key that do
//! not exist yet — so the transaction pays roughly half the fee rate the user
//! asked for and sits in the mempool until it expires. [`crate::sign`] closes
//! the loop by measuring the signed transaction and comparing.
//!
//! # Anti-fee-sniping
//!
//! `lock_time` is set to the current tip height with `sequence =
//! 0xfffffffe`, which is Bitcoin Core's anti-fee-sniping construction. The
//! transaction is final the moment it can be mined (the next block is at
//! `tip_height + 1 > lock_time`, and CONTRACT §4.3 requires only `lock_time <=
//! height`), but it cannot be pulled into a *re-mined* older block. That
//! removes a small incentive to reorg the chain tip for the fees in it.
//!
//! # Output order
//!
//! Recipients keep the order the request gave them and change goes last. A
//! privacy-maximising wallet shuffles, but shuffling needs an RNG and
//! `Wallet::build_transaction` has none in its contract signature; a
//! reproducible transaction is worth more here than the last increment of
//! change-output ambiguity, and the trade is written down rather than
//! accidental.

use ferrum_crypto::Address;
use ferrum_types::{Amount, Coin, LOCKTIME_THRESHOLD, OutPoint, Script, Transaction, TxIn, TxOut};

use crate::error::WalletError;
use crate::fee::{
    FeeRate, P2PKH_INPUT_BYTES, P2PKH_SCRIPT_SIG_BYTES, TX_OVERHEAD_BYTES, input_size, output_size,
};
use crate::select::{Candidate, Selection, SelectionParams, SelectionStrategy, select_coins};

/// `sequence` value that leaves `lock_time` active.
///
/// `u32::MAX` would make the transaction unconditionally final and disable the
/// anti-fee-sniping lock time; one less than that enables it while still
/// disabling BIP-68 relative locks (bit 31 clear would enable them, and we do
/// not want one).
pub const SEQUENCE_ENABLE_LOCKTIME: u32 = 0xffff_fffe;

/// The transaction version this wallet writes.
pub const DEFAULT_TX_VERSION: u32 = 1;

/// The largest transaction the wallet will build.
///
/// Bitcoin's standardness limit. A transaction above it is consensus-valid but
/// relayed by nobody, so building one wastes the user's coins on a fee that
/// buys no confirmation.
pub const MAX_TRANSACTION_BYTES: usize = 100_000;

/// What to send, and how urgently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendRequest {
    /// Recipients, in the order they will appear in the transaction.
    pub outputs: Vec<(Address, Amount)>,
    /// Grains per 1000 bytes.
    pub fee_rate: u64,
    /// Where change goes. `None` uses the wallet's own change chain.
    pub change_to: Option<Address>,
}

impl SendRequest {
    /// A single-recipient request.
    pub fn to(address: Address, amount: Amount, fee_rate: u64) -> Self {
        SendRequest { outputs: vec![(address, amount)], fee_rate, change_to: None }
    }

    /// Add another recipient.
    #[must_use]
    pub fn and_to(mut self, address: Address, amount: Amount) -> Self {
        self.outputs.push((address, amount));
        self
    }

    /// Send change somewhere specific.
    #[must_use]
    pub fn with_change_to(mut self, address: Address) -> Self {
        self.change_to = Some(address);
        self
    }

    /// Sum of every recipient amount.
    pub fn total(&self) -> Result<Amount, WalletError> {
        let mut total = Amount::ZERO;
        for (_, amount) in &self.outputs {
            total = total
                .checked_add(*amount)
                .ok_or(WalletError::AmountOverflow("summing requested outputs"))?;
        }
        if !total.is_valid_money() {
            return Err(WalletError::AmountOverflow("summing requested outputs"));
        }
        Ok(total)
    }
}

/// The knobs the builder needs that are not in the request.
#[derive(Clone, Copy, Debug)]
pub struct BuildParams {
    /// Change below this is folded into the fee.
    pub dust_threshold: Amount,
    /// `lock_time` for the transaction.
    pub lock_time: u32,
    /// `version` for the transaction.
    pub tx_version: u32,
    /// `sequence` for every input.
    pub sequence: u32,
}

impl BuildParams {
    /// Defaults for a wallet at `tip_height`: anti-fee-sniping lock time,
    /// locktime-enabling sequence, version 1.
    pub fn at_tip(dust_threshold: Amount, tip_height: u64) -> Self {
        // A height at or above `LOCKTIME_THRESHOLD` would be reinterpreted as
        // a Unix timestamp (CONTRACT §3), which would lock the transaction
        // until the year 1985 — i.e. never, since it is already past. Fall
        // back to no lock time rather than build something unspendable.
        let lock_time =
            u32::try_from(tip_height).ok().filter(|h| *h < LOCKTIME_THRESHOLD).unwrap_or(0);
        BuildParams {
            dust_threshold,
            lock_time,
            tx_version: DEFAULT_TX_VERSION,
            sequence: SEQUENCE_ENABLE_LOCKTIME,
        }
    }
}

/// An unsigned transaction plus everything needed to sign and audit it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxPlan {
    /// The unsigned transaction. Every `script_sig` is empty.
    pub tx: Transaction,
    /// The coins being spent, in the same order as `tx.inputs`.
    pub selected: Vec<(OutPoint, Coin)>,
    /// Sum of the recipient outputs.
    pub target: Amount,
    /// The fee this transaction pays.
    pub fee: Amount,
    /// The change amount, or `None` for a changeless transaction.
    pub change: Option<Amount>,
    /// Size of the transaction **once signed**, in bytes.
    pub estimated_size: usize,
    /// Which selector produced it.
    pub strategy: SelectionStrategy,
}

impl TxPlan {
    /// The prevouts, in input order, ready for
    /// [`crate::Wallet::sign_transaction`].
    pub fn prevouts(&self) -> Vec<Coin> {
        self.selected.iter().map(|(_, coin)| coin.clone()).collect()
    }

    /// The outpoints being spent, for reserving them in the coin cache.
    pub fn out_points(&self) -> Vec<OutPoint> {
        self.selected.iter().map(|(op, _)| *op).collect()
    }

    /// The fee rate this transaction will realise, in grains per 1000 bytes.
    pub fn fee_rate(&self) -> u64 {
        FeeRate::of(self.fee, self.estimated_size)
    }
}

/// Build an unsigned transaction paying `req` from `candidates`.
///
/// `candidates` must already be filtered to spendable coins — this function
/// knows nothing about maturity or confirmations, only about value and size.
pub fn plan_transaction(
    candidates: &[(OutPoint, Coin)],
    req: &SendRequest,
    change_address: &Address,
    params: &BuildParams,
) -> Result<TxPlan, WalletError> {
    if req.outputs.is_empty() {
        return Err(WalletError::NoOutputs);
    }
    let fee_rate = FeeRate::from_per_kb(req.fee_rate)?;

    // ---- recipient outputs, and the dust rule applied to them ----
    let mut outputs: Vec<TxOut> = Vec::with_capacity(req.outputs.len().saturating_add(1));
    let mut base_size = TX_OVERHEAD_BYTES;
    for (index, (address, amount)) in req.outputs.iter().enumerate() {
        if *amount < params.dust_threshold {
            return Err(WalletError::DustOutput {
                index,
                value: amount.to_grains(),
                threshold: params.dust_threshold.to_grains(),
            });
        }
        let script_pubkey = address.script_pubkey();
        base_size = base_size.saturating_add(output_size(&script_pubkey));
        outputs.push(TxOut { value: *amount, script_pubkey });
    }
    let target = req.total()?;

    // ---- what a change output would cost, now and when it is spent ----
    let change_script = change_address.script_pubkey();
    let change_output_size = output_size(&change_script);
    // A change address the wallet cannot spend later is unusual but not
    // illegal; price its future input as a P2PKH one rather than refusing.
    let change_spend_size = input_size(&change_script).unwrap_or(P2PKH_INPUT_BYTES);

    // ---- price the candidates ----
    let mut pool: Vec<Candidate> = Vec::with_capacity(candidates.len());
    for (out_point, coin) in candidates {
        match Candidate::price(*out_point, coin.clone(), fee_rate) {
            Ok(Some(candidate)) => pool.push(candidate),
            Ok(None) => {
                tracing::debug!(
                    outpoint = %format_args!("{}:{}", out_point.txid, out_point.vout),
                    value = coin.value.to_grains(),
                    "skipping a coin that cannot pay for its own input",
                );
            }
            Err(_) => {
                tracing::debug!(
                    outpoint = %format_args!("{}:{}", out_point.txid, out_point.vout),
                    "skipping a coin with a script this wallet cannot sign",
                );
            }
        }
    }

    let selection_params = SelectionParams {
        fee_rate,
        dust_threshold: params.dust_threshold,
        base_size,
        change_output_size,
        change_spend_size,
    };
    let selection: Selection = select_coins(&pool, target, &selection_params)?;

    // ---- assemble ----
    if let Some(change) = selection.change {
        outputs.push(TxOut { value: change, script_pubkey: change_script });
    }
    let inputs: Vec<TxIn> = selection
        .inputs
        .iter()
        .map(|(out_point, _)| TxIn {
            prev_out: *out_point,
            script_sig: Script::EMPTY,
            sequence: params.sequence,
        })
        .collect();
    let tx =
        Transaction { version: params.tx_version, inputs, outputs, lock_time: params.lock_time };

    // ---- close the loop on the size estimate ----
    // The skeleton has empty `script_sig`s; adding the bytes each signature
    // will occupy must reproduce exactly the size selection charged for.
    let signed_size =
        tx.serialized_size().saturating_add(tx.inputs.len().saturating_mul(P2PKH_SCRIPT_SIG_BYTES));
    if signed_size != selection.size {
        return Err(WalletError::SizeEstimateDrift {
            estimated: selection.size,
            actual: signed_size,
        });
    }
    if signed_size > MAX_TRANSACTION_BYTES {
        return Err(WalletError::TransactionTooLarge(signed_size));
    }

    // ---- and on the money ----
    let output_total =
        tx.total_output().ok_or(WalletError::AmountOverflow("summing built outputs"))?;
    let fee = selection
        .input_total
        .checked_sub(output_total)
        .ok_or(WalletError::AmountOverflow("computing the fee"))?;
    if fee != selection.fee {
        return Err(WalletError::AmountOverflow("reconciling the fee"));
    }

    Ok(TxPlan {
        tx,
        selected: selection.inputs,
        target,
        fee,
        change: selection.change,
        estimated_size: signed_size,
        strategy: selection.strategy,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]

    use ferrum_crypto::{Mnemonic, SecretKey};
    use ferrum_types::{Network, Txid};

    use super::*;
    use crate::hd::HdKeychain;

    const DUST: Amount = Amount::from_grains(3_000);

    fn keychain() -> HdKeychain {
        let mnemonic = Mnemonic::from_entropy(&[0x5au8; 32]).unwrap();
        HdKeychain::from_mnemonic(&mnemonic, "", Network::Devnet).unwrap()
    }

    fn address(index: u32) -> Address {
        keychain().address(0, 0, index).unwrap()
    }

    fn coin(value: u64, index: u32) -> Coin {
        Coin {
            value: Amount::from_grains(value),
            script_pubkey: address(index).script_pubkey(),
            height: 1,
            is_coinbase: false,
        }
    }

    fn out_point(n: u8) -> OutPoint {
        OutPoint::new(Txid::from_bytes([n; 32]), 0)
    }

    fn params() -> BuildParams {
        BuildParams::at_tip(DUST, 500)
    }

    #[test]
    fn a_request_with_no_outputs_is_rejected() {
        let req = SendRequest { outputs: vec![], fee_rate: 1_000, change_to: None };
        let err = plan_transaction(&[], &req, &address(9), &params()).unwrap_err();
        assert!(matches!(err, WalletError::NoOutputs));
    }

    #[test]
    fn a_zero_fee_rate_is_rejected() {
        let req = SendRequest::to(address(1), Amount::from_grains(10_000), 0);
        let err = plan_transaction(&[], &req, &address(9), &params()).unwrap_err();
        assert!(matches!(err, WalletError::ZeroFeeRate));
    }

    #[test]
    fn a_dust_recipient_output_is_rejected() {
        let req = SendRequest::to(address(1), Amount::from_grains(2_999), 1_000);
        let err = plan_transaction(&[], &req, &address(9), &params()).unwrap_err();
        match err {
            WalletError::DustOutput { index, value, threshold } => {
                assert_eq!(index, 0);
                assert_eq!(value, 2_999);
                assert_eq!(threshold, 3_000);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn a_simple_send_produces_two_outputs_and_one_input() {
        let candidates = vec![(out_point(1), coin(1_000_000, 0))];
        let req = SendRequest::to(address(1), Amount::from_grains(400_000), 1_000);
        let plan = plan_transaction(&candidates, &req, &address(9), &params()).unwrap();
        assert_eq!(plan.tx.inputs.len(), 1);
        assert_eq!(plan.tx.outputs.len(), 2);
        assert_eq!(plan.tx.outputs[0].value, Amount::from_grains(400_000));
        assert_eq!(plan.change, Some(plan.tx.outputs[1].value));
        assert_eq!(plan.target, Amount::from_grains(400_000));
    }

    #[test]
    fn the_change_output_pays_the_change_address() {
        let candidates = vec![(out_point(1), coin(1_000_000, 0))];
        let change = address(9);
        let req = SendRequest::to(address(1), Amount::from_grains(400_000), 1_000);
        let plan = plan_transaction(&candidates, &req, &change, &params()).unwrap();
        assert_eq!(plan.tx.outputs[1].script_pubkey, change.script_pubkey());
    }

    #[test]
    fn multiple_recipients_keep_their_order() {
        let candidates = vec![(out_point(1), coin(5_000_000, 0))];
        let req = SendRequest::to(address(1), Amount::from_grains(100_000), 1_000)
            .and_to(address(2), Amount::from_grains(200_000))
            .and_to(address(3), Amount::from_grains(300_000));
        let plan = plan_transaction(&candidates, &req, &address(9), &params()).unwrap();
        assert_eq!(plan.tx.outputs[0].script_pubkey, address(1).script_pubkey());
        assert_eq!(plan.tx.outputs[1].script_pubkey, address(2).script_pubkey());
        assert_eq!(plan.tx.outputs[2].script_pubkey, address(3).script_pubkey());
        assert_eq!(plan.target, Amount::from_grains(600_000));
    }

    #[test]
    fn the_estimated_size_matches_the_skeleton_plus_the_signatures() {
        let candidates = vec![(out_point(1), coin(1_000_000, 0)), (out_point(2), coin(900_000, 1))];
        let req = SendRequest::to(address(1), Amount::from_grains(1_500_000), 1_000);
        let plan = plan_transaction(&candidates, &req, &address(9), &params()).unwrap();
        assert_eq!(
            plan.estimated_size,
            plan.tx.serialized_size() + plan.tx.inputs.len() * P2PKH_SCRIPT_SIG_BYTES
        );
    }

    #[test]
    fn the_fee_is_inputs_minus_outputs() {
        let candidates = vec![(out_point(1), coin(1_000_000, 0))];
        let req = SendRequest::to(address(1), Amount::from_grains(400_000), 1_000);
        let plan = plan_transaction(&candidates, &req, &address(9), &params()).unwrap();
        let input_total: u64 = plan.selected.iter().map(|(_, c)| c.value.to_grains()).sum();
        let output_total = plan.tx.total_output().unwrap().to_grains();
        assert_eq!(plan.fee.to_grains(), input_total - output_total);
    }

    #[test]
    fn the_realised_fee_rate_meets_the_request() {
        for rate in [1_000u64, 2_500, 10_000] {
            let candidates = vec![(out_point(1), coin(9_000_000, 0))];
            let req = SendRequest::to(address(1), Amount::from_grains(400_000), rate);
            let plan = plan_transaction(&candidates, &req, &address(9), &params()).unwrap();
            assert!(plan.fee_rate() >= rate, "requested {rate}, realised {}", plan.fee_rate());
        }
    }

    #[test]
    fn insufficient_funds_is_reported_with_numbers() {
        let candidates = vec![(out_point(1), coin(10_000, 0))];
        let req = SendRequest::to(address(1), Amount::from_grains(400_000), 1_000);
        let err = plan_transaction(&candidates, &req, &address(9), &params()).unwrap_err();
        assert!(matches!(err, WalletError::InsufficientFunds { .. }));
    }

    #[test]
    fn coins_with_scripts_we_cannot_sign_are_skipped() {
        let unspendable = Coin {
            value: Amount::from_grains(9_000_000),
            script_pubkey: ferrum_script::templates::p2sh(&ferrum_types::Hash32::ZERO),
            height: 1,
            is_coinbase: false,
        };
        let candidates = vec![(out_point(1), unspendable)];
        let req = SendRequest::to(address(1), Amount::from_grains(400_000), 1_000);
        let err = plan_transaction(&candidates, &req, &address(9), &params()).unwrap_err();
        assert!(matches!(err, WalletError::InsufficientFunds { available: 0, .. }));
    }

    #[test]
    fn a_p2pk_coin_is_skipped_too() {
        let secret = SecretKey::from_bytes(&[3u8; 32]).unwrap();
        let unspendable = Coin {
            value: Amount::from_grains(9_000_000),
            script_pubkey: ferrum_script::templates::p2pk(&secret.public_key()),
            height: 1,
            is_coinbase: false,
        };
        let req = SendRequest::to(address(1), Amount::from_grains(400_000), 1_000);
        let err = plan_transaction(&[(out_point(1), unspendable)], &req, &address(9), &params())
            .unwrap_err();
        assert!(matches!(err, WalletError::InsufficientFunds { available: 0, .. }));
    }

    #[test]
    fn anti_fee_sniping_sets_the_lock_time_to_the_tip() {
        let p = BuildParams::at_tip(DUST, 1_234);
        assert_eq!(p.lock_time, 1_234);
        assert_eq!(p.sequence, SEQUENCE_ENABLE_LOCKTIME);
        let candidates = vec![(out_point(1), coin(1_000_000, 0))];
        let req = SendRequest::to(address(1), Amount::from_grains(400_000), 1_000);
        let plan = plan_transaction(&candidates, &req, &address(9), &p).unwrap();
        assert_eq!(plan.tx.lock_time, 1_234);
        assert!(plan.tx.inputs.iter().all(|i| i.sequence == SEQUENCE_ENABLE_LOCKTIME));
    }

    #[test]
    fn a_tip_beyond_the_locktime_threshold_falls_back_to_zero() {
        let p = BuildParams::at_tip(DUST, u64::from(LOCKTIME_THRESHOLD));
        assert_eq!(p.lock_time, 0);
        let p = BuildParams::at_tip(DUST, u64::from(u32::MAX) + 1);
        assert_eq!(p.lock_time, 0);
    }

    #[test]
    fn every_input_script_sig_starts_empty() {
        let candidates = vec![(out_point(1), coin(1_000_000, 0)), (out_point(2), coin(900_000, 1))];
        let req = SendRequest::to(address(1), Amount::from_grains(1_500_000), 1_000);
        let plan = plan_transaction(&candidates, &req, &address(9), &params()).unwrap();
        assert!(plan.tx.inputs.iter().all(|i| i.script_sig.is_empty()));
    }

    #[test]
    fn prevouts_line_up_with_inputs() {
        let candidates = vec![(out_point(1), coin(1_000_000, 0)), (out_point(2), coin(900_000, 1))];
        let req = SendRequest::to(address(1), Amount::from_grains(1_500_000), 1_000);
        let plan = plan_transaction(&candidates, &req, &address(9), &params()).unwrap();
        assert_eq!(plan.prevouts().len(), plan.tx.inputs.len());
        for (input, (out_point, _)) in plan.tx.inputs.iter().zip(plan.selected.iter()) {
            assert_eq!(&input.prev_out, out_point);
        }
        assert_eq!(plan.out_points().len(), plan.tx.inputs.len());
    }

    #[test]
    fn a_send_request_builder_composes() {
        let req = SendRequest::to(address(1), Amount::from_grains(1), 1_000)
            .and_to(address(2), Amount::from_grains(2))
            .with_change_to(address(3));
        assert_eq!(req.outputs.len(), 2);
        assert_eq!(req.change_to, Some(address(3)));
        assert_eq!(req.total().unwrap(), Amount::from_grains(3));
    }

    #[test]
    fn an_overflowing_request_total_is_an_error() {
        let req = SendRequest::to(address(1), Amount::from_grains(u64::MAX), 1_000)
            .and_to(address(2), Amount::from_grains(1));
        assert!(matches!(req.total(), Err(WalletError::AmountOverflow(_))));
    }

    #[test]
    fn a_total_above_max_money_is_an_error() {
        let req = SendRequest::to(address(1), Amount::from_grains(u64::MAX - 1), 1_000);
        assert!(matches!(req.total(), Err(WalletError::AmountOverflow(_))));
    }
}
