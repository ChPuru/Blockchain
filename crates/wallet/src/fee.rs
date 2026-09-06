//! Transaction size and fee arithmetic.
//!
//! The whole point of this module is that the size is computed **before**
//! signing. A wallet that estimates the fee from the unsigned skeleton
//! underestimates by roughly 99 bytes per input, produces a transaction whose
//! real fee rate is a fraction of the requested one, and then wonders why it
//! never confirms. So every number here is exact rather than approximate, and
//! [`crate::sign`] asserts after signing that the measurement matches the
//! estimate to within [`SIZE_ESTIMATE_TOLERANCE`] bytes.
//!
//! # Why the sizes are exact and not estimates
//!
//! Ferrum has no DER signatures and no low-`s` grinding, so a signature is
//! *always* 65 bytes (64-byte Schnorr plus one sighash-type byte) and a
//! public key is *always* the 32-byte x-only form. A P2PKH `script_sig` is
//! therefore always `push(65) || push(32)` = `1 + 65 + 1 + 32` = 99 bytes.
//! Bitcoin cannot make this claim — its signatures vary between 71 and 72
//! bytes — and that variance is exactly why Bitcoin Core carries a "virtual
//! size" estimator with a slack term. Ferrum needs neither.
//!
//! # Borsh layout the constants come from
//!
//! ```text
//! tx_envelope := type_byte:u8 || borsh(Transaction)
//! Transaction := version:u32 || u32 len || inputs || u32 len || outputs || lock_time:u32
//! TxIn        := OutPoint(36) || u32 len || script_sig || sequence:u32
//! TxOut       := value:u64 || u32 len || script_pubkey
//! ```

use ferrum_types::{Amount, Script};

use crate::error::WalletError;

/// Bytes a transaction costs before any input or output: the envelope type
/// byte, `version`, both `Vec` length prefixes and `lock_time`.
pub const TX_OVERHEAD_BYTES: usize = 17;

/// Bytes one input costs excluding its `script_sig`: the 36-byte outpoint, the
/// `u32` script length prefix and the `u32` sequence.
pub const INPUT_FIXED_BYTES: usize = 44;

/// Bytes one output costs excluding its `script_pubkey`: the `u64` value and
/// the `u32` script length prefix.
pub const OUTPUT_FIXED_BYTES: usize = 12;

/// A script signature is exactly 65 bytes: 64-byte Schnorr plus the sighash
/// type byte (CONTRACT §5.5).
pub const SCRIPT_SIGNATURE_BYTES: usize = 65;

/// An x-only public key is 32 bytes.
pub const PUBLIC_KEY_BYTES: usize = 32;

/// `push(<65-byte sig>) || push(<32-byte pubkey>)`, both direct pushes because
/// each length is below `OP_PUSHDATA1`.
pub const P2PKH_SCRIPT_SIG_BYTES: usize = 1 + SCRIPT_SIGNATURE_BYTES + 1 + PUBLIC_KEY_BYTES;

/// Total wire cost of one P2PKH input, signature included.
pub const P2PKH_INPUT_BYTES: usize = INPUT_FIXED_BYTES + P2PKH_SCRIPT_SIG_BYTES;

/// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`.
pub const P2PKH_SCRIPT_PUBKEY_BYTES: usize = 25;

/// Total wire cost of one P2PKH output.
pub const P2PKH_OUTPUT_BYTES: usize = OUTPUT_FIXED_BYTES + P2PKH_SCRIPT_PUBKEY_BYTES;

/// `OP_HASH256 <32> OP_EQUAL`.
pub const P2SH_SCRIPT_PUBKEY_BYTES: usize = 35;

/// Total wire cost of one P2SH output.
pub const P2SH_OUTPUT_BYTES: usize = OUTPUT_FIXED_BYTES + P2SH_SCRIPT_PUBKEY_BYTES;

/// Fee rates are quoted per this many bytes, matching
/// `ChainParams::min_relay_fee_per_kb` and `MempoolEntry::fee_rate`.
pub const FEE_RATE_UNIT_BYTES: u64 = 1_000;

/// A dust output is one worth less than this multiple of the minimum relay
/// fee (CONTRACT §12).
pub const DUST_RELAY_MULTIPLIER: u64 = 3;

/// How far the post-signing measurement may drift from the pre-signing
/// estimate before [`crate::sign`] refuses the transaction.
///
/// Zero would be defensible for the templates this wallet signs, but a
/// two-byte window leaves room for a future template whose push encoding
/// changes length without turning a size check into a release blocker.
pub const SIZE_ESTIMATE_TOLERANCE: usize = 2;

/// The dust threshold for a network: `3 * min_relay_fee_per_kb`.
///
/// Below this an output costs more to spend than it is worth, and it sits in
/// every full node's UTXO set forever. Creating one is a small externality
/// imposed on the whole network, so the wallet folds such change into the fee
/// instead.
pub fn dust_threshold(min_relay_fee_per_kb: Amount) -> Amount {
    // `3 * 1_000` grains cannot overflow; saturate rather than wrap if a
    // caller passes an absurd relay fee.
    Amount::from_grains(min_relay_fee_per_kb.to_grains().saturating_mul(DUST_RELAY_MULTIPLIER))
}

/// Wire cost of one output with the given locking script.
///
/// Exact for every script, because an output carries no signature.
pub fn output_size(script_pubkey: &Script) -> usize {
    OUTPUT_FIXED_BYTES.saturating_add(script_pubkey.len())
}

/// Wire cost of one *signed* input spending the given locking script.
///
/// Only the templates this wallet can sign are sizeable; anything else is
/// [`WalletError::UnsupportedScript`], because guessing a size for a script we
/// cannot satisfy would silently underpay the fee.
pub fn input_size(script_pubkey: &Script) -> Result<usize, WalletError> {
    match ferrum_script::templates::classify(script_pubkey) {
        ferrum_script::ScriptType::P2PKH => Ok(P2PKH_INPUT_BYTES),
        _ => Err(WalletError::UnsupportedScript),
    }
}

/// A fee rate in grains per [`FEE_RATE_UNIT_BYTES`] bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeeRate(u64);

impl FeeRate {
    /// The lowest rate that can produce a non-zero fee for a normal
    /// transaction.
    pub const MIN: FeeRate = FeeRate(1);

    /// Build a rate from grains per 1000 bytes.
    ///
    /// Zero is rejected: a zero-fee transaction is not relayable, and a wallet
    /// that silently builds one has produced a transaction that never
    /// confirms.
    pub fn from_per_kb(grains: u64) -> Result<FeeRate, WalletError> {
        if grains == 0 { Err(WalletError::ZeroFeeRate) } else { Ok(FeeRate(grains)) }
    }

    /// Grains per 1000 bytes.
    pub const fn to_per_kb(self) -> u64 {
        self.0
    }

    /// The fee this rate charges for `bytes`, rounded **up**.
    ///
    /// Rounding up is what makes "the realised fee rate is at least the
    /// requested fee rate" true rather than approximately true; rounding down
    /// would let every transaction pay a hair under policy and be rejected by
    /// a strict relay.
    pub fn fee_for_size(self, bytes: usize) -> Result<Amount, WalletError> {
        let bytes = u128::try_from(bytes).map_err(|_| WalletError::TransactionTooLarge(bytes))?;
        let numerator = bytes
            .checked_mul(u128::from(self.0))
            .and_then(|v| v.checked_add(u128::from(FEE_RATE_UNIT_BYTES).saturating_sub(1)))
            .ok_or(WalletError::AmountOverflow("computing a fee"))?;
        let grains = numerator
            .checked_div(u128::from(FEE_RATE_UNIT_BYTES))
            .ok_or(WalletError::AmountOverflow("computing a fee"))?;
        let grains =
            u64::try_from(grains).map_err(|_| WalletError::AmountOverflow("computing a fee"))?;
        Ok(Amount::from_grains(grains))
    }

    /// The realised rate of `fee` over `bytes`, rounded **down**.
    ///
    /// The inverse of [`FeeRate::fee_for_size`], used to assert that a built
    /// transaction pays at least what was asked for.
    pub fn of(fee: Amount, bytes: usize) -> u64 {
        if bytes == 0 {
            return 0;
        }
        let bytes = u128::try_from(bytes).unwrap_or(u128::MAX);
        let numerator = u128::from(fee.to_grains()).saturating_mul(u128::from(FEE_RATE_UNIT_BYTES));
        // `bytes != 0` was checked above, so the division is defined.
        let rate = numerator.checked_div(bytes).unwrap_or(0);
        u64::try_from(rate).unwrap_or(u64::MAX)
    }
}

impl std::fmt::Display for FeeRate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} grains/kB", self.0)
    }
}

/// Total wire size of a transaction with the given signed inputs and outputs.
pub fn transaction_size(input_bytes: &[usize], output_bytes: &[usize]) -> usize {
    let inputs: usize = input_bytes.iter().copied().fold(0usize, usize::saturating_add);
    let outputs: usize = output_bytes.iter().copied().fold(0usize, usize::saturating_add);
    TX_OVERHEAD_BYTES.saturating_add(inputs).saturating_add(outputs)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]

    use ferrum_types::{Amount, OutPoint, Script, Transaction, TxIn, TxOut, Txid};

    use super::*;

    fn p2pkh_script() -> Script {
        ferrum_script::templates::p2pkh(&[7u8; 20])
    }

    #[test]
    fn tx_overhead_matches_borsh() {
        let tx = Transaction { version: 1, inputs: vec![], outputs: vec![], lock_time: 0 };
        assert_eq!(tx.serialized_size(), TX_OVERHEAD_BYTES);
    }

    #[test]
    fn input_fixed_bytes_matches_borsh() {
        let empty = Transaction { version: 1, inputs: vec![], outputs: vec![], lock_time: 0 };
        let one = Transaction {
            inputs: vec![TxIn::new(OutPoint::new(Txid::ZERO, 0), Script::EMPTY)],
            ..empty.clone()
        };
        assert_eq!(one.serialized_size() - empty.serialized_size(), INPUT_FIXED_BYTES);
    }

    #[test]
    fn output_fixed_bytes_matches_borsh() {
        let empty = Transaction { version: 1, inputs: vec![], outputs: vec![], lock_time: 0 };
        let one =
            Transaction { outputs: vec![TxOut::new(Amount::ZERO, Script::EMPTY)], ..empty.clone() };
        assert_eq!(one.serialized_size() - empty.serialized_size(), OUTPUT_FIXED_BYTES);
    }

    #[test]
    fn p2pkh_output_size_matches_the_real_script() {
        let script = p2pkh_script();
        assert_eq!(script.len(), P2PKH_SCRIPT_PUBKEY_BYTES);
        assert_eq!(output_size(&script), P2PKH_OUTPUT_BYTES);
    }

    #[test]
    fn p2sh_output_size_matches_the_real_script() {
        let script = ferrum_script::templates::p2sh(&ferrum_types::Hash32::ZERO);
        assert_eq!(script.len(), P2SH_SCRIPT_PUBKEY_BYTES);
        assert_eq!(output_size(&script), P2SH_OUTPUT_BYTES);
    }

    #[test]
    fn input_size_rejects_a_script_we_cannot_sign() {
        let script = ferrum_script::templates::p2sh(&ferrum_types::Hash32::ZERO);
        assert!(matches!(input_size(&script), Err(WalletError::UnsupportedScript)));
    }

    #[test]
    fn input_size_of_p2pkh_is_the_constant() {
        assert_eq!(input_size(&p2pkh_script()).unwrap(), P2PKH_INPUT_BYTES);
    }

    #[test]
    fn fee_rounds_up() {
        let rate = FeeRate::from_per_kb(1_000).unwrap();
        // 1 grain per byte exactly.
        assert_eq!(rate.fee_for_size(191).unwrap(), Amount::from_grains(191));

        let rate = FeeRate::from_per_kb(1).unwrap();
        // 191 * 1 / 1000 = 0.191 -> rounds up to 1.
        assert_eq!(rate.fee_for_size(191).unwrap(), Amount::from_grains(1));
    }

    #[test]
    fn fee_of_zero_bytes_is_zero() {
        let rate = FeeRate::from_per_kb(5_000).unwrap();
        assert_eq!(rate.fee_for_size(0).unwrap(), Amount::ZERO);
    }

    #[test]
    fn zero_fee_rate_is_rejected() {
        assert!(matches!(FeeRate::from_per_kb(0), Err(WalletError::ZeroFeeRate)));
    }

    #[test]
    fn realised_rate_is_never_below_the_requested_rate() {
        for rate_per_kb in [1u64, 7, 250, 1_000, 3_333, 100_000] {
            let rate = FeeRate::from_per_kb(rate_per_kb).unwrap();
            for bytes in [1usize, 17, 191, 250, 1_000, 4_321] {
                let fee = rate.fee_for_size(bytes).unwrap();
                assert!(
                    FeeRate::of(fee, bytes) >= rate_per_kb,
                    "rate {rate_per_kb} over {bytes} bytes realised {}",
                    FeeRate::of(fee, bytes)
                );
            }
        }
    }

    #[test]
    fn dust_threshold_is_three_times_the_relay_fee() {
        assert_eq!(dust_threshold(Amount::from_grains(1_000)), Amount::from_grains(3_000));
    }

    #[test]
    fn transaction_size_sums_the_parts() {
        assert_eq!(
            transaction_size(&[P2PKH_INPUT_BYTES], &[P2PKH_OUTPUT_BYTES, P2PKH_OUTPUT_BYTES]),
            TX_OVERHEAD_BYTES + P2PKH_INPUT_BYTES + 2 * P2PKH_OUTPUT_BYTES
        );
    }

    #[test]
    fn fee_rate_displays_its_unit() {
        assert_eq!(FeeRate::from_per_kb(2_500).unwrap().to_string(), "2500 grains/kB");
    }
}
