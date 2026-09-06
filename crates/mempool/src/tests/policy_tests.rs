//! Relay policy: the fee-rate arithmetic, the config defaults and the
//! standardness rules.

use ferrum_script::templates::{multisig, op_return, p2pkh, p2sh_of};
use ferrum_types::{Amount, ChainParams, Script, TxOut};

use crate::error::MempoolError;
use crate::policy::{
    DEFAULT_EXPIRY_BLOCKS, DEFAULT_MAX_BYTES, DEFAULT_MAX_ORPHANS, FEE_RATE_DIVISOR,
    MAX_STANDARD_TX_SIZE, MempoolConfig, check_standard, fee_rate, is_standard_script_pubkey,
};
use crate::tests::support::{locked, tx, unknown_out};

#[test]
fn the_contract_defaults_are_what_the_contract_says() {
    let cfg = MempoolConfig::new(ChainParams::mainnet());
    assert_eq!(cfg.max_bytes, 8 * 1024 * 1024, "CONTRACT §9: 8 MiB");
    assert_eq!(cfg.max_orphans, 200, "CONTRACT §9: 200 orphans");
    assert_eq!(cfg.expiry_blocks, 336, "CONTRACT §9: 336 blocks");
    assert_eq!(DEFAULT_MAX_BYTES, cfg.max_bytes);
    assert_eq!(DEFAULT_MAX_ORPHANS, cfg.max_orphans);
    assert_eq!(DEFAULT_EXPIRY_BLOCKS, cfg.expiry_blocks);
}

#[test]
fn the_fee_floor_comes_from_the_chain_parameters() {
    let params = ChainParams::mainnet();
    let cfg = MempoolConfig::new(params.clone());
    assert_eq!(cfg.min_fee_rate, params.min_relay_fee_per_kb.to_grains());
    assert_eq!(cfg.min_fee_rate, 1_000, "SPEC §1: 1000 grains per kB");
}

#[test]
fn default_is_mainnet_so_a_misconfiguration_fails_closed() {
    assert_eq!(MempoolConfig::default().params, ChainParams::mainnet());
}

#[test]
fn the_builders_change_one_field_each() {
    let cfg = MempoolConfig::new(ChainParams::devnet())
        .with_max_bytes(1)
        .with_max_orphans(2)
        .with_min_fee_rate(3)
        .with_expiry_blocks(4);
    assert_eq!((cfg.max_bytes, cfg.max_orphans, cfg.min_fee_rate, cfg.expiry_blocks), (1, 2, 3, 4));
}

#[test]
fn a_fee_rate_is_grains_per_thousand_bytes() {
    assert_eq!(FEE_RATE_DIVISOR, 1_000);
    assert_eq!(fee_rate(Amount::from_grains(1_000), 1_000), Some(1_000));
    assert_eq!(fee_rate(Amount::from_grains(500), 1_000), Some(500));
    assert_eq!(fee_rate(Amount::from_grains(1_000), 250), Some(4_000));
}

#[test]
fn a_fee_rate_truncates_rather_than_rounding_up() {
    // Rounding up would let a transaction one grain short of the floor pass it.
    assert_eq!(fee_rate(Amount::from_grains(1), 3), Some(333));
    assert_eq!(fee_rate(Amount::from_grains(999), 1_000), Some(999));
}

#[test]
fn a_zero_size_has_no_fee_rate() {
    assert_eq!(fee_rate(Amount::from_grains(1), 0), None);
}

#[test]
fn a_fee_rate_that_would_overflow_is_none_rather_than_wrapping() {
    // Unreachable inside the money range, which is exactly why it is typed
    // rather than assumed.
    assert_eq!(fee_rate(Amount::from_grains(u64::MAX), 1), None);
    assert!(fee_rate(Amount::MAX_MONEY, 1).is_some());
}

#[test]
fn the_standard_templates_are_standard() {
    assert!(is_standard_script_pubkey(&p2sh_of(&Script::new(vec![0x51]))));
    assert!(is_standard_script_pubkey(&p2pkh(&[7u8; 20])));
    assert!(is_standard_script_pubkey(&op_return(b"hello").expect("payload fits")));
}

#[test]
fn a_bare_op_1_output_is_not_relayed_but_is_still_spendable_in_a_block() {
    // Policy, not consensus: a block paying to `OP_1` is perfectly valid.
    assert!(!is_standard_script_pubkey(&Script::new(vec![0x51])));
    assert!(!is_standard_script_pubkey(&Script::EMPTY));
}

#[test]
fn a_multisig_output_is_standard() {
    use ferrum_crypto::SecretKey;
    let keys: Vec<_> = (1u8..=3)
        .map(|i| SecretKey::from_bytes(&[i; 32]).expect("valid key").public_key())
        .collect();
    let script = multisig(2, &keys).expect("2-of-3 builds");
    assert!(is_standard_script_pubkey(&script));
}

#[test]
fn check_standard_rejects_a_non_standard_output_and_names_it() {
    let mut t = tx(&[unknown_out(1, 0)], &[100]);
    t.outputs.push(TxOut::new(Amount::from_grains(1), Script::new(vec![0x51])));
    let size = t.serialized_size();
    assert_eq!(check_standard(&t, size), Err(MempoolError::NonStandardOutput { vout: 1 }));
}

#[test]
fn check_standard_rejects_a_script_sig_that_is_not_push_only() {
    let mut t = tx(&[unknown_out(1, 0)], &[100]);
    // OP_DUP: a genuine operation, not a push.
    t.inputs[0].script_sig = Script::new(vec![0x76]);
    let size = t.serialized_size();
    assert_eq!(
        check_standard(&t, size),
        Err(MempoolError::NonPushOnlyScriptSig { input_index: 0 })
    );
}

#[test]
fn op_1_through_op_16_still_count_as_pushes() {
    let mut t = tx(&[unknown_out(1, 0)], &[100]);
    t.inputs[0].script_sig = Script::new(vec![0x51, 0x60]);
    let size = t.serialized_size();
    assert_eq!(check_standard(&t, size), Ok(()));
}

#[test]
fn check_standard_rejects_an_oversized_transaction() {
    let values = vec![1u64; 2_500];
    let t = tx(&[unknown_out(1, 0)], &values);
    let size = t.serialized_size();
    assert!(size > MAX_STANDARD_TX_SIZE, "fixture must exceed the policy limit, got {size}");
    assert_eq!(
        check_standard(&t, size),
        Err(MempoolError::TooLarge { size, max: MAX_STANDARD_TX_SIZE })
    );
}

#[test]
fn a_transaction_at_the_policy_size_limit_is_accepted() {
    let t = tx(&[unknown_out(1, 0)], &[100]);
    assert_eq!(check_standard(&t, MAX_STANDARD_TX_SIZE), Ok(()));
    assert!(matches!(
        check_standard(&t, MAX_STANDARD_TX_SIZE + 1),
        Err(MempoolError::TooLarge { .. })
    ));
}

#[test]
fn the_fixture_output_script_is_the_one_the_policy_accepts() {
    assert!(is_standard_script_pubkey(&locked()));
}
