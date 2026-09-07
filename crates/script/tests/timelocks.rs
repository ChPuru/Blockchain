//! `OP_CHECKLOCKTIMEVERIFY` (BIP-65) and `OP_CHECKSEQUENCEVERIFY` (BIP-68/112).
//!
//! Both opcodes inspect their operand without consuming it, so every script
//! here is `<value> OP_CxV OP_DROP OP_1` — which is also the shape the
//! templates use.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{ctx_for, num, push, script, spending_tx};
use ferrum_script::limits::{
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG, sequence_from_blocks,
    sequence_from_seconds,
};
use ferrum_script::{ExecCtx, ScriptError, ScriptNum, Stack, eval};
use ferrum_types::{ChainId, LOCKTIME_THRESHOLD, Script};

const OP_1: u8 = 0x51;
const OP_DROP: u8 = 0x75;
const OP_CLTV: u8 = 0xb1;
const OP_CSV: u8 = 0xb2;
const FINAL: u32 = 0xffff_ffff;
const NOT_FINAL: u32 = 0xffff_fffe;

/// `<operand> OP_CxV OP_DROP OP_1`.
fn timelock_script(operand: &[u8], opcode: u8) -> Vec<u8> {
    let mut out = push(operand);
    out.push(opcode);
    out.push(OP_DROP);
    out.push(OP_1);
    out
}

/// Run a CLTV script against a transaction with the given `lock_time` and
/// input `sequence`.
fn cltv(operand: &[u8], lock_time: u32, sequence: u32) -> Result<Stack, ScriptError> {
    let tx = spending_tx(Script::EMPTY, sequence, lock_time);
    let ctx = ctx_for(&tx, ChainId::DEVNET);
    eval(&script(&timelock_script(operand, OP_CLTV)), Vec::new(), &ctx)
}

/// How old the spent coin is, in blocks and in seconds of median time past.
///
/// BIP-68 is only a timelock because the input's `sequence` is measured against
/// this; the script operand alone is two numbers the spender chose.
#[derive(Clone, Copy)]
struct CoinAge {
    coin_height: Option<u64>,
    block_height: u64,
    coin_mtp_s: Option<u64>,
    block_mtp_s: u64,
}

/// A coin far older than any 16-bit relative lock can ask for: 65 535 blocks is
/// the widest block count and 65 535 * 512 s the widest time, so nothing here
/// can fail on age. Every test that is about the *operand* uses this.
const MATURE: CoinAge = CoinAge {
    coin_height: Some(0),
    block_height: 1_000_000,
    coin_mtp_s: Some(0),
    block_mtp_s: 1_700_000_000,
};

/// The context knows nothing about the coin being spent.
const UNKNOWN_AGE: CoinAge = CoinAge {
    coin_height: None,
    block_height: 1_000_000,
    coin_mtp_s: None,
    block_mtp_s: 1_700_000_000,
};

/// Run a CSV script against a transaction whose input has `sequence`, with the
/// spent coin's age given by `age`.
fn csv_aged(operand: &[u8], sequence: u32, age: CoinAge) -> Result<Stack, ScriptError> {
    let tx = spending_tx(Script::EMPTY, sequence, 0);
    let ctx = ExecCtx {
        input_height: age.coin_height,
        input_mtp_s: age.coin_mtp_s,
        block_height: age.block_height,
        block_mtp_s: age.block_mtp_s,
        ..ctx_for(&tx, ChainId::DEVNET)
    };
    eval(&script(&timelock_script(operand, OP_CSV)), Vec::new(), &ctx)
}

/// Run a CSV script against a transaction whose input has `sequence`, spending
/// a coin old enough that the age half of BIP-68 cannot be what fails.
fn csv(operand: &[u8], sequence: u32) -> Result<Stack, ScriptError> {
    csv_aged(operand, sequence, MATURE)
}

// ---------------------------------------------------------------------------
// CLTV
// ---------------------------------------------------------------------------

#[test]
fn cltv_passes_when_the_locktime_is_met() {
    assert!(cltv(&num(100), 100, NOT_FINAL).is_ok());
    assert!(cltv(&num(100), 101, NOT_FINAL).is_ok());
    assert!(cltv(&num(0), 0, NOT_FINAL).is_ok());
}

#[test]
fn cltv_fails_when_the_locktime_is_not_met() {
    assert_eq!(
        cltv(&num(100), 99, NOT_FINAL),
        Err(ScriptError::UnsatisfiedLockTime { required: 100, tx: 99 })
    );
}

#[test]
fn cltv_fails_on_a_negative_operand() {
    assert_eq!(cltv(&num(-1), 100, NOT_FINAL), Err(ScriptError::NegativeLockTime(-1)));
    assert_eq!(
        cltv(&num(-500_000_001), 600_000_000, NOT_FINAL),
        Err(ScriptError::NegativeLockTime(-500_000_001))
    );
}

#[test]
fn cltv_fails_on_a_locktime_type_mismatch() {
    let height = LOCKTIME_THRESHOLD - 1;
    let timestamp = LOCKTIME_THRESHOLD;
    // Script wants a timestamp, transaction carries a height.
    assert_eq!(
        cltv(&num(i64::from(timestamp)), height, NOT_FINAL),
        Err(ScriptError::LockTimeTypeMismatch { required: u64::from(timestamp), tx: height })
    );
    // Script wants a height, transaction carries a timestamp.
    assert_eq!(
        cltv(&num(i64::from(height)), timestamp, NOT_FINAL),
        Err(ScriptError::LockTimeTypeMismatch { required: u64::from(height), tx: timestamp })
    );
}

#[test]
fn cltv_both_sides_of_the_threshold_work_when_they_agree() {
    assert!(
        cltv(&num(i64::from(LOCKTIME_THRESHOLD - 1)), LOCKTIME_THRESHOLD - 1, NOT_FINAL).is_ok()
    );
    assert!(cltv(&num(i64::from(LOCKTIME_THRESHOLD)), LOCKTIME_THRESHOLD, NOT_FINAL).is_ok());
}

#[test]
fn cltv_fails_when_the_input_sequence_is_final() {
    // A final input opts out of `lock_time` enforcement, so the timelock would
    // be a lie.
    assert_eq!(cltv(&num(100), 100, FINAL), Err(ScriptError::FinalSequence));
    assert!(cltv(&num(100), 100, FINAL - 1).is_ok());
}

#[test]
fn cltv_accepts_a_five_byte_operand() {
    // A locktime above 0x7fffffff needs five bytes in sign-magnitude form, and
    // this is why the operand limit is 5 rather than MAX_NUM_SIZE.
    let big = 0xffff_ffffi64;
    let encoded = ScriptNum::new(big).to_vec();
    assert_eq!(encoded.len(), 5);
    assert!(cltv(&encoded, 0xffff_ffff, NOT_FINAL).is_ok());
}

#[test]
fn cltv_rejects_a_six_byte_operand() {
    let too_wide = ScriptNum::new(0x1_0000_0000_0000).to_vec();
    assert_eq!(too_wide.len(), 7);
    assert_eq!(
        cltv(&too_wide, 0xffff_ffff, NOT_FINAL),
        Err(ScriptError::NumTooLarge { len: 7, max: 5 })
    );
}

#[test]
fn cltv_rejects_a_non_minimal_operand() {
    assert_eq!(cltv(&[0x64, 0x00], 100, NOT_FINAL), Err(ScriptError::NonMinimalNum));
}

#[test]
fn cltv_does_not_consume_its_operand() {
    let tx = spending_tx(Script::EMPTY, NOT_FINAL, 100);
    let ctx = ctx_for(&tx, ChainId::DEVNET);
    let mut bytes = push(&num(100));
    bytes.push(OP_CLTV);
    let stack = eval(&script(&bytes), Vec::new(), &ctx).unwrap();
    assert_eq!(stack, vec![num(100)]);
}

#[test]
fn cltv_on_an_empty_stack_underflows() {
    let tx = spending_tx(Script::EMPTY, NOT_FINAL, 100);
    let ctx = ctx_for(&tx, ChainId::DEVNET);
    assert_eq!(
        eval(&script(&[OP_CLTV]), Vec::new(), &ctx),
        Err(ScriptError::StackUnderflow { needed: 1, found: 0 })
    );
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

#[test]
fn csv_passes_for_a_block_count_that_is_met() {
    assert!(csv(&num(10), sequence_from_blocks(10)).is_ok());
    assert!(csv(&num(10), sequence_from_blocks(11)).is_ok());
    assert!(csv(&num(0), sequence_from_blocks(0)).is_ok());
}

#[test]
fn csv_fails_for_a_block_count_that_is_not_met() {
    assert_eq!(
        csv(&num(10), sequence_from_blocks(9)),
        Err(ScriptError::UnsatisfiedSequence { required: 10, sequence: 9 })
    );
}

#[test]
fn csv_passes_for_a_time_lock_that_is_met() {
    // 512-second granularity: 1024 seconds is two units.
    let required = i64::from(sequence_from_seconds(1024));
    assert!(csv(&num(required), sequence_from_seconds(1024)).is_ok());
    assert!(csv(&num(required), sequence_from_seconds(2048)).is_ok());
    assert_eq!(
        csv(&num(required), sequence_from_seconds(512)),
        Err(ScriptError::UnsatisfiedSequence {
            required: sequence_from_seconds(1024),
            sequence: sequence_from_seconds(512),
        })
    );
}

#[test]
fn csv_granularity_is_512_seconds() {
    // Anything under 512 seconds rounds down to zero units.
    assert_eq!(sequence_from_seconds(511), SEQUENCE_LOCKTIME_TYPE_FLAG);
    assert_eq!(sequence_from_seconds(512), SEQUENCE_LOCKTIME_TYPE_FLAG | 1);
    assert!(csv(&num(i64::from(sequence_from_seconds(511))), sequence_from_seconds(0)).is_ok());
}

#[test]
fn csv_fails_on_a_type_mismatch() {
    let time_operand = i64::from(sequence_from_seconds(1024));
    assert_eq!(
        csv(&num(time_operand), sequence_from_blocks(1000)),
        Err(ScriptError::SequenceTypeMismatch {
            required: sequence_from_seconds(1024),
            sequence: 1000,
        })
    );
    assert_eq!(
        csv(&num(10), sequence_from_seconds(100_000)),
        Err(ScriptError::SequenceTypeMismatch {
            required: 10,
            sequence: sequence_from_seconds(100_000),
        })
    );
}

#[test]
fn csv_fails_when_the_input_disables_relative_locktime() {
    assert_eq!(
        csv(&num(10), SEQUENCE_LOCKTIME_DISABLE_FLAG | 10),
        Err(ScriptError::SequenceLockDisabled)
    );
    // The final sequence has the disable bit set too.
    assert_eq!(csv(&num(10), FINAL), Err(ScriptError::SequenceLockDisabled));
}

#[test]
fn csv_fails_when_the_operand_sets_the_disable_bit() {
    // Bitcoin makes this a no-op for soft-fork compatibility. Ferrum has no
    // soft-fork hooks, so a script that asks for nothing is an error.
    let operand = i64::from(SEQUENCE_LOCKTIME_DISABLE_FLAG) | 10;
    assert_eq!(
        csv(&num(operand), sequence_from_blocks(10)),
        Err(ScriptError::SequenceDisabledOperand(u64::from(SEQUENCE_LOCKTIME_DISABLE_FLAG) | 10))
    );
}

#[test]
fn csv_fails_on_a_negative_operand() {
    assert_eq!(csv(&num(-1), sequence_from_blocks(10)), Err(ScriptError::NegativeLockTime(-1)));
}

#[test]
fn csv_rejects_a_non_minimal_operand() {
    assert_eq!(csv(&[0x0a, 0x00], sequence_from_blocks(10)), Err(ScriptError::NonMinimalNum));
}

#[test]
fn csv_ignores_the_bits_between_16_and_22() {
    // Only bits 0..15 and bit 22 are consulted, so noise in between does not
    // change the outcome. This is BIP-68's forward-compatibility reservation.
    let sequence = sequence_from_blocks(10) | 0x0010_0000;
    assert!(csv(&num(10), sequence).is_ok());
}

#[test]
fn csv_does_not_consume_its_operand() {
    let tx = spending_tx(Script::EMPTY, sequence_from_blocks(10), 0);
    let ctx = ExecCtx {
        input_height: MATURE.coin_height,
        input_mtp_s: MATURE.coin_mtp_s,
        block_height: MATURE.block_height,
        block_mtp_s: MATURE.block_mtp_s,
        ..ctx_for(&tx, ChainId::DEVNET)
    };
    let mut bytes = push(&num(10));
    bytes.push(OP_CSV);
    let stack = eval(&script(&bytes), Vec::new(), &ctx).unwrap();
    assert_eq!(stack, vec![num(10)]);
}

// ---------------------------------------------------------------------------
// CSV — BIP-68: the input's sequence against the age of the coin it spends.
//
// The script half of BIP-112 compares the operand with `TxIn::sequence`, and
// both of those are written by the spender. Without the rules below a
// `<n> OP_CSV OP_DROP` output is spendable in the very next block by anyone who
// can sign, which is no timelock at all.
// ---------------------------------------------------------------------------

#[test]
fn csv_fails_when_the_coin_is_younger_than_the_block_count() {
    // The finding's exact scenario: a 10-block relative lock on a coin created
    // at height 100, spent at height 101 with sequence = 10.
    let age = CoinAge { coin_height: Some(100), block_height: 101, ..MATURE };
    assert_eq!(
        csv_aged(&num(10), sequence_from_blocks(10), age),
        Err(ScriptError::ImmatureRelativeHeight {
            required: 10,
            coin_height: 100,
            block_height: 101,
        })
    );
}

#[test]
fn csv_block_count_matures_exactly_at_coin_height_plus_the_count() {
    let at = |block_height| CoinAge { coin_height: Some(100), block_height, ..MATURE };
    // 109 is nine blocks after the coin: one short.
    assert_eq!(
        csv_aged(&num(10), sequence_from_blocks(10), at(109)),
        Err(ScriptError::ImmatureRelativeHeight {
            required: 10,
            coin_height: 100,
            block_height: 109,
        })
    );
    assert!(csv_aged(&num(10), sequence_from_blocks(10), at(110)).is_ok());
    assert!(csv_aged(&num(10), sequence_from_blocks(10), at(111)).is_ok());
}

#[test]
fn csv_measures_the_inputs_sequence_not_the_operand() {
    // BIP-68 enforces the lock the *input* claims. An operand of 1 with a
    // sequence of 10 still has to wait ten blocks, because the sequence is what
    // the chain measures.
    let age = CoinAge { coin_height: Some(100), block_height: 105, ..MATURE };
    assert_eq!(
        csv_aged(&num(1), sequence_from_blocks(10), age),
        Err(ScriptError::ImmatureRelativeHeight {
            required: 10,
            coin_height: 100,
            block_height: 105,
        })
    );
}

#[test]
fn csv_fails_when_the_coin_is_younger_than_the_time_lock() {
    // Two 512-second units = 1024 seconds.
    let sequence = sequence_from_seconds(1024);
    let operand = i64::from(sequence);
    let at = |block_mtp_s| CoinAge { coin_mtp_s: Some(1_000), block_mtp_s, ..MATURE };
    assert_eq!(
        csv_aged(&num(operand), sequence, at(1_000 + 1_023)),
        Err(ScriptError::ImmatureRelativeTime {
            required_s: 1_024,
            coin_mtp_s: 1_000,
            block_mtp_s: 2_023,
        })
    );
    assert!(csv_aged(&num(operand), sequence, at(1_000 + 1_024)).is_ok());
}

#[test]
fn csv_type_bit_selects_which_clock_the_age_is_measured_on() {
    // Bit 22 set: the age is a time, so a coin one block old but old enough in
    // seconds passes...
    let sequence = sequence_from_seconds(1024);
    let operand = i64::from(sequence);
    let young_in_blocks = CoinAge {
        coin_height: Some(100),
        block_height: 101,
        coin_mtp_s: Some(1_000),
        block_mtp_s: 1_000 + 1_024,
    };
    assert!(csv_aged(&num(operand), sequence, young_in_blocks).is_ok());

    // ...and bit 22 clear: the age is a block count, so a coin that is old in
    // seconds but young in blocks fails.
    let old_in_seconds = CoinAge {
        coin_height: Some(100),
        block_height: 101,
        coin_mtp_s: Some(0),
        block_mtp_s: 1_700_000_000,
    };
    assert_eq!(
        csv_aged(&num(10), sequence_from_blocks(10), old_in_seconds),
        Err(ScriptError::ImmatureRelativeHeight {
            required: 10,
            coin_height: 100,
            block_height: 101,
        })
    );
}

#[test]
fn csv_fails_closed_when_the_context_does_not_know_the_coins_age() {
    // A context that cannot say how old the coin is must not let a relative
    // locktime through unchecked.
    assert_eq!(
        csv_aged(&num(10), sequence_from_blocks(10), UNKNOWN_AGE),
        Err(ScriptError::UnknownCoinHeight)
    );
    let sequence = sequence_from_seconds(1024);
    assert_eq!(
        csv_aged(&num(i64::from(sequence)), sequence, UNKNOWN_AGE),
        Err(ScriptError::UnknownCoinTime)
    );
}

#[test]
fn csv_with_a_zero_relative_lock_needs_no_coin_age() {
    // `sequence & 0xffff == 0` asks for nothing, so there is nothing to
    // measure and no reason to demand the coin's age.
    assert!(csv_aged(&num(0), sequence_from_blocks(0), UNKNOWN_AGE).is_ok());
    let sequence = sequence_from_seconds(511); // rounds down to zero units
    assert!(csv_aged(&num(i64::from(sequence)), sequence, UNKNOWN_AGE).is_ok());
}

#[test]
fn csv_disable_bit_is_checked_before_the_age() {
    // Bit 31 in the input's sequence opts out of relative locktime entirely, so
    // it is rejected before the coin's age is ever consulted — even when the
    // age is unknown.
    assert_eq!(
        csv_aged(&num(10), SEQUENCE_LOCKTIME_DISABLE_FLAG | 10, UNKNOWN_AGE),
        Err(ScriptError::SequenceLockDisabled)
    );
}

#[test]
fn csv_enforces_the_widest_block_count_bip68_can_express() {
    // 0xffff blocks is the maximum the low 16 bits carry.
    let sequence = sequence_from_blocks(0xffff);
    let operand = i64::from(sequence);
    let at = |block_height| CoinAge { coin_height: Some(1), block_height, ..MATURE };
    assert_eq!(
        csv_aged(&num(operand), sequence, at(1 + 0xfffe)),
        Err(ScriptError::ImmatureRelativeHeight {
            required: 0xffff,
            coin_height: 1,
            block_height: 1 + 0xfffe,
        })
    );
    assert!(csv_aged(&num(operand), sequence, at(1 + 0xffff)).is_ok());
}

#[test]
fn csv_on_an_empty_stack_underflows() {
    let tx = spending_tx(Script::EMPTY, sequence_from_blocks(10), 0);
    let ctx = ctx_for(&tx, ChainId::DEVNET);
    assert_eq!(
        eval(&script(&[OP_CSV]), Vec::new(), &ctx),
        Err(ScriptError::StackUnderflow { needed: 1, found: 0 })
    );
}
