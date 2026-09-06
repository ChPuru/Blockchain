//! Every way a Ferrum script can fail.
//!
//! The enum is deliberately fine-grained and deliberately **not**
//! `#[non_exhaustive]`. A test that only asserts "the script was rejected"
//! passes when the script was rejected for the wrong reason, which is how a
//! consensus rule silently stops being tested. Every rule in CONTRACT §5 has
//! its own variant so a test can name it.
//!
//! Every variant is `Clone + PartialEq`, so an assertion can compare against a
//! constructed value rather than matching a shape.

use thiserror::Error;

/// A script failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScriptError {
    // ---- size and resource limits (CONTRACT §5.1) ----
    /// A script exceeded [`crate::limits::MAX_SCRIPT_SIZE`].
    #[error("script is {len} bytes, limit is {max}")]
    ScriptTooLarge {
        /// Actual length.
        len: usize,
        /// The configured limit.
        max: usize,
    },

    /// A stack element exceeded [`crate::limits::MAX_ELEMENT_SIZE`].
    #[error("stack element is {len} bytes, limit is {max}")]
    ElementTooLarge {
        /// Actual length.
        len: usize,
        /// The configured limit.
        max: usize,
    },

    /// Stack plus altstack exceeded [`crate::limits::MAX_STACK_SIZE`].
    #[error("stack depth {size} exceeds limit {max}")]
    StackOverflow {
        /// Combined depth after the offending operation.
        size: usize,
        /// The configured limit.
        max: usize,
    },

    /// More than [`crate::limits::MAX_OPS`] non-push opcodes were reached.
    #[error("more than {max} non-push opcodes")]
    OpCountExceeded {
        /// The configured limit.
        max: u32,
    },

    /// More than [`crate::limits::MAX_PUBKEYS_PER_MULTISIG`] keys, or a
    /// negative count, in `OP_CHECKMULTISIG`.
    #[error("multisig pubkey count {0} is out of range")]
    PubKeyCountOutOfRange(i64),

    /// The signature count in `OP_CHECKMULTISIG` is negative or exceeds the
    /// pubkey count.
    #[error("multisig signature count {k} is out of range for {n} pubkeys")]
    SigCountOutOfRange {
        /// The requested threshold.
        k: i64,
        /// The number of pubkeys.
        n: i64,
    },

    // ---- parsing (CONTRACT §5.2) ----
    /// A byte that is not in the opcode table. Ferrum has no `OP_NOP1..10`
    /// soft-fork hooks, so the table is exhaustive and this fails the script
    /// even inside an untaken conditional branch.
    #[error("opcode 0x{0:02x} is not defined")]
    InvalidOpcode(u8),

    /// A push ran past the end of the script.
    #[error("push 0x{opcode:02x} needs {needed} more bytes, only {found} remain")]
    TruncatedPush {
        /// The push opcode.
        opcode: u8,
        /// Bytes the push declared.
        needed: usize,
        /// Bytes actually available.
        found: usize,
    },

    /// A push did not use the shortest available form.
    #[error("push 0x{opcode:02x} of {len} bytes is not the minimal encoding")]
    NonMinimalPush {
        /// The push opcode used.
        opcode: u8,
        /// Length of the pushed data.
        len: usize,
    },

    /// A push longer than `OP_PUSHDATA2` can express was requested while
    /// building a script.
    #[error("cannot encode a push of {0} bytes: OP_PUSHDATA4 does not exist in Ferrum")]
    PushTooLarge(usize),

    // ---- numbers (CONTRACT §5.3) ----
    /// A `ScriptNum` operand carried redundant leading zero bytes.
    #[error("script number is not minimally encoded")]
    NonMinimalNum,

    /// A `ScriptNum` operand was longer than the opcode allows.
    #[error("script number is {len} bytes, limit is {max}")]
    NumTooLarge {
        /// Actual length.
        len: usize,
        /// The configured limit.
        max: usize,
    },

    /// A checked arithmetic operation overflowed.
    #[error("script arithmetic overflowed")]
    NumericOverflow,

    // ---- stack discipline ----
    /// An opcode needed more stack than was there.
    #[error("stack underflow: needed {needed}, found {found}")]
    StackUnderflow {
        /// Elements the opcode requires.
        needed: usize,
        /// Elements available.
        found: usize,
    },

    /// `OP_FROMALTSTACK` on an empty altstack.
    #[error("altstack underflow")]
    AltStackUnderflow,

    /// `OP_PICK` or `OP_ROLL` with an index outside the stack.
    #[error("stack index {index} is outside a stack of depth {depth}")]
    InvalidStackIndex {
        /// The requested index.
        index: i64,
        /// The stack depth at the time.
        depth: usize,
    },

    // ---- conditionals (CONTRACT §5.2) ----
    /// `OP_ELSE`/`OP_ENDIF` with no open conditional, or a script that ended
    /// with one still open.
    #[error("unbalanced conditional")]
    UnbalancedConditional,

    /// A second `OP_ELSE` in the same conditional. Bitcoin tolerates toggling;
    /// Ferrum does not, because it is pure script malleability.
    #[error("duplicate OP_ELSE in one conditional")]
    DuplicateElse,

    /// An `OP_IF`/`OP_NOTIF` condition that was not exactly `{}` or `{0x01}`.
    #[error("OP_IF condition must be minimally encoded as empty or 0x01")]
    MinimalIf,

    // ---- execution outcomes ----
    /// `OP_VERIFY` on a false value.
    #[error("OP_VERIFY failed")]
    VerifyFailed,

    /// `OP_EQUALVERIFY` on two unequal values.
    #[error("OP_EQUALVERIFY failed")]
    EqualVerifyFailed,

    /// `OP_NUMEQUALVERIFY` on two unequal numbers.
    #[error("OP_NUMEQUALVERIFY failed")]
    NumEqualVerifyFailed,

    /// `OP_CHECKSIGVERIFY` on a signature that did not verify.
    #[error("OP_CHECKSIGVERIFY failed")]
    CheckSigVerifyFailed,

    /// `OP_CHECKMULTISIGVERIFY` on a set of signatures that did not verify.
    #[error("OP_CHECKMULTISIGVERIFY failed")]
    CheckMultiSigVerifyFailed,

    /// `OP_RETURN` was executed.
    #[error("OP_RETURN")]
    OpReturn,

    /// The final stack held a number of elements other than one. The
    /// clean-stack rule is consensus in Ferrum from day one.
    #[error("clean stack violated: {size} elements remain, expected exactly 1")]
    CleanStack {
        /// Elements remaining.
        size: usize,
    },

    /// Exactly one element remained and it was false.
    #[error("script evaluated to false")]
    EvalFalse,

    /// `script_sig` contained something other than pushes. A consensus rule in
    /// Ferrum, not a policy rule.
    #[error("script_sig must be push-only")]
    PushOnly,

    /// A P2SH `script_pubkey` was matched but `script_sig` pushed nothing, so
    /// there is no redeem script.
    #[error("P2SH script_sig pushed no redeem script")]
    P2shEmptyScriptSig,

    // ---- signatures (CONTRACT §5.5) ----
    /// A signature was not exactly 65 bytes.
    #[error("signature must be exactly 65 bytes, got {0}")]
    InvalidSignatureLength(usize),

    /// A sighash-type byte was not one of `0x01`, `0x02`, `0x03`, `0x81`,
    /// `0x82`, `0x83`.
    #[error("invalid sighash type 0x{0:02x}")]
    InvalidSigHashType(u8),

    /// A public key on the stack was not a valid 32-byte x-only point.
    #[error("invalid x-only public key")]
    InvalidPublicKey,

    /// `SIGHASH_SINGLE` with no matching output. Bitcoin returns the signable
    /// constant `uint256(1)` here; Ferrum returns an error.
    #[error("SIGHASH_SINGLE: input {input_index} has no matching output ({outputs} outputs)")]
    SigHashSingleOutOfRange {
        /// The index being signed.
        input_index: usize,
        /// How many outputs the transaction has.
        outputs: usize,
    },

    /// `ExecCtx::input_index` is not an index into `tx.inputs`.
    #[error("input index {index} is outside a transaction with {inputs} inputs")]
    InvalidInputIndex {
        /// The index requested.
        index: usize,
        /// How many inputs the transaction has.
        inputs: usize,
    },

    // ---- timelocks ----
    /// A negative `OP_CHECKLOCKTIMEVERIFY` / `OP_CHECKSEQUENCEVERIFY` operand.
    #[error("negative locktime operand {0}")]
    NegativeLockTime(i64),

    /// The operand and `tx.lock_time` sit on opposite sides of
    /// [`ferrum_types::LOCKTIME_THRESHOLD`], so one is a height and the other
    /// a timestamp.
    #[error("locktime type mismatch: script requires {required}, transaction has {tx}")]
    LockTimeTypeMismatch {
        /// The value the script demands.
        required: u64,
        /// The transaction's own `lock_time`.
        tx: u32,
    },

    /// `tx.lock_time` has not reached the value the script demands.
    #[error("locktime not satisfied: script requires {required}, transaction has {tx}")]
    UnsatisfiedLockTime {
        /// The value the script demands.
        required: u64,
        /// The transaction's own `lock_time`.
        tx: u32,
    },

    /// The input's `sequence` is `u32::MAX`, which opts out of `lock_time`
    /// enforcement entirely and so can never satisfy a CLTV.
    #[error("OP_CHECKLOCKTIMEVERIFY on an input with sequence == u32::MAX")]
    FinalSequence,

    /// The `OP_CHECKSEQUENCEVERIFY` operand had BIP-68's disable bit set.
    /// Ferrum has no NOP semantics to fall back on, so this is an error.
    #[error("OP_CHECKSEQUENCEVERIFY operand {0} has the BIP-68 disable bit set")]
    SequenceDisabledOperand(u64),

    /// The input's `sequence` has BIP-68's disable bit set, so no relative
    /// locktime can be satisfied.
    #[error("relative locktime is disabled for this input")]
    SequenceLockDisabled,

    /// The operand and the input's `sequence` disagree about blocks vs time.
    #[error("relative locktime type mismatch: script 0x{required:08x}, input 0x{sequence:08x}")]
    SequenceTypeMismatch {
        /// The value the script demands.
        required: u32,
        /// The input's `sequence`.
        sequence: u32,
    },

    /// The input's relative locktime is smaller than the script demands.
    #[error("relative locktime not satisfied: script 0x{required:08x}, input 0x{sequence:08x}")]
    UnsatisfiedSequence {
        /// The value the script demands.
        required: u32,
        /// The input's `sequence`.
        sequence: u32,
    },

    // ---- template construction ----
    /// `templates::multisig` was given zero keys, or more than
    /// [`crate::limits::MAX_PUBKEYS_PER_MULTISIG`].
    #[error("multisig needs 1..={max} pubkeys, got {n}")]
    MultisigKeyCount {
        /// Keys supplied.
        n: usize,
        /// The configured limit.
        max: usize,
    },

    /// `templates::multisig` was given a threshold outside `1..=n`.
    #[error("multisig threshold {k} is not in 1..={n}")]
    MultisigThreshold {
        /// The requested threshold.
        k: u8,
        /// Keys supplied.
        n: usize,
    },

    /// `templates::op_return` was given more than
    /// [`crate::limits::MAX_OP_RETURN_PAYLOAD`] bytes.
    #[error("OP_RETURN payload is {len} bytes, limit is {max}")]
    OpReturnTooLarge {
        /// Actual length.
        len: usize,
        /// The configured limit.
        max: usize,
    },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;

    #[test]
    fn errors_are_comparable_and_named() {
        let a = ScriptError::ScriptTooLarge { len: 1_001, max: 1_000 };
        assert_eq!(a, ScriptError::ScriptTooLarge { len: 1_001, max: 1_000 });
        assert_ne!(a, ScriptError::ScriptTooLarge { len: 1_002, max: 1_000 });
        assert_eq!(a.to_string(), "script is 1001 bytes, limit is 1000");
    }

    #[test]
    fn opcode_errors_render_in_hex() {
        assert_eq!(ScriptError::InvalidOpcode(0xba).to_string(), "opcode 0xba is not defined");
        assert_eq!(ScriptError::InvalidSigHashType(0x04).to_string(), "invalid sighash type 0x04");
    }

    #[test]
    fn clone_is_available_for_assertions() {
        let e = ScriptError::CleanStack { size: 3 };
        assert_eq!(e.clone(), e);
    }
}
