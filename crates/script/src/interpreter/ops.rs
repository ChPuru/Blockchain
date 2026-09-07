//! Opcode semantics.
//!
//! One method per group, dispatched from [`Machine::exec_op`]. Everything here
//! runs only on a live branch: the conditional opcodes are handled by the run
//! loop in the parent module, because they must keep working inside a branch
//! that is not taken.
//!
//! Two rules govern the whole file:
//!
//! - **Nothing may panic.** Every pop and index goes through the checked
//!   helpers on [`Machine`], and every `+ - *` is `checked_*` or `saturating_*`.
//! - **A malformed value is an error; a wrong value is `false`.** A signature
//!   that is not 65 bytes, a public key that is not a point, a non-minimal
//!   number: those fail the script. A well-formed signature that does not
//!   verify pushes `false`, because `OP_CHECKMULTISIG` has to probe pubkeys in
//!   order and a failed probe is expected.

use ferrum_crypto::{PublicKey, hash160, hash256, sha256};
use ferrum_types::LOCKTIME_THRESHOLD;
use ripemd::{Digest as _, Ripemd160};

use crate::error::ScriptError;
use crate::interpreter::Machine;
use crate::limits::{
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_GRANULARITY, SEQUENCE_LOCKTIME_MASK,
    SEQUENCE_LOCKTIME_TYPE_FLAG,
};
use crate::num::{ScriptNum, cast_to_bool};
use crate::opcode::Opcode;
use crate::sighash::split_signature;

impl Machine<'_, '_> {
    /// Read the top of the stack as an arithmetic operand and pop it.
    fn pop_num(&mut self) -> Result<i64, ScriptError> {
        let bytes = self.pop()?;
        Ok(ScriptNum::arithmetic(&bytes, self.ctx.limits.max_num_size)?.value())
    }

    /// Push a number in its minimal encoding.
    fn push_num(&mut self, v: i64) -> Result<(), ScriptError> {
        self.push(ScriptNum::new(v).to_vec())
    }

    /// Pop two numbers: the top becomes `b`, the one below it `a`.
    fn pop_two_nums(&mut self) -> Result<(i64, i64), ScriptError> {
        let b = self.pop_num()?;
        let a = self.pop_num()?;
        Ok((a, b))
    }

    /// Execute one non-conditional opcode on a live branch.
    pub(crate) fn exec_op(&mut self, op: Opcode, script_code: &[u8]) -> Result<(), ScriptError> {
        match op {
            Opcode::Nop => Ok(()),
            Opcode::If | Opcode::NotIf | Opcode::Else | Opcode::EndIf => {
                // Handled by the run loop; unreachable in practice, and a plain
                // no-op rather than a panic if that ever stops being true.
                Ok(())
            }
            Opcode::Verify => {
                let top = self.pop()?;
                if cast_to_bool(&top) { Ok(()) } else { Err(ScriptError::VerifyFailed) }
            }
            Opcode::Return => Err(ScriptError::OpReturn),
            Opcode::ToAltStack | Opcode::FromAltStack => self.altstack_op(op),
            Opcode::TwoDup
            | Opcode::IfDup
            | Opcode::Depth
            | Opcode::Drop
            | Opcode::Dup
            | Opcode::Nip
            | Opcode::Over
            | Opcode::Pick
            | Opcode::Roll
            | Opcode::Rot
            | Opcode::Swap
            | Opcode::Tuck
            | Opcode::Size => self.stack_op(op),
            Opcode::Equal | Opcode::EqualVerify => {
                let b = self.pop()?;
                let a = self.pop()?;
                let equal = a == b;
                if op == Opcode::EqualVerify {
                    if equal { Ok(()) } else { Err(ScriptError::EqualVerifyFailed) }
                } else {
                    self.push_bool(equal)
                }
            }
            Opcode::Add1
            | Opcode::Sub1
            | Opcode::Negate
            | Opcode::Abs
            | Opcode::Not
            | Opcode::ZeroNotEqual => self.unary_num(op),
            Opcode::Add
            | Opcode::Sub
            | Opcode::BoolAnd
            | Opcode::BoolOr
            | Opcode::NumEqual
            | Opcode::NumEqualVerify
            | Opcode::NumNotEqual
            | Opcode::LessThan
            | Opcode::GreaterThan
            | Opcode::LessThanOrEqual
            | Opcode::GreaterThanOrEqual
            | Opcode::Min
            | Opcode::Max => self.binary_num(op),
            Opcode::Within => {
                let max = self.pop_num()?;
                let min = self.pop_num()?;
                let x = self.pop_num()?;
                self.push_bool(min <= x && x < max)
            }
            Opcode::Ripemd160 | Opcode::Sha256 | Opcode::Hash160 | Opcode::Hash256 => {
                self.hash_op(op)
            }
            Opcode::CheckSig | Opcode::CheckSigVerify => {
                let pubkey = self.pop()?;
                let signature = self.pop()?;
                let ok = self.check_signature(&signature, &pubkey, script_code)?;
                if op == Opcode::CheckSigVerify {
                    if ok { Ok(()) } else { Err(ScriptError::CheckSigVerifyFailed) }
                } else {
                    self.push_bool(ok)
                }
            }
            Opcode::CheckMultiSig | Opcode::CheckMultiSigVerify => {
                let ok = self.check_multisig(script_code)?;
                if op == Opcode::CheckMultiSigVerify {
                    if ok { Ok(()) } else { Err(ScriptError::CheckMultiSigVerifyFailed) }
                } else {
                    self.push_bool(ok)
                }
            }
            Opcode::CheckLockTimeVerify => self.check_lock_time(),
            Opcode::CheckSequenceVerify => self.check_sequence(),
        }
    }

    /// `OP_TOALTSTACK` / `OP_FROMALTSTACK`.
    fn altstack_op(&mut self, op: Opcode) -> Result<(), ScriptError> {
        if op == Opcode::ToAltStack {
            let v = self.pop()?;
            self.altstack.push(v);
        } else {
            let v = self.altstack.pop().ok_or(ScriptError::AltStackUnderflow)?;
            self.push(v)?;
        }
        Ok(())
    }

    /// The pure stack shuffles.
    fn stack_op(&mut self, op: Opcode) -> Result<(), ScriptError> {
        match op {
            Opcode::Depth => {
                let depth =
                    i64::try_from(self.stack.len()).map_err(|_| ScriptError::NumericOverflow)?;
                self.push_num(depth)
            }
            Opcode::Drop => {
                self.pop()?;
                Ok(())
            }
            Opcode::Dup => {
                let top = self.peek(0)?.to_vec();
                self.push(top)
            }
            Opcode::IfDup => {
                let top = self.peek(0)?.to_vec();
                if cast_to_bool(&top) { self.push(top) } else { Ok(()) }
            }
            Opcode::TwoDup => {
                let second = self.peek(1)?.to_vec();
                let first = self.peek(0)?.to_vec();
                self.push(second)?;
                self.push(first)
            }
            Opcode::Nip => {
                self.need(2)?;
                let index = self.index_from_top(1)?;
                self.stack.remove(index);
                Ok(())
            }
            Opcode::Over => {
                let second = self.peek(1)?.to_vec();
                self.push(second)
            }
            Opcode::Swap => {
                self.need(2)?;
                let a = self.index_from_top(0)?;
                let b = self.index_from_top(1)?;
                self.stack.swap(a, b);
                Ok(())
            }
            Opcode::Rot => {
                self.need(3)?;
                let index = self.index_from_top(2)?;
                let third = self.stack.remove(index);
                self.push(third)
            }
            Opcode::Tuck => {
                self.need(2)?;
                let top = self.peek(0)?.to_vec();
                let index = self.index_from_top(1)?;
                if top.len() > self.ctx.limits.max_element_size {
                    return Err(ScriptError::ElementTooLarge {
                        len: top.len(),
                        max: self.ctx.limits.max_element_size,
                    });
                }
                self.stack.insert(index, top);
                Ok(())
            }
            Opcode::Size => {
                let len =
                    i64::try_from(self.peek(0)?.len()).map_err(|_| ScriptError::NumericOverflow)?;
                self.push_num(len)
            }
            Opcode::Pick | Opcode::Roll => {
                let n = self.pop_num()?;
                let depth = self.stack.len();
                let offset = usize::try_from(n)
                    .ok()
                    .filter(|o| *o < depth)
                    .ok_or(ScriptError::InvalidStackIndex { index: n, depth })?;
                let index = self.index_from_top(offset)?;
                if op == Opcode::Pick {
                    let picked =
                        self.stack.get(index).cloned().ok_or(ScriptError::StackUnderflow {
                            needed: offset.saturating_add(1),
                            found: depth,
                        })?;
                    self.push(picked)
                } else {
                    let rolled = self.stack.remove(index);
                    self.push(rolled)
                }
            }
            _ => Ok(()),
        }
    }

    /// Translate "`depth` items from the top" into an index into `self.stack`.
    fn index_from_top(&self, depth: usize) -> Result<usize, ScriptError> {
        self.stack.len().checked_sub(depth).and_then(|d| d.checked_sub(1)).ok_or(
            ScriptError::StackUnderflow {
                needed: depth.saturating_add(1),
                found: self.stack.len(),
            },
        )
    }

    /// `OP_1ADD`, `OP_1SUB`, `OP_NEGATE`, `OP_ABS`, `OP_NOT`, `OP_0NOTEQUAL`.
    fn unary_num(&mut self, op: Opcode) -> Result<(), ScriptError> {
        let a = self.pop_num()?;
        match op {
            Opcode::Add1 => {
                let v = a.checked_add(1).ok_or(ScriptError::NumericOverflow)?;
                self.push_num(v)
            }
            Opcode::Sub1 => {
                let v = a.checked_sub(1).ok_or(ScriptError::NumericOverflow)?;
                self.push_num(v)
            }
            Opcode::Negate => {
                let v = a.checked_neg().ok_or(ScriptError::NumericOverflow)?;
                self.push_num(v)
            }
            Opcode::Abs => {
                let v = a.checked_abs().ok_or(ScriptError::NumericOverflow)?;
                self.push_num(v)
            }
            Opcode::Not => self.push_bool(a == 0),
            _ => self.push_bool(a != 0),
        }
    }

    /// The two-operand numeric opcodes.
    fn binary_num(&mut self, op: Opcode) -> Result<(), ScriptError> {
        let (a, b) = self.pop_two_nums()?;
        match op {
            Opcode::Add => {
                let v = a.checked_add(b).ok_or(ScriptError::NumericOverflow)?;
                self.push_num(v)
            }
            Opcode::Sub => {
                let v = a.checked_sub(b).ok_or(ScriptError::NumericOverflow)?;
                self.push_num(v)
            }
            Opcode::BoolAnd => self.push_bool(a != 0 && b != 0),
            Opcode::BoolOr => self.push_bool(a != 0 || b != 0),
            Opcode::NumEqual => self.push_bool(a == b),
            Opcode::NumEqualVerify => {
                if a == b {
                    Ok(())
                } else {
                    Err(ScriptError::NumEqualVerifyFailed)
                }
            }
            Opcode::NumNotEqual => self.push_bool(a != b),
            Opcode::LessThan => self.push_bool(a < b),
            Opcode::GreaterThan => self.push_bool(a > b),
            Opcode::LessThanOrEqual => self.push_bool(a <= b),
            Opcode::GreaterThanOrEqual => self.push_bool(a >= b),
            Opcode::Min => self.push_num(a.min(b)),
            _ => self.push_num(a.max(b)),
        }
    }

    /// `OP_RIPEMD160`, `OP_SHA256`, `OP_HASH160`, `OP_HASH256`.
    ///
    /// `OP_HASH256` is `tagged_hash(TAG_SCRIPT, x)` — Ferrum's domain-separated
    /// BLAKE3, not Bitcoin's double SHA-256. It is the hash a P2SH address
    /// commits to.
    fn hash_op(&mut self, op: Opcode) -> Result<(), ScriptError> {
        let data = self.pop()?;
        let digest: Vec<u8> = match op {
            Opcode::Ripemd160 => Ripemd160::digest(&data).to_vec(),
            Opcode::Sha256 => sha256(&data).to_vec(),
            Opcode::Hash160 => hash160(&data).to_vec(),
            _ => hash256(&data).as_bytes().to_vec(),
        };
        self.push(digest)
    }

    /// Verify one 65-byte signature against one 32-byte x-only public key.
    ///
    /// Returns `false` only for a well-formed signature that does not verify;
    /// a malformed signature or key is an error.
    ///
    /// The digest comes from the machine's [`crate::sighash::SighashCache`], so
    /// the three transaction-wide mid-states are hashed once rather than once
    /// per check. A script may legally perform 201 signature checks, and every
    /// input of the transaction runs this path: recomputing them here is what
    /// makes validation quadratic in transaction size.
    fn check_signature(
        &mut self,
        signature: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
    ) -> Result<bool, ScriptError> {
        let (sig, ty) = split_signature(signature)?;
        let key_bytes: [u8; 32] = pubkey.try_into().map_err(|_| ScriptError::InvalidPublicKey)?;
        let key = PublicKey::from_bytes(&key_bytes).map_err(|_| ScriptError::InvalidPublicKey)?;
        let msg = self.sighash_cache().signature_hash(
            self.ctx.input_index,
            script_code,
            self.ctx.input_value,
            self.ctx.chain_id,
            ty,
        )?;
        self.sig_checks = self.sig_checks.saturating_add(1);
        Ok(key.verify(&msg, &sig).is_ok())
    }

    /// `OP_CHECKMULTISIG` with no dummy element.
    ///
    /// Pops exactly `n`, then `n` pubkeys, then `k`, then `k` signatures.
    /// Bitcoin's extra pop is an off-by-one bug that had to be enshrined; there
    /// is nothing to be compatible with here, so it is simply absent.
    ///
    /// Matching is in order: signature `i` is tried against successive pubkeys
    /// until one verifies, and a pubkey once passed is never revisited. That
    /// makes a `k`-of-`n` check cost at most `n` verifications.
    fn check_multisig(&mut self, script_code: &[u8]) -> Result<bool, ScriptError> {
        let max_keys = self.ctx.limits.max_pubkeys_per_multisig;
        let n_num = self.pop_num()?;
        let n = usize::try_from(n_num)
            .ok()
            .filter(|n| *n <= max_keys)
            .ok_or(ScriptError::PubKeyCountOutOfRange(n_num))?;

        // Each key is a potential verification, so each is charged as an
        // operation. This is what bounds the work an input can demand.
        self.charge(u32::try_from(n).map_err(|_| ScriptError::NumericOverflow)?)?;

        self.need(n)?;
        let mut pubkeys: Vec<Vec<u8>> = Vec::with_capacity(n);
        for _ in 0..n {
            pubkeys.push(self.pop()?);
        }
        pubkeys.reverse();

        let k_num = self.pop_num()?;
        let k = usize::try_from(k_num)
            .ok()
            .filter(|k| *k <= n)
            .ok_or(ScriptError::SigCountOutOfRange { k: k_num, n: n_num })?;

        self.need(k)?;
        let mut signatures: Vec<Vec<u8>> = Vec::with_capacity(k);
        for _ in 0..k {
            signatures.push(self.pop()?);
        }
        signatures.reverse();

        let mut sig_index: usize = 0;
        let mut key_index: usize = 0;
        while sig_index < k {
            let sigs_left = k.saturating_sub(sig_index);
            let keys_left = n.saturating_sub(key_index);
            if keys_left < sigs_left {
                return Ok(false);
            }
            let signature = signatures.get(sig_index).ok_or(ScriptError::NumericOverflow)?.clone();
            let key = pubkeys.get(key_index).ok_or(ScriptError::NumericOverflow)?.clone();
            if self.check_signature(&signature, &key, script_code)? {
                sig_index = sig_index.checked_add(1).ok_or(ScriptError::NumericOverflow)?;
            }
            key_index = key_index.checked_add(1).ok_or(ScriptError::NumericOverflow)?;
        }
        Ok(true)
    }

    /// `OP_CHECKLOCKTIMEVERIFY` — BIP-65 semantics.
    ///
    /// The operand is inspected, not popped, so the canonical template is
    /// `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP …`.
    fn check_lock_time(&mut self) -> Result<(), ScriptError> {
        let operand = self.peek(0)?.to_vec();
        // Five bytes, not four: a `lock_time` above 0x7fffffff needs the extra
        // sign byte.
        let value =
            ScriptNum::from_slice(&operand, self.ctx.limits.max_locktime_num_size(), true)?.value();
        if value < 0 {
            return Err(ScriptError::NegativeLockTime(value));
        }
        let required = u64::try_from(value).map_err(|_| ScriptError::NumericOverflow)?;
        let tx_lock_time = self.ctx.tx.lock_time;
        let threshold = u64::from(LOCKTIME_THRESHOLD);

        // Both must be heights, or both timestamps. Mixing them would let a
        // script demanding block 500 be satisfied by a timestamp of 500.
        if (required < threshold) != (u64::from(tx_lock_time) < threshold) {
            return Err(ScriptError::LockTimeTypeMismatch { required, tx: tx_lock_time });
        }
        if required > u64::from(tx_lock_time) {
            return Err(ScriptError::UnsatisfiedLockTime { required, tx: tx_lock_time });
        }
        // A final input opts out of `lock_time` enforcement, so the timelock
        // would be unenforced even though the script demanded it.
        let input =
            self.ctx.tx.inputs.get(self.ctx.input_index).ok_or(ScriptError::InvalidInputIndex {
                index: self.ctx.input_index,
                inputs: self.ctx.tx.inputs.len(),
            })?;
        if input.sequence == u32::MAX {
            return Err(ScriptError::FinalSequence);
        }
        Ok(())
    }

    /// `OP_CHECKSEQUENCEVERIFY` — BIP-68/112 semantics.
    ///
    /// Bit 31 disables relative locktime, bit 22 selects 512-second units over
    /// block counts, and bits 0..15 carry the value. Bitcoin treats an operand
    /// with bit 31 set as a no-op so that old nodes stay compatible; Ferrum has
    /// no soft-fork hooks and no old nodes, so it is an error.
    ///
    /// The opcode has two halves and **both** are needed for it to be a
    /// timelock at all:
    ///
    /// 1. BIP-112, the script half: the operand must not ask for more than the
    ///    input's `sequence` claims, and must agree with it about blocks vs
    ///    time. Both of those numbers are written by the spender, so this half
    ///    on its own enforces nothing.
    /// 2. BIP-68, the chain half: the input's `sequence` must actually be
    ///    satisfied by the age of the coin being spent, measured from
    ///    [`crate::ExecCtx::input_height`] (blocks) or
    ///    [`crate::ExecCtx::input_mtp_s`] (512-second units of median time
    ///    past). Without it a `<n> OP_CSV OP_DROP` output is spendable in the
    ///    very next block by whoever can sign.
    ///
    /// A context that cannot supply the coin's age fails the script rather than
    /// skipping the second half.
    fn check_sequence(&mut self) -> Result<(), ScriptError> {
        let operand = self.peek(0)?.to_vec();
        let value =
            ScriptNum::from_slice(&operand, self.ctx.limits.max_locktime_num_size(), true)?.value();
        if value < 0 {
            return Err(ScriptError::NegativeLockTime(value));
        }
        let required = u64::try_from(value).map_err(|_| ScriptError::NumericOverflow)?;
        // Anything at or above 2^31 either sets the disable bit or overflows a
        // `u32`; both mean "this script asks for something BIP-68 cannot say".
        if required >= u64::from(SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            return Err(ScriptError::SequenceDisabledOperand(required));
        }
        let required =
            u32::try_from(required).map_err(|_| ScriptError::SequenceDisabledOperand(required))?;

        let input =
            self.ctx.tx.inputs.get(self.ctx.input_index).ok_or(ScriptError::InvalidInputIndex {
                index: self.ctx.input_index,
                inputs: self.ctx.tx.inputs.len(),
            })?;
        let sequence = input.sequence;

        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return Err(ScriptError::SequenceLockDisabled);
        }
        if (required & SEQUENCE_LOCKTIME_TYPE_FLAG) != (sequence & SEQUENCE_LOCKTIME_TYPE_FLAG) {
            return Err(ScriptError::SequenceTypeMismatch { required, sequence });
        }
        if (required & SEQUENCE_LOCKTIME_MASK) > (sequence & SEQUENCE_LOCKTIME_MASK) {
            return Err(ScriptError::UnsatisfiedSequence { required, sequence });
        }

        self.check_sequence_age(sequence)
    }

    /// The BIP-68 half of `OP_CHECKSEQUENCEVERIFY`: measure the input's
    /// `sequence` against the age of the coin it spends.
    ///
    /// `sequence` has already been checked to have the disable bit clear and to
    /// be at least what the script operand demands, so enforcing the input's
    /// own claim also enforces the script's.
    fn check_sequence_age(&self, sequence: u32) -> Result<(), ScriptError> {
        let relative = sequence & SEQUENCE_LOCKTIME_MASK;
        if relative == 0 {
            // The input asks for no delay, so there is nothing to measure and
            // no reason to demand the coin's age.
            return Ok(());
        }

        if sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
            let coin_mtp_s = self.ctx.input_mtp_s.ok_or(ScriptError::UnknownCoinTime)?;
            // Units of 512 seconds; 0xffff << 9 cannot overflow a u64.
            let required_s = u64::from(relative)
                .checked_shl(SEQUENCE_LOCKTIME_GRANULARITY)
                .ok_or(ScriptError::NumericOverflow)?;
            let matures_at =
                coin_mtp_s.checked_add(required_s).ok_or(ScriptError::NumericOverflow)?;
            if self.ctx.block_mtp_s < matures_at {
                return Err(ScriptError::ImmatureRelativeTime {
                    required_s,
                    coin_mtp_s,
                    block_mtp_s: self.ctx.block_mtp_s,
                });
            }
        } else {
            let coin_height = self.ctx.input_height.ok_or(ScriptError::UnknownCoinHeight)?;
            let matures_at =
                coin_height.checked_add(u64::from(relative)).ok_or(ScriptError::NumericOverflow)?;
            if self.ctx.block_height < matures_at {
                return Err(ScriptError::ImmatureRelativeHeight {
                    required: relative,
                    coin_height,
                    block_height: self.ctx.block_height,
                });
            }
        }
        Ok(())
    }
}
