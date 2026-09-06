//! The execution model (CONTRACT §5.4).
//!
//! # Order of execution
//!
//! 1. `script_sig` runs on an empty stack. It **must be push-only** — a
//!    consensus rule in Ferrum, not a policy rule, because arbitrary operations
//!    in an unlocking script serve no purpose and double the attack surface.
//! 2. The resulting stack is carried into `script_pubkey`.
//! 3. If `script_pubkey` matched the P2SH template `OP_HASH256 <32B> OP_EQUAL`,
//!    it only has to leave a true value on top — the elements below it are the
//!    redeem script's arguments. The last `script_sig` push is then taken as
//!    the redeem script and executed on the stack that remained after
//!    `script_sig`. Its hash has already been checked by the `OP_EQUAL`.
//!    **P2SH does not recurse**: a redeem script that itself matches the
//!    template simply executes.
//! 4. The script that ran last must leave **exactly one** element and it must
//!    be true. Bitcoin added the clean-stack rule late, as policy, because it
//!    could not make it consensus retroactively; here it is consensus from day
//!    one.
//!
//! Limits apply to each script separately, but the **operation count is not
//! reset between them**, so an attacker cannot buy extra work by splitting a
//! script in two. The altstack is fresh for each script; the data stack is not.
//!
//! # Panic freedom
//!
//! Every pop, index and slice in this module is checked and maps to a
//! [`ScriptError`]. `testing/fuzz/fuzz_targets/script.rs` and the proptests in
//! `tests/never_panics.rs` exist to keep it that way. The script VM is the
//! largest surface in the project reachable by unauthenticated input.

mod ops;

use ferrum_types::{Amount, ChainId, Script, Transaction};

use crate::error::ScriptError;
use crate::limits::ScriptLimits;
use crate::num::cast_to_bool;
use crate::opcode::{Instruction, OP_PUSHBYTES_MAX, Opcode};
use crate::parse::parse;

/// The interpreter's data stack: a stack of byte strings, bottom first.
pub type Stack = Vec<Vec<u8>>;

/// Everything a script needs to know about the world outside itself.
///
/// There is no clock and no randomness here: `block_height` and `block_mtp_s`
/// are supplied by the caller, which keeps the whole VM a pure function of its
/// inputs.
#[derive(Debug)]
pub struct ExecCtx<'a> {
    /// The network this signature must have been made for. Signing over it is
    /// what makes a testnet signature useless on mainnet.
    pub chain_id: ChainId,
    /// The transaction being validated.
    pub tx: &'a Transaction,
    /// Which input of [`ExecCtx::tx`] this script unlocks.
    pub input_index: usize,
    /// The value of the output being spent, committed to by the sighash.
    pub input_value: Amount,
    /// Height of the block containing [`ExecCtx::tx`].
    pub block_height: u64,
    /// Median time past in **seconds**, for a timestamp-flavoured CLTV.
    pub block_mtp_s: u64,
    /// The limit table in force.
    pub limits: ScriptLimits,
}

impl<'a> ExecCtx<'a> {
    /// A context with consensus limits and everything else at its zero value.
    pub fn new(chain_id: ChainId, tx: &'a Transaction, input_index: usize) -> Self {
        ExecCtx {
            chain_id,
            tx,
            input_index,
            input_value: Amount::ZERO,
            block_height: 0,
            block_mtp_s: 0,
            limits: ScriptLimits::CONSENSUS,
        }
    }
}

/// What one `verify` call cost.
///
/// Returned rather than logged so the mempool and the block validator can bill
/// for it without re-running anything.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ExecStats {
    /// Non-push opcodes executed, across every script of this input.
    pub ops: u32,
    /// Deepest the stack and altstack got, combined.
    pub max_stack: usize,
    /// Signature verifications attempted, including the failed probes an
    /// in-order `OP_CHECKMULTISIG` makes.
    pub sig_checks: u32,
}

/// One open `OP_IF`/`OP_NOTIF`.
#[derive(Clone, Copy, Debug)]
struct Conditional {
    /// Whether the branch currently being read is the one that executes.
    taken: bool,
    /// Whether an `OP_ELSE` has already been seen for this conditional. A
    /// second one is rejected: Bitcoin lets `OP_ELSE` toggle, which is pure
    /// script malleability with no legitimate use.
    else_seen: bool,
}

/// The interpreter state.
pub(crate) struct Machine<'a, 'c> {
    pub(crate) ctx: &'c ExecCtx<'a>,
    pub(crate) stack: Stack,
    pub(crate) altstack: Stack,
    pub(crate) ops: u32,
    pub(crate) sig_checks: u32,
    pub(crate) max_stack: usize,
}

impl<'a, 'c> Machine<'a, 'c> {
    fn new(ctx: &'c ExecCtx<'a>) -> Self {
        Machine {
            ctx,
            stack: Vec::new(),
            altstack: Vec::new(),
            ops: 0,
            sig_checks: 0,
            max_stack: 0,
        }
    }

    fn stats(&self) -> ExecStats {
        ExecStats { ops: self.ops, max_stack: self.max_stack, sig_checks: self.sig_checks }
    }

    // ---- checked stack primitives -------------------------------------
    // Nothing below may panic. `expect` and raw indexing are both banned here
    // on purpose: an out-of-range access is a consensus bug, not a crash.

    pub(crate) fn need(&self, n: usize) -> Result<(), ScriptError> {
        if self.stack.len() < n {
            return Err(ScriptError::StackUnderflow { needed: n, found: self.stack.len() });
        }
        Ok(())
    }

    pub(crate) fn pop(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.stack.pop().ok_or(ScriptError::StackUnderflow { needed: 1, found: 0 })
    }

    /// Borrow the element `depth` from the top, where `0` is the top itself.
    pub(crate) fn peek(&self, depth: usize) -> Result<&[u8], ScriptError> {
        let len = self.stack.len();
        let index = len
            .checked_sub(depth)
            .and_then(|d| d.checked_sub(1))
            .ok_or(ScriptError::StackUnderflow { needed: depth.saturating_add(1), found: len })?;
        self.stack
            .get(index)
            .map(Vec::as_slice)
            .ok_or(ScriptError::StackUnderflow { needed: depth.saturating_add(1), found: len })
    }

    pub(crate) fn push(&mut self, v: Vec<u8>) -> Result<(), ScriptError> {
        if v.len() > self.ctx.limits.max_element_size {
            return Err(ScriptError::ElementTooLarge {
                len: v.len(),
                max: self.ctx.limits.max_element_size,
            });
        }
        self.stack.push(v);
        Ok(())
    }

    pub(crate) fn push_bool(&mut self, v: bool) -> Result<(), ScriptError> {
        self.push(crate::num::bool_to_vec(v))
    }

    /// Enforce the combined stack/altstack depth limit.
    fn check_depth(&mut self) -> Result<(), ScriptError> {
        let size = self.stack.len().saturating_add(self.altstack.len());
        if size > self.ctx.limits.max_stack_size {
            return Err(ScriptError::StackOverflow { size, max: self.ctx.limits.max_stack_size });
        }
        if size > self.max_stack {
            self.max_stack = size;
        }
        Ok(())
    }

    /// Charge `n` operations against [`ScriptLimits::max_ops`].
    pub(crate) fn charge(&mut self, n: u32) -> Result<(), ScriptError> {
        self.ops = self.ops.saturating_add(n);
        if self.ops > self.ctx.limits.max_ops {
            return Err(ScriptError::OpCountExceeded { max: self.ctx.limits.max_ops });
        }
        Ok(())
    }

    // ---- the run loop --------------------------------------------------

    /// Parse and execute one script, using it as its own `script_code`.
    fn run(&mut self, script: &Script) -> Result<(), ScriptError> {
        if script.len() > self.ctx.limits.max_script_size {
            return Err(ScriptError::ScriptTooLarge {
                len: script.len(),
                max: self.ctx.limits.max_script_size,
            });
        }
        let instructions = parse(script)?;
        self.execute(&instructions, script.as_bytes())
    }

    /// Execute an already-parsed script.
    fn execute(
        &mut self,
        instructions: &[Instruction],
        script_code: &[u8],
    ) -> Result<(), ScriptError> {
        // The altstack is per-script, matching Bitcoin: it cannot be used to
        // smuggle values from `script_sig` into `script_pubkey`.
        self.altstack.clear();
        let mut conditionals: Vec<Conditional> = Vec::new();

        for instruction in instructions {
            let executing = conditionals.iter().all(|c| c.taken);

            match instruction {
                Instruction::Push { data, .. } => {
                    // Element size is checked even in an untaken branch: the
                    // push is decoded either way, so it costs the same memory.
                    if data.len() > self.ctx.limits.max_element_size {
                        return Err(ScriptError::ElementTooLarge {
                            len: data.len(),
                            max: self.ctx.limits.max_element_size,
                        });
                    }
                    if executing {
                        self.stack.push(data.clone());
                    }
                }
                Instruction::Op(op) => {
                    // Operations are charged whether or not they run, so a
                    // long untaken branch is not free.
                    self.charge(1)?;
                    if op.is_conditional() {
                        self.conditional(*op, &mut conditionals, executing)?;
                    } else if executing {
                        self.exec_op(*op, script_code)?;
                    }
                }
            }
            self.check_depth()?;
        }

        if !conditionals.is_empty() {
            return Err(ScriptError::UnbalancedConditional);
        }
        Ok(())
    }

    /// `OP_IF`, `OP_NOTIF`, `OP_ELSE`, `OP_ENDIF`.
    ///
    /// These four run even inside an untaken branch, because the interpreter
    /// still has to find the matching `OP_ENDIF`. The condition operand is only
    /// popped when the branch is live, exactly as Bitcoin does.
    fn conditional(
        &mut self,
        op: Opcode,
        conditionals: &mut Vec<Conditional>,
        executing: bool,
    ) -> Result<(), ScriptError> {
        match op {
            Opcode::If | Opcode::NotIf => {
                let taken = if executing {
                    let condition = self.pop()?;
                    if !crate::num::is_minimal_bool(&condition) {
                        return Err(ScriptError::MinimalIf);
                    }
                    let value = cast_to_bool(&condition);
                    if op == Opcode::If { value } else { !value }
                } else {
                    false
                };
                conditionals.push(Conditional { taken, else_seen: false });
            }
            Opcode::Else => {
                let frame = conditionals.last_mut().ok_or(ScriptError::UnbalancedConditional)?;
                if frame.else_seen {
                    return Err(ScriptError::DuplicateElse);
                }
                frame.else_seen = true;
                // Flip this frame only. Whether the branch actually runs is
                // still `all(taken)` over the whole stack, so a nested
                // conditional inside a dead outer branch stays dead.
                frame.taken = !frame.taken;
            }
            Opcode::EndIf => {
                conditionals.pop().ok_or(ScriptError::UnbalancedConditional)?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// True when `s` is exactly `OP_HASH256 <32 bytes> OP_EQUAL`.
///
/// Matched on raw bytes rather than on a parse, so that a script which happens
/// to be unparseable can never be mistaken for a P2SH output.
pub fn is_p2sh(s: &Script) -> bool {
    let b = s.as_bytes();
    b.len() == 35
        && b.first() == Some(&Opcode::Hash256.to_byte())
        && b.get(1) == Some(&0x20)
        && b.get(34) == Some(&Opcode::Equal.to_byte())
}

/// Validate one input: run `script_sig`, then `script_pubkey`, then — for a
/// P2SH output — the redeem script.
///
/// # Errors
///
/// Every rule in CONTRACT §5 has its own [`ScriptError`] variant, so a test can
/// assert *why* a script was rejected rather than merely that it was.
pub fn verify(
    script_sig: &Script,
    script_pubkey: &Script,
    ctx: &ExecCtx<'_>,
) -> Result<ExecStats, ScriptError> {
    if script_sig.len() > ctx.limits.max_script_size {
        return Err(ScriptError::ScriptTooLarge {
            len: script_sig.len(),
            max: ctx.limits.max_script_size,
        });
    }
    if script_pubkey.len() > ctx.limits.max_script_size {
        return Err(ScriptError::ScriptTooLarge {
            len: script_pubkey.len(),
            max: ctx.limits.max_script_size,
        });
    }

    let sig_instructions = parse(script_sig)?;
    if !sig_instructions.iter().all(Instruction::is_push) {
        return Err(ScriptError::PushOnly);
    }

    let mut machine = Machine::new(ctx);
    machine.execute(&sig_instructions, script_sig.as_bytes())?;

    // Keep the post-`script_sig` stack: P2SH re-runs from here.
    let after_sig = machine.stack.clone();

    machine.run(script_pubkey)?;

    if is_p2sh(script_pubkey) {
        // The P2SH wrapper only commits to the redeem script's hash, so all it
        // has to leave is a true value on top; everything below it is the
        // redeem script's own arguments. The clean-stack rule applies once, to
        // whichever script ran last.
        require_top_true(&machine.stack)?;

        let (redeem_bytes, rest) = after_sig.split_last().ok_or(ScriptError::P2shEmptyScriptSig)?;
        let redeem = Script::new(redeem_bytes.clone());
        if redeem.len() > ctx.limits.max_script_size {
            return Err(ScriptError::ScriptTooLarge {
                len: redeem.len(),
                max: ctx.limits.max_script_size,
            });
        }
        machine.stack = rest.to_vec();
        // No recursion: a redeem script shaped like P2SH is just a script.
        machine.run(&redeem)?;
    }

    check_clean_stack(&machine.stack)?;
    Ok(machine.stats())
}

/// Run one script over `initial` and return the stack it leaves.
///
/// This is `chain-cli script eval` and the workhorse of the test suite. It
/// applies every limit and every minimality rule, but not the clean-stack rule,
/// because the caller may want to inspect an intermediate stack.
pub fn eval(
    script: &Script,
    initial: Vec<Vec<u8>>,
    ctx: &ExecCtx<'_>,
) -> Result<Stack, ScriptError> {
    if initial.len() > ctx.limits.max_stack_size {
        return Err(ScriptError::StackOverflow {
            size: initial.len(),
            max: ctx.limits.max_stack_size,
        });
    }
    if let Some(oversized) = initial.iter().find(|e| e.len() > ctx.limits.max_element_size) {
        return Err(ScriptError::ElementTooLarge {
            len: oversized.len(),
            max: ctx.limits.max_element_size,
        });
    }

    let mut machine = Machine::new(ctx);
    machine.stack = initial;
    machine.run(script)?;
    Ok(machine.stack)
}

/// The top of the stack must exist and be true. Used between the two halves of
/// a P2SH spend, where the stack still holds the redeem script's arguments.
fn require_top_true(stack: &[Vec<u8>]) -> Result<(), ScriptError> {
    match stack.last() {
        Some(top) if cast_to_bool(top) => Ok(()),
        Some(_) => Err(ScriptError::EvalFalse),
        None => Err(ScriptError::CleanStack { size: 0 }),
    }
}

/// The clean-stack rule: exactly one element, and it must be true.
fn check_clean_stack(stack: &[Vec<u8>]) -> Result<(), ScriptError> {
    match stack {
        [only] => {
            if cast_to_bool(only) {
                Ok(())
            } else {
                Err(ScriptError::EvalFalse)
            }
        }
        other => Err(ScriptError::CleanStack { size: other.len() }),
    }
}

/// The largest data payload a direct push can carry, re-exported so template
/// builders can size their buffers without importing the opcode module.
pub const MAX_DIRECT_PUSH: usize = OP_PUSHBYTES_MAX as usize;

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ferrum_types::{OutPoint, Script, TxIn, TxOut};

    fn tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::new(ferrum_types::Txid::ZERO, 0),
                script_sig: Script::EMPTY,
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOut::new(Amount::from_grains(1), Script::EMPTY)],
            lock_time: 0,
        }
    }

    #[test]
    fn p2sh_template_is_matched_on_raw_bytes() {
        let mut bytes = vec![0xaa, 0x20];
        bytes.extend(std::iter::repeat_n(0u8, 32));
        bytes.push(0x87);
        assert!(is_p2sh(&Script::new(bytes.clone())));

        bytes.pop();
        assert!(!is_p2sh(&Script::new(bytes)));
        assert!(!is_p2sh(&Script::EMPTY));
    }

    #[test]
    fn clean_stack_wants_exactly_one_true_element() {
        assert!(check_clean_stack(&[vec![1]]).is_ok());
        assert_eq!(check_clean_stack(&[]), Err(ScriptError::CleanStack { size: 0 }));
        assert_eq!(
            check_clean_stack(&[vec![1], vec![1]]),
            Err(ScriptError::CleanStack { size: 2 })
        );
        assert_eq!(check_clean_stack(&[Vec::new()]), Err(ScriptError::EvalFalse));
        assert_eq!(check_clean_stack(&[vec![0x80]]), Err(ScriptError::EvalFalse));
    }

    #[test]
    fn exec_ctx_default_constructor() {
        let t = tx();
        let ctx = ExecCtx::new(ChainId::DEVNET, &t, 0);
        assert_eq!(ctx.limits, ScriptLimits::CONSENSUS);
        assert_eq!(ctx.input_value, Amount::ZERO);
        assert_eq!(ctx.block_height, 0);
    }

    #[test]
    fn stats_start_at_zero_and_count_up() {
        let t = tx();
        let ctx = ExecCtx::new(ChainId::DEVNET, &t, 0);
        // OP_1 OP_1 OP_ADD
        let stats = verify(&Script::EMPTY, &Script::new(vec![0x51, 0x51, 0x93]), &ctx).unwrap();
        assert_eq!(stats.ops, 1);
        assert_eq!(stats.sig_checks, 0);
        assert_eq!(stats.max_stack, 2);
        assert_eq!(MAX_DIRECT_PUSH, 75);
    }
}
