//! Script decoding, push-only classification and disassembly.
//!
//! [`parse`] is the **strict** decoder the interpreter runs on. It enforces
//! three things, all of them consensus rules:
//!
//! 1. every opcode byte is in the table — there are no soft-fork hooks, so an
//!    undefined byte fails the script even inside an untaken branch;
//! 2. no push runs off the end of the script;
//! 3. every push uses the shortest form that can express its data.
//!
//! Minimality is checked here rather than at execution time, which makes it
//! apply inside untaken conditional branches too. That is stricter than
//! Bitcoin, where `MINIMALDATA` is only checked on the executed path, and it is
//! the same choice CONTRACT §5.2 already makes for undefined opcodes: a script
//! is either canonical everywhere or it is not a script.
//!
//! [`disassemble`] is the **tolerant** counterpart used by
//! `chain-cli script disassemble`. It never fails, because a debugging tool
//! that refuses to show you the bytes that broke is useless.

use ferrum_types::Script;

use crate::error::ScriptError;
use crate::opcode::{
    Instruction, OP_0, OP_1, OP_1NEGATE, OP_16, OP_PUSHBYTES_MAX, OP_PUSHBYTES_MIN, OP_PUSHDATA1,
    OP_PUSHDATA2, Opcode, minimal_push_opcode,
};

/// Fully disassemble a script into its instructions.
///
/// Errors: [`ScriptError::InvalidOpcode`], [`ScriptError::TruncatedPush`],
/// [`ScriptError::NonMinimalPush`].
pub fn parse(s: &Script) -> Result<Vec<Instruction>, ScriptError> {
    parse_bytes(s.as_bytes())
}

/// [`parse`], over raw bytes.
pub fn parse_bytes(bytes: &[u8]) -> Result<Vec<Instruction>, ScriptError> {
    // Instructions are at least one byte each, so this never over-reserves by
    // more than the script length.
    let mut out = Vec::new();
    let mut pc: usize = 0;

    while let Some(&opcode) = bytes.get(pc) {
        pc = pc.checked_add(1).ok_or(ScriptError::NumericOverflow)?;
        match opcode {
            OP_PUSHBYTES_MIN..=OP_PUSHBYTES_MAX => {
                let n = usize::from(opcode);
                let data = take(bytes, &mut pc, n, opcode)?;
                push_instruction(&mut out, opcode, data)?;
            }
            OP_PUSHDATA1 => {
                let len_bytes = take(bytes, &mut pc, 1, opcode)?;
                let n = usize::from(len_bytes.first().copied().unwrap_or(0));
                let data = take(bytes, &mut pc, n, opcode)?;
                push_instruction(&mut out, opcode, data)?;
            }
            OP_PUSHDATA2 => {
                let len_bytes = take(bytes, &mut pc, 2, opcode)?;
                let lo = len_bytes.first().copied().unwrap_or(0);
                let hi = len_bytes.get(1).copied().unwrap_or(0);
                let n = usize::from(u16::from_le_bytes([lo, hi]));
                let data = take(bytes, &mut pc, n, opcode)?;
                push_instruction(&mut out, opcode, data)?;
            }
            OP_0 => push_instruction(&mut out, opcode, &[])?,
            OP_1NEGATE => push_instruction(&mut out, opcode, &crate::opcode::NEGATIVE_ONE)?,
            OP_1..=OP_16 => {
                // OP_1 encodes 1, so the value is the opcode minus OP_1 plus 1.
                let v = opcode.wrapping_sub(OP_1).wrapping_add(1);
                push_instruction(&mut out, opcode, &[v])?;
            }
            other => {
                let op = Opcode::from_byte(other).ok_or(ScriptError::InvalidOpcode(other))?;
                out.push(Instruction::Op(op));
            }
        }
    }

    Ok(out)
}

/// Read `n` bytes at `pc`, advancing it.
fn take<'a>(
    bytes: &'a [u8],
    pc: &mut usize,
    n: usize,
    opcode: u8,
) -> Result<&'a [u8], ScriptError> {
    let end = pc.checked_add(n).ok_or(ScriptError::NumericOverflow)?;
    let slice = bytes.get(*pc..end).ok_or(ScriptError::TruncatedPush {
        opcode,
        needed: n,
        found: bytes.len().saturating_sub(*pc),
    })?;
    *pc = end;
    Ok(slice)
}

/// Record a push, rejecting any encoding that is not the shortest one.
fn push_instruction(
    out: &mut Vec<Instruction>,
    opcode: u8,
    data: &[u8],
) -> Result<(), ScriptError> {
    let minimal = minimal_push_opcode(data).ok_or(ScriptError::PushTooLarge(data.len()))?;
    if minimal != opcode {
        return Err(ScriptError::NonMinimalPush { opcode, len: data.len() });
    }
    out.push(Instruction::Push { opcode, data: data.to_vec() });
    Ok(())
}

/// Re-encode an instruction list into script bytes.
///
/// `encode(parse(s)) == s` for every script `parse` accepts, which is what
/// makes the parse lossless and the minimality rule meaningful.
pub fn encode(instructions: &[Instruction]) -> Script {
    let mut out = Vec::new();
    for instruction in instructions {
        instruction.encode_into(&mut out);
    }
    Script::new(out)
}

/// True when every instruction in `s` is a push.
///
/// A `script_sig` that is not push-only is rejected by [`crate::verify`] — in
/// Ferrum that is a **consensus** rule, not a policy rule. A script that does
/// not parse is not push-only either.
pub fn is_push_only(s: &Script) -> bool {
    match parse(s) {
        Ok(instructions) => instructions.iter().all(Instruction::is_push),
        Err(_) => false,
    }
}

/// Human-readable disassembly for the CLI.
///
/// Never fails. A byte that cannot be decoded is rendered as
/// `[error: <reason>]` and the remaining bytes as `[<hex>]`, so the operator
/// can see exactly where a script went wrong.
pub fn disassemble(s: &Script) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut pc: usize = 0;

    while let Some(&opcode) = bytes.get(pc) {
        let start = pc;
        pc = pc.saturating_add(1);
        let rendered = match opcode {
            OP_0 => Ok("OP_0".to_owned()),
            OP_1NEGATE => Ok("OP_1NEGATE".to_owned()),
            OP_1..=OP_16 => Ok(format!("OP_{}", opcode.wrapping_sub(OP_1).wrapping_add(1))),
            OP_PUSHBYTES_MIN..=OP_PUSHBYTES_MAX => {
                render_push(bytes, &mut pc, usize::from(opcode), opcode, "OP_PUSHBYTES")
            }
            OP_PUSHDATA1 => match take_len(bytes, &mut pc, 1) {
                Some(n) => render_push(bytes, &mut pc, n, opcode, "OP_PUSHDATA1"),
                None => Err("truncated OP_PUSHDATA1 length".to_owned()),
            },
            OP_PUSHDATA2 => match take_len(bytes, &mut pc, 2) {
                Some(n) => render_push(bytes, &mut pc, n, opcode, "OP_PUSHDATA2"),
                None => Err("truncated OP_PUSHDATA2 length".to_owned()),
            },
            other => match Opcode::from_byte(other) {
                Some(op) => Ok(op.name().to_owned()),
                None => Err(format!("undefined opcode 0x{other:02x}")),
            },
        };
        match rendered {
            Ok(text) => out.push(text),
            Err(reason) => {
                out.push(format!("[error: {reason}]"));
                let tail = bytes.get(start..).unwrap_or(&[]);
                out.push(format!("[{}]", hex::encode(tail)));
                break;
            }
        }
    }

    out.join(" ")
}

/// Read a little-endian length of `width` bytes for the tolerant disassembler.
fn take_len(bytes: &[u8], pc: &mut usize, width: usize) -> Option<usize> {
    let end = pc.checked_add(width)?;
    let slice = bytes.get(*pc..end)?;
    let mut n: usize = 0;
    for (i, &b) in slice.iter().enumerate() {
        let shift = u32::try_from(i).ok()?.checked_mul(8)?;
        n = n.checked_add(usize::from(b).checked_shl(shift)?)?;
    }
    *pc = end;
    Some(n)
}

/// Render one push for the tolerant disassembler.
fn render_push(
    bytes: &[u8],
    pc: &mut usize,
    n: usize,
    opcode: u8,
    label: &str,
) -> Result<String, String> {
    let end = pc.checked_add(n).ok_or_else(|| "push length overflows".to_owned())?;
    let data = bytes.get(*pc..end).ok_or_else(|| {
        format!("truncated push: {n} bytes declared, {} available", bytes.len().saturating_sub(*pc))
    })?;
    *pc = end;
    let minimal = minimal_push_opcode(data).is_some_and(|m| m == opcode);
    let suffix = if minimal { "" } else { " (non-minimal)" };
    Ok(format!("{label}_{n} 0x{}{suffix}", hex::encode(data)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use proptest::prelude::*;

    fn script(bytes: &[u8]) -> Script {
        Script::new(bytes.to_vec())
    }

    #[test]
    fn parses_each_push_form() {
        let s = script(&[0x00, 0x51, 0x60, 0x4f, 0x01, 0xaa]);
        let instructions = parse(&s).unwrap();
        assert_eq!(instructions.len(), 5);
        assert_eq!(instructions[0].push_data(), Some(&[][..]));
        assert_eq!(instructions[1].push_data(), Some(&[1u8][..]));
        assert_eq!(instructions[2].push_data(), Some(&[16u8][..]));
        assert_eq!(instructions[3].push_data(), Some(&[0x81u8][..]));
        assert_eq!(instructions[4].push_data(), Some(&[0xaau8][..]));
    }

    #[test]
    fn parses_pushdata1_and_pushdata2() {
        let mut bytes = vec![OP_PUSHDATA1, 100];
        bytes.extend(std::iter::repeat_n(0x77u8, 100));
        assert_eq!(parse(&script(&bytes)).unwrap().len(), 1);

        let mut bytes = vec![OP_PUSHDATA2, 0x2c, 0x01];
        bytes.extend(std::iter::repeat_n(0x77u8, 300));
        let parsed = parse(&script(&bytes)).unwrap();
        assert_eq!(parsed[0].push_data().unwrap().len(), 300);
    }

    #[test]
    fn undefined_opcodes_are_rejected() {
        for b in [0x4e, 0x50, 0x62, 0x65, 0x66, 0x6d, 0x7e, 0xa8, 0xab, 0xb0, 0xb3, 0xff] {
            assert_eq!(parse(&script(&[b])), Err(ScriptError::InvalidOpcode(b)), "0x{b:02x}");
        }
    }

    #[test]
    fn truncated_pushes_are_rejected() {
        assert_eq!(
            parse(&script(&[0x05, 0x01, 0x02])),
            Err(ScriptError::TruncatedPush { opcode: 0x05, needed: 5, found: 2 })
        );
        assert_eq!(
            parse(&script(&[OP_PUSHDATA1])),
            Err(ScriptError::TruncatedPush { opcode: OP_PUSHDATA1, needed: 1, found: 0 })
        );
        assert_eq!(
            parse(&script(&[OP_PUSHDATA2, 0x01])),
            Err(ScriptError::TruncatedPush { opcode: OP_PUSHDATA2, needed: 2, found: 1 })
        );
    }

    #[test]
    fn non_minimal_pushes_are_rejected() {
        // Direct push of one byte that OP_1 could have encoded.
        assert_eq!(
            parse(&script(&[0x01, 0x01])),
            Err(ScriptError::NonMinimalPush { opcode: 0x01, len: 1 })
        );
        // OP_PUSHDATA1 for data a direct push covers.
        assert_eq!(
            parse(&script(&[OP_PUSHDATA1, 0x02, 0xaa, 0xbb])),
            Err(ScriptError::NonMinimalPush { opcode: OP_PUSHDATA1, len: 2 })
        );
        // OP_PUSHDATA2 for data OP_PUSHDATA1 covers.
        let mut bytes = vec![OP_PUSHDATA2, 100, 0];
        bytes.extend(std::iter::repeat_n(0u8, 100));
        assert_eq!(
            parse(&script(&bytes)),
            Err(ScriptError::NonMinimalPush { opcode: OP_PUSHDATA2, len: 100 })
        );
        // A zero-length OP_PUSHDATA1 where OP_0 would do.
        assert_eq!(
            parse(&script(&[OP_PUSHDATA1, 0x00])),
            Err(ScriptError::NonMinimalPush { opcode: OP_PUSHDATA1, len: 0 })
        );
    }

    #[test]
    fn minimality_applies_inside_an_untaken_branch_too() {
        // OP_0 OP_IF <non-minimal push> OP_ENDIF OP_1
        let s = script(&[0x00, 0x63, 0x01, 0x05, 0x68, 0x51]);
        assert_eq!(parse(&s), Err(ScriptError::NonMinimalPush { opcode: 0x01, len: 1 }));
    }

    #[test]
    fn push_only_classification() {
        assert!(is_push_only(&script(&[0x00, 0x51, 0x02, 0xaa, 0xbb])));
        assert!(is_push_only(&Script::EMPTY));
        assert!(!is_push_only(&script(&[0x51, 0x76])));
        // Does not parse, so not push-only.
        assert!(!is_push_only(&script(&[0x05, 0x01])));
    }

    #[test]
    fn encode_is_the_inverse_of_parse() {
        let s = script(&[0x00, 0x51, 0x76, 0xa9, 0x02, 0xaa, 0xbb, 0x88, 0xac]);
        assert_eq!(encode(&parse(&s).unwrap()), s);
    }

    #[test]
    fn disassembly_is_readable() {
        let s = script(&[0x76, 0xa9, 0x02, 0xaa, 0xbb, 0x88, 0xac]);
        assert_eq!(
            disassemble(&s),
            "OP_DUP OP_HASH160 OP_PUSHBYTES_2 0xaabb OP_EQUALVERIFY OP_CHECKSIG"
        );
        assert_eq!(disassemble(&script(&[0x00, 0x4f, 0x51, 0x60])), "OP_0 OP_1NEGATE OP_1 OP_16");
        assert_eq!(disassemble(&Script::EMPTY), "");
    }

    #[test]
    fn disassembly_never_fails_on_garbage() {
        let s = script(&[0x76, 0xff, 0xaa]);
        let text = disassemble(&s);
        assert!(text.starts_with("OP_DUP [error: undefined opcode 0xff]"), "{text}");
        let s = script(&[0x05, 0x01]);
        assert!(disassemble(&s).contains("truncated push"));
        let s = script(&[0x01, 0x01]);
        assert!(disassemble(&s).contains("non-minimal"));
    }

    proptest! {
        #[test]
        fn parsing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let s = Script::new(bytes);
            let _ = parse(&s);
            let _ = is_push_only(&s);
            let _ = disassemble(&s);
        }

        #[test]
        fn accepted_scripts_re_encode_identically(
            bytes in proptest::collection::vec(any::<u8>(), 0..300)
        ) {
            let s = Script::new(bytes);
            if let Ok(instructions) = parse(&s) {
                prop_assert_eq!(encode(&instructions), s);
            }
        }
    }
}
