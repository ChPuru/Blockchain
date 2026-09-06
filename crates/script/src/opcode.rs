//! The opcode table (CONTRACT §5.2) and the instruction it decodes into.
//!
//! The table is **exhaustive**: every byte that is not listed is
//! [`ScriptError::InvalidOpcode`], including inside an untaken conditional
//! branch. Ferrum has no `OP_NOP1..10` soft-fork hooks, so there is no
//! "reserved but tolerated" class of opcode to reason about.
//!
//! `OP_PUSHDATA4` deliberately does not exist: [`MAX_SCRIPT_SIZE`] is 1 000
//! bytes, so a four-byte length prefix could only ever encode a script that is
//! already too large.
//!
//! [`MAX_SCRIPT_SIZE`]: crate::limits::MAX_SCRIPT_SIZE

use crate::error::ScriptError;

// ---------------------------------------------------------------------------
// Push opcodes. These are raw bytes rather than `Opcode` variants because
// 0x01..=0x4b is seventy-five near-identical direct pushes.
// ---------------------------------------------------------------------------

/// Push the empty byte string.
pub const OP_0: u8 = 0x00;
/// Smallest direct push: one byte of data.
pub const OP_PUSHBYTES_MIN: u8 = 0x01;
/// Largest direct push: 75 bytes of data.
pub const OP_PUSHBYTES_MAX: u8 = 0x4b;
/// Push with a one-byte length prefix.
pub const OP_PUSHDATA1: u8 = 0x4c;
/// Push with a two-byte little-endian length prefix.
pub const OP_PUSHDATA2: u8 = 0x4d;
/// Push the number `-1`.
pub const OP_1NEGATE: u8 = 0x4f;
/// Push the number `1`.
pub const OP_1: u8 = 0x51;
/// Push the number `16`.
pub const OP_16: u8 = 0x60;

/// The byte string `OP_1NEGATE` pushes: minimally-encoded `-1`.
pub const NEGATIVE_ONE: [u8; 1] = [0x81];

/// True when `b` is a push opcode — `OP_0`, a direct push, `OP_PUSHDATA1`,
/// `OP_PUSHDATA2`, `OP_1NEGATE` or `OP_1..=OP_16`.
///
/// This is exactly the set that may appear in a `script_sig`.
pub const fn is_push_opcode(b: u8) -> bool {
    matches!(b, OP_0..=OP_PUSHDATA2 | OP_1NEGATE | OP_1..=OP_16)
}

/// Every opcode that is not a push.
///
/// The discriminants are the wire bytes, so `op as u8` is the encoding and a
/// `#[repr(u8)]` cast is the decoding half of a bijection that
/// [`Opcode::from_byte`] completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Opcode {
    /// Do nothing. The only no-op in the table, and it is not a soft-fork hook.
    Nop = 0x61,
    /// Pop a condition and execute the following branch when it is true.
    If = 0x63,
    /// Pop a condition and execute the following branch when it is false.
    NotIf = 0x64,
    /// Switch to the other branch of the innermost conditional.
    Else = 0x67,
    /// Close the innermost conditional.
    EndIf = 0x68,
    /// Pop a value; fail unless it is true.
    Verify = 0x69,
    /// Fail unconditionally.
    Return = 0x6a,
    /// Move the top item to the altstack.
    ToAltStack = 0x6b,
    /// Move the top altstack item back to the stack.
    FromAltStack = 0x6c,
    /// Duplicate the top two items.
    TwoDup = 0x72,
    /// Duplicate the top item if it is true.
    IfDup = 0x73,
    /// Push the stack depth.
    Depth = 0x74,
    /// Pop and discard the top item.
    Drop = 0x75,
    /// Duplicate the top item.
    Dup = 0x76,
    /// Remove the second-from-top item.
    Nip = 0x77,
    /// Copy the second-from-top item to the top.
    Over = 0x78,
    /// Pop `n`, then copy the item `n` deep to the top.
    Pick = 0x79,
    /// Pop `n`, then move the item `n` deep to the top.
    Roll = 0x7a,
    /// Rotate the top three items: `x1 x2 x3` becomes `x2 x3 x1`.
    Rot = 0x7b,
    /// Swap the top two items.
    Swap = 0x7c,
    /// Copy the top item behind the second: `x1 x2` becomes `x2 x1 x2`.
    Tuck = 0x7d,
    /// Push the byte length of the top item, without popping it.
    Size = 0x82,
    /// Pop two items; push whether they are byte-identical.
    Equal = 0x87,
    /// [`Opcode::Equal`] followed by [`Opcode::Verify`].
    EqualVerify = 0x88,
    /// Add one.
    Add1 = 0x8b,
    /// Subtract one.
    Sub1 = 0x8c,
    /// Negate.
    Negate = 0x8f,
    /// Absolute value.
    Abs = 0x90,
    /// Push whether the operand is zero.
    Not = 0x91,
    /// Push whether the operand is non-zero.
    ZeroNotEqual = 0x92,
    /// Add two numbers.
    Add = 0x93,
    /// Subtract the top number from the one below it.
    Sub = 0x94,
    /// Logical and of two numbers.
    BoolAnd = 0x9a,
    /// Logical or of two numbers.
    BoolOr = 0x9b,
    /// Numeric equality.
    NumEqual = 0x9c,
    /// [`Opcode::NumEqual`] followed by [`Opcode::Verify`].
    NumEqualVerify = 0x9d,
    /// Numeric inequality.
    NumNotEqual = 0x9e,
    /// `a < b`.
    LessThan = 0x9f,
    /// `a > b`.
    GreaterThan = 0xa0,
    /// `a <= b`.
    LessThanOrEqual = 0xa1,
    /// `a >= b`.
    GreaterThanOrEqual = 0xa2,
    /// The smaller of two numbers.
    Min = 0xa3,
    /// The larger of two numbers.
    Max = 0xa4,
    /// `min <= x < max`.
    Within = 0xa5,
    /// RIPEMD-160 of the top item.
    Ripemd160 = 0xa6,
    /// SHA-256 of the top item.
    Sha256 = 0xa7,
    /// `ripemd160(sha256(x))` of the top item — 20 bytes.
    Hash160 = 0xa9,
    /// `tagged_hash(TAG_SCRIPT, x)` of the top item — 32 bytes. Note this is
    /// *not* Bitcoin's double SHA-256.
    Hash256 = 0xaa,
    /// Pop a pubkey and a signature; push whether the signature is valid.
    CheckSig = 0xac,
    /// [`Opcode::CheckSig`] followed by [`Opcode::Verify`].
    CheckSigVerify = 0xad,
    /// `k`-of-`n` signature check, popping exactly `n`, `n` pubkeys, `k` and
    /// `k` signatures — no dummy element.
    CheckMultiSig = 0xae,
    /// [`Opcode::CheckMultiSig`] followed by [`Opcode::Verify`].
    CheckMultiSigVerify = 0xaf,
    /// Absolute timelock against `tx.lock_time` (BIP-65 shape).
    CheckLockTimeVerify = 0xb1,
    /// Relative timelock against the input's `sequence` (BIP-68/112 shape).
    CheckSequenceVerify = 0xb2,
}

impl Opcode {
    /// Every opcode in the table, in ascending byte order.
    pub const ALL: [Opcode; 54] = [
        Opcode::Nop,
        Opcode::If,
        Opcode::NotIf,
        Opcode::Else,
        Opcode::EndIf,
        Opcode::Verify,
        Opcode::Return,
        Opcode::ToAltStack,
        Opcode::FromAltStack,
        Opcode::TwoDup,
        Opcode::IfDup,
        Opcode::Depth,
        Opcode::Drop,
        Opcode::Dup,
        Opcode::Nip,
        Opcode::Over,
        Opcode::Pick,
        Opcode::Roll,
        Opcode::Rot,
        Opcode::Swap,
        Opcode::Tuck,
        Opcode::Size,
        Opcode::Equal,
        Opcode::EqualVerify,
        Opcode::Add1,
        Opcode::Sub1,
        Opcode::Negate,
        Opcode::Abs,
        Opcode::Not,
        Opcode::ZeroNotEqual,
        Opcode::Add,
        Opcode::Sub,
        Opcode::BoolAnd,
        Opcode::BoolOr,
        Opcode::NumEqual,
        Opcode::NumEqualVerify,
        Opcode::NumNotEqual,
        Opcode::LessThan,
        Opcode::GreaterThan,
        Opcode::LessThanOrEqual,
        Opcode::GreaterThanOrEqual,
        Opcode::Min,
        Opcode::Max,
        Opcode::Within,
        Opcode::Ripemd160,
        Opcode::Sha256,
        Opcode::Hash160,
        Opcode::Hash256,
        Opcode::CheckSig,
        Opcode::CheckSigVerify,
        Opcode::CheckMultiSig,
        Opcode::CheckMultiSigVerify,
        Opcode::CheckLockTimeVerify,
        Opcode::CheckSequenceVerify,
    ];

    /// Decode a byte. `None` for every push opcode and for every byte outside
    /// the table.
    pub const fn from_byte(b: u8) -> Option<Opcode> {
        let op = match b {
            0x61 => Opcode::Nop,
            0x63 => Opcode::If,
            0x64 => Opcode::NotIf,
            0x67 => Opcode::Else,
            0x68 => Opcode::EndIf,
            0x69 => Opcode::Verify,
            0x6a => Opcode::Return,
            0x6b => Opcode::ToAltStack,
            0x6c => Opcode::FromAltStack,
            0x72 => Opcode::TwoDup,
            0x73 => Opcode::IfDup,
            0x74 => Opcode::Depth,
            0x75 => Opcode::Drop,
            0x76 => Opcode::Dup,
            0x77 => Opcode::Nip,
            0x78 => Opcode::Over,
            0x79 => Opcode::Pick,
            0x7a => Opcode::Roll,
            0x7b => Opcode::Rot,
            0x7c => Opcode::Swap,
            0x7d => Opcode::Tuck,
            0x82 => Opcode::Size,
            0x87 => Opcode::Equal,
            0x88 => Opcode::EqualVerify,
            0x8b => Opcode::Add1,
            0x8c => Opcode::Sub1,
            0x8f => Opcode::Negate,
            0x90 => Opcode::Abs,
            0x91 => Opcode::Not,
            0x92 => Opcode::ZeroNotEqual,
            0x93 => Opcode::Add,
            0x94 => Opcode::Sub,
            0x9a => Opcode::BoolAnd,
            0x9b => Opcode::BoolOr,
            0x9c => Opcode::NumEqual,
            0x9d => Opcode::NumEqualVerify,
            0x9e => Opcode::NumNotEqual,
            0x9f => Opcode::LessThan,
            0xa0 => Opcode::GreaterThan,
            0xa1 => Opcode::LessThanOrEqual,
            0xa2 => Opcode::GreaterThanOrEqual,
            0xa3 => Opcode::Min,
            0xa4 => Opcode::Max,
            0xa5 => Opcode::Within,
            0xa6 => Opcode::Ripemd160,
            0xa7 => Opcode::Sha256,
            0xa9 => Opcode::Hash160,
            0xaa => Opcode::Hash256,
            0xac => Opcode::CheckSig,
            0xad => Opcode::CheckSigVerify,
            0xae => Opcode::CheckMultiSig,
            0xaf => Opcode::CheckMultiSigVerify,
            0xb1 => Opcode::CheckLockTimeVerify,
            0xb2 => Opcode::CheckSequenceVerify,
            _ => return None,
        };
        Some(op)
    }

    /// The wire byte.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// The mnemonic, as the CLI disassembler prints it.
    pub const fn name(self) -> &'static str {
        match self {
            Opcode::Nop => "OP_NOP",
            Opcode::If => "OP_IF",
            Opcode::NotIf => "OP_NOTIF",
            Opcode::Else => "OP_ELSE",
            Opcode::EndIf => "OP_ENDIF",
            Opcode::Verify => "OP_VERIFY",
            Opcode::Return => "OP_RETURN",
            Opcode::ToAltStack => "OP_TOALTSTACK",
            Opcode::FromAltStack => "OP_FROMALTSTACK",
            Opcode::TwoDup => "OP_2DUP",
            Opcode::IfDup => "OP_IFDUP",
            Opcode::Depth => "OP_DEPTH",
            Opcode::Drop => "OP_DROP",
            Opcode::Dup => "OP_DUP",
            Opcode::Nip => "OP_NIP",
            Opcode::Over => "OP_OVER",
            Opcode::Pick => "OP_PICK",
            Opcode::Roll => "OP_ROLL",
            Opcode::Rot => "OP_ROT",
            Opcode::Swap => "OP_SWAP",
            Opcode::Tuck => "OP_TUCK",
            Opcode::Size => "OP_SIZE",
            Opcode::Equal => "OP_EQUAL",
            Opcode::EqualVerify => "OP_EQUALVERIFY",
            Opcode::Add1 => "OP_1ADD",
            Opcode::Sub1 => "OP_1SUB",
            Opcode::Negate => "OP_NEGATE",
            Opcode::Abs => "OP_ABS",
            Opcode::Not => "OP_NOT",
            Opcode::ZeroNotEqual => "OP_0NOTEQUAL",
            Opcode::Add => "OP_ADD",
            Opcode::Sub => "OP_SUB",
            Opcode::BoolAnd => "OP_BOOLAND",
            Opcode::BoolOr => "OP_BOOLOR",
            Opcode::NumEqual => "OP_NUMEQUAL",
            Opcode::NumEqualVerify => "OP_NUMEQUALVERIFY",
            Opcode::NumNotEqual => "OP_NUMNOTEQUAL",
            Opcode::LessThan => "OP_LESSTHAN",
            Opcode::GreaterThan => "OP_GREATERTHAN",
            Opcode::LessThanOrEqual => "OP_LESSTHANOREQUAL",
            Opcode::GreaterThanOrEqual => "OP_GREATERTHANOREQUAL",
            Opcode::Min => "OP_MIN",
            Opcode::Max => "OP_MAX",
            Opcode::Within => "OP_WITHIN",
            Opcode::Ripemd160 => "OP_RIPEMD160",
            Opcode::Sha256 => "OP_SHA256",
            Opcode::Hash160 => "OP_HASH160",
            Opcode::Hash256 => "OP_HASH256",
            Opcode::CheckSig => "OP_CHECKSIG",
            Opcode::CheckSigVerify => "OP_CHECKSIGVERIFY",
            Opcode::CheckMultiSig => "OP_CHECKMULTISIG",
            Opcode::CheckMultiSigVerify => "OP_CHECKMULTISIGVERIFY",
            Opcode::CheckLockTimeVerify => "OP_CHECKLOCKTIMEVERIFY",
            Opcode::CheckSequenceVerify => "OP_CHECKSEQUENCEVERIFY",
        }
    }

    /// True for `OP_IF`, `OP_NOTIF`, `OP_ELSE` and `OP_ENDIF`.
    ///
    /// These four are the only opcodes that run inside an untaken branch: the
    /// interpreter must keep tracking nesting there or it cannot find the
    /// matching `OP_ENDIF`.
    pub const fn is_conditional(self) -> bool {
        matches!(self, Opcode::If | Opcode::NotIf | Opcode::Else | Opcode::EndIf)
    }
}

impl std::fmt::Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// One decoded script instruction.
///
/// A push carries both the opcode byte that produced it and the bytes it
/// pushes, so `parse` is lossless: re-encoding the instruction list reproduces
/// the original script byte for byte.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Instruction {
    /// A push of `data` onto the stack. `opcode` is one of `OP_0`, a direct
    /// push, `OP_PUSHDATA1`, `OP_PUSHDATA2`, `OP_1NEGATE` or `OP_1..=OP_16`.
    Push {
        /// The opcode byte that encoded this push.
        opcode: u8,
        /// The bytes pushed onto the stack.
        data: Vec<u8>,
    },
    /// Any non-push opcode.
    Op(Opcode),
}

impl Instruction {
    /// A push using the minimal encoding for `data`.
    pub fn push(data: &[u8]) -> Result<Instruction, ScriptError> {
        let opcode = minimal_push_opcode(data).ok_or(ScriptError::PushTooLarge(data.len()))?;
        Ok(Instruction::Push { opcode, data: data.to_vec() })
    }

    /// True for [`Instruction::Push`]. `script_sig` may contain nothing else.
    pub const fn is_push(&self) -> bool {
        matches!(self, Instruction::Push { .. })
    }

    /// The leading opcode byte.
    pub const fn opcode_byte(&self) -> u8 {
        match self {
            Instruction::Push { opcode, .. } => *opcode,
            Instruction::Op(op) => op.to_byte(),
        }
    }

    /// The pushed bytes, or `None` for a non-push instruction.
    pub fn push_data(&self) -> Option<&[u8]> {
        match self {
            Instruction::Push { data, .. } => Some(data),
            Instruction::Op(_) => None,
        }
    }

    /// Append the wire encoding of this instruction to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Instruction::Push { opcode, data } => {
                out.push(*opcode);
                match *opcode {
                    OP_PUSHDATA1 => {
                        // Length fits in one byte or `minimal_push_opcode`
                        // would not have chosen this form.
                        out.push(u8::try_from(data.len()).unwrap_or(u8::MAX));
                        out.extend_from_slice(data);
                    }
                    OP_PUSHDATA2 => {
                        let n = u16::try_from(data.len()).unwrap_or(u16::MAX);
                        out.extend_from_slice(&n.to_le_bytes());
                        out.extend_from_slice(data);
                    }
                    OP_PUSHBYTES_MIN..=OP_PUSHBYTES_MAX => out.extend_from_slice(data),
                    // OP_0, OP_1NEGATE and OP_1..=OP_16 carry no payload.
                    _ => {}
                }
            }
            Instruction::Op(op) => out.push(op.to_byte()),
        }
    }
}

/// The opcode that minimally encodes a push of `data`.
///
/// `None` when `data` is longer than `OP_PUSHDATA2` can express. Minimality is
/// a consensus rule: a value has exactly one spelling, so a witness cannot be
/// mutated without changing the txid.
pub const fn minimal_push_opcode(data: &[u8]) -> Option<u8> {
    match data.len() {
        0 => Some(OP_0),
        1 => {
            // A single byte is `OP_1NEGATE` for 0x81, `OP_1..=OP_16` for 1..=16
            // and a direct push otherwise.
            let b = data[0];
            if b == NEGATIVE_ONE[0] {
                Some(OP_1NEGATE)
            } else if matches!(b, 1..=16) {
                Some(OP_1.wrapping_add(b).wrapping_sub(1))
            } else {
                Some(OP_PUSHBYTES_MIN)
            }
        }
        n if n <= OP_PUSHBYTES_MAX as usize => Some(n as u8),
        n if n <= u8::MAX as usize => Some(OP_PUSHDATA1),
        n if n <= u16::MAX as usize => Some(OP_PUSHDATA2),
        _ => None,
    }
}

/// The wire bytes of a minimal push of `data`.
pub fn encode_push(data: &[u8]) -> Result<Vec<u8>, ScriptError> {
    let mut out = Vec::with_capacity(data.len().saturating_add(3));
    Instruction::push(data)?.encode_into(&mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn every_defined_byte_decodes_to_itself() {
        for op in Opcode::ALL {
            assert_eq!(Opcode::from_byte(op.to_byte()), Some(op), "{op}");
        }
    }

    #[test]
    fn the_table_is_exhaustive_and_the_rest_is_invalid() {
        let defined: Vec<u8> =
            (0u8..=255).filter(|b| Opcode::from_byte(*b).is_some() || is_push_opcode(*b)).collect();
        // 0x00..=0x4d (78) plus OP_1NEGATE (1) plus OP_1..=OP_16 (16).
        let pushes = (0u8..=255).filter(|b| is_push_opcode(*b)).count();
        assert_eq!(pushes, 95);
        // Plus the 54 distinct non-push opcodes: 149 of 256 bytes are defined.
        assert_eq!(defined.len(), 149);
    }

    #[test]
    fn undefined_bytes_are_undefined() {
        for b in [0x4e, 0x50, 0x62, 0x65, 0x66, 0x6d, 0x7e, 0x83, 0x89, 0xa8, 0xab, 0xb0, 0xff] {
            assert!(Opcode::from_byte(b).is_none(), "0x{b:02x}");
            assert!(!is_push_opcode(b), "0x{b:02x}");
        }
    }

    #[test]
    fn names_are_unique() {
        let mut names: Vec<&str> = Opcode::ALL.iter().map(|o| o.name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
        assert_eq!(before, 54);
    }

    #[test]
    fn conditionals_are_the_four_branch_opcodes() {
        let c: Vec<Opcode> = Opcode::ALL.iter().copied().filter(|o| o.is_conditional()).collect();
        assert_eq!(c, vec![Opcode::If, Opcode::NotIf, Opcode::Else, Opcode::EndIf]);
    }

    #[test]
    fn minimal_push_opcode_picks_the_shortest_form() {
        assert_eq!(minimal_push_opcode(&[]), Some(OP_0));
        assert_eq!(minimal_push_opcode(&[0x01]), Some(OP_1));
        assert_eq!(minimal_push_opcode(&[0x10]), Some(OP_16));
        assert_eq!(minimal_push_opcode(&[0x81]), Some(OP_1NEGATE));
        assert_eq!(minimal_push_opcode(&[0x00]), Some(OP_PUSHBYTES_MIN));
        assert_eq!(minimal_push_opcode(&[0x11]), Some(OP_PUSHBYTES_MIN));
        assert_eq!(minimal_push_opcode(&[0u8; 75]), Some(0x4b));
        assert_eq!(minimal_push_opcode(&[0u8; 76]), Some(OP_PUSHDATA1));
        assert_eq!(minimal_push_opcode(&[0u8; 255]), Some(OP_PUSHDATA1));
        assert_eq!(minimal_push_opcode(&[0u8; 256]), Some(OP_PUSHDATA2));
        assert_eq!(minimal_push_opcode(&vec![0u8; 65_536]), None);
    }

    #[test]
    fn encode_push_round_trips_each_form() {
        assert_eq!(encode_push(&[]).unwrap(), vec![OP_0]);
        assert_eq!(encode_push(&[0x05]).unwrap(), vec![0x55]);
        assert_eq!(encode_push(&[0x81]).unwrap(), vec![OP_1NEGATE]);
        assert_eq!(encode_push(&[0xaa]).unwrap(), vec![0x01, 0xaa]);
        assert_eq!(encode_push(&[0xaa, 0xbb]).unwrap(), vec![0x02, 0xaa, 0xbb]);

        let long = vec![7u8; 100];
        let enc = encode_push(&long).unwrap();
        assert_eq!(&enc[..2], &[OP_PUSHDATA1, 100]);

        let longer = vec![7u8; 300];
        let enc = encode_push(&longer).unwrap();
        assert_eq!(&enc[..3], &[OP_PUSHDATA2, 0x2c, 0x01]);
    }

    #[test]
    fn encode_push_rejects_what_pushdata2_cannot_express() {
        assert_eq!(encode_push(&vec![0u8; 70_000]), Err(ScriptError::PushTooLarge(70_000)));
    }

    #[test]
    fn instruction_helpers() {
        let p = Instruction::push(&[1, 2, 3]).unwrap();
        assert!(p.is_push());
        assert_eq!(p.opcode_byte(), 0x03);
        assert_eq!(p.push_data(), Some(&[1u8, 2, 3][..]));

        let o = Instruction::Op(Opcode::Dup);
        assert!(!o.is_push());
        assert_eq!(o.opcode_byte(), 0x76);
        assert_eq!(o.push_data(), None);
        assert_eq!(Opcode::Dup.to_string(), "OP_DUP");
    }

    #[test]
    fn encode_into_is_the_inverse_of_the_push_form() {
        for data in [vec![], vec![0x01], vec![0x81], vec![0xff], vec![9u8; 200], vec![9u8; 600]] {
            let instr = Instruction::push(&data).unwrap();
            let mut out = Vec::new();
            instr.encode_into(&mut out);
            assert_eq!(out, encode_push(&data).unwrap());
        }
    }
}
