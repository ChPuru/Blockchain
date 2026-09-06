//! The hard limits of the Ferrum script VM (CONTRACT §5.1).
//!
//! Every limit is present from the first commit rather than retrofitted. A
//! limit added later is a hard fork, and a VM without limits is a denial of
//! service waiting for someone to notice.
//!
//! [`ScriptLimits`] carries the same table as a value so that a test can
//! *tighten* a limit and exercise the rejection path without having to build a
//! thousand-byte script. Consensus always uses [`ScriptLimits::CONSENSUS`],
//! which is also [`Default`].

/// Maximum size in bytes of one script.
///
/// Applies independently to `script_sig`, `script_pubkey` and a P2SH redeem
/// script. 1 000 bytes is small enough that `OP_PUSHDATA4` has no reason to
/// exist, which is why the opcode table omits it.
pub const MAX_SCRIPT_SIZE: usize = 1_000;

/// Maximum number of elements on the data stack and altstack **combined**.
pub const MAX_STACK_SIZE: usize = 100;

/// Maximum size in bytes of a single stack element.
pub const MAX_ELEMENT_SIZE: usize = 520;

/// Maximum number of non-push opcodes executed across one input's scripts.
///
/// The count is *not* reset between `script_sig`, `script_pubkey` and the P2SH
/// redeem script, so an attacker cannot buy extra work by splitting a script.
pub const MAX_OPS: u32 = 201;

/// Maximum `n` in an `n`-of-`m` `OP_CHECKMULTISIG`.
pub const MAX_PUBKEYS_PER_MULTISIG: usize = 20;

/// Maximum length in bytes of a number *read* by an arithmetic opcode.
///
/// Four bytes keeps operands inside the `i32` range; results are held in an
/// `i64` and may serialise to five bytes, at which point they can no longer be
/// read back by an arithmetic opcode. That asymmetry is deliberate and is
/// exactly Bitcoin's `CScriptNum` contract.
pub const MAX_NUM_SIZE: usize = 4;

/// Maximum length in bytes of the operand to `OP_CHECKLOCKTIMEVERIFY` and
/// `OP_CHECKSEQUENCEVERIFY`.
///
/// Five, not [`MAX_NUM_SIZE`]: a `lock_time` is a `u32`, and any value at or
/// above `0x8000_0000` needs five bytes in sign-magnitude form. BIP-65 and
/// BIP-112 make the same widening for the same reason.
pub const MAX_LOCKTIME_NUM_SIZE: usize = 5;

/// The absolute ceiling on a number's byte length, whatever the caller asks
/// for. Sized so the decoder's fixed buffer can never be overrun.
pub(crate) const NUM_BUFFER_SIZE: usize = 8;

/// A signature inside a `script_sig` is exactly this long: a 64-byte BIP-340
/// Schnorr signature followed by one sighash-type byte. Any other length is an
/// error, never a "false" result.
pub const SIGNATURE_SIZE: usize = 65;

/// The BIP-340 signature itself, without the trailing sighash-type byte.
pub const SCHNORR_SIGNATURE_SIZE: usize = 64;

/// An x-only BIP-340 public key.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// A `hash160` public-key hash, as used by P2PKH and by HTLC preimages.
pub const PUBKEY_HASH_SIZE: usize = 20;

/// A `tagged_hash(TAG_SCRIPT, ·)` script hash, as used by P2SH.
pub const SCRIPT_HASH_SIZE: usize = 32;

/// Maximum payload of a standard `OP_RETURN` output.
pub const MAX_OP_RETURN_PAYLOAD: usize = 80;

/// BIP-68: set in a `TxIn::sequence` this disables relative locktime for that
/// input.
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// BIP-68: set, the relative locktime is a time in 512-second units; clear, it
/// is a block count.
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// BIP-68: the low 16 bits carry the relative locktime value.
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;

/// BIP-68: the time flavour counts in units of `1 << 9` = 512 seconds.
pub const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9;

/// A `sequence` encoding a relative locktime of `blocks` blocks.
pub const fn sequence_from_blocks(blocks: u16) -> u32 {
    blocks as u32
}

/// A `sequence` encoding a relative locktime of `seconds` seconds, rounded
/// down to the 512-second granularity BIP-68 uses.
pub const fn sequence_from_seconds(seconds: u32) -> u32 {
    SEQUENCE_LOCKTIME_TYPE_FLAG
        | (seconds.wrapping_shr(SEQUENCE_LOCKTIME_GRANULARITY) & SEQUENCE_LOCKTIME_MASK)
}

/// The limit table, as a value.
///
/// Consensus uses [`ScriptLimits::CONSENSUS`]. Tests tighten individual fields
/// so that each rejection path can be reached cheaply, and so that a test
/// asserting "too many ops" cannot accidentally pass because the script was
/// too long instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScriptLimits {
    /// See [`MAX_SCRIPT_SIZE`].
    pub max_script_size: usize,
    /// See [`MAX_STACK_SIZE`].
    pub max_stack_size: usize,
    /// See [`MAX_ELEMENT_SIZE`].
    pub max_element_size: usize,
    /// See [`MAX_OPS`].
    pub max_ops: u32,
    /// See [`MAX_PUBKEYS_PER_MULTISIG`].
    pub max_pubkeys_per_multisig: usize,
    /// See [`MAX_NUM_SIZE`].
    pub max_num_size: usize,
}

impl ScriptLimits {
    /// The consensus values from CONTRACT §5.1. Changing any of them is a hard
    /// fork.
    pub const CONSENSUS: ScriptLimits = ScriptLimits {
        max_script_size: MAX_SCRIPT_SIZE,
        max_stack_size: MAX_STACK_SIZE,
        max_element_size: MAX_ELEMENT_SIZE,
        max_ops: MAX_OPS,
        max_pubkeys_per_multisig: MAX_PUBKEYS_PER_MULTISIG,
        max_num_size: MAX_NUM_SIZE,
    };

    /// The number-length ceiling used by `OP_CHECKLOCKTIMEVERIFY` and
    /// `OP_CHECKSEQUENCEVERIFY`, which is one byte wider than
    /// [`ScriptLimits::max_num_size`] but never narrower than it.
    pub const fn max_locktime_num_size(&self) -> usize {
        if self.max_num_size > MAX_LOCKTIME_NUM_SIZE {
            self.max_num_size
        } else {
            MAX_LOCKTIME_NUM_SIZE
        }
    }
}

impl Default for ScriptLimits {
    fn default() -> Self {
        ScriptLimits::CONSENSUS
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;

    #[test]
    fn default_is_the_consensus_table() {
        assert_eq!(ScriptLimits::default(), ScriptLimits::CONSENSUS);
        assert_eq!(ScriptLimits::CONSENSUS.max_script_size, 1_000);
        assert_eq!(ScriptLimits::CONSENSUS.max_stack_size, 100);
        assert_eq!(ScriptLimits::CONSENSUS.max_element_size, 520);
        assert_eq!(ScriptLimits::CONSENSUS.max_ops, 201);
        assert_eq!(ScriptLimits::CONSENSUS.max_pubkeys_per_multisig, 20);
        assert_eq!(ScriptLimits::CONSENSUS.max_num_size, 4);
    }

    #[test]
    fn locktime_numbers_are_one_byte_wider() {
        assert_eq!(ScriptLimits::CONSENSUS.max_locktime_num_size(), 5);
        let wide = ScriptLimits { max_num_size: 7, ..ScriptLimits::CONSENSUS };
        assert_eq!(wide.max_locktime_num_size(), 7);
    }

    #[test]
    fn signature_is_schnorr_plus_one_type_byte() {
        assert_eq!(SIGNATURE_SIZE, SCHNORR_SIGNATURE_SIZE + 1);
    }

    #[test]
    fn bip68_sequence_helpers() {
        assert_eq!(sequence_from_blocks(10), 10);
        assert_eq!(sequence_from_seconds(512), SEQUENCE_LOCKTIME_TYPE_FLAG | 1);
        assert_eq!(sequence_from_seconds(1023), SEQUENCE_LOCKTIME_TYPE_FLAG | 1);
        assert_eq!(sequence_from_seconds(1024), SEQUENCE_LOCKTIME_TYPE_FLAG | 2);
        assert_eq!(SEQUENCE_LOCKTIME_DISABLE_FLAG, 0x8000_0000);
        assert_eq!(SEQUENCE_LOCKTIME_TYPE_FLAG, 0x0040_0000);
    }

    #[test]
    fn num_buffer_holds_the_widest_number() {
        const { assert!(NUM_BUFFER_SIZE >= MAX_LOCKTIME_NUM_SIZE) };
    }
}
