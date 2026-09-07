//! The standard script templates (CONTRACT §5.6).
//!
//! Everything a Ferrum wallet produces is one of these seven shapes. Keeping
//! the set small is a policy decision with a consensus flavour: the explorer,
//! the mempool and the wallet all need to agree on what a script *means*, and
//! [`classify`] is the single place that decides.
//!
//! ```text
//! P2PK      <32B pk> OP_CHECKSIG
//! P2PKH     OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG
//! P2SH      OP_HASH256 <32B> OP_EQUAL
//! Multisig  <k> <pk1> … <pkn> <n> OP_CHECKMULTISIG
//! Cltv      <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP  <P2PKH…>
//! Htlc      OP_IF <hash branch> OP_ELSE <timeout branch> OP_ENDIF
//! OpReturn  OP_RETURN <=80B>
//! ```
//!
//! Every push a template emits is minimal, because [`mod@crate::parse`] rejects any
//! other encoding.

use ferrum_crypto::{PublicKey, hash256};
use ferrum_types::{Hash32, Script};
use serde::{Deserialize, Serialize};

use crate::error::ScriptError;
use crate::limits::{
    MAX_LOCKTIME_NUM_SIZE, MAX_NUM_SIZE, MAX_OP_RETURN_PAYLOAD, MAX_PUBKEYS_PER_MULTISIG,
    PUBKEY_HASH_SIZE,
};
use crate::num::ScriptNum;
use crate::opcode::{Instruction, Opcode};
use crate::parse::parse;

/// What a `script_pubkey` is, as the explorer and the wallet label it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptType {
    /// Pay to a bare public key.
    P2PK,
    /// Pay to a public-key hash.
    P2PKH,
    /// Pay to a script hash.
    P2SH,
    /// `k`-of-`n` bare multisig.
    Multisig {
        /// Signatures required.
        k: u8,
        /// Public keys offered.
        n: u8,
    },
    /// A P2PKH behind an absolute timelock.
    Cltv,
    /// A hash-timelocked contract: preimage branch or refund branch.
    Htlc,
    /// A provably-unspendable data carrier.
    OpReturn,
    /// Anything else. Valid to spend if it evaluates, but not relayed by
    /// default policy.
    NonStandard,
}

/// Append a minimal push of `data`.
///
/// Every call site here pushes a fixed 20- or 32-byte value or a small number,
/// all of which a direct push covers, so the "too large for `OP_PUSHDATA2`"
/// case that [`Instruction::push`] rejects cannot arise. If it somehow did,
/// nothing is appended — which yields an obviously broken script rather than a
/// panic.
fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    if let Ok(instruction) = Instruction::push(data) {
        instruction.encode_into(out);
    }
}

/// Append a minimally-encoded number.
fn push_num(out: &mut Vec<u8>, value: i64) {
    push_data(out, &ScriptNum::new(value).to_vec());
}

/// Append the P2PKH tail: `OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`.
fn push_p2pkh_tail(out: &mut Vec<u8>, pkh: &[u8; PUBKEY_HASH_SIZE]) {
    out.push(Opcode::Dup.to_byte());
    out.push(Opcode::Hash160.to_byte());
    push_data(out, pkh);
    out.push(Opcode::EqualVerify.to_byte());
    out.push(Opcode::CheckSig.to_byte());
}

/// `<32B pk> OP_CHECKSIG`.
pub fn p2pk(pk: &PublicKey) -> Script {
    let mut out = Vec::with_capacity(34);
    push_data(&mut out, pk.as_bytes());
    out.push(Opcode::CheckSig.to_byte());
    Script::new(out)
}

/// `OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2pkh(pkh: &[u8; PUBKEY_HASH_SIZE]) -> Script {
    let mut out = Vec::with_capacity(25);
    push_p2pkh_tail(&mut out, pkh);
    Script::new(out)
}

/// `OP_HASH256 <32B> OP_EQUAL`.
///
/// The hash is `tagged_hash(TAG_SCRIPT, redeem_script)`, which is what
/// [`ferrum_crypto::Address::p2sh`] commits to.
pub fn p2sh(script_hash: &Hash32) -> Script {
    let mut out = Vec::with_capacity(35);
    out.push(Opcode::Hash256.to_byte());
    push_data(&mut out, script_hash.as_bytes());
    out.push(Opcode::Equal.to_byte());
    Script::new(out)
}

/// The P2SH `script_pubkey` that locks to `redeem`.
pub fn p2sh_of(redeem: &Script) -> Script {
    p2sh(&hash256(redeem.as_bytes()))
}

/// `<k> <pk1> … <pkn> <n> OP_CHECKMULTISIG`.
///
/// # Errors
///
/// [`ScriptError::MultisigKeyCount`] for zero keys or more than
/// [`MAX_PUBKEYS_PER_MULTISIG`]; [`ScriptError::MultisigThreshold`] for a `k`
/// outside `1..=n`.
pub fn multisig(k: u8, pks: &[PublicKey]) -> Result<Script, ScriptError> {
    let n = pks.len();
    if n == 0 || n > MAX_PUBKEYS_PER_MULTISIG {
        return Err(ScriptError::MultisigKeyCount { n, max: MAX_PUBKEYS_PER_MULTISIG });
    }
    if k == 0 || usize::from(k) > n {
        return Err(ScriptError::MultisigThreshold { k, n });
    }

    let mut out = Vec::with_capacity(n.saturating_mul(34).saturating_add(4));
    push_num(&mut out, i64::from(k));
    for pk in pks {
        push_data(&mut out, pk.as_bytes());
    }
    // `n` can be 17..=20, which `OP_1..OP_16` cannot express, so this is a
    // one-byte direct push there and an `OP_n` below 17.
    push_num(&mut out, i64::try_from(n).map_err(|_| ScriptError::NumericOverflow)?);
    out.push(Opcode::CheckMultiSig.to_byte());
    Ok(Script::new(out))
}

/// `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 <20B>
/// OP_EQUALVERIFY OP_CHECKSIG`.
///
/// `OP_CHECKLOCKTIMEVERIFY` inspects its operand rather than consuming it, so
/// the `OP_DROP` is part of the template, not an accident.
pub fn cltv_p2pkh(locktime: u32, pkh: &[u8; PUBKEY_HASH_SIZE]) -> Script {
    let mut out = Vec::with_capacity(33);
    push_num(&mut out, i64::from(locktime));
    out.push(Opcode::CheckLockTimeVerify.to_byte());
    out.push(Opcode::Drop.to_byte());
    push_p2pkh_tail(&mut out, pkh);
    Script::new(out)
}

/// A hash-timelocked contract.
///
/// ```text
/// OP_IF
///     OP_HASH160 <hash> OP_EQUALVERIFY
///     OP_DUP OP_HASH160 <receiver_pkh> OP_EQUALVERIFY OP_CHECKSIG
/// OP_ELSE
///     <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
///     OP_DUP OP_HASH160 <refund_pkh> OP_EQUALVERIFY OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// The receiver spends with `<sig> <pubkey> <preimage> OP_1`; the sender
/// refunds after `timeout` with `<sig> <pubkey> OP_0`. Both `script_sig`s are
/// push-only, and `OP_1`/`OP_0` are the only two branch selectors the
/// minimal-`OP_IF` rule allows.
pub fn htlc(
    hash: &[u8; PUBKEY_HASH_SIZE],
    receiver_pkh: &[u8; PUBKEY_HASH_SIZE],
    timeout: u32,
    refund_pkh: &[u8; PUBKEY_HASH_SIZE],
) -> Script {
    let mut out = Vec::with_capacity(100);
    out.push(Opcode::If.to_byte());
    out.push(Opcode::Hash160.to_byte());
    push_data(&mut out, hash);
    out.push(Opcode::EqualVerify.to_byte());
    push_p2pkh_tail(&mut out, receiver_pkh);
    out.push(Opcode::Else.to_byte());
    push_num(&mut out, i64::from(timeout));
    out.push(Opcode::CheckLockTimeVerify.to_byte());
    out.push(Opcode::Drop.to_byte());
    push_p2pkh_tail(&mut out, refund_pkh);
    out.push(Opcode::EndIf.to_byte());
    Script::new(out)
}

/// `OP_RETURN <data>` — provably unspendable, so the output never enters the
/// UTXO set.
///
/// # Errors
///
/// [`ScriptError::OpReturnTooLarge`] above [`MAX_OP_RETURN_PAYLOAD`] bytes.
pub fn op_return(data: &[u8]) -> Result<Script, ScriptError> {
    if data.len() > MAX_OP_RETURN_PAYLOAD {
        return Err(ScriptError::OpReturnTooLarge { len: data.len(), max: MAX_OP_RETURN_PAYLOAD });
    }
    let mut out = Vec::with_capacity(data.len().saturating_add(3));
    out.push(Opcode::Return.to_byte());
    push_data(&mut out, data);
    Ok(Script::new(out))
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// True when `i` is exactly the opcode `want`.
fn is_op(i: Option<&Instruction>, want: Opcode) -> bool {
    matches!(i, Some(Instruction::Op(op)) if *op == want)
}

/// The pushed bytes when `i` is a push of exactly `len` bytes.
fn push_of_len(i: Option<&Instruction>, len: usize) -> Option<&[u8]> {
    i.and_then(Instruction::push_data).filter(|d| d.len() == len)
}

/// The number a push encodes, when it is a minimal arithmetic `ScriptNum`.
///
/// Four bytes, the arithmetic ceiling — right for the `k` and `n` of a
/// multisig, wrong for a locktime.
fn push_as_num(i: Option<&Instruction>) -> Option<i64> {
    let data = i.and_then(Instruction::push_data)?;
    ScriptNum::from_slice(data, MAX_NUM_SIZE, true).ok().map(ScriptNum::value)
}

/// The number a push encodes when it is a **locktime** operand.
///
/// Five bytes, not [`MAX_NUM_SIZE`]: a `lock_time` is a `u32`, and any value at
/// or above `0x8000_0000` needs the extra sign byte. `check_lock_time` reads
/// the operand at exactly this width, so the classifier must accept exactly
/// these widths too — otherwise a script the VM executes happily is labelled
/// [`ScriptType::NonStandard`] and the mempool refuses to relay an output this
/// module itself builds.
fn push_as_locktime_num(i: Option<&Instruction>) -> Option<i64> {
    let data = i.and_then(Instruction::push_data)?;
    ScriptNum::from_slice(data, MAX_LOCKTIME_NUM_SIZE, true).ok().map(ScriptNum::value)
}

/// True when `window` is `OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG`.
fn is_p2pkh_tail(window: &[Instruction]) -> bool {
    window.len() == 5
        && is_op(window.first(), Opcode::Dup)
        && is_op(window.get(1), Opcode::Hash160)
        && push_of_len(window.get(2), PUBKEY_HASH_SIZE).is_some()
        && is_op(window.get(3), Opcode::EqualVerify)
        && is_op(window.get(4), Opcode::CheckSig)
}

/// Label a `script_pubkey`.
///
/// A script that does not parse is [`ScriptType::NonStandard`], never a panic
/// and never a partial match.
pub fn classify(s: &Script) -> ScriptType {
    let Ok(instructions) = parse(s) else {
        return ScriptType::NonStandard;
    };
    let i = &instructions[..];

    // P2PK: <32B> OP_CHECKSIG
    if i.len() == 2 && push_of_len(i.first(), 32).is_some() && is_op(i.get(1), Opcode::CheckSig) {
        return ScriptType::P2PK;
    }

    // P2PKH
    if is_p2pkh_tail(i) {
        return ScriptType::P2PKH;
    }

    // P2SH: OP_HASH256 <32B> OP_EQUAL
    if i.len() == 3
        && is_op(i.first(), Opcode::Hash256)
        && push_of_len(i.get(1), 32).is_some()
        && is_op(i.get(2), Opcode::Equal)
    {
        return ScriptType::P2SH;
    }

    // OP_RETURN, with or without a payload.
    if is_op(i.first(), Opcode::Return) {
        let payload_ok = match i.len() {
            1 => true,
            2 => i
                .get(1)
                .and_then(Instruction::push_data)
                .is_some_and(|d| d.len() <= MAX_OP_RETURN_PAYLOAD),
            _ => false,
        };
        if payload_ok {
            return ScriptType::OpReturn;
        }
        return ScriptType::NonStandard;
    }

    // CLTV: <locktime> OP_CLTV OP_DROP <P2PKH tail>
    if i.len() == 8
        && push_as_locktime_num(i.first()).is_some_and(|v| v >= 0)
        && is_op(i.get(1), Opcode::CheckLockTimeVerify)
        && is_op(i.get(2), Opcode::Drop)
        && i.get(3..8).is_some_and(is_p2pkh_tail)
    {
        return ScriptType::Cltv;
    }

    if is_htlc(i) {
        return ScriptType::Htlc;
    }

    if let Some(t) = classify_multisig(i) {
        return t;
    }

    ScriptType::NonStandard
}

/// The exact 19-instruction shape [`htlc`] emits.
fn is_htlc(i: &[Instruction]) -> bool {
    i.len() == 19
        && is_op(i.first(), Opcode::If)
        && is_op(i.get(1), Opcode::Hash160)
        && push_of_len(i.get(2), PUBKEY_HASH_SIZE).is_some()
        && is_op(i.get(3), Opcode::EqualVerify)
        && i.get(4..9).is_some_and(is_p2pkh_tail)
        && is_op(i.get(9), Opcode::Else)
        && push_as_locktime_num(i.get(10)).is_some_and(|v| v >= 0)
        && is_op(i.get(11), Opcode::CheckLockTimeVerify)
        && is_op(i.get(12), Opcode::Drop)
        && i.get(13..18).is_some_and(is_p2pkh_tail)
        && is_op(i.get(18), Opcode::EndIf)
}

/// `<k> <pk1> … <pkn> <n> OP_CHECKMULTISIG`.
fn classify_multisig(i: &[Instruction]) -> Option<ScriptType> {
    if i.len() < 4 || !is_op(i.last(), Opcode::CheckMultiSig) {
        return None;
    }
    let key_count = i.len().checked_sub(3)?;
    let k = push_as_num(i.first())?;
    let declared = push_as_num(i.get(key_count.checked_add(1)?))?;
    if declared != i64::try_from(key_count).ok()? {
        return None;
    }
    if key_count > MAX_PUBKEYS_PER_MULTISIG || k < 1 || k > declared {
        return None;
    }
    for index in 1..=key_count {
        push_of_len(i.get(index), 32)?;
    }
    Some(ScriptType::Multisig { k: u8::try_from(k).ok()?, n: u8::try_from(key_count).ok()? })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ferrum_crypto::SecretKey;

    fn key(seed: u8) -> PublicKey {
        SecretKey::from_bytes(&[seed.max(1); 32]).unwrap().public_key()
    }

    #[test]
    fn p2pk_shape() {
        let pk = key(1);
        let s = p2pk(&pk);
        assert_eq!(s.len(), 34);
        assert_eq!(s.as_bytes().first(), Some(&0x20));
        assert_eq!(s.as_bytes().last(), Some(&0xac));
        assert_eq!(classify(&s), ScriptType::P2PK);
    }

    #[test]
    fn p2pkh_shape() {
        let s = p2pkh(&[7u8; 20]);
        assert_eq!(s.len(), 25);
        assert_eq!(
            s.as_bytes(),
            &[
                0x76, 0xa9, 0x14, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0x88,
                0xac
            ]
        );
        assert_eq!(classify(&s), ScriptType::P2PKH);
    }

    #[test]
    fn p2sh_shape_matches_the_address_crate() {
        let redeem = p2pkh(&[3u8; 20]);
        let s = p2sh_of(&redeem);
        assert_eq!(s.len(), 35);
        assert_eq!(s.as_bytes().first(), Some(&0xaa));
        assert_eq!(s.as_bytes().last(), Some(&0x87));
        assert_eq!(classify(&s), ScriptType::P2SH);

        let address = ferrum_crypto::Address::p2sh(ferrum_types::Network::Devnet, &redeem);
        assert_eq!(address.script_pubkey(), s);
    }

    #[test]
    fn p2pkh_matches_the_address_crate() {
        let pk = key(9);
        let address = ferrum_crypto::Address::p2pkh(ferrum_types::Network::Mainnet, &pk);
        assert_eq!(address.script_pubkey(), p2pkh(&ferrum_crypto::hash160(pk.as_bytes())));
    }

    #[test]
    fn multisig_shape_and_classification() {
        let keys: Vec<PublicKey> = (1u8..=3).map(key).collect();
        let s = multisig(2, &keys).unwrap();
        assert_eq!(s.as_bytes().first(), Some(&0x52));
        assert_eq!(s.as_bytes().last(), Some(&0xae));
        assert_eq!(classify(&s), ScriptType::Multisig { k: 2, n: 3 });
    }

    #[test]
    fn multisig_above_sixteen_keys_uses_a_direct_push() {
        let keys: Vec<PublicKey> = (1u8..=17).map(key).collect();
        let s = multisig(17, &keys).unwrap();
        assert_eq!(classify(&s), ScriptType::Multisig { k: 17, n: 17 });
        // <17> is a one-byte direct push, not an OP_n.
        assert_eq!(s.as_bytes().first(), Some(&0x01));
        assert_eq!(s.as_bytes().get(1), Some(&17u8));
    }

    #[test]
    fn multisig_rejects_bad_shapes() {
        let keys: Vec<PublicKey> = (1u8..=3).map(key).collect();
        assert_eq!(
            multisig(2, &[]),
            Err(ScriptError::MultisigKeyCount { n: 0, max: MAX_PUBKEYS_PER_MULTISIG })
        );
        let too_many: Vec<PublicKey> = (1u8..=21).map(key).collect();
        assert_eq!(
            multisig(2, &too_many),
            Err(ScriptError::MultisigKeyCount { n: 21, max: MAX_PUBKEYS_PER_MULTISIG })
        );
        assert_eq!(multisig(0, &keys), Err(ScriptError::MultisigThreshold { k: 0, n: 3 }));
        assert_eq!(multisig(4, &keys), Err(ScriptError::MultisigThreshold { k: 4, n: 3 }));
    }

    #[test]
    fn cltv_shape() {
        let s = cltv_p2pkh(500_000, &[1u8; 20]);
        assert_eq!(classify(&s), ScriptType::Cltv);
        // <500000> is a three-byte push, then OP_CLTV OP_DROP.
        assert_eq!(s.as_bytes().first(), Some(&0x03));
        assert_eq!(s.as_bytes().get(4), Some(&0xb1));
        assert_eq!(s.as_bytes().get(5), Some(&0x75));
    }

    #[test]
    fn cltv_is_classified_across_the_five_byte_locktime_boundary() {
        // A locktime at or above 0x8000_0000 needs five bytes in sign-magnitude
        // form — which is why the interpreter reads the operand at
        // MAX_LOCKTIME_NUM_SIZE. The classifier has to accept exactly the same
        // widths, or the mempool calls a script the VM executes NonStandard and
        // refuses to relay an output this very module builds. Unix timestamps
        // cross 0x8000_0000 in January 2038.
        for locktime in [0u32, 1, 500_000, 0x7fff_ffff, 0x8000_0000, 0x8000_0001, 0xffff_ffff] {
            let s = cltv_p2pkh(locktime, &[1u8; 20]);
            assert_eq!(classify(&s), ScriptType::Cltv, "locktime {locktime}");
            assert!(parse(&s).is_ok(), "locktime {locktime}");
        }
        // The five-byte encoding really is five bytes: <05> <ll ll ll ll 00>.
        assert_eq!(cltv_p2pkh(0x8000_0000, &[1u8; 20]).as_bytes().first(), Some(&0x05));
    }

    #[test]
    fn htlc_is_classified_across_the_five_byte_timeout_boundary() {
        for timeout in [0u32, 600_000, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
            let s = htlc(&[1u8; 20], &[2u8; 20], timeout, &[3u8; 20]);
            assert_eq!(classify(&s), ScriptType::Htlc, "timeout {timeout}");
        }
    }

    #[test]
    fn a_six_byte_operand_is_still_not_a_cltv() {
        // The widening stops at five bytes: the operand limit the interpreter
        // enforces. A wider push is NonStandard, as it is unexecutable.
        // 2^40 needs six bytes; 2^32 would still fit in five and is therefore
        // a legal, if unsatisfiable, operand.
        let operand = ScriptNum::new(0x100_0000_0000).to_vec();
        assert_eq!(operand.len(), 6);
        let mut bytes = Vec::new();
        push_data(&mut bytes, &operand);
        bytes.push(Opcode::CheckLockTimeVerify.to_byte());
        bytes.push(Opcode::Drop.to_byte());
        push_p2pkh_tail(&mut bytes, &[1u8; 20]);
        assert_eq!(classify(&Script::new(bytes)), ScriptType::NonStandard);
    }

    #[test]
    fn htlc_shape() {
        let s = htlc(&[1u8; 20], &[2u8; 20], 600_000, &[3u8; 20]);
        assert_eq!(classify(&s), ScriptType::Htlc);
        assert_eq!(s.as_bytes().first(), Some(&0x63));
        assert_eq!(s.as_bytes().last(), Some(&0x68));
        assert_eq!(parse(&s).unwrap().len(), 19);
    }

    #[test]
    fn op_return_shape_and_limit() {
        let s = op_return(b"ferrum").unwrap();
        assert_eq!(s.as_bytes().first(), Some(&0x6a));
        assert_eq!(classify(&s), ScriptType::OpReturn);
        assert_eq!(classify(&op_return(&[]).unwrap()), ScriptType::OpReturn);
        assert_eq!(classify(&op_return(&[9u8; 80]).unwrap()), ScriptType::OpReturn);
        assert_eq!(op_return(&[0u8; 81]), Err(ScriptError::OpReturnTooLarge { len: 81, max: 80 }));
    }

    #[test]
    fn non_standard_is_the_default() {
        assert_eq!(classify(&Script::EMPTY), ScriptType::NonStandard);
        assert_eq!(classify(&Script::new(vec![0x51])), ScriptType::NonStandard);
        assert_eq!(classify(&Script::new(vec![0x51, 0x52])), ScriptType::NonStandard);
        // Does not parse.
        assert_eq!(classify(&Script::new(vec![0x05, 0x01])), ScriptType::NonStandard);
        // OP_RETURN followed by two pushes is not the template.
        assert_eq!(classify(&Script::new(vec![0x6a, 0x51, 0x52])), ScriptType::NonStandard);
        // A multisig whose declared n disagrees with the key count.
        let keys: Vec<PublicKey> = (1u8..=3).map(key).collect();
        let mut bytes = multisig(2, &keys).unwrap().into_bytes();
        let last = bytes.len() - 2;
        bytes[last] = 0x54; // claims n = 4
        assert_eq!(classify(&Script::new(bytes)), ScriptType::NonStandard);
    }

    #[test]
    fn script_type_serialises_for_the_explorer() {
        assert_eq!(serde_json::to_string(&ScriptType::P2PKH).unwrap(), "\"p2pkh\"");
        assert_eq!(
            serde_json::to_string(&ScriptType::Multisig { k: 2, n: 3 }).unwrap(),
            "{\"multisig\":{\"k\":2,\"n\":3}}"
        );
    }

    #[test]
    fn every_template_parses_and_is_minimal() {
        let keys: Vec<PublicKey> = (1u8..=3).map(key).collect();
        let scripts = [
            p2pk(&keys[0]),
            p2pkh(&[1u8; 20]),
            p2sh(&Hash32::ZERO),
            multisig(2, &keys).unwrap(),
            cltv_p2pkh(1000, &[1u8; 20]),
            htlc(&[1u8; 20], &[2u8; 20], 1000, &[3u8; 20]),
            op_return(b"x").unwrap(),
        ];
        for s in scripts {
            assert!(parse(&s).is_ok(), "{s}");
            assert!(s.len() <= crate::limits::MAX_SCRIPT_SIZE);
        }
    }
}
