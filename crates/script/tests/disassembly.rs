//! `parse`, `disassemble` and `is_p2sh` — the surface `chain-cli script` uses.

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{ctx_for, pkh, public, push, script, script_sig, spending_tx};
use ferrum_script::opcode::{Instruction, Opcode};
use ferrum_script::{ScriptError, disassemble, is_p2sh, parse, templates, verify};
use ferrum_types::{ChainId, Hash32, Script};

const NOT_FINAL: u32 = 0xffff_fffe;

#[test]
fn p2pkh_disassembles_to_its_mnemonics() {
    let s = templates::p2pkh(&[0xab; 20]);
    assert_eq!(
        disassemble(&s),
        "OP_DUP OP_HASH160 OP_PUSHBYTES_20 0xabababababababababababababababababababab \
         OP_EQUALVERIFY OP_CHECKSIG"
    );
}

#[test]
fn p2sh_disassembles_to_its_mnemonics() {
    let s = templates::p2sh(&Hash32::ZERO);
    assert!(s.to_string().starts_with("aa20"));
    assert!(disassemble(&s).starts_with("OP_HASH256 OP_PUSHBYTES_32 0x0000"));
    assert!(disassemble(&s).ends_with("OP_EQUAL"));
}

#[test]
fn a_multisig_disassembles_with_its_thresholds() {
    let keys: Vec<_> = (1u8..=3).map(public).collect();
    let s = templates::multisig(2, &keys).unwrap();
    let text = disassemble(&s);
    assert!(text.starts_with("OP_2 OP_PUSHBYTES_32"), "{text}");
    assert!(text.ends_with("OP_3 OP_CHECKMULTISIG"), "{text}");
}

#[test]
fn an_htlc_disassembles_with_both_branches() {
    let s = templates::htlc(&[1u8; 20], &pkh(2), 700_000, &pkh(3));
    let text = disassemble(&s);
    assert!(text.starts_with("OP_IF OP_HASH160"), "{text}");
    assert!(text.contains("OP_ELSE"), "{text}");
    assert!(text.contains("OP_CHECKLOCKTIMEVERIFY OP_DROP"), "{text}");
    assert!(text.ends_with("OP_ENDIF"), "{text}");
}

#[test]
fn parse_is_lossless_for_every_template() {
    let keys: Vec<_> = (1u8..=3).map(public).collect();
    let scripts = [
        templates::p2pk(&keys[0]),
        templates::p2pkh(&pkh(1)),
        templates::p2sh(&Hash32::ZERO),
        templates::multisig(2, &keys).unwrap(),
        templates::cltv_p2pkh(600_000, &pkh(1)),
        templates::htlc(&[1u8; 20], &pkh(2), 700_000, &pkh(3)),
        templates::op_return(b"ferrum").unwrap(),
    ];
    for s in scripts {
        let instructions = parse(&s).unwrap();
        assert_eq!(ferrum_script::parse::encode(&instructions), s, "{s}");
    }
}

#[test]
fn instructions_expose_their_opcode_and_data() {
    let s = templates::p2pkh(&[0x07; 20]);
    let instructions = parse(&s).unwrap();
    assert_eq!(instructions[0], Instruction::Op(Opcode::Dup));
    assert_eq!(instructions[1], Instruction::Op(Opcode::Hash160));
    assert_eq!(instructions[2].push_data(), Some(&[0x07u8; 20][..]));
    assert_eq!(instructions[2].opcode_byte(), 0x14);
    assert_eq!(instructions[3], Instruction::Op(Opcode::EqualVerify));
    assert_eq!(instructions[4], Instruction::Op(Opcode::CheckSig));
}

#[test]
fn is_p2sh_matches_only_the_exact_template() {
    assert!(is_p2sh(&templates::p2sh(&Hash32::ZERO)));
    assert!(!is_p2sh(&templates::p2pkh(&[0u8; 20])));
    assert!(!is_p2sh(&Script::EMPTY));

    // A 31-byte hash is not the template.
    let mut wrong = vec![0xaa, 0x1f];
    wrong.extend(std::iter::repeat_n(0u8, 31));
    wrong.push(0x87);
    assert!(!is_p2sh(&script(&wrong)));

    // Right shape, wrong trailing opcode.
    let mut wrong = templates::p2sh(&Hash32::ZERO).into_bytes();
    let last = wrong.len() - 1;
    wrong[last] = 0x88;
    assert!(!is_p2sh(&script(&wrong)));
}

#[test]
fn a_p2sh_output_with_an_empty_script_sig_underflows() {
    // `P2shEmptyScriptSig` is defensive: `OP_HASH256` needs something to hash,
    // so an empty `script_sig` fails inside `script_pubkey` long before the
    // redeem script is looked for.
    let script_pubkey = templates::p2sh(&Hash32::ZERO);
    let tx = spending_tx(Script::EMPTY, NOT_FINAL, 0);
    let ctx = ctx_for(&tx, ChainId::DEVNET);
    assert_eq!(
        verify(&Script::EMPTY, &script_pubkey, &ctx),
        Err(ScriptError::StackUnderflow { needed: 1, found: 0 })
    );
}

#[test]
fn a_p2sh_redeem_script_that_does_not_parse_is_rejected() {
    // The redeem script is attacker-supplied bytes; an undefined opcode inside
    // it must fail, not be skipped.
    let redeem = script(&[0xff]);
    let script_pubkey = templates::p2sh_of(&redeem);
    let unlock = script_sig(&[redeem.as_bytes()]);
    let tx = spending_tx(unlock.clone(), NOT_FINAL, 0);
    let ctx = ctx_for(&tx, ChainId::DEVNET);
    assert_eq!(verify(&unlock, &script_pubkey, &ctx), Err(ScriptError::InvalidOpcode(0xff)));
}

#[test]
fn disassembly_of_a_long_push_names_the_form() {
    let text = disassemble(&script(&push(&[0x11u8; 100])));
    assert!(text.starts_with("OP_PUSHDATA1_100 0x"), "{text}");
    let text = disassemble(&script(&push(&[0x11u8; 300])));
    assert!(text.starts_with("OP_PUSHDATA2_300 0x"), "{text}");
}

#[test]
fn disassembly_flags_a_non_minimal_push_without_failing() {
    let text = disassemble(&script(&[0x4c, 0x01, 0xaa]));
    assert!(text.contains("(non-minimal)"), "{text}");
    // The strict parser rejects the same bytes.
    assert_eq!(
        parse(&script(&[0x4c, 0x01, 0xaa])),
        Err(ScriptError::NonMinimalPush { opcode: 0x4c, len: 1 })
    );
}

#[test]
fn every_opcode_in_the_table_disassembles_to_a_unique_name() {
    let mut names: Vec<String> = Vec::new();
    for op in Opcode::ALL {
        let text = disassemble(&script(&[op.to_byte()]));
        assert_eq!(text, op.name());
        names.push(text);
    }
    names.sort();
    let before = names.len();
    names.dedup();
    assert_eq!(names.len(), before);
}
