//! The explorer's reverse index — `tx_index` and `addr_index` (CONTRACT §7).
//!
//! **Neither table is consensus state.** They are built only when
//! [`crate::StoreConfig::index_transactions`] is on, and a node without them
//! validates exactly the same chain. That is why a mistake here can never
//! split the network, and why the address extractor below is allowed to be
//! best-effort rather than exhaustive.
//!
//! # What gets indexed
//!
//! `tx_index` maps every txid in a connected block to its
//! [`TxLocation`]. `addr_index` maps
//! `addr_key ‖ be_u64(height) ‖ be_u32(tx_idx)` to the txid, for every address
//! key a transaction *touches* — the scripts of the outputs it creates and the
//! scripts of the coins it spends. A spend's script is not in the transaction
//! (a `TxIn` carries only an outpoint), so it comes from the block's
//! [`crate::StateDiff`] on connect and from the stored
//! [`crate::UndoBlock`] on disconnect. Those two carry the same coins, which
//! is what makes indexing exactly reversible.
//!
//! # How an address key is derived from a script
//!
//! `ferrum-storage` sits below `ferrum-script` in the dependency order, so it
//! cannot call `templates::classify`. Instead of duplicating that table — two
//! copies of one rule become two different rules — this module applies three
//! structural rules over the raw push stream:
//!
//! 1. a 20-byte push immediately preceded by `OP_HASH160` → that hash
//!    (P2PKH, and the P2PKH tail of the CLTV and HTLC templates);
//! 2. a 32-byte push immediately preceded by `OP_HASH256` → that hash (P2SH);
//! 3. a 32-byte push immediately followed by `OP_CHECKSIG`/`OP_CHECKSIGVERIFY`,
//!    or any 32-byte push in a script that *ends* with `OP_CHECKMULTISIG`/
//!    `OP_CHECKMULTISIGVERIFY` → `hash160` of it. That is a bare x-only public
//!    key, and it is filed under the same key the holder's P2PKH address uses
//!    so one wallet has one history. The multisig form needs the
//!    "ends with" shape because the last pubkey is followed by the `n` push,
//!    not by the opcode.
//!
//! Anything else is simply not indexed, which for a non-standard script is the
//! correct answer: it has no address to file it under.

use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use ferrum_crypto::hash160;
use ferrum_types::{Block, BlockHash, Coin, OutPoint, Script, Transaction};
use serde::{Deserialize, Serialize};

use crate::error::StorageError;
use crate::tables::{ADDR_INDEX, TX_INDEX, addr_index_key, txid, txid_key};

/// Where a transaction sits on the active chain.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct TxLocation {
    /// The block that contains the transaction.
    pub block_hash: BlockHash,
    /// Its position within `block.txs`; `0` is the coinbase.
    pub index: u32,
}

impl TxLocation {
    /// Name a position in a block.
    #[must_use]
    pub const fn new(block_hash: BlockHash, index: u32) -> Self {
        TxLocation { block_hash, index }
    }
}

/// Length of a public-key-hash address key.
pub const ADDR_KEY_PKH_LEN: usize = 20;
/// Length of a script-hash address key.
pub const ADDR_KEY_SCRIPT_LEN: usize = 32;

// The handful of opcodes this module needs, taken from CONTRACT §5.2. They are
// re-stated rather than imported because `ferrum-script` is above this crate in
// the dependency order; a test pins the byte values against the contract table.
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_HASH160: u8 = 0xa9;
const OP_HASH256: u8 = 0xaa;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
const MAX_DIRECT_PUSH: u8 = 0x4b;

/// One decoded element of a script, for the address extractor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Item<'a> {
    /// A data push and its payload.
    Push(&'a [u8]),
    /// A bare opcode byte.
    Op(u8),
}

/// Split a script into pushes and opcodes.
///
/// Stops at the first malformed push rather than failing: this feeds a
/// non-consensus index, and half an address history beats none. Bounded by the
/// script length, so it always terminates and never panics.
fn scan(script: &[u8]) -> Vec<Item<'_>> {
    let mut items = Vec::new();
    let mut i = 0usize;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let len = match op {
            1..=MAX_DIRECT_PUSH => usize::from(op),
            OP_PUSHDATA1 => {
                let Some(&n) = script.get(i) else { break };
                i += 1;
                usize::from(n)
            }
            OP_PUSHDATA2 => {
                let Some(bytes) = script.get(i..i.saturating_add(2)) else { break };
                i = i.saturating_add(2);
                usize::from(u16::from_le_bytes([bytes[0], bytes[1]]))
            }
            _ => {
                items.push(Item::Op(op));
                continue;
            }
        };
        let Some(data) = script.get(i..i.saturating_add(len)) else { break };
        i += len;
        items.push(Item::Push(data));
    }
    items
}

/// Every address key a locking script commits to, deduplicated and ordered.
///
/// A `BTreeSet` rather than a `Vec`: the same hash can appear twice in a
/// script (an HTLC refund branch that pays the same key), and index writes
/// must be deterministic.
#[must_use]
pub fn address_keys(script: &Script) -> BTreeSet<Vec<u8>> {
    let items = scan(script.as_bytes());
    let multisig =
        matches!(items.last(), Some(Item::Op(OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY)));
    let mut keys = BTreeSet::new();
    for (idx, item) in items.iter().enumerate() {
        let Item::Push(data) = item else { continue };
        let before = idx.checked_sub(1).and_then(|j| items.get(j));
        let after = items.get(idx + 1);
        match data.len() {
            ADDR_KEY_PKH_LEN if before == Some(&Item::Op(OP_HASH160)) => {
                keys.insert(data.to_vec());
            }
            ADDR_KEY_SCRIPT_LEN if before == Some(&Item::Op(OP_HASH256)) => {
                keys.insert(data.to_vec());
            }
            ADDR_KEY_SCRIPT_LEN
                if multisig || matches!(after, Some(Item::Op(OP_CHECKSIG | OP_CHECKSIGVERIFY))) =>
            {
                // A bare x-only pubkey: file it under the hash its P2PKH
                // address would use, so one key has one history.
                keys.insert(hash160(data).to_vec());
            }
            _ => {}
        }
    }
    keys
}

/// Whether `key` is a length this index can store.
///
/// CONTRACT §7 fixes `addr_key` at 20 or 32 bytes; anything else would make
/// [`crate::tables::addr_index_parts`] ambiguous.
#[must_use]
pub const fn is_valid_addr_key(key: &[u8]) -> bool {
    key.len() == ADDR_KEY_PKH_LEN || key.len() == ADDR_KEY_SCRIPT_LEN
}

/// Every address key one transaction touches: the scripts it creates plus the
/// scripts of the coins it spends.
///
/// The spent scripts come from `spent`, a lookup over the block's
/// [`crate::StateDiff`] on connect and over the stored [`crate::UndoBlock`] on
/// disconnect. Those two hold the same coins, so the key set is identical in
/// both directions and un-indexing is exact.
fn touched_keys(tx: &Transaction, spent: &BTreeMap<OutPoint, Coin>) -> BTreeSet<Vec<u8>> {
    let mut keys = BTreeSet::new();
    for out in &tx.outputs {
        keys.extend(address_keys(&out.script_pubkey));
    }
    for input in &tx.inputs {
        // The coinbase input names no output, so there is nothing to resolve.
        if input.prev_out.is_null() {
            continue;
        }
        if let Some(coin) = spent.get(&input.prev_out) {
            keys.extend(address_keys(&coin.script_pubkey));
        }
    }
    keys.retain(|k| is_valid_addr_key(k));
    keys
}

/// The position of each transaction in a block, as the `u32` the index keys use.
fn tx_positions(block: &Block) -> Result<Vec<u32>, StorageError> {
    (0..block.txs.len())
        .map(|i| {
            u32::try_from(i)
                .map_err(|_| StorageError::TooManyTransactions { count: block.txs.len() })
        })
        .collect()
}

/// Write the `tx_index` and `addr_index` entries for a connected block.
///
/// Called inside the block's single write transaction, so the index is exactly
/// as atomic as the UTXO set it describes.
pub(crate) fn index_block(
    txn: &redb::WriteTransaction,
    block_hash: &BlockHash,
    height: u64,
    block: &Block,
    spent: &BTreeMap<OutPoint, Coin>,
) -> Result<(), StorageError> {
    let positions = tx_positions(block)?;
    let mut tx_index = txn.open_table(TX_INDEX)?;
    let mut addr_index = txn.open_table(ADDR_INDEX)?;
    for (tx, idx) in block.txs.iter().zip(positions) {
        let id = txid(tx);
        let key = txid_key(&id);
        let loc = TxLocation::new(*block_hash, idx);
        let bytes = borsh::to_vec(&loc).map_err(|e| StorageError::corrupt("tx location", e))?;
        tx_index.insert(&key, bytes.as_slice())?;
        for addr in touched_keys(tx, spent) {
            addr_index.insert(addr_index_key(&addr, height, idx).as_slice(), &key)?;
        }
    }
    Ok(())
}

/// Remove the `tx_index` and `addr_index` entries a block put there.
///
/// The mirror image of [`index_block`], driven by the same `(block, spent)`
/// pair, so every key it wrote is a key this removes.
pub(crate) fn unindex_block(
    txn: &redb::WriteTransaction,
    height: u64,
    block: &Block,
    spent: &BTreeMap<OutPoint, Coin>,
) -> Result<(), StorageError> {
    let positions = tx_positions(block)?;
    let mut tx_index = txn.open_table(TX_INDEX)?;
    let mut addr_index = txn.open_table(ADDR_INDEX)?;
    for (tx, idx) in block.txs.iter().zip(positions) {
        let key = txid_key(&txid(tx));
        tx_index.remove(&key)?;
        for addr in touched_keys(tx, spent) {
            addr_index.remove(addr_index_key(&addr, height, idx).as_slice())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ferrum_types::{Amount, Hash32, TxIn, TxOut, Txid};

    fn p2pkh(h: &[u8; 20]) -> Script {
        let mut v = vec![0x76, OP_HASH160, 0x14];
        v.extend_from_slice(h);
        v.extend_from_slice(&[0x88, OP_CHECKSIG]);
        Script::new(v)
    }

    fn p2sh(h: &[u8; 32]) -> Script {
        let mut v = vec![OP_HASH256, 0x20];
        v.extend_from_slice(h);
        v.push(0x87);
        Script::new(v)
    }

    fn p2pk(pk: &[u8; 32]) -> Script {
        let mut v = vec![0x20];
        v.extend_from_slice(pk);
        v.push(OP_CHECKSIG);
        Script::new(v)
    }

    #[test]
    fn opcode_bytes_match_the_contract_table() {
        assert_eq!(OP_HASH160, 0xa9);
        assert_eq!(OP_HASH256, 0xaa);
        assert_eq!(OP_CHECKSIG, 0xac);
        assert_eq!(OP_CHECKMULTISIG, 0xae);
        assert_eq!(OP_PUSHDATA1, 0x4c);
        assert_eq!(OP_PUSHDATA2, 0x4d);
        assert_eq!(MAX_DIRECT_PUSH, 0x4b);
    }

    #[test]
    fn p2pkh_yields_its_pubkey_hash() {
        let h = [0x11u8; 20];
        let keys = address_keys(&p2pkh(&h));
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(h.as_slice()));
    }

    #[test]
    fn p2sh_yields_its_script_hash() {
        let h = [0x22u8; 32];
        let keys = address_keys(&p2sh(&h));
        assert_eq!(keys, BTreeSet::from([h.to_vec()]));
    }

    #[test]
    fn p2pk_yields_the_hash160_of_the_key() {
        let pk = [0x33u8; 32];
        let keys = address_keys(&p2pk(&pk));
        assert_eq!(keys, BTreeSet::from([hash160(&pk).to_vec()]));
    }

    #[test]
    fn a_p2pk_and_a_p2pkh_for_one_key_share_a_history() {
        let pk = [0x44u8; 32];
        let pkh = hash160(&pk);
        assert_eq!(address_keys(&p2pk(&pk)), address_keys(&p2pkh(&pkh)));
    }

    #[test]
    fn a_cltv_wrapped_p2pkh_still_yields_the_pubkey_hash() {
        // <locktime> OP_CLTV OP_DROP OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        let h = [0x55u8; 20];
        let mut v = vec![0x04, 0x00, 0x01, 0x02, 0x03, 0xb1, 0x75, 0x76, OP_HASH160, 0x14];
        v.extend_from_slice(&h);
        v.extend_from_slice(&[0x88, OP_CHECKSIG]);
        assert_eq!(address_keys(&Script::new(v)), BTreeSet::from([h.to_vec()]));
    }

    #[test]
    fn an_htlc_yields_both_branches() {
        // OP_IF OP_HASH160 <secret20> OP_EQUALVERIFY OP_DUP OP_HASH160 <recv20>
        // OP_ELSE <timeout> OP_CLTV OP_DROP OP_DUP OP_HASH160 <refund20>
        // OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG
        let secret = [0x01u8; 20];
        let recv = [0x02u8; 20];
        let refund = [0x03u8; 20];
        let mut v = vec![0x63, OP_HASH160, 0x14];
        v.extend_from_slice(&secret);
        v.extend_from_slice(&[0x88, 0x76, OP_HASH160, 0x14]);
        v.extend_from_slice(&recv);
        v.extend_from_slice(&[0x67, 0x04, 0, 0, 0, 1, 0xb1, 0x75, 0x76, OP_HASH160, 0x14]);
        v.extend_from_slice(&refund);
        v.extend_from_slice(&[0x68, 0x88, OP_CHECKSIG]);
        let keys = address_keys(&Script::new(v));
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(recv.as_slice()));
        assert!(keys.contains(refund.as_slice()));
        assert!(keys.contains(secret.as_slice()), "the hashlock is a 20-byte OP_HASH160 push too");
    }

    #[test]
    fn multisig_yields_every_key_once() {
        let a = [0x0au8; 32];
        let b = [0x0bu8; 32];
        let mut v = vec![0x52, 0x20];
        v.extend_from_slice(&a);
        v.push(0x20);
        v.extend_from_slice(&b);
        v.extend_from_slice(&[0x52, OP_CHECKMULTISIG]);
        let keys = address_keys(&Script::new(v));
        assert_eq!(keys.len(), 2, "both pubkeys are indexed");
        assert!(keys.contains(hash160(&a).as_slice()));
        assert!(keys.contains(hash160(&b).as_slice()));
    }

    #[test]
    fn a_repeated_hash_is_indexed_once() {
        let h = [0x77u8; 20];
        let mut v = vec![OP_HASH160, 0x14];
        v.extend_from_slice(&h);
        v.extend_from_slice(&[0x88, OP_HASH160, 0x14]);
        v.extend_from_slice(&h);
        v.push(0x87);
        assert_eq!(address_keys(&Script::new(v)).len(), 1);
    }

    #[test]
    fn an_op_return_yields_nothing() {
        let mut v = vec![0x6a, 0x0b];
        v.extend_from_slice(b"hello world");
        assert!(address_keys(&Script::new(v)).is_empty());
    }

    #[test]
    fn an_empty_script_yields_nothing() {
        assert!(address_keys(&Script::new(Vec::new())).is_empty());
    }

    #[test]
    fn a_truncated_push_does_not_panic() {
        // Claims 32 bytes but supplies 3.
        assert!(address_keys(&Script::new(vec![0x20, 1, 2, 3])).is_empty());
        // PUSHDATA1 with no length byte.
        assert!(address_keys(&Script::new(vec![OP_PUSHDATA1])).is_empty());
        // PUSHDATA2 with one length byte.
        assert!(address_keys(&Script::new(vec![OP_PUSHDATA2, 0x01])).is_empty());
        // PUSHDATA2 claiming 65535 bytes.
        assert!(address_keys(&Script::new(vec![OP_PUSHDATA2, 0xff, 0xff, 0x00])).is_empty());
    }

    #[test]
    fn pushdata1_carrying_a_hash_is_still_found() {
        let h = [0x99u8; 32];
        let mut v = vec![OP_HASH256, OP_PUSHDATA1, 0x20];
        v.extend_from_slice(&h);
        v.push(0x87);
        assert_eq!(address_keys(&Script::new(v)), BTreeSet::from([h.to_vec()]));
    }

    #[test]
    fn a_bare_twenty_byte_push_without_hash160_is_not_an_address() {
        let mut v = vec![0x14];
        v.extend_from_slice(&[0x01u8; 20]);
        assert!(address_keys(&Script::new(v)).is_empty());
    }

    #[test]
    fn valid_key_lengths_are_twenty_and_thirty_two() {
        assert!(is_valid_addr_key(&[0u8; 20]));
        assert!(is_valid_addr_key(&[0u8; 32]));
        assert!(!is_valid_addr_key(&[0u8; 19]));
        assert!(!is_valid_addr_key(&[0u8; 33]));
        assert!(!is_valid_addr_key(&[]));
    }

    #[test]
    fn tx_location_round_trips_through_borsh_and_json() {
        let l = TxLocation::new(BlockHash(Hash32::from_bytes([7u8; 32])), 4);
        let b = borsh::to_vec(&l).unwrap();
        assert_eq!(b.len(), 36, "32-byte hash plus a u32");
        assert_eq!(borsh::from_slice::<TxLocation>(&b).unwrap(), l);
        assert_eq!(
            serde_json::from_str::<TxLocation>(&serde_json::to_string(&l).unwrap()).unwrap(),
            l
        );
        let mut extra = b;
        extra.push(0);
        assert!(borsh::from_slice::<TxLocation>(&extra).is_err());
    }

    #[test]
    fn touched_keys_covers_outputs_and_resolved_inputs() {
        let recv = [0x01u8; 20];
        let funded = [0x02u8; 20];
        let prev = OutPoint::new(Txid(Hash32::from_bytes([9u8; 32])), 0);
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn::new(prev, Script::new(vec![0x51]))],
            outputs: vec![TxOut::new(Amount::from_grains(1), p2pkh(&recv))],
            lock_time: 0,
        };
        let mut spent = BTreeMap::new();
        spent.insert(
            prev,
            Coin {
                value: Amount::from_grains(2),
                script_pubkey: p2pkh(&funded),
                height: 1,
                is_coinbase: false,
            },
        );
        let keys = touched_keys(&tx, &spent);
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(recv.as_slice()));
        assert!(keys.contains(funded.as_slice()), "the spent script is indexed too");
    }

    #[test]
    fn touched_keys_ignores_a_coinbase_input() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(Script::new(vec![0x51, 0x00]))],
            outputs: vec![TxOut::new(Amount::from_grains(1), p2pkh(&[7u8; 20]))],
            lock_time: 0,
        };
        let keys = touched_keys(&tx, &BTreeMap::new());
        assert_eq!(keys, BTreeSet::from([[7u8; 20].to_vec()]));
    }

    #[test]
    fn touched_keys_skips_an_unresolvable_input() {
        let prev = OutPoint::new(Txid(Hash32::from_bytes([9u8; 32])), 0);
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn::new(prev, Script::new(vec![0x51]))],
            outputs: Vec::new(),
            lock_time: 0,
        };
        assert!(touched_keys(&tx, &BTreeMap::new()).is_empty());
    }

    #[test]
    fn scanning_never_panics_on_arbitrary_bytes() {
        for seed in 0u16..=512 {
            let bytes: Vec<u8> =
                (0..64u16).map(|i| (seed.wrapping_mul(i).wrapping_add(i)) as u8).collect();
            let _ = address_keys(&Script::new(bytes));
        }
    }
}
