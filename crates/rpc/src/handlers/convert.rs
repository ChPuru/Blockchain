//! Consensus types in, data-transfer objects out.
//!
//! The whole of the mapping between the internal model and the published JSON
//! lives here, so "what does this field mean?" has exactly one answer and a
//! rename is a local edit.
//!
//! # Addresses are derived the way the index files them
//!
//! [`address_of_script`] agrees with `ferrum_storage::address_keys`, the
//! function that populates `addr_index`. If they disagreed, an address page
//! would list a transaction in its history and then fail to attribute any value
//! to it — history and balance computed from the same script would not add up.
//! That is why a bare public key (`P2PK`) is reported under the *P2PKH* address
//! of its `hash160`: one key, one history.
//!
//! A script with more than one relevant key — an HTLC has a receiver and a
//! refund key, a `k`-of-`n` multisig has `n` — has **no** single address, and
//! this module returns `None` rather than naming one of them. The explorer then
//! shows the script type, which is the truth.

use ferrum_consensus::{Target, compact_to_target, difficulty_x1000, work_from_target};
use ferrum_crypto::{Address, AddressPayload, hash160};
use ferrum_script::{ScriptType, templates};
use ferrum_storage::header_hash;
use ferrum_types::{
    Amount, BlockHash, BlockHeader, Coin, Hash32, Network, OutPoint, Script, Transaction, Txid,
};

use crate::error::{RpcError, RpcErrorCode};
use crate::types::U64String;
use crate::types::rpc::{BlockHeaderJson, TxInJson, TxOutJson};

/// The number of decimal places [`difficulty_string`] renders.
pub const DIFFICULTY_DECIMALS: u32 = 3;

/// Hex of a 32-byte digest, in natural byte order.
///
/// Ferrum does not reverse hash bytes for display; Bitcoin's reversal is a
/// historical accident and reproducing it costs debugging hours forever
/// (CONTRACT §2.4).
#[must_use]
pub fn hash_hex(h: &Hash32) -> String {
    h.to_hex()
}

/// Hex of a block hash.
#[must_use]
pub fn block_hash_hex(h: &BlockHash) -> String {
    h.to_hex()
}

/// Hex of a transaction id.
#[must_use]
pub fn txid_hex(t: &Txid) -> String {
    t.to_hex()
}

/// `"<txid>:<vout>"`, the form `listunspent` publishes.
#[must_use]
pub fn outpoint_string(op: &OutPoint) -> String {
    format!("{}:{}", op.txid.to_hex(), op.vout)
}

/// Difficulty relative to `pow_limit`, as a decimal string with three places.
///
/// Built from [`difficulty_x1000`], which returns thousandths as an integer.
/// Every explorer prints this number as a float; floats are denied
/// workspace-wide because one in consensus arithmetic splits the chain along
/// CPU architecture lines, and the most visible number on the page is a bad
/// place to make the single exception.
#[must_use]
pub fn difficulty_string(target: Target, pow_limit: Target) -> String {
    let thousandths = difficulty_x1000(target, pow_limit);
    format!("{}.{:03}", thousandths / 1_000, thousandths % 1_000)
}

/// The `pow_limit` of a parameter set, expanded.
#[must_use]
pub fn pow_limit_target(params: &ferrum_types::ChainParams) -> Target {
    Target::from_be_bytes(&params.pow_limit)
}

/// The engine tag that goes on the wire: `pow` or `bft`.
#[must_use]
pub const fn engine_name(engine_id: u8) -> &'static str {
    match engine_id {
        ferrum_types::BlockSeal::ENGINE_BFT => "bft",
        _ => "pow",
    }
}

/// How many blocks sit on top of `height`, counting the block itself.
///
/// `0` when the block is not on the active chain, which is what tells the
/// explorer to render a side-chain block as unconfirmed.
#[must_use]
pub fn confirmations(tip_height: u64, height: u64, on_active_chain: bool) -> u64 {
    if !on_active_chain || height > tip_height {
        return 0;
    }
    tip_height.saturating_sub(height).saturating_add(1)
}

/// A one-word name for a locking script, as the explorer labels it.
#[must_use]
pub fn script_type_name(script: &Script) -> String {
    match templates::classify(script) {
        ScriptType::P2PK => "p2pk".to_owned(),
        ScriptType::P2PKH => "p2pkh".to_owned(),
        ScriptType::P2SH => "p2sh".to_owned(),
        ScriptType::Multisig { k, n } => format!("multisig {k}-of-{n}"),
        ScriptType::Cltv => "cltv".to_owned(),
        ScriptType::Htlc => "htlc".to_owned(),
        ScriptType::OpReturn => "op_return".to_owned(),
        ScriptType::NonStandard => "nonstandard".to_owned(),
    }
}

/// The single address a locking script pays, when it has one.
///
/// See the module documentation for why `P2PK` maps to a P2PKH address and why
/// multi-key scripts map to nothing.
#[must_use]
pub fn address_of_script(script: &Script, network: Network) -> Option<Address> {
    let bytes = script.as_bytes();
    match templates::classify(script) {
        // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        ScriptType::P2PKH => {
            let payload: [u8; 20] = bytes.get(3..23)?.try_into().ok()?;
            Some(Address::new(network, AddressPayload::PubKeyHash(payload)))
        }
        // OP_HASH256 <32> OP_EQUAL
        ScriptType::P2SH => {
            let payload: [u8; 32] = bytes.get(2..34)?.try_into().ok()?;
            Some(Address::new(network, AddressPayload::ScriptHash(payload)))
        }
        // <32-byte x-only pubkey> OP_CHECKSIG
        ScriptType::P2PK => {
            let key = bytes.get(1..33)?;
            Some(Address::new(network, AddressPayload::PubKeyHash(hash160(key))))
        }
        _ => None,
    }
}

/// [`address_of_script`], already encoded.
#[must_use]
pub fn address_string(script: &Script, network: Network) -> Option<String> {
    address_of_script(script, network).map(|a| a.encode())
}

/// The `addr_index` key for an address: the raw payload bytes.
///
/// The same 20 or 32 bytes `ferrum_storage::address_keys` extracts from a
/// locking script, which is what makes a history query and a balance query
/// agree.
#[must_use]
pub fn address_index_key(address: &Address) -> Vec<u8> {
    address.payload.as_bytes().to_vec()
}

/// Whether `script` pays the address whose index key is `key`.
#[must_use]
pub fn script_pays_key(script: &Script, key: &[u8]) -> bool {
    ferrum_storage::address_keys(script).contains(key)
}

/// Decode and network-check an address, or fail with
/// [`RpcErrorCode::InvalidAddress`].
///
/// The network check is not politeness: a mainnet address on a devnet node
/// would be filed under the same 20-byte payload and would report a balance
/// that belongs to a different chain.
///
/// # Errors
/// [`RpcErrorCode::InvalidAddress`] on a bad checksum, an unknown version or
/// the wrong human-readable prefix.
pub fn parse_address(s: &str, network: Network) -> Result<Address, RpcError> {
    let address = Address::decode(s)
        .map_err(|e| RpcError::new(RpcErrorCode::InvalidAddress, format!("{s:?}: {e}")))?;
    if address.network != network {
        return Err(RpcError::new(
            RpcErrorCode::InvalidAddress,
            format!(
                "{s:?} is a {} address; this node runs {}",
                address.network.name(),
                network.name()
            ),
        ));
    }
    Ok(address)
}

/// The six header fields plus the hash they produce.
#[must_use]
pub fn header_json(header: &BlockHeader) -> BlockHeaderJson {
    BlockHeaderJson {
        hash: header_hash(header).to_hex(),
        version: header.version,
        prev_hash: header.prev_hash.to_hex(),
        merkle_root: header.merkle_root.to_hex(),
        timestamp_ms: header.timestamp_ms,
        bits: header.bits.to_u32(),
        nonce: U64String(header.nonce),
    }
}

/// The expanded target of a header, as 64 hex characters.
///
/// # Errors
/// [`RpcErrorCode::BlockRejected`] when `bits` is not a canonical compact
/// target — which a stored header never is, but a header handed in by a client
/// can be.
pub fn target_hex(header: &BlockHeader) -> Result<String, RpcError> {
    let target = compact_to_target(header.bits)?;
    Ok(hex::encode(target.to_be_bytes()))
}

/// The work one header contributes, big-endian hex.
///
/// # Errors
/// As [`target_hex`].
pub fn header_work_hex(header: &BlockHeader) -> Result<String, RpcError> {
    let target = compact_to_target(header.bits)?;
    Ok(hex::encode(work_from_target(target).to_be_bytes()))
}

/// One input.
#[must_use]
pub fn tx_in_json(input: &ferrum_types::TxIn) -> TxInJson {
    let coinbase = input.prev_out.is_null();
    TxInJson {
        coinbase,
        txid: (!coinbase).then(|| input.prev_out.txid.to_hex()),
        vout: (!coinbase).then_some(input.prev_out.vout),
        script_sig: input.script_sig.to_hex(),
        sequence: input.sequence,
    }
}

/// One output.
#[must_use]
pub fn tx_out_json(index: u32, output: &ferrum_types::TxOut, network: Network) -> TxOutJson {
    TxOutJson {
        n: index,
        value: output.value.into(),
        script_pubkey: output.script_pubkey.to_hex(),
        script_type: script_type_name(&output.script_pubkey),
        address: address_string(&output.script_pubkey, network),
    }
}

/// The sum of a transaction's outputs, as a typed error rather than a wrap.
///
/// # Errors
/// [`RpcErrorCode::Overflow`] when the sum leaves the valid money range —
/// which `check_transaction_sanity` already rejects, so seeing it here means
/// the caller handed us something that never passed validation.
pub fn total_output(tx: &Transaction) -> Result<Amount, RpcError> {
    tx.total_output().ok_or_else(|| RpcError::overflow("transaction output sum"))
}

/// `sum(inputs) - sum(outputs)`, given the resolved funding coins.
///
/// Returns zero for a coinbase, whose "fee" is the subsidy and is reported as
/// its value instead. Returns zero when a funding coin could not be resolved,
/// which happens only on a node without the reverse index; the alternative —
/// refusing to render the page at all — is worse.
///
/// # Errors
/// [`RpcErrorCode::Overflow`] when either sum leaves the valid money range.
pub fn transaction_fee(tx: &Transaction, prevouts: &[Option<Coin>]) -> Result<Amount, RpcError> {
    if tx.is_coinbase() {
        return Ok(Amount::ZERO);
    }
    let mut inputs = Amount::ZERO;
    for coin in prevouts {
        let Some(coin) = coin else { return Ok(Amount::ZERO) };
        inputs = inputs
            .checked_add(coin.value)
            .ok_or_else(|| RpcError::overflow("transaction input sum"))?;
    }
    let outputs = total_output(tx)?;
    Ok(inputs.checked_sub(outputs).unwrap_or(Amount::ZERO))
}

/// Fee rate in grains per 1000 bytes, the unit every policy knob uses.
#[must_use]
pub fn fee_rate(fee: Amount, size: usize) -> u64 {
    if size == 0 {
        return 0;
    }
    let size = u64::try_from(size).unwrap_or(u64::MAX);
    fee.to_grains().saturating_mul(1_000).checked_div(size).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_crypto::{PublicKey, SecretKey};
    use ferrum_types::{CompactTarget, TxOut};

    use super::*;

    fn key(byte: u8) -> (SecretKey, PublicKey) {
        let secret = SecretKey::from_bytes(&[byte; 32]).unwrap();
        let public = secret.public_key();
        (secret, public)
    }

    #[test]
    fn difficulty_renders_three_decimal_places_without_a_float() {
        let limit = Target(ferrum_consensus::U256::from(1_000_000u64));
        assert_eq!(difficulty_string(limit, limit), "1.000");
        let harder = Target(ferrum_consensus::U256::from(500_000u64));
        assert_eq!(difficulty_string(harder, limit), "2.000");
        let slightly = Target(ferrum_consensus::U256::from(800_000u64));
        assert_eq!(difficulty_string(slightly, limit), "1.250");
    }

    #[test]
    fn engine_names_are_the_wire_tags() {
        assert_eq!(engine_name(0), "pow");
        assert_eq!(engine_name(1), "bft");
        assert_eq!(engine_name(7), "pow", "an unknown engine reads as proof of work");
    }

    #[test]
    fn confirmations_count_the_block_itself() {
        assert_eq!(confirmations(10, 10, true), 1);
        assert_eq!(confirmations(10, 0, true), 11);
        assert_eq!(confirmations(10, 4, false), 0, "a side-chain block has none");
        assert_eq!(confirmations(10, 11, true), 0);
    }

    #[test]
    fn p2pkh_scripts_yield_their_address() {
        let (_, public) = key(3);
        let address = Address::p2pkh(Network::Devnet, &public);
        let script = address.script_pubkey();
        assert_eq!(script_type_name(&script), "p2pkh");
        assert_eq!(address_of_script(&script, Network::Devnet), Some(address));
    }

    #[test]
    fn p2sh_scripts_yield_their_address() {
        let redeem = Script::new(vec![0x51]);
        let address = Address::p2sh(Network::Devnet, &redeem);
        let script = address.script_pubkey();
        assert_eq!(script_type_name(&script), "p2sh");
        assert_eq!(address_of_script(&script, Network::Devnet), Some(address));
    }

    #[test]
    fn a_bare_pubkey_is_filed_under_its_p2pkh_address() {
        let (_, public) = key(5);
        let script = templates::p2pk(&public);
        assert_eq!(script_type_name(&script), "p2pk");
        let address = address_of_script(&script, Network::Devnet).unwrap();
        // The same key the reverse index would use, so history and balance
        // agree.
        assert_eq!(address_index_key(&address), hash160(public.as_bytes()).to_vec());
        assert!(script_pays_key(&script, &address_index_key(&address)));
    }

    #[test]
    fn multi_key_scripts_have_no_single_address() {
        let (_, a) = key(7);
        let (_, b) = key(9);
        let script = templates::multisig(1, &[a, b]).unwrap();
        assert_eq!(script_type_name(&script), "multisig 1-of-2");
        assert_eq!(address_of_script(&script, Network::Devnet), None);
    }

    #[test]
    fn op_return_has_no_address() {
        let script = templates::op_return(b"ferrum").unwrap();
        assert_eq!(script_type_name(&script), "op_return");
        assert_eq!(address_of_script(&script, Network::Devnet), None);
    }

    #[test]
    fn an_address_from_the_wrong_network_is_refused() {
        let (_, public) = key(11);
        let mainnet = Address::p2pkh(Network::Mainnet, &public).encode();
        let err = parse_address(&mainnet, Network::Devnet).unwrap_err();
        assert_eq!(err.code(), RpcErrorCode::InvalidAddress);
        assert!(err.detail().contains("mainnet"));
    }

    #[test]
    fn a_malformed_address_is_refused() {
        let err = parse_address("rfer1notanaddress", Network::Devnet).unwrap_err();
        assert_eq!(err.code(), RpcErrorCode::InvalidAddress);
    }

    #[test]
    fn header_json_carries_the_nonce_as_a_string() {
        let header = BlockHeader {
            version: 1,
            prev_hash: BlockHash::ZERO,
            merkle_root: Hash32::ZERO,
            timestamp_ms: 1_700_000_000_000,
            bits: CompactTarget(0x1d00_ffff),
            nonce: u64::MAX,
        };
        let json = header_json(&header);
        assert_eq!(json.nonce.0, u64::MAX);
        let value = serde_json::to_value(&json).unwrap();
        assert!(value["nonce"].is_string(), "a u64 nonce would round as a JSON number");
        assert!(value["bits"].is_number(), "the explorer bit-shifts `bits`");
        assert!(value["timestamp_ms"].is_number());
    }

    #[test]
    fn fee_rate_is_grains_per_thousand_bytes() {
        assert_eq!(fee_rate(Amount::from_grains(1_000), 1_000), 1_000);
        assert_eq!(fee_rate(Amount::from_grains(250), 500), 500);
        assert_eq!(fee_rate(Amount::from_grains(1), 0), 0, "a zero size never divides");
    }

    #[test]
    fn an_unresolved_prevout_yields_a_zero_fee_rather_than_a_wrong_one() {
        let tx = Transaction {
            version: 1,
            inputs: vec![ferrum_types::TxIn::new(OutPoint::new(Txid::ZERO, 0), Script::EMPTY)],
            outputs: vec![TxOut::new(Amount::from_grains(10), Script::new(vec![0x51]))],
            lock_time: 0,
        };
        assert_eq!(transaction_fee(&tx, &[None]).unwrap(), Amount::ZERO);
    }

    #[test]
    fn outpoint_strings_are_txid_colon_vout() {
        let op = OutPoint::new(Txid::ZERO, 7);
        assert!(outpoint_string(&op).ends_with(":7"));
        assert_eq!(outpoint_string(&op).len(), 64 + 2);
    }
}
