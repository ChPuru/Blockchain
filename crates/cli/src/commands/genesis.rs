//! `chain-cli genesis mine` — grind a genesis block for a new network.
//!
//! `RUNNING.md` §4 tells an operator to run this, put the nonce into their
//! `ChainParams` and publish the hash. CONTRACT §13.1 fixes the last line of
//! stdout as `nonce=<n> hash=<hex>`, so that is exactly what comes out.
//!
//! # The nonce is inside the block it seals
//!
//! Ferrum's genesis coinbase pays a provably unspendable `OP_RETURN` whose
//! payload is `genesis_commitment(params)` — a hash over every consensus
//! parameter *including `genesis_nonce`* (`ferrum_chain::genesis`). Without
//! that commitment mainnet and testnet, which differ only in chain id and
//! address prefix, would produce the same genesis hash and a testnet node
//! could complete a header handshake with a mainnet peer.
//!
//! It also means the search is not the usual "bump the nonce and re-hash the
//! header": changing the nonce changes the commitment, which changes the
//! coinbase, which changes the Merkle root. Each candidate is therefore built
//! from scratch. That is slower per try, and it is the only way the result
//! matches what a node will independently compute from the parameters alone.

use ferrum_chain::{build_coinbase_script_sig, compute_merkle_root, genesis_message};
use ferrum_consensus::{compact_to_target, hash_meets_target};
use ferrum_storage::header_hash;
use ferrum_types::{
    Block, BlockHash, BlockHeader, BlockSeal, ChainParams, CompactTarget, Transaction, TxIn, TxOut,
};
use serde_json::json;

use crate::error::{CliError, CliResult};
use crate::output::CommandOutput;
use crate::paths::parse_network;

/// Header version of a genesis block, matching `ferrum_chain::GENESIS_VERSION`.
pub const GENESIS_VERSION: u32 = ferrum_chain::GENESIS_VERSION;

/// `genesis mine`.
///
/// # Errors
///
/// [`CliError::Invalid`] for an unknown network, an unusable `--bits` or a
/// message that will not fit a coinbase `script_sig`, and
/// [`CliError::NotFound`] when `--max-tries` is exhausted.
pub fn mine(
    network: &str,
    message: Option<&str>,
    timestamp: Option<u64>,
    bits: Option<&str>,
    start_nonce: u64,
    max_tries: u64,
) -> CliResult<CommandOutput> {
    let mut params = parse_network(network)?.params();
    if let Some(ms) = timestamp {
        params.genesis_timestamp_ms = ms;
    }
    if let Some(text) = bits {
        params.genesis_bits = parse_bits(text)?;
    }
    let message = message.map_or_else(|| genesis_message(&params), str::to_owned);
    let target = compact_to_target(params.genesis_bits)?;

    // Fail on an impossible message before grinding rather than after.
    build_coinbase(&params, &message)?;

    let mut nonce = start_nonce;
    let mut tried: u64 = 0;
    while tried < max_tries {
        params.genesis_nonce = nonce;
        let (coinbase, header) = candidate(&params, &message)?;
        let hash = header_hash(&header);
        if hash_meets_target(&hash, target) {
            let block = Block::new(header, vec![coinbase], BlockSeal::POW);
            return Ok(found(&params, &message, &block, &hash, tried.saturating_add(1)));
        }
        nonce = nonce.wrapping_add(1);
        tried = tried.saturating_add(1);
    }

    Err(CliError::not_found(format!(
        "no genesis nonce satisfied bits {:#010x} in {max_tries} tries from {start_nonce}",
        params.genesis_bits.to_u32()
    )))
}

/// The output for a solved genesis.
fn found(
    params: &ChainParams,
    message: &str,
    block: &Block,
    hash: &BlockHash,
    tries: u64,
) -> CommandOutput {
    let header = &block.header;
    CommandOutput::empty()
        .with_bare(format!("nonce={} hash={}", header.nonce, hash))
        .with_json(json!({
            "nonce": header.nonce.to_string(),
            "hash": hash.to_string(),
            "network": params.network.name(),
            "chain_id": params.chain_id.to_u32(),
            "message": message,
            "timestamp_ms": header.timestamp_ms,
            "bits": header.bits.to_u32(),
            "merkle_root": header.merkle_root.to_hex(),
            "version": header.version,
            "tries": tries,
            "block_hex": hex::encode(borsh_block(block)),
        }))
        .with_field("network", params.network.name())
        .with_field("message", message)
        .with_field("timestamp", header.timestamp_ms)
        .with_field("bits", format!("{:#010x}", header.bits.to_u32()))
        .with_field("merkle root", header.merkle_root.to_hex())
        .with_field("tries", tries)
}

/// `borsh(Block)`, or an empty vector if it will not serialise.
///
/// A block that has just been built from valid components always serialises;
/// returning empty rather than propagating keeps a display-only field from
/// turning a solved genesis into an error.
fn borsh_block(block: &Block) -> Vec<u8> {
    borsh::to_vec(block).unwrap_or_default()
}

/// Parse `--bits` as hex (`0x1d00ffff` or `1d00ffff`) or decimal.
fn parse_bits(text: &str) -> CliResult<CompactTarget> {
    let trimmed = text.trim();
    let value = if let Some(body) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(body, 16)
            .map_err(|e| CliError::invalid("--bits", text, e.to_string()))?
    } else if trimmed.len() == 8 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        u32::from_str_radix(trimmed, 16)
            .map_err(|e| CliError::invalid("--bits", text, e.to_string()))?
    } else {
        trimmed.parse::<u32>().map_err(|e| CliError::invalid("--bits", text, e.to_string()))?
    };
    let bits = CompactTarget(value);
    // Reject the negative and zero-mantissa forms here rather than after a
    // fruitless grind.
    compact_to_target(bits)?;
    Ok(bits)
}

/// The genesis coinbase for these parameters and this message.
fn build_coinbase(params: &ChainParams, message: &str) -> CliResult<Transaction> {
    let script_sig = build_coinbase_script_sig(0, message.as_bytes()).map_err(|e| {
        CliError::invalid("--message", message, format!("{e}; keep it under about 95 bytes"))
    })?;
    Ok(Transaction {
        version: GENESIS_VERSION,
        inputs: vec![TxIn::coinbase(script_sig)],
        outputs: vec![TxOut::new(
            params.block_subsidy(0),
            ferrum_chain::genesis_script_pubkey(params),
        )],
        lock_time: 0,
    })
}

/// One candidate: the coinbase and the header that commits to it.
fn candidate(params: &ChainParams, message: &str) -> CliResult<(Transaction, BlockHeader)> {
    let coinbase = build_coinbase(params, message)?;
    let header = BlockHeader {
        version: GENESIS_VERSION,
        prev_hash: BlockHash::ZERO,
        merkle_root: compute_merkle_root(std::slice::from_ref(&coinbase)),
        timestamp_ms: params.genesis_timestamp_ms,
        bits: params.genesis_bits,
        nonce: params.genesis_nonce,
    };
    Ok((coinbase, header))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ferrum_types::Network;

    #[test]
    fn devnet_genesis_is_found_and_satisfies_its_own_target() {
        let out = mine("devnet", None, None, None, 0, 1 << 20).unwrap();
        let bare = out.bare.clone().unwrap();
        assert!(bare.starts_with("nonce="), "{bare}");
        assert!(bare.contains(" hash="), "{bare}");

        let hash = BlockHash::from_hex(out.json["hash"].as_str().unwrap()).unwrap();
        let bits = CompactTarget(u32::try_from(out.json["bits"].as_u64().unwrap()).unwrap());
        assert!(hash_meets_target(&hash, compact_to_target(bits).unwrap()));
    }

    #[test]
    fn the_default_message_reproduces_the_block_a_node_computes() {
        // With no overrides the grinder must land on exactly the genesis
        // `ferrum_chain` derives from the same parameters, or a freshly
        // launched node would disagree with the value published in the README.
        let params = Network::Devnet.params();
        let out = mine("devnet", None, None, None, params.genesis_nonce, 1).unwrap();
        assert_eq!(out.json["hash"], ferrum_chain::genesis_hash(&params).to_string());
        assert_eq!(
            out.json["merkle_root"],
            ferrum_chain::genesis_header(&params).merkle_root.to_hex()
        );
    }

    #[test]
    fn a_custom_message_changes_the_hash() {
        let plain = mine("devnet", None, None, None, 0, 1 << 20).unwrap();
        let custom = mine("devnet", Some("hello ferrum"), None, None, 0, 1 << 20).unwrap();
        assert_ne!(plain.json["hash"], custom.json["hash"]);
        assert_eq!(custom.json["message"], "hello ferrum");
    }

    #[test]
    fn a_custom_timestamp_changes_the_hash() {
        let a = mine("devnet", None, Some(1_700_000_000_000), None, 0, 1 << 20).unwrap();
        let b = mine("devnet", None, Some(1_700_000_001_000), None, 0, 1 << 20).unwrap();
        assert_ne!(a.json["hash"], b.json["hash"]);
        assert_eq!(a.json["timestamp_ms"], 1_700_000_000_000_u64);
    }

    #[test]
    fn each_network_grinds_a_different_genesis() {
        // The `OP_RETURN` commitment is what stops two networks that differ
        // only in chain id from sharing a genesis hash.
        let dev = mine("devnet", None, None, None, 0, 1 << 20).unwrap();
        assert_eq!(dev.json["chain_id"], 3);
    }

    #[test]
    fn exhausting_the_budget_is_an_error_not_a_wrong_answer() {
        // Mainnet's target is far out of reach in one try.
        let err = mine("mainnet", None, None, None, 0, 1).unwrap_err();
        assert!(err.to_string().contains("no genesis nonce"), "{err}");
    }

    #[test]
    fn bits_parse_in_hex_with_and_without_a_prefix_and_in_decimal() {
        assert_eq!(parse_bits("0x207fffff").unwrap().to_u32(), 0x207f_ffff);
        assert_eq!(parse_bits("207fffff").unwrap().to_u32(), 0x207f_ffff);
        assert_eq!(parse_bits("545259519").unwrap().to_u32(), 0x207f_ffff);
    }

    #[test]
    fn a_negative_compact_target_is_refused_before_grinding() {
        // Mantissa bit 0x00800000 set is the negative form (CONTRACT §6.1).
        assert!(parse_bits("0x20800000").is_err());
    }

    #[test]
    fn an_oversized_message_is_refused_by_name() {
        let err = mine("devnet", Some(&"x".repeat(200)), None, None, 0, 1).unwrap_err();
        assert!(err.to_string().contains("--message"), "{err}");
    }

    #[test]
    fn the_solved_block_serialises() {
        let out = mine("devnet", None, None, None, 0, 1 << 20).unwrap();
        let hex_body = out.json["block_hex"].as_str().unwrap();
        assert!(!hex_body.is_empty());
        let raw = hex::decode(hex_body).unwrap();
        let block: Block = borsh::from_slice(&raw).unwrap();
        assert_eq!(block.seal.engine, BlockSeal::ENGINE_POW);
        assert!(block.txs[0].is_coinbase());
    }
}
