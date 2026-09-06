//! The genesis block, computed from [`ChainParams`] rather than trusted from a
//! file (SPEC §2).
//!
//! A node that read its genesis block out of a file would believe whatever the
//! file said. Ferrum computes it, and compares the result against the hash
//! published in `RUNNING.md`. A node whose computed genesis differs from its
//! peers' cannot sync with them, which is the intended outcome: that is the
//! check working, not the check failing.
//!
//! # Shape
//!
//! ```text
//! version      = 1
//! prev_hash    = 0x00 * 32
//! merkle_root  = merkle_root([txid(genesis_coinbase)])
//! timestamp_ms = params.genesis_timestamp_ms
//! bits         = params.genesis_bits
//! nonce        = params.genesis_nonce
//! seal         = BlockSeal::POW
//! ```
//!
//! The coinbase has one input (`OutPoint::NULL`) whose `script_sig` is the
//! BIP-34 push of height `0` followed by an ASCII message, and **one output
//! that is provably unspendable** (`OP_RETURN`). The genesis subsidy is
//! therefore burned, exactly as Bitcoin's is. That is not ceremony: an
//! unspendable genesis output removes a special case from the UTXO set and
//! removes any question about a premine.
//!
//! # Why the output commits to the parameters
//!
//! Mainnet and testnet differ only in `chain_id` and address prefix — every
//! structural and monetary rule is shared. Without something network-specific
//! inside the genesis block, the two would produce the *same* genesis hash and
//! a testnet node could complete a header handshake with a mainnet peer. The
//! `OP_RETURN` payload is [`genesis_commitment`], a `TAG_GENESIS` hash over the
//! consensus-critical parameters, so a difference anywhere in them is a
//! different genesis block and an immediate, loud disagreement.

use ferrum_crypto::{TAG_GENESIS, tagged_hash};
use ferrum_script::Opcode;
use ferrum_storage::header_hash;
use ferrum_types::{
    Block, BlockHash, BlockHeader, BlockSeal, ChainParams, Hash32, Script, Transaction, TxIn, TxOut,
};

use crate::validate::{build_coinbase_script_sig, compute_merkle_root};

/// The ASCII message in every Ferrum genesis coinbase, before the network
/// name is appended.
pub const GENESIS_MESSAGE_PREFIX: &str = "Ferrum v1 genesis";

/// Block version of the genesis header.
pub const GENESIS_VERSION: u32 = 1;

/// The ASCII message this network's genesis coinbase carries.
///
/// The network name is part of it so that the message a human reads in a block
/// explorer says which chain they are looking at.
#[must_use]
pub fn genesis_message(params: &ChainParams) -> String {
    format!("{GENESIS_MESSAGE_PREFIX} {}", params.network.name())
}

/// A commitment to the consensus-critical fields of `params`.
///
/// `tagged_hash(TAG_GENESIS, ...)` over an explicitly little-endian encoding of
/// every parameter two nodes must agree on. Written out field by field rather
/// than derived, so that adding a field to [`ChainParams`] that does not belong
/// in consensus cannot silently change every network's genesis hash.
#[must_use]
pub fn genesis_commitment(params: &ChainParams) -> Hash32 {
    let mut buf: Vec<u8> = Vec::with_capacity(128);
    buf.extend_from_slice(&params.chain_id.to_u32().to_le_bytes());
    buf.extend_from_slice(&params.target_spacing_ms.to_le_bytes());
    buf.extend_from_slice(&params.asert_halflife_s.to_le_bytes());
    buf.extend_from_slice(&params.pow_limit);
    buf.extend_from_slice(&params.initial_subsidy.to_grains().to_le_bytes());
    buf.extend_from_slice(&params.halving_interval.to_le_bytes());
    buf.extend_from_slice(&params.coinbase_maturity.to_le_bytes());
    buf.extend_from_slice(&u64::try_from(params.max_block_size).unwrap_or(u64::MAX).to_le_bytes());
    buf.extend_from_slice(
        &u64::try_from(params.median_time_span).unwrap_or(u64::MAX).to_le_bytes(),
    );
    buf.extend_from_slice(&params.genesis_timestamp_ms.to_le_bytes());
    buf.extend_from_slice(&params.genesis_bits.to_u32().to_le_bytes());
    buf.extend_from_slice(&params.genesis_nonce.to_le_bytes());
    tagged_hash(TAG_GENESIS, &buf)
}

/// The provably unspendable genesis output script: `OP_RETURN <commitment>`.
///
/// Built byte by byte rather than through `templates::op_return` so that
/// genesis construction is infallible: a 32-byte payload is far inside the
/// 80-byte `OP_RETURN` limit, and a `Result` here would put an error path in
/// the one function every node runs before it can do anything else.
#[must_use]
pub fn genesis_script_pubkey(params: &ChainParams) -> Script {
    let commitment = genesis_commitment(params);
    let mut bytes = Vec::with_capacity(34);
    bytes.push(Opcode::Return.to_byte());
    bytes.push(0x20); // minimal direct push of 32 bytes
    bytes.extend_from_slice(commitment.as_bytes());
    Script::new(bytes)
}

/// The genesis coinbase transaction.
#[must_use]
pub fn genesis_coinbase(params: &ChainParams) -> Transaction {
    let message = genesis_message(params);
    // `build_coinbase_script_sig` only fails outside the 2..=100 byte window,
    // and "Ferrum v1 genesis <network>" plus two push headers is 27 bytes. The
    // fallback keeps the function total without an unwrap.
    let script_sig = build_coinbase_script_sig(0, message.as_bytes())
        .unwrap_or_else(|_| Script::new(vec![0x00, 0x00]));
    Transaction {
        version: GENESIS_VERSION,
        inputs: vec![TxIn::coinbase(script_sig)],
        // The subsidy is claimed and immediately burned: the script can never
        // be satisfied, so the coin exists in the UTXO set and can never move.
        outputs: vec![TxOut::new(params.block_subsidy(0), genesis_script_pubkey(params))],
        lock_time: 0,
    }
}

/// The genesis header for `params`.
#[must_use]
pub fn genesis_header(params: &ChainParams) -> BlockHeader {
    let coinbase = genesis_coinbase(params);
    BlockHeader {
        version: GENESIS_VERSION,
        prev_hash: BlockHash::ZERO,
        merkle_root: compute_merkle_root(std::slice::from_ref(&coinbase)),
        timestamp_ms: params.genesis_timestamp_ms,
        bits: params.genesis_bits,
        nonce: params.genesis_nonce,
    }
}

/// The whole genesis block for `params`.
#[must_use]
pub fn genesis_block(params: &ChainParams) -> Block {
    Block::new(genesis_header(params), vec![genesis_coinbase(params)], BlockSeal::POW)
}

/// The genesis block hash for `params`.
///
/// This is the value published in `RUNNING.md` and the value a node compares
/// its datadir against on startup.
#[must_use]
pub fn genesis_hash(params: &ChainParams) -> BlockHash {
    header_hash(&genesis_header(params))
}
