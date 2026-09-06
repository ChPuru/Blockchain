//! The Ferrum wire protocol: gossip topics, gossip payloads and the
//! `/ferrum/sync/1.0.0` request/response frames (CONTRACT §10.2).
//!
//! Everything here is Borsh, decoded with `borsh::from_slice` so that a
//! trailing byte is a decode failure rather than silently ignored input. That
//! matters even outside consensus: the gossipsub message id is a hash of the
//! payload bytes, so two encodings of the same logical message would be two
//! messages on the mesh.
//!
//! This module is pure. It performs no I/O, holds no state and never touches a
//! clock, which is what lets the response caps be unit-tested without a swarm.

use borsh::{BorshDeserialize, BorshSerialize};
use ferrum_crypto::{TAG_P2P_MSGID, tagged_hash};
use ferrum_types::{Block, BlockHash, BlockHeader, ChainId, Transaction};
use libp2p::gossipsub::{IdentTopic, MessageId};

use crate::error::{P2pError, decode_error, encode_error};
use crate::limits;

/// The libp2p protocol name for block and header sync.
pub const SYNC_PROTOCOL: &str = "/ferrum/sync/1.0.0";

// ---------------------------------------------------------------------------
// Topics
// ---------------------------------------------------------------------------

/// Name of the block gossip topic for a chain: `ferrum/{chain_id}/blocks/v1`.
///
/// The chain id is in the topic so a testnet node and a mainnet node that
/// somehow dial each other still cannot exchange blocks.
pub fn blocks_topic_name(chain_id: ChainId) -> String {
    format!("ferrum/{}/blocks/v1", chain_id.0)
}

/// Name of the transaction gossip topic: `ferrum/{chain_id}/txs/v1`.
pub fn txs_topic_name(chain_id: ChainId) -> String {
    format!("ferrum/{}/txs/v1", chain_id.0)
}

/// The block gossip topic.
///
/// [`IdentTopic`] keeps the topic string on the wire rather than hashing it,
/// which makes a packet capture readable and costs nothing: the topic is not a
/// secret.
pub fn blocks_topic(chain_id: ChainId) -> IdentTopic {
    IdentTopic::new(blocks_topic_name(chain_id))
}

/// The transaction gossip topic.
pub fn txs_topic(chain_id: ChainId) -> IdentTopic {
    IdentTopic::new(txs_topic_name(chain_id))
}

// ---------------------------------------------------------------------------
// Message id
// ---------------------------------------------------------------------------

/// The gossipsub message id: a pure content hash of the payload.
///
/// libp2p defaults to `base58(source_peer) || sequence_number`, which gives the
/// same block two different ids when it arrives from two peers and produces
/// duplicate storms on any mesh wider than a couple of nodes. Hashing the
/// content instead makes the id a function of the message and nothing else, so
/// the duplicate cache actually deduplicates.
pub fn gossip_message_id(data: &[u8]) -> MessageId {
    MessageId::from(tagged_hash(TAG_P2P_MSGID, data).as_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Sync frames
// ---------------------------------------------------------------------------

/// A request on `/ferrum/sync/1.0.0`.
// The shared `Get` prefix is the contract's wire vocabulary (CONTRACT 10.2);
// renaming the variants to please the lint would change the protocol.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SyncRequest {
    /// Headers after the first locator hash we both know about.
    GetHeaders {
        /// Block locator, newest first, with exponentially growing gaps.
        locator: Vec<BlockHash>,
        /// Stop once this hash has been sent, if it is reached first.
        stop: Option<BlockHash>,
        /// How many headers the caller would like. Advisory: the server caps at
        /// [`limits::MAX_HEADERS_PER_RESPONSE`].
        max: u32,
    },
    /// Full blocks by hash.
    GetBlocks {
        /// The hashes wanted, in the order the caller wants them.
        hashes: Vec<BlockHash>,
    },
    /// The peer's current best tip.
    GetTip,
}

impl SyncRequest {
    /// A short static name for the variant, for error messages and metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            SyncRequest::GetHeaders { .. } => "GetHeaders",
            SyncRequest::GetBlocks { .. } => "GetBlocks",
            SyncRequest::GetTip => "GetTip",
        }
    }

    /// Borsh-encode the request.
    pub fn encode(&self) -> Result<Vec<u8>, P2pError> {
        borsh::to_vec(self).map_err(encode_error)
    }

    /// Borsh-decode a request, rejecting trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, P2pError> {
        borsh::from_slice(bytes).map_err(decode_error)
    }

    /// How many headers we will actually serve for this request.
    ///
    /// A request for `u32::MAX` headers is legal on the wire and yields
    /// [`limits::MAX_HEADERS_PER_RESPONSE`] headers, never more.
    pub fn effective_max_headers(&self) -> usize {
        match self {
            SyncRequest::GetHeaders { max, .. } => {
                usize::try_from(*max).unwrap_or(usize::MAX).min(limits::MAX_HEADERS_PER_RESPONSE)
            }
            _ => 0,
        }
    }

    /// Clamp a request received from a peer to sizes we are willing to process.
    ///
    /// This bounds the *server-side work*, which the response caps alone do
    /// not: a locator of ten million hashes is expensive to look up even if the
    /// answer is one header.
    pub fn clamped(self) -> Self {
        match self {
            SyncRequest::GetHeaders { mut locator, stop, max } => {
                locator.truncate(limits::MAX_LOCATOR_HASHES);
                let max =
                    max.min(u32::try_from(limits::MAX_HEADERS_PER_RESPONSE).unwrap_or(u32::MAX));
                SyncRequest::GetHeaders { locator, stop, max }
            }
            SyncRequest::GetBlocks { mut hashes } => {
                hashes.truncate(limits::MAX_REQUESTED_BLOCK_HASHES);
                SyncRequest::GetBlocks { hashes }
            }
            SyncRequest::GetTip => SyncRequest::GetTip,
        }
    }
}

/// A response on `/ferrum/sync/1.0.0`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SyncResponse {
    /// Headers in ascending height order, starting at the fork point.
    Headers(Vec<BlockHeader>),
    /// Full blocks, in the order they were requested.
    Blocks(Vec<Block>),
    /// The peer's tip.
    Tip {
        /// Hash of the peer's best block.
        hash: BlockHash,
        /// Height of the peer's best block.
        height: u64,
        /// Cumulative work at that tip, big-endian `U256`.
        work: [u8; 32],
    },
    /// The peer has nothing that satisfies the request.
    NotFound,
}

impl SyncResponse {
    /// A short static name for the variant, for error messages and metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            SyncResponse::Headers(_) => "Headers",
            SyncResponse::Blocks(_) => "Blocks",
            SyncResponse::Tip { .. } => "Tip",
            SyncResponse::NotFound => "NotFound",
        }
    }

    /// Borsh-encode the response.
    pub fn encode(&self) -> Result<Vec<u8>, P2pError> {
        borsh::to_vec(self).map_err(encode_error)
    }

    /// Borsh-decode a response, rejecting trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, P2pError> {
        borsh::from_slice(bytes).map_err(decode_error)
    }

    /// Apply the server-side caps of CONTRACT §10.2.
    ///
    /// This runs on **every** outbound response, after the node has produced
    /// it, so the cap holds regardless of what the peer asked for and
    /// regardless of what the node handed back. Headers are capped by count,
    /// blocks by count and by a byte budget, because 64 maximum-size blocks are
    /// 64 MB and no single response should be able to allocate that.
    pub fn capped(self) -> Self {
        match self {
            SyncResponse::Headers(mut headers) => {
                headers.truncate(limits::MAX_HEADERS_PER_RESPONSE);
                SyncResponse::Headers(headers)
            }
            SyncResponse::Blocks(blocks) => SyncResponse::Blocks(cap_blocks(blocks)),
            other => other,
        }
    }
}

/// Truncate a block vector to the count cap and the byte budget.
///
/// At least one block is always kept even if it alone exceeds the budget:
/// returning an empty response for a legal block would stall sync forever.
fn cap_blocks(mut blocks: Vec<Block>) -> Vec<Block> {
    blocks.truncate(limits::MAX_BLOCKS_PER_RESPONSE);

    let mut budget: usize = 0;
    let mut keep: usize = 0;
    for block in &blocks {
        let size = block.serialized_size();
        let next = budget.saturating_add(size);
        if keep > 0 && next > limits::MAX_RESPONSE_BODY_BYTES {
            break;
        }
        budget = next;
        keep = keep.saturating_add(1);
    }
    blocks.truncate(keep);
    blocks
}

// ---------------------------------------------------------------------------
// Gossip payloads
// ---------------------------------------------------------------------------

/// A payload on one of the two gossip topics.
///
/// `NewBlock` boxes the block because it is two orders of magnitude larger than
/// the other variants and every `GossipMessage` would otherwise be block-sized.
// The shared `New` prefix is the contract's wire vocabulary (CONTRACT 10.2).
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum GossipMessage {
    /// A newly accepted block, published on the blocks topic.
    NewBlock(Box<Block>),
    /// A transaction for the mempool, published on the txs topic.
    NewTransaction(Transaction),
    /// A tip announcement, published on the blocks topic. Cheap enough to send
    /// on every tip change and it lets a lagging peer start header sync without
    /// waiting for a full block.
    NewTip {
        /// Hash of the announced tip.
        hash: BlockHash,
        /// Height of the announced tip.
        height: u64,
    },
}

impl GossipMessage {
    /// A short static name for the variant, for logs and metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            GossipMessage::NewBlock(_) => "NewBlock",
            GossipMessage::NewTransaction(_) => "NewTransaction",
            GossipMessage::NewTip { .. } => "NewTip",
        }
    }

    /// Borsh-encode the payload.
    pub fn encode(&self) -> Result<Vec<u8>, P2pError> {
        borsh::to_vec(self).map_err(encode_error)
    }

    /// Borsh-decode a payload, rejecting trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, P2pError> {
        borsh::from_slice(bytes).map_err(decode_error)
    }

    /// The gossipsub message id this payload will have once encoded.
    pub fn message_id(&self) -> Result<MessageId, P2pError> {
        Ok(gossip_message_id(&self.encode()?))
    }

    /// Whether this payload belongs on the blocks topic (as opposed to txs).
    pub fn is_block_topic(&self) -> bool {
        match self {
            GossipMessage::NewBlock(_) | GossipMessage::NewTip { .. } => true,
            GossipMessage::NewTransaction(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_types::{
        Amount, BlockHeader, BlockSeal, CompactTarget, Hash32, OutPoint, Script, TxIn, TxOut,
    };

    fn header(nonce: u64) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_hash: BlockHash::from_bytes([7u8; 32]),
            merkle_root: Hash32::from_bytes([9u8; 32]),
            timestamp_ms: 1_700_000_000_000,
            bits: CompactTarget(0x1d00_ffff),
            nonce,
        }
    }

    fn tx(lock_time: u32) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint { txid: ferrum_types::Txid::from_bytes([3u8; 32]), vout: 0 },
                script_sig: Script::new(vec![0x51]),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: Amount::from_grains(50_000),
                script_pubkey: Script::new(vec![0x52]),
            }],
            lock_time,
        }
    }

    fn block(nonce: u64) -> Block {
        Block { header: header(nonce), txs: vec![tx(nonce as u32)], seal: BlockSeal::POW }
    }

    // ---- topics -----------------------------------------------------------

    #[test]
    fn topic_names_carry_the_chain_id() {
        assert_eq!(blocks_topic_name(ChainId(1)), "ferrum/1/blocks/v1");
        assert_eq!(txs_topic_name(ChainId(3)), "ferrum/3/txs/v1");
        assert_ne!(blocks_topic_name(ChainId(1)), blocks_topic_name(ChainId(2)));
    }

    #[test]
    fn topic_hashes_are_the_identity_of_the_name() {
        assert_eq!(blocks_topic(ChainId(2)).hash().as_str(), "ferrum/2/blocks/v1");
        assert_ne!(blocks_topic(ChainId(2)).hash(), txs_topic(ChainId(2)).hash());
    }

    // ---- message id -------------------------------------------------------

    #[test]
    fn message_id_is_a_pure_content_hash() {
        let a = gossip_message_id(b"same bytes");
        let b = gossip_message_id(b"same bytes");
        let c = gossip_message_id(b"other bytes");
        assert_eq!(a, b, "the id must depend only on the payload");
        assert_ne!(a, c);
        assert_eq!(a.0.len(), 32);
    }

    #[test]
    fn message_id_equals_the_domain_separated_tagged_hash() {
        let data = b"ferrum block payload";
        let expected = tagged_hash(TAG_P2P_MSGID, data).as_bytes().to_vec();
        assert_eq!(gossip_message_id(data).0, expected);
    }

    #[test]
    fn message_id_of_a_gossip_message_matches_its_encoding() {
        let msg = GossipMessage::NewBlock(Box::new(block(1)));
        let bytes = msg.encode().expect("encode");
        assert_eq!(msg.message_id().expect("id"), gossip_message_id(&bytes));
    }

    // ---- borsh round trips ------------------------------------------------

    #[test]
    fn sync_request_get_headers_round_trips() {
        let req = SyncRequest::GetHeaders {
            locator: vec![BlockHash::from_bytes([1u8; 32]), BlockHash::from_bytes([2u8; 32])],
            stop: Some(BlockHash::from_bytes([3u8; 32])),
            max: 2_000,
        };
        let bytes = req.encode().expect("encode");
        assert_eq!(SyncRequest::decode(&bytes).expect("decode"), req);
    }

    #[test]
    fn sync_request_get_headers_without_stop_round_trips() {
        let req = SyncRequest::GetHeaders { locator: vec![], stop: None, max: 1 };
        let bytes = req.encode().expect("encode");
        assert_eq!(SyncRequest::decode(&bytes).expect("decode"), req);
    }

    #[test]
    fn sync_request_get_blocks_round_trips() {
        let req = SyncRequest::GetBlocks { hashes: vec![BlockHash::from_bytes([4u8; 32])] };
        let bytes = req.encode().expect("encode");
        assert_eq!(SyncRequest::decode(&bytes).expect("decode"), req);
    }

    #[test]
    fn sync_request_get_tip_round_trips() {
        let bytes = SyncRequest::GetTip.encode().expect("encode");
        assert_eq!(SyncRequest::decode(&bytes).expect("decode"), SyncRequest::GetTip);
    }

    #[test]
    fn sync_response_headers_round_trips() {
        let resp = SyncResponse::Headers(vec![header(1), header(2), header(3)]);
        let bytes = resp.encode().expect("encode");
        assert_eq!(SyncResponse::decode(&bytes).expect("decode"), resp);
    }

    #[test]
    fn sync_response_blocks_round_trips() {
        let resp = SyncResponse::Blocks(vec![block(1), block(2)]);
        let bytes = resp.encode().expect("encode");
        assert_eq!(SyncResponse::decode(&bytes).expect("decode"), resp);
    }

    #[test]
    fn sync_response_tip_round_trips() {
        let resp = SyncResponse::Tip {
            hash: BlockHash::from_bytes([8u8; 32]),
            height: 4_242,
            work: [0xab; 32],
        };
        let bytes = resp.encode().expect("encode");
        assert_eq!(SyncResponse::decode(&bytes).expect("decode"), resp);
    }

    #[test]
    fn sync_response_not_found_round_trips() {
        let bytes = SyncResponse::NotFound.encode().expect("encode");
        assert_eq!(SyncResponse::decode(&bytes).expect("decode"), SyncResponse::NotFound);
    }

    #[test]
    fn gossip_new_block_round_trips() {
        let msg = GossipMessage::NewBlock(Box::new(block(11)));
        let bytes = msg.encode().expect("encode");
        assert_eq!(GossipMessage::decode(&bytes).expect("decode"), msg);
    }

    #[test]
    fn gossip_new_transaction_round_trips() {
        let msg = GossipMessage::NewTransaction(tx(17));
        let bytes = msg.encode().expect("encode");
        assert_eq!(GossipMessage::decode(&bytes).expect("decode"), msg);
    }

    #[test]
    fn gossip_new_tip_round_trips() {
        let msg = GossipMessage::NewTip { hash: BlockHash::from_bytes([5u8; 32]), height: 9 };
        let bytes = msg.encode().expect("encode");
        assert_eq!(GossipMessage::decode(&bytes).expect("decode"), msg);
    }

    #[test]
    fn decoding_rejects_trailing_bytes() {
        let mut bytes = SyncRequest::GetTip.encode().expect("encode");
        bytes.push(0);
        assert!(SyncRequest::decode(&bytes).is_err());

        let mut bytes = GossipMessage::NewTip { hash: BlockHash::from_bytes([1u8; 32]), height: 1 }
            .encode()
            .expect("encode");
        bytes.push(0xff);
        assert!(GossipMessage::decode(&bytes).is_err());
    }

    #[test]
    fn decoding_rejects_an_unknown_enum_discriminant() {
        assert!(SyncRequest::decode(&[0x7f]).is_err());
        assert!(GossipMessage::decode(&[0x7f]).is_err());
    }

    #[test]
    fn re_encoding_a_decoded_frame_is_byte_identical() {
        let resp = SyncResponse::Headers(vec![header(1), header(2)]);
        let bytes = resp.encode().expect("encode");
        let decoded = SyncResponse::decode(&bytes).expect("decode");
        assert_eq!(decoded.encode().expect("re-encode"), bytes);
    }

    // ---- caps -------------------------------------------------------------

    #[test]
    fn headers_are_capped_even_when_the_request_asked_for_more() {
        let over = limits::MAX_HEADERS_PER_RESPONSE + 500;
        let resp = SyncResponse::Headers((0..over as u64).map(header).collect());
        match resp.capped() {
            SyncResponse::Headers(h) => assert_eq!(h.len(), limits::MAX_HEADERS_PER_RESPONSE),
            other => panic!("wrong variant: {}", other.kind()),
        }
    }

    #[test]
    fn blocks_are_capped_even_when_the_request_asked_for_more() {
        let over = limits::MAX_BLOCKS_PER_RESPONSE + 100;
        let resp = SyncResponse::Blocks((0..over as u64).map(block).collect());
        match resp.capped() {
            SyncResponse::Blocks(b) => assert_eq!(b.len(), limits::MAX_BLOCKS_PER_RESPONSE),
            other => panic!("wrong variant: {}", other.kind()),
        }
    }

    #[test]
    fn a_short_response_is_left_alone_by_the_cap() {
        let resp = SyncResponse::Headers(vec![header(1)]);
        match resp.capped() {
            SyncResponse::Headers(h) => assert_eq!(h.len(), 1),
            other => panic!("wrong variant: {}", other.kind()),
        }
    }

    #[test]
    fn the_byte_budget_stops_before_the_count_cap_for_big_blocks() {
        // One "block" whose transactions push it over the whole budget.
        let mut fat = block(1);
        let filler = Script::new(vec![0u8; limits::MAX_RESPONSE_BODY_BYTES / 2]);
        fat.txs.push(Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut { value: Amount::ZERO, script_pubkey: filler }],
            lock_time: 0,
        });
        let capped = cap_blocks(vec![fat.clone(), fat.clone(), fat.clone(), fat]);
        assert!(capped.len() < 4, "the byte budget must bite before the count cap");
        assert!(!capped.is_empty(), "a legal block is never dropped entirely");
    }

    #[test]
    fn one_oversized_block_is_still_returned() {
        let mut huge = block(1);
        huge.txs.push(Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: Script::new(vec![0u8; limits::MAX_RESPONSE_BODY_BYTES + 1]),
            }],
            lock_time: 0,
        });
        assert_eq!(cap_blocks(vec![huge]).len(), 1);
    }

    #[test]
    fn tip_and_not_found_pass_the_cap_unchanged() {
        let tip = SyncResponse::Tip {
            hash: BlockHash::from_bytes([2u8; 32]),
            height: 1,
            work: [0u8; 32],
        };
        assert_eq!(tip.clone().capped(), tip);
        assert_eq!(SyncResponse::NotFound.capped(), SyncResponse::NotFound);
    }

    #[test]
    fn effective_max_headers_clamps_an_absurd_request() {
        let req = SyncRequest::GetHeaders { locator: vec![], stop: None, max: u32::MAX };
        assert_eq!(req.effective_max_headers(), limits::MAX_HEADERS_PER_RESPONSE);

        let req = SyncRequest::GetHeaders { locator: vec![], stop: None, max: 7 };
        assert_eq!(req.effective_max_headers(), 7);

        assert_eq!(SyncRequest::GetTip.effective_max_headers(), 0);
    }

    #[test]
    fn clamping_truncates_a_hostile_locator_and_hash_list() {
        let req = SyncRequest::GetHeaders {
            locator: vec![BlockHash::ZERO; limits::MAX_LOCATOR_HASHES + 50],
            stop: None,
            max: u32::MAX,
        };
        match req.clamped() {
            SyncRequest::GetHeaders { locator, max, .. } => {
                assert_eq!(locator.len(), limits::MAX_LOCATOR_HASHES);
                assert_eq!(max as usize, limits::MAX_HEADERS_PER_RESPONSE);
            }
            other => panic!("wrong variant: {}", other.kind()),
        }

        let req = SyncRequest::GetBlocks {
            hashes: vec![BlockHash::ZERO; limits::MAX_REQUESTED_BLOCK_HASHES + 9],
        };
        match req.clamped() {
            SyncRequest::GetBlocks { hashes } => {
                assert_eq!(hashes.len(), limits::MAX_REQUESTED_BLOCK_HASHES);
            }
            other => panic!("wrong variant: {}", other.kind()),
        }
    }

    #[test]
    fn kind_names_are_stable() {
        assert_eq!(SyncRequest::GetTip.kind(), "GetTip");
        assert_eq!(SyncResponse::NotFound.kind(), "NotFound");
        assert_eq!(GossipMessage::NewTransaction(tx(0)).kind(), "NewTransaction");
    }

    #[test]
    fn only_transactions_go_on_the_tx_topic() {
        assert!(GossipMessage::NewBlock(Box::new(block(1))).is_block_topic());
        assert!(GossipMessage::NewTip { hash: BlockHash::ZERO, height: 0 }.is_block_topic());
        assert!(!GossipMessage::NewTransaction(tx(0)).is_block_topic());
    }
}
