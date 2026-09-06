//! Ferrum's networking stack: TCP + Noise + Yamux, gossipsub, and a
//! request/response sync protocol (CONTRACT §10, SPEC §11).
//!
//! # What this crate is
//!
//! Transport, and only transport. It moves bytes between peers, enforces every
//! wire limit and feeds gossip validation verdicts back into peer scoring. It
//! does not validate a block, does not touch a store and does not drive sync;
//! all of that lives in the node, which talks to this crate through
//! [`P2pHandle`] and [`P2pEvent`].
//!
//! # The decisions worth knowing about
//!
//! - **The deprecated stream multiplexer is never offered.** Noise and Yamux
//!   only. The libp2p specification deprecates that multiplexer for liveness
//!   problems, and a fallback that is offered is a fallback that eventually
//!   gets negotiated. A source audit asserts its name occurs nowhere in this
//!   crate.
//! - **Five gossipsub defaults are overridden**, each for a concrete reason and
//!   each asserted by a test: transmit size, message id, `mesh_n_low`,
//!   duplicate cache time, and explicit validation. See
//!   [`P2pConfig::gossipsub_config`].
//! - **The message id is a content hash**, `tagged_hash(TAG_P2P_MSGID, data)`.
//!   The libp2p default of `base58(peer) || seqno` gives the same block a
//!   different id from every relay, which is a duplicate storm.
//! - **The yamux receive window is raised** from 256 KiB, which otherwise caps
//!   one substream near 3 MB/s at an 80 ms round trip.
//! - **No unbounded queue exists.** Every queue has a capacity constant in
//!   [`limits`] and sheds with a `tracing::warn!` and a counter when full. A
//!   source audit asserts tokio's unbounded constructor is never named in this
//!   crate.
//! - **Response caps are server-side**: 2000 headers and 64 blocks, applied to
//!   every outbound response regardless of what the peer asked for.
//! - **Peer discovery is a static list** with exponential reconnect backoff. No
//!   Kademlia, no discv5, no mDNS: those defend permissionless discovery, and
//!   a network whose peers come from a config file has nothing to defend.
//!
//! # Example
//!
//! ```no_run
//! use ferrum_p2p::{P2pConfig, P2pEvent, P2pService};
//! use ferrum_types::ChainId;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let config = P2pConfig::new(ChainId(3))
//!     .with_listen_addr("/ip4/127.0.0.1/tcp/0".parse()?);
//!
//! let (handle, task) = P2pService::spawn(config)?;
//! let mut events = handle.events()?;
//!
//! while let Some(event) = events.recv().await {
//!     if let P2pEvent::Gossip { peer, msg_id, message, .. } = event {
//!         // ... validate `message`, then feed the verdict back into scoring:
//!         handle.report_validation(msg_id, peer, ferrum_p2p::MessageAcceptance::Accept)?;
//!     }
//! }
//! task.await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

pub mod behaviour;
pub mod codec;
pub mod config;
pub mod error;
pub mod limits;
pub mod message;
pub mod service;

pub use crate::behaviour::{FerrumBehaviour, FerrumBehaviourEvent, SYNC_STREAM_PROTOCOL};
pub use crate::codec::SyncCodec;
pub use crate::config::{P2pConfig, PROTOCOL_VERSION};
pub use crate::error::P2pError;
pub use crate::message::{
    GossipMessage, SYNC_PROTOCOL, SyncRequest, SyncResponse, blocks_topic, blocks_topic_name,
    gossip_message_id, txs_topic, txs_topic_name,
};
pub use crate::service::{
    P2pEvent, P2pHandle, P2pService, PeerInfo, RequestId, ShedCounters, ShedCounts, SyncResponder,
    TipInfo, peer_id_from_multiaddr, reconnect_backoff,
};

// The libp2p types that appear in this crate's public API, re-exported so the
// node does not have to depend on libp2p directly to use them.
pub use libp2p::gossipsub::{MessageAcceptance, MessageId};
pub use libp2p::identity::Keypair;
pub use libp2p::{Multiaddr, PeerId};

#[cfg(test)]
mod source_audit {
    //! Two rules from the contract are properties of the *source text*, not of
    //! any runtime value, so they are asserted against the source text.
    //!
    //! The needles are assembled from fragments so that this test file does not
    //! itself contain the strings it forbids.

    // `lib.rs` is included: the audit is only meaningful if it covers every
    // source file in the crate, prose included.
    const SOURCES: &[(&str, &str)] = &[
        ("lib.rs", include_str!("lib.rs")),
        ("behaviour.rs", include_str!("behaviour.rs")),
        ("codec.rs", include_str!("codec.rs")),
        ("config.rs", include_str!("config.rs")),
        ("error.rs", include_str!("error.rs")),
        ("limits.rs", include_str!("limits.rs")),
        ("message.rs", include_str!("message.rs")),
        ("service.rs", include_str!("service.rs")),
        ("service/worker.rs", include_str!("service/worker.rs")),
        ("service/worker/events.rs", include_str!("service/worker/events.rs")),
    ];

    #[test]
    fn the_deprecated_multiplexer_appears_nowhere_in_this_crate() {
        let needle = concat!("mp", "lex");
        for (name, source) in SOURCES {
            assert!(
                !source.contains(needle),
                "{name} mentions the deprecated multiplexer; Noise and Yamux only"
            );
        }
    }

    #[test]
    fn no_unbounded_queue_is_constructed_in_this_crate() {
        let needle = concat!("unbounded_", "channel");
        for (name, source) in SOURCES {
            assert!(
                !source.contains(needle),
                "{name} creates an unbounded queue; every queue needs a capacity from limits.rs"
            );
        }
    }

    #[test]
    fn no_non_deterministic_collection_in_this_crate() {
        for needle in [concat!("Hash", "Map"), concat!("Hash", "Set")] {
            for (name, source) in SOURCES {
                assert!(
                    !source.contains(needle),
                    "{name} uses {needle}; iteration order must be deterministic"
                );
            }
        }
    }

    #[test]
    fn no_floating_point_types_in_this_crate() {
        for needle in [concat!("f", "64"), concat!("f", "32")] {
            for (name, source) in SOURCES {
                assert!(!source.contains(needle), "{name} mentions {needle}");
            }
        }
    }

    #[test]
    fn every_source_file_stays_under_the_size_budget() {
        for (name, source) in SOURCES {
            let lines = source.lines().count();
            assert!(lines < 760, "{name} is {lines} lines; split it into modules");
        }
    }
}
