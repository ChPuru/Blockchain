//! The composed `NetworkBehaviour` for a Ferrum node.
//!
//! Four protocols, and deliberately no more:
//!
//! - **gossipsub** for block and transaction propagation, tuned by
//!   [`crate::P2pConfig::gossipsub_config`].
//! - **request-response** over `/ferrum/sync/1.0.0` for headers and bodies.
//! - **identify** so `getpeerinfo` can report an agent string, and so a peer's
//!   listen addresses are known for redialling.
//! - **ping** for liveness, which is the cheapest way to notice a black-holed
//!   TCP connection.
//!
//! There is **no Kademlia, no mDNS, no AutoNAT, no relay and no DCUtR**. Those
//! protocols exist to make permissionless discovery survive an adversary;
//! Ferrum's peers come from a config file, so the whole category of attack is
//! absent and the code that would defend against it is absent too. See
//! `docs/DECISIONS.md` D6.

use std::fmt;

use libp2p::identity::Keypair;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::{StreamProtocol, gossipsub, identify, ping};

use crate::codec::SyncCodec;
use crate::config::P2pConfig;
use crate::error::P2pError;
use crate::message::SYNC_PROTOCOL;

/// The sync protocol as a libp2p [`StreamProtocol`].
pub const SYNC_STREAM_PROTOCOL: StreamProtocol = StreamProtocol::new(SYNC_PROTOCOL);

/// The behaviours a Ferrum node speaks.
#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(to_swarm = "FerrumBehaviourEvent")]
pub struct FerrumBehaviour {
    /// Block and transaction gossip.
    pub gossipsub: gossipsub::Behaviour,
    /// Header and block sync over `/ferrum/sync/1.0.0`.
    pub sync: request_response::Behaviour<SyncCodec>,
    /// Peer identification.
    pub identify: identify::Behaviour,
    /// Liveness.
    pub ping: ping::Behaviour,
}

// The inner behaviours do not implement `Debug`, so a derive is impossible; the
// workspace still requires one on every public type. Naming the fields without
// dumping their state is what a `Debug` on a live swarm behaviour could
// usefully print anyway.
impl fmt::Debug for FerrumBehaviour {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FerrumBehaviour")
            .field("protocols", &["gossipsub", SYNC_PROTOCOL, "identify", "ping"])
            .finish_non_exhaustive()
    }
}

impl FerrumBehaviour {
    /// Build the behaviour and subscribe to both gossip topics for
    /// `config.chain_id`.
    ///
    /// Subscription happens here rather than in the service loop so that a
    /// topic-name mistake is a construction error rather than a node that runs
    /// happily and never sees a block.
    pub fn new(keypair: &Keypair, config: &P2pConfig) -> Result<Self, P2pError> {
        let gossip_config = config.gossipsub_config()?;

        // Signed messages: the author and sequence number are covered by a
        // signature, which is what ValidationMode::Strict requires.
        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossip_config,
        )
        .map_err(|e| P2pError::Behaviour(e.to_string()))?;

        let blocks = config.blocks_topic();
        let txs = config.txs_topic();
        gossipsub.subscribe(&blocks).map_err(|e| P2pError::Subscribe {
            topic: blocks.hash().into_string(),
            reason: e.to_string(),
        })?;
        gossipsub.subscribe(&txs).map_err(|e| P2pError::Subscribe {
            topic: txs.hash().into_string(),
            reason: e.to_string(),
        })?;

        let sync = request_response::Behaviour::with_codec(
            SyncCodec::new(),
            [(SYNC_STREAM_PROTOCOL, ProtocolSupport::Full)],
            config.request_response_config(),
        );

        Ok(FerrumBehaviour {
            gossipsub,
            sync,
            identify: identify::Behaviour::new(config.identify_config()),
            ping: ping::Behaviour::new(config.ping_config()),
        })
    }
}

/// The event type produced by [`FerrumBehaviour`].
///
/// Written out by hand rather than generated so that every variant is
/// documented and the large `identify::Event` can be boxed.
#[derive(Debug)]
pub enum FerrumBehaviourEvent {
    /// A gossipsub event: a message, a subscription change, or a slow peer.
    Gossipsub(Box<gossipsub::Event>),
    /// A sync request, response, or failure.
    Sync(Box<request_response::Event<crate::message::SyncRequest, crate::message::SyncResponse>>),
    /// An identify exchange.
    Identify(Box<identify::Event>),
    /// A ping result.
    Ping(ping::Event),
}

impl From<gossipsub::Event> for FerrumBehaviourEvent {
    fn from(e: gossipsub::Event) -> Self {
        FerrumBehaviourEvent::Gossipsub(Box::new(e))
    }
}

impl From<request_response::Event<crate::message::SyncRequest, crate::message::SyncResponse>>
    for FerrumBehaviourEvent
{
    fn from(
        e: request_response::Event<crate::message::SyncRequest, crate::message::SyncResponse>,
    ) -> Self {
        FerrumBehaviourEvent::Sync(Box::new(e))
    }
}

impl From<identify::Event> for FerrumBehaviourEvent {
    fn from(e: identify::Event) -> Self {
        FerrumBehaviourEvent::Identify(Box::new(e))
    }
}

impl From<ping::Event> for FerrumBehaviourEvent {
    fn from(e: ping::Event) -> Self {
        FerrumBehaviourEvent::Ping(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_types::ChainId;

    #[test]
    fn the_behaviour_builds_and_subscribes_to_both_topics() {
        let config = P2pConfig::new(ChainId(3));
        let behaviour =
            FerrumBehaviour::new(&config.keypair, &config).expect("behaviour must build");

        let topics: Vec<String> =
            behaviour.gossipsub.topics().map(|t| t.as_str().to_owned()).collect();
        assert!(topics.contains(&"ferrum/3/blocks/v1".to_owned()), "topics were {topics:?}");
        assert!(topics.contains(&"ferrum/3/txs/v1".to_owned()), "topics were {topics:?}");
        assert_eq!(topics.len(), 2, "no other topic is subscribed");
    }

    #[test]
    fn topics_follow_the_configured_chain_id() {
        let config = P2pConfig::new(ChainId(1));
        let behaviour = FerrumBehaviour::new(&config.keypair, &config).expect("build");
        let topics: Vec<String> =
            behaviour.gossipsub.topics().map(|t| t.as_str().to_owned()).collect();
        assert!(topics.contains(&"ferrum/1/blocks/v1".to_owned()));
        assert!(!topics.contains(&"ferrum/3/blocks/v1".to_owned()));
    }

    #[test]
    fn the_sync_protocol_name_is_the_contract_name() {
        assert_eq!(SYNC_STREAM_PROTOCOL.as_ref(), "/ferrum/sync/1.0.0");
        assert_eq!(SYNC_PROTOCOL, "/ferrum/sync/1.0.0");
    }

    #[test]
    fn debug_names_the_protocols_without_dumping_state() {
        let config = P2pConfig::default();
        let behaviour = FerrumBehaviour::new(&config.keypair, &config).expect("build");
        let rendered = format!("{behaviour:?}");
        assert!(rendered.contains("gossipsub"));
        assert!(rendered.contains("/ferrum/sync/1.0.0"));
    }

    #[test]
    fn behaviour_events_convert_from_each_inner_event() {
        let ev: FerrumBehaviourEvent =
            gossipsub::Event::GossipsubNotSupported { peer_id: libp2p::PeerId::random() }.into();
        assert!(matches!(ev, FerrumBehaviourEvent::Gossipsub(_)));

        let ev: FerrumBehaviourEvent = ping::Event {
            peer: libp2p::PeerId::random(),
            connection: libp2p::swarm::ConnectionId::new_unchecked(0),
            result: Ok(std::time::Duration::from_millis(3)),
        }
        .into();
        assert!(matches!(ev, FerrumBehaviourEvent::Ping(_)));
    }
}
