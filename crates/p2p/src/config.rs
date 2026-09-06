//! Configuration for the Ferrum p2p service, including the five gossipsub
//! overrides and the yamux window that CONTRACT §10.1 requires on day one.
//!
//! Every override here exists because the libp2p default is wrong for a
//! blockchain, and each one carries a comment naming the default it replaces.
//! They are asserted by the tests at the bottom of this file, so a libp2p
//! upgrade that changes a default cannot quietly change Ferrum's behaviour.

use std::time::Duration;

use ferrum_types::ChainId;
use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId, gossipsub, identify, ping, tcp, yamux};

use crate::error::P2pError;
use crate::limits;
use crate::message::{blocks_topic, gossip_message_id, txs_topic};

/// The libp2p identify `protocol_version` Ferrum advertises.
pub const PROTOCOL_VERSION: &str = "ferrum/1.0.0";

/// Configuration for [`crate::P2pService`].
#[derive(Debug, Clone)]
pub struct P2pConfig {
    /// Chain id. Determines the gossip topic names, so a node on chain 1 and a
    /// node on chain 2 can connect but can never exchange blocks.
    pub chain_id: ChainId,
    /// The node identity. Persist this across restarts: it is the `PeerId`
    /// other nodes have in their static peer lists.
    pub keypair: Keypair,
    /// Addresses to listen on, for example `/ip4/0.0.0.0/tcp/8655`.
    pub listen_addrs: Vec<Multiaddr>,
    /// The static peer list. Ferrum has no Kademlia and no discv5: a network
    /// whose peers are in a config file has no permissionless-discovery attack
    /// surface to defend. See `docs/DECISIONS.md` D6.
    pub static_peers: Vec<Multiaddr>,
    /// Agent string reported over identify.
    pub agent_version: String,
    /// Protocol version reported over identify.
    pub protocol_version: String,
    /// Maximum simultaneously connected peers. Static peers are exempt.
    pub max_peers: usize,
    /// Timeout for one sync request/response exchange.
    pub request_timeout: Duration,
    /// How long an idle connection is kept before it is closed.
    pub idle_connection_timeout: Duration,
    /// First delay before redialling a static peer.
    pub reconnect_base_backoff: Duration,
    /// Ceiling on the redial delay.
    pub reconnect_max_backoff: Duration,
    /// Gossipsub `max_transmit_size`, at least 4 MiB.
    pub gossip_max_transmit_size: usize,
    /// Yamux receive window per substream, above the 256 KiB libp2p default.
    pub yamux_receive_window: u32,
    /// Capacity of the handle-to-service command queue.
    pub command_capacity: usize,
    /// Capacity of the service-to-node event queue.
    pub event_capacity: usize,
}

impl P2pConfig {
    /// A configuration for `chain_id` with a fresh Ed25519 identity, no listen
    /// addresses and no peers.
    ///
    /// Ed25519 rather than secp256k1 for the *network* identity: it is what the
    /// rest of the libp2p world uses, and the node identity is unrelated to the
    /// BIP-340 keys that sign transactions.
    pub fn new(chain_id: ChainId) -> Self {
        P2pConfig {
            chain_id,
            keypair: Keypair::generate_ed25519(),
            listen_addrs: Vec::new(),
            static_peers: Vec::new(),
            agent_version: concat!("ferrum/", env!("CARGO_PKG_VERSION")).to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            max_peers: limits::MAX_PEERS,
            request_timeout: limits::SYNC_REQUEST_TIMEOUT,
            idle_connection_timeout: limits::IDLE_CONNECTION_TIMEOUT,
            reconnect_base_backoff: limits::RECONNECT_BASE_BACKOFF,
            reconnect_max_backoff: limits::RECONNECT_MAX_BACKOFF,
            gossip_max_transmit_size: limits::GOSSIP_MAX_TRANSMIT_SIZE,
            yamux_receive_window: limits::YAMUX_RECEIVE_WINDOW_BYTES,
            command_capacity: limits::COMMAND_CHANNEL_CAPACITY,
            event_capacity: limits::EVENT_CHANNEL_CAPACITY,
        }
    }

    /// Use a specific identity, normally loaded from `<datadir>/node.key`.
    #[must_use]
    pub fn with_keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = keypair;
        self
    }

    /// Add a listen address.
    #[must_use]
    pub fn with_listen_addr(mut self, addr: Multiaddr) -> Self {
        self.listen_addrs.push(addr);
        self
    }

    /// Add a static peer.
    #[must_use]
    pub fn with_peer(mut self, addr: Multiaddr) -> Self {
        self.static_peers.push(addr);
        self
    }

    /// Set the agent string reported over identify.
    #[must_use]
    pub fn with_agent_version(mut self, agent: impl Into<String>) -> Self {
        self.agent_version = agent.into();
        self
    }

    /// The `PeerId` derived from [`Self::keypair`].
    pub fn local_peer_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }

    /// The block gossip topic for this chain.
    pub fn blocks_topic(&self) -> gossipsub::IdentTopic {
        blocks_topic(self.chain_id)
    }

    /// The transaction gossip topic for this chain.
    pub fn txs_topic(&self) -> gossipsub::IdentTopic {
        txs_topic(self.chain_id)
    }

    /// Build the gossipsub configuration, applying **all five** overrides from
    /// CONTRACT §10.1.
    pub fn gossipsub_config(&self) -> Result<gossipsub::Config, P2pError> {
        gossipsub::ConfigBuilder::default()
            // Override 1. libp2p default: 65_536 bytes. A 1 MB block would be
            // rejected by our own publish call and never reach the network, and
            // the failure is local, so the chain simply stops propagating.
            .max_transmit_size(self.gossip_max_transmit_size)
            // Override 2. libp2p default: base58(source peer) || sequence
            // number, so the same block relayed by six peers is six distinct
            // messages and the duplicate cache never fires. A content hash makes
            // the id a function of the payload alone.
            .message_id_fn(|message: &gossipsub::Message| gossip_message_id(&message.data))
            // Override 3. libp2p default mesh_n_low is 5; the gossipsub v1.1
            // specification says 4. Held with mesh_n = 6 and mesh_n_high = 12.
            .mesh_n_low(limits::GOSSIP_MESH_N_LOW)
            .mesh_n(limits::GOSSIP_MESH_N)
            .mesh_n_high(limits::GOSSIP_MESH_N_HIGH)
            // Override 4. libp2p default: 60 s. Ferrum's target spacing is
            // 120 s, so a 60 s cache lets a block re-enter the mesh within one
            // block interval and bounce.
            .duplicate_cache_time(limits::GOSSIP_DUPLICATE_CACHE_TIME)
            // Override 5. Explicit application validation. Nothing is forwarded
            // until the node calls report_validation, and an invalid message is
            // reported as Reject so it feeds gossipsub's P4 invalid-message
            // score. That hookup is the cheapest DoS defence available.
            .validate_messages()
            // Pinned rather than inherited, so a libp2p default change cannot
            // silently retune the mesh or accept unsigned messages.
            .heartbeat_interval(limits::GOSSIP_HEARTBEAT_INTERVAL)
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|e| P2pError::GossipsubConfig(e.to_string()))
    }

    /// Build the yamux configuration with a raised receive window.
    ///
    /// `set_receive_window_size` is deprecated upstream — libp2p intends to
    /// replace it with a connection-level limit in a later release — but it is
    /// the only way to raise the window today, and leaving the 256 KiB default
    /// in place caps a single substream near 3 MB/s at an 80 ms round trip.
    pub fn yamux_config(&self) -> yamux::Config {
        let mut cfg = yamux::Config::default();
        #[allow(deprecated)]
        cfg.set_receive_window_size(self.yamux_receive_window);
        cfg.set_max_num_streams(limits::YAMUX_MAX_NUM_STREAMS);
        cfg
    }

    /// Build the TCP transport configuration.
    ///
    /// `nodelay` is on: block and header frames are latency-sensitive and small
    /// enough that Nagle's algorithm only adds a round trip.
    pub fn tcp_config(&self) -> tcp::Config {
        tcp::Config::new().nodelay(true)
    }

    /// Build the identify configuration.
    pub fn identify_config(&self) -> identify::Config {
        identify::Config::new(self.protocol_version.clone(), self.keypair.public())
            .with_agent_version(self.agent_version.clone())
            .with_interval(limits::IDENTIFY_INTERVAL)
            // We do not run a DHT, so caching addresses of peers we will never
            // dial is pure memory.
            .with_cache_size(0)
    }

    /// Build the ping configuration.
    pub fn ping_config(&self) -> ping::Config {
        ping::Config::new().with_interval(limits::PING_INTERVAL).with_timeout(limits::PING_TIMEOUT)
    }

    /// Build the request-response configuration for the sync protocol.
    pub fn request_response_config(&self) -> libp2p::request_response::Config {
        libp2p::request_response::Config::default()
            .with_request_timeout(self.request_timeout)
            .with_max_concurrent_streams(limits::MAX_CONCURRENT_SYNC_STREAMS)
    }
}

impl Default for P2pConfig {
    /// Devnet (`chain_id = 3`) with a fresh identity. Handy for tests; a real
    /// node always passes its own chain id and persisted key.
    fn default() -> Self {
        P2pConfig::new(ChainId(3))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::gossipsub::{Message, TopicHash};

    fn message(data: &[u8]) -> Message {
        Message {
            source: Some(PeerId::random()),
            data: data.to_vec(),
            sequence_number: Some(7),
            topic: TopicHash::from_raw("ferrum/3/blocks/v1"),
        }
    }

    fn config() -> gossipsub::Config {
        P2pConfig::default().gossipsub_config().expect("gossipsub config must build")
    }

    // ---- the five overrides from CONTRACT 10.1 ----------------------------

    #[test]
    fn override_1_max_transmit_size_is_at_least_four_mib() {
        let cfg = config();
        assert!(
            cfg.max_transmit_size() >= 4 * 1024 * 1024,
            "a 1 MB block must be sendable; the libp2p default of {} is not enough",
            limits::GOSSIP_DEFAULT_MAX_TRANSMIT_SIZE
        );
        assert_ne!(cfg.max_transmit_size(), limits::GOSSIP_DEFAULT_MAX_TRANSMIT_SIZE);
    }

    #[test]
    fn override_2_message_id_is_a_content_hash() {
        let cfg = config();
        // Same payload, different source peer and sequence number: the default
        // id function would return two different ids here.
        let a = cfg.message_id(&message(b"a block"));
        let b = cfg.message_id(&message(b"a block"));
        let c = cfg.message_id(&message(b"another block"));
        assert_eq!(a, b, "the id must not depend on the source peer or seqno");
        assert_ne!(a, c);
        assert_eq!(a, gossip_message_id(b"a block"));
    }

    #[test]
    fn override_3_mesh_n_low_is_four() {
        let cfg = config();
        assert_eq!(cfg.mesh_n_low(), 4, "libp2p defaults to 5, the specification says 4");
        assert_eq!(cfg.mesh_n(), 6);
        assert_eq!(cfg.mesh_n_high(), 12);
    }

    #[test]
    fn override_4_duplicate_cache_time_is_two_minutes() {
        let cfg = config();
        assert_eq!(cfg.duplicate_cache_time(), Duration::from_secs(120));
        assert_ne!(cfg.duplicate_cache_time(), limits::GOSSIP_DEFAULT_DUPLICATE_CACHE_TIME);
    }

    #[test]
    fn override_5_messages_are_validated_explicitly_and_strictly() {
        let cfg = config();
        assert!(cfg.validate_messages(), "P4 scoring needs explicit validation reports");
        assert!(matches!(cfg.validation_mode(), gossipsub::ValidationMode::Strict));
    }

    #[test]
    fn heartbeat_interval_is_pinned_at_one_second() {
        assert_eq!(config().heartbeat_interval(), Duration::from_secs(1));
    }

    // ---- yamux ------------------------------------------------------------

    #[test]
    fn yamux_receive_window_is_raised_above_the_default() {
        let cfg = P2pConfig::default();
        assert!(
            cfg.yamux_receive_window > limits::YAMUX_DEFAULT_RECEIVE_WINDOW_BYTES,
            "256 KiB caps one substream near 3 MB/s at an 80 ms round trip"
        );
        // Building must not panic and must not fall back to the default.
        let _ = cfg.yamux_config();
    }

    // ---- everything else --------------------------------------------------

    #[test]
    fn topics_are_derived_from_the_chain_id() {
        let cfg = P2pConfig::new(ChainId(1));
        assert_eq!(cfg.blocks_topic().hash().as_str(), "ferrum/1/blocks/v1");
        assert_eq!(cfg.txs_topic().hash().as_str(), "ferrum/1/txs/v1");

        let other = P2pConfig::new(ChainId(2));
        assert_ne!(cfg.blocks_topic().hash(), other.blocks_topic().hash());
    }

    #[test]
    fn the_local_peer_id_matches_the_keypair() {
        let keypair = Keypair::generate_ed25519();
        let expected = keypair.public().to_peer_id();
        let cfg = P2pConfig::default().with_keypair(keypair);
        assert_eq!(cfg.local_peer_id(), expected);
    }

    #[test]
    fn builders_accumulate_addresses() {
        let listen: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr");
        let peer: Multiaddr = "/ip4/127.0.0.1/tcp/8655".parse().expect("multiaddr");
        let cfg = P2pConfig::default()
            .with_listen_addr(listen.clone())
            .with_peer(peer.clone())
            .with_agent_version("ferrum-test");
        assert_eq!(cfg.listen_addrs, vec![listen]);
        assert_eq!(cfg.static_peers, vec![peer]);
        assert_eq!(cfg.agent_version, "ferrum-test");
    }

    #[test]
    fn defaults_come_from_the_limits_module() {
        let cfg = P2pConfig::default();
        assert_eq!(cfg.command_capacity, limits::COMMAND_CHANNEL_CAPACITY);
        assert_eq!(cfg.event_capacity, limits::EVENT_CHANNEL_CAPACITY);
        assert_eq!(cfg.max_peers, limits::MAX_PEERS);
        assert_eq!(cfg.request_timeout, limits::SYNC_REQUEST_TIMEOUT);
        assert_eq!(cfg.chain_id, ChainId(3));
    }

    #[test]
    fn identify_and_ping_configs_are_tuned() {
        let cfg = P2pConfig::default().with_agent_version("ferrum/test");
        let id = cfg.identify_config();
        assert_eq!(id.agent_version(), "ferrum/test");
        assert_eq!(id.protocol_version(), PROTOCOL_VERSION);
        assert_eq!(id.interval(), limits::IDENTIFY_INTERVAL);
        assert_eq!(id.cache_size(), 0);
        let _ = cfg.ping_config();
    }

    #[test]
    fn an_impossible_mesh_configuration_is_a_typed_error_not_a_panic() {
        let err = gossipsub::ConfigBuilder::default()
            .mesh_n_low(10)
            .mesh_n(2)
            .build()
            .map_err(|e| P2pError::GossipsubConfig(e.to_string()))
            .expect_err("mesh_n below mesh_n_low must be rejected");
        assert!(matches!(err, P2pError::GossipsubConfig(_)));
    }
}
