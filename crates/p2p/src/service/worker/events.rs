//! Swarm-event handling for the p2p worker.
//!
//! Split out of `worker.rs` to keep both halves readable: this one reacts to
//! what the network did, the other to what the node asked for.
//!
//! Two rules live here and nowhere else:
//!
//! - a gossip payload that does not decode, or that arrives on the wrong topic,
//!   is reported as [`MessageAcceptance::Reject`] immediately, which is what
//!   feeds gossipsub's P4 invalid-message score;
//! - a static peer whose dial fails has its backoff doubled, while one that was
//!   connected and then dropped is retried from the base delay;
//! - an inbound connection is refused when it would take this node over
//!   `max_peers` *distinct* peers or over
//!   [`limits::MAX_CONNECTIONS_PER_PEER`] connections from one identity. The
//!   second half is the one that bounds an attacker: `self.peers.len()`
//!   counts identities, so it never rises for a single keypair however often
//!   it dials.

use std::sync::Arc;

use libp2p::gossipsub::{MessageAcceptance, MessageId};
use libp2p::swarm::SwarmEvent;
use libp2p::{PeerId, Swarm, gossipsub, identify, ping, request_response};
use tokio::time::Instant;

use super::Worker;
use crate::behaviour::{FerrumBehaviour, FerrumBehaviourEvent};
use crate::error::P2pError;
use crate::limits;
use crate::message::{GossipMessage, SyncRequest, SyncResponse};
use crate::service::{P2pEvent, SyncResponder, reconnect_backoff};

impl Worker {
    pub(super) fn handle_swarm_event(
        &mut self,
        swarm: &mut Swarm<FerrumBehaviour>,
        event: SwarmEvent<FerrumBehaviourEvent>,
    ) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!(%address, "listening");
                self.emit(P2pEvent::Listening { address });
            }

            SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                let address = endpoint.get_remote_address().clone();
                let record = self.peers.entry(peer_id).or_default();
                record.connections = record.connections.saturating_add(1);
                record.address = Some(address.clone());
                let connections = record.connections;
                let first = connections == 1;

                for peer in &mut self.static_peers {
                    if peer.dialing == Some(connection_id) || peer.peer_id == Some(peer_id) {
                        peer.dialing = None;
                        peer.connected_as = Some(peer_id);
                        peer.failures = 0;
                    }
                }

                // Both ceilings are evaluated here, before the `first`
                // shortcut. Evaluating only on a peer's *first* connection is
                // what let one identity hold an unbounded number of them:
                // `self.peers.len()` counts identities, so it does not move
                // when the same peer dials again.
                let refusal = self.refuse_connection(&peer_id, connections, first);
                if let Some(reason) = refusal {
                    tracing::warn!(
                        %peer_id,
                        peers = self.peers.len(),
                        max_peers = self.max_peers,
                        connections,
                        max_per_peer = limits::MAX_CONNECTIONS_PER_PEER,
                        reason,
                        "refusing a connection"
                    );
                    swarm.close_connection(connection_id);
                    return;
                }

                if !first {
                    return;
                }
                tracing::debug!(%peer_id, %address, "peer connected");
                self.emit(P2pEvent::PeerConnected { peer: peer_id, address });
            }

            SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                if num_established > 0 {
                    if let Some(record) = self.peers.get_mut(&peer_id) {
                        record.connections = num_established;
                    }
                    return;
                }
                self.peers.remove(&peer_id);
                let now = Instant::now();
                let base = self.base_backoff;
                for peer in &mut self.static_peers {
                    if peer.connected_as == Some(peer_id) || peer.peer_id == Some(peer_id) {
                        peer.connected_as = None;
                        peer.dialing = None;
                        // A peer that was up and went away is retried from the
                        // base delay, not from wherever the backoff had climbed.
                        peer.failures = 0;
                        peer.next_attempt = now + base;
                    }
                }
                tracing::debug!(%peer_id, "peer disconnected");
                self.emit(P2pEvent::PeerDisconnected { peer: peer_id });
            }

            SwarmEvent::OutgoingConnectionError { connection_id, error, .. } => {
                let now = Instant::now();
                let base = self.base_backoff;
                let max = self.max_backoff;
                for peer in &mut self.static_peers {
                    if peer.dialing != Some(connection_id) {
                        continue;
                    }
                    peer.dialing = None;
                    peer.failures = peer.failures.saturating_add(1);
                    let delay = reconnect_backoff(peer.failures, base, max);
                    peer.next_attempt = now + delay;
                    tracing::warn!(
                        addr = %peer.addr,
                        failures = peer.failures,
                        backoff_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                        error = %error,
                        "static peer dial failed; backing off"
                    );
                }
            }

            SwarmEvent::Behaviour(FerrumBehaviourEvent::Gossipsub(event)) => {
                self.handle_gossipsub(swarm, *event);
            }
            SwarmEvent::Behaviour(FerrumBehaviourEvent::Sync(event)) => self.handle_sync(*event),
            SwarmEvent::Behaviour(FerrumBehaviourEvent::Identify(event)) => {
                self.handle_identify(*event);
            }
            SwarmEvent::Behaviour(FerrumBehaviourEvent::Ping(event)) => self.handle_ping(event),

            other => tracing::trace!(?other, "swarm event"),
        }
    }

    /// Why a newly established connection must be closed, if it must.
    ///
    /// A configured static peer is never refused: the operator asked for it,
    /// and refusing it would make the node unable to reach the network it was
    /// told to join.
    fn refuse_connection(
        &self,
        peer_id: &PeerId,
        connections: u32,
        first: bool,
    ) -> Option<&'static str> {
        if self.is_static(peer_id) {
            return None;
        }
        if connections > limits::MAX_CONNECTIONS_PER_PEER {
            return Some("too many connections from one peer id");
        }
        // The peer ceiling counts identities, so it can only be crossed by a
        // peer that is new to the map.
        if first && self.peers.len() > self.max_peers {
            return Some("peer limit reached");
        }
        None
    }

    /// Report a message as invalid and tell the node why.
    ///
    /// `Reject` rather than `Ignore` on purpose: it is what feeds gossipsub's
    /// P4 invalid-message score, and a peer that sends undecodable frames is
    /// exactly the peer whose score should fall.
    fn reject_gossip(
        &self,
        swarm: &mut Swarm<FerrumBehaviour>,
        msg_id: &MessageId,
        peer: &PeerId,
        topic: String,
        reason: String,
    ) {
        let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
            msg_id,
            peer,
            MessageAcceptance::Reject,
        );
        tracing::warn!(%peer, %msg_id, %topic, %reason, "rejecting a gossip message");
        self.emit(P2pEvent::InvalidGossip { peer: *peer, msg_id: msg_id.clone(), topic, reason });
    }

    fn handle_gossipsub(&mut self, swarm: &mut Swarm<FerrumBehaviour>, event: gossipsub::Event) {
        match event {
            gossipsub::Event::Message { propagation_source, message_id, message } => {
                let on_blocks = message.topic == self.blocks_topic;
                let on_txs = message.topic == self.txs_topic;
                let topic = message.topic.to_string();

                if !on_blocks && !on_txs {
                    self.reject_gossip(
                        swarm,
                        &message_id,
                        &propagation_source,
                        topic,
                        "message on a topic we never subscribed to".to_owned(),
                    );
                    return;
                }

                match GossipMessage::decode(&message.data) {
                    Ok(decoded) => {
                        if decoded.is_block_topic() != on_blocks {
                            let reason = format!("a {} is not valid on this topic", decoded.kind());
                            self.reject_gossip(
                                swarm,
                                &message_id,
                                &propagation_source,
                                topic,
                                reason,
                            );
                            return;
                        }
                        tracing::trace!(
                            peer = %propagation_source,
                            kind = decoded.kind(),
                            "gossip received"
                        );
                        self.emit(P2pEvent::Gossip {
                            peer: propagation_source,
                            msg_id: message_id,
                            topic,
                            message: Box::new(decoded),
                        });
                    }
                    Err(error) => {
                        self.reject_gossip(
                            swarm,
                            &message_id,
                            &propagation_source,
                            topic,
                            error.to_string(),
                        );
                    }
                }
            }
            gossipsub::Event::Subscribed { peer_id, topic } => {
                tracing::debug!(%peer_id, %topic, "peer subscribed");
            }
            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                tracing::debug!(%peer_id, %topic, "peer unsubscribed");
            }
            gossipsub::Event::GossipsubNotSupported { peer_id } => {
                tracing::debug!(%peer_id, "peer does not speak gossipsub");
            }
            gossipsub::Event::SlowPeer { peer_id, failed_messages } => {
                tracing::warn!(%peer_id, ?failed_messages, "peer cannot keep up with the mesh");
            }
        }
    }

    fn handle_sync(&mut self, event: request_response::Event<SyncRequest, SyncResponse>) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request { request, channel, .. } => {
                    if self.pending_inbound.len() >= limits::MAX_PENDING_INBOUND_REQUESTS {
                        let shed = self.counters.shed_inbound_request();
                        tracing::warn!(
                            %peer,
                            parked = self.pending_inbound.len(),
                            shed_total = shed,
                            "too many inbound sync requests parked; shedding"
                        );
                        drop(channel);
                        return;
                    }

                    let id = self.next_id();
                    self.pending_inbound.insert(id, channel);
                    let responder = SyncResponder {
                        id,
                        peer,
                        commands: self.responder_commands.clone(),
                        counters: Arc::clone(&self.counters),
                        answered: false,
                    };
                    let event = P2pEvent::InboundRequest { peer, request, responder };
                    if let Some(P2pEvent::InboundRequest { mut responder, .. }) =
                        self.emit_or_return(event)
                    {
                        // The node never saw it, so unpark it here and suppress
                        // the responder's cancel: the entry is already gone.
                        self.pending_inbound.remove(&id);
                        responder.answered = true;
                    }
                }
                request_response::Message::Response { request_id, response } => {
                    match self.pending_outbound.remove(&request_id) {
                        Some(pending) => pending.fulfil(response),
                        None => tracing::debug!(%peer, "response for an unknown request"),
                    }
                }
            },
            request_response::Event::OutboundFailure { peer, request_id, error, .. } => {
                if let Some(pending) = self.pending_outbound.remove(&request_id) {
                    pending.fail(P2pError::Request {
                        peer: peer.to_string(),
                        reason: error.to_string(),
                    });
                }
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                tracing::debug!(%peer, %error, "inbound sync request failed");
            }
            request_response::Event::ResponseSent { peer, .. } => {
                tracing::trace!(%peer, "sync response sent");
            }
        }
    }

    fn handle_identify(&mut self, event: identify::Event) {
        match event {
            identify::Event::Received { peer_id, info, .. } => {
                if let Some(record) = self.peers.get_mut(&peer_id) {
                    record.agent_version = Some(info.agent_version.clone());
                    record.protocol_version = Some(info.protocol_version.clone());
                }
                tracing::debug!(%peer_id, agent = %info.agent_version, "peer identified");
            }
            identify::Event::Sent { peer_id, .. } => {
                tracing::trace!(%peer_id, "identify sent");
            }
            identify::Event::Pushed { peer_id, .. } => {
                tracing::trace!(%peer_id, "identify pushed");
            }
            identify::Event::Error { peer_id, error, .. } => {
                tracing::debug!(%peer_id, %error, "identify failed");
            }
        }
    }

    fn handle_ping(&mut self, event: ping::Event) {
        match event.result {
            // Integer milliseconds: no float may appear in this workspace.
            Ok(rtt) => {
                let ms = u64::try_from(rtt.as_millis()).unwrap_or(u64::MAX);
                if let Some(record) = self.peers.get_mut(&event.peer) {
                    record.last_rtt_ms = Some(ms);
                }
            }
            Err(failure) => {
                tracing::debug!(peer = %event.peer, %failure, "ping failed");
            }
        }
    }
}
