//! Typed errors for the Ferrum p2p stack.
//!
//! Nothing in this crate panics on a remote input: every decode failure, every
//! oversized frame and every full queue becomes one of these variants. The enum
//! is `#[non_exhaustive]` so that adding a failure mode is not a breaking change
//! for the node.

use std::io;

/// Everything that can go wrong in the networking layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum P2pError {
    /// The libp2p transport could not be built (Noise keys, TCP binding).
    #[error("failed to build the libp2p transport: {0}")]
    Transport(String),

    /// A `NetworkBehaviour` could not be constructed.
    #[error("failed to build the network behaviour: {0}")]
    Behaviour(String),

    /// The gossipsub `ConfigBuilder` rejected our overrides.
    #[error("invalid gossipsub configuration: {0}")]
    GossipsubConfig(String),

    /// Binding a listen address failed.
    #[error("failed to listen on {addr}: {reason}")]
    Listen {
        /// The multiaddress we tried to bind.
        addr: String,
        /// The transport-level reason.
        reason: String,
    },

    /// Borsh refused to encode a value. In practice only an allocation failure.
    #[error("borsh encoding failed: {0}")]
    Encode(String),

    /// Borsh refused to decode bytes from a peer, trailing bytes included.
    #[error("borsh decoding failed: {0}")]
    Decode(String),

    /// A length-prefixed frame exceeded its cap. This is a hard protocol error:
    /// we do not attempt to read the body.
    #[error("frame of {size} bytes exceeds the {max}-byte limit")]
    FrameTooLarge {
        /// The advertised or actual frame size.
        size: usize,
        /// The configured limit.
        max: usize,
    },

    /// The swarm task has exited, so no command can be delivered.
    #[error("the p2p service has stopped")]
    ServiceStopped,

    /// A bounded queue was full and the message was shed rather than queued.
    #[error("the {queue} queue is full; the message was shed")]
    QueueFull {
        /// Name of the queue, for the operator reading the log line.
        queue: &'static str,
    },

    /// Gossipsub refused to publish.
    #[error("publishing to topic {topic} failed: {reason}")]
    Publish {
        /// The topic name.
        topic: String,
        /// The gossipsub reason, for example `InsufficientPeers`.
        reason: String,
    },

    /// Gossipsub refused a subscription.
    #[error("subscribing to topic {topic} failed: {reason}")]
    Subscribe {
        /// The topic name.
        topic: String,
        /// The gossipsub reason.
        reason: String,
    },

    /// An outbound sync request failed at the transport level.
    #[error("sync request to peer {peer} failed: {reason}")]
    Request {
        /// The peer we asked.
        peer: String,
        /// Dial failure, timeout, unsupported protocol, connection closed.
        reason: String,
    },

    /// A peer answered a request with the wrong response variant. Treated as a
    /// protocol violation rather than an empty answer.
    #[error("peer {peer} answered a {expected} request with {got}")]
    UnexpectedResponse {
        /// The peer that misbehaved.
        peer: String,
        /// The request kind we sent.
        expected: &'static str,
        /// The response variant we got back.
        got: &'static str,
    },

    /// Too many sync requests are already in flight.
    #[error("too many sync requests already in flight ({in_flight})")]
    TooManyInFlight {
        /// Number of requests currently awaiting a response.
        in_flight: usize,
    },

    /// [`crate::P2pHandle::events`] was called more than once. The event stream
    /// is single-consumer by construction.
    #[error("the p2p event stream has already been taken")]
    EventsAlreadyTaken,

    /// Dialling a peer failed.
    #[error("dialling {addr} failed: {reason}")]
    Dial {
        /// The multiaddress dialled.
        addr: String,
        /// The dial error.
        reason: String,
    },

    /// A configured multiaddress could not be parsed or used.
    #[error("invalid multiaddress: {0}")]
    InvalidMultiaddr(String),

    /// An I/O error on a substream.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
}

impl P2pError {
    /// Whether this failure is worth retrying against the same peer.
    ///
    /// The node uses this to decide between backing off and dropping a peer: a
    /// full queue or a missing mesh peer is transient, a decode failure is not.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            P2pError::QueueFull { .. }
                | P2pError::Publish { .. }
                | P2pError::Request { .. }
                | P2pError::TooManyInFlight { .. }
                | P2pError::Dial { .. }
                | P2pError::Io(_)
        )
    }

    /// Whether this failure means the remote peer violated the protocol, and so
    /// should have its gossip score lowered or be disconnected.
    pub fn is_peer_fault(&self) -> bool {
        matches!(
            self,
            P2pError::Decode(_)
                | P2pError::FrameTooLarge { .. }
                | P2pError::UnexpectedResponse { .. }
        )
    }
}

/// Convert a Borsh I/O error from a decode into a [`P2pError::Decode`].
pub(crate) fn decode_error(e: impl std::fmt::Display) -> P2pError {
    P2pError::Decode(e.to_string())
}

/// Convert a Borsh I/O error from an encode into a [`P2pError::Encode`].
pub(crate) fn encode_error(e: impl std::fmt::Display) -> P2pError {
    P2pError::Encode(e.to_string())
}

impl From<P2pError> for io::Error {
    fn from(e: P2pError) -> Self {
        match e {
            P2pError::Io(inner) => inner,
            P2pError::FrameTooLarge { .. } => io::Error::new(io::ErrorKind::InvalidData, e),
            P2pError::Decode(_) => io::Error::new(io::ErrorKind::InvalidData, e),
            other => io::Error::other(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_too_large_is_a_peer_fault_not_transient() {
        let e = P2pError::FrameTooLarge { size: 99, max: 10 };
        assert!(e.is_peer_fault());
        assert!(!e.is_transient());
        assert!(e.to_string().contains("99"));
    }

    #[test]
    fn queue_full_is_transient_not_a_peer_fault() {
        let e = P2pError::QueueFull { queue: "events" };
        assert!(e.is_transient());
        assert!(!e.is_peer_fault());
        assert!(e.to_string().contains("events"));
    }

    #[test]
    fn frame_too_large_maps_to_invalid_data() {
        let io_err: io::Error = P2pError::FrameTooLarge { size: 1, max: 0 }.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn io_errors_round_trip_through_the_conversion() {
        let original = io::Error::new(io::ErrorKind::UnexpectedEof, "short read");
        let wrapped: P2pError = original.into();
        let unwrapped: io::Error = wrapped.into();
        assert_eq!(unwrapped.kind(), io::ErrorKind::UnexpectedEof);
    }
}
