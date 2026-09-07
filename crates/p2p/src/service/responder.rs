//! [`SyncResponder`] — the reply channel for one inbound sync request.
//!
//! Its own module because the answer to an inbound request is the one place
//! where a node bug could put an unbounded response on the wire, and because
//! the type has a `Drop` obligation: a responder that is dropped without
//! answering must free the parked response channel, or the peer's stream stays
//! open until libp2p times it out and a slot in the bounded inbound table is
//! wasted until then.

use std::sync::Arc;

use libp2p::PeerId;
use tokio::sync::mpsc;

use crate::error::P2pError;
use crate::message::SyncResponse;
use crate::service::{P2pCommand, RequestId, ShedCounters, send_command};

/// The reply channel for one inbound sync request.
///
/// The response is capped again by the service before it goes on the wire, so
/// a node bug cannot exceed the contract's 2000 headers or 64 blocks.
#[derive(Debug)]
pub struct SyncResponder {
    pub(super) id: RequestId,
    pub(super) peer: PeerId,
    pub(super) commands: mpsc::Sender<P2pCommand>,
    pub(super) counters: Arc<ShedCounters>,
    pub(super) answered: bool,
}

impl SyncResponder {
    /// A responder whose service is gone.
    ///
    /// [`Self::respond`] fails and dropping it cancels nothing, because there
    /// is no swarm task on the other end. It exists so that a caller driving
    /// the node's event loop without a live swarm can build a
    /// [`crate::P2pEvent::InboundRequest`] at all: the real constructor needs
    /// the worker's private command channel, so a loop that cannot be handed
    /// an inbound request cannot be tested for how it behaves under one.
    #[must_use]
    pub fn abandoned(peer: PeerId) -> Self {
        let (commands, _closed) = mpsc::channel(1);
        SyncResponder {
            id: RequestId::new(0),
            peer,
            commands,
            counters: Arc::new(ShedCounters::default()),
            answered: false,
        }
    }

    /// The libp2p id of the request being answered.
    pub fn request_id(&self) -> RequestId {
        self.id
    }

    /// The peer waiting for the answer.
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// Send the answer.
    ///
    /// Consumes the responder: a request is answered exactly once.
    ///
    /// # Errors
    /// [`P2pError::QueueFull`] when the command queue is full, or
    /// [`P2pError::ServiceStopped`] when the swarm task has gone.
    pub fn respond(mut self, response: SyncResponse) -> Result<(), P2pError> {
        self.answered = true;
        send_command(
            &self.commands,
            &self.counters,
            P2pCommand::Respond { id: self.id, response: Box::new(response) },
        )
    }
}

impl Drop for SyncResponder {
    fn drop(&mut self) {
        if !self.answered {
            // Free the parked response channel; libp2p will report a
            // ResponseOmission to the peer rather than leaving it hanging.
            let _ = self.commands.try_send(P2pCommand::CancelResponse { id: self.id });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unanswered_responder_cancels_its_request_on_drop() {
        let (tx, mut rx) = mpsc::channel::<P2pCommand>(4);
        let responder = SyncResponder {
            id: RequestId::new(7),
            peer: PeerId::random(),
            commands: tx,
            counters: Arc::new(ShedCounters::default()),
            answered: false,
        };
        let id = responder.request_id();
        drop(responder);

        match rx.try_recv().expect("a cancel must be queued") {
            P2pCommand::CancelResponse { id: got } => assert_eq!(got, id),
            other => panic!("wrong command: {}", other.kind()),
        }
    }

    #[tokio::test]
    async fn answering_a_responder_sends_the_response_and_no_cancel() {
        let (tx, mut rx) = mpsc::channel::<P2pCommand>(4);
        let responder = SyncResponder {
            id: RequestId::new(7),
            peer: PeerId::random(),
            commands: tx,
            counters: Arc::new(ShedCounters::default()),
            answered: false,
        };
        responder.respond(SyncResponse::NotFound).expect("respond");

        match rx.try_recv().expect("a response must be queued") {
            P2pCommand::Respond { response, .. } => {
                assert_eq!(*response, SyncResponse::NotFound);
            }
            other => panic!("wrong command: {}", other.kind()),
        }
        assert!(rx.try_recv().is_err(), "no cancel may follow a response");
    }

    #[tokio::test]
    async fn an_abandoned_responder_answers_nobody_and_panics_at_nothing() {
        let peer = PeerId::random();
        let responder = SyncResponder::abandoned(peer);
        assert_eq!(responder.peer(), peer);
        // The service is gone, so answering fails rather than hanging, and
        // dropping the failed responder must not panic either.
        assert!(matches!(
            responder.respond(SyncResponse::NotFound),
            Err(P2pError::ServiceStopped)
        ));
        drop(SyncResponder::abandoned(peer));
    }
}
