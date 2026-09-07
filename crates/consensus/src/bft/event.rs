//! The alphabet of the round machine: what goes in, and what comes out.
//!
//! Keeping the events and actions in their own module is what makes the seam
//! obvious. [`BftMachine`](crate::BftMachine) is a function from a
//! [`BftEvent`] and its current state to a list of [`BftAction`]s; everything
//! that touches a socket, a timer or a block store is on the driver's side of
//! that line, in `ferrum-node`.

use core::time::Duration;

use ferrum_types::BlockHash;

use crate::bft::state::Timeout;
use crate::bft::vote::{Proposal, SignedVote};

/// A message the driver must gossip to the validator set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BftMessage {
    /// A block proposal from this round's proposer.
    Proposal(Proposal),
    /// A prevote.
    Prevote(SignedVote),
    /// A precommit.
    Precommit(SignedVote),
}

impl BftMessage {
    /// The event this message becomes at the receiving validator.
    ///
    /// Delivery is symmetric: the driver hands every broadcast to every
    /// validator, the sender included, so a vote is counted through exactly one
    /// path.
    pub fn into_event(self) -> BftEvent {
        match self {
            BftMessage::Proposal(p) => BftEvent::Proposal(p),
            BftMessage::Prevote(v) => BftEvent::Prevote(v),
            BftMessage::Precommit(v) => BftEvent::Precommit(v),
        }
    }
}

/// Something that happened, fed into [`BftMachine::step`](crate::BftMachine::step).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BftEvent {
    /// A proposal arrived.
    Proposal(Proposal),
    /// A prevote arrived.
    Prevote(SignedVote),
    /// A precommit arrived.
    Precommit(SignedVote),
    /// A timer the machine armed has expired.
    Timeout(Timeout),
    /// Begin deciding a new height. Resets locks, valid values and votes.
    NewHeight(u64),
}

/// Something the driver must do, returned from
/// [`BftMachine::step`](crate::BftMachine::step).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BftAction {
    /// Send this message to every validator, this one included.
    Broadcast(BftMessage),
    /// Arm this timer for this long, then feed it back as
    /// [`BftEvent::Timeout`].
    ScheduleTimeout(Timeout, Duration),
    /// This block is committed at the machine's current height. The full
    /// certificate is [`BftMachine::decision`](crate::BftMachine::decision).
    Decide(BlockHash),
}
