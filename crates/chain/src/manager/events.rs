//! What acceptance did, and how the rest of the node hears about it.
//!
//! # There are no unbounded channels in Ferrum
//!
//! An unbounded channel converts backpressure into an out-of-memory kill: the
//! producer never blocks, so a subscriber that stops draining is answered by
//! the allocator instead of by a warning. [`EventBus`] therefore hands out a
//! **bounded** `std::sync::mpsc` receiver with an explicit capacity and sheds
//! events, loudly, when one fills.
//!
//! The receiver is synchronous because this whole crate is; an async caller
//! drains it from `tokio::task::spawn_blocking`.

use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

use ferrum_types::BlockHash;
use parking_lot::Mutex;

/// How many chain events one subscriber may fall behind before the bus starts
/// dropping them.
///
/// 256 is roughly eight hours of blocks at the two-minute target spacing: long
/// enough that a subscriber doing real work never misses an event, short enough
/// that a stalled one costs a few kilobytes rather than the process.
pub const CHAIN_EVENT_CAPACITY: usize = 256;

/// What accepting a block did to the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcceptOutcome {
    /// The block extended the active tip.
    Extended(BlockHash),
    /// The block was on a branch that has now become the active chain.
    Reorged {
        /// The tip that was replaced.
        from: BlockHash,
        /// The new tip.
        to: BlockHash,
        /// Blocks removed from the active chain, tip first.
        disconnected: Vec<BlockHash>,
        /// Blocks added to the active chain, ancestor first.
        connected: Vec<BlockHash>,
    },
    /// The block is valid but its branch does not have the most work.
    SideChain(BlockHash),
    /// The block was already known, with its body.
    Duplicate,
    /// The block's parent is unknown; the block is held, not rejected.
    Orphan,
}

impl AcceptOutcome {
    /// Whether this outcome moved the active tip.
    #[must_use]
    pub fn moved_the_tip(&self) -> bool {
        matches!(self, AcceptOutcome::Extended(_) | AcceptOutcome::Reorged { .. })
    }
}

/// Something the chain did, broadcast to every subscriber.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainEvent {
    /// The active tip moved.
    NewTip {
        /// The new tip.
        hash: BlockHash,
        /// Its height.
        height: u64,
        /// Cumulative work to it, big-endian.
        total_work: [u8; 32],
    },
    /// The active chain was reorganised.
    Reorg {
        /// The tip that was replaced.
        from: BlockHash,
        /// The new tip.
        to: BlockHash,
        /// Blocks removed, tip first.
        disconnected: Vec<BlockHash>,
        /// Blocks added, ancestor first.
        connected: Vec<BlockHash>,
    },
}

/// The fan-out to every [`ChainEvent`] subscriber.
#[derive(Debug, Default)]
pub struct EventBus {
    subscribers: Mutex<Vec<SyncSender<ChainEvent>>>,
}

impl EventBus {
    /// A bus with no subscribers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a bounded receiver of future events.
    #[must_use]
    pub fn subscribe(&self) -> Receiver<ChainEvent> {
        let (tx, rx) = sync_channel(CHAIN_EVENT_CAPACITY);
        self.subscribers.lock().push(tx);
        rx
    }

    /// How many live subscribers the bus believes it has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.subscribers.lock().len()
    }

    /// Whether nobody is listening.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Deliver `event`, dropping subscribers that are gone and shedding for
    /// those that are too far behind.
    pub fn emit(&self, event: &ChainEvent) {
        let mut subscribers = self.subscribers.lock();
        subscribers.retain(|tx| match tx.try_send(event.clone()) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                tracing::warn!(
                    capacity = CHAIN_EVENT_CAPACITY,
                    "chain event subscriber is full; shedding the event"
                );
                true
            }
            Err(TrySendError::Disconnected(_)) => false,
        });
    }
}
