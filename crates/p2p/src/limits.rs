//! Hard capacity limits for every queue, frame and response in the p2p stack.
//!
//! Two rules from CONTRACT §10.3 are enforced here and nowhere else:
//!
//! 1. **There is no unbounded channel in this crate.** Every `mpsc` channel is
//!    created with an explicit capacity taken from this module, and a producer
//!    that finds the queue full sheds the message with a `tracing::warn!` and a
//!    counter rather than growing the queue. An unbounded queue does not remove
//!    backpressure, it converts backpressure into an out-of-memory kill.
//! 2. **Response sizes are capped server-side, regardless of what the peer
//!    asked for.** A peer that requests one million headers gets
//!    [`MAX_HEADERS_PER_RESPONSE`] of them.
//!
//! Every constant is `pub` so that tests, the node and the metrics exporter can
//! all name the same number.

use std::time::Duration;

// ---------------------------------------------------------------------------
// Response caps (CONTRACT §10.2)
// ---------------------------------------------------------------------------

/// Maximum headers in a single `SyncResponse::Headers`, enforced by the server
/// whatever `GetHeaders::max` says. 2000 x 88 bytes is roughly 176 KiB.
pub const MAX_HEADERS_PER_RESPONSE: usize = 2_000;

/// Maximum blocks in a single `SyncResponse::Blocks`, enforced by the server
/// whatever the request asked for.
pub const MAX_BLOCKS_PER_RESPONSE: usize = 64;

/// Byte budget for the block vector inside one response.
///
/// The count cap alone is not a memory bound: 64 maximum-size blocks are 64 MB,
/// which a peer could force us to buffer on every stream. Bitcoin Core caps a
/// protocol message at 4 MB and ships one block per message; 8 MiB per response
/// is generous next to that, and a peer that asks for more blocks than fit
/// simply gets a short response and asks again.
pub const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Upper bound on the number of block hashes we will honour in one
/// `GetBlocks`. Anything beyond this is truncated before the lookup, so a
/// malicious request cannot turn into a large server-side scan.
pub const MAX_REQUESTED_BLOCK_HASHES: usize = 512;

/// Upper bound on locator length. An exponential back-off locator over a
/// 2^64-block chain needs fewer than 70 entries; 128 is slack for a peer with a
/// slightly different locator shape.
pub const MAX_LOCATOR_HASHES: usize = 128;

// ---------------------------------------------------------------------------
// Frame limits (bounded framing for `/ferrum/sync/1.0.0`)
// ---------------------------------------------------------------------------

/// Size of the length prefix on every sync frame: `u32` little-endian.
pub const FRAME_LENGTH_PREFIX_BYTES: usize = 4;

/// Largest sync **request** frame we will read or write.
///
/// A request is a locator plus a handful of scalars; 1 MiB is already three
/// orders of magnitude more than a legitimate request needs.
pub const MAX_REQUEST_FRAME_BYTES: usize = 1024 * 1024;

/// Largest sync **response** frame we will read or write. Sits above
/// [`MAX_RESPONSE_BODY_BYTES`] so a legal maximum-size body plus its Borsh
/// framing always fits.
pub const MAX_RESPONSE_FRAME_BYTES: usize = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Gossipsub tuning (CONTRACT §10.1)
// ---------------------------------------------------------------------------

/// Gossipsub `max_transmit_size`. The libp2p default is 65_536 bytes, which
/// makes any block above 64 KiB **silently** unsendable: the publish fails
/// locally and the network never hears about the block.
pub const GOSSIP_MAX_TRANSMIT_SIZE: usize = 4 * 1024 * 1024;

/// The libp2p gossipsub default transmit size, kept here so the regression test
/// can assert that Ferrum really does raise it.
pub const GOSSIP_DEFAULT_MAX_TRANSMIT_SIZE: usize = 65_536;

/// Gossipsub `mesh_n_low`. libp2p defaults to 5; the gossipsub v1.1
/// specification says 4.
pub const GOSSIP_MESH_N_LOW: usize = 4;

/// Gossipsub `mesh_n`, the desired mesh degree.
pub const GOSSIP_MESH_N: usize = 6;

/// Gossipsub `mesh_n_high`, the degree above which the mesh is pruned.
pub const GOSSIP_MESH_N_HIGH: usize = 12;

/// Gossipsub `duplicate_cache_time`. libp2p defaults to 60 s; Ferrum targets
/// 120 s block spacing, so a 60 s cache lets the same block re-enter the mesh
/// within one block interval.
pub const GOSSIP_DUPLICATE_CACHE_TIME: Duration = Duration::from_secs(120);

/// The libp2p gossipsub default duplicate cache time, for the regression test.
pub const GOSSIP_DEFAULT_DUPLICATE_CACHE_TIME: Duration = Duration::from_secs(60);

/// Gossipsub heartbeat interval. Pinned explicitly rather than inherited so a
/// libp2p default change cannot silently retune the mesh.
pub const GOSSIP_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// Yamux tuning
// ---------------------------------------------------------------------------

/// Yamux receive window per substream.
///
/// The libp2p default is 256 KiB. At an 80 ms round trip a 256 KiB window caps
/// a single stream near 3 MB/s, which is the difference between syncing a chain
/// in minutes and syncing it in hours.
pub const YAMUX_RECEIVE_WINDOW_BYTES: u32 = 4 * 1024 * 1024;

/// The libp2p yamux default receive window, kept here so the regression test
/// can assert that Ferrum really does raise it.
pub const YAMUX_DEFAULT_RECEIVE_WINDOW_BYTES: u32 = 256 * 1024;

/// Maximum concurrent yamux substreams per connection.
pub const YAMUX_MAX_NUM_STREAMS: usize = 256;

// ---------------------------------------------------------------------------
// Channel capacities: the whole reason this module exists
// ---------------------------------------------------------------------------

/// Capacity of the command queue from [`crate::P2pHandle`] to the swarm task.
pub const COMMAND_CHANNEL_CAPACITY: usize = 256;

/// Capacity of the event queue from the swarm task to the node.
pub const EVENT_CHANNEL_CAPACITY: usize = 1_024;

/// Maximum inbound sync requests awaiting a response from the node before new
/// ones are shed. Each parked request holds a response channel and a peer
/// substream open, so this is a real memory and descriptor bound.
pub const MAX_PENDING_INBOUND_REQUESTS: usize = 128;

/// Maximum outbound sync requests in flight before new ones are refused.
pub const MAX_PENDING_OUTBOUND_REQUESTS: usize = 256;

// ---------------------------------------------------------------------------
// Timers and peering
// ---------------------------------------------------------------------------

/// Timeout for one inbound or outbound `/ferrum/sync/1.0.0` exchange.
pub const SYNC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum concurrent sync streams per connection. Deliberately far below the
/// libp2p default of 100: 16 x 10 MiB is the worst-case buffered bytes a single
/// peer can force us to hold.
pub const MAX_CONCURRENT_SYNC_STREAMS: usize = 16;

/// How long a connection with no active substream is kept alive. Reconnecting
/// costs a Noise handshake; 60 s of idle is cheaper than paying it repeatedly.
pub const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// First reconnect delay for a static peer.
pub const RECONNECT_BASE_BACKOFF: Duration = Duration::from_secs(1);

/// Ceiling on the reconnect delay for a static peer.
pub const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(300);

/// How often the service re-examines the static peer list.
pub const RECONNECT_TICK: Duration = Duration::from_millis(500);

/// Interval between identify exchanges with a connected peer.
pub const IDENTIFY_INTERVAL: Duration = Duration::from_secs(300);

/// Interval between liveness pings.
pub const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Timeout for a single ping.
pub const PING_TIMEOUT: Duration = Duration::from_secs(20);

/// Default maximum number of simultaneously connected peers. Static peers are
/// always admitted; peers beyond this are disconnected.
pub const MAX_PEERS: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    // The constants are read into locals first. Comparing two `const` items
    // directly is a compile-time-constant assertion, which clippy rightly warns
    // about; going through a binding keeps the check but makes it a real
    // runtime assertion that shows the offending value on failure.

    #[test]
    fn response_caps_match_the_contract() {
        assert_eq!(MAX_HEADERS_PER_RESPONSE, 2_000);
        assert_eq!(MAX_BLOCKS_PER_RESPONSE, 64);
        assert_eq!(FRAME_LENGTH_PREFIX_BYTES, 4);
    }

    #[test]
    fn gossip_max_transmit_size_is_at_least_four_mib() {
        let configured = GOSSIP_MAX_TRANSMIT_SIZE;
        let libp2p_default = GOSSIP_DEFAULT_MAX_TRANSMIT_SIZE;
        assert!(configured >= 4 * 1024 * 1024, "a 1 MB block must be sendable, got {configured}");
        assert!(configured > libp2p_default, "the libp2p default silently drops blocks");
    }

    #[test]
    fn yamux_receive_window_is_raised_above_the_libp2p_default() {
        let configured = YAMUX_RECEIVE_WINDOW_BYTES;
        let libp2p_default = YAMUX_DEFAULT_RECEIVE_WINDOW_BYTES;
        assert_eq!(libp2p_default, 256 * 1024);
        assert!(configured > libp2p_default, "256 KiB caps one substream near 3 MB/s");
    }

    #[test]
    fn mesh_parameters_are_ordered_and_low_is_four() {
        let (low, target, high) = (GOSSIP_MESH_N_LOW, GOSSIP_MESH_N, GOSSIP_MESH_N_HIGH);
        assert_eq!(low, 4, "the gossipsub specification says 4, libp2p defaults to 5");
        assert!(low <= target, "mesh_n_low {low} must not exceed mesh_n {target}");
        assert!(target <= high, "mesh_n {target} must not exceed mesh_n_high {high}");
    }

    #[test]
    fn duplicate_cache_covers_a_block_interval() {
        let configured = GOSSIP_DUPLICATE_CACHE_TIME;
        let libp2p_default = GOSSIP_DEFAULT_DUPLICATE_CACHE_TIME;
        // target_spacing_ms is 120_000, so the cache must span a whole block.
        assert!(configured >= Duration::from_secs(120), "got {configured:?}");
        assert!(configured > libp2p_default);
    }

    #[test]
    fn every_channel_capacity_is_non_zero() {
        let capacities = [
            ("commands", COMMAND_CHANNEL_CAPACITY),
            ("events", EVENT_CHANNEL_CAPACITY),
            ("pending inbound", MAX_PENDING_INBOUND_REQUESTS),
            ("pending outbound", MAX_PENDING_OUTBOUND_REQUESTS),
        ];
        for (name, capacity) in capacities {
            assert!(capacity > 0, "the {name} queue has no capacity");
        }
    }

    #[test]
    fn response_frame_has_room_for_a_maximum_body() {
        let (request, response, body) =
            (MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES, MAX_RESPONSE_BODY_BYTES);
        assert!(response > body, "a legal body plus framing must fit in a frame");
        assert!(request < response, "a request is a locator, a response is 64 blocks");
    }

    #[test]
    fn backoff_bounds_are_sane() {
        let (base, ceiling, tick) = (RECONNECT_BASE_BACKOFF, RECONNECT_MAX_BACKOFF, RECONNECT_TICK);
        assert!(base < ceiling, "{base:?} must be below the ceiling {ceiling:?}");
        assert!(tick <= base, "the tick must be fine enough to honour the base delay");
    }
}
