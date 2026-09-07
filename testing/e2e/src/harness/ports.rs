//! Ephemeral loopback ports, reserved once and reused across restarts.
//!
//! # Why a port is reserved rather than left to `/tcp/0`
//!
//! libp2p will happily bind port zero, but a node's *peers* are configured with
//! a multiaddr before any of them start, and `ferrum-node` reports the
//! configured listen address rather than the one the kernel chose — so a
//! network of nodes on port zero has no way to describe itself to itself.
//! Reserving a port up front is the standard answer: bind a listener on
//! `127.0.0.1:0`, note the port the kernel picked, close it, and hand it out.
//!
//! There is a race in that — the kernel may hand the same port to some other
//! process between the close and the node's bind — which is why every start
//! goes through [`await_port_free`] and is retried. The alternative, a fixed
//! port range, races with every other test on the machine instead, and does so
//! deterministically.
//!
//! # Why the process keeps a ledger
//!
//! The kernel is free to return a port it has just handed back. Two nodes in
//! one network with the same port is not a flake, it is a hang: the second
//! bind fails and the first node never hears from anybody. The `BTreeSet`
//! below makes that impossible within this process, whatever the kernel does.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// How many times [`reserve_port`] asks the kernel for a fresh port before
/// giving up.
///
/// Each attempt only fails when the kernel returns a port this process has
/// already handed out, which needs the ephemeral range to have wrapped. Sixty
/// four attempts is far past the point where the machine has a real problem.
pub const RESERVE_ATTEMPTS: usize = 64;

/// How long [`await_port_free`] waits between probes.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(50);

/// Ports this process has handed out, so it never hands one out twice.
static RESERVED: LazyLock<Mutex<BTreeSet<u16>>> = LazyLock::new(|| Mutex::new(BTreeSet::new()));

/// Reserve a loopback port that no other node in this process is using.
///
/// # Errors
///
/// When a loopback listener cannot be bound at all, or when
/// [`RESERVE_ATTEMPTS`] consecutive attempts all returned a port already
/// reserved here.
pub fn reserve_port() -> Result<u16> {
    for _ in 0..RESERVE_ATTEMPTS {
        let port = ephemeral_port().context("asking the kernel for an ephemeral loopback port")?;
        let mut reserved = RESERVED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if reserved.insert(port) {
            return Ok(port);
        }
    }
    bail!("could not find an unused loopback port in {RESERVE_ATTEMPTS} attempts")
}

/// Whether a loopback listener can be bound to `port` right now.
///
/// Used as a pre-flight before restarting a node on the port it just released:
/// a listening socket is gone the moment its owner drops it, but the operating
/// system does not always agree instantly, and "wait until the port is free"
/// makes a restart a wait rather than a failure.
#[must_use]
pub fn port_is_free(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

/// Wait until `port` can be bound, or until `timeout` elapses.
///
/// Returns whether the port was free when the wait ended. A `false` is not by
/// itself a failure: libp2p's listener may still succeed where this probe did
/// not, so the caller starts the node anyway and lets the real bind be the
/// judge.
pub async fn await_port_free(port: u16, timeout: Duration) -> bool {
    let poll = async {
        while !port_is_free(port) {
            tokio::time::sleep(PROBE_INTERVAL).await;
        }
    };
    tokio::time::timeout(timeout, poll).await.is_ok()
}

/// The multiaddr a node listening on `port` is dialled at.
#[must_use]
pub fn loopback_multiaddr(port: u16) -> String {
    format!("/ip4/127.0.0.1/tcp/{port}")
}

/// Bind `127.0.0.1:0`, read the port the kernel chose, and release it.
fn ephemeral_port() -> Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn reserved_ports_are_distinct_and_bindable() {
        let ports: Vec<u16> = (0..8).map(|_| reserve_port().unwrap()).collect();
        let unique: BTreeSet<u16> = ports.iter().copied().collect();
        assert_eq!(unique.len(), ports.len(), "a port was handed out twice: {ports:?}");
        for port in ports {
            assert_ne!(port, 0, "the kernel never hands back port zero");
            assert!(port_is_free(port), "a freshly reserved port must still be bindable");
        }
    }

    #[test]
    fn a_port_in_use_is_not_free() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(!port_is_free(port), "a bound port must not look free");
        drop(listener);
    }

    #[test]
    fn the_multiaddr_is_the_shape_devnet_uses() {
        assert_eq!(loopback_multiaddr(8655), "/ip4/127.0.0.1/tcp/8655");
    }

    #[tokio::test]
    async fn waiting_on_a_free_port_returns_immediately() {
        let port = reserve_port().unwrap();
        assert!(await_port_free(port, Duration::from_secs(5)).await);
    }

    #[tokio::test]
    async fn waiting_on_a_held_port_times_out_rather_than_hanging() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(!await_port_free(port, Duration::from_millis(200)).await);
        drop(listener);
    }
}
