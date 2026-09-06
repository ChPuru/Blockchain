//! Lifecycle of a single node: start, listen, answer, stop.
//!
//! These live outside the crate because each one spawns a real swarm task on a
//! real tokio runtime. Keeping them out of the unit tests keeps `service.rs` to
//! the pure logic that can be checked without one.

use std::time::Duration;

use ferrum_p2p::{MessageAcceptance, MessageId, P2pConfig, P2pError, P2pEvent, P2pService, PeerId};
use ferrum_types::{BlockHash, ChainId};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(20);

fn devnet() -> P2pConfig {
    P2pConfig::new(ChainId(3))
}

#[tokio::test]
async fn spawn_binds_a_listener_and_stops_on_shutdown() {
    let config = devnet().with_listen_addr("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"));
    let expected = config.local_peer_id();

    let (handle, task) = P2pService::spawn(config).expect("the service must start");
    assert_eq!(handle.local_peer_id(), expected);

    let mut events = handle.events().expect("the first take succeeds");
    assert!(
        matches!(handle.events(), Err(P2pError::EventsAlreadyTaken)),
        "the event stream is single-consumer"
    );

    let first = timeout(STEP, events.recv())
        .await
        .expect("a listen address must be reported")
        .expect("the event stream must stay open");
    match first {
        P2pEvent::Listening { address } => {
            assert!(address.to_string().contains("/tcp/"), "got {address}");
            assert!(address.to_string().contains("127.0.0.1"), "got {address}");
        }
        other => panic!("unexpected first event: {other:?}"),
    }

    handle.shutdown().expect("shutdown must be accepted");
    timeout(STEP, task).await.expect("the task must stop").expect("the task must not panic");
}

#[tokio::test]
async fn an_unbindable_listen_address_is_an_error_not_a_silent_failure() {
    // Port 1 on a non-local interface: binding must fail here, in `spawn`,
    // rather than inside a detached task where nobody sees it.
    let config = devnet().with_listen_addr("/ip4/203.0.113.1/tcp/1".parse().expect("multiaddr"));
    match P2pService::spawn(config) {
        Err(P2pError::Listen { .. }) => {}
        Err(other) => panic!("wrong error: {other}"),
        Ok((handle, task)) => {
            // Some platforms accept the bind; the service must at least run.
            handle.shutdown().expect("shutdown");
            let _ = timeout(STEP, task).await;
        }
    }
}

#[tokio::test]
async fn dropping_every_handle_stops_the_task() {
    let (handle, task) = P2pService::spawn(devnet()).expect("the service must start");
    let clone = handle.clone();
    drop(handle);
    drop(clone);
    timeout(STEP, task)
        .await
        .expect("the task must stop when no handle remains")
        .expect("the task must not panic");
}

#[tokio::test]
async fn commands_fail_cleanly_once_the_service_has_stopped() {
    let (handle, task) = P2pService::spawn(devnet()).expect("start");
    handle.shutdown().expect("shutdown");
    let _ = timeout(STEP, task).await;

    let err = handle.peers().await.expect_err("a stopped service must refuse commands");
    assert!(matches!(err, P2pError::ServiceStopped), "got {err}");
    assert!(!err.is_transient(), "a stopped service is not worth retrying");
}

#[tokio::test]
async fn peers_is_empty_on_a_fresh_node() {
    let (handle, task) = P2pService::spawn(devnet()).expect("start");
    let peers = timeout(STEP, handle.peers())
        .await
        .expect("peers must answer")
        .expect("peers must succeed");
    assert!(peers.is_empty());
    assert_eq!(handle.shed_counts().total(), 0);
    handle.shutdown().expect("shutdown");
    let _ = timeout(STEP, task).await;
}

#[tokio::test]
async fn publishing_with_no_peers_is_a_typed_error_not_a_panic() {
    let (handle, task) = P2pService::spawn(devnet()).expect("start");
    let err = timeout(STEP, handle.publish_tip(BlockHash::ZERO, 1))
        .await
        .expect("publish must answer")
        .expect_err("publishing with no peers must fail");
    assert!(matches!(err, P2pError::Publish { .. }), "got {err}");
    assert!(err.is_transient(), "no mesh peers yet is a retry, not a fault");
    handle.shutdown().expect("shutdown");
    let _ = timeout(STEP, task).await;
}

#[tokio::test]
async fn reporting_validation_for_an_unknown_message_is_not_an_error() {
    // A verdict that arrives after the message left the duplicate cache is
    // normal under load; it must not fail the caller.
    let (handle, task) = P2pService::spawn(devnet()).expect("start");
    handle
        .report_validation(
            MessageId::from(vec![1, 2, 3]),
            PeerId::random(),
            MessageAcceptance::Reject,
        )
        .expect("the command must be accepted");
    handle.shutdown().expect("shutdown");
    let _ = timeout(STEP, task).await;
}

#[tokio::test]
async fn a_request_to_an_unreachable_peer_fails_rather_than_hanging() {
    let (handle, task) = P2pService::spawn(devnet()).expect("start");
    let unknown = PeerId::random();

    let err = timeout(STEP, handle.request_tip(unknown))
        .await
        .expect("the request must not hang")
        .expect_err("a peer we have no address for cannot be reached");
    assert!(matches!(err, P2pError::Request { .. }), "got {err}");

    handle.shutdown().expect("shutdown");
    let _ = timeout(STEP, task).await;
}
