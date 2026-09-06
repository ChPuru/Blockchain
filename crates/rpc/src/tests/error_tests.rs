//! Malformed input, over a real listener.
//!
//! The question these tests answer is the one that matters for an
//! unauthenticated public port: does bad input produce a *JSON-RPC error* with
//! a stable code, or a 500 and a stack trace? Driving the real `jsonrpsee`
//! server rather than the handler trait is the point — the framing, the
//! parameter decoding and the transport are exactly where a 500 would come
//! from.

use std::net::SocketAddr;

use crate::error::RpcErrorCode;
use crate::server::{RpcServerConfig, RpcServerHandle, spawn_rpc_server};
use crate::tests::fixture::Fixture;

/// Bind the JSON-RPC server on an ephemeral port.
async fn serve(f: &Fixture) -> RpcServerHandle {
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    spawn_rpc_server(RpcServerConfig::at(listen), f.context()).await.unwrap()
}

/// POST a raw body to the JSON-RPC endpoint and return `(status, body)`.
///
/// Hand-rolled rather than routed through a JSON-RPC client, because the whole
/// point is to send things a client would refuse to construct.
async fn raw_post(addr: SocketAddr, body: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    let payload = text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
    (status, payload)
}

/// The `error.code` of a JSON-RPC response body, chunked framing tolerated.
fn error_code(body: &str) -> i64 {
    // `Connection: close` responses may still be chunk-framed; find the JSON.
    let start = body.find('{').expect("a JSON body");
    let end = body.rfind('}').expect("a JSON body");
    let json: serde_json::Value =
        serde_json::from_str(&body[start..=end]).expect("a JSON-RPC response");
    json["error"]["code"].as_i64().expect("an error object with a code")
}

#[tokio::test]
async fn a_body_that_is_not_json_is_a_parse_error_not_a_500() {
    let f = Fixture::build(1, false);
    let server = serve(&f).await;
    let (status, body) = raw_post(server.local_addr(), "{ not json at all").await;
    assert_eq!(status, 200, "JSON-RPC reports faults in the body, not the status");
    assert_eq!(error_code(&body), i64::from(RpcErrorCode::ParseError.code()));
    server.stop();
}

#[tokio::test]
async fn valid_json_that_is_not_a_request_is_a_reserved_code_not_a_500() {
    let f = Fixture::build(1, false);
    let server = serve(&f).await;
    let (status, body) = raw_post(server.local_addr(), r#"{"hello":"world"}"#).await;
    assert_eq!(status, 200);
    // `jsonrpsee` folds "not a request object" into its parse error rather
    // than minting -32600; either is a legal JSON-RPC answer and both are in
    // the reserved range. What matters is that it is not a 500 and not one of
    // Ferrum's own codes.
    let code = error_code(&body);
    assert!(
        code == i64::from(RpcErrorCode::ParseError.code())
            || code == i64::from(RpcErrorCode::InvalidRequest.code()),
        "code was {code}"
    );
    assert!(code < i64::from(crate::error::FERRUM_CODE_BASE));
    server.stop();
}

#[tokio::test]
async fn an_unknown_method_is_method_not_found() {
    let f = Fixture::build(1, false);
    let server = serve(&f).await;
    let (_, body) = raw_post(
        server.local_addr(),
        r#"{"jsonrpc":"2.0","id":1,"method":"drop_the_database","params":[]}"#,
    )
    .await;
    assert_eq!(error_code(&body), i64::from(RpcErrorCode::MethodNotFound.code()));
    server.stop();
}

#[tokio::test]
async fn the_wrong_parameter_type_is_invalid_params() {
    let f = Fixture::build(1, false);
    let server = serve(&f).await;
    let (_, body) = raw_post(
        server.local_addr(),
        r#"{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":["not a height"]}"#,
    )
    .await;
    assert_eq!(error_code(&body), i64::from(RpcErrorCode::InvalidParams.code()));
    server.stop();
}

#[tokio::test]
async fn a_missing_required_parameter_is_invalid_params() {
    let f = Fixture::build(1, false);
    let server = serve(&f).await;
    let (_, body) = raw_post(
        server.local_addr(),
        r#"{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[]}"#,
    )
    .await;
    assert_eq!(error_code(&body), i64::from(RpcErrorCode::InvalidParams.code()));
    server.stop();
}

#[tokio::test]
async fn an_application_error_keeps_its_ferrum_code_over_the_wire() {
    let f = Fixture::build(1, false);
    let server = serve(&f).await;
    let (_, body) = raw_post(
        server.local_addr(),
        r#"{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[9999]}"#,
    )
    .await;
    assert_eq!(error_code(&body), i64::from(RpcErrorCode::HeightOutOfRange.code()));
    assert!(error_code(&body) >= i64::from(crate::error::FERRUM_CODE_BASE));
    server.stop();
}

#[tokio::test]
async fn a_hostile_hash_argument_is_rejected_rather_than_looked_up() {
    let f = Fixture::build(1, false);
    let server = serve(&f).await;
    let long = "f".repeat(100_000);
    let request =
        format!(r#"{{"jsonrpc":"2.0","id":1,"method":"getblock","params":["{long}",1]}}"#);
    let (_, body) = raw_post(server.local_addr(), &request).await;
    assert_eq!(error_code(&body), i64::from(RpcErrorCode::InvalidHash.code()));
    server.stop();
}

#[tokio::test]
async fn a_body_over_the_limit_is_refused_without_being_buffered() {
    let f = Fixture::build(1, false);
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = RpcServerConfig { max_request_body: 512, ..RpcServerConfig::at(listen) };
    let server = spawn_rpc_server(config, f.context()).await.unwrap();
    let padding = "a".repeat(4_096);
    let request = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[1],"pad":"{padding}"}}"#
    );
    let (status, _) = raw_post(server.local_addr(), &request).await;
    assert_eq!(status, 413, "an oversized body must not be read into memory");
    server.stop();
}

#[tokio::test]
async fn the_server_survives_the_requests_that_failed() {
    // A 500 that kills the connection pool is worse than a rejection; after
    // every malformed request above, a good one must still work.
    let f = Fixture::build(1, false);
    let server = serve(&f).await;
    let addr = server.local_addr();
    for hostile in [
        "{ not json",
        r#"{"hello":"world"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"nope","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":["x"]}"#,
    ] {
        let _ = raw_post(addr, hostile).await;
    }
    let (_, body) =
        raw_post(addr, r#"{"jsonrpc":"2.0","id":9,"method":"getblockchaininfo","params":[]}"#)
            .await;
    let start = body.find('{').unwrap();
    let end = body.rfind('}').unwrap();
    let json: serde_json::Value = serde_json::from_str(&body[start..=end]).unwrap();
    assert_eq!(json["result"]["height"], 1);
    server.stop();
}
