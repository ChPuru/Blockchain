//! The JSON-RPC client `chain-cli` talks to a node with.
//!
//! The typed client comes from `ferrum-rpc`: the `#[rpc(server, client)]`
//! macro on `ferrum_rpc::api::FerrumRpc` generates both halves from one trait,
//! so the CLI and the node cannot drift apart in a method name, a parameter
//! order or a response shape. There is no hand-written request builder here
//! and there must never be one.
//!
//! Everything else in this module is about failure messages. "connection
//! refused" from a raw client tells an operator nothing; the errors here name
//! the URL that was tried and the method that failed, because the first
//! question after a failed `chain-cli` call is always "which node, doing
//! what?".

use std::time::Duration;

use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};

use crate::error::{CliError, CliResult};

/// The default node endpoint (CONTRACT §13.1).
pub const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8645";

/// The environment variable that overrides `--rpc`.
pub const RPC_ENV: &str = "FERRUM_RPC";

/// How long one call may take before it is abandoned.
///
/// Twenty seconds: `getblocktemplate` and `getstateroot` walk the UTXO set on
/// a busy node, and `devnet/lib.sh` already applies its own ten-second budget
/// with `curl --max-time`. A client timeout below the server's slowest honest
/// answer turns a slow node into an apparently broken one.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Largest response body accepted: 16 MiB.
///
/// `getblock` at verbosity 2 expands a one-megabyte block several times over,
/// and the server's own ceiling is 8 MiB; the client's is set above it so that
/// a truncation is always attributable to the server.
pub const MAX_RESPONSE_BYTES: u32 = 16 * 1024 * 1024;

/// Build a client for `url`.
///
/// # Errors
///
/// [`CliError::RpcConnect`] when the URL is not one the transport can use. No
/// connection is made here — the first call does that — so a node that is not
/// running yet fails at the call, with the method named.
pub fn connect(url: &str) -> CliResult<HttpClient> {
    HttpClientBuilder::default()
        .request_timeout(REQUEST_TIMEOUT)
        .max_response_size(MAX_RESPONSE_BYTES)
        .build(url)
        .map_err(|source| CliError::RpcConnect { url: url.to_owned(), source })
}

/// Resolve the endpoint: the flag if given, then `FERRUM_RPC`, then the
/// default.
///
/// The same precedence CONTRACT §13 gives `chaind`: CLI flag beats environment
/// beats default.
#[must_use]
pub fn resolve_url(flag: Option<&str>) -> String {
    if let Some(url) = flag {
        return url.to_owned();
    }
    match std::env::var(RPC_ENV) {
        Ok(url) if !url.is_empty() => url,
        _ => DEFAULT_RPC_URL.to_owned(),
    }
}

/// Attach the method name to a client error.
///
/// Used as `map_err(rpc_err("getblockchaininfo"))` at every call site, which
/// is shorter than a match and impossible to get subtly wrong.
pub fn rpc_err(method: &'static str) -> impl Fn(jsonrpsee::core::ClientError) -> CliError {
    move |source| CliError::Rpc { method, source }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_default_endpoint_is_the_contract_port() {
        assert_eq!(DEFAULT_RPC_URL, "http://127.0.0.1:8645");
    }

    #[test]
    fn an_explicit_url_beats_the_environment() {
        // SAFETY-equivalent note: this only reads the variable when the flag is
        // absent, so the test does not need to mutate the process environment.
        assert_eq!(resolve_url(Some("http://10.0.0.1:9999")), "http://10.0.0.1:9999");
    }

    #[test]
    fn a_client_builds_for_a_well_formed_url() {
        assert!(connect(DEFAULT_RPC_URL).is_ok());
    }

    #[test]
    fn a_nonsense_url_fails_at_build_time_naming_itself() {
        let err = connect("not a url").unwrap_err();
        assert!(err.to_string().contains("not a url"), "{err}");
    }
}
