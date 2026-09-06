//! The stable numeric error table (CONTRACT §11).
//!
//! Every failure this crate can report has exactly one code, the codes are
//! listed in one place, and a test pins each number. A client that special-cases
//! "the transaction was rejected" must be able to do so without string
//! matching, and a code that drifts between releases silently breaks every such
//! client.
//!
//! # Why the application codes are positive
//!
//! JSON-RPC 2.0 reserves `-32768..=-32000` for the protocol and its
//! implementations; `jsonrpsee` already mints codes in that window for parse
//! errors, unknown methods, oversized bodies and so on. Ferrum's own codes
//! start at [`FERRUM_CODE_BASE`] (`1000`) so that they can never collide with a
//! transport-level code, and so that "is this the server's fault or the
//! caller's?" is answerable from the sign of the number alone.
//!
//! # One error type, two transports
//!
//! [`RpcError`] converts into a JSON-RPC [`ErrorObjectOwned`] for the
//! `jsonrpsee` surface and into an HTTP response carrying
//! `{"error": "...", "code": N}` for the REST surface. The explorer reads the
//! `error` field of that body, so the shape is part of the interface.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ferrum_chain::{ChainError, ValidationError};
use ferrum_crypto::CryptoError;
use ferrum_script::ScriptError;
use ferrum_storage::StorageError;
use ferrum_types::TypeError;
use ferrum_wallet::WalletError;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};

/// First Ferrum-specific error code. Everything below this is JSON-RPC's own.
pub const FERRUM_CODE_BASE: i32 = 1000;

/// The stable error table.
///
/// The numbers are frozen. Adding a variant is allowed; renumbering one is a
/// breaking change to every client, and `error_codes_are_frozen` in this
/// module's tests exists to make that impossible to do by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RpcErrorCode {
    // ---- JSON-RPC 2.0 reserved range -------------------------------------
    /// The request was not valid JSON.
    ParseError,
    /// The request was valid JSON but not a valid JSON-RPC request object.
    InvalidRequest,
    /// No such method.
    MethodNotFound,
    /// The parameters did not match the method's signature.
    InvalidParams,
    /// An unexpected server-side failure.
    InternalError,

    // ---- Ferrum application range (>= FERRUM_CODE_BASE) -------------------
    /// No block, transaction, output or address record with that identifier.
    NotFound,
    /// A hash argument was not 64 hex characters.
    InvalidHash,
    /// An address failed bech32m decoding, or belongs to another network.
    InvalidAddress,
    /// A hex argument contained a non-hex character or an odd length.
    InvalidHex,
    /// Well-formed hex that is not a valid Borsh encoding of the expected type.
    DecodeFailed,
    /// A height argument is beyond the tip, or the chain has no tip yet.
    HeightOutOfRange,
    /// The query needs the `tx_index`/`addr_index` reverse index, which this
    /// node was started without (`chaind --index`).
    IndexDisabled,
    /// The mempool refused the transaction.
    TxRejected,
    /// The chain refused the block.
    BlockRejected,
    /// A block template could not be assembled.
    TemplateFailed,
    /// The database failed.
    StorageFailure,
    /// A state root was requested for a height that is not the tip.
    StateRootUnavailable,
    /// This node runs no faucet.
    FaucetDisabled,
    /// The caller has already drawn from the faucet inside the window.
    FaucetRateLimited,
    /// The faucet wallet has nothing left to send.
    FaucetDrained,
    /// The faucet failed for some other reason.
    FaucetFailed,
    /// No peer-to-peer service is attached to this RPC server.
    NetworkUnavailable,
    /// No mempool is attached to this RPC server.
    MempoolUnavailable,
    /// The request is well-formed but this build does not implement it.
    Unsupported,
    /// A monetary or size computation overflowed.
    Overflow,
}

impl RpcErrorCode {
    /// Every code, for the exhaustiveness test and for documentation tooling.
    pub const ALL: [RpcErrorCode; 25] = [
        RpcErrorCode::ParseError,
        RpcErrorCode::InvalidRequest,
        RpcErrorCode::MethodNotFound,
        RpcErrorCode::InvalidParams,
        RpcErrorCode::InternalError,
        RpcErrorCode::NotFound,
        RpcErrorCode::InvalidHash,
        RpcErrorCode::InvalidAddress,
        RpcErrorCode::InvalidHex,
        RpcErrorCode::DecodeFailed,
        RpcErrorCode::HeightOutOfRange,
        RpcErrorCode::IndexDisabled,
        RpcErrorCode::TxRejected,
        RpcErrorCode::BlockRejected,
        RpcErrorCode::TemplateFailed,
        RpcErrorCode::StorageFailure,
        RpcErrorCode::StateRootUnavailable,
        RpcErrorCode::FaucetDisabled,
        RpcErrorCode::FaucetRateLimited,
        RpcErrorCode::FaucetDrained,
        RpcErrorCode::FaucetFailed,
        RpcErrorCode::NetworkUnavailable,
        RpcErrorCode::MempoolUnavailable,
        RpcErrorCode::Unsupported,
        RpcErrorCode::Overflow,
    ];

    /// The wire number. **Frozen.**
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            RpcErrorCode::ParseError => -32700,
            RpcErrorCode::InvalidRequest => -32600,
            RpcErrorCode::MethodNotFound => -32601,
            RpcErrorCode::InvalidParams => -32602,
            RpcErrorCode::InternalError => -32603,

            RpcErrorCode::NotFound => 1001,
            RpcErrorCode::InvalidHash => 1002,
            RpcErrorCode::InvalidAddress => 1003,
            RpcErrorCode::InvalidHex => 1004,
            RpcErrorCode::DecodeFailed => 1005,
            RpcErrorCode::HeightOutOfRange => 1006,
            RpcErrorCode::IndexDisabled => 1007,
            RpcErrorCode::TxRejected => 1008,
            RpcErrorCode::BlockRejected => 1009,
            RpcErrorCode::TemplateFailed => 1010,
            RpcErrorCode::StorageFailure => 1011,
            RpcErrorCode::StateRootUnavailable => 1012,
            RpcErrorCode::FaucetDisabled => 1013,
            RpcErrorCode::FaucetRateLimited => 1014,
            RpcErrorCode::FaucetDrained => 1015,
            RpcErrorCode::FaucetFailed => 1016,
            RpcErrorCode::NetworkUnavailable => 1017,
            RpcErrorCode::MempoolUnavailable => 1018,
            RpcErrorCode::Unsupported => 1019,
            RpcErrorCode::Overflow => 1020,
        }
    }

    /// The short, stable summary that precedes any per-call detail.
    #[must_use]
    pub const fn summary(self) -> &'static str {
        match self {
            RpcErrorCode::ParseError => "parse error",
            RpcErrorCode::InvalidRequest => "invalid request",
            RpcErrorCode::MethodNotFound => "method not found",
            RpcErrorCode::InvalidParams => "invalid parameters",
            RpcErrorCode::InternalError => "internal error",
            RpcErrorCode::NotFound => "not found",
            RpcErrorCode::InvalidHash => "invalid hash",
            RpcErrorCode::InvalidAddress => "invalid address",
            RpcErrorCode::InvalidHex => "invalid hex",
            RpcErrorCode::DecodeFailed => "decode failed",
            RpcErrorCode::HeightOutOfRange => "height out of range",
            RpcErrorCode::IndexDisabled => "transaction index disabled",
            RpcErrorCode::TxRejected => "transaction rejected",
            RpcErrorCode::BlockRejected => "block rejected",
            RpcErrorCode::TemplateFailed => "block template failed",
            RpcErrorCode::StorageFailure => "storage failure",
            RpcErrorCode::StateRootUnavailable => "state root unavailable",
            RpcErrorCode::FaucetDisabled => "faucet disabled",
            RpcErrorCode::FaucetRateLimited => "faucet rate limited",
            RpcErrorCode::FaucetDrained => "faucet drained",
            RpcErrorCode::FaucetFailed => "faucet failed",
            RpcErrorCode::NetworkUnavailable => "network unavailable",
            RpcErrorCode::MempoolUnavailable => "mempool unavailable",
            RpcErrorCode::Unsupported => "unsupported",
            RpcErrorCode::Overflow => "arithmetic overflow",
        }
    }

    /// The HTTP status the REST surface answers with.
    ///
    /// The explorer only reads the body, but a status that lies makes every
    /// proxy, cache and monitoring rule in front of this server wrong.
    #[must_use]
    pub const fn http_status(self) -> StatusCode {
        match self {
            RpcErrorCode::ParseError
            | RpcErrorCode::InvalidRequest
            | RpcErrorCode::InvalidParams
            | RpcErrorCode::InvalidHash
            | RpcErrorCode::InvalidAddress
            | RpcErrorCode::InvalidHex
            | RpcErrorCode::DecodeFailed
            | RpcErrorCode::HeightOutOfRange
            | RpcErrorCode::TxRejected
            | RpcErrorCode::BlockRejected => StatusCode::BAD_REQUEST,

            RpcErrorCode::MethodNotFound | RpcErrorCode::NotFound => StatusCode::NOT_FOUND,

            RpcErrorCode::FaucetRateLimited => StatusCode::TOO_MANY_REQUESTS,

            RpcErrorCode::IndexDisabled
            | RpcErrorCode::StateRootUnavailable
            | RpcErrorCode::Unsupported => StatusCode::NOT_IMPLEMENTED,

            RpcErrorCode::FaucetDisabled
            | RpcErrorCode::FaucetDrained
            | RpcErrorCode::NetworkUnavailable
            | RpcErrorCode::MempoolUnavailable => StatusCode::SERVICE_UNAVAILABLE,

            RpcErrorCode::InternalError
            | RpcErrorCode::TemplateFailed
            | RpcErrorCode::StorageFailure
            | RpcErrorCode::FaucetFailed
            | RpcErrorCode::Overflow => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// A failure with a stable code and a human-readable detail.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}: {message}", .code.summary())]
pub struct RpcError {
    code: RpcErrorCode,
    message: String,
}

impl RpcError {
    /// Build an error with an explicit code and detail.
    #[must_use]
    pub fn new(code: RpcErrorCode, message: impl Into<String>) -> Self {
        RpcError { code, message: message.into() }
    }

    /// The stable code.
    #[must_use]
    pub const fn code(&self) -> RpcErrorCode {
        self.code
    }

    /// The stable code as the number that goes on the wire.
    #[must_use]
    pub const fn numeric_code(&self) -> i32 {
        self.code.code()
    }

    /// The detail, without the summary prefix.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.message
    }

    /// The full message a client sees: `"<summary>: <detail>"`.
    #[must_use]
    pub fn message(&self) -> String {
        format!("{}: {}", self.code.summary(), self.message)
    }

    /// `1001 NotFound`.
    #[must_use]
    pub fn not_found(what: impl Into<String>) -> Self {
        RpcError::new(RpcErrorCode::NotFound, what)
    }

    /// `-32602 InvalidParams`.
    #[must_use]
    pub fn invalid_params(what: impl Into<String>) -> Self {
        RpcError::new(RpcErrorCode::InvalidParams, what)
    }

    /// `-32603 InternalError`.
    #[must_use]
    pub fn internal(what: impl Into<String>) -> Self {
        RpcError::new(RpcErrorCode::InternalError, what)
    }

    /// `1020 Overflow`. Used wherever a `checked_*` returns `None`.
    #[must_use]
    pub fn overflow(what: impl Into<String>) -> Self {
        RpcError::new(RpcErrorCode::Overflow, what)
    }

    /// `1007 IndexDisabled`, with the standard remedy in the message.
    #[must_use]
    pub fn index_disabled(what: &str) -> Self {
        RpcError::new(
            RpcErrorCode::IndexDisabled,
            format!("{what} needs the reverse index; restart the node with --index"),
        )
    }
}

/// The JSON body every REST failure carries.
///
/// `error` is the field `explorer/index.html` reads out of a failed response,
/// so its name is load-bearing; `code` is the same stable number the JSON-RPC
/// surface reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestErrorBody {
    /// Human-readable message, `"<summary>: <detail>"`.
    pub error: String,
    /// The stable numeric code from [`RpcErrorCode`].
    pub code: i32,
}

impl From<&RpcError> for RestErrorBody {
    fn from(e: &RpcError) -> Self {
        RestErrorBody { error: e.message(), code: e.numeric_code() }
    }
}

impl From<RpcError> for ErrorObjectOwned {
    fn from(e: RpcError) -> Self {
        ErrorObjectOwned::owned(e.numeric_code(), e.message(), None::<()>)
    }
}

impl IntoResponse for RpcError {
    fn into_response(self) -> Response {
        let status = self.code.http_status();
        let body = RestErrorBody::from(&self);
        (status, Json(body)).into_response()
    }
}

// ---------------------------------------------------------------- conversions

impl From<StorageError> for RpcError {
    fn from(e: StorageError) -> Self {
        // The store reports "no index" as its own variant; keeping that
        // distinction is the difference between "your node is misconfigured"
        // and "your node is broken".
        match e {
            StorageError::IndexDisabled => {
                RpcError::new(RpcErrorCode::IndexDisabled, "this node was started without --index")
            }
            other => RpcError::new(RpcErrorCode::StorageFailure, other.to_string()),
        }
    }
}

impl From<ChainError> for RpcError {
    fn from(e: ChainError) -> Self {
        // A database failure while accepting a block is the node's fault, not
        // the submitter's; reporting it as "block rejected" would send an
        // honest miner off to debug a block that was fine.
        match e {
            ChainError::Storage(inner) => inner.into(),
            ChainError::Arithmetic(what) => RpcError::overflow(what),
            other => RpcError::new(RpcErrorCode::BlockRejected, other.to_string()),
        }
    }
}

impl From<ValidationError> for RpcError {
    fn from(e: ValidationError) -> Self {
        RpcError::new(RpcErrorCode::BlockRejected, e.to_string())
    }
}

impl From<TypeError> for RpcError {
    fn from(e: TypeError) -> Self {
        RpcError::new(RpcErrorCode::DecodeFailed, e.to_string())
    }
}

impl From<CryptoError> for RpcError {
    fn from(e: CryptoError) -> Self {
        RpcError::new(RpcErrorCode::InvalidAddress, e.to_string())
    }
}

impl From<ScriptError> for RpcError {
    fn from(e: ScriptError) -> Self {
        RpcError::new(RpcErrorCode::DecodeFailed, e.to_string())
    }
}

impl From<WalletError> for RpcError {
    fn from(e: WalletError) -> Self {
        RpcError::new(RpcErrorCode::FaucetFailed, e.to_string())
    }
}

impl From<ferrum_consensus::ConsensusError> for RpcError {
    fn from(e: ferrum_consensus::ConsensusError) -> Self {
        RpcError::new(RpcErrorCode::BlockRejected, e.to_string())
    }
}

/// Decode a 64-character hex hash, or fail with [`RpcErrorCode::InvalidHash`].
pub fn parse_hash32(s: &str) -> Result<ferrum_types::Hash32, RpcError> {
    ferrum_types::Hash32::from_hex(s)
        .map_err(|e| RpcError::new(RpcErrorCode::InvalidHash, format!("{s:?}: {e}")))
}

/// Decode hex into bytes, or fail with [`RpcErrorCode::InvalidHex`].
pub fn parse_hex(s: &str) -> Result<Vec<u8>, RpcError> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(trimmed).map_err(|e| RpcError::new(RpcErrorCode::InvalidHex, e.to_string()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn error_codes_are_frozen() {
        // If this test needs editing, you are changing a published interface.
        assert_eq!(RpcErrorCode::ParseError.code(), -32700);
        assert_eq!(RpcErrorCode::InvalidRequest.code(), -32600);
        assert_eq!(RpcErrorCode::MethodNotFound.code(), -32601);
        assert_eq!(RpcErrorCode::InvalidParams.code(), -32602);
        assert_eq!(RpcErrorCode::InternalError.code(), -32603);
        assert_eq!(RpcErrorCode::NotFound.code(), 1001);
        assert_eq!(RpcErrorCode::InvalidHash.code(), 1002);
        assert_eq!(RpcErrorCode::InvalidAddress.code(), 1003);
        assert_eq!(RpcErrorCode::InvalidHex.code(), 1004);
        assert_eq!(RpcErrorCode::DecodeFailed.code(), 1005);
        assert_eq!(RpcErrorCode::HeightOutOfRange.code(), 1006);
        assert_eq!(RpcErrorCode::IndexDisabled.code(), 1007);
        assert_eq!(RpcErrorCode::TxRejected.code(), 1008);
        assert_eq!(RpcErrorCode::BlockRejected.code(), 1009);
        assert_eq!(RpcErrorCode::TemplateFailed.code(), 1010);
        assert_eq!(RpcErrorCode::StorageFailure.code(), 1011);
        assert_eq!(RpcErrorCode::StateRootUnavailable.code(), 1012);
        assert_eq!(RpcErrorCode::FaucetDisabled.code(), 1013);
        assert_eq!(RpcErrorCode::FaucetRateLimited.code(), 1014);
        assert_eq!(RpcErrorCode::FaucetDrained.code(), 1015);
        assert_eq!(RpcErrorCode::FaucetFailed.code(), 1016);
        assert_eq!(RpcErrorCode::NetworkUnavailable.code(), 1017);
        assert_eq!(RpcErrorCode::MempoolUnavailable.code(), 1018);
        assert_eq!(RpcErrorCode::Unsupported.code(), 1019);
        assert_eq!(RpcErrorCode::Overflow.code(), 1020);
    }

    #[test]
    fn every_code_is_distinct() {
        let codes: BTreeSet<i32> = RpcErrorCode::ALL.iter().map(|c| c.code()).collect();
        assert_eq!(codes.len(), RpcErrorCode::ALL.len(), "two variants share a number");
    }

    #[test]
    fn application_codes_never_collide_with_json_rpc_reserved_range() {
        for code in RpcErrorCode::ALL {
            let n = code.code();
            if n >= FERRUM_CODE_BASE {
                continue;
            }
            assert!(
                (-32768..=-32000).contains(&n),
                "{code:?} sits between the reserved range and the Ferrum range"
            );
        }
    }

    #[test]
    fn summaries_are_present_and_distinct() {
        let summaries: BTreeSet<&str> = RpcErrorCode::ALL.iter().map(|c| c.summary()).collect();
        assert_eq!(summaries.len(), RpcErrorCode::ALL.len());
        assert!(RpcErrorCode::ALL.iter().all(|c| !c.summary().is_empty()));
    }

    #[test]
    fn json_rpc_conversion_keeps_the_code() {
        let err = RpcError::not_found("block 99");
        let obj: ErrorObjectOwned = err.into();
        assert_eq!(obj.code(), 1001);
        assert!(obj.message().contains("block 99"));
        assert!(obj.message().starts_with("not found"));
    }

    #[test]
    fn rest_body_carries_error_and_code() {
        let err = RpcError::new(RpcErrorCode::FaucetRateLimited, "try again in 60s");
        let body = RestErrorBody::from(&err);
        assert_eq!(body.code, 1014);
        assert!(body.error.contains("try again in 60s"));
        let json = serde_json::to_value(&body).unwrap();
        assert!(json.get("error").is_some(), "the explorer reads `error`");
    }

    #[test]
    fn http_statuses_are_sensible() {
        assert_eq!(RpcErrorCode::NotFound.http_status(), StatusCode::NOT_FOUND);
        assert_eq!(RpcErrorCode::FaucetRateLimited.http_status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(RpcErrorCode::InvalidAddress.http_status(), StatusCode::BAD_REQUEST);
        assert_eq!(RpcErrorCode::IndexDisabled.http_status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(RpcErrorCode::StorageFailure.http_status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(RpcErrorCode::FaucetDrained.http_status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn hash_parsing_reports_invalid_hash() {
        assert_eq!(parse_hash32("not a hash").unwrap_err().code(), RpcErrorCode::InvalidHash);
        let zero = "0".repeat(64);
        assert_eq!(parse_hash32(&zero).unwrap(), ferrum_types::Hash32::ZERO);
    }

    #[test]
    fn hex_parsing_reports_invalid_hex_and_accepts_0x() {
        assert_eq!(parse_hex("zz").unwrap_err().code(), RpcErrorCode::InvalidHex);
        assert_eq!(parse_hex("0x00ff").unwrap(), vec![0x00, 0xff]);
    }

    #[test]
    fn storage_index_disabled_keeps_its_own_code() {
        let err: RpcError = StorageError::IndexDisabled.into();
        assert_eq!(err.code(), RpcErrorCode::IndexDisabled);
    }
}
