//! A minimal HTTP/1.1 POST, for the one endpoint that is not JSON-RPC.
//!
//! The explorer's faucet is REST (`POST /api/faucet`, CONTRACT §11), not
//! JSON-RPC, so the typed `jsonrpsee` client cannot reach it. Rather than pull
//! a whole HTTP client into the workspace for one devnet convenience, this
//! module writes the request itself over a `tokio` TCP stream.
//!
//! The scope is deliberately tiny and stated here so nobody mistakes it for a
//! general client:
//!
//! - **`http://` only.** No TLS. The faucet is a devnet and testnet facility
//!   and `RUNNING.md` puts the explorer behind a reverse proxy in production;
//!   a half-implemented TLS client would be worse than none.
//! - **No redirects, no chunked responses, no keep-alive.** `Connection: close`
//!   is sent, the body is read to end of stream, and a `Transfer-Encoding`
//!   response is reported as unsupported rather than mis-parsed.
//! - **A hard response cap**, so a hostile or broken server cannot make the
//!   CLI allocate without bound.

use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::error::{CliError, CliResult};

/// Largest response body accepted: 256 KiB.
///
/// A faucet reply is a few hundred bytes. The cap exists so that a wrong URL
/// pointing at something enormous fails quickly instead of buffering it.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// How long the whole exchange may take.
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// A parsed `http://host[:port]/path` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpTarget {
    /// Host name or IP literal, as written.
    pub host: String,
    /// Port, defaulted to 80 when the URL omits it.
    pub port: u16,
    /// Request path, always starting with `/`.
    pub path: String,
}

impl HttpTarget {
    /// Parse a URL and replace its path.
    ///
    /// The path is supplied by the caller rather than taken from the URL so
    /// that `--explorer http://host:8665` and `--explorer http://host:8665/`
    /// behave identically.
    ///
    /// # Errors
    ///
    /// [`CliError::Invalid`] for a non-`http` scheme, a missing host or an
    /// unparseable port.
    pub fn parse(url: &str, path: &str) -> CliResult<Self> {
        let trimmed = url.trim();
        let rest = trimmed.strip_prefix("http://").ok_or_else(|| {
            CliError::invalid("--explorer", trimmed, "expected an http:// URL (no TLS here)")
        })?;
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        if authority.is_empty() {
            return Err(CliError::invalid("--explorer", trimmed, "no host"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            // An IPv6 literal has colons inside brackets; splitting on the last
            // one is only a port when what follows is numeric.
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (
                h.to_owned(),
                p.parse::<u16>()
                    .map_err(|e| CliError::invalid("--explorer", trimmed, e.to_string()))?,
            ),
            _ => (authority.to_owned(), 80),
        };
        let path = if path.starts_with('/') { path.to_owned() } else { format!("/{path}") };
        Ok(HttpTarget { host, port, path })
    }
}

/// POST a JSON body and return `(status, body)`.
///
/// # Errors
///
/// [`CliError::BareIo`] when the connection fails, and [`CliError::Invalid`]
/// when the response is not something this deliberately small client can read.
pub async fn post_json(target: &HttpTarget, body: &str) -> CliResult<(u16, String)> {
    let exchange = async {
        let mut stream = TcpStream::connect((target.host.as_str(), target.port)).await?;
        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Accept: application/json\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            target.path,
            target.host,
            target.port,
            body.len(),
            body
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let mut raw = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            if raw.len().saturating_add(read) > MAX_RESPONSE_BYTES {
                return Err(std::io::Error::other("response exceeded the size cap"));
            }
            raw.extend_from_slice(&chunk[..read]);
        }
        Ok::<Vec<u8>, std::io::Error>(raw)
    };

    let raw = tokio::time::timeout(TIMEOUT, exchange).await.map_err(|_| {
        CliError::internal(format!("{}:{} did not answer in time", target.host, target.port))
    })??;

    parse_response(&raw)
}

/// Split an HTTP/1.1 response into its status code and body.
///
/// # Errors
///
/// [`CliError::Invalid`] when the response has no status line, no header
/// terminator, or uses a transfer encoding this client does not implement.
pub fn parse_response(raw: &[u8]) -> CliResult<(u16, String)> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or_else(|| CliError::invalid("http response", "<truncated>", "no header terminator"))?;

    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| CliError::invalid("http response", "<empty>", "no status line"))?;
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| CliError::invalid("http response", status_line, "no status code"))?;

    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        return Err(CliError::invalid(
            "http response",
            "chunked",
            "this client reads only identity-encoded responses",
        ));
    }

    Ok((code, body.to_owned()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_url_without_a_port_defaults_to_eighty() {
        let t = HttpTarget::parse("http://example.test", "/api/faucet").unwrap();
        assert_eq!(t.host, "example.test");
        assert_eq!(t.port, 80);
        assert_eq!(t.path, "/api/faucet");
    }

    #[test]
    fn an_explicit_port_is_kept_and_a_trailing_path_is_replaced() {
        let t = HttpTarget::parse("http://127.0.0.1:8665/ignored", "/api/faucet").unwrap();
        assert_eq!(t.port, 8665);
        assert_eq!(t.path, "/api/faucet");
    }

    #[test]
    fn a_relative_path_is_made_absolute() {
        let t = HttpTarget::parse("http://h:1", "api/faucet").unwrap();
        assert_eq!(t.path, "/api/faucet");
    }

    #[test]
    fn https_is_refused_rather_than_silently_downgraded() {
        let err = HttpTarget::parse("https://example.test", "/x").unwrap_err();
        assert!(err.to_string().contains("http://"), "{err}");
    }

    #[test]
    fn a_response_splits_into_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        let (code, body) = parse_response(raw).unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, "{}");
    }

    #[test]
    fn an_error_status_is_reported_not_swallowed() {
        let raw = b"HTTP/1.1 429 Too Many Requests\r\n\r\nslow down";
        let (code, body) = parse_response(raw).unwrap();
        assert_eq!(code, 429);
        assert_eq!(body, "slow down");
    }

    #[test]
    fn a_chunked_response_is_refused_rather_than_mis_parsed() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert!(parse_response(raw).is_err());
    }

    #[test]
    fn a_truncated_response_is_an_error() {
        assert!(parse_response(b"HTTP/1.1 200 OK").is_err());
    }
}
