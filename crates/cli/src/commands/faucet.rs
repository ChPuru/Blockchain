//! `chain-cli faucet request` — ask a node's explorer for devnet coins.
//!
//! The faucet is REST, not JSON-RPC: `POST /api/faucet` on the explorer
//! listener (CONTRACT §11), which is a different port from `--rpc`. Hence the
//! separate `--explorer` flag, defaulting to `127.0.0.1:8665` — the explorer
//! port CONTRACT §13.1 gives node 1 of a devnet.

use ferrum_crypto::Address;
use ferrum_rpc::types::explorer::FaucetResponse;
use serde_json::json;

use crate::commands::{Context, wallet};
use crate::error::{CliError, CliResult};
use crate::http::{HttpTarget, post_json};
use crate::output::CommandOutput;
use crate::passphrase::PassphraseSource;

/// The explorer route the faucet lives at.
pub const FAUCET_PATH: &str = "/api/faucet";

/// `faucet request`.
///
/// With no `--address` the wallet's current receive address is used, creating
/// the wallet if there is none — which is the whole point of a faucet: getting
/// a stranger from nothing to a funded address in one command.
///
/// # Errors
///
/// [`CliError::Invalid`] for a bad address or explorer URL, and
/// [`CliError::NotFound`] when the faucet refuses (rate limit, disabled, or
/// out of coins) — the server's own message is passed through.
pub async fn request(
    ctx: &Context,
    address: Option<&str>,
    explorer: &str,
    source: &PassphraseSource,
) -> CliResult<CommandOutput> {
    let address = match address {
        Some(text) => Address::decode(text)
            .map_err(|e| CliError::invalid("--address", text, e.to_string()))?
            .encode(),
        None => {
            let out = wallet::address(ctx, false, source).await?;
            out.bare.ok_or_else(|| CliError::internal("wallet address produced no address"))?
        }
    };

    let target = HttpTarget::parse(explorer, FAUCET_PATH)?;
    let body = json!({ "address": address }).to_string();
    let (status, text) = post_json(&target, &body).await?;

    if status != 200 {
        return Err(CliError::not_found(format!(
            "faucet at {}:{} answered {status}: {}",
            target.host,
            target.port,
            text.trim()
        )));
    }

    let response: FaucetResponse = serde_json::from_str(&text)
        .map_err(|e| CliError::invalid("faucet response", text.trim(), e.to_string()))?;

    Ok(CommandOutput::scalar("txid", response.txid.clone())
        .with_json(json!({
            "txid": response.txid,
            "address": response.address,
            "amount": response.amount.0.to_frm_string(),
            "amount_grains": response.amount.0.to_grains().to_string(),
        }))
        .with_field("address", &response.address)
        .with_field("amount", format!("{} FRM", response.amount.0.to_frm_string())))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_default_explorer_port_is_the_contract_one() {
        let target = HttpTarget::parse("http://127.0.0.1:8665", FAUCET_PATH).unwrap();
        assert_eq!(target.port, 8665);
        assert_eq!(target.path, "/api/faucet");
    }

    #[tokio::test]
    async fn a_malformed_address_is_refused_before_any_request() {
        let ctx = Context {
            datadir: std::path::PathBuf::from("."),
            rpc_url: "http://127.0.0.1:1".to_owned(),
            json: false,
        };
        let err =
            request(&ctx, Some("not-an-address"), "http://127.0.0.1:1", &PassphraseSource::empty())
                .await
                .unwrap_err();
        assert!(err.to_string().contains("--address"), "{err}");
    }
}
