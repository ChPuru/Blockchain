//! `chain-cli wallet ...` — keys, addresses, balances and spending.
//!
//! # Where the coins come from
//!
//! The wallet never rescans. It asks the node for the unspent outputs paying
//! its own addresses (`listunspent`, which needs `chaind --index`), hands them
//! to [`Wallet::sync`], and reads the balance out of that view. CONTRACT §12
//! and milestone M5 both require it: two sources of truth about the same coins
//! is how wallets lose money.
//!
//! # Output shape
//!
//! Every command here obeys CONTRACT §13.1: the bare value — an address, a
//! balance in FRM, a txid — is the last line of stdout, and `--json` replaces
//! the whole rendering with a document. `wallet address` in particular prints
//! *exactly one line*, because `devnet/ci-e2e.sh` reads it with `| tail -1`
//! and a second line would make the address the second-to-last.

use std::path::Path;

use ferrum_crypto::{Address, Mnemonic};
use ferrum_types::{Amount, Coin, Network, OutPoint, Script, Txid};
use ferrum_wallet::{SendRequest, Wallet};
use serde_json::json;
use zeroize::Zeroizing;

use crate::commands::Context;
use crate::error::{CliError, CliResult};
use crate::output::CommandOutput;
use crate::passphrase::PassphraseSource;
use crate::rpc::rpc_err;
use crate::{keyfile, paths};

use ferrum_rpc::FerrumRpcClient as _;

/// Open the wallet at `datadir`, or create one if there is none.
///
/// Creation on first use is what lets `devnet/ci-e2e.sh` run
/// `chain-cli --rpc … wallet address` with no setup step. The mnemonic goes to
/// **stderr**, never to stdout.
async fn open_or_create(ctx: &Context, source: &PassphraseSource) -> CliResult<Wallet> {
    let path = paths::wallet_path(&ctx.datadir);
    if path.exists() {
        return open_existing(&path, source);
    }

    paths::ensure_dir(&ctx.datadir)?;
    let network = ctx.probe_network().await.unwrap_or(Network::Devnet);
    let passphrase = source.resolve(false)?;
    let (wallet, mnemonic) =
        Wallet::create(&path, network, &passphrase, DEFAULT_WORDS, &mut rand::rngs::OsRng)?;
    eprintln!("created a new {} wallet at {}", network.name(), path.display());
    eprintln!("mnemonic: {}", mnemonic.phrase());
    eprintln!("write it down: the plaintext seed never touches disk.");
    Ok(wallet)
}

/// Mnemonic length used when a wallet is created implicitly.
///
/// Twelve words is 128 bits of entropy, which is the security of the
/// underlying curve; more words buy nothing here and are harder to copy down.
pub const DEFAULT_WORDS: usize = 12;

/// Open an existing keystore, falling back to a prompt on a wrong passphrase.
///
/// The fallback only fires when the operator gave no passphrase flag at all
/// *and* stdin is a terminal, so an unattended caller gets a clean error
/// instead of a hang.
fn open_existing(path: &Path, source: &PassphraseSource) -> CliResult<Wallet> {
    let passphrase = source.resolve(false)?;
    match Wallet::open(path, &passphrase) {
        Ok(wallet) => Ok(wallet),
        Err(ferrum_wallet::WalletError::WrongPassphrase) if source.can_fall_back_to_prompt() => {
            let typed = crate::passphrase::prompt_line("Passphrase: ")?;
            Ok(Wallet::open(path, &typed)?)
        }
        Err(e) => Err(e.into()),
    }
}

/// `wallet new`.
pub async fn new(
    ctx: &Context,
    output: Option<&Path>,
    words: usize,
    network: &str,
    force: bool,
    source: &PassphraseSource,
) -> CliResult<CommandOutput> {
    let network = paths::parse_network(network)?;
    let path = paths::wallet_path(&ctx.datadir);
    if path.exists() {
        if !force {
            return Err(CliError::invalid(
                "--datadir",
                ctx.datadir.display().to_string(),
                format!(
                    "a wallet already exists at {}; pass --force to replace it",
                    path.display()
                ),
            ));
        }
        std::fs::remove_file(&path).map_err(|e| CliError::io(&path, e))?;
    }
    paths::ensure_dir(&ctx.datadir)?;

    let passphrase = source.resolve(true)?;
    let (mut wallet, mnemonic) =
        Wallet::create(&path, network, &passphrase, words, &mut rand::rngs::OsRng)?;
    let address = wallet.new_address()?;

    // CONTRACT §13.1: the mnemonic goes to stderr, or to --output. It must
    // never reach stdout, where `| tail -1` is reading for the address.
    match output {
        Some(file) => {
            keyfile::write_key_file(file, &mnemonic)?;
            eprintln!("mnemonic written to {}", file.display());
        }
        None => eprintln!("mnemonic: {}", mnemonic.phrase()),
    }

    Ok(CommandOutput::scalar("address", address.encode())
        .with_json(json!({
            "address": address.encode(),
            "network": network.name(),
            "words": words,
            "keystore": path.display().to_string(),
            "mnemonic_written_to": output.map(|p| p.display().to_string()),
        }))
        .with_line(format!("wallet    {}", path.display()))
        .with_line(format!("network   {}", network.name())))
}

/// `wallet restore`.
pub fn restore(
    ctx: &Context,
    mnemonic_file: Option<&Path>,
    network: &str,
    force: bool,
    source: &PassphraseSource,
) -> CliResult<CommandOutput> {
    let network = paths::parse_network(network)?;
    let path = paths::wallet_path(&ctx.datadir);
    if path.exists() {
        if !force {
            return Err(CliError::invalid(
                "--datadir",
                ctx.datadir.display().to_string(),
                format!(
                    "a wallet already exists at {}; pass --force to replace it",
                    path.display()
                ),
            ));
        }
        std::fs::remove_file(&path).map_err(|e| CliError::io(&path, e))?;
    }
    paths::ensure_dir(&ctx.datadir)?;

    let phrase = read_mnemonic(mnemonic_file)?;
    let mnemonic = Mnemonic::from_phrase(phrase.trim())?;
    let passphrase = source.resolve(false)?;
    let mut wallet = Wallet::restore(&path, network, &mnemonic, &passphrase)?;
    let address = wallet.new_address()?;

    Ok(CommandOutput::scalar("address", address.encode())
        .with_json(json!({
            "address": address.encode(),
            "network": network.name(),
            "keystore": path.display().to_string(),
        }))
        .with_line(format!("restored  {}", path.display())))
}

/// Read a mnemonic from a file, or from stdin when no file is named.
fn read_mnemonic(file: Option<&Path>) -> CliResult<Zeroizing<String>> {
    match file {
        Some(path) => {
            let raw = std::fs::read(path).map_err(|e| CliError::io(path, e))?;
            let text = String::from_utf8(raw).map_err(|_| {
                CliError::invalid("--mnemonic-file", path.display().to_string(), "not valid UTF-8")
            })?;
            Ok(Zeroizing::new(text))
        }
        None => {
            eprint!("Mnemonic: ");
            let mut line = Zeroizing::new(String::new());
            let read = std::io::stdin().read_line(&mut line)?;
            if read == 0 {
                return Err(CliError::invalid("mnemonic", "<empty>", "end of input on stdin"));
            }
            Ok(line)
        }
    }
}

/// `wallet address`.
///
/// Exactly one line of stdout, always.
pub async fn address(
    ctx: &Context,
    fresh: bool,
    source: &PassphraseSource,
) -> CliResult<CommandOutput> {
    let mut wallet = open_or_create(ctx, source).await?;
    let address = if fresh {
        wallet.new_address()?
    } else {
        match wallet.addresses().last() {
            Some(existing) => *existing,
            None => wallet.new_address()?,
        }
    };
    Ok(CommandOutput::scalar("address", address.encode()))
}

/// `wallet balance`.
pub async fn balance(ctx: &Context, source: &PassphraseSource) -> CliResult<CommandOutput> {
    let mut wallet = open_or_create(ctx, source).await?;
    let tip = sync_from_node(ctx, &mut wallet).await?;
    let balance = wallet.balance_at(tip);

    Ok(CommandOutput::scalar("confirmed", balance.confirmed.to_frm_string())
        .with_json(json!({
            "confirmed": balance.confirmed.to_frm_string(),
            "immature": balance.immature.to_frm_string(),
            "pending": balance.pending.to_frm_string(),
            "confirmed_grains": balance.confirmed.to_grains().to_string(),
            "immature_grains": balance.immature.to_grains().to_string(),
            "pending_grains": balance.pending.to_grains().to_string(),
            "height": tip,
        }))
        .with_field("immature", format!("{} FRM", balance.immature.to_frm_string()))
        .with_field("pending", format!("{} FRM", balance.pending.to_frm_string()))
        .with_field("height", tip))
}

/// `wallet list-unspent`.
pub async fn list_unspent(ctx: &Context, source: &PassphraseSource) -> CliResult<CommandOutput> {
    let mut wallet = open_or_create(ctx, source).await?;
    let tip = sync_from_node(ctx, &mut wallet).await?;
    let coins = wallet.list_coins(tip);

    let rows: Vec<_> = coins
        .iter()
        .map(|c| {
            json!({
                "outpoint": format!("{}:{}", c.out_point.txid, c.out_point.vout),
                "value": c.coin.value.to_frm_string(),
                "value_grains": c.coin.value.to_grains().to_string(),
                "height": c.coin.height,
                "is_coinbase": c.coin.is_coinbase,
                "status": format!("{:?}", c.status).to_lowercase(),
                "script": c.coin.script_pubkey.to_hex(),
            })
        })
        .collect();

    let mut out = CommandOutput::document(json!({ "height": tip, "unspent": rows }));
    for coin in &coins {
        out = out.with_line(format!(
            "{}:{:<3} {:>16} FRM  h={:<8} {:?}",
            coin.out_point.txid,
            coin.out_point.vout,
            coin.coin.value.to_frm_string(),
            coin.coin.height,
            coin.status
        ));
    }
    Ok(out.with_bare(coins.len().to_string()))
}

/// `wallet send`.
pub async fn send(
    ctx: &Context,
    to: &str,
    amount: &str,
    fee_rate: u64,
    dry_run: bool,
    source: &PassphraseSource,
) -> CliResult<CommandOutput> {
    let recipient =
        Address::decode(to).map_err(|e| CliError::invalid("--to", to, e.to_string()))?;
    let value = Amount::from_frm_str(amount)
        .map_err(|e| CliError::invalid("--amount", amount, e.to_string()))?;

    let mut wallet = open_or_create(ctx, source).await?;
    let tip = sync_from_node(ctx, &mut wallet).await?;

    let request = SendRequest::to(recipient, value, fee_rate);
    let plan = wallet.send(&request, tip)?;
    let envelope = plan.tx.encode_envelope();
    let txid = ferrum_storage::txid(&plan.tx);
    let hex_envelope = hex::encode(&envelope);

    let document = json!({
        "txid": txid.to_string(),
        "fee": plan.fee.to_frm_string(),
        "fee_grains": plan.fee.to_grains().to_string(),
        "fee_rate": plan.fee_rate(),
        "size": plan.estimated_size,
        "inputs": plan.selected.len(),
        "change": plan.change.map(|c| c.to_frm_string()),
        "broadcast": !dry_run,
        "hex": hex_envelope.clone(),
    });

    if dry_run {
        return Ok(CommandOutput::document(document)
            .with_line("dry run: not broadcast")
            .with_bare(hex_envelope));
    }

    let client = ctx.client()?;
    let returned =
        client.send_raw_transaction(hex_envelope).await.map_err(rpc_err("sendrawtransaction"))?;

    Ok(CommandOutput::scalar("txid", returned.clone())
        .with_json(document)
        .with_field("fee", format!("{} FRM", plan.fee.to_frm_string()))
        .with_field("size", plan.estimated_size))
}

/// `wallet dump-seed`.
pub async fn dump_seed(ctx: &Context, source: &PassphraseSource) -> CliResult<CommandOutput> {
    let wallet = open_or_create(ctx, source).await?;
    let phrase = wallet.mnemonic().phrase().to_owned();
    eprintln!("anyone holding this phrase holds every coin this wallet controls.");
    Ok(CommandOutput::scalar("mnemonic", phrase))
}

/// `wallet dump-pubkey`.
///
/// `devnet/fork.sh` reads this with `| tail -1` to build the BFT validator
/// set, so the last line is the 64-hex x-only key and nothing else.
pub fn dump_pubkey(key: &Path, network: &str) -> CliResult<CommandOutput> {
    let network = paths::parse_network(network)?;
    let loaded = keyfile::load_key_file(key, network)?;
    let hex_key = hex::encode(loaded.public.as_bytes());
    let address = Address::p2pkh(network, &loaded.public);
    Ok(CommandOutput::scalar("pubkey", hex_key)
        .with_json(json!({
            "pubkey": hex::encode(loaded.public.as_bytes()),
            "address": address.encode(),
            "network": network.name(),
        }))
        .with_field("address", address.encode()))
}

/// Ask the node for this wallet's coins and hand them to [`Wallet::sync`].
///
/// Returns the tip height the view is current as of. Every address the wallet
/// has issued is queried, receive and change alike: a change output the wallet
/// forgot about is a coin it can no longer spend.
async fn sync_from_node(ctx: &Context, wallet: &mut Wallet) -> CliResult<u64> {
    let client = ctx.client()?;
    let info = client.get_blockchain_info().await.map_err(rpc_err("getblockchaininfo"))?;

    let mut utxos: Vec<(OutPoint, Coin)> = Vec::new();
    let mut addresses = wallet.addresses();
    addresses.extend(wallet.change_addresses());

    for address in addresses {
        let encoded = address.encode();
        let rows = client.list_unspent(encoded.clone()).await.map_err(rpc_err("listunspent"))?;
        for row in rows {
            let out_point = parse_outpoint(&row.outpoint)?;
            // `listunspent` does not report coinbase-ness, and spending an
            // immature coinbase is a **consensus** failure, not a policy one:
            // the transaction is invalid and the wallet would have built a
            // payment that can never confirm. `gettxout` carries the flag, so
            // each candidate costs one more round trip and the wallet's idea
            // of what it can spend matches the node's.
            let Some(coin) = client
                .get_tx_out(out_point.txid.to_string(), out_point.vout)
                .await
                .map_err(rpc_err("gettxout"))?
            else {
                // Spent between the two calls. Dropping it is right: the coin
                // is gone, and the next sync will not see it either.
                continue;
            };
            let script_pubkey = Script::from_hex(&coin.script_pubkey).map_err(|e| {
                CliError::invalid("gettxout.script_pubkey", &coin.script_pubkey, e.to_string())
            })?;
            utxos.push((
                out_point,
                Coin {
                    value: coin.value.0,
                    script_pubkey,
                    height: coin.height,
                    is_coinbase: coin.is_coinbase,
                },
            ));
        }
    }

    wallet.sync(utxos, info.height);
    Ok(info.height)
}

/// Parse a `"<txid>:<vout>"` outpoint as `listunspent` reports it.
fn parse_outpoint(text: &str) -> CliResult<OutPoint> {
    let (txid, vout) = text
        .rsplit_once(':')
        .ok_or_else(|| CliError::invalid("outpoint", text, "expected <txid>:<vout>"))?;
    let txid =
        Txid::from_hex(txid).map_err(|e| CliError::invalid("outpoint", text, e.to_string()))?;
    let vout =
        vout.parse::<u32>().map_err(|e| CliError::invalid("outpoint", text, e.to_string()))?;
    Ok(OutPoint::new(txid, vout))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn an_outpoint_round_trips_through_its_text_form() {
        let txid = Txid::from_hex(&"ab".repeat(32)).unwrap();
        let text = format!("{txid}:7");
        let parsed = parse_outpoint(&text).unwrap();
        assert_eq!(parsed.txid, txid);
        assert_eq!(parsed.vout, 7);
    }

    #[test]
    fn an_outpoint_without_a_vout_is_refused() {
        assert!(parse_outpoint(&"ab".repeat(32)).is_err());
    }

    #[test]
    fn an_outpoint_with_a_bad_vout_is_refused() {
        assert!(parse_outpoint(&format!("{}:x", "ab".repeat(32))).is_err());
    }

    #[test]
    fn the_implicit_wallet_uses_twelve_words() {
        assert!(ferrum_crypto::VALID_WORD_COUNTS.contains(&DEFAULT_WORDS));
    }
}
