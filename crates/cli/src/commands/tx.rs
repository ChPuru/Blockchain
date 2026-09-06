//! `chain-cli tx ...` — raw transactions.
//!
//! `decode` is local: the envelope carries everything needed to render a
//! transaction, and being able to inspect one without a node is what makes
//! debugging a rejected broadcast possible. `send` and `get` need the node.

use ferrum_rpc::FerrumRpcClient as _;
use ferrum_rpc::types::rpc::GetRawTransactionResult;
use ferrum_script::templates;
use ferrum_types::{Transaction, Txid};
use serde_json::json;

use crate::commands::Context;
use crate::error::{CliError, CliResult};
use crate::output::CommandOutput;
use crate::rpc::rpc_err;

/// `tx decode`.
///
/// # Errors
///
/// [`CliError::Invalid`] when the hex or the envelope does not decode. A
/// trailing byte is a decode failure, not a warning: CONTRACT §2 forbids
/// tolerating one, because a tolerated suffix is a txid-malleability bug.
pub fn decode(hex_text: &str) -> CliResult<CommandOutput> {
    let raw = hex::decode(hex_text.trim().trim_start_matches("0x"))
        .map_err(|e| CliError::invalid("tx", hex_text, e.to_string()))?;
    let tx = Transaction::decode_envelope(&raw)
        .map_err(|e| CliError::invalid("tx", hex_text, e.to_string()))?;
    let txid = ferrum_storage::txid(&tx);

    Ok(CommandOutput::scalar("txid", txid.to_string())
        .with_json(describe(&tx, &txid))
        .with_field("version", tx.version)
        .with_field("inputs", tx.inputs.len())
        .with_field("outputs", tx.outputs.len())
        .with_field("size", tx.serialized_size())
        .with_field("coinbase", tx.is_coinbase()))
}

/// The JSON rendering of a decoded transaction.
///
/// Its own shape rather than `ferrum_rpc`'s: this path never talks to a node,
/// so there is no server DTO to echo, and a local decode should not depend on
/// a wire type it does not otherwise use.
fn describe(tx: &Transaction, txid: &Txid) -> serde_json::Value {
    let inputs: Vec<_> = tx
        .inputs
        .iter()
        .map(|input| {
            json!({
                "txid": input.prev_out.txid.to_string(),
                "vout": input.prev_out.vout,
                "coinbase": input.prev_out.is_null(),
                "script_sig": input.script_sig.to_hex(),
                "sequence": input.sequence,
            })
        })
        .collect();
    let outputs: Vec<_> = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(n, output)| {
            json!({
                "n": n,
                "value": output.value.to_frm_string(),
                "value_grains": output.value.to_grains().to_string(),
                "script_pubkey": output.script_pubkey.to_hex(),
                "script_type": format!("{:?}", templates::classify(&output.script_pubkey)),
            })
        })
        .collect();

    json!({
        "txid": txid.to_string(),
        "version": tx.version,
        "lock_time": tx.lock_time,
        "size": tx.serialized_size(),
        "coinbase": tx.is_coinbase(),
        // `None` on overflow, which a decoded-but-invalid transaction can have.
        "total_output": tx.total_output().map(ferrum_types::Amount::to_frm_string),
        "vin": inputs,
        "vout": outputs,
    })
}

/// `tx send`.
///
/// # Errors
///
/// [`CliError::Rpc`] when the node refuses the transaction, and
/// [`CliError::Invalid`] when the hex does not decode locally — checked first,
/// so a typo is caught without a round trip.
pub async fn send(ctx: &Context, hex_text: &str) -> CliResult<CommandOutput> {
    let cleaned = hex_text.trim().trim_start_matches("0x").to_owned();
    let raw = hex::decode(&cleaned).map_err(|e| CliError::invalid("tx", hex_text, e.to_string()))?;
    Transaction::decode_envelope(&raw)
        .map_err(|e| CliError::invalid("tx", hex_text, e.to_string()))?;

    let client = ctx.client()?;
    let txid = client.send_raw_transaction(cleaned).await.map_err(rpc_err("sendrawtransaction"))?;
    Ok(CommandOutput::scalar("txid", txid))
}

/// `tx get`.
///
/// # Errors
///
/// [`CliError::Invalid`] for a malformed txid and [`CliError::Rpc`] when the
/// node does not have it.
pub async fn get(ctx: &Context, txid: &str, raw: bool) -> CliResult<CommandOutput> {
    let parsed = Txid::from_hex(txid.trim())
        .map_err(|e| CliError::invalid("txid", txid, e.to_string()))?;
    let client = ctx.client()?;
    let result = client
        .get_raw_transaction(parsed.to_string(), Some(!raw))
        .await
        .map_err(rpc_err("getrawtransaction"))?;

    match result {
        GetRawTransactionResult::Hex(hex_body) => Ok(CommandOutput::scalar("hex", hex_body)),
        GetRawTransactionResult::Verbose(tx) => {
            let document = serde_json::to_value(&*tx)
                .map_err(|e| CliError::internal(format!("cannot render transaction: {e}")))?;
            Ok(CommandOutput::scalar("txid", tx.txid.clone())
                .with_json(document)
                .with_field("size", tx.size)
                .with_field("value", format!("{} FRM", tx.value.0.to_frm_string()))
                .with_field("confirmations", tx.confirmations.unwrap_or(0)))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ferrum_types::{Amount, OutPoint, Script, TxIn, TxOut};

    fn a_transaction() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn::new(OutPoint::new(Txid::ZERO, 3), Script::new(vec![0x51]))],
            outputs: vec![TxOut::new(Amount::from_grains(12_345), Script::new(vec![0x6a]))],
            lock_time: 7,
        }
    }

    #[test]
    fn a_round_tripped_envelope_decodes_to_the_same_txid() {
        let tx = a_transaction();
        let hex_body = hex::encode(tx.encode_envelope());
        let out = decode(&hex_body).unwrap();
        assert_eq!(out.bare.as_deref(), Some(ferrum_storage::txid(&tx).to_string().as_str()));
        assert_eq!(out.json["lock_time"], 7);
        assert_eq!(out.json["vin"][0]["vout"], 3);
    }

    #[test]
    fn a_trailing_byte_is_refused() {
        let mut raw = a_transaction().encode_envelope();
        raw.push(0);
        assert!(decode(&hex::encode(raw)).is_err());
    }

    #[test]
    fn the_0x_prefix_is_accepted() {
        let hex_body = format!("0x{}", hex::encode(a_transaction().encode_envelope()));
        assert!(decode(&hex_body).is_ok());
    }

    #[test]
    fn non_hex_is_refused_by_name() {
        let err = decode("zzzz").unwrap_err();
        assert!(err.to_string().contains("tx"), "{err}");
    }

    #[test]
    fn the_output_script_type_is_reported() {
        let out = decode(&hex::encode(a_transaction().encode_envelope())).unwrap();
        assert_eq!(out.json["vout"][0]["script_type"], "OpReturn");
    }
}
