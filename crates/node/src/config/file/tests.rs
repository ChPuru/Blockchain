#![allow(clippy::unwrap_used)]

use super::*;

fn p() -> PathBuf {
    PathBuf::from("ferrum.toml")
}

#[test]
fn the_documented_example_parses() {
    // Verbatim from docs/RUNNING.md section 3.
    let text = r#"
network  = "devnet"
datadir  = "./data"

[p2p]
listen   = "/ip4/0.0.0.0/tcp/8655"
peers    = ["/ip4/10.0.0.2/tcp/8655", "/ip4/10.0.0.3/tcp/8655"]

[rpc]
listen   = "127.0.0.1:8645"
ws       = true

[explorer]
listen   = "0.0.0.0:8665"
faucet   = true
faucet_amount = "1.0"

[mining]
enabled  = false
address  = "fer1qexample"
threads  = 4

[index]
transactions = true

[telemetry]
metrics  = "127.0.0.1:9100"
log_format = "json"
"#;
    let cfg = ConfigFile::parse(text, &p()).unwrap();
    assert_eq!(cfg.network.as_deref(), Some("devnet"));
    assert_eq!(cfg.datadir, Some(PathBuf::from("./data")));
    assert_eq!(cfg.p2p.peers.as_ref().map(Vec::len), Some(2));
    assert_eq!(cfg.rpc.ws, Some(true));
    assert_eq!(cfg.explorer.faucet_amount.as_deref(), Some("1.0"));
    assert_eq!(cfg.mining.threads, Some(4));
    assert_eq!(cfg.index.transactions, Some(true));
    assert_eq!(cfg.telemetry.log_format.as_deref(), Some("json"));
}

#[test]
fn an_empty_file_is_valid_and_sets_nothing() {
    let cfg = ConfigFile::parse("", &p()).unwrap();
    assert_eq!(cfg, ConfigFile::default());
}

#[test]
fn an_unknown_field_is_rejected_rather_than_ignored() {
    let e = ConfigFile::parse("netwrok = \"devnet\"\n", &p()).unwrap_err();
    assert!(matches!(e, ConfigError::ParseFile { .. }), "{e}");
}

#[test]
fn an_unknown_section_is_rejected() {
    let e = ConfigFile::parse("[minning]\nenabled = true\n", &p()).unwrap_err();
    assert!(matches!(e, ConfigError::ParseFile { .. }), "{e}");
}

#[test]
fn a_field_of_the_wrong_type_is_rejected() {
    let e = ConfigFile::parse("[rpc]\nws = \"yes\"\n", &p()).unwrap_err();
    assert!(matches!(e, ConfigError::ParseFile { .. }), "{e}");
}

#[test]
fn reading_a_missing_file_names_the_path() {
    let e = ConfigFile::load(Path::new("definitely-not-here.toml")).unwrap_err();
    match e {
        ConfigError::ReadFile { path, .. } => {
            assert_eq!(path, PathBuf::from("definitely-not-here.toml"));
        }
        other => panic!("expected ReadFile, got {other}"),
    }
}

#[test]
fn a_consensus_file_decodes_its_validator_set() {
    let key = "ab".repeat(32);
    let text = format!("bft_activation_height = 50000\nbft_validators = [\"{key}\"]\n");
    let cfg = ConsensusFile::parse(&text, &p()).unwrap();
    assert_eq!(cfg.bft_activation_height, Some(50_000));
    let validators = cfg.validators().unwrap();
    assert_eq!(validators.len(), 1);
    assert_eq!(validators[0].0, [0xabu8; 32]);
}

#[test]
fn a_short_validator_key_is_rejected() {
    let cfg = ConsensusFile::parse("bft_validators = [\"abcd\"]\n", &p()).unwrap();
    assert!(matches!(cfg.validators(), Err(ConfigError::ValidatorKey(_))));
}

#[test]
fn a_non_hex_validator_key_is_rejected() {
    let cfg = ConsensusFile::parse("bft_validators = [\"zz\"]\n", &p()).unwrap();
    assert!(matches!(cfg.validators(), Err(ConfigError::ValidatorKey(_))));
}
