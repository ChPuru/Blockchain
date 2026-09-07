#![allow(clippy::unwrap_used)]

use ferrum_crypto::{PublicKey, SecretKey};

use super::*;
use crate::config::MapEnv;
use crate::config::file::{
    ConsensusSection, ExplorerSection, IndexSection, MiningSection, P2pSection, RpcSection,
    TelemetrySection,
};

fn devnet_address() -> (Address, String) {
    let sk = SecretKey::from_bytes(&[7u8; 32]).unwrap();
    let pk: PublicKey = sk.public_key();
    let address = Address::p2pkh(Network::Devnet, &pk);
    let text = address.encode();
    (address, text)
}

fn cfg(cli: CliOverrides, env: MapEnv, file: Option<ConfigFile>) -> NodeConfig {
    resolve(&cli, &env, file.as_ref()).unwrap()
}

// ---------------------------------------------------------------- defaults

#[test]
fn with_nothing_set_every_field_is_a_network_default() {
    let c = cfg(CliOverrides::default(), MapEnv::new(), None);
    assert_eq!(c.network, Network::Mainnet);
    assert_eq!(c.rpc_listen, SocketAddr::from(([127, 0, 0, 1], 8645)));
    assert_eq!(c.explorer_listen, SocketAddr::from(([127, 0, 0, 1], 8665)));
    assert_eq!(c.p2p_listen.to_string(), "/ip4/0.0.0.0/tcp/8655");
    assert_eq!(c.metrics_listen, None);
    assert!(!c.mine);
    assert!(!c.index);
    assert_eq!(c.log_format, LogFormat::Text);
    assert_eq!(c.source_of(field::RPC_LISTEN), ValueSource::Default);
}

#[test]
fn the_default_ports_are_the_ones_the_devnet_scripts_assume() {
    assert_eq!(DEFAULT_RPC_PORT, 8645);
    assert_eq!(DEFAULT_P2P_PORT, 8655);
    assert_eq!(DEFAULT_EXPLORER_PORT, 8665);
    assert_eq!(DEFAULT_METRICS_PORT, 9100);
}

#[test]
fn the_datadir_default_is_per_network() {
    for network in [Network::Mainnet, Network::Testnet, Network::Devnet] {
        let d = NetworkDefaults::for_network(network);
        assert_eq!(d.datadir, PathBuf::from("data").join(network.to_string()));
    }
}

#[test]
fn the_faucet_defaults_on_for_devnet_only() {
    assert!(NetworkDefaults::for_network(Network::Devnet).faucet);
    assert!(!NetworkDefaults::for_network(Network::Mainnet).faucet);
    assert!(!NetworkDefaults::for_network(Network::Testnet).faucet);
}

// ------------------------------------------------------------- precedence

#[test]
fn the_cli_beats_the_environment() {
    let c = cfg(
        CliOverrides { rpc_listen: Some("127.0.0.1:1111".to_owned()), ..Default::default() },
        MapEnv::new().with(ENV_RPC_LISTEN, "127.0.0.1:2222"),
        None,
    );
    assert_eq!(c.rpc_listen.port(), 1111);
    assert_eq!(c.source_of(field::RPC_LISTEN), ValueSource::Cli);
}

#[test]
fn the_environment_beats_the_config_file() {
    let file = ConfigFile {
        rpc: RpcSection { listen: Some("127.0.0.1:3333".to_owned()), ws: None },
        ..Default::default()
    };
    let c = cfg(
        CliOverrides::default(),
        MapEnv::new().with(ENV_RPC_LISTEN, "127.0.0.1:2222"),
        Some(file),
    );
    assert_eq!(c.rpc_listen.port(), 2222);
    assert_eq!(c.source_of(field::RPC_LISTEN), ValueSource::Env);
}

#[test]
fn the_config_file_beats_the_network_default() {
    let file = ConfigFile {
        rpc: RpcSection { listen: Some("127.0.0.1:3333".to_owned()), ws: None },
        ..Default::default()
    };
    let c = cfg(CliOverrides::default(), MapEnv::new(), Some(file));
    assert_eq!(c.rpc_listen.port(), 3333);
    assert_eq!(c.source_of(field::RPC_LISTEN), ValueSource::File);
}

#[test]
fn the_full_chain_holds_for_one_field() {
    let file = ConfigFile {
        rpc: RpcSection { listen: Some("127.0.0.1:3333".to_owned()), ws: None },
        ..Default::default()
    };
    let env = MapEnv::new().with(ENV_RPC_LISTEN, "127.0.0.1:2222");
    let cli = CliOverrides { rpc_listen: Some("127.0.0.1:1111".to_owned()), ..Default::default() };

    assert_eq!(cfg(cli.clone(), env.clone(), Some(file.clone())).rpc_listen.port(), 1111);
    assert_eq!(cfg(CliOverrides::default(), env, Some(file.clone())).rpc_listen.port(), 2222);
    assert_eq!(cfg(CliOverrides::default(), MapEnv::new(), Some(file)).rpc_listen.port(), 3333);
    assert_eq!(cfg(CliOverrides::default(), MapEnv::new(), None).rpc_listen.port(), 8645);
}

#[test]
fn precedence_is_per_field_not_per_layer() {
    // The file sets the explorer; the flag sets metrics. Both must survive.
    let file = ConfigFile {
        explorer: ExplorerSection { listen: Some("0.0.0.0:9999".to_owned()), ..Default::default() },
        ..Default::default()
    };
    let c = cfg(
        CliOverrides { metrics_listen: Some("127.0.0.1:9100".to_owned()), ..Default::default() },
        MapEnv::new(),
        Some(file),
    );
    assert_eq!(c.explorer_listen.port(), 9999);
    assert_eq!(c.metrics_listen.map(|a| a.port()), Some(9100));
    assert_eq!(c.source_of(field::EXPLORER_LISTEN), ValueSource::File);
    assert_eq!(c.source_of(field::METRICS_LISTEN), ValueSource::Cli);
}

#[test]
fn the_network_itself_follows_the_same_precedence() {
    let file = ConfigFile { network: Some("mainnet".to_owned()), ..Default::default() };
    assert_eq!(
        cfg(CliOverrides::default(), MapEnv::new(), Some(file.clone())).network,
        Network::Mainnet
    );
    assert_eq!(
        cfg(
            CliOverrides::default(),
            MapEnv::new().with(ENV_NETWORK, "testnet"),
            Some(file.clone())
        )
        .network,
        Network::Testnet
    );
    assert_eq!(
        cfg(
            CliOverrides { network: Some("devnet".to_owned()), ..Default::default() },
            MapEnv::new().with(ENV_NETWORK, "testnet"),
            Some(file)
        )
        .network,
        Network::Devnet
    );
}

#[test]
fn the_network_selects_the_parameter_set() {
    let c = cfg(
        CliOverrides { network: Some("devnet".to_owned()), ..Default::default() },
        MapEnv::new(),
        None,
    );
    assert_eq!(c.params, ChainParams::devnet());
    assert_eq!(c.params.chain_id, Network::Devnet.chain_id());
}

#[test]
fn an_absent_mine_flag_does_not_disable_a_configured_miner() {
    let file = ConfigFile {
        mining: MiningSection { enabled: Some(true), ..Default::default() },
        ..Default::default()
    };
    let c = cfg(CliOverrides::default(), MapEnv::new(), Some(file));
    assert!(c.mine, "silence from the flag layer must not override the file");
    assert_eq!(c.source_of(field::MINE), ValueSource::File);
}

#[test]
fn an_explicit_false_in_the_file_does_disable_the_miner() {
    let file = ConfigFile {
        mining: MiningSection { enabled: Some(false), ..Default::default() },
        ..Default::default()
    };
    let c = cfg(CliOverrides::default(), MapEnv::new(), Some(file));
    assert!(!c.mine);
}

#[test]
fn the_environment_can_switch_mining_off_against_the_file() {
    let file = ConfigFile {
        mining: MiningSection { enabled: Some(true), ..Default::default() },
        ..Default::default()
    };
    let c = cfg(CliOverrides::default(), MapEnv::new().with(ENV_MINE, "0"), Some(file));
    assert!(!c.mine);
    assert_eq!(c.source_of(field::MINE), ValueSource::Env);
}

#[test]
fn the_index_flag_follows_the_same_rule() {
    let file =
        ConfigFile { index: IndexSection { transactions: Some(true) }, ..Default::default() };
    assert!(cfg(CliOverrides::default(), MapEnv::new(), Some(file.clone())).index);
    assert!(
        !cfg(CliOverrides::default(), MapEnv::new().with(ENV_INDEX, "false"), Some(file)).index
    );
    assert!(
        cfg(CliOverrides { index: Some(true), ..Default::default() }, MapEnv::new(), None).index
    );
}

#[test]
fn peers_come_from_exactly_one_layer_never_a_merge() {
    // Merging peer lists across layers would make "remove a peer" impossible.
    let file = ConfigFile {
        p2p: P2pSection {
            listen: None,
            peers: Some(vec![
                "/ip4/10.0.0.2/tcp/8655".to_owned(),
                "/ip4/10.0.0.3/tcp/8655".to_owned(),
            ]),
        },
        ..Default::default()
    };
    let c = cfg(
        CliOverrides {
            peers: Some(vec!["/ip4/127.0.0.1/tcp/8656".to_owned()]),
            ..Default::default()
        },
        MapEnv::new(),
        Some(file),
    );
    assert_eq!(c.peers.len(), 1);
    assert_eq!(c.peers[0].to_string(), "/ip4/127.0.0.1/tcp/8656");
}

#[test]
fn peers_can_come_from_a_comma_separated_environment_variable() {
    let c = cfg(
        CliOverrides::default(),
        MapEnv::new().with(ENV_PEERS, "/ip4/10.0.0.2/tcp/8655, /ip4/10.0.0.3/tcp/8655"),
        None,
    );
    assert_eq!(c.peers.len(), 2);
    assert_eq!(c.source_of(field::PEERS), ValueSource::Env);
}

#[test]
fn the_log_format_follows_precedence() {
    let file = ConfigFile {
        telemetry: TelemetrySection { metrics: None, log_format: Some("json".to_owned()) },
        ..Default::default()
    };
    assert_eq!(
        cfg(CliOverrides::default(), MapEnv::new(), Some(file.clone())).log_format,
        LogFormat::Json
    );
    assert_eq!(
        cfg(
            CliOverrides { log_format: Some("text".to_owned()), ..Default::default() },
            MapEnv::new(),
            Some(file)
        )
        .log_format,
        LogFormat::Text
    );
}

#[test]
fn metrics_stay_off_unless_a_listen_address_is_given() {
    assert_eq!(cfg(CliOverrides::default(), MapEnv::new(), None).metrics_listen, None);
    let c = cfg(
        CliOverrides::default(),
        MapEnv::new().with(ENV_METRICS_LISTEN, "127.0.0.1:9100"),
        None,
    );
    assert_eq!(c.metrics_listen.map(|a| a.port()), Some(9100));
}

#[test]
fn the_forced_engine_follows_precedence() {
    let file = ConfigFile {
        consensus: ConsensusSection { engine: Some("pow".to_owned()), ..Default::default() },
        ..Default::default()
    };
    assert_eq!(
        cfg(CliOverrides::default(), MapEnv::new(), Some(file.clone())).consensus,
        Some(EngineChoice::Pow)
    );
    assert_eq!(
        cfg(
            CliOverrides { consensus: Some("bft".to_owned()), ..Default::default() },
            MapEnv::new(),
            Some(file)
        )
        .consensus,
        Some(EngineChoice::Bft)
    );
    assert_eq!(cfg(CliOverrides::default(), MapEnv::new(), None).consensus, None);
}

// ------------------------------------------------------------- rejections

#[test]
fn a_bad_socket_address_names_the_layer_that_supplied_it() {
    let e = resolve(
        &CliOverrides::default(),
        &MapEnv::new().with(ENV_RPC_LISTEN, "not-an-address"),
        None,
    )
    .unwrap_err();
    match e {
        ConfigError::Invalid { layer, key, .. } => {
            assert_eq!(layer, ValueSource::Env);
            assert_eq!(key, ENV_RPC_LISTEN);
        }
        other => panic!("expected Invalid, got {other}"),
    }
}

#[test]
fn a_bad_multiaddr_from_the_command_line_names_the_flag() {
    let e = resolve(
        &CliOverrides { p2p_listen: Some("127.0.0.1:8655".to_owned()), ..Default::default() },
        &MapEnv::new(),
        None,
    )
    .unwrap_err();
    match e {
        ConfigError::Invalid { layer, key, .. } => {
            assert_eq!(layer, ValueSource::Cli);
            assert_eq!(key, "--p2p-listen");
        }
        other => panic!("expected Invalid, got {other}"),
    }
}

#[test]
fn an_unknown_network_is_refused() {
    let e = resolve(
        &CliOverrides { network: Some("mainet".to_owned()), ..Default::default() },
        &MapEnv::new(),
        None,
    )
    .unwrap_err();
    assert!(matches!(e, ConfigError::UnknownNetwork(_)), "{e}");
}

#[test]
fn a_boolean_typo_is_refused_rather_than_read_as_false() {
    let e = resolve(&CliOverrides::default(), &MapEnv::new().with(ENV_MINE, "maybe"), None)
        .unwrap_err();
    assert!(matches!(e, ConfigError::Invalid { .. }), "{e}");
}

#[test]
fn a_mine_address_for_another_network_is_refused() {
    let (_, text) = devnet_address();
    let e = resolve(
        &CliOverrides {
            network: Some("mainnet".to_owned()),
            mine_address: Some(text),
            ..Default::default()
        },
        &MapEnv::new(),
        None,
    )
    .unwrap_err();
    assert!(matches!(e, ConfigError::AddressNetworkMismatch { .. }), "{e}");
}

#[test]
fn a_mine_address_for_this_network_is_accepted() {
    let (address, text) = devnet_address();
    let c = cfg(
        CliOverrides {
            network: Some("devnet".to_owned()),
            mine_address: Some(text),
            ..Default::default()
        },
        MapEnv::new(),
        None,
    );
    assert_eq!(c.mine_address, Some(address));
}

#[test]
fn an_undecodable_mine_address_is_refused() {
    let e = resolve(
        &CliOverrides {
            network: Some("devnet".to_owned()),
            mine_address: Some("not-an-address".to_owned()),
            ..Default::default()
        },
        &MapEnv::new(),
        None,
    )
    .unwrap_err();
    assert!(matches!(e, ConfigError::Address { .. }), "{e}");
}

#[test]
fn no_mine_address_means_derive_one_from_the_node_key() {
    let c = cfg(
        CliOverrides { network: Some("devnet".to_owned()), mine: Some(true), ..Default::default() },
        MapEnv::new(),
        None,
    );
    assert!(c.mine);
    assert_eq!(c.mine_address, None, "a devnet must start with no wallet setup");
}

// -------------------------------------------------------- consensus file

#[test]
fn a_consensus_file_schedules_the_fork() {
    let mut c = cfg(CliOverrides::default(), MapEnv::new(), None);
    assert_eq!(c.params.bft_activation_height, None);
    let consensus = ConsensusFile {
        bft_activation_height: Some(50_000),
        bft_validators: vec!["ab".repeat(32); 4],
    };
    apply_consensus_file(&mut c, &consensus).unwrap();
    assert_eq!(c.params.bft_activation_height, Some(50_000));
    assert_eq!(c.params.bft_validators.len(), 4);
}

#[test]
fn an_empty_consensus_file_changes_nothing() {
    let mut c = cfg(CliOverrides::default(), MapEnv::new(), None);
    let before = c.params.clone();
    apply_consensus_file(&mut c, &ConsensusFile::default()).unwrap();
    assert_eq!(c.params, before);
}

#[test]
fn the_faucet_amount_is_parsed_as_an_integer_count_of_grains() {
    let file = ConfigFile {
        explorer: ExplorerSection { faucet_amount: Some("1.5".to_owned()), ..Default::default() },
        ..Default::default()
    };
    let c = cfg(CliOverrides::default(), MapEnv::new(), Some(file));
    assert_eq!(c.faucet_amount, Some(Amount::from_grains(150_000_000)));
}

#[test]
fn a_malformed_faucet_amount_is_refused() {
    let file = ConfigFile {
        explorer: ExplorerSection {
            faucet_amount: Some("one and a half".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    };
    let e = resolve(&CliOverrides::default(), &MapEnv::new(), Some(&file)).unwrap_err();
    assert!(matches!(e, ConfigError::Invalid { .. }), "{e}");
}
