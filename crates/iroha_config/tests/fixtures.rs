#![allow(clippy::needless_raw_string_hashes)] // triggered by `expect!` snapshots

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use assertables::{assert_contains, assert_contains_as_result};
use error_stack::ResultExt;
use expect_test::expect;
use iroha_config::parameters::{actual::Root as Config, user::Root as UserConfig};
use iroha_config_base::{env::MockEnv, read::ConfigReader};
use iroha_data_model::Identifiable;
use thiserror::Error;

fn fixtures_dir() -> PathBuf {
    // CWD is the crate's root
    PathBuf::from("tests/fixtures")
}

fn parse_env(raw: impl AsRef<str>) -> HashMap<String, String> {
    raw.as_ref()
        .lines()
        .map(|line| {
            let mut items = line.split('=');
            let key = items
                .next()
                .expect("line should be in {key}={value} format");
            let value = items
                .next()
                .expect("line should be in {key}={value} format");
            (key.to_string(), value.to_string())
        })
        .collect()
}

fn test_env_from_file(p: impl AsRef<Path>) -> MockEnv {
    let contents = fs::read_to_string(p).expect("the path should be valid");
    let map = parse_env(contents);
    MockEnv::with_map(map)
}

#[derive(Error, Debug)]
#[error("failed to load config from fixtures")]
struct FixtureConfigLoadError;

fn load_config_from_fixtures(
    path: impl AsRef<Path>,
) -> error_stack::Result<Config, FixtureConfigLoadError> {
    let config = ConfigReader::new()
        .read_toml_with_extends(fixtures_dir().join(path))
        .change_context(FixtureConfigLoadError)?
        .read_and_complete::<UserConfig>()
        .change_context(FixtureConfigLoadError)?
        .parse()
        .change_context(FixtureConfigLoadError)?;

    Ok(config)
}

/// This test not only asserts that the minimal set of fields is enough;
/// it also gives an insight into every single default value
#[test]
#[allow(clippy::too_many_lines)]
fn minimal_config_snapshot() {
    let config = load_config_from_fixtures("minimal_with_trusted_peers.toml")
        .expect("config should be valid");

    expect![[r#"
        Root {
            common: Common {
                chain: ChainId(
                    "0",
                ),
                key_pair: KeyPair {
                    public_key: PublicKey(
                        ed25519(
                            "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB",
                        ),
                    ),
                    private_key: "[REDACTED PrivateKey]",
                },
                peer: Peer {
                    address: 127.0.0.1:1337,
                    id: ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB,
                },
                trusted_peers: WithOrigin {
                    value: TrustedPeers {
                        myself: Peer {
                            address: 127.0.0.1:1337,
                            id: ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB,
                        },
                        others: UniqueVec(
                            [
                                Peer {
                                    address: 127.0.0.1:1338,
                                    id: ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB,
                                },
                            ],
                        ),
                    },
                    origin: File {
                        id: ParameterId(trusted_peers),
                        path: "tests/fixtures/base_trusted_peers.toml",
                    },
                },
            },
            network: Network {
                address: WithOrigin {
                    value: 127.0.0.1:1337,
                    origin: File {
                        id: ParameterId(network.address),
                        path: "tests/fixtures/base.toml",
                    },
                },
                public_address: WithOrigin {
                    value: 127.0.0.1:1337,
                    origin: File {
                        id: ParameterId(network.public_address),
                        path: "tests/fixtures/base.toml",
                    },
                },
                idle_timeout: 60s,
            },
            genesis: Genesis {
                public_key: PublicKey(
                    ed25519(
                        "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB",
                    ),
                ),
                file: None,
            },
            torii: Torii {
                address: WithOrigin {
                    value: 127.0.0.1:8080,
                    origin: File {
                        id: ParameterId(torii.address),
                        path: "tests/fixtures/base.toml",
                    },
                },
                max_content_len: Bytes(
                    16777216,
                ),
            },
            kura: Kura {
                init_mode: Strict,
                store_dir: WithOrigin {
                    value: "./storage",
                    origin: Default {
                        id: ParameterId(kura.store_dir),
                    },
                },
                blocks_in_memory: 128,
                debug_output_new_blocks: false,
            },
            sumeragi: Sumeragi {
                debug_force_soft_fork: false,
            },
            block_sync: BlockSync {
                gossip_period: 10s,
                gossip_size: 4,
            },
            transaction_gossiper: TransactionGossiper {
                gossip_period: 1s,
                gossip_size: 500,
            },
            live_query_store: LiveQueryStore {
                idle_time: 10s,
                capacity: 128,
                capacity_per_user: 128,
            },
            logger: Logger {
                level: info,
                format: Full,
            },
            queue: Queue {
                capacity: 65536,
                capacity_per_user: 65536,
                transaction_time_to_live: 86400s,
            },
            snapshot: Snapshot {
                mode: ReadWrite,
                create_every_ms: DurationMs(
                    600s,
                ),
                store_dir: WithOrigin {
                    value: "./storage/snapshot",
                    origin: Default {
                        id: ParameterId(snapshot.store_dir),
                    },
                },
            },
            telemetry: None,
            dev_telemetry: DevTelemetry {
                out_file: None,
            },
        }"#]].assert_eq(&format!("{config:#?}"));
}

#[test]
fn config_with_genesis() {
    let _config =
        load_config_from_fixtures("minimal_alone_with_genesis.toml").expect("should be valid");
}

#[test]
fn self_is_presented_in_trusted_peers() {
    let config =
        load_config_from_fixtures("minimal_alone_with_genesis.toml").expect("valid config");

    assert!(config
        .common
        .trusted_peers
        .value()
        .clone()
        .into_non_empty_vec()
        .contains(config.common.peer.id()));
}

#[test]
fn missing_fields() {
    let error = load_config_from_fixtures("bad.missing_fields.toml")
        .expect_err("should fail without missing fields");

    assert_contains!(format!("{error:?}"), "missing parameter: `chain`");
    assert_contains!(format!("{error:?}"), "missing parameter: `public_key`");
    assert_contains!(format!("{error:?}"), "missing parameter: `network.address`");
}

#[test]
fn extra_fields() {
    let error = load_config_from_fixtures("bad.extra_fields.toml")
        .expect_err("should fail with extra field");

    assert_contains!(format!("{error:?}"), "Found unrecognised parameters");
    assert_contains!(format!("{error:?}"), "unknown parameter: `bar`");
    assert_contains!(format!("{error:?}"), "unknown parameter: `foo`");
}

/// Aims the purpose of checking that every single provided env variable is consumed and parsed
/// into a valid config.
#[test]
fn full_envs_set_is_consumed() {
    let env = test_env_from_file(fixtures_dir().join("full.env"));

    ConfigReader::new()
        .with_env(env.clone())
        .read_and_complete::<UserConfig>()
        .expect("should be fine");

    assert_eq!(env.unvisited(), HashSet::new());
    assert_eq!(env.unknown(), HashSet::new());
}

#[test]
fn config_from_file_and_env() {
    let env = test_env_from_file(fixtures_dir().join("minimal_file_and_env.env"));

    ConfigReader::new()
        .with_env(env)
        .read_toml_with_extends(fixtures_dir().join("minimal_file_and_env.toml"))
        .expect("files are fine")
        .read_and_complete::<UserConfig>()
        .expect("should be fine")
        .parse()
        .expect("should be fine, again");
}

#[test]
fn full_config_parses_fine() {
    let _cfg = load_config_from_fixtures("full.toml").expect("should be fine");
}
