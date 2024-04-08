#![allow(clippy::needless_raw_string_hashes)] // triggered by `expect_test` snapshots

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use assertables::{assert_contains, assert_contains_as_result};
use expect_test::expect;
use iroha_config::parameters::{
    actual::Root as Config,
    user::{CliContext, Root as UserConfig},
};
use iroha_config_base::{
    env::MockEnv,
    read::{ConfigReader, ReadConfig},
};

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

fn load_config_from_fixtures(
    path: impl AsRef<Path>,
    submit_genesis: bool,
) -> error_stack::Result<Config, iroha_config::parameters::actual::LoadError> {
    Config::load(
        Some(fixtures_dir().join(path)),
        CliContext { submit_genesis },
    )
}

/// This test not only asserts that the minimal set of fields is enough;
/// it also gives an insight into every single default value
#[test]
#[allow(clippy::too_many_lines)]
fn minimal_config_snapshot() {
    let config = load_config_from_fixtures("minimal_with_trusted_peers.toml", false)
        .expect("config should be valid");

    expect![[r#"
        Root {
            common: Common {
                chain_id: ChainId(
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
                peer_id: PeerId {
                    address: 127.0.0.1:1337,
                    public_key: PublicKey(
                        ed25519(
                            "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB",
                        ),
                    ),
                },
            },
            network: Network {
                address: WithOrigin {
                    value: 127.0.0.1:1337,
                    origin: File {
                        path: "tests/fixtures/base.toml",
                        id: ParameterId(network.address),
                    },
                },
                idle_timeout: 60s,
            },
            genesis: Partial {
                public_key: PublicKey(
                    ed25519(
                        "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB",
                    ),
                ),
            },
            torii: Torii {
                address: WithOrigin {
                    value: 127.0.0.1:8080,
                    origin: File {
                        path: "tests/fixtures/base.toml",
                        id: ParameterId(torii.address),
                    },
                },
                max_content_len_bytes: 16777216,
            },
            kura: Kura {
                init_mode: Strict,
                store_dir: WithOrigin {
                    value: "./storage",
                    origin: Default {
                        id: ParameterId(kura.store_dir),
                    },
                },
                debug_output_new_blocks: false,
            },
            sumeragi: Sumeragi {
                trusted_peers: UniqueVec(
                    [
                        PeerId {
                            address: 127.0.0.1:1338,
                            public_key: PublicKey(
                                ed25519(
                                    "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB",
                                ),
                            ),
                        },
                    ],
                ),
                debug_force_soft_fork: false,
            },
            block_sync: BlockSync {
                gossip_period: 10s,
                gossip_max_size: 4,
            },
            transaction_gossiper: TransactionGossiper {
                gossip_period: 1s,
                gossip_max_size: 500,
            },
            live_query_store: LiveQueryStore {
                idle_time: 30s,
            },
            logger: Logger {
                level: INFO,
                format: Full,
            },
            queue: Queue {
                capacity: 65536,
                capacity_per_user: 65536,
                transaction_time_to_live: HumanDuration(
                    86400s,
                ),
                future_threshold: HumanDuration(
                    1s,
                ),
            },
            snapshot: Snapshot {
                mode: ReadWrite,
                create_every: HumanDuration(
                    60s,
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
            chain_wide: ChainWide {
                max_transactions_in_block: 512,
                block_time: 2s,
                commit_time: 4s,
                transaction_limits: TransactionLimits {
                    max_instruction_number: 4096,
                    max_wasm_size_bytes: 4194304,
                },
                domain_metadata_limits: Limits {
                    capacity: 1048576,
                    max_entry_len: 4096,
                },
                asset_definition_metadata_limits: Limits {
                    capacity: 1048576,
                    max_entry_len: 4096,
                },
                account_metadata_limits: Limits {
                    capacity: 1048576,
                    max_entry_len: 4096,
                },
                asset_metadata_limits: Limits {
                    capacity: 1048576,
                    max_entry_len: 4096,
                },
                trigger_metadata_limits: Limits {
                    capacity: 1048576,
                    max_entry_len: 4096,
                },
                ident_length_limits: LengthLimits {
                    min: 1,
                    max: 128,
                },
                executor_runtime: WasmRuntime {
                    fuel_limit: 55000000,
                    max_memory_bytes: 524288000,
                },
                wasm_runtime: WasmRuntime {
                    fuel_limit: 55000000,
                    max_memory_bytes: 524288000,
                },
            },
        }"#]].assert_eq(&format!("{config:#?}"));
}

#[test]
fn config_with_genesis() {
    let _config = load_config_from_fixtures("minimal_alone_with_genesis.toml", true)
        .expect("should be valid");
}

#[test]
fn minimal_with_genesis_but_no_cli_arg_fails() {
    let error = load_config_from_fixtures("minimal_alone_with_genesis.toml", false)
        .expect_err("should fail since `--submit-genesis=false`");

    assert_contains!(
        format!("{error:?}"),
        "`genesis.file` and `genesis.private_key` are set, but `--submit-genesis` is not"
    );
}

#[test]
fn minimal_without_genesis_but_with_submit_fails() {
    let error = load_config_from_fixtures("minimal_with_trusted_peers.toml", true).expect_err(
        "should fail since there is no genesis in the config, but `--submit-genesis=true`",
    );

    assert_contains!(
        format!("{error:?}"),
        "`--submit-genesis` is set, but `genesis.file` and `genesis.private_key` are not"
    )
}

#[test]
fn self_is_presented_in_trusted_peers() {
    let config =
        load_config_from_fixtures("minimal_alone_with_genesis.toml", true).expect("valid config");

    assert!(config
        .sumeragi
        .trusted_peers
        .contains(&config.common.peer_id()));
}

#[test]
fn missing_fields() {
    let error = load_config_from_fixtures("bad.missing_fields.toml", false)
        .expect_err("should fail without missing fields");

    assert_contains!(format!("{error:?}"), "missing parameter: `chain_id`");
    assert_contains!(format!("{error:?}"), "missing parameter: `public_key`");
    assert_contains!(format!("{error:?}"), "missing parameter: `network.address`");
}

#[test]
fn extra_fields() {
    let error = load_config_from_fixtures("bad.extra_fields.toml", false)
        .expect_err("should fail with extra field");

    assert_contains!(format!("{error:?}"), "Some parameters aren't recognised");
    assert_contains!(format!("{error:?}"), "unknown parameter: `bar`");
    assert_contains!(format!("{error:?}"), "unknown parameter: `foo`");
}

#[test]
fn inconsistent_genesis_config() {
    let error = load_config_from_fixtures("inconsistent_genesis.toml", false)
        .expect_err("should fail with bad genesis config");

    assert_contains!(
        format!("{error:?}"),
        "`genesis.private_key` is set, but `genesis.file` is not"
    );
}

/// Aims the purpose of checking that every single provided env variable is consumed and parsed
/// into a valid config.
#[test]
fn full_envs_set_is_consumed() {
    let env = test_env_from_file(fixtures_dir().join("full.env"));

    let reader = ConfigReader::new().with_env(env.clone());
    let (_config, reader) = UserConfig::read(reader);
    reader.into_result().expect("should be fine");

    assert_eq!(env.unvisited(), HashSet::new());
}

#[test]
fn config_from_file_and_env() {
    let env = test_env_from_file(fixtures_dir().join("minimal_file_and_env.env"));
    let reader = ConfigReader::new()
        .with_env(env)
        .read_toml_with_extends(fixtures_dir().join("minimal_file_and_env.toml"))
        .expect("files are fine");
    let (config, reader) = UserConfig::read(reader);
    reader.into_result().expect("should be fine");
    let _config = config
        .unwrap()
        .parse(CliContext {
            submit_genesis: false,
        })
        .expect("should be fine, again");
}

#[test]
fn fails_if_torii_address_and_p2p_address_are_equal() {
    let error = load_config_from_fixtures("bad.torii_addr_eq_p2p_addr.toml", false)
        .expect_err("should fail because of bad input");

    assert_contains!(
        format!("{error:?}"),
        "Torii and Network addresses are the same, but should be different"
    );
}

#[test]
fn full_config_parses_fine() {
    let _cfg = load_config_from_fixtures("full.toml", true).expect("should be fine");
}
