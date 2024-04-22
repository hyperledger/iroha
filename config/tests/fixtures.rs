#![allow(clippy::needless_raw_string_hashes)] // triggered by `expect_test` snapshots

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use eyre::Result;
use iroha_config::parameters::{
    actual::{Genesis, Root},
    user::{CliContext, RootPartial},
};
use iroha_config_base::{FromEnv, TestEnv, UnwrapPartial as _};

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

fn test_env_from_file(p: impl AsRef<Path>) -> TestEnv {
    let contents = fs::read_to_string(p).expect("the path should be valid");
    let map = parse_env(contents);
    TestEnv::with_map(map)
}

/// This test not only asserts that the minimal set of fields is enough;
/// it also gives an insight into every single default value
#[test]
#[allow(clippy::too_many_lines)]
fn minimal_config_snapshot() -> Result<()> {
    let config = RootPartial::from_toml(fixtures_dir().join("minimal_with_trusted_peers.toml"))?
        .unwrap_partial()?
        .parse(CliContext {
            submit_genesis: false,
        })?;

    let expected = expect_test::expect![[r#"
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
                address: 127.0.0.1:1337,
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
                address: 127.0.0.1:8080,
                max_content_len_bytes: 16777216,
            },
            kura: Kura {
                init_mode: Strict,
                store_dir: "./storage",
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
                transaction_time_to_live: 86400s,
                future_threshold: 1s,
            },
            snapshot: Snapshot {
                mode: ReadWrite,
                create_every: 60s,
                store_dir: "./storage/snapshot",
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
        }"#]];
    expected.assert_eq(&format!("{config:#?}"));

    Ok(())
}

#[test]
fn config_with_genesis() -> Result<()> {
    let _config = RootPartial::from_toml(fixtures_dir().join("minimal_alone_with_genesis.toml"))?
        .unwrap_partial()?
        .parse(CliContext {
            submit_genesis: true,
        })?;
    Ok(())
}

#[test]
fn minimal_with_genesis_but_no_cli_arg_fails() -> Result<()> {
    let error = RootPartial::from_toml(fixtures_dir().join("minimal_alone_with_genesis.toml"))?
        .unwrap_partial()?
        .parse(CliContext {
            submit_genesis: false,
        })
        .expect_err("should fail since `--submit-genesis=false`");

    let expected = expect_test::expect![[r#"
        `genesis.file` and `genesis.private_key` are presented, but `--submit-genesis` was not set
        The network consists from this one peer only (no `sumeragi.trusted_peers` provided). Since `--submit-genesis` is not set, there is no way to receive the genesis block. Either provide the genesis by setting `--submit-genesis` argument, `genesis.private_key`, and `genesis.file` configuration parameters, or increase the number of trusted peers in the network using `sumeragi.trusted_peers` configuration parameter."#]];
    expected.assert_eq(&format!("{error:#}"));

    Ok(())
}

#[test]
fn minimal_without_genesis_but_with_submit_fails() -> Result<()> {
    let error = RootPartial::from_toml(fixtures_dir().join("minimal_with_trusted_peers.toml"))?
        .unwrap_partial()?
        .parse(CliContext {
            submit_genesis: true,
        })
        .expect_err(
            "should fail since there is no genesis in the config, but `--submit-genesis=true`",
        );

    let expected = expect_test::expect!["`--submit-genesis` was set, but `genesis.file` and `genesis.private_key` are not presented"];
    expected.assert_eq(&format!("{error:#}"));

    Ok(())
}

#[test]
fn self_is_presented_in_trusted_peers() -> Result<()> {
    let config = RootPartial::from_toml(fixtures_dir().join("minimal_alone_with_genesis.toml"))?
        .unwrap_partial()?
        .parse(CliContext {
            submit_genesis: true,
        })?;

    assert!(config
        .sumeragi
        .trusted_peers
        .contains(&config.common.peer_id()));

    Ok(())
}

#[test]
fn missing_fields() -> Result<()> {
    let error = RootPartial::from_toml(fixtures_dir().join("bad.missing_fields.toml"))?
        .unwrap_partial()
        .expect_err("should fail with missing fields");

    let expected = expect_test::expect![[r#"
        missing field: `chain_id`
        missing field: `public_key`
        missing field: `private_key`
        missing field: `genesis.public_key`
        missing field: `network.address`
        missing field: `torii.address`"#]];
    expected.assert_eq(&format!("{error:#}"));

    Ok(())
}

#[test]
fn extra_fields() {
    let error = RootPartial::from_toml(fixtures_dir().join("extra_fields.toml"))
        .expect_err("should fail with extra fields");

    let expected = expect_test::expect!["cannot open file at location `tests/fixtures/extra_fields.toml`: No such file or directory (os error 2)"];
    expected.assert_eq(&format!("{error:#}"));
}

#[test]
fn inconsistent_genesis_config() -> Result<()> {
    let error = RootPartial::from_toml(fixtures_dir().join("inconsistent_genesis.toml"))?
        .unwrap_partial()
        .expect("all fields are present")
        .parse(CliContext {
            submit_genesis: false,
        })
        .expect_err("should fail with bad genesis config");

    let expected = expect_test::expect![[r#"
        `genesis.file` and `genesis.private_key` should be set together
        The network consists from this one peer only (no `sumeragi.trusted_peers` provided). Since `--submit-genesis` is not set, there is no way to receive the genesis block. Either provide the genesis by setting `--submit-genesis` argument, `genesis.private_key`, and `genesis.file` configuration parameters, or increase the number of trusted peers in the network using `sumeragi.trusted_peers` configuration parameter."#]];
    expected.assert_eq(&format!("{error:#}"));

    Ok(())
}

/// Aims the purpose of checking that every single provided env variable is consumed and parsed
/// into a valid config.
#[test]
#[allow(clippy::too_many_lines)]
fn full_envs_set_is_consumed() -> Result<()> {
    let env = test_env_from_file(fixtures_dir().join("full.env"));

    let layer = RootPartial::from_env(&env)?;

    assert_eq!(env.unvisited(), HashSet::new());

    let expected = expect_test::expect![[r#"
        RootPartial {
            extends: None,
            chain_id: Some(
                ChainId(
                    "0-0",
                ),
            ),
            public_key: Some(
                PublicKey(
                    ed25519(
                        "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB",
                    ),
                ),
            ),
            private_key: Some(
                "[REDACTED PrivateKey]",
            ),
            genesis: GenesisPartial {
                public_key: Some(
                    PublicKey(
                        ed25519(
                            "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB",
                        ),
                    ),
                ),
                private_key: Some(
                    "[REDACTED PrivateKey]",
                ),
                file: None,
            },
            kura: KuraPartial {
                init_mode: Some(
                    Strict,
                ),
                store_dir: Some(
                    "/store/path/from/env",
                ),
                debug: KuraDebugPartial {
                    output_new_blocks: Some(
                        false,
                    ),
                },
            },
            sumeragi: SumeragiPartial {
                trusted_peers: Some(
                    [
                        PeerId {
                            address: SocketAddrHost {
                                host: "iroha2",
                                port: 1339,
                            },
                            public_key: PublicKey(
                                ed25519(
                                    "ed0120312C1B7B5DE23D366ADCF23CD6DB92CE18B2AA283C7D9F5033B969C2DC2B92F4",
                                ),
                            ),
                        },
                    ],
                ),
                debug: SumeragiDebugPartial {
                    force_soft_fork: None,
                },
            },
            network: NetworkPartial {
                address: Some(
                    127.0.0.1:5432,
                ),
                block_gossip_max_size: None,
                block_gossip_period: None,
                transaction_gossip_max_size: None,
                transaction_gossip_period: None,
                idle_timeout: None,
            },
            logger: LoggerPartial {
                level: Some(
                    DEBUG,
                ),
                format: Some(
                    Pretty,
                ),
            },
            queue: QueuePartial {
                capacity: None,
                capacity_per_user: None,
                transaction_time_to_live: None,
                future_threshold: None,
            },
            snapshot: SnapshotPartial {
                mode: Some(
                    ReadWrite,
                ),
                create_every: None,
                store_dir: Some(
                    "/snapshot/path/from/env",
                ),
            },
            telemetry: TelemetryPartial {
                name: None,
                url: None,
                min_retry_period: None,
                max_retry_delay_exponent: None,
            },
            dev_telemetry: DevTelemetryPartial {
                out_file: None,
            },
            torii: ToriiPartial {
                address: Some(
                    127.0.0.1:8080,
                ),
                max_content_len: None,
                query_idle_time: None,
            },
            chain_wide: ChainWidePartial {
                max_transactions_in_block: None,
                block_time: None,
                commit_time: None,
                transaction_limits: None,
                domain_metadata_limits: None,
                asset_definition_metadata_limits: None,
                account_metadata_limits: None,
                asset_metadata_limits: None,
                trigger_metadata_limits: None,
                ident_length_limits: None,
                executor_fuel_limit: None,
                executor_max_memory: None,
                wasm_fuel_limit: None,
                wasm_max_memory: None,
            },
        }"#]];
    expected.assert_eq(&format!("{layer:#?}"));

    Ok(())
}

#[test]
fn multiple_env_parsing_errors() {
    let env = test_env_from_file(fixtures_dir().join("bad.multiple_bad_envs.env"));

    let error = RootPartial::from_env(&env).expect_err("the input from env is invalid");

    let expected = expect_test::expect![[r#"
        `PRIVATE_KEY_PAYLOAD` env was provided, but `PRIVATE_KEY_ALGORITHM` was not
        failed to parse `genesis.private_key.algorithm` field from `GENESIS_PRIVATE_KEY_ALGORITHM` env variable
        failed to parse `kura.debug.output_new_blocks` field from `KURA_DEBUG_OUTPUT_NEW_BLOCKS` env variable
        failed to parse `logger.format` field from `LOG_FORMAT` env variable
        failed to parse `torii.address` field from `API_ADDRESS` env variable"#]];
    expected.assert_eq(&format!("{error:#}"));
}

#[test]
fn config_from_file_and_env() -> Result<()> {
    let env = test_env_from_file(fixtures_dir().join("minimal_file_and_env.env"));

    let _config = RootPartial::from_toml(fixtures_dir().join("minimal_file_and_env.toml"))?
        .merge(RootPartial::from_env(&env)?)
        .unwrap_partial()?
        .parse(CliContext {
            submit_genesis: false,
        })?;

    Ok(())
}

#[test]
fn fails_if_torii_address_and_p2p_address_are_equal() -> Result<()> {
    let error = RootPartial::from_toml(fixtures_dir().join("bad.torii_addr_eq_p2p_addr.toml"))?
        .unwrap_partial()
        .expect("should not fail, all fields are present")
        .parse(CliContext {
            submit_genesis: false,
        })
        .expect_err("should fail because of bad input");

    let expected =
        expect_test::expect!["`iroha.p2p_address` and `torii.address` should not be the same"];
    expected.assert_eq(&format!("{error:#}"));

    Ok(())
}

#[test]
fn fails_if_extends_leads_to_nowhere() {
    let error = RootPartial::from_toml(fixtures_dir().join("bad.extends_nowhere.toml"))
        .expect_err("should fail with bad input");

    let expected = expect_test::expect!["cannot extend from `tests/fixtures/nowhere.toml`: cannot open file at location `tests/fixtures/nowhere.toml`: No such file or directory (os error 2)"];
    expected.assert_eq(&format!("{error:#}"));
}

#[test]
fn multiple_extends_works() -> Result<()> {
    // we are looking into `logger` in particular
    let layer = RootPartial::from_toml(fixtures_dir().join("multiple_extends.toml"))?.logger;

    let expected = expect_test::expect![[r#"
        LoggerPartial {
            level: Some(
                ERROR,
            ),
            format: Some(
                Compact,
            ),
        }"#]];
    expected.assert_eq(&format!("{layer:#?}"));

    Ok(())
}

#[test]
fn full_config_parses_fine() {
    let _cfg = Root::load(
        Some(fixtures_dir().join("full.toml")),
        CliContext {
            submit_genesis: true,
        },
    )
    .expect("should be fine");
}

#[test]
fn absolute_paths_are_preserved() {
    let cfg = Root::load(
        Some(fixtures_dir().join("absolute_paths.toml")),
        CliContext {
            submit_genesis: true,
        },
    )
    .expect("should be fine");

    assert_eq!(cfg.kura.store_dir, PathBuf::from("/kura/store"));
    assert_eq!(cfg.snapshot.store_dir, PathBuf::from("/snapshot/store"));
    assert_eq!(
        cfg.dev_telemetry.out_file.unwrap(),
        PathBuf::from("/telemetry/file.json")
    );
    if let Genesis::Full {
        file: genesis_file, ..
    } = cfg.genesis
    {
        assert_eq!(genesis_file, PathBuf::from("/oh/my/genesis.json"));
    } else {
        unreachable!()
    };
}
