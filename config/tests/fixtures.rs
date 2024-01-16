use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use eyre::Result;
use iroha_config::parameters::user_layer::Root;
use iroha_config_base::{Complete as _, FromEnv, TestEnv};

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
fn minimal_config_snapshot() -> Result<()> {
    let config = Root::from_toml(fixtures_dir().join("minimal_config.toml"))?.complete()?;

    let expected = expect_test::expect![[r#"
        Config {
            iroha: Config {
                key_pair: KeyPair {
                    public_key: {digest: ed25519, payload: ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB},
                    private_key: {digest: ed25519, payload: 8F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F8BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB},
                },
                p2p_address: 127.0.0.1:1337,
            },
            genesis: Partial {
                public_key: {digest: ed25519, payload: ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB},
            },
            kura: Config {
                init_mode: Strict,
                block_store_path: "./storage",
                debug_output_new_blocks: false,
            },
            sumeragi: Config {
                block_gossip_period: 10s,
                max_blocks_per_gossip: 4,
                max_transactions_per_gossip: 500,
                transaction_gossip_period: 1s,
                trusted_peers: TrustedPeers {
                    peers: UniqueVec(
                        [],
                    ),
                },
            },
            logger: Config {
                level: INFO,
                format: Full,
            },
            queue: Config {
                max_transactions_in_queue: 65536,
                max_transactions_in_queue_per_user: 65536,
                transaction_time_to_live_ms: 86400s,
                future_threshold_ms: 1s,
            },
            snapshot: Config {
                create_every_ms: 60s,
                store_path: "./storage",
                creation_enabled: true,
            },
            telemetry: Config {
                regular: None,
                dev: None,
            },
            torii: Config {
                address: 127.0.0.1:8080,
                max_content_len: ByteSize(
                    16777216,
                ),
                query_idle_time: 30s,
            },
            chain_wide: Config {
                max_transactions_in_block: 512,
                block_time: 2s,
                commit_time: 4s,
                transactions_limits: TransactionLimits {
                    max_instruction_number: 4096,
                    max_wasm_size_bytes: 4194304,
                },
                asset_metadata_limits: Limits {
                    max_len: 1048576,
                    max_entry_byte_size: 4096,
                },
                asset_definition_metadata_limits: Limits {
                    max_len: 1048576,
                    max_entry_byte_size: 4096,
                },
                account_metadata_limits: Limits {
                    max_len: 1048576,
                    max_entry_byte_size: 4096,
                },
                domain_metadata_limits: Limits {
                    max_len: 1048576,
                    max_entry_byte_size: 4096,
                },
                identifier_length_limits: LengthLimits {
                    min: 1,
                    max: 128,
                },
                wasm_fuel_limit: 23000000,
                wasm_max_memory: ByteSize(
                    524288000,
                ),
            },
        }"#]];
    expected.assert_eq(&format!("{config:#?}"));

    Ok(())
}

#[test]
fn config_with_genesis() -> Result<()> {
    let _config = Root::from_toml(fixtures_dir().join("with_genesis.toml"))?.complete()?;
    Ok(())
}

#[test]
fn missing_fields() -> Result<()> {
    let error = Root::from_toml(fixtures_dir().join("missing_fields.toml"))?
        .complete()
        .expect_err("should fail with missing fields");

    let expected = expect_test::expect![[r#"
        Missing field: iroha.public_key
        Missing field: iroha.private_key
        Missing field: iroha.p2p_address
        Missing field: genesis.public_key
        Missing field: torii.address"#]];
    expected.assert_eq(&format!("{error:#}"));

    Ok(())
}

#[test]
fn extra_fields() {
    let error = Root::from_toml(fixtures_dir().join("extra_fields.toml"))
        .expect_err("should fail with extra fields");

    let expected = expect_test::expect![[r#"
        failed to parse toml: TOML parse error at line 1, column 1
          |
        1 | i_am_unknown = true
          | ^^^^^^^^^^^^
        unknown field `i_am_unknown`, expected one of `iroha`, `genesis`, `kura`, `sumeragi`, `logger`, `queue`, `snapshot`, `telemetry`, `torii`, `chain_wide`
    "#]];
    expected.assert_eq(&format!("{error:#}"));
}

#[test]
fn inconsistent_genesis_config() -> Result<()> {
    let error = Root::from_toml(fixtures_dir().join("inconsistent_genesis.toml"))?
        .complete()
        .expect_err("should fail with bad genesis config");

    let expected = expect_test::expect!["FIXME"];
    expected.assert_eq(&format!("{error:#}"));

    Ok(())
}

/// Aims the purpose of checking that every single provided env variable is consumed and parsed
/// into a valid config.
#[test]
fn full_envs_set_is_consumed() -> Result<()> {
    let env = test_env_from_file(fixtures_dir().join("full.env"));

    let layer = Root::from_env(&env)?;

    assert_eq!(env.unvisited(), HashSet::new());

    let expected = expect_test::expect![[r#"
        UserLayer {
            iroha: UserLayer {
                public_key: Some(
                    {digest: ed25519, payload: ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB},
                ),
                private_key: Some(
                    {digest: ed25519, payload: 8F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F8BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB},
                ),
                p2p_address: Some(
                    127.0.0.1:5432,
                ),
            },
            genesis: UserLayer {
                public_key: Some(
                    {digest: ed25519, payload: ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB},
                ),
                private_key: Some(
                    {digest: ed25519, payload: 8F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F8BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB},
                ),
                file: None,
            },
            kura: UserLayer {
                init_mode: Some(
                    Strict,
                ),
                block_store_path: Some(
                    "/store/path/from/env",
                ),
                debug: DebugUserConfig {
                    output_new_blocks: Some(
                        false,
                    ),
                },
            },
            sumeragi: UserLayer {
                block_gossip_period: None,
                max_blocks_per_gossip: None,
                max_transactions_per_gossip: None,
                transaction_gossip_period: None,
                trusted_peers: UserTrustedPeers {
                    peers: [],
                },
            },
            logger: UserLayer {
                level: Some(
                    DEBUG,
                ),
                format: Some(
                    Pretty,
                ),
            },
            queue: UserLayer {
                max_transactions_in_queue: None,
                max_transactions_in_queue_per_user: None,
                transaction_time_to_live_ms: None,
                future_threshold_ms: None,
            },
            snapshot: UserLayer {
                create_every_ms: None,
                store_path: Some(
                    "/snapshot/path/from/env",
                ),
                creation_enabled: Some(
                    false,
                ),
            },
            telemetry: UserLayer {
                name: None,
                url: None,
                min_retry_period: None,
                max_retry_delay_exponent: None,
                dev: DevUserLayer {
                    file: None,
                },
            },
            torii: UserLayer {
                address: Some(
                    127.0.0.1:8080,
                ),
                max_content_len: None,
                query_idle_time: None,
            },
            chain_wide: UserLayer {
                max_transactions_in_block: None,
                block_time: None,
                commit_time: None,
                transactions_limits: None,
                asset_metadata_limits: None,
                asset_definition_metadata_limits: None,
                account_metadata_limits: None,
                domain_metadata_limits: None,
                identifier_length_limits: None,
                wasm_fuel_limit: None,
                wasm_max_memory: None,
            },
        }"#]];
    expected.assert_eq(&format!("{layer:#?}"));

    Ok(())
}

#[test]
#[ignore]
fn multiple_env_parsing_errors() {
    todo!("put invalid data into multiple ENV variables in different modules and check the error report")
}

#[test]
fn config_from_file_and_env() -> Result<()> {
    let env = test_env_from_file(fixtures_dir().join("config_and_env.env"));

    let _config = Root::from_toml(fixtures_dir().join("config_and_env.toml"))?
        .merge_chain(Root::from_env(&env)?)
        .complete()?;

    Ok(())
}
