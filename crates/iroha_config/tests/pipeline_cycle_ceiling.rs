//! Neither a configuration file nor a process environment variable can set an
//! execution limit of the pipeline.
//!
//! The IVM cycle ceiling and the other execution limits (overlay size, decoded
//! program bounds, the quarantine lane, query limits, the AMX budget model and
//! the access-set derivation mode) are committed chain policy
//! (`pipeline_validity_policy_v1`). The node schema holds local resources and
//! the fee policy only; the settings value a node builds carries the protocol
//! default of every limit.
use iroha_config::parameters::{actual::Root as ActualConfig, defaults, user::Root as UserConfig};
use iroha_config_base::{env::MockEnv, read::ConfigReader, toml::TomlSource};
use std::{collections::HashMap, path::PathBuf};

/// Every key of `[pipeline]` that is chain policy, with a value that differs
/// from the protocol default.
const CHAIN_POLICY_KEYS: [(&str, &str); 16] = [
    ("dynamic_prepass", "false"),
    ("overlay_max_instructions", "7"),
    ("overlay_max_bytes", "7"),
    ("overlay_chunk_instructions", "7"),
    ("ivm_max_cycles_upper_bound", "42"),
    ("ivm_max_decoded_instructions", "7"),
    ("ivm_max_decoded_bytes", "7"),
    ("quarantine_max_txs_per_block", "7"),
    ("quarantine_tx_max_cycles", "7"),
    ("query_max_fetch_size", "7"),
    ("query_stored_min_gas_units", "7"),
    ("amx_per_dataspace_budget_ms", "7"),
    ("amx_group_budget_ms", "7"),
    ("amx_per_instruction_ns", "7"),
    ("amx_per_memory_access_ns", "7"),
    ("amx_per_syscall_ns", "7"),
];

fn base_reader() -> ConfigReader {
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base.toml");
    ConfigReader::new()
        .read_toml_with_extends(base_path)
        .expect("base config should load")
}

fn inline_source(source: &str) -> TomlSource {
    let table: toml::Table = source.parse().expect("inline TOML should parse");
    TomlSource::inline(table)
}

fn assert_protocol_defaults(config: &ActualConfig) {
    let pipeline = &config.pipeline;
    assert_eq!(
        pipeline.dynamic_prepass,
        defaults::pipeline::DYNAMIC_PREPASS
    );
    assert_eq!(
        pipeline.overlay_max_instructions,
        defaults::pipeline::OVERLAY_MAX_INSTRUCTIONS
    );
    assert_eq!(
        pipeline.overlay_max_bytes,
        defaults::pipeline::OVERLAY_MAX_BYTES
    );
    assert_eq!(
        pipeline.overlay_chunk_instructions,
        defaults::pipeline::OVERLAY_CHUNK_INSTRUCTIONS
    );
    assert_eq!(pipeline.ivm_max_cycles_upper_bound.get(), 1_000_000);
    assert_eq!(
        pipeline.ivm_max_decoded_instructions,
        defaults::pipeline::IVM_MAX_DECODED_INSTRUCTIONS
    );
    assert_eq!(
        pipeline.ivm_max_decoded_bytes,
        defaults::pipeline::IVM_MAX_DECODED_BYTES
    );
    assert_eq!(
        pipeline.quarantine_max_txs_per_block,
        defaults::pipeline::QUARANTINE_MAX_TXS_PER_BLOCK
    );
    assert_eq!(
        pipeline.quarantine_tx_max_cycles,
        defaults::pipeline::QUARANTINE_TX_MAX_CYCLES
    );
    assert_eq!(
        pipeline.query_max_fetch_size,
        defaults::pipeline::QUERY_MAX_FETCH_SIZE
    );
    assert_eq!(
        pipeline.query_stored_min_gas_units,
        defaults::pipeline::QUERY_STORED_MIN_GAS_UNITS
    );
    assert_eq!(
        pipeline.amx_per_dataspace_budget_ms,
        defaults::pipeline::AMX_PER_DATASPACE_BUDGET_MS
    );
    assert_eq!(
        pipeline.amx_group_budget_ms,
        defaults::pipeline::AMX_GROUP_BUDGET_MS
    );
    assert_eq!(
        pipeline.amx_per_instruction_ns,
        defaults::pipeline::AMX_PER_INSTRUCTION_NS
    );
    assert_eq!(
        pipeline.amx_per_memory_access_ns,
        defaults::pipeline::AMX_PER_MEMORY_ACCESS_NS
    );
    assert_eq!(
        pipeline.amx_per_syscall_ns,
        defaults::pipeline::AMX_PER_SYSCALL_NS
    );
}

#[test]
fn execution_limits_of_a_node_settings_value_are_the_protocol_defaults() {
    let config = base_reader()
        .read_and_complete::<UserConfig>()
        .expect("default user config should read")
        .parse()
        .expect("default actual config should parse");
    assert_protocol_defaults(&config);
}

#[test]
fn configuration_file_cannot_set_an_execution_limit() {
    use std::fmt::Write as _;

    // Each chain-policy key alone is an unknown parameter of the node schema.
    for (key, value) in CHAIN_POLICY_KEYS {
        let error = base_reader()
            .with_toml_source(inline_source(&format!("[pipeline]\n{key} = {value}\n")))
            .read_and_complete::<UserConfig>()
            .expect_err("an execution limit is not node configuration");
        let diagnostic = format!("{error:?}");
        assert!(
            diagnostic.contains("unknown parameter")
                && diagnostic.contains(&format!("`pipeline.{key}`")),
            "{key}: {diagnostic}"
        );
    }
    // One file naming all of them reports every one in a single aggregated error.
    let mut all = String::new();
    for (key, value) in CHAIN_POLICY_KEYS {
        writeln!(&mut all, "{key} = {value}").expect("write to fixture string");
    }
    let error = base_reader()
        .with_toml_source(inline_source(&format!("[pipeline]\n{all}")))
        .read_and_complete::<UserConfig>()
        .expect_err("execution limits are not node configuration");
    let diagnostic = format!("{error:?}");
    for (key, _) in CHAIN_POLICY_KEYS {
        assert!(
            diagnostic.contains(&format!("`pipeline.{key}`")),
            "{key}: {diagnostic}"
        );
    }
    // Local resources of the same section still load.
    let config: ActualConfig = base_reader()
        .with_toml_source(inline_source(
            "[pipeline]\nworkers = 3\nstateless_cache_cap = 17\n",
        ))
        .read_and_complete::<UserConfig>()
        .expect("local resources are node configuration")
        .parse()
        .expect("config should parse");
    assert_eq!(config.pipeline.workers, 3);
    assert_eq!(config.pipeline.stateless_cache_cap, 17);
    assert_protocol_defaults(&config);
}

#[test]
fn environment_cannot_set_an_execution_limit() {
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base.toml");
    let names: Vec<String> = CHAIN_POLICY_KEYS
        .iter()
        .map(|(key, _)| format!("PIPELINE_{}", key.to_uppercase()))
        .collect();
    let env = MockEnv::with_map(
        names
            .iter()
            .zip(CHAIN_POLICY_KEYS)
            .map(|(name, (_, value))| (name.clone(), value.to_owned()))
            .collect::<HashMap<_, _>>(),
    );
    let config: ActualConfig = ConfigReader::new()
        .with_env(env.clone())
        .read_toml_with_extends(base_path)
        .expect("base config should load")
        .read_and_complete::<UserConfig>()
        .expect("unrecognized environment variables must not affect configuration")
        .parse()
        .expect("default actual config should parse");
    assert_protocol_defaults(&config);
    let unvisited = env.unvisited();
    for name in &names {
        assert!(
            unvisited.contains(name.as_str()),
            "{name} must not be an environment alias of the node schema"
        );
    }
}

#[test]
fn environment_still_sets_local_pipeline_resources() {
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base.toml");
    let env = MockEnv::with_map(HashMap::from([
        ("PIPELINE_WORKERS".to_owned(), "5".to_owned()),
        ("PIPELINE_CACHE_SIZE".to_owned(), "9".to_owned()),
    ]));
    let config: ActualConfig = ConfigReader::new()
        .with_env(env)
        .read_toml_with_extends(base_path)
        .expect("base config should load")
        .read_and_complete::<UserConfig>()
        .expect("user config should read")
        .parse()
        .expect("config should parse");
    assert_eq!(config.pipeline.workers, 5);
    assert_eq!(config.pipeline.cache_size, 9);
}
