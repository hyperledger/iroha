//! Validate FASTPQ Metal queue overrides parse correctly from env and reject invalid values.

use iroha_config::parameters::{actual::Root as ActualConfig, user::Root as UserConfig};
use iroha_config_base::{env::MockEnv, read::ConfigReader};
use std::{
    collections::HashMap,
    panic::{self, AssertUnwindSafe},
    path::PathBuf,
    sync::Once,
};
fn fixtures_dir() -> PathBuf {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"))
            .expect("tests run relative to crate root");
    });
    PathBuf::from("tests/fixtures")
}
fn load_with_env(env: MockEnv) -> ActualConfig {
    ConfigReader::new()
        .with_env(env)
        .read_toml_with_extends(fixtures_dir().join("base.toml"))
        .expect("fixture should load")
        .read_and_complete::<UserConfig>()
        .expect("user config should read")
        .parse()
        .expect("config should parse")
}
#[test]
fn metal_queue_overrides_parse_from_env() {
    let env = MockEnv::with_map(HashMap::from([
        ("FASTPQ_METAL_QUEUE_FANOUT".to_string(), "3".to_string()),
        (
            "FASTPQ_METAL_COLUMN_THRESHOLD".to_string(),
            "24".to_string(),
        ),
        ("FASTPQ_DEVICE_CLASS".to_string(), " apple-m4 ".to_string()),
        ("FASTPQ_CHIP_FAMILY".to_string(), "  m4".to_string()),
        ("FASTPQ_GPU_KIND".to_string(), "integrated ".to_string()),
        ("FASTPQ_METAL_MAX_IN_FLIGHT".to_string(), "5".to_string()),
        ("FASTPQ_METAL_THREADGROUP".to_string(), "128".to_string()),
        ("FASTPQ_METAL_TRACE".to_string(), "true".to_string()),
        ("FASTPQ_DEBUG_METAL_ENUM".to_string(), "true".to_string()),
    ]));
    let cfg = load_with_env(env);
    assert_eq!(cfg.zk.fastpq.metal_queue_fanout, Some(3));
    assert_eq!(cfg.zk.fastpq.metal_queue_column_threshold, Some(24));
    assert_eq!(cfg.zk.fastpq.device_class.as_deref(), Some("apple-m4"));
    assert_eq!(cfg.zk.fastpq.chip_family.as_deref(), Some("m4"));
    assert_eq!(cfg.zk.fastpq.gpu_kind.as_deref(), Some("integrated"));
    assert_eq!(cfg.zk.fastpq.metal_max_in_flight, Some(5));
    assert_eq!(cfg.zk.fastpq.metal_threadgroup_width, Some(128));
    assert!(cfg.zk.fastpq.metal_trace);
    assert!(cfg.zk.fastpq.metal_debug_enum);
    assert_eq!(
        cfg.zk.fastpq.execution_mode,
        iroha_config::parameters::actual::FastpqExecutionMode::Cpu
    );
    assert_eq!(
        cfg.zk.fastpq.poseidon_mode,
        iroha_config::parameters::actual::FastpqPoseidonMode::Cpu
    );
    assert_eq!(
        cfg.zk.fastpq.proof_sidecar_queue_cap,
        iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_QUEUE_CAP
    );
    assert_eq!(
        cfg.zk.fastpq.proof_sidecar_max_bytes.get(),
        iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_BYTES.get()
    );
    assert_eq!(
        cfg.zk.fastpq.proof_sidecar_max_retries,
        iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_RETRIES
    );
}
#[test]
fn metal_debug_overrides_reject_boolean_aliases() {
    let error = ConfigReader::new()
        .with_env(MockEnv::from([("FASTPQ_DEBUG_METAL_ENUM", "1")]))
        .read_toml_with_extends(fixtures_dir().join("base.toml"))
        .expect("fixture should load")
        .read_and_complete::<UserConfig>()
        .expect_err("noncanonical boolean aliases must fail");
    assert!(
        format!("{error:?}").contains("FASTPQ_DEBUG_METAL_ENUM"),
        "unexpected error: {error:?}"
    );
}
#[test]
fn metal_queue_overrides_reject_invalid_values() {
    let bad_fanout = MockEnv::with_map(HashMap::from([(
        "FASTPQ_METAL_QUEUE_FANOUT".to_string(),
        "0".to_string(),
    )]));
    let bad_threshold = MockEnv::with_map(HashMap::from([(
        "FASTPQ_METAL_COLUMN_THRESHOLD".to_string(),
        "0".to_string(),
    )]));
    let bad_max_in_flight = MockEnv::with_map(HashMap::from([(
        "FASTPQ_METAL_MAX_IN_FLIGHT".to_string(),
        "0".to_string(),
    )]));
    let bad_threadgroup = MockEnv::with_map(HashMap::from([(
        "FASTPQ_METAL_THREADGROUP".to_string(),
        "0".to_string(),
    )]));
    let fanout_panic = panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = load_with_env(bad_fanout);
    }));
    assert!(fanout_panic.is_err(), "fanout <1 must be rejected");
    let threshold_panic = panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = load_with_env(bad_threshold);
    }));
    assert!(
        threshold_panic.is_err(),
        "column threshold <=0 must be rejected"
    );
    let max_in_flight_panic = panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = load_with_env(bad_max_in_flight);
    }));
    assert!(
        max_in_flight_panic.is_err(),
        "max_in_flight <=0 must be rejected"
    );
    let threadgroup_panic = panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = load_with_env(bad_threadgroup);
    }));
    assert!(
        threadgroup_panic.is_err(),
        "threadgroup width <=0 must be rejected"
    );
}
