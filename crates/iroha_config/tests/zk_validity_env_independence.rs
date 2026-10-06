//! Neither a process environment variable nor a configuration file can set a
//! validity-affecting `[zk]` or `[confidential]` value.
//!
//! Proof limits, windows, verifier switches, relation-selecting keys and the
//! verification gas schedule are committed chain policy
//! (`zk_validity_policy_v1`). The node schema holds local resource settings of
//! the ZK verifier lane only, and environment aliases only for those.
use iroha_config::parameters::{actual::Root as ActualConfig, defaults, user::Root as UserConfig};
use iroha_config_base::{env::MockEnv, read::ConfigReader};
use std::{collections::HashMap, path::PathBuf, sync::Once};

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

/// Every environment name that used to alias a validity-affecting `[zk]` field.
const RETIRED_VALIDITY_ALIASES: [(&str, &str); 23] = [
    ("ZK_BALLOT_HISTORY_CAP", "7"),
    ("ZK_BRIDGE_PROOF_MAX_FUTURE_DRIFT_BLOCKS", "7"),
    ("ZK_BRIDGE_PROOF_MAX_PAST_AGE_BLOCKS", "7"),
    ("ZK_BRIDGE_PROOF_MAX_RANGE_LEN", "7"),
    ("ZK_HALO2_BACKEND", "ipa"),
    ("ZK_HALO2_CURVE", "bn254"),
    ("ZK_HALO2_ENABLED", "false"),
    ("ZK_HALO2_ENFORCE_TRANSCRIPT_LABEL_ASCII", "false"),
    ("ZK_HALO2_MAX_ENVELOPE_BYTES", "7"),
    ("ZK_HALO2_MAX_K", "7"),
    ("ZK_HALO2_MAX_PROOF_BYTES", "7"),
    ("ZK_HALO2_MAX_TRANSCRIPT_LABEL_LEN", "7"),
    ("ZK_HALO2_VERIFIER_MAX_BATCH", "7"),
    ("ZK_PEDERSEN_PARAMS_ID", "7"),
    ("ZK_POSEIDON_PARAMS_ID", "7"),
    ("ZK_PREVERIFY_BUDGET_BYTES", "7"),
    ("ZK_PREVERIFY_MAX_BYTES", "7"),
    ("ZK_PROOF_HISTORY_CAP", "7"),
    ("ZK_PROOF_PRUNE_BATCH", "7"),
    ("ZK_PROOF_RETENTION_GRACE_BLOCKS", "7"),
    ("ZK_STARK_ENABLED", "false"),
    ("ZK_STARK_MAX_ENVELOPE_BYTES", "7"),
    ("ZK_STARK_MAX_PROOF_BYTES", "7"),
];

#[test]
fn environment_cannot_set_a_zk_validity_value() {
    let env = MockEnv::with_map(
        RETIRED_VALIDITY_ALIASES
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect::<HashMap<_, _>>(),
    );
    let with_env = load_with_env(env);
    let without_env = load_with_env(MockEnv::default());

    let zk = &with_env.zk;
    let reference = &without_env.zk;
    assert_eq!(zk.ballot_history_cap, reference.ballot_history_cap);
    assert_eq!(
        zk.bridge_proof_max_future_drift_blocks,
        reference.bridge_proof_max_future_drift_blocks
    );
    assert_eq!(
        zk.bridge_proof_max_past_age_blocks,
        reference.bridge_proof_max_past_age_blocks
    );
    assert_eq!(
        zk.bridge_proof_max_range_len,
        reference.bridge_proof_max_range_len
    );
    assert_eq!(zk.halo2.enabled, reference.halo2.enabled);
    assert_eq!(zk.halo2.curve, reference.halo2.curve);
    assert_eq!(
        zk.halo2.enforce_transcript_label_ascii,
        reference.halo2.enforce_transcript_label_ascii
    );
    assert_eq!(
        zk.halo2.max_envelope_bytes,
        reference.halo2.max_envelope_bytes
    );
    assert_eq!(zk.halo2.max_k, reference.halo2.max_k);
    assert_eq!(zk.halo2.max_proof_bytes, reference.halo2.max_proof_bytes);
    assert_eq!(
        zk.halo2.max_transcript_label_len,
        reference.halo2.max_transcript_label_len
    );
    assert_eq!(
        zk.halo2.verifier_max_batch,
        reference.halo2.verifier_max_batch
    );
    assert_eq!(zk.pedersen_params_id, reference.pedersen_params_id);
    assert_eq!(zk.poseidon_params_id, reference.poseidon_params_id);
    assert_eq!(zk.preverify_budget_bytes, reference.preverify_budget_bytes);
    assert_eq!(zk.preverify_max_bytes, reference.preverify_max_bytes);
    assert_eq!(zk.proof_history_cap, reference.proof_history_cap);
    assert_eq!(zk.proof_prune_batch, reference.proof_prune_batch);
    assert_eq!(
        zk.proof_retention_grace_blocks,
        reference.proof_retention_grace_blocks
    );
    assert_eq!(zk.stark.enabled, reference.stark.enabled);
    assert_eq!(
        zk.stark.max_envelope_bytes,
        reference.stark.max_envelope_bytes
    );
    assert_eq!(zk.stark.max_proof_bytes, reference.stark.max_proof_bytes);

    // The reference values are the protocol defaults, not the values offered above.
    assert_eq!(zk.halo2.max_k, defaults::zk::halo2::MAX_K);
    assert_eq!(zk.halo2.enabled, defaults::zk::halo2::ENABLED);
    assert_eq!(zk.stark.enabled, defaults::zk::stark::ENABLED);
    assert_eq!(
        zk.ballot_history_cap,
        defaults::zk::vote::BALLOT_HISTORY_CAP
    );
}

#[test]
fn environment_still_sets_local_verifier_resources() {
    let env = MockEnv::with_map(HashMap::from([
        (
            "ZK_HALO2_VERIFIER_WORKER_THREADS".to_owned(),
            "3".to_owned(),
        ),
        ("ZK_HALO2_VERIFIER_QUEUE_CAP".to_owned(), "17".to_owned()),
    ]));
    let config = load_with_env(env);
    assert_eq!(config.zk.halo2.verifier_worker_threads, 3);
    assert_eq!(config.zk.halo2.verifier_queue_cap, 17);
}

#[test]
fn configuration_file_cannot_set_a_zk_validity_value() {
    use iroha_config_base::toml::TomlSource;

    // One file names several chain-policy values; loading reports every one of
    // them as an unknown parameter in a single aggregated error.
    let table: toml::Table = toml::from_str(
        "[zk.halo2]\nmax_k = 3\n[zk.stark]\nenabled = false\n[zk.sccp]\nmax_proofs_per_block = 9\n\
         [zk]\nballot_history_cap = 1\n[confidential]\nmax_proof_size_bytes = 1\n\
         [confidential.gas]\nproof_base = 1\n",
    )
    .expect("test TOML parses");
    let error = ConfigReader::new()
        .read_toml_with_extends(fixtures_dir().join("base.toml"))
        .expect("fixture should load")
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .expect_err("chain-policy values are not node configuration");
    let diagnostic = format!("{error:?}");
    // A removed key is named by itself; a removed section by the section.
    for name in [
        "`zk.halo2.max_k`",
        "`zk.stark`",
        "`zk.sccp`",
        "`zk.ballot_history_cap`",
        "`confidential.max_proof_size_bytes`",
        "`confidential.gas`",
    ] {
        assert!(
            diagnostic.contains("unknown parameter") && diagnostic.contains(name),
            "{name}: {diagnostic}"
        );
    }
    // Local resource settings of the same sections still load.
    let table: toml::Table = toml::from_str(
        "[zk.halo2]\nverifier_worker_threads = 3\n[confidential]\nverify_timeout_ms = 9\n",
    )
    .expect("test TOML parses");
    let config = ConfigReader::new()
        .read_toml_with_extends(fixtures_dir().join("base.toml"))
        .expect("fixture should load")
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .expect("local resources are node configuration")
        .parse()
        .expect("config should parse");
    assert_eq!(config.zk.halo2.verifier_worker_threads, 3);
    assert_eq!(
        config.zk.verify_timeout,
        std::time::Duration::from_millis(9)
    );
    assert_eq!(config.zk.halo2.max_k, defaults::zk::halo2::MAX_K);
}
