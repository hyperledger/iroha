//! First-release queue and storage configuration reject retired protocol controls.

use iroha_config::parameters::user::Root;
use iroha_config_base::{read::ConfigReader, toml::TomlSource};
use std::path::PathBuf;

fn reader() -> ConfigReader {
    ConfigReader::new()
        .read_toml_with_extends(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base.toml"),
        )
        .expect("base config")
}

#[test]
fn retired_queue_plan_fields_are_unknown_even_at_zero() {
    for (field, value) in [
        ("plan_journal_max_bytes", "0"),
        ("plan_journal_max_bytes", "67108864"),
        ("plan_journal_enabled", "false"),
    ] {
        let table = format!("[queue]\n{field} = {value}\n").parse().unwrap();
        let error = reader()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<Root>()
            .expect_err("retired queue journal field");
        let report = format!("{error:?}");
        assert!(
            report.contains("unknown parameter") && report.contains(&format!("queue.{field}")),
            "{report}"
        );
    }
}

#[test]
fn native_queue_defaults_keep_finite_capacity_and_expiry() {
    let user = reader()
        .read_and_complete::<Root>()
        .expect("canonical config");
    let queue = user.parse().expect("canonical runtime config").queue;
    assert!(queue.capacity.get() > 0);
    assert!(queue.capacity_per_user.get() > 0);
    assert!(queue.max_retained_bytes.get() > 0);
    assert!(!queue.transaction_time_to_live.is_zero());
    assert!(queue.expired_cull_batch.get() > 0);
}

#[test]
fn retired_merge_ledger_cache_capacity_is_unknown_even_at_zero() {
    for value in [0, 256, 1_048_576] {
        let table = format!("[kura]\nmerge_ledger_cache_capacity = {value}\n")
            .parse()
            .unwrap();
        let error = reader()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<Root>()
            .expect_err("retired MergeLedger cache field");
        let report = format!("{error:?}");
        assert!(
            report.contains("unknown parameter")
                && report.contains("kura.merge_ledger_cache_capacity"),
            "{report}"
        );
    }
}

#[test]
fn retired_merge_ledger_cache_environment_name_is_not_an_input() {
    let environment =
        iroha_config_base::env::MockEnv::new().set("KURA_MERGE_LEDGER_CACHE_CAPACITY", "1");
    reader()
        .with_env(environment.clone())
        .read_and_complete::<Root>()
        .expect("retired environment variable is not a schema input")
        .parse()
        .expect("current configuration remains valid");
    assert!(
        environment
            .unvisited()
            .contains("KURA_MERGE_LEDGER_CACHE_CAPACITY")
    );
}
