//! Validate configurable first-release bounds on public-lane staking work.

use std::path::PathBuf;

use iroha_config::parameters::{actual::Root as ActualConfig, defaults, user::Root as UserConfig};
use iroha_config_base::{read::ConfigReader, toml::TomlSource};

fn base_reader() -> ConfigReader {
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base.toml");
    ConfigReader::new()
        .read_toml_with_extends(base_path)
        .expect("base config should load")
}

fn parse_actual_config(inline_toml: &str) -> ActualConfig {
    let table: toml::Table = inline_toml
        .parse()
        .expect("inline staking configuration should parse as TOML");
    base_reader()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .expect("bounded staking configuration should complete")
        .parse()
        .expect("bounded staking configuration should be valid")
}

#[test]
fn staking_work_bounds_have_conservative_nonzero_defaults() {
    let staking = parse_actual_config("").nexus.staking;
    assert_eq!(
        staking.max_stake_shares_per_validator,
        defaults::nexus::staking::MAX_STAKE_SHARES_PER_VALIDATOR
    );
    assert_eq!(staking.max_stake_shares_per_validator.get(), 256);
    assert_eq!(
        staking.max_pending_unbonds_per_share,
        defaults::nexus::staking::MAX_PENDING_UNBONDS_PER_SHARE
    );
    assert_eq!(staking.max_pending_unbonds_per_share.get(), 8);
}

#[test]
fn staking_work_bounds_parse_from_toml() {
    let staking = parse_actual_config(concat!(
        "[nexus.staking]\n",
        "max_stake_shares_per_validator = 17\n",
        "max_pending_unbonds_per_share = 5\n",
    ))
    .nexus
    .staking;
    assert_eq!(staking.max_stake_shares_per_validator.get(), 17);
    assert_eq!(staking.max_pending_unbonds_per_share.get(), 5);
}

#[test]
fn staking_snapshot_must_fit_one_bounded_reward_exposure() {
    let cap = iroha_data_model::validation_fee_rewards::MAX_REWARD_RECIPIENTS;
    let accepted = parse_actual_config(&format!(
        "[nexus.staking]\nmax_stake_shares_per_validator = {cap}\n"
    ));
    assert_eq!(
        accepted.nexus.staking.max_stake_shares_per_validator.get() as usize,
        cap
    );
    let table: toml::Table = format!(
        "[nexus.staking]\nmax_stake_shares_per_validator = {}\n",
        cap + 1
    )
    .parse()
    .expect("configuration TOML");
    let config = base_reader()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .expect("configuration input");
    assert!(
        config.parse().is_err(),
        "oversized live stake snapshots must be refused before chain execution"
    );
}
