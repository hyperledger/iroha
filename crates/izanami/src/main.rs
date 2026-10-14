#![allow(
    clippy::cast_possible_truncation,
    clippy::cloned_instead_of_copied,
    clippy::clone_on_copy,
    clippy::collapsible_if,
    clippy::implicit_clone,
    clippy::large_enum_variant,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::match_wildcard_for_single_variants,
    clippy::redundant_pub_crate,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    clippy::vec_init_then_push
)]
//! Izanami chaosnet tool for orchestrating fault-injection scenarios on local Iroha clusters.
mod chaos;
mod config;
mod instructions;
mod persistence;
mod smart_contracts;
mod tui;
use crate::config::IzanamiArgs;
use clap::{ArgMatches, CommandFactory, FromArgMatches, parser::ValueSource};
use color_eyre::Result;
pub use izanami::faults;
#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let command = config::IzanamiArgs::command();
    let matches = command.get_matches();
    let args = config::IzanamiArgs::from_arg_matches(&matches)
        .expect("command-generated matches should parse");
    if args.tui {
        let defaults = config::IzanamiArgs::defaults();
        let persisted = persistence::load_args()?.unwrap_or_else(|| defaults.clone());
        let initial = merge_with_overrides(persisted, &args, &matches);
        match tui::launch(initial)? {
            Some((config, mut updated_args)) => {
                updated_args.tui = false;
                persistence::store_args(&updated_args)?;
                config::init_tracing_with_filter(&config.log_filter);
                persistence::store_config(&config)?;
                chaos::IzanamiRunner::new(config).await?.run().await
            }
            None => Ok(()),
        }
    } else {
        let config = config::ChaosConfig::try_from(args.clone())?;
        persistence::store_config(&config)?;
        config::init_tracing_with_filter(&config.log_filter);
        chaos::IzanamiRunner::new(config).await?.run().await
    }
}
fn merge_with_overrides(
    mut base: IzanamiArgs,
    overrides: &IzanamiArgs,
    matches: &ArgMatches,
) -> IzanamiArgs {
    if is_cli_source(matches, "allow_net") {
        base.allow_net = overrides.allow_net;
    }
    if is_cli_source(matches, "peers") {
        base.peers = overrides.peers;
    }
    if is_cli_source(matches, "faulty") {
        base.faulty = overrides.faulty;
    }
    if is_cli_source(matches, "duration") {
        base.duration = overrides.duration;
    }
    if is_cli_source(matches, "pipeline_time") {
        base.pipeline_time = overrides.pipeline_time;
    }
    if is_cli_source(matches, "target_blocks") {
        base.target_blocks = overrides.target_blocks;
    }
    if is_cli_source(matches, "progress_interval") {
        base.progress_interval = overrides.progress_interval;
    }
    if is_cli_source(matches, "progress_timeout") {
        base.progress_timeout = overrides.progress_timeout;
    }
    if is_cli_source(matches, "shutdown_drain_timeout") {
        base.shutdown_drain_timeout = overrides.shutdown_drain_timeout;
    }
    if is_cli_source(matches, "latency_p95_threshold") {
        base.latency_p95_threshold = overrides.latency_p95_threshold;
    }
    if is_cli_source(matches, "fault_window_start") {
        base.fault_window_start = overrides.fault_window_start;
    }
    if is_cli_source(matches, "fault_window_end") {
        base.fault_window_end = overrides.fault_window_end;
    }
    if is_cli_source(matches, "seed") {
        base.seed = overrides.seed;
    }
    if is_cli_source(matches, "tps") {
        base.tps = overrides.tps;
    }
    if is_cli_source(matches, "max_inflight") {
        base.max_inflight = overrides.max_inflight;
    }
    if is_cli_source(matches, "submitters") {
        base.submitters = overrides.submitters;
    }
    if is_cli_source(matches, "prebuild_tx_buffer") {
        base.prebuild_tx_buffer = overrides.prebuild_tx_buffer;
    }
    if is_cli_source(matches, "prebuild_tx_workers") {
        base.prebuild_tx_workers = overrides.prebuild_tx_workers;
    }
    if is_cli_source(matches, "sumeragi_block_max_transactions") {
        base.sumeragi_block_max_transactions = overrides.sumeragi_block_max_transactions;
    }

    if is_cli_source(matches, "workload_profile") {
        base.workload_profile = overrides.workload_profile;
    }
    if is_cli_source(matches, "allow_contract_deploy_in_stable") {
        base.allow_contract_deploy_in_stable = overrides.allow_contract_deploy_in_stable;
    }
    if is_cli_source(matches, "log_filter") {
        base.log_filter.clone_from(&overrides.log_filter);
    }
    if is_cli_source(matches, "fault_interval_min") {
        base.fault_interval_min = overrides.fault_interval_min;
    }
    if is_cli_source(matches, "fault_interval_max") {
        base.fault_interval_max = overrides.fault_interval_max;
    }
    if is_cli_source(matches, "crash_restart") {
        base.faults.crash_restart = overrides.faults.crash_restart;
    }
    if is_cli_source(matches, "wipe_storage") {
        base.faults.wipe_storage = overrides.faults.wipe_storage;
    }
    if is_cli_source(matches, "spam_invalid_transactions") {
        base.faults.spam_invalid_transactions = overrides.faults.spam_invalid_transactions;
    }
    if is_cli_source(matches, "network_latency") {
        base.faults.network_latency = overrides.faults.network_latency;
    }
    if is_cli_source(matches, "network_partition") {
        base.faults.network_partition = overrides.faults.network_partition;
    }
    if is_cli_source(matches, "cpu_stress") {
        base.faults.cpu_stress = overrides.faults.cpu_stress;
    }
    if is_cli_source(matches, "disk_saturation") {
        base.faults.disk_saturation = overrides.faults.disk_saturation;
    }
    if is_cli_source(matches, "nexus") {
        base.nexus = overrides.nexus;
    }
    if is_cli_source(matches, "diagnostic_dir") {
        base.diagnostic_dir.clone_from(&overrides.diagnostic_dir);
    }
    base.tui = overrides.tui;
    base
}
fn is_cli_source(matches: &ArgMatches, id: &str) -> bool {
    use std::borrow::Cow;
    let mut variants: Vec<Cow<'_, str>> = vec![Cow::Borrowed(id)];
    if id.contains('-') {
        variants.push(Cow::Owned(id.replace('-', "_")));
    }
    if id.contains('_') {
        variants.push(Cow::Owned(id.replace('_', "-")));
    }
    for candidate in variants {
        let needle = candidate.as_ref();
        if matches.ids().any(|existing| existing.as_str() == needle)
            && matches
                .value_source(needle)
                .is_some_and(|source| source == ValueSource::CommandLine)
        {
            return true;
        }
    }
    false
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use clap::{CommandFactory, FromArgMatches};
    use std::time::Duration;
    fn parse_cli_arguments(args: Vec<String>) -> (IzanamiArgs, ArgMatches) {
        let command = config::IzanamiArgs::command();
        let matches = command
            .try_get_matches_from(args)
            .expect("cli arguments should parse");
        let parsed = config::IzanamiArgs::from_arg_matches(&matches)
            .expect("matches produced by clap should be valid");
        (parsed, matches)
    }
    #[test]
    fn tui_cli_overrides_persisted_peers_even_when_default() {
        let defaults = config::IzanamiArgs::defaults();
        let mut persisted = defaults.clone();
        persisted.tui = false;
        persisted.peers = defaults.peers + 5;
        persisted.faulty = defaults.faulty + 1;
        persisted.duration = Duration::from_secs(300);
        persisted.pipeline_time = Some(Duration::from_secs(4));
        persisted.target_blocks = Some(256);
        persisted.progress_interval = Duration::from_secs(9);
        persisted.progress_timeout = Duration::from_secs(90);
        persisted.shutdown_drain_timeout = Duration::from_secs(17);
        persisted.fault_window_start = Some(Duration::from_secs(13));
        persisted.fault_window_end = Some(Duration::from_secs(26));
        persisted.seed = Some(13);
        persisted.tps = defaults.tps + 1.0;
        persisted.max_inflight = defaults.max_inflight + 10;
        persisted.submitters = defaults.submitters + 2;
        persisted.log_filter = "debug".to_string();
        persisted.fault_interval_min = Duration::from_secs(1);
        persisted.fault_interval_max = Duration::from_secs(2);
        let peers_arg = defaults.peers.to_string();
        let (cli_args, matches) = parse_cli_arguments(vec![
            "izanami".to_string(),
            "--tui".to_string(),
            "--peers".to_string(),
            peers_arg,
        ]);
        let merged = merge_with_overrides(persisted.clone(), &cli_args, &matches);
        assert!(merged.tui, "cli --tui flag should be respected");
        assert_eq!(merged.peers, defaults.peers);
        assert_eq!(merged.faulty, persisted.faulty);
        assert_eq!(merged.duration, persisted.duration);
        assert_eq!(merged.pipeline_time, persisted.pipeline_time);
        assert_eq!(merged.target_blocks, persisted.target_blocks);
        assert_eq!(merged.progress_interval, persisted.progress_interval);
        assert_eq!(merged.progress_timeout, persisted.progress_timeout);
        assert_eq!(
            merged.shutdown_drain_timeout,
            persisted.shutdown_drain_timeout
        );
        assert_eq!(merged.fault_window_start, persisted.fault_window_start);
        assert_eq!(merged.fault_window_end, persisted.fault_window_end);
        assert_eq!(merged.seed, persisted.seed);
        assert!((merged.tps - persisted.tps).abs() <= f64::EPSILON);
        assert_eq!(merged.max_inflight, persisted.max_inflight);
        assert_eq!(merged.submitters, persisted.submitters);
        assert_eq!(merged.log_filter, persisted.log_filter);
        assert_eq!(merged.fault_interval_min, persisted.fault_interval_min);
        assert_eq!(merged.fault_interval_max, persisted.fault_interval_max);
    }
    #[test]
    fn cli_value_matching_default_replaces_persisted_setting() {
        let defaults = config::IzanamiArgs::defaults();
        let mut persisted = defaults.clone();
        persisted.max_inflight = defaults.max_inflight * 2;
        persisted.submitters = defaults.submitters * 3;
        persisted.pipeline_time = Some(Duration::from_secs(11));
        persisted.target_blocks = Some(42);
        persisted.progress_interval = Duration::from_secs(5);
        persisted.progress_timeout = Duration::from_secs(50);
        persisted.shutdown_drain_timeout = Duration::from_secs(31);
        persisted.fault_window_start = Some(Duration::from_secs(5));
        persisted.fault_window_end = Some(Duration::from_secs(10));
        let max_inflight_arg = defaults.max_inflight.to_string();
        let (cli_args, matches) = parse_cli_arguments(vec![
            "izanami".to_string(),
            "--tui".to_string(),
            "--max-inflight".to_string(),
            max_inflight_arg,
        ]);
        let merged = merge_with_overrides(persisted.clone(), &cli_args, &matches);
        assert_eq!(merged.max_inflight, defaults.max_inflight);
        assert_eq!(merged.submitters, persisted.submitters);
        assert_eq!(merged.peers, persisted.peers);
        assert_eq!(merged.pipeline_time, persisted.pipeline_time);
        assert_eq!(merged.target_blocks, persisted.target_blocks);
        assert_eq!(merged.progress_interval, persisted.progress_interval);
        assert_eq!(merged.progress_timeout, persisted.progress_timeout);
        assert_eq!(
            merged.shutdown_drain_timeout,
            persisted.shutdown_drain_timeout
        );
        assert_eq!(merged.fault_window_start, persisted.fault_window_start);
        assert_eq!(merged.fault_window_end, persisted.fault_window_end);
    }
    #[test]
    fn cli_overrides_fault_window_offsets() {
        let defaults = config::IzanamiArgs::defaults();
        let mut persisted = defaults.clone();
        persisted.fault_window_start = Some(Duration::from_secs(33));
        persisted.fault_window_end = Some(Duration::from_secs(66));
        let (cli_args, matches) = parse_cli_arguments(vec![
            "izanami".to_string(),
            "--tui".to_string(),
            "--fault-window-start".to_string(),
            "133s".to_string(),
            "--fault-window-end".to_string(),
            "266s".to_string(),
        ]);
        let merged = merge_with_overrides(persisted, &cli_args, &matches);
        assert_eq!(merged.fault_window_start, Some(Duration::from_secs(133)));
        assert_eq!(merged.fault_window_end, Some(Duration::from_secs(266)));
    }
    #[test]
    fn cli_overrides_latency_p95_threshold() {
        let defaults = config::IzanamiArgs::defaults();
        let mut persisted = defaults.clone();
        persisted.target_blocks = Some(50);
        persisted.latency_p95_threshold = Some(Duration::from_millis(2_000));
        let (cli_args, matches) = parse_cli_arguments(vec![
            "izanami".to_string(),
            "--tui".to_string(),
            "--target-blocks".to_string(),
            "50".to_string(),
            "--latency-p95-threshold".to_string(),
            "900ms".to_string(),
        ]);
        let merged = merge_with_overrides(persisted, &cli_args, &matches);
        assert_eq!(
            merged.latency_p95_threshold,
            Some(Duration::from_millis(900))
        );
    }
    #[test]
    fn cli_overrides_sumeragi_block_tuning() {
        let defaults = config::IzanamiArgs::defaults();
        let mut persisted = defaults.clone();
        persisted.sumeragi_block_max_transactions = 1_024;
        let (cli_args, matches) = parse_cli_arguments(vec![
            "izanami".to_string(),
            "--tui".to_string(),
            "--sumeragi-block-max-transactions".to_string(),
            "1536".to_string(),
        ]);
        let merged = merge_with_overrides(persisted, &cli_args, &matches);
        assert_eq!(merged.sumeragi_block_max_transactions, 1_536);
    }
    #[test]
    fn cli_overrides_shutdown_drain_timeout() {
        let defaults = config::IzanamiArgs::defaults();
        let mut persisted = defaults.clone();
        persisted.shutdown_drain_timeout = Duration::from_secs(9);
        let (cli_args, matches) = parse_cli_arguments(vec![
            "izanami".to_string(),
            "--tui".to_string(),
            "--shutdown-drain-timeout".to_string(),
            "60s".to_string(),
        ]);
        let merged = merge_with_overrides(persisted, &cli_args, &matches);
        assert_eq!(merged.shutdown_drain_timeout, Duration::from_secs(60));
    }
    #[test]
    fn cli_overrides_allow_contract_deploy_in_stable() {
        let defaults = config::IzanamiArgs::defaults();
        let mut persisted = defaults.clone();
        persisted.allow_contract_deploy_in_stable = false;
        let (cli_args, matches) = parse_cli_arguments(vec![
            "izanami".to_string(),
            "--allow-contract-deploy-in-stable".to_string(),
        ]);
        let merged = merge_with_overrides(persisted, &cli_args, &matches);
        assert!(
            merged.allow_contract_deploy_in_stable,
            "cli flag should enable contract deploys in stable runs"
        );
    }
    #[test]
    fn tui_cli_overrides_fault_toggles() {
        let defaults = config::IzanamiArgs::defaults();
        let mut persisted = defaults.clone();
        persisted.tui = false;
        persisted.faults = config::FaultArgs {
            crash_restart: false,
            wipe_storage: false,
            spam_invalid_transactions: false,
            network_latency: false,
            network_partition: false,
            cpu_stress: false,
            disk_saturation: false,
        };
        let (cli_args, matches) = parse_cli_arguments(vec![
            "izanami".to_string(),
            "--tui".to_string(),
            "--fault-enable-crash-restart".to_string(),
            "--fault-enable-wipe-storage".to_string(),
            "--fault-enable-network-latency".to_string(),
            "--fault-enable-spam-invalid-transactions".to_string(),
            "--fault-enable-cpu-stress".to_string(),
        ]);
        let merged = merge_with_overrides(persisted, &cli_args, &matches);
        assert!(merged.faults.crash_restart);
        assert!(merged.faults.wipe_storage);
        assert!(merged.faults.spam_invalid_transactions);
        assert!(merged.faults.network_latency);
        assert!(merged.faults.cpu_stress);
        assert!(!merged.faults.network_partition);
        assert!(!merged.faults.disk_saturation);
    }
    #[test]
    fn cli_accepts_explicit_false_fault_toggles() {
        let (cli_args, _) = parse_cli_arguments(vec![
            "izanami".to_string(),
            "--fault-enable-crash-restart=false".to_string(),
            "--fault-enable-wipe-storage=false".to_string(),
            "--fault-enable-spam-invalid-transactions=false".to_string(),
            "--fault-enable-network-latency=false".to_string(),
            "--fault-enable-network-partition=false".to_string(),
            "--fault-enable-cpu-stress=false".to_string(),
            "--fault-enable-disk-saturation=false".to_string(),
        ]);
        assert!(!cli_args.faults.crash_restart);
        assert!(!cli_args.faults.wipe_storage);
        assert!(!cli_args.faults.spam_invalid_transactions);
        assert!(!cli_args.faults.network_latency);
        assert!(!cli_args.faults.network_partition);
        assert!(!cli_args.faults.cpu_stress);
        assert!(!cli_args.faults.disk_saturation);
    }
    #[test]
    fn cli_overrides_submitter_count() {
        let defaults = config::IzanamiArgs::defaults();
        let mut persisted = defaults.clone();
        persisted.submitters = 7;
        let (cli_args, matches) = parse_cli_arguments(vec![
            "izanami".to_string(),
            "--submitters".to_string(),
            "3".to_string(),
        ]);
        let merged = merge_with_overrides(persisted, &cli_args, &matches);
        assert_eq!(merged.submitters, 3);
    }
}
