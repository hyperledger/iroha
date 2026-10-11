//! Diagnostic installed-CLI latency samples; this is not release or reference-host evidence.

use super::developer_smoke::{Harness, require_deployment, require_phase};
use iroha_deploy::managed::NativeBundleLayout;
use norito::json::{self, JsonDeserialize, JsonSerialize, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
};

const RUNS: u8 = 20;
const MAX_SAMPLE_BYTES: u64 = 32 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const SCHEMA: &str = "iroha.devex.latency-sample.v1";
const LOCAL_CASES: [&str; 4] = [
    "localnet_fresh_state",
    "ready_source",
    "ready_bytecode",
    "ready_local_package",
];
const REMOTE_CASE: &str = "disposable_loopback_attachment";
const REMOTE_CASES: [&str; 4] = [
    REMOTE_CASE,
    "ready_private_source",
    "ready_private_bytecode",
    "ready_private_local_package",
];
const PACKAGE: &str = "manifest-version = 1\n\n[package]\nnamespace = \"latency\"\nname = \"package\"\nversion = \"0.1.0\"\nedition = \"1\"\nabi-version = 1\n\n[[contract]]\nname = \"package\"\npath = \"contract.ko\"\n";
const PACKAGE_SOURCE: &str = "seiyaku LatencyPackage { view fn quote(int cups) authorize(anyone) -> int { return cups * 30; } }";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Succeeded,
    SpawnFailed,
    CommandFailed,
    TimedOut,
    ControllerIo,
    OutputRejected,
    VerificationFailed,
    CandidateChanged,
}
impl Outcome {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::SpawnFailed => "spawn_failed",
            Self::CommandFailed => "command_failed",
            Self::TimedOut => "timed_out",
            Self::ControllerIo => "controller_io",
            Self::OutputRejected => "output_rejected",
            Self::VerificationFailed => "verification_failed",
            Self::CandidateChanged => "candidate_changed",
        }
    }
    fn parse(value: &str) -> Option<Self> {
        [
            Self::Succeeded,
            Self::SpawnFailed,
            Self::CommandFailed,
            Self::TimedOut,
            Self::ControllerIo,
            Self::OutputRejected,
            Self::VerificationFailed,
            Self::CandidateChanged,
        ]
        .into_iter()
        .find(|outcome| outcome.as_str() == value)
    }
}

pub(super) struct CommandObservation {
    pub(super) elapsed_ns: u64,
    pub(super) outcome: Outcome,
    pub(super) value: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Candidate {
    /// Observed digests are not signed provenance or proof of a release build.
    binaries: BTreeMap<String, String>,
    manifest_sha256: String,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Sample {
    schema: String,
    campaign: String,
    ordinal: u8,
    case: String,
    workload: String,
    host_os_observed: String,
    host_arch_observed: String,
    driver_sha256: Option<String>,
    elapsed_ns: u64,
    outcome: String,
    before: Candidate,
    after: Option<Candidate>,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RunRecord {
    schema: String,
    campaign: String,
    ordinal: u8,
    workload: String,
    host_os_observed: String,
    host_arch_observed: String,
    driver_sha256: Option<String>,
    driver_sha256_after: Option<String>,
    before: Candidate,
    after: Option<Candidate>,
    outcome: String,
    cleanup_confirmed: bool,
}

#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Cleanup {
    schema: String,
    campaign: String,
    ordinal: u8,
    zero_owned_resources: bool,
}

fn digest(path: &Path) -> Result<String, Box<dyn Error>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("candidate input must be a regular file".into());
    }
    let (hash, _) = iroha_crypto::sha256_reader_bounded(File::open(path)?, 2 * 1024 * 1024 * 1024)?;
    Ok(hex::encode(hash))
}

fn candidate(bundle: &Path) -> Result<Candidate, Box<dyn Error>> {
    // An observed release label is only a prerequisite, never authenticated provenance.
    let manifest = bundle.join("manifest.json");
    if !fs::symlink_metadata(&manifest)?.file_type().is_file() {
        return Err("bundle manifest must be a regular file".into());
    }
    let mut bytes = Vec::new();
    File::open(&manifest)?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("bundle manifest exceeds its bound".into());
    }
    let value: Value = json::from_slice(&bytes)?;
    if value.get("profile").and_then(Value::as_str) != Some("release") {
        return Err("latency collection requires an observed release bundle profile".into());
    }
    let binaries = ["mochi", "kagami", "iroha3d"]
        .into_iter()
        .map(|name| {
            let path = NativeBundleLayout::current().executable(bundle, name);
            Ok((name.into(), digest(&path)?))
        })
        .collect::<Result<_, Box<dyn Error>>>()?;
    Ok(Candidate {
        binaries,
        manifest_sha256: hex::encode(iroha_crypto::sha256(&bytes)),
    })
}

fn write_new<T: JsonSerialize>(path: &Path, value: &T) -> Result<(), Box<dyn Error>> {
    let bytes = json::to_vec(value)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn sample(
    campaign: &str,
    ordinal: u8,
    case: &str,
    observation: CommandObservation,
    before: Candidate,
    after: Option<Candidate>,
) -> Sample {
    Sample {
        schema: SCHEMA.into(),
        campaign: campaign.into(),
        ordinal,
        case: case.into(),
        workload: "installed_global_ready4_local_package".into(),
        host_os_observed: std::env::consts::OS.into(),
        host_arch_observed: std::env::consts::ARCH.into(),
        driver_sha256: None,
        elapsed_ns: observation.elapsed_ns,
        outcome: if after.as_ref() == Some(&before) {
            observation.outcome
        } else {
            Outcome::CandidateChanged
        }
        .as_str()
        .into(),
        before,
        after,
    }
}

fn verify_command(harness: &Harness, case: &str, observation: &mut CommandObservation) {
    if observation.outcome != Outcome::Succeeded {
        return;
    }
    let valid = observation.value.as_ref().is_some_and(|value| {
        if case == "localnet_fresh_state" {
            require_phase(value, "ready", 4).is_ok()
        } else {
            // Includes original execution scope, exact artifact readback and a genuine view on
            // every validator. These are success postconditions, outside the CLI duration.
            require_deployment(value).is_ok()
                && harness
                    .execute_on_every_peer(
                        value,
                        match case {
                            "ready_source" => "30",
                            "ready_bytecode" => "60",
                            "ready_local_package" => "90",
                            _ => return false,
                        },
                    )
                    .is_ok()
        }
    });
    if !valid {
        observation.outcome = Outcome::VerificationFailed;
    }
}

/// Collect exactly twenty attempted fresh-state starts and three separate ready-input cases.
/// Failed startup skips its dependent ready cases; uncertain cleanup stops the campaign.
/// Missing samples stay visibly incomplete.
/// No measurement or user assertion promotes this diagnostic into qualification evidence.
pub(crate) fn collect(bundle: &Path, output: &Path) -> Result<(), Box<dyn Error>> {
    let bundle = bundle.canonicalize()?;
    let initial = candidate(&bundle)?;
    fs::create_dir(output)?;
    let kagami = NativeBundleLayout::current().executable(&bundle, "kagami");
    // Offline controller compilation is untimed; .to never reuses a timed .ko upload or journal.
    let bytecode = super::developer_smoke::prepare_distinct_bytecode()?;
    let campaign = hex::encode(rand::random::<[u8; 16]>());
    let mut complete = true;
    for ordinal in 1..=RUNS {
        let mut harness = Harness::new(&kagami)?;
        let result = (|| -> Result<(bool, bool), Box<dyn Error>> {
            fs::write(harness.workspace.join("hello.to"), &bytecode)?;
            let package = harness.workspace.join("package");
            fs::create_dir(&package)?;
            fs::write(package.join("Musubi.toml"), PACKAGE)?;
            fs::write(package.join("contract.ko"), PACKAGE_SOURCE)?;
            let commands: [(&str, &[&str]); 4] = [
                (LOCAL_CASES[0], &["localnet", "up"]),
                (LOCAL_CASES[1], &["contract", "deploy", "hello.ko"]),
                (
                    LOCAL_CASES[2],
                    &[
                        "contract",
                        "deploy",
                        "hello.to",
                        "--alias",
                        "LatencyBytecode::universal",
                    ],
                ),
                (LOCAL_CASES[3], &["contract", "deploy", "package"]),
            ];
            let mut run_failed = false;
            let mut changed = false;
            let mut deployments = Vec::new();
            for (case, args) in commands {
                let before = candidate(&bundle)?;
                if before != initial {
                    return Ok((true, true));
                }
                let mut observation = harness.observe_command(args);
                verify_command(&harness, case, &mut observation);
                if case != LOCAL_CASES[0] && observation.outcome == Outcome::Succeeded {
                    if let Some(value) = observation.value.as_ref() {
                        deployments.push(value.clone());
                    }
                    if super::developer_smoke::require_distinct_artifacts(
                        &deployments.iter().collect::<Vec<_>>(),
                    )
                    .is_err()
                    {
                        observation.outcome = Outcome::VerificationFailed;
                    }
                }
                let startup_failed =
                    case == LOCAL_CASES[0] && observation.outcome != Outcome::Succeeded;
                let record = sample(
                    &campaign,
                    ordinal,
                    case,
                    observation,
                    before,
                    candidate(&bundle).ok(),
                );
                changed = record.outcome == Outcome::CandidateChanged.as_str();
                if record.outcome != Outcome::Succeeded.as_str() {
                    run_failed = true;
                }
                write_new(&output.join(format!("{ordinal:02}-{case}.json")), &record)?;
                if startup_failed || changed {
                    break;
                }
            }
            Ok((run_failed, changed))
        })();
        let stopped = harness.stop();
        let after = candidate(&bundle).ok();
        let publication = write_new(
            &output.join(format!("{ordinal:02}-run.json")),
            &RunRecord {
                schema: "iroha.devex.latency-run.v1".into(),
                campaign: campaign.clone(),
                ordinal,
                workload: "installed_global_ready4_local_package".into(),
                host_os_observed: std::env::consts::OS.into(),
                host_arch_observed: std::env::consts::ARCH.into(),
                driver_sha256: None,
                driver_sha256_after: None,
                before: initial.clone(),
                outcome: if after.as_ref() != Some(&initial) {
                    "candidate_changed"
                } else if !stopped {
                    "cleanup_unconfirmed"
                } else if matches!(&result, Ok((false, false))) {
                    "passed"
                } else {
                    "failed"
                }
                .into(),
                after,
                cleanup_confirmed: stopped,
            },
        );
        if let Err(error) = publication {
            harness.retain();
            return Err(error);
        }
        let (run_failed, changed) = match result {
            Ok(flags) => flags,
            Err(error) => {
                harness.retain();
                return Err(error);
            }
        };
        if run_failed || changed || !stopped {
            harness.retain();
            complete = false;
        }
        if changed || !stopped {
            break;
        }
        // A failed start leaves the three ready cases unattempted, never replaced by a retry.
        // The next ordinal is a distinct fresh-state attempt, and all existing rows are retained.
    }
    summarize(output, &output.join("report.json"))?;
    if !complete {
        return Err("diagnostic campaign incomplete; attempted samples were retained".into());
    }
    Ok(())
}

/// Run the exact disposable-parent integration test twenty times, retaining its overall result.
/// The supplied driver is observed by digest; matching release provenance remains unverified.
pub(crate) fn collect_remote(
    bundle: &Path,
    driver: &Path,
    output: &Path,
) -> Result<(), Box<dyn Error>> {
    const TEST: &str = "managed::tests::attachment_installed::installed_parent_attachment_private_contracts_and_payload_isolation";
    let bundle = bundle.canonicalize()?;
    let driver = driver.canonicalize()?;
    let initial = candidate(&bundle)?;
    let initial_driver = digest(&driver)?;
    fs::create_dir(output)?;
    let samples = output.join("samples");
    let control = output.join("control");
    fs::create_dir(&samples)?;
    fs::create_dir(&control)?;
    let campaign = hex::encode(rand::random::<[u8; 16]>());
    let mut complete = true;
    for ordinal in 1..=RUNS {
        if candidate(&bundle)? != initial || digest(&driver)? != initial_driver {
            complete = false;
            break;
        }
        let logs = tempfile::Builder::new()
            .prefix("iroha-latency-driver-")
            .tempdir()?;
        // The original test owns bounded command deadlines and authenticated shutdown. Do not
        // terminate its process and skip that cleanup merely to manufacture another ordinal.
        let result = Command::new(&driver)
            .args([
                "--exact",
                TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(
                "IROHA_TEST_RUNTIME_DIRECTORY",
                NativeBundleLayout::current().runtime_directory(&bundle),
            )
            .env("IROHA_DEVEX_LATENCY_OUTPUT", &samples)
            .env("IROHA_DEVEX_LATENCY_BUNDLE", &bundle)
            .env("IROHA_DEVEX_LATENCY_CAMPAIGN", &campaign)
            .env("IROHA_DEVEX_LATENCY_ORDINAL", ordinal.to_string())
            .stdin(Stdio::null())
            .stdout(File::create(logs.path().join("stdout"))?)
            .stderr(File::create(logs.path().join("stderr"))?)
            .spawn()
            .map_err(|_| "spawn_failed")
            .and_then(|mut child| child.wait().map_err(|_| "controller_io"));
        let cleanup = read_cleanup(
            &control.join(format!("{ordinal:02}-cleanup.json")),
            &campaign,
            ordinal,
        );
        let after = candidate(&bundle).ok();
        let driver_after = digest(&driver).ok();
        let outcome =
            if after.as_ref() != Some(&initial) || driver_after.as_ref() != Some(&initial_driver) {
                "candidate_changed"
            } else if !cleanup {
                "cleanup_unconfirmed"
            } else {
                match result {
                    Ok(status) if status.success() => "passed",
                    Ok(_) => "failed",
                    Err(code) => code,
                }
            };
        let run = RunRecord {
            schema: "iroha.devex.latency-run.v1".into(),
            campaign: campaign.clone(),
            ordinal,
            workload: "disposable_loopback_parent4_child4_tls".into(),
            host_os_observed: std::env::consts::OS.into(),
            host_arch_observed: std::env::consts::ARCH.into(),
            driver_sha256: Some(initial_driver.clone()),
            driver_sha256_after: driver_after,
            before: initial.clone(),
            after,
            outcome: outcome.into(),
            cleanup_confirmed: cleanup,
        };
        if let Err(error) = write_new(&samples.join(format!("{ordinal:02}-run.json")), &run) {
            let retained = logs.keep();
            eprintln!(
                "retained private test-driver diagnostics at {}",
                retained.display()
            );
            return Err(error);
        }
        if outcome != "passed" {
            complete = false;
            let retained = logs.keep();
            eprintln!(
                "retained private test-driver diagnostics at {}",
                retained.display()
            );
        }
        if !cleanup || outcome == "candidate_changed" {
            break;
        }
    }
    summarize(&samples, &output.join("report.json"))?;
    if !complete {
        return Err(
            "diagnostic remote campaign failed or incomplete; attempted records retained".into(),
        );
    }
    Ok(())
}

fn read_cleanup(path: &Path, campaign: &str, ordinal: u8) -> bool {
    let read = (|| -> Result<Cleanup, Box<dyn Error>> {
        if !fs::symlink_metadata(path)?.is_file() {
            return Err("invalid cleanup observation".into());
        }
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_SAMPLE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_SAMPLE_BYTES {
            return Err("cleanup observation exceeds bound".into());
        }
        Ok(json::from_slice(&bytes)?)
    })();
    read.is_ok_and(|cleanup| {
        cleanup.schema == "iroha.devex.latency-cleanup.v1"
            && cleanup.campaign == campaign
            && cleanup.ordinal == ordinal
            && cleanup.zero_owned_resources
    })
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn validate_sample(record: &Sample) -> Result<(), Box<dyn Error>> {
    let local = LOCAL_CASES.contains(&record.case.as_str());
    if record.schema != SCHEMA
        || !lowercase_hex(&record.campaign, 32)
        || !(1..=RUNS).contains(&record.ordinal)
        || (!local && !REMOTE_CASES.contains(&record.case.as_str()))
        || (local && record.workload != "installed_global_ready4_local_package")
        || (!local && record.workload != "disposable_loopback_parent4_child4_tls")
        || record.elapsed_ns == 0
        || !matches!(
            record.host_os_observed.as_str(),
            "linux" | "macos" | "windows"
        )
        || !matches!(record.host_arch_observed.as_str(), "x86_64" | "aarch64")
        || Outcome::parse(&record.outcome).is_none()
        || (local && record.driver_sha256.is_some())
        || (!local
            && !record
                .driver_sha256
                .as_ref()
                .is_some_and(|hash| lowercase_hex(hash, 64)))
    {
        return Err("invalid diagnostic sample fields".into());
    }
    for identity in std::iter::once(&record.before).chain(record.after.iter()) {
        if !lowercase_hex(&identity.manifest_sha256, 64)
            || identity.binaries.len() != 3
            || ["mochi", "kagami", "iroha3d"].iter().any(|name| {
                identity
                    .binaries
                    .get(*name)
                    .is_none_or(|hash| !lowercase_hex(hash, 64))
            })
        {
            return Err("invalid observed candidate hashes".into());
        }
    }
    if record.after.as_ref() != Some(&record.before)
        && record.outcome != Outcome::CandidateChanged.as_str()
    {
        return Err("changed candidate cannot be reported as a completed measurement".into());
    }
    Ok(())
}

fn aggregate(records: &[Sample], runs: &[RunRecord]) -> Result<Value, Box<dyn Error>> {
    let (campaign, candidate, host_os, host_arch, driver, workload) =
        if let Some(first) = records.first() {
            (
                &first.campaign,
                &first.before,
                &first.host_os_observed,
                &first.host_arch_observed,
                &first.driver_sha256,
                &first.workload,
            )
        } else if let Some(first) = runs.first() {
            (
                &first.campaign,
                &first.before,
                &first.host_os_observed,
                &first.host_arch_observed,
                &first.driver_sha256,
                &first.workload,
            )
        } else {
            return Err("no diagnostic attempts".into());
        };
    let mut unique = BTreeSet::new();
    for record in records {
        validate_sample(record)?;
        if &record.campaign != campaign
            || &record.before != candidate
            || &record.host_os_observed != host_os
            || &record.host_arch_observed != host_arch
            || &record.driver_sha256 != driver
        {
            return Err("cannot combine different campaigns, candidates or execution hosts".into());
        }
        if !unique.insert((&record.case, record.ordinal)) {
            return Err("duplicate case and attempt ordinal".into());
        }
    }
    let remote = workload == "disposable_loopback_parent4_child4_tls";
    let cases: &[&str] = if remote { &REMOTE_CASES } else { &LOCAL_CASES };
    if records
        .iter()
        .any(|record| !cases.contains(&record.case.as_str()))
    {
        return Err("local and disposable-parent workloads are separate campaigns".into());
    }
    let mut run_ordinals = BTreeSet::new();
    let mut passed_runs = 0;
    for run in runs {
        // Reuse the exact closed identity/host/workload rules, without creating a measurement.
        validate_sample(&Sample {
            schema: SCHEMA.into(),
            campaign: run.campaign.clone(),
            ordinal: run.ordinal,
            case: cases[0].into(),
            workload: run.workload.clone(),
            host_os_observed: run.host_os_observed.clone(),
            host_arch_observed: run.host_arch_observed.clone(),
            driver_sha256: run.driver_sha256.clone(),
            elapsed_ns: 1,
            outcome: if run.after.as_ref() == Some(&run.before) {
                "command_failed"
            } else {
                "candidate_changed"
            }
            .into(),
            before: run.before.clone(),
            after: run.after.clone(),
        })?;
        if run.schema != "iroha.devex.latency-run.v1"
            || &run.campaign != campaign
            || &run.before != candidate
            || &run.host_os_observed != host_os
            || &run.host_arch_observed != host_arch
            || &run.driver_sha256 != driver
            || run
                .driver_sha256_after
                .as_ref()
                .is_some_and(|hash| !lowercase_hex(hash, 64))
            || (!remote && run.driver_sha256_after.is_some())
            || &run.workload != workload
            || !run_ordinals.insert(run.ordinal)
            || !matches!(
                run.outcome.as_str(),
                "passed"
                    | "failed"
                    | "spawn_failed"
                    | "controller_io"
                    | "timed_out"
                    | "candidate_changed"
                    | "cleanup_unconfirmed"
            )
        {
            return Err("invalid, duplicate or mismatched diagnostic run".into());
        }
        if run.outcome == "passed" {
            if !run.cleanup_confirmed
                || run.after.as_ref() != Some(&run.before)
                || run.driver_sha256_after != run.driver_sha256
            {
                return Err("passed run lacks exact candidate or cleanup evidence".into());
            }
            passed_runs += 1;
        }
    }
    // Every ordinal is bounded and every (case, ordinal) is unique above. Thus the full grid
    // plus successful outcomes is required even when an imported driver row claims "passed".
    // Inconsistent or incomplete inputs remain useful failure reports, never partial successes.
    let complete_measurements = records.len() == cases.len() * usize::from(RUNS)
        && records
            .iter()
            .all(|record| record.outcome == Outcome::Succeeded.as_str());
    let campaign_passed = passed_runs == usize::from(RUNS)
        && runs.len() == usize::from(RUNS)
        && complete_measurements;
    let mut summaries = Vec::new();
    for case in cases {
        let selected: Vec<_> = records
            .iter()
            .filter(|record| record.case == *case)
            .collect();
        let successes = selected
            .iter()
            .filter(|record| record.outcome == Outcome::Succeeded.as_str())
            .count();
        // No failed/timeout attempt is dropped or replaced by a retry to manufacture 20 successes.
        let mut times: Vec<_> = selected.iter().map(|record| record.elapsed_ns).collect();
        times.sort_unstable();
        let p95 = (campaign_passed
            && selected.len() == usize::from(RUNS)
            && successes == usize::from(RUNS))
        .then(|| times[18]);
        let limit = if *case == REMOTE_CASE {
            60_000_000_000_u64
        } else {
            30_000_000_000
        };
        summaries.push(norito::json!({
            "case": (*case), "planned": RUNS, "attempted": (selected.len()),
            "unattempted": (usize::from(RUNS) - selected.len()),
            "succeeded": successes, "failed": (selected.len() - successes),
            "p95_ns": p95, "diagnostic_threshold_met": (p95.is_some_and(|time| time <= limit)),
        }));
    }
    let mut prerequisites = vec![
        "signed_release_source_provenance",
        "reference_8_core_32_gib_ssd_host",
    ];
    if remote {
        prerequisites.extend([
            "matching_release_test_driver_provenance",
            "healthy_remote_parent_rtt_at_most_100_ms",
            "official_taira_profile",
            "production_remote_workload",
        ]);
    }
    Ok(norito::json!({
        "schema": "iroha.devex.latency-report.v1", "campaign": (campaign.clone()),
        "qualification": "diagnostic", "reference_latency_qualified": false,
        "candidate_observed": (candidate.clone()),
        "test_driver_sha256_observed": (driver.clone()),
        "host_os_observed": (host_os.clone()), "host_arch_observed": (host_arch.clone()),
        "runs_attempted": (runs.len()), "runs_passed": passed_runs, "all_runs_passed": campaign_passed,
        "unverified_prerequisites": prerequisites,
        "cases": summaries,
    }))
}

/// Aggregate one complete or partial campaign without dropping any failure or accepting logs.
pub(crate) fn summarize(directory: &Path, output: &Path) -> Result<(), Box<dyn Error>> {
    let mut records = Vec::new();
    let mut runs = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path == output || path.file_name().is_some_and(|name| name == "report.json") {
            continue;
        }
        if !fs::symlink_metadata(&path)?.is_file() {
            return Err("sample directory contains a non-file".into());
        }
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_SAMPLE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_SAMPLE_BYTES {
            return Err("diagnostic sample exceeds its bound".into());
        }
        let value: Value = json::from_slice(&bytes)?;
        match value.get("schema").and_then(Value::as_str) {
            Some(SCHEMA) => records.push(json::from_value::<Sample>(value)?),
            Some("iroha.devex.latency-run.v1") => runs.push(json::from_value::<RunRecord>(value)?),
            _ => return Err("unknown diagnostic record schema".into()),
        }
        if records.len() > usize::from(RUNS) * LOCAL_CASES.len() || runs.len() > usize::from(RUNS) {
            return Err("too many diagnostic samples".into());
        }
    }
    write_new(output, &aggregate(&records, &runs)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Candidate {
        Candidate {
            binaries: ["mochi", "kagami", "iroha3d"]
                .into_iter()
                .map(|name| (name.into(), "a".repeat(64)))
                .collect(),
            manifest_sha256: "b".repeat(64),
        }
    }
    fn records() -> Vec<Sample> {
        (1..=RUNS)
            .flat_map(|ordinal| {
                LOCAL_CASES.map(|case| {
                    sample(
                        &"c".repeat(32),
                        ordinal,
                        case,
                        CommandObservation {
                            elapsed_ns: u64::from(ordinal),
                            outcome: Outcome::Succeeded,
                            value: None,
                        },
                        identity(),
                        Some(identity()),
                    )
                })
            })
            .collect()
    }
    fn run_records(records: &[Sample]) -> Vec<RunRecord> {
        let mut by_ordinal = BTreeMap::new();
        for record in records {
            by_ordinal.entry(record.ordinal).or_insert(record);
        }
        by_ordinal
            .into_values()
            .map(|record| RunRecord {
                schema: "iroha.devex.latency-run.v1".into(),
                campaign: record.campaign.clone(),
                ordinal: record.ordinal,
                workload: record.workload.clone(),
                host_os_observed: record.host_os_observed.clone(),
                host_arch_observed: record.host_arch_observed.clone(),
                driver_sha256: record.driver_sha256.clone(),
                driver_sha256_after: record.driver_sha256.clone(),
                before: record.before.clone(),
                after: Some(record.before.clone()),
                outcome: "passed".into(),
                cleanup_confirmed: true,
            })
            .collect()
    }
    fn aggregate(records: &[Sample]) -> Result<Value, Box<dyn Error>> {
        super::aggregate(records, &run_records(records))
    }
    fn summary<'a>(report: &'a Value, case: &str) -> &'a Value {
        report
            .get("cases")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item.get("case").and_then(Value::as_str) == Some(case))
            .unwrap()
    }

    #[test]
    fn package_fixture_compiles_with_explicit_open_view_authorization() {
        let (_, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(PACKAGE_SOURCE)
            .expect("compile the exact latency package source offline");
        assert_eq!(manifest.seiyaku_name.as_deref(), Some("LatencyPackage"));
        let quote = manifest
            .entrypoints
            .as_ref()
            .unwrap()
            .iter()
            .find(|entrypoint| entrypoint.name == "quote")
            .unwrap();
        assert_eq!(
            quote.kind,
            iroha_data_model::smart_contract::manifest::EntryPointKind::View
        );
        assert_eq!(
            quote.authorization,
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone
        );
    }

    #[test]
    fn exact_twenty_cases_use_nearest_rank_p95_and_remain_diagnostic() {
        let report = aggregate(&records()).unwrap();
        for case in LOCAL_CASES {
            let item = summary(&report, case);
            assert_eq!(item.get("attempted").and_then(Value::as_u64), Some(20));
            assert_eq!(item.get("p95_ns").and_then(Value::as_u64), Some(19));
            assert_eq!(
                item.get("diagnostic_threshold_met")
                    .and_then(Value::as_bool),
                Some(true)
            );
        }
        assert_eq!(
            report.get("qualification").and_then(Value::as_str),
            Some("diagnostic")
        );
        assert_eq!(
            report
                .get("reference_latency_qualified")
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn failed_missing_and_duplicate_attempts_cannot_be_replaced_by_twenty_successes() {
        let mut rows = records();
        rows[1].outcome = Outcome::TimedOut.as_str().into();
        let report = aggregate(&rows).unwrap();
        let source = summary(&report, "ready_source");
        assert_eq!(source.get("attempted").and_then(Value::as_u64), Some(20));
        assert_eq!(source.get("failed").and_then(Value::as_u64), Some(1));
        assert_eq!(source.get("p95_ns"), Some(&Value::Null));
        rows.remove(1);
        let partial = aggregate(&rows).unwrap();
        assert_eq!(
            summary(&partial, "ready_source")
                .get("attempted")
                .and_then(Value::as_u64),
            Some(19)
        );
        assert_eq!(
            summary(&partial, "ready_source").get("p95_ns"),
            Some(&Value::Null)
        );
        rows.push(rows[0].clone());
        assert!(aggregate(&rows).is_err());
    }

    #[test]
    fn candidate_drift_and_untrusted_sample_fields_fail_closed() {
        let mut rows = records();
        rows[1].campaign = "d".repeat(32);
        assert!(aggregate(&rows).is_err());
        rows = records();
        rows[1].before.manifest_sha256 = "d".repeat(64);
        assert!(aggregate(&rows).is_err());
        rows = records();
        rows[1].after = None;
        assert!(aggregate(&rows).is_err());
        rows[1].outcome = Outcome::CandidateChanged.as_str().into();
        assert_eq!(
            summary(&aggregate(&rows).unwrap(), "ready_source").get("p95_ns"),
            Some(&Value::Null)
        );
        rows[1].outcome = "Authorization: secret /private/owner/key response-body".into();
        let error = aggregate(&rows).unwrap_err().to_string();
        assert!(!error.contains("secret"));
        let mut value = json::to_value(&records()[0]).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("qualified".into(), true.into());
        assert!(json::from_value::<Sample>(value).is_err());
    }

    #[test]
    fn aggregation_preserves_execution_host_and_rejects_mixed_hosts() {
        let mut rows = records();
        for row in &mut rows {
            row.host_os_observed = "linux".into();
            row.host_arch_observed = "aarch64".into();
        }
        let report = aggregate(&rows).unwrap();
        assert_eq!(
            report.get("host_os_observed").and_then(Value::as_str),
            Some("linux")
        );
        assert_eq!(
            report.get("host_arch_observed").and_then(Value::as_str),
            Some("aarch64")
        );
        let prerequisites =
            json::to_string(report.get("unverified_prerequisites").unwrap()).unwrap();
        assert!(!prerequisites.contains("taira"));
        assert!(!prerequisites.contains("remote"));
        rows[1].host_os_observed = "windows".into();
        assert!(aggregate(&rows).is_err());
        rows[1].host_os_observed = "linux".into();
        rows[1].host_arch_observed = "x86_64".into();
        assert!(aggregate(&rows).is_err());
        rows[1].host_arch_observed = "secret-value".into();
        assert!(
            !aggregate(&rows)
                .unwrap_err()
                .to_string()
                .contains("secret-value")
        );
    }

    #[test]
    fn candidate_requires_release_profile_before_creating_any_campaign_output() {
        let temp = tempfile::tempdir().unwrap();
        let bundle = temp.path().join("bundle");
        fs::create_dir(&bundle).unwrap();
        fs::create_dir_all(NativeBundleLayout::current().runtime_directory(&bundle)).unwrap();
        for name in ["mochi", "kagami", "iroha3d"] {
            fs::write(
                NativeBundleLayout::current().executable(&bundle, name),
                b"fixture binary",
            )
            .unwrap();
        }
        let output = temp.path().join("samples");
        for profile in ["debug", "local-release", "unknown"] {
            fs::write(
                bundle.join("manifest.json"),
                json::to_vec(&norito::json!({"profile": profile})).unwrap(),
            )
            .unwrap();
            assert!(collect(&bundle, &output).is_err());
            assert!(!output.exists());
        }
        fs::write(bundle.join("manifest.json"), b"{\"profile\":\"release\"}").unwrap();
        assert!(candidate(&bundle).is_ok());
        fs::write(
            bundle.join("manifest.json"),
            vec![b' '; usize::try_from(MAX_MANIFEST_BYTES + 1).unwrap()],
        )
        .unwrap();
        assert!(candidate(&bundle).is_err());
    }

    #[test]
    fn sample_output_drops_raw_cli_details_and_observed_hash_changes_are_detected() {
        let record = sample(
            &"c".repeat(32),
            1,
            LOCAL_CASES[0],
            CommandObservation {
                elapsed_ns: 1,
                outcome: Outcome::CommandFailed,
                value: Some(
                    norito::json!({"body": "fixture-secret", "journal": "/private/owner/key"}),
                ),
            },
            identity(),
            None,
        );
        assert_eq!(record.outcome, "candidate_changed");
        let encoded = String::from_utf8(json::to_vec(&record).unwrap()).unwrap();
        assert!(!encoded.contains("fixture-secret"));
        assert!(!encoded.contains("/private"));
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("binary");
        fs::write(&path, b"first candidate").unwrap();
        let first = digest(&path).unwrap();
        fs::write(&path, b"other candidate").unwrap();
        assert_ne!(first, digest(&path).unwrap());
    }

    #[test]
    fn aggregate_files_are_bounded_create_only_and_remote_workload_stays_distinct() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("samples");
        fs::create_dir(&input).unwrap();
        for record in records() {
            write_new(
                &input.join(format!("{}-{}.json", record.ordinal, record.case)),
                &record,
            )
            .unwrap();
        }
        for record in run_records(&records()) {
            write_new(&input.join(format!("{}-run.json", record.ordinal)), &record).unwrap();
        }
        let output = temp.path().join("report.json");
        summarize(&input, &output).unwrap();
        assert!(summarize(&input, &output).is_err());
        let mut remote = records().remove(0);
        remote.case = REMOTE_CASE.into();
        remote.workload = "disposable_loopback_parent4_child4_tls".into();
        remote.driver_sha256 = Some("d".repeat(64));
        let mut mixed = records();
        mixed.push(remote.clone());
        assert!(aggregate(&mixed).is_err());
        let report = aggregate(&[remote]).unwrap();
        assert_eq!(
            summary(&report, REMOTE_CASE).get("p95_ns"),
            Some(&Value::Null)
        );
        fs::write(
            input.join("oversized.json"),
            vec![b' '; usize::try_from(MAX_SAMPLE_BYTES + 1).unwrap()],
        )
        .unwrap();
        assert!(summarize(&input, &temp.path().join("refused.json")).is_err());
    }

    #[test]
    fn latency_commands_require_explicit_inputs_and_reject_qualification_assertions() {
        for command in ["mochi-latency", "mochi-latency-report"] {
            let input = if command == "mochi-latency" {
                "--bundle"
            } else {
                "--samples"
            };
            assert!(
                crate::parse_command(
                    ["xtask", command, input, "input", "--out", "output"]
                        .into_iter()
                        .map(str::to_owned)
                )
                .is_ok()
            );
            assert!(
                crate::parse_command(
                    [
                        "xtask",
                        command,
                        input,
                        "input",
                        "--out",
                        "output",
                        "--qualified"
                    ]
                    .into_iter()
                    .map(str::to_owned)
                )
                .is_err()
            );
            assert!(
                crate::parse_command(
                    ["xtask", command, input, "input"]
                        .into_iter()
                        .map(str::to_owned)
                )
                .is_err()
            );
        }
        assert!(
            crate::parse_command(
                [
                    "xtask",
                    "mochi-latency-remote",
                    "--bundle",
                    "bundle",
                    "--driver",
                    "driver",
                    "--out",
                    "samples"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .is_ok()
        );
        assert!(
            crate::parse_command(
                [
                    "xtask",
                    "mochi-latency-remote",
                    "--bundle",
                    "bundle",
                    "--out",
                    "samples"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .is_err()
        );
    }

    #[test]
    fn later_remote_failure_or_missing_cleanup_prevents_threshold_claim() {
        let mut records = records();
        for record in &mut records {
            record.case = REMOTE_CASES[LOCAL_CASES
                .iter()
                .position(|case| *case == record.case)
                .unwrap()]
            .into();
            record.workload = "disposable_loopback_parent4_child4_tls".into();
            record.driver_sha256 = Some("d".repeat(64));
        }
        let mut runs = run_records(&records);
        let passed = super::aggregate(&records, &runs).unwrap();
        assert_eq!(
            passed.get("all_runs_passed").and_then(Value::as_bool),
            Some(true)
        );
        runs[19].outcome = "failed".into();
        let failed = super::aggregate(&records, &runs).unwrap();
        for case in REMOTE_CASES {
            assert_eq!(summary(&failed, case).get("p95_ns"), Some(&Value::Null));
        }
        runs[19].outcome = "passed".into();
        runs[19].cleanup_confirmed = false;
        assert!(super::aggregate(&records, &runs).is_err());
        runs.pop();
        assert_eq!(
            super::aggregate(&records, &runs)
                .unwrap()
                .get("all_runs_passed")
                .and_then(Value::as_bool),
            Some(false)
        );
        let setup_failed = super::aggregate(&[], &runs).unwrap();
        assert_eq!(
            summary(&setup_failed, REMOTE_CASE)
                .get("unattempted")
                .and_then(Value::as_u64),
            Some(20)
        );
    }

    #[test]
    fn passed_driver_rows_cannot_hide_failed_or_missing_measurements() {
        let complete = records();
        let runs = run_records(&complete);
        let mut failed = complete.clone();
        failed[1].outcome = "verification_failed".into();
        let mut missing = complete.clone();
        missing.remove(1);
        for input in [&failed, &missing] {
            let report = super::aggregate(input, &runs).unwrap();
            assert_eq!(
                report.get("all_runs_passed").and_then(Value::as_bool),
                Some(false)
            );
            for case in LOCAL_CASES {
                assert_eq!(summary(&report, case).get("p95_ns"), Some(&Value::Null));
                assert_eq!(
                    summary(&report, case)
                        .get("diagnostic_threshold_met")
                        .and_then(Value::as_bool),
                    Some(false)
                );
            }
        }
    }

    #[test]
    fn cleanup_record_requires_matching_campaign_ordinal_and_true_bounded_result() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("cleanup.json");
        let campaign = "a".repeat(32);
        let value = norito::json!({"schema":"iroha.devex.latency-cleanup.v1", "campaign":(campaign.clone()), "ordinal":1, "zero_owned_resources":true});
        fs::write(&path, json::to_vec(&value).unwrap()).unwrap();
        assert!(read_cleanup(&path, &campaign, 1));
        assert!(!read_cleanup(&path, &campaign, 2));
        assert!(!read_cleanup(&path, &"b".repeat(32), 1));
        fs::write(
            &path,
            vec![b' '; usize::try_from(MAX_SAMPLE_BYTES + 1).unwrap()],
        )
        .unwrap();
        assert!(!read_cleanup(&path, &campaign, 1));
    }
}
