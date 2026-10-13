//! Optional, diagnostic-only timing records for the disposable eight-validator test controller.

use super::{Path, PathBuf, TestResult, ensure, eyre};
use crate::managed::NativeBundleLayout;
use iroha_fs::{OwnerDirectory, PublishMode};
use norito::json::{self, JsonDeserialize, JsonSerialize, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read as _,
    time::Instant,
};

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Candidate {
    binaries: BTreeMap<String, String>,
    manifest_sha256: String,
}

#[derive(JsonSerialize)]
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

pub(super) struct CampaignAttempt {
    output: PathBuf,
    bundle: PathBuf,
    copied_bin: PathBuf,
    campaign: String,
    ordinal: u8,
    driver: String,
    driver_path: PathBuf,
    candidate: Candidate,
}

pub(super) struct Measurement {
    output: PathBuf,
    bundle: PathBuf,
    copied_bin: PathBuf,
    driver: String,
    driver_path: PathBuf,
    record: Sample,
    started: Instant,
    completed: bool,
}

fn digest(path: &Path) -> TestResult<String> {
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "timing input is not a regular file"
    );
    Ok(hex::encode(
        iroha_crypto::sha256_reader_bounded(File::open(path)?, 2 * 1024 * 1024 * 1024)?.0,
    ))
}

fn candidate(bundle: &Path, copied_bin: &Path) -> TestResult<Candidate> {
    let manifest = bundle.join("manifest.json");
    ensure!(
        fs::symlink_metadata(&manifest)?.is_file(),
        "timing manifest is not a regular file"
    );
    let mut bytes = Vec::new();
    File::open(&manifest)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1024 * 1024, "timing manifest exceeds bound");
    let value: Value = json::from_slice(&bytes)?;
    ensure!(
        value.get("profile").and_then(Value::as_str) == Some("release"),
        "diagnostic timing requires observed release profile"
    );
    let mut binaries = BTreeMap::new();
    for name in ["mochi", "kagami", "iroha3d"] {
        let filename = format!("{name}{}", std::env::consts::EXE_SUFFIX);
        let hash = digest(
            &NativeBundleLayout::current()
                .runtime_directory(bundle)
                .join(&filename),
        )?;
        // The explicit desktop campaign inventories its full source bundle. Only the two CLI
        // programs execute in this fixture, so an unused UI is never copied or required there.
        if name != "mochi" {
            ensure!(
                digest(&copied_bin.join(&filename))? == hash,
                "timed CLI runtime differs from bundle"
            );
        }
        binaries.insert(name.into(), hash);
    }
    Ok(Candidate {
        binaries,
        manifest_sha256: hex::encode(iroha_crypto::sha256(&bytes)),
    })
}

fn valid_campaign(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl CampaignAttempt {
    pub(super) fn from_environment(
        installed: &Path,
        copied_bin: &Path,
    ) -> TestResult<Option<Self>> {
        let variables = [
            "IROHA_DEVEX_LATENCY_OUTPUT",
            "IROHA_DEVEX_LATENCY_BUNDLE",
            "IROHA_DEVEX_LATENCY_CAMPAIGN",
            "IROHA_DEVEX_LATENCY_ORDINAL",
        ];
        let values: Vec<_> = variables.into_iter().map(std::env::var_os).collect();
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        ensure!(
            values.iter().all(Option::is_some),
            "incomplete diagnostic timing inputs"
        );
        let output = PathBuf::from(values[0].as_ref().unwrap()).canonicalize()?;
        let bundle = PathBuf::from(values[1].as_ref().unwrap()).canonicalize()?;
        ensure!(
            installed.canonicalize()?
                == NativeBundleLayout::current()
                    .runtime_directory(&bundle)
                    .canonicalize()?,
            "timing runtime must be the observed bundle"
        );
        let campaign = values[2]
            .as_ref()
            .unwrap()
            .to_str()
            .ok_or_else(|| eyre!("invalid timing campaign"))?
            .to_owned();
        let ordinal: u8 = values[3]
            .as_ref()
            .unwrap()
            .to_str()
            .ok_or_else(|| eyre!("invalid timing ordinal"))?
            .parse()?;
        ensure!(
            valid_campaign(&campaign) && (1..=20).contains(&ordinal),
            "invalid timing campaign or ordinal"
        );
        OwnerDirectory::open(&output)?;
        let candidate = candidate(&bundle, copied_bin)?;
        let driver_path = std::env::current_exe()?;
        let driver = digest(&driver_path)?;
        Ok(Some(Self {
            output,
            bundle,
            copied_bin: copied_bin.into(),
            campaign,
            ordinal,
            driver,
            driver_path,
            candidate,
        }))
    }

    pub(super) fn start(&self, case: &str) -> TestResult<Measurement> {
        ensure!(
            matches!(
                case,
                "disposable_loopback_attachment"
                    | "ready_private_source"
                    | "ready_private_bytecode"
                    | "ready_private_local_package"
            ),
            "unknown diagnostic case"
        );
        let before = candidate(&self.bundle, &self.copied_bin)?;
        ensure!(
            before == self.candidate && digest(&self.driver_path)? == self.driver,
            "timing candidate changed before command"
        );
        let record = Sample {
            schema: "iroha.devex.latency-sample.v1".into(),
            campaign: self.campaign.clone(),
            ordinal: self.ordinal,
            case: case.into(),
            workload: "disposable_loopback_parent4_child4_tls".into(),
            host_os_observed: std::env::consts::OS.into(),
            host_arch_observed: std::env::consts::ARCH.into(),
            driver_sha256: Some(self.driver.clone()),
            elapsed_ns: 1,
            outcome: "command_failed".into(),
            before,
            after: None,
        };
        Ok(Measurement {
            output: self.output.clone(),
            bundle: self.bundle.clone(),
            copied_bin: self.copied_bin.clone(),
            driver: self.driver.clone(),
            driver_path: self.driver_path.clone(),
            record,
            started: Instant::now(),
            completed: false,
        })
    }

    pub(super) fn cleanup(&self, zero_owned_resources: bool) -> TestResult<()> {
        let value = norito::json!({"schema": "iroha.devex.latency-cleanup.v1", "campaign": (self.campaign.clone()), "ordinal": (self.ordinal), "zero_owned_resources": zero_owned_resources});
        OwnerDirectory::open(
            self.output
                .parent()
                .ok_or_else(|| eyre!("missing diagnostic campaign directory"))?
                .join("control"),
        )?
        .write_atomic(
            format!("{:02}-cleanup.json", self.ordinal),
            &json::to_vec(&value)?,
            PublishMode::CreateNew,
        )?;
        Ok(())
    }
}

impl Measurement {
    /// Stop the CLI timer before protocol/readback checks; failed commands never become successes.
    pub(super) fn command_finished(&mut self, succeeded: bool) {
        self.record.elapsed_ns = u64::try_from(self.started.elapsed().as_nanos())
            .unwrap_or(u64::MAX)
            .max(1);
        self.record.outcome = if succeeded {
            "verification_failed"
        } else {
            "command_failed"
        }
        .into();
    }

    pub(super) fn verified(mut self) -> TestResult<()> {
        ensure!(
            self.record.outcome == "verification_failed",
            "cannot verify a failed or unfinished timed command"
        );
        self.record.outcome = "succeeded".into();
        self.publish()?;
        ensure!(
            self.record.outcome == "succeeded",
            "timing candidate changed during verified command"
        );
        Ok(())
    }

    fn publish(&mut self) -> TestResult<()> {
        if self.completed {
            return Ok(());
        }
        self.record.after = candidate(&self.bundle, &self.copied_bin).ok();
        if self.record.after.as_ref() != Some(&self.record.before)
            || digest(&self.driver_path).ok().as_ref() != Some(&self.driver)
        {
            self.record.outcome = "candidate_changed".into();
        }
        OwnerDirectory::open(&self.output)?.write_atomic(
            format!("{:02}-{}.json", self.record.ordinal, self.record.case),
            &json::to_vec(&self.record)?,
            PublishMode::CreateNew,
        )?;
        self.completed = true;
        Ok(())
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        if !self.completed && self.publish().is_err() {
            eprintln!("diagnostic sample publication failed");
        }
    }
}

#[test]
fn diagnostic_campaign_identifiers_are_closed_and_never_echo_input() {
    assert!(valid_campaign(&"a".repeat(32)));
    assert!(!valid_campaign("/private/secret"));
    assert!(!valid_campaign(&"A".repeat(32)));
}

#[test]
fn timed_failures_candidate_changes_and_later_verification_remain_distinct() {
    let root = tempfile::tempdir().unwrap();
    let bundle = root.path().join("bundle");
    let output = root.path().join("samples");
    let copied_bin = root.path().join("copied");
    for path in [
        &bundle,
        &NativeBundleLayout::current().runtime_directory(&bundle),
        &output,
        &copied_bin,
        &root.path().join("control"),
    ] {
        fs::create_dir_all(path).unwrap();
    }
    fs::write(bundle.join("manifest.json"), b"{\"profile\":\"release\"}").unwrap();
    for name in ["mochi", "kagami", "iroha3d"] {
        let filename = format!("{name}{}", std::env::consts::EXE_SUFFIX);
        fs::write(
            NativeBundleLayout::current()
                .runtime_directory(&bundle)
                .join(&filename),
            name.as_bytes(),
        )
        .unwrap();
        fs::write(copied_bin.join(&filename), name.as_bytes()).unwrap();
    }
    let driver_path = root.path().join("driver");
    fs::write(&driver_path, b"test driver").unwrap();
    let attempt = CampaignAttempt {
        output: output.clone(),
        candidate: candidate(&bundle, &copied_bin).unwrap(),
        bundle,
        copied_bin,
        campaign: "a".repeat(32),
        ordinal: 1,
        driver: digest(&driver_path).unwrap(),
        driver_path,
    };
    let read = |case: &str| -> Value {
        json::from_slice(&fs::read(output.join(format!("01-{case}.json"))).unwrap()).unwrap()
    };
    let mut failed = attempt.start("disposable_loopback_attachment").unwrap();
    failed.command_finished(false);
    assert!(failed.verified().is_err());
    assert_eq!(
        read("disposable_loopback_attachment")
            .get("outcome")
            .and_then(Value::as_str),
        Some("command_failed")
    );
    let mut unverified = attempt.start("ready_private_source").unwrap();
    unverified.command_finished(true);
    drop(unverified);
    assert_eq!(
        read("ready_private_source")
            .get("outcome")
            .and_then(Value::as_str),
        Some("verification_failed")
    );
    let mut verified = attempt.start("ready_private_bytecode").unwrap();
    verified.command_finished(true);
    verified.verified().unwrap();
    let value = read("ready_private_bytecode");
    assert_eq!(
        value.get("outcome").and_then(Value::as_str),
        Some("succeeded")
    );
    assert!(value.get("elapsed_ns").and_then(Value::as_u64).unwrap() > 0);
    assert!(
        !json::to_string(&value)
            .unwrap()
            .contains(root.path().to_str().unwrap())
    );
    let mut changed = attempt.start("ready_private_local_package").unwrap();
    changed.command_finished(true);
    fs::write(&attempt.driver_path, b"other driver").unwrap();
    assert!(changed.verified().is_err());
    assert_eq!(
        read("ready_private_local_package")
            .get("outcome")
            .and_then(Value::as_str),
        Some("candidate_changed")
    );
    assert!(attempt.start("ready_private_source").is_err());
    attempt.cleanup(false).unwrap();
    assert!(attempt.cleanup(true).is_err());
    let cleanup: Value =
        json::from_slice(&fs::read(root.path().join("control/01-cleanup.json")).unwrap()).unwrap();
    assert_eq!(
        cleanup.get("zero_owned_resources").and_then(Value::as_bool),
        Some(false)
    );
}
