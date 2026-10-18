//! Opt-in complete ordinary and structural-maximum proofs with public-only receipts.
//!
//! This test uses the real first-release producer and independent verifier. It
//! retains public proof bytes before checking the unchanged time target. Run
//! the optimized exact test under `/usr/bin/time -l` on macOS to measure RSS;
//! the private allocation ledger is not an observation of process memory.

use super::*;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read as _, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest as _, Sha256};

thread_local! {
    // Enabled only around a locally constructed public release fixture or a
    // retained public candidate replay. Ordinary tests and production have no sink.
    static PUBLIC_DIAGNOSTIC_DIRECTORY_V1: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

struct PublicFixtureDiagnosticGuardV1 {
    // A thread-local capability must also be dropped on its creating thread.
    _thread: core::marker::PhantomData<std::rc::Rc<()>>,
}

impl PublicFixtureDiagnosticGuardV1 {
    fn begin_v1(directory: &Path) -> Self {
        PUBLIC_DIAGNOSTIC_DIRECTORY_V1.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(
                slot.is_none(),
                "public diagnostic capture is already active"
            );
            *slot = Some(directory.to_path_buf());
        });
        Self {
            _thread: core::marker::PhantomData,
        }
    }
}

impl Drop for PublicFixtureDiagnosticGuardV1 {
    fn drop(&mut self) {
        PUBLIC_DIAGNOSTIC_DIRECTORY_V1.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }
}

fn record_public_diagnostic_v1(directory: &Path, record: &str) -> io::Result<()> {
    append_receipt_v1(&directory.join("receipt.txt"), record)?;
    println!("{record}");
    Ok(())
}

/// Identity context for the shared phase-tree record of one diagnostic run.
///
/// `scripts/zk_resource_harness.py` writes the context into its output
/// directory before starting this process. Without a harness the identity is
/// explicitly unbound, and the record's own validation reports that.
fn harness_context_from_v1(
    directory: Option<PathBuf>,
) -> (iroha_measurement::RunContext, Option<PathBuf>) {
    match directory {
        Some(directory) => (
            iroha_measurement::read_harness_context(&directory)
                .expect("harness output directory holds a readable context"),
            Some(directory),
        ),
        None => (iroha_measurement::RunContext::unbound(), None),
    }
}

/// Read the harness hand-off. This diagnostic-only variable selects where a
/// public record is written; no prover or verifier code reads it.
fn harness_context_v1() -> (iroha_measurement::RunContext, Option<PathBuf>) {
    harness_context_from_v1(
        std::env::var_os(iroha_measurement::HARNESS_OUTPUT_DIR_ENV).map(PathBuf::from),
    )
}

/// Retain the public phase-tree record beside the receipt and return the
/// receipt lines that describe it. Earlier records are never overwritten.
///
/// `harness` is what the observation's own session wrote into the harness
/// directory: the session writes there itself so that a failed, abandoned or
/// unwound run is retained too. A record the harness did not receive in both
/// forms is an error.
fn retain_phase_tree_v1(
    directory: &Path,
    harness: Option<&iroha_measurement::DirectoryReport>,
    record: &iroha_measurement::MeasurementRecord,
) -> io::Result<String> {
    use core::fmt::Write as _;
    let mut text = String::new();
    let mut sink =
        iroha_measurement::DirectorySink::new(directory.to_path_buf(), "zk_x509-phase-tree");
    let retained = sink.report();
    iroha_measurement::RecordSink::accept(&mut sink, record.clone());
    for (key, report) in [
        ("phase_tree_record", Some(&retained)),
        ("phase_tree_harness_record", harness),
    ] {
        let Some(report) = report else { continue };
        if let Some(kind) = report.errors().first() {
            return Err(io::Error::new(*kind, "phase-tree record was not retained"));
        }
        if report.written().len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "phase-tree record was not written exactly once",
            ));
        }
        for path in report.written() {
            writeln!(text, "{key}={}", path.display()).expect("String formatting");
        }
    }
    let attribution = record.attribution().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "phase-tree record has no root")
    })?;
    // The one-percent rule alone is met by a single wrapper phase, so the
    // receipt also states the largest phase that no child divides.
    let (undivided_phase, undivided_ppm) =
        record
            .largest_undivided_phase()
            .map_or(("none", 0), |largest| {
                (
                    record.phase_tree.nodes[largest.phase as usize]
                        .label
                        .as_str(),
                    largest.share_parts_per_million(),
                )
            });
    write!(
        text,
        "phase_tree_outcome={}\nphase_tree_root_wall_ns={}\nphase_tree_unattributed_wall_ns={}\nphase_tree_unattributed_ppm={}\nphase_tree_within_one_percent={}\nphase_tree_largest_undivided_phase={undivided_phase}\nphase_tree_largest_undivided_ppm={undivided_ppm}\nphase_tree_findings={:?}",
        record.outcome.as_str(),
        attribution.root_wall_ns,
        attribution.unattributed_wall_ns,
        attribution.unattributed_parts_per_million(),
        attribution.within_limit(),
        record.findings(),
    )
    .expect("String formatting");
    Ok(text)
}

#[test]
fn phase_tree_record_is_retained_beside_the_receipt_and_for_the_harness() {
    use super::super::prover_observation::{ObservationV1, PhaseTimerV1, PhaseV1};
    let evidence = run_directory_v1(&std::env::temp_dir()).unwrap();
    let harness = evidence.join("harness");
    fs::create_dir(&harness).unwrap();
    let context = iroha_measurement::RunContext {
        source_commit: "7e93d3e049".repeat(4),
        source_dirty: false,
        source_dirty_digest: None,
        artifact: "sha256:x509-diagnostic".into(),
        profile: "complete49-MAIN-plus-compactCA".into(),
        config: "taira_default".into(),
        hardware: "reference/unit-test-host".into(),
        cache_policy: iroha_measurement::CachePolicy::Cold,
    };
    fs::write(
        harness.join(iroha_measurement::HARNESS_CONTEXT_FILE),
        context.to_json_view(),
    )
    .unwrap();
    assert_eq!(
        harness_context_from_v1(None),
        (iroha_measurement::RunContext::unbound(), None)
    );
    let (bound, directory) = harness_context_from_v1(Some(harness.clone()));
    assert_eq!((&bound, directory.as_deref()), (&context, Some(&*harness)));
    assert_eq!(
        harness_context_v1(),
        harness_context_from_v1(
            std::env::var_os(iroha_measurement::HARNESS_OUTPUT_DIR_ENV).map(PathBuf::from)
        )
    );

    // The session writes the harness copy itself when the observation ends.
    let observation = ObservationV1::begin_with_harness_v1(bound, directory);
    PhaseTimerV1::start_v1(PhaseV1::Preparation).complete_v1();
    observation.record_failure_v1("producer", "error");
    observation.record_proof_bytes_v1(4096);
    let receipt = observation.finish_v1();
    let record = receipt.measurement_v1().unwrap();
    assert_eq!(fs::read_dir(&harness).unwrap().count(), 3);
    let text = retain_phase_tree_v1(&evidence, receipt.harness_v1(), record).unwrap();
    let written: Vec<_> = text
        .lines()
        .filter_map(|line| {
            line.strip_prefix("phase_tree_record=")
                .or_else(|| line.strip_prefix("phase_tree_harness_record="))
        })
        .map(PathBuf::from)
        .collect();
    assert_eq!(written.len(), 2);
    assert_eq!(written[0].parent(), Some(&*evidence));
    assert_eq!(written[1].parent(), Some(&*harness));
    // Retaining the evidence copy does not write the harness copy again.
    assert_eq!(fs::read_dir(&harness).unwrap().count(), 3);
    for path in &written {
        let decoded =
            iroha_measurement::MeasurementRecord::from_norito_bytes(&fs::read(path).unwrap())
                .unwrap();
        assert_eq!(&decoded, record);
        let view = fs::read_to_string(path.with_extension("json")).unwrap();
        assert_eq!(
            &iroha_measurement::MeasurementRecord::from_json_view(&view).unwrap(),
            record
        );
    }
    // A failed producer run is retained as a failed record, not dropped.
    assert!(text.contains("phase_tree_outcome=failed"));
    assert!(text.contains("phase_tree_within_one_percent="));
    assert!(text.contains("RunNotSucceeded"));
    assert!(text.contains(&format!(
        "phase_tree_root_wall_ns={}",
        record.attribution().unwrap().root_wall_ns
    )));
    // The receipt states how coarse the tree is, not only the 1% rule.
    assert!(text.contains("phase_tree_largest_undivided_phase=Preparation\n"));
    assert!(text.contains(&format!(
        "phase_tree_largest_undivided_ppm={}\n",
        record
            .largest_undivided_phase()
            .unwrap()
            .share_parts_per_million()
    )));
    // Retaining again adds new files and leaves the first record intact.
    let before = fs::read(&written[0]).unwrap();
    let again = retain_phase_tree_v1(&evidence, None, record).unwrap();
    assert!(!again.contains(&written[0].display().to_string()));
    assert!(!again.contains("phase_tree_harness_record="));
    assert_eq!(fs::read(&written[0]).unwrap(), before);
    assert!(retain_phase_tree_v1(&evidence.join("absent"), None, record).is_err());
    // A harness copy that was not written exactly once is an error, not a
    // silently missing record.
    let unwritten = iroha_measurement::DirectorySink::new(harness.join("absent"), "x").report();
    assert!(retain_phase_tree_v1(&evidence, Some(&unwritten), record).is_err());
    fs::remove_dir_all(evidence).unwrap();
}

fn retain_unverified_candidate_v1(directory: &Path, proof: &[u8]) -> io::Result<PathBuf> {
    if proof.is_empty() || proof.len() > super::super::profile::ZK_X509_MAX_PROOF_BYTES_V1 as usize
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "public candidate exceeds proof cap",
        ));
    }
    let digest = hex::encode(Sha256::digest(proof));
    let path = directory.join(format!("unverified-{digest}.x5s1"));
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(proof)?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file()
                || metadata.len() != proof.len() as u64
                || read_unverified_candidate_v1(&path)? != proof
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "existing candidate differs",
                ));
            }
        }
        Err(error) => return Err(error),
    }
    Ok(path)
}

/// Retain only the already encoded public candidate, never prover/witness state.
pub fn capture_public_unverified_candidate_v1(proof: &[u8]) {
    PUBLIC_DIAGNOSTIC_DIRECTORY_V1.with(|slot| {
        let slot = slot.borrow();
        let Some(directory) = slot.as_ref() else { return; };
        let path = retain_unverified_candidate_v1(directory, proof).expect("public candidate custody");
        record_public_diagnostic_v1(directory, &format!(
            "candidate_status=unverified\ncandidate_path={}\ncandidate_bytes={}\ncandidate_sha256={}\ncandidate_qualification=false\nprivate_witness_recorded=false",
            path.display(), proof.len(), hex::encode(Sha256::digest(proof)),
        )).expect("public candidate receipt");
    });
}

/// Record the exact error returned by a verifier of public bytes, only on opt-in.
pub fn record_public_verifier_error_v1(stage: &'static str, error: &impl core::fmt::Debug) {
    PUBLIC_DIAGNOSTIC_DIRECTORY_V1.with(|slot| {
        let slot = slot.borrow();
        let Some(directory) = slot.as_ref() else {
            return;
        };
        record_public_diagnostic_v1(
            directory,
            &format!("public_verifier_stage={stage}\npublic_verifier_error={error:?}"),
        )
        .expect("public verifier diagnostic receipt");
    });
}

#[test]
fn public_candidate_capture_requires_explicit_scope_and_restores_on_unwind() {
    let directory = run_directory_v1(&std::env::temp_dir()).unwrap();
    let proof = b"public unverified candidate fixture";
    capture_public_unverified_candidate_v1(proof);
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
    assert!(
        std::panic::catch_unwind(|| {
            let _guard = PublicFixtureDiagnosticGuardV1::begin_v1(&directory);
            capture_public_unverified_candidate_v1(proof);
            record_public_verifier_error_v1("fixture-only", &"public failure");
            panic!("public fixture unwind");
        })
        .is_err()
    );
    let before = fs::read(directory.join("receipt.txt")).unwrap();
    capture_public_unverified_candidate_v1(b"unscoped public bytes");
    record_public_verifier_error_v1("unscoped", &"public failure");
    assert_eq!(fs::read(directory.join("receipt.txt")).unwrap(), before);
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 2);
    assert!(
        String::from_utf8(before)
            .unwrap()
            .contains("candidate_status=unverified")
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn unverified_candidate_owner_preserves_hash_bounds_and_rejects_substitution() {
    let directory = run_directory_v1(&std::env::temp_dir()).unwrap();
    let proof = b"public candidate owner fixture";
    let path = retain_unverified_candidate_v1(&directory, proof).unwrap();
    assert_eq!(
        path.file_name().unwrap().to_str().unwrap(),
        format!("unverified-{}.x5s1", hex::encode(Sha256::digest(proof)))
    );
    assert_eq!(fs::read(&path).unwrap(), proof);
    assert_eq!(
        retain_unverified_candidate_v1(&directory, proof).unwrap(),
        path
    );
    assert!(retain_unverified_candidate_v1(&directory, &[]).is_err());
    let oversized = vec![0; super::super::profile::ZK_X509_MAX_PROOF_BYTES_V1 as usize + 1];
    assert!(retain_unverified_candidate_v1(&directory, &oversized).is_err());
    fs::write(&path, vec![0; proof.len()]).unwrap();
    assert!(retain_unverified_candidate_v1(&directory, proof).is_err());
    fs::remove_dir_all(directory).unwrap();
}

/// Read a retained public candidate under the unchanged cap and exact digest name.
fn read_unverified_candidate_v1(path: &Path) -> io::Result<Vec<u8>> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid retained public candidate",
        )
    };
    let cap = u64::from(super::super::profile::ZK_X509_MAX_PROOF_BYTES_V1);
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute() || !metadata.is_file() || metadata.len() == 0 || metadata.len() > cap {
        return Err(invalid());
    }
    let mut proof = Vec::new();
    fs::File::open(path)?
        .take(cap + 1)
        .read_to_end(&mut proof)?;
    if proof.is_empty() || proof.len() as u64 > cap || proof.len() as u64 != metadata.len() {
        return Err(invalid());
    }
    let name = format!("unverified-{}.x5s1", hex::encode(Sha256::digest(&proof)));
    if path.file_name().and_then(|name| name.to_str()) != Some(name.as_str()) {
        return Err(invalid());
    }
    Ok(proof)
}

#[test]
fn retained_candidate_reader_rejects_wrong_names_bounds_and_symlinks() {
    let directory = run_directory_v1(&std::env::temp_dir()).unwrap();
    let proof = b"public retained replay fixture";
    let path = retain_unverified_candidate_v1(&directory, proof).unwrap();
    assert_eq!(read_unverified_candidate_v1(&path).unwrap(), proof);
    let wrong = directory.join("wrong.x5s1");
    fs::write(&wrong, proof).unwrap();
    assert!(read_unverified_candidate_v1(&wrong).is_err());
    fs::write(&path, b"changed").unwrap();
    assert!(read_unverified_candidate_v1(&path).is_err());
    fs::write(&path, b"").unwrap();
    assert!(read_unverified_candidate_v1(&path).is_err());
    fs::File::create(&path)
        .unwrap()
        .set_len(u64::from(super::super::profile::ZK_X509_MAX_PROOF_BYTES_V1) + 1)
        .unwrap();
    assert!(read_unverified_candidate_v1(&path).is_err());
    fs::remove_file(&path).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&wrong, &path).unwrap();
        assert!(read_unverified_candidate_v1(&path).is_err());
    }
    fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "verifier-only replay of an explicitly selected unverified public maximum-fixture candidate"]
fn retained_public_maximum_candidate_replays_without_prover() {
    retained_public_candidate_replays_without_prover_v1(true);
}

#[test]
#[ignore = "verifier-only replay of an explicitly selected unverified public ordinary depth-two fixture candidate"]
fn retained_public_ordinary_candidate_replays_without_prover() {
    retained_public_candidate_replays_without_prover_v1(false);
}

fn retained_public_candidate_replays_without_prover_v1(maximum_shape: bool) {
    use super::super::relation::release_fixture::{
        build_zk_x509_release_fixture_v1, reference_statement_context_v1,
    };
    let candidate = PathBuf::from(
        std::env::var_os("IROHA_X509_PUBLIC_CANDIDATE")
            .expect("explicit retained public candidate path"),
    );
    let proof =
        read_unverified_candidate_v1(&candidate).expect("bounded digest-bound public candidate");
    let fixture = build_zk_x509_release_fixture_v1(reference_statement_context_v1(), maximum_shape)
        .expect(if maximum_shape {
            "same deterministic maximum public fixture"
        } else {
            "same deterministic ordinary depth-two public fixture"
        });
    let genesis = *fixture.statement.context.network_id.as_bytes();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("privacy crate is under the repository crates directory");
    let directory = run_directory_v1(&repository.join("dist/zk-x509-prover-evidence"))
        .expect("persistent public diagnostic output directory");
    record_public_diagnostic_v1(&directory, &format!(
        "output_directory={}\nreplay_source_candidate={}\ncandidate_status=unverified\ncandidate_sha256={}\ncandidate_bytes={}\nactivation=unavailable\nfull_release_qualification=false\nprivate_witness_recorded=false\nproof_regenerated=false",
        directory.display(), candidate.display(), hex::encode(Sha256::digest(&proof)), proof.len(),
    )).unwrap();
    record_public_diagnostic_v1(
        &directory,
        &format!(
            "fixture_kind={}\ncertificate_chain_depth={}",
            if maximum_shape {
                "maximum-depth-three"
            } else {
                "ordinary-depth-two"
            },
            fixture.resource_shape.certificate_chain_depth,
        ),
    )
    .unwrap();
    let public_capture = PublicFixtureDiagnosticGuardV1::begin_v1(&directory);
    let start = Instant::now();
    let result = verify_zk_x509_credential_proof_v1(
        &fixture.statement,
        &fixture.authoritative_state,
        genesis,
        &proof,
    );
    drop(public_capture);
    record_public_diagnostic_v1(&directory, &format!(
        "retained_public_candidate_replay={result:?}\nreplay_seconds={:.6}\nfull_release_qualification=false", start.elapsed().as_secs_f64(),
    )).unwrap();
    result.expect(if maximum_shape {
        "retained public maximum candidate must pass the unchanged verifier"
    } else {
        "retained public ordinary candidate must pass the unchanged verifier"
    });
}

#[test]
fn public_verifier_diagnostic_preserves_real_decode_failure() {
    use super::super::relation::release_fixture::{
        build_zk_x509_release_fixture_v1, reference_statement_context_v1,
    };
    let fixture =
        build_zk_x509_release_fixture_v1(reference_statement_context_v1(), false).unwrap();
    let genesis = *fixture.statement.context.network_id.as_bytes();
    let directory = run_directory_v1(&std::env::temp_dir()).unwrap();
    let verify = || {
        verify_zk_x509_credential_proof_v1(
            &fixture.statement,
            &fixture.authoritative_state,
            genesis,
            b"malformed public fixture",
        )
    };
    let unscoped = verify();
    assert!(unscoped.is_err());
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
    let guard = PublicFixtureDiagnosticGuardV1::begin_v1(&directory);
    let scoped = verify();
    drop(guard);
    assert_eq!(scoped, unscoped);
    let receipt = fs::read_to_string(directory.join("receipt.txt")).unwrap();
    assert!(receipt.contains("public_verifier_stage=credential-envelope-decode"));
    assert!(receipt.contains("public_verifier_error="));
    assert!(!receipt.contains("candidate_status="));
    assert_eq!(verify(), unscoped);
    assert_eq!(
        fs::read_to_string(directory.join("receipt.txt")).unwrap(),
        receipt
    );
    fs::remove_dir_all(directory).unwrap();
}

fn retain_public_proof_v1(directory: &Path, proof: &[u8]) -> io::Result<PathBuf> {
    let digest = hex::encode(Sha256::digest(proof));
    let path = directory.join(format!("{digest}.x5s1"));
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(proof)?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if fs::read(&path)? != proof {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "existing proof artifact does not match its content digest",
                ));
            }
        }
        Err(error) => return Err(error),
    }
    Ok(path)
}

fn append_receipt_v1(path: &Path, public_record: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{public_record}")?;
    file.sync_all()
}

fn run_directory_v1(parent: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(parent)?;
    let tick = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let directory = parent.join(format!(
        "iroha-x509-full-credential-{}-{tick}",
        std::process::id(),
    ));
    fs::create_dir(&directory)?;
    Ok(directory)
}

// Only the ignored complete-proof process uses this global hook. The hook
// covers Rayon worker assertions too; its failure outcome never forwards an
// internal payload to libtest or the retained public receipt.
fn catch_private_prover_panic_v1<T>(operation: impl FnOnce() -> T) -> Result<T, ()> {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {
        let _ = writeln!(io::stderr().lock(), "X509 prover panicked; payload omitted");
    }));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
    std::panic::set_hook(previous);
    result.map_err(|payload| {
        // Formatted assertions normally own a String. Other panic payloads are
        // not formatted, inspected, or propagated beyond this diagnostic.
        if let Ok(mut text) = payload.downcast::<String>() {
            zeroize::Zeroize::zeroize(&mut *text);
        }
    })
}

#[test]
fn private_prover_panic_is_redacted_in_its_isolated_process() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "privacy_engines::zk_x509::engine::prover_diagnostic::private_prover_panic_hook_subprocess",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(combined.contains("1 passed"));
    assert!(!combined.contains("SYNTHETIC_PRIVATE_PANIC_4e9314"));
    assert!(combined.contains("X509 prover panicked; payload omitted"));
    assert!(combined.contains("PUBLIC_RESTORED_PANIC_HOOK"));
}

#[test]
#[ignore = "isolated process helper for private-prover panic-hook coverage"]
fn private_prover_panic_hook_subprocess() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    assert!(
        catch_private_prover_panic_v1(|| {
            pool.install(|| panic!("{}", "SYNTHETIC_PRIVATE_PANIC_4e9314"));
        })
        .is_err()
    );
    assert!(std::panic::catch_unwind(|| panic!("PUBLIC_RESTORED_PANIC_HOOK")).is_err());
}

#[test]
fn public_proof_receipt_preserves_exact_bytes_and_rejects_existing_mismatch() {
    let directory = run_directory_v1(&std::env::temp_dir()).unwrap();
    let proof = b"public fixture for artifact-owner validation";
    let path = retain_public_proof_v1(&directory, proof).unwrap();
    assert_eq!(fs::read(&path).unwrap(), proof);
    assert_eq!(retain_public_proof_v1(&directory, proof).unwrap(), path);
    fs::write(&path, b"changed").unwrap();
    assert_eq!(
        retain_public_proof_v1(&directory, proof)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData,
    );
    let receipt = directory.join("receipt.txt");
    append_receipt_v1(&receipt, "producer=error").unwrap();
    append_receipt_v1(&receipt, "private_witness_recorded=false").unwrap();
    assert_eq!(
        fs::read_to_string(&receipt).unwrap(),
        "producer=error\nprivate_witness_recorded=false\n",
    );
    fs::remove_file(path).unwrap();
    fs::remove_file(receipt).unwrap();
    fs::remove_dir(directory).unwrap();
}

#[test]
#[ignore = "complete maximum-structural MAIN+CA credential proof; optimized build and external RSS measurement required"]
fn maximum_structural_credential_proof_with_retained_public_receipt() {
    complete_credential_proof_with_retained_public_receipt_v1(true);
}

#[test]
#[ignore = "complete ordinary depth-two MAIN+CA credential proof; optimized build and external RSS measurement required"]
fn ordinary_depth_two_credential_proof_with_retained_public_receipt() {
    complete_credential_proof_with_retained_public_receipt_v1(false);
}

fn complete_credential_proof_with_retained_public_receipt_v1(maximum_shape: bool) {
    use super::super::{
        profile::{
            ZK_X509_MAX_PROOF_BYTES_V1, ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1,
            ZK_X509_PROVER_ADDRESS_SPACE_CEILING_BYTES_V1, ZK_X509_PROVER_PEAK_MEMORY_BYTES_V1,
            ZK_X509_PROVER_TARGET_SECONDS_V1,
        },
        relation::release_fixture::{
            build_zk_x509_release_fixture_v1, reference_statement_context_v1,
        },
    };

    crate::test_support::require_no_debug_assertions("run this full proof with --release");
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("Core crate is under the repository crates directory");
    // Keep actual proof evidence in the ignored repository output directory:
    // temporary-directory cleanup must not discard an expensive proof receipt.
    let directory = run_directory_v1(&repository.join("dist/zk-x509-prover-evidence"))
        .expect("persistent public diagnostic output directory");
    let receipt = directory.join("receipt.txt");
    let record = |text: String| {
        eprintln!("{text}");
        append_receipt_v1(&receipt, &text).expect("durable public diagnostic receipt");
    };
    record(format!("rayon_workers={}", rayon::current_num_threads()));
    record(format!(
        "output_directory={}\nprofile=complete49-MAIN-plus-compactCA\nproof_cap_bytes={ZK_X509_MAX_PROOF_BYTES_V1}\nencoded_geometry_bound_bytes={ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1}\nprover_target_seconds={ZK_X509_PROVER_TARGET_SECONDS_V1}\npeak_rss_limit_bytes={ZK_X509_PROVER_PEAK_MEMORY_BYTES_V1}\naddress_space_limit_bytes={ZK_X509_PROVER_ADDRESS_SPACE_CEILING_BYTES_V1}\nrss_evidence=external-time-l-required\nactivation=unavailable\nprivate_witness_recorded=false",
        directory.display(),
    ));
    let fixture = build_zk_x509_release_fixture_v1(reference_statement_context_v1(), maximum_shape)
        .expect(if maximum_shape {
            "maximum structural release fixture"
        } else {
            "ordinary depth-two release fixture"
        });
    fixture.resource_shape.validate_v1().unwrap();
    if maximum_shape {
        assert_eq!(fixture.resource_shape.certificate_chain_depth, 3);
        assert_eq!(fixture.statement.disclosed_attributes.len(), 4);
        assert_eq!(fixture.crl_entry_count, 64);
        assert_eq!(fixture.resource_shape.maximum_serial_bytes, 20);
    } else {
        assert_eq!(fixture.resource_shape.certificate_chain_depth, 2);
        assert_eq!(fixture.statement.disclosed_attributes.len(), 1);
        assert_eq!(fixture.crl_entry_count, 0);
        assert_eq!(fixture.resource_shape.maximum_serial_bytes, 1);
        // Inspect the actual normalized document census. Depth two includes a
        // dummy top-level slot; raw certificate slots are not document ordinals.
        // This preflight owner drops before the measured genuine proof begins.
        let trust_anchor = fixture.authoritative_state.trust_anchor();
        let crl = fixture.authoritative_state.crl_record();
        let assembly = super::super::main_assembly::build_zk_x509_main_trace_assembly_v1(
            &fixture.statement,
            super::super::relation::ZkX509GovernanceV1 {
                trust_anchor: &trust_anchor,
                certificate_policy: fixture.authoritative_state.certificate_policy(),
                crl: &crl,
            },
            &fixture.witness,
        )
        .expect("ordinary admitted complete MAIN assembly");
        let shape = &assembly.rfc_base.private_shape;
        assert_eq!(shape.chain_depth, 2);
        assert_eq!(shape.top_document_count, 3);
        assert_eq!(shape.embedded_document_count, 11);
        let source_documents =
            usize::from(shape.top_document_count) + usize::from(shape.embedded_document_count);
        let source_document_capacity = super::super::der_air::ZK_X509_DER_AIR_MAX_DOCUMENTS_V1
            + super::super::der_air::ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1;
        assert_eq!(source_documents, 14);
        assert_eq!(source_document_capacity, 19);
        assert_eq!(source_document_capacity - source_documents, 5);
        record(format!(
            "rfc_top_documents={}\nrfc_embedded_documents={}\nrfc_source_documents={source_documents}\nrfc_source_document_capacity={source_document_capacity}\nrfc_inactive_source_documents={}",
            shape.top_document_count,
            shape.embedded_document_count,
            source_document_capacity - source_documents,
        ));
    }
    record(format!(
        "fixture_kind={}\ncertificate_chain_depth={}",
        if maximum_shape {
            "maximum-depth-three"
        } else {
            "ordinary-depth-two"
        },
        fixture.resource_shape.certificate_chain_depth,
    ));
    record(format!("structural_shape={:?}", fixture.resource_shape));
    let witness = zeroize::Zeroizing::new(fixture.witness.encode_v1().unwrap());
    let genesis = *fixture.statement.context.network_id.as_bytes();
    let (measurement_context, harness_directory) = harness_context_v1();
    // The observation's session writes the record into the harness directory
    // itself, so a producer that fails, returns early or unwinds is retained.
    let observation = super::super::prover_observation::ObservationV1::begin_with_harness_v1(
        measurement_context,
        harness_directory,
    );
    let start = Instant::now();
    let public_capture = PublicFixtureDiagnosticGuardV1::begin_v1(&directory);
    let produced = catch_private_prover_panic_v1(|| {
        prove_zk_x509_credential_proof_v1_with_rng(
            &fixture.statement,
            &fixture.authoritative_state,
            fixture.statement.presentation_not_before_unix_seconds * 1_000,
            &PrivacyConsensusLimitsV1::taira_default(),
            genesis,
            &witness,
            &mut rand::rngs::OsRng,
        )
    });
    drop(public_capture);
    let prove_elapsed = start.elapsed();
    // A failed producer is retained in the shared record as a raw failure;
    // only these two literals are recorded, never the error payload.
    match &produced {
        Ok(Ok(proof)) => observation.record_proof_bytes_v1(proof.len() as u64),
        Ok(Err(_)) => observation.record_failure_v1("producer", "error"),
        Err(()) => observation.record_failure_v1("producer", "unwind"),
    }
    let observation = observation.finish_v1();
    record(observation.public_text_v1());
    // TODO: X.3 owns the complete X509 run under scripts/zk_resource_harness.py
    // and the phases that close the remaining attribution gap. The last
    // retained maximum receipt left about 4.45% of the proving time outside
    // every top-level phase, so this record is expected to report
    // `phase_tree_within_one_percent=false` until those phases exist.
    record(
        retain_phase_tree_v1(
            &directory,
            observation.harness_v1(),
            observation
                .measurement_v1()
                .expect("shared phase-tree record of this observation"),
        )
        .expect("durable public phase-tree record"),
    );
    let proof = match produced {
        Ok(Ok(proof)) => proof,
        Ok(Err(error)) => {
            record(format!(
                "producer=error\nproving_seconds={:.6}\nerror={error:?}",
                prove_elapsed.as_secs_f64(),
            ));
            panic!(
                "full credential producer failed; public receipt at {}",
                receipt.display()
            );
        }
        Err(()) => {
            // Preserve only the public outcome, including on stderr.
            record(format!(
                "producer=unwind\nproving_seconds={:.6}",
                prove_elapsed.as_secs_f64(),
            ));
            panic!(
                "full credential producer panicked; public receipt at {}",
                receipt.display()
            );
        }
    };
    let proof_path = retain_public_proof_v1(&directory, &proof).expect("public proof artifact");
    record(format!(
        "producer=success\nproof_path={}\nproof_bytes={}\nproof_sha256={}\nproving_seconds={:.6}\nproducer_self_check=passed",
        proof_path.display(),
        proof.len(),
        hex::encode(Sha256::digest(&proof)),
        prove_elapsed.as_secs_f64(),
    ));
    let replay_start = Instant::now();
    let replay = verify_zk_x509_credential_proof_v1(
        &fixture.statement,
        &fixture.authoritative_state,
        genesis,
        &proof,
    );
    record(format!(
        "independent_replay={replay:?}\nindependent_replay_seconds={:.6}",
        replay_start.elapsed().as_secs_f64(),
    ));
    replay.expect("independent complete credential verification");
    let mut wrong_genesis = genesis;
    wrong_genesis[0] ^= 1;
    assert!(
        verify_zk_x509_credential_proof_v1(
            &fixture.statement,
            &fixture.authoritative_state,
            wrong_genesis,
            &proof,
        )
        .is_err()
    );
    // X5S1 fixes the public instance nonce immediately after its eight-byte prefix.
    // Reuse one completed proof and independently change each nonce byte; framing
    // alone accepts these substitutions, so the complete verifier must reject them.
    let mut nonce_tampered = proof.clone();
    for nonce_byte in 0..32 {
        let offset = 8 + nonce_byte;
        nonce_tampered[offset] ^= 1;
        assert!(
            verify_zk_x509_credential_proof_v1(
                &fixture.statement,
                &fixture.authoritative_state,
                genesis,
                &nonce_tampered,
            )
            .is_err(),
            "substituted proof-instance nonce byte {nonce_byte} must be rejected",
        );
        nonce_tampered[offset] ^= 1;
    }
    let mut tampered = proof.clone();
    *tampered.last_mut().expect("nonempty credential proof") ^= 1;
    assert!(
        verify_zk_x509_credential_proof_v1(
            &fixture.statement,
            &fixture.authoritative_state,
            genesis,
            &tampered,
        )
        .is_err()
    );
    record(format!(
        "wrong_genesis_rejected=true\nnonce_byte_mutations_rejected=32\ntampered_proof_rejected=true\ntime_target_met={}\nfull_release_qualification=false",
        prove_elapsed.as_secs_f64() <= ZK_X509_PROVER_TARGET_SECONDS_V1 as f64,
    ));
    observation.assert_complete_main_coverage_v1(
        super::super::stark::main_diagnostic_transform_columns_v1().unwrap(),
    );
    assert!(proof.len() <= ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1 as usize);
    assert!(proof.len() <= ZK_X509_MAX_PROOF_BYTES_V1 as usize);
    assert!(
        prove_elapsed.as_secs_f64() <= ZK_X509_PROVER_TARGET_SECONDS_V1 as f64,
        "complete proof exceeds unchanged proving target; verified public proof and receipt retained at {}",
        directory.display(),
    );
}

#[test]
fn canonical_witness_round_trip_clears_its_owned_bytes_on_match_and_mismatch() {
    use super::super::private_table::inspection::observe_v1;
    let fixture = super::super::relation::tests::fixture();
    let encoded = zeroize::Zeroizing::new(fixture.witness.encode_v1().unwrap());
    for mismatch in [false, true] {
        let mut supplied = encoded.clone();
        if mismatch {
            supplied[0] ^= 1;
        }
        let (result, observations) =
            observe_v1(|| validate_witness_round_trip_v1(&fixture.witness, &supplied));
        assert_eq!(result.is_err(), mismatch);
        assert!(observations.iter().any(|row| {
            row.cells == encoded.len() && row.nonzero_before > 0 && row.nonzero_after == 0
        }));
        assert!(observations.iter().all(|row| row.nonzero_after == 0));
        assert_eq!(supplied[0], encoded[0] ^ u8::from(mismatch));
    }
}
