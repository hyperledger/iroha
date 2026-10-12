//! Current two-child public producers, durable public evidence and independent replay.
//!
//! The fixed caller facts are selected before artifact access. The normal library
//! supplies every proof and verifier; these tests never call backend diagnostics.

use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest as _, Sha256};

use super::effect_fixture::EffectFixture;
use super::*;
use fastpq_prover::offline_compact::execution_effect_profile_id;

const CHILDREN: usize = 2;

// Test-only canonical carrier views allow adversarial edits of genuine public
// output. They do not select proof geometry or manufacture a successful child.
#[derive(
    Clone, Debug, PartialEq, Eq, NoritoSerialize, norito::NoritoDeserialize, norito::NoritoSchema,
)]
#[norito_schema(
    name = "offline_compact::TwoOrdinaryCarrier",
    frame = "fastpq_prover::compact_v1::ExecutionEffectBundleV1"
)]
struct OrdinaryCarrier {
    version: u16,
    intermediate_roots: Vec<[u8; 32]>,
    segments: Vec<Vec<u8>>,
}

#[derive(
    Clone, Debug, PartialEq, Eq, NoritoSerialize, norito::NoritoDeserialize, norito::NoritoSchema,
)]
#[norito_schema(
    name = "offline_compact::TwoAxtCarrier",
    frame = "fastpq_prover::compact_v1::AxtTransferBundleV1"
)]
struct AxtCarrier {
    version: u16,
    intermediate_roots: Vec<[u8; 32]>,
    segments: Vec<Vec<u8>>,
}

fn carrier_frame(bytes: &[u8], is_axt: bool) -> Vec<u8> {
    let limits = VerificationLimits::default();
    if is_axt {
        FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
            bytes,
            quantity_profile_id(),
            limits.transport,
        )
        .unwrap()
        .bundle_frame
    } else {
        FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
            bytes,
            execution_effect_profile_id(),
            limits.transport,
        )
        .unwrap()
        .bundle_frame
    }
}

fn decode_carrier(frame: &[u8], is_axt: bool) -> OrdinaryCarrier {
    let limits = VerificationLimits::default().transport.norito;
    if is_axt {
        let decoded: AxtCarrier = norito::decode_canonical_with_limits(frame, limits).unwrap();
        assert_eq!(norito::encode_canonical(&decoded).unwrap(), frame);
        OrdinaryCarrier {
            version: decoded.version,
            intermediate_roots: decoded.intermediate_roots,
            segments: decoded.segments,
        }
    } else {
        let decoded: OrdinaryCarrier = norito::decode_canonical_with_limits(frame, limits).unwrap();
        assert_eq!(norito::encode_canonical(&decoded).unwrap(), frame);
        decoded
    }
}

fn encode_carrier(carrier: OrdinaryCarrier, is_axt: bool) -> Vec<u8> {
    if is_axt {
        norito::encode_canonical(&AxtCarrier {
            version: carrier.version,
            intermediate_roots: carrier.intermediate_roots,
            segments: carrier.segments,
        })
        .unwrap()
    } else {
        norito::encode_canonical(&carrier).unwrap()
    }
}

fn replace_carrier(bytes: &[u8], carrier: OrdinaryCarrier, is_axt: bool) -> Vec<u8> {
    let frame = encode_carrier(carrier, is_axt);
    let limits = VerificationLimits::default();
    if is_axt {
        let mut artifact = FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
            bytes,
            quantity_profile_id(),
            limits.transport,
        )
        .unwrap();
        artifact.bundle_frame = frame;
        norito::encode_canonical(&artifact).unwrap()
    } else {
        let mut artifact = FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
            bytes,
            execution_effect_profile_id(),
            limits.transport,
        )
        .unwrap();
        artifact.bundle_frame = frame;
        norito::encode_canonical(&artifact).unwrap()
    }
}

fn verify_two(
    bytes: &[u8],
    is_axt: bool,
    fixture: &capture::CaptureFixture,
) -> fastpq_prover::offline_compact::VerifiedArtifact {
    let frame = carrier_frame(bytes, is_axt);
    let original = decode_carrier(&frame, is_axt);
    assert_eq!(replace_carrier(bytes, original.clone(), is_axt), bytes);
    assert_eq!(original.version, 1);
    assert_eq!(original.segments.len(), CHILDREN);
    assert_eq!(original.intermediate_roots.len(), CHILDREN - 1);
    assert_ne!(original.segments[0], original.segments[1]);
    let maximum_child_bytes = original.segments.iter().map(Vec::len).max().unwrap();
    let limits = VerificationLimits::default();
    assert_eq!(limits.bundle.max_segments, CHILDREN);
    assert_eq!(limits.bundle.max_total_queries, 77 * CHILDREN);
    assert!(
        original
            .segments
            .iter()
            .all(|child| child.len() <= limits.bundle.segment.max_proof_bytes)
    );
    let verified =
        single::verify_count(bytes, is_axt, fixture, CHILDREN, Some(maximum_child_bytes));
    assert_eq!(
        verified.work().proof_bytes,
        original.segments.iter().map(Vec::len).sum::<usize>()
    );
    assert_ne!(verified.air_row_roots()[0], verified.air_row_roots()[1]);
    let effect = EffectFixture::from_transfer_facts(&fixture.statement);
    let verify = |changed: &[u8]| {
        if is_axt {
            verify_quantity_axt_artifact(changed, fixture.expected, fixture.context(), limits)
        } else {
            effect.verify(changed, &limits)
        }
    };
    // Valid canonical envelopes containing genuine children must retain exact
    // occurrence order and the original intermediate touched-tree commitment.
    for mutation in 0..6 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.segments.swap(0, 1),
            1 => {
                let (first, rest) = changed.segments.split_at_mut(1);
                rest[0].clone_from(&first[0]);
            }
            2 => changed.intermediate_roots[0][0] ^= 1,
            3 => {
                changed.segments.pop();
                changed.intermediate_roots.clear();
            }
            4 => changed.intermediate_roots.clear(),
            5 => {
                changed.segments[1].pop();
            }
            _ => unreachable!(),
        }
        let changed = replace_carrier(bytes, changed, is_axt);
        assert!(
            verify(&changed).is_err(),
            "two-child canonical mutation {mutation}"
        );
    }
    verified
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_bounded(path: &Path, cap: usize) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let bound = u64::try_from(cap).map_err(|_| invalid("artifact cap overflow"))?;
    if file.metadata()?.len() > bound {
        return Err(invalid("artifact exceeds read cap"));
    }
    let mut bytes = Vec::new();
    file.take(bound.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(invalid("artifact grew beyond read cap"));
    }
    Ok(bytes)
}

fn write_exact(path: &Path, bytes: &[u8]) -> io::Result<()> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if read_bounded(path, bytes.len())? != bytes {
                return Err(invalid("existing artifact differs"));
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn read_addressed(path: &Path, label: &str, cap: usize) -> io::Result<Vec<u8>> {
    let prefix = format!("quantity-public-{label}-two-");
    let sha = path
        .file_name()
        .and_then(|v| v.to_str())
        .and_then(|v| v.strip_prefix(&prefix))
        .and_then(|v| v.strip_suffix(".bin"))
        .filter(|v| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(|| invalid("artifact must use its canonical SHA-256 name"))?;
    let bytes = read_bounded(path, cap)?;
    if hex::encode(Sha256::digest(&bytes)) != sha {
        return Err(invalid("artifact SHA-256 mismatch"));
    }
    Ok(bytes)
}

fn retain_in(
    directory: &Path,
    label: &str,
    bytes: &[u8],
    public_facts: &str,
    elapsed: f64,
) -> io::Result<(PathBuf, PathBuf)> {
    fs::create_dir_all(directory)?;
    let sha = hex::encode(Sha256::digest(bytes));
    let path = directory.join(format!("quantity-public-{label}-two-{sha}.bin"));
    write_exact(&path, bytes)?;
    let tick = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let receipt = directory.join(format!(
        "quantity-public-{label}-two-{sha}-{}-{tick}.receipt.txt",
        std::process::id()
    ));
    let text = format!(
        "format=fastpq-two-child-public-receipt-v1\nroute={label}\nsegments=2\nartifact_file={}\nartifact_bytes={}\nartifact_sha256={sha}\nartifact_iroha_hash={}\nproving_including_self_verification_seconds={elapsed:.9}\n{public_facts}private_witness_recorded=false\nverification_status=not_yet_checked_by_diagnostic_controls\n",
        path.file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| invalid("artifact name"))?,
        bytes.len(),
        Hash::new(bytes),
    );
    write_exact(&receipt, text.as_bytes())?;
    #[cfg(unix)]
    fs::File::open(directory)?.sync_all()?;
    Ok((path, receipt))
}

fn mark_controls_passed(receipt: &Path, work: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().append(true).open(receipt)?;
    writeln!(file, "diagnostic_controls=passed\nverification_work={work}")?;
    file.sync_all()
}

#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
fn produce_two(is_axt: bool) {
    produce_fixture(
        is_axt,
        if is_axt { "axt" } else { "ordinary" },
        capture::CaptureFixture::new,
        "application_shape=repeated-two-key-continuity\n",
    );
}

/// Run the same normal facade, retention and mutation controls for fixed caller facts.
#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
pub fn produce_fixture(
    is_axt: bool,
    label: &str,
    fixture: impl FnOnce() -> capture::CaptureFixture,
    shape_facts: &str,
) {
    use fastpq_prover::{Digest384GpuBackendV1, DigestExecutionV1};
    fastpq_prover::preflight_digest384_continuation_v1(Digest384GpuBackendV1::Metal).unwrap();
    let fixture = fixture();
    let proving = ProvingLimits {
        digest_execution: DigestExecutionV1::Device(Digest384GpuBackendV1::Metal),
        ..ProvingLimits::default()
    };
    let limits = VerificationLimits::default();
    // All receipt facts come from the independently prepared caller, never from
    // decoding an output proof. The artifact already contains the public context.
    let effect = EffectFixture::from_transfer_facts(&fixture.statement);
    let (statement_frame, statement_digest, source_facts) = if is_axt {
        (
            norito::encode_canonical(&fixture.statement).unwrap(),
            fixture.expected.public_statement_digest,
            String::new(),
        )
    } else {
        (
            norito::encode_canonical(&effect.statement).unwrap(),
            effect.public_expectation().public_statement_digest,
            format!(
                "synthetic_source_leaf_canonical_hex={}\n",
                hex::encode(norito::encode_canonical(&effect.source).unwrap())
            ),
        )
    };
    let public_facts = format!(
        "{shape_facts}{source_facts}required_device=Metal\npublic_statement_canonical_hex={}\nexpected_statement_digest={}\nmaximum_segment_charge_bytes={}\nmaximum_segment_work_units={}\nmaximum_child_frame_bytes={}\nmaximum_artifact_bytes={}\nmaximum_total_queries={}\n",
        hex::encode(statement_frame),
        hex::encode(statement_digest),
        proving.max_segment_charge_bytes,
        proving.max_segment_work_units,
        limits.bundle.segment.max_proof_bytes,
        limits.transport.max_wire_bytes,
        limits.bundle.max_total_queries,
    );
    eprintln!(
        "two_public_producer={label}; required_device=Metal; default_payload_cap={}; default_work_cap={}",
        proving.max_segment_charge_bytes, proving.max_segment_work_units
    );
    let started = std::time::Instant::now();
    let bytes = if is_axt {
        prove_quantity_axt_artifact(
            &fixture.statement,
            fixture.expected,
            fixture.context(),
            proving,
            limits,
        )
    } else {
        effect.prove(proving, &limits)
    }
    .unwrap();
    let elapsed = started.elapsed();
    // Retain every successful producer result before diagnostic cap assertions;
    // filesystem time is excluded from the construction/self-check measurement.
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../dist/fastpq-proof-diagnostics");
    let (path, receipt) = retain_in(
        &directory,
        label,
        &bytes,
        &public_facts,
        elapsed.as_secs_f64(),
    )
    .unwrap();
    eprintln!(
        "two_public_producer={label}; bytes={}; sha256={}; proving_including_self_verification={elapsed:?}; retained={}; public_receipt={}",
        bytes.len(),
        hex::encode(Sha256::digest(&bytes)),
        path.display(),
        receipt.display()
    );
    assert_eq!(proving.max_segment_charge_bytes, 2 * 1024 * 1024 * 1024);
    assert_eq!(proving.max_segment_work_units, 1_usize << 42);
    assert_eq!(limits.transport.max_wire_bytes, 1024 * 1024);
    assert!(limits.bundle.segment.max_proof_bytes <= 512 * 1024);
    assert!(bytes.len() <= limits.transport.max_wire_bytes);
    let started = std::time::Instant::now();
    let verified = verify_two(&bytes, is_axt, &fixture);
    mark_controls_passed(&receipt, &format!("{:?}", verified.work())).unwrap();
    eprintln!(
        "two_public_verification={label}; controls={:?}; work={:?}",
        started.elapsed(),
        verified.work()
    );
}

#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
#[test]
#[ignore = "complete two-child ordinary public producer on required Metal, unchanged default bounds"]
fn required_metal_two_child_ordinary_producer_and_reused_verifier_controls() {
    produce_two(false);
}

#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
#[test]
#[ignore = "complete two-child AXT public producer on required Metal, unchanged default bounds"]
fn required_metal_two_child_axt_producer_and_reused_verifier_controls() {
    produce_two(true);
}

fn replay_two(is_axt: bool) {
    // Select both occurrences and derive every expected value before path access.
    let fixture = capture::CaptureFixture::new();
    let (variable, label) = if is_axt {
        ("FASTPQ_TEST_AXT_TWO_ARTIFACT", "axt")
    } else {
        ("FASTPQ_TEST_ORDINARY_TWO_ARTIFACT", "ordinary")
    };
    replay_fixture(is_axt, label, variable, &fixture);
}

/// Verify retained public bytes using fixture facts selected before artifact access.
pub fn replay_fixture(
    is_axt: bool,
    label: &str,
    variable: &str,
    fixture: &capture::CaptureFixture,
) {
    let path = PathBuf::from(std::env::var_os(variable).expect(variable));
    let bytes = read_addressed(
        &path,
        label,
        VerificationLimits::default().transport.max_wire_bytes,
    )
    .unwrap();
    verify_two(&bytes, is_axt, fixture);
}

#[test]
#[ignore = "requires FASTPQ_TEST_ORDINARY_TWO_ARTIFACT; no witness or prover"]
fn captured_two_child_ordinary_artifact_verifies_without_reproving() {
    replay_two(false);
}

#[test]
#[ignore = "requires FASTPQ_TEST_AXT_TWO_ARTIFACT; no witness or prover"]
fn captured_two_child_axt_artifact_verifies_without_reproving() {
    replay_two(true);
}

#[test]
fn canonical_mutation_views_preserve_bytes_and_distinguish_bundle_schema() {
    let value = OrdinaryCarrier {
        version: 1,
        intermediate_roots: vec![[7; 32]],
        segments: vec![vec![1, 2], vec![3, 4, 5]],
    };
    let mut frames = Vec::new();
    for is_axt in [false, true] {
        let frame = encode_carrier(value.clone(), is_axt);
        assert_eq!(decode_carrier(&frame, is_axt), value);
        assert_eq!(
            encode_carrier(decode_carrier(&frame, is_axt), is_axt),
            frame
        );
        frames.push(frame);
    }
    assert_ne!(frames[0], frames[1]);
    assert!(
        norito::decode_canonical_with_limits::<OrdinaryCarrier>(
            &frames[1],
            VerificationLimits::default().transport.norito
        )
        .is_err()
    );
    assert!(
        norito::decode_canonical_with_limits::<AxtCarrier>(
            &frames[0],
            VerificationLimits::default().transport.norito
        )
        .is_err()
    );
}

#[test]
fn two_child_public_retention_is_exact_bounded_and_refuses_mismatch() {
    let directory = std::env::temp_dir().join(format!(
        "fastpq-two-retention-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let bytes = b"public two-child retention fixture";
    let (path, receipt) =
        retain_in(&directory, "ordinary", bytes, "public_fact=fixture\n", 1.25).unwrap();
    assert_eq!(
        read_addressed(&path, "ordinary", bytes.len()).unwrap(),
        bytes
    );
    assert!(read_addressed(&path, "ordinary", bytes.len() - 1).is_err());
    assert!(read_addressed(&path, "axt", bytes.len()).is_err());
    write_exact(&path, bytes).unwrap();
    mark_controls_passed(&receipt, "public fixture work").unwrap();
    let text = fs::read_to_string(&receipt).unwrap();
    assert!(text.contains("segments=2\n"));
    assert!(text.contains("private_witness_recorded=false\n"));
    assert!(text.ends_with("diagnostic_controls=passed\nverification_work=public fixture work\n"));
    fs::write(&path, b"changed").unwrap();
    assert!(read_addressed(&path, "ordinary", bytes.len()).is_err());
    assert!(write_exact(&path, bytes).is_err());
    fs::remove_file(path).unwrap();
    fs::remove_file(receipt).unwrap();
    fs::remove_dir(directory).unwrap();
}
