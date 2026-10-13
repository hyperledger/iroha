//! Real one-child public producers and reusable verification controls.
//!
//! One occurrence still uses the complete ordinary or AXT bundle relation.
//! These tests do not replace the separate two-child ordering/root-chain tests.

use super::effect_fixture::EffectFixture;
use super::*;
use fastpq_prover::offline_compact::{VerifiedArtifact, execution_effect_profile_id};

fn verify_effect_public(
    fixture: &EffectFixture,
    bytes: &[u8],
    public: ExpectedStatement,
    limits: &VerificationLimits,
) -> Verified {
    let mut expected = fixture.expected();
    expected.statement.public_inputs = public.inputs;
    expected.statement.statement_digest = Hash::from_marked_bytes(public.public_statement_digest)
        .expect("test expected digest retains the canonical marker");
    // Ordering is committed by the complete independently expected statement
    // digest. Its offered-byte mutation is exercised separately below; the new
    // API does not pretend to accept a second independent ordering expectation.
    fixture.verify_expected(bytes, expected, limits)
}

#[test]
fn independent_capture_counts_preserve_full_quantity_facts() {
    let one = capture::CaptureFixture::with_occurrences(1);
    let two = capture::CaptureFixture::new();
    for (fixture, count) in [(&one, 1), (&two, 2)] {
        assert_eq!(fixture.statement.transcripts.len(), count);
        assert!(
            fixture
                .statement
                .transcripts
                .iter()
                .all(|claim| claim.deltas.len() == 1 && claim.deltas[0].amount == Quantity::one())
        );
        assert_eq!(
            ExpectedStatement::from_statement(&fixture.statement).unwrap(),
            fixture.expected
        );
        let context = fixture.context();
        assert_eq!(context.remote_spend_claims.unwrap().len(), count);
        assert_eq!(context.binding.remote_spend_intent_commitments.len(), count);
        let outer = 5 * u128::try_from(count).unwrap();
        assert_eq!(context.mirrors.committed_amount, Some(outer));
        assert_eq!(context.metadata.committed_amount, Some(outer.to_le_bytes()));
    }
    assert_eq!(one.expected.inputs.old_root, two.expected.inputs.old_root);
    assert_ne!(one.expected.inputs.new_root, two.expected.inputs.new_root);
    assert_ne!(one.expected.ordering_hash, two.expected.ordering_hash);
    assert_ne!(
        one.expected.public_statement_digest,
        two.expected.public_statement_digest
    );
}

fn deep_context_rejected(error: &VerificationError) {
    assert!(
        matches!(error,
            VerificationError::Verify(Error::InvalidTraceShape { details })
            if details == "DEEP out-of-domain AIR quotient identity does not hold"
                || details == "DEEP opening positions differ from the exact derived query set"
        ),
        "coherent public context mutation must reach its DEEP binding check: {error:?}"
    );
}

/// Complete verification outcome of one artifact.
type Verified = Result<VerifiedArtifact, VerificationError>;
/// One exact verifier route, fixed by the caller to ordinary or AXT semantics.
type VerifyRoute<'r> = dyn Fn(&[u8], ExpectedStatement, VerificationLimits) -> Verified + 'r;

/// Tight inclusive limits accept the same bytes; each one-unit deficit
/// independently rejects, without spending entropy on another proof.
fn assert_inclusive_limits(
    verify: &VerifyRoute<'_>,
    bytes: &[u8],
    expected: ExpectedStatement,
    limits: &VerificationLimits,
    accepted: &VerifiedArtifact,
    frame_len: usize,
    maximum_child_bytes: usize,
) {
    let count = accepted.segments();
    let mut exact = *limits;
    exact.transport.max_wire_bytes = bytes.len();
    exact.transport.max_bundle_frame_bytes = frame_len;
    exact.bundle.max_wire_bytes = frame_len;
    exact.bundle.max_segments = count;
    exact.bundle.max_total_queries = 77 * count;
    exact.bundle.max_total_statement_bytes = accepted.statement_bytes();
    exact.bundle.max_total_segment_bytes = accepted.work().proof_bytes;
    exact.bundle.segment.max_proof_bytes = maximum_child_bytes;
    assert_eq!(verify(bytes, expected, exact).unwrap(), *accepted);
    for boundary in 0..9 {
        let mut low = *limits;
        match boundary {
            0 => low.transport.max_wire_bytes = bytes.len() - 1,
            1 => low.transport.max_bundle_frame_bytes = frame_len - 1,
            2 => low.bundle.max_wire_bytes = frame_len - 1,
            3 => low.bundle.max_segments = count - 1,
            4 => low.bundle.max_total_queries = 77 * count - 1,
            5 => low.bundle.max_total_statement_bytes = accepted.statement_bytes() - 1,
            6 => low.bundle.max_total_segment_bytes = accepted.work().proof_bytes - 1,
            7 => low.bundle.segment.max_proof_bytes = maximum_child_bytes - 1,
            8 => low.max_segment_decode_allocation_charges = 0,
            _ => unreachable!(),
        }
        assert!(
            verify(bytes, expected, low).is_err(),
            "inclusive boundary {boundary}"
        );
    }
    let strict = DecodeLimits::new(20 << 20, 20 << 20, 30 << 20, 0, 32);
    assert!(
        norito::core::with_decode_limits_scope(strict, || verify(bytes, expected, *limits))
            .is_err()
    );
}

/// Every changed independent public fact and damaged byte string rejects.
/// Ordinary ordering is bound by the independently expected full statement digest.
fn assert_changed_expectations_rejected(
    verify: &VerifyRoute<'_>,
    bytes: &[u8],
    expected: ExpectedStatement,
    limits: &VerificationLimits,
    is_axt: bool,
) {
    for field in 0..8 {
        if field == 6 && !is_axt {
            let mut changed = FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
                bytes,
                execution_effect_profile_id(),
                limits.transport,
            )
            .unwrap();
            changed.statement.ordering_hash[0] ^= 1;
            assert!(matches!(
                verify(
                    &norito::encode_canonical(&changed).unwrap(),
                    expected,
                    *limits
                ),
                Err(VerificationError::Verify(Error::PublicIoMismatch { .. }))
            ));
            continue;
        }
        let mut wrong = expected;
        match field {
            0 => wrong.inputs.dsid[0] ^= 1,
            1 => wrong.inputs.slot ^= 1,
            2 => wrong.inputs.old_root[0] ^= 1,
            3 => wrong.inputs.new_root[0] ^= 1,
            4 => wrong.inputs.perm_root[0] ^= 1,
            5 => wrong.inputs.tx_set_hash[0] ^= 1,
            6 => wrong.ordering_hash[0] ^= 1,
            _ => wrong.public_statement_digest[0] ^= 1,
        }
        if !is_axt && field < 6 {
            assert!(matches!(
                verify(bytes, wrong, *limits),
                Err(VerificationError::Verify(Error::TransferInvariant { details }))
                    if details == "execution effect independent statement expectation mismatch"
            ));
            continue;
        }
        assert!(matches!(
            verify(bytes, wrong, *limits),
            Err(VerificationError::Verify(Error::PublicIoMismatch { .. }))
        ));
    }
    assert!(verify(&[], expected, *limits).is_err());
    assert!(verify(&bytes[..bytes.len() - 1], expected, *limits).is_err());
    let mut malformed = bytes.to_vec();
    *malformed.last_mut().unwrap() ^= 1;
    assert!(verify(&malformed, expected, *limits).is_err());
}

/// Keep the same child and a valid canonical transport while changing both
/// the independently known statement and its advertised copy. This must fail
/// the mathematical transcript binding, not an outer checksum/equality check.
fn assert_changed_statement_rejected(
    verify: &VerifyRoute<'_>,
    bytes: &[u8],
    is_axt: bool,
    fixture: &capture::CaptureFixture,
    limits: &VerificationLimits,
) {
    if is_axt {
        let mut changed_statement = fixture.statement.clone();
        changed_statement.public_inputs.perm_root[0] ^= 1;
        let changed_expected = ExpectedStatement::from_statement(&changed_statement).unwrap();
        let mut artifact = FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
            bytes,
            quantity_profile_id(),
            limits.transport,
        )
        .unwrap();
        artifact.statement = changed_statement;
        let changed_bytes = norito::encode_canonical(&artifact).unwrap();
        deep_context_rejected(&verify(&changed_bytes, changed_expected, *limits).unwrap_err());
    } else {
        let mut changed = EffectFixture::from_transfer_facts(&fixture.statement);
        changed.statement.public_inputs.perm_root[0] ^= 1;
        changed.source.perm_root = changed.statement.public_inputs.perm_root;
        let mut artifact = FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
            bytes,
            execution_effect_profile_id(),
            limits.transport,
        )
        .unwrap();
        artifact.source = changed.source;
        artifact.statement = changed.statement.clone();
        let changed_bytes = norito::encode_canonical(&artifact).unwrap();
        // Full source and statement mirrors plus independently recomputed digest
        // agree, leaving the genuine original child's context/DEEP binding to reject.
        deep_context_rejected(&changed.verify(&changed_bytes, limits).unwrap_err());
    }
}

/// Changed AXT expectations reject, and the ordinary route cannot bypass them.
fn assert_axt_context_changes_rejected(
    bytes: &[u8],
    expected: ExpectedStatement,
    context: ExpectedAxtContext<'_>,
    limits: &VerificationLimits,
    effect: &EffectFixture,
) {
    let limits = *limits;
    let mut wrong = context;
    wrong.mirrors.expiry_slot = Some(457);
    assert!(matches!(
        verify_quantity_axt_artifact(bytes, expected, wrong, limits),
        Err(VerificationError::Verify(Error::PublicIoMismatch { .. }))
    ));
    let mut wrong = context;
    wrong.remote_spend_claims = None;
    assert!(matches!(
        verify_quantity_axt_artifact(bytes, expected, wrong, limits),
        Err(VerificationError::Verify(Error::PublicIoMismatch { .. }))
    ));

    let mut binding = context.binding.clone();
    binding.corridor = "changed-corridor".into();
    let mut artifact = FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
        bytes,
        quantity_profile_id(),
        limits.transport,
    )
    .unwrap();
    artifact.binding = binding.clone();
    let changed = norito::encode_canonical(&artifact).unwrap();
    deep_context_rejected(
        &verify_quantity_axt_artifact(
            &changed,
            expected,
            ExpectedAxtContext {
                binding: &binding,
                ..context
            },
            limits,
        )
        .unwrap_err(),
    );

    let mut metadata = context.metadata.clone();
    metadata.expiry_slot = 457_u64.to_le_bytes();
    let mut mirrors = context.mirrors;
    mirrors.expiry_slot = Some(457);
    let mut artifact = FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
        bytes,
        quantity_profile_id(),
        limits.transport,
    )
    .unwrap();
    artifact.metadata = metadata.clone();
    artifact.mirrors = mirrors;
    let changed = norito::encode_canonical(&artifact).unwrap();
    deep_context_rejected(
        &verify_quantity_axt_artifact(
            &changed,
            expected,
            ExpectedAxtContext {
                metadata: &metadata,
                mirrors,
                ..context
            },
            limits,
        )
        .unwrap_err(),
    );
    assert!(effect.verify(bytes, &limits).is_err());
}

pub fn verify_count(
    bytes: &[u8],
    is_axt: bool,
    fixture: &capture::CaptureFixture,
    count: usize,
    maximum_child_bytes: Option<usize>,
) -> fastpq_prover::offline_compact::VerifiedArtifact {
    assert_eq!(fixture.statement.transcripts.len(), count);
    let effect = EffectFixture::from_transfer_facts(&fixture.statement);
    let expected = if is_axt {
        fixture.expected
    } else {
        effect.public_expectation()
    };
    let context = fixture.context();
    let limits = VerificationLimits::default();
    let verify = |bytes: &[u8], expected, limits| {
        if is_axt {
            verify_quantity_axt_artifact(bytes, expected, context, limits)
        } else {
            verify_effect_public(&effect, bytes, expected, &limits)
        }
    };
    let accepted = verify(bytes, expected, limits).unwrap();
    assert_eq!(accepted.expected_statement(), expected);
    assert_eq!(accepted.segments(), count);
    assert_eq!(accepted.air_row_roots().len(), count);
    assert_eq!(accepted.work().transcripts, count);
    assert_eq!(accepted.work().air_evaluations, count);
    assert_eq!(accepted.work().terminal_degree_checks, count);
    assert_eq!(accepted.work().row_leaves, 77 * count);
    assert_eq!(accepted.work().oracle_leaves, 77 * count);
    assert!(accepted.work().proof_bytes <= count * 512 * 1024);
    let maximum_child_bytes = maximum_child_bytes.unwrap_or_else(|| accepted.work().proof_bytes);
    assert!(maximum_child_bytes <= limits.bundle.segment.max_proof_bytes);
    assert_eq!(
        accepted.identity().profile_id,
        if is_axt {
            quantity_profile_id()
        } else {
            execution_effect_profile_id()
        }
    );
    assert_eq!(
        accepted.identity().artifact_bytes,
        u64::try_from(bytes.len()).unwrap()
    );
    assert_eq!(
        accepted.identity().artifact_digest,
        <[u8; 32]>::from(Hash::new(bytes))
    );
    let frame = if is_axt {
        let artifact = FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
            bytes,
            quantity_profile_id(),
            limits.transport,
        )
        .unwrap();
        assert_eq!(artifact.statement, fixture.statement);
        assert_eq!(artifact.binding, *context.binding);
        assert_eq!(artifact.metadata, *context.metadata);
        artifact.bundle_frame
    } else {
        let artifact = FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
            bytes,
            execution_effect_profile_id(),
            limits.transport,
        )
        .unwrap();
        assert_eq!(artifact.statement, effect.statement);
        assert_eq!(artifact.source, effect.source);
        artifact.bundle_frame
    };
    assert_eq!(accepted.bundle_frame_bytes(), frame.len());
    assert_eq!(
        accepted.identity().inner_bundle_digest,
        <[u8; 32]>::from(Hash::new(&frame))
    );

    assert_inclusive_limits(
        &verify,
        bytes,
        expected,
        &limits,
        &accepted,
        frame.len(),
        maximum_child_bytes,
    );
    assert_changed_expectations_rejected(&verify, bytes, expected, &limits, is_axt);
    assert_changed_statement_rejected(&verify, bytes, is_axt, fixture, &limits);
    if is_axt {
        assert_axt_context_changes_rejected(bytes, expected, context, &limits, &effect);
    } else {
        assert!(verify_quantity_axt_artifact(bytes, expected, context, limits).is_err());
    }
    accepted
}

fn verify_one(
    bytes: &[u8],
    is_axt: bool,
    fixture: &capture::CaptureFixture,
) -> fastpq_prover::offline_compact::VerifiedArtifact {
    verify_count(bytes, is_axt, fixture, 1, None)
}

#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
fn produce_one(is_axt: bool) {
    use fastpq_prover::{Digest384GpuBackendV1, DigestExecutionV1};
    use sha2::{Digest as _, Sha256};
    use std::io::Write;

    // Required-device availability is checked even before fixture touched-tree
    // construction; the actual public producer performs its own preflight too.
    fastpq_prover::preflight_digest384_continuation_v1(Digest384GpuBackendV1::Metal).unwrap();
    let fixture = capture::CaptureFixture::with_occurrences(1);
    let proving = ProvingLimits {
        digest_execution: DigestExecutionV1::Device(Digest384GpuBackendV1::Metal),
        ..ProvingLimits::default()
    };
    assert_eq!(proving.max_segment_charge_bytes, 2 * 1024 * 1024 * 1024);
    assert_eq!(proving.max_segment_work_units, 1_usize << 42);
    let limits = VerificationLimits::default();
    let label = if is_axt { "axt-one" } else { "ordinary-one" };
    eprintln!(
        "single_public_producer={label}; required_device=Metal; default_payload_cap={}; default_work_cap={}",
        proving.max_segment_charge_bytes, proving.max_segment_work_units
    );
    let effect = EffectFixture::from_transfer_facts(&fixture.statement);
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
    assert!(bytes.len() <= limits.transport.max_wire_bytes);
    let sha = format!("{:x}", Sha256::digest(&bytes));
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/fastpq-production-validation");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!("quantity-public-producer-deep-{label}-{sha}.bin"));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        Err(error) => panic!("retain one-child public artifact: {error}"),
    }
    eprintln!(
        "single_public_producer={label}; bytes={}; sha256={sha}; proving_including_self_verification={elapsed:?}; retained={}",
        bytes.len(),
        path.display()
    );
    let started = std::time::Instant::now();
    let verified = verify_one(&bytes, is_axt, &fixture);
    eprintln!(
        "single_public_verification={label}; controls={:?}; work={:?}",
        started.elapsed(),
        verified.work()
    );
}

#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
#[test]
#[ignore = "complete one-child ordinary public producer on required Metal, unchanged default bounds"]
fn required_metal_ordinary_producer_and_reused_verifier_controls() {
    produce_one(false);
}

#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
#[test]
#[ignore = "complete one-child AXT public producer on required Metal, unchanged default bounds"]
fn required_metal_axt_producer_and_reused_verifier_controls() {
    produce_one(true);
}

#[test]
#[ignore = "requires FASTPQ_TEST_ORDINARY_SINGLE_ARTIFACT and FASTPQ_TEST_AXT_SINGLE_ARTIFACT"]
fn captured_single_artifacts_verify_without_reproving() {
    // Fixture count and every expectation are fixed before reading either file.
    let fixture = capture::CaptureFixture::with_occurrences(1);
    for (is_axt, variable, label) in [
        (
            false,
            "FASTPQ_TEST_ORDINARY_SINGLE_ARTIFACT",
            "ordinary-one",
        ),
        (true, "FASTPQ_TEST_AXT_SINGLE_ARTIFACT", "axt-one"),
    ] {
        let bytes = capture::read_capture(variable, label);
        verify_one(&bytes, is_axt, &fixture);
    }
}
