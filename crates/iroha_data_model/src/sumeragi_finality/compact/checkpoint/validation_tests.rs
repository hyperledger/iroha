//! Exact operation-local compact checkpoint validation and unchanged decoder refusal.

use super::tests::{authenticated_boundary, certificate, root};
use super::*;
use crate::sumeragi::epoch::validation_counts;
use norito::core::{DecodeAttemptErrorKind, DecodeBudgetContext};

fn read_and_restore(
    bytes: &[u8],
    native: &SumeragiFinalityVerifier,
    mut validation: Option<&mut EpochValidationScope>,
) -> Result<SumeragiCommitCheckpointV1, FinalityReadError> {
    let checkpoint = SumeragiCommitCheckpointV1::decode_canonical_with_validation(
        bytes,
        validation.as_deref_mut(),
    )?;
    SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint_with_validation(
        &checkpoint,
        native,
        validation,
    )?;
    Ok(checkpoint)
}

#[test]
fn compact_operation_scope_reuses_exact_contexts_and_keeps_authority_checks() {
    let (fixture, chain, reader) = authenticated_boundary(4);
    let native = root(&fixture);
    for (epoch, old_calls, new_calls) in [(0, 4, 1), (1, 8, 2)] {
        let checkpoint = reader.export_epoch_checkpoint(epoch).unwrap();
        let bytes = checkpoint.encode_canonical().unwrap();
        let before = validation_counts::calls();
        let original = read_and_restore(&bytes, &native, None).unwrap();
        assert_eq!(validation_counts::calls() - before, old_calls);
        let mut validation = EpochValidationScope::new();
        let before = validation_counts::calls();
        let actual = read_and_restore(&bytes, &native, Some(&mut validation)).unwrap();
        assert_eq!(validation_counts::calls() - before, new_calls);
        assert_eq!(actual, original);
        assert_eq!(actual.encode_canonical().unwrap(), bytes);
        let mut expected =
            SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&original, &native).unwrap();
        let before = validation_counts::calls();
        let mut restored = SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint_with_validation(
            &actual,
            &native,
            Some(&mut validation),
        )
        .unwrap();
        assert_eq!(validation_counts::calls() - before, 0);
        assert_eq!(restored.epochs, expected.epochs);
        if epoch == 1 {
            let expected_core = core_epoch(checkpoint.selected_epoch()).unwrap();
            let before = validation_counts::calls();
            assert_eq!(
                validation.core_epoch(checkpoint.selected_epoch()).unwrap(),
                expected_core
            );
            assert_eq!(validation_counts::calls() - before, 1);
            // Upgrading one entry must preserve the other exact context in the two-slot
            // workspace. Both repeated projection and complete restore remain hits.
            let before = validation_counts::calls();
            assert_eq!(
                validation.core_epoch(checkpoint.selected_epoch()).unwrap(),
                expected_core
            );
            read_and_restore(&bytes, &native, Some(&mut validation)).unwrap();
            assert_eq!(validation_counts::calls() - before, 0);
        }
        let proof = certificate(&fixture, &chain[if epoch == 0 { 1 } else { 3 }]);
        assert_eq!(
            restored.verify(&proof).unwrap().commitment(),
            expected.verify(&proof).unwrap().commitment()
        );
        let mut independent = EpochValidationScope::new();
        let before = validation_counts::calls();
        assert_eq!(
            read_and_restore(&bytes, &native, Some(&mut independent)).unwrap(),
            checkpoint
        );
        assert_eq!(validation_counts::calls() - before, new_calls);
    }
    let mut validation = EpochValidationScope::new();
    let before = validation_counts::calls();
    let initial = SumeragiCommitCheckpointV1::from_authenticated_genesis_with_validation(
        &native,
        Some(&mut validation),
    )
    .unwrap();
    SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint_with_validation(
        &initial,
        &native,
        Some(&mut validation),
    )
    .unwrap();
    assert_eq!(validation_counts::calls() - before, 1);
    assert_eq!(
        initial,
        SumeragiCommitCheckpointV1::from_authenticated_genesis(&native).unwrap()
    );
    // Validation-only insertion does not manufacture a core projection. The original
    // canonical derivation still runs once when another consumer explicitly requests it.
    let expected = core_epoch(initial.selected_epoch()).unwrap();
    let before = validation_counts::calls();
    assert_eq!(
        validation.core_epoch(initial.selected_epoch()).unwrap(),
        expected
    );
    assert_eq!(validation_counts::calls() - before, 1);
    let before = validation_counts::calls();
    assert_eq!(
        validation.core_epoch(initial.selected_epoch()).unwrap(),
        expected
    );
    assert_eq!(validation_counts::calls() - before, 0);
}

#[test]
fn warmed_compact_scope_rejects_changed_contexts_roots_and_relationships_in_order() {
    let (fixture, _, reader) = authenticated_boundary(4);
    let native = root(&fixture);
    let checkpoint = reader.export_epoch_checkpoint(1).unwrap();
    let bytes = checkpoint.encode_canonical().unwrap();
    let mut validation = EpochValidationScope::new();
    read_and_restore(&bytes, &native, Some(&mut validation)).unwrap();
    for mutate in [
        |c: &mut SumeragiCommitCheckpointV1| c.chain.clear(),
        |c: &mut SumeragiCommitCheckpointV1| c.chain = "wrong-chain".into(),
        |c: &mut SumeragiCommitCheckpointV1| c.instance.0[0] ^= 1,
        |c: &mut SumeragiCommitCheckpointV1| c.initial.leader_seed[0] ^= 1,
        |c: &mut SumeragiCommitCheckpointV1| c.selected.version = 2,
        |c: &mut SumeragiCommitCheckpointV1| c.selected.committee.reverse(),
        |c: &mut SumeragiCommitCheckpointV1| c.selected.committee[0].proof_of_possession[0] ^= 1,
        |c: &mut SumeragiCommitCheckpointV1| {
            c.selected.authorization.previous_authorization_id[0] ^= 1
        },
        |c: &mut SumeragiCommitCheckpointV1| {
            c.selected.authorization.first_height = c.initial.authorization.last_height
        },
        |c: &mut SumeragiCommitCheckpointV1| {
            c.chain.clear();
            c.initial.committee[0].proof_of_possession.clear();
        },
    ] {
        let mut changed = checkpoint.clone();
        mutate(&mut changed);
        let wire = norito::encode_canonical(&changed).unwrap();
        let expected = read_and_restore(&wire, &native, None).unwrap_err();
        for _ in 0..2 {
            let actual = read_and_restore(&wire, &native, Some(&mut validation)).unwrap_err();
            let (FinalityReadError::Invalid(actual), FinalityReadError::Invalid(expected)) =
                (&actual, &expected)
            else {
                panic!("completed validation errors required")
            };
            assert_eq!(actual, expected);
        }
    }
    let foreign = super::tests::root(
        &crate::sumeragi_finality::test_fixtures::NativeFinalityFixture::start(
            "compact-scope-foreign",
        ),
    );
    let expected = SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&checkpoint, &foreign)
        .err()
        .unwrap();
    let actual = SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint_with_validation(
        &checkpoint,
        &foreign,
        Some(&mut validation),
    )
    .err()
    .unwrap();
    assert_eq!(actual, expected);
    for wire in [
        Vec::new(),
        bytes[..bytes.len() - 1].to_vec(),
        [bytes.as_slice(), &[0]].concat(),
        vec![0; MAX_COMMIT_CHECKPOINT_BYTES + 1],
    ] {
        let expected = read_and_restore(&wire, &native, None).unwrap_err();
        let actual = read_and_restore(&wire, &native, Some(&mut validation)).unwrap_err();
        assert_eq!(actual.to_string(), expected.to_string());
    }
    // A warm scope never turns an invalid observation into a negative cache or changes DATA.
    assert_eq!(
        read_and_restore(&bytes, &native, Some(&mut validation)).unwrap(),
        checkpoint
    );
}

#[test]
fn warmed_compact_scope_preserves_outer_charges_refusal_and_same_bytes_retry() {
    let (fixture, _, reader) = authenticated_boundary(4);
    let native = root(&fixture);
    let checkpoint = reader.export_epoch_checkpoint(1).unwrap();
    let bytes = checkpoint.encode_canonical().unwrap();
    let mut validation = EpochValidationScope::new();
    read_and_restore(&bytes, &native, Some(&mut validation)).unwrap();
    let limits = |allocation| norito::DecodeLimits::new(1 << 20, 1 << 20, 1 << 20, allocation, 64);
    let original = DecodeBudgetContext::new(limits(16 << 20));
    original
        .with(|| read_and_restore(&bytes, &native, None))
        .unwrap();
    let charge = usize::try_from(original.consumed_allocated_bytes()).unwrap();
    assert!(charge > 1);
    for cap in [0, charge / 2, charge - 1, charge] {
        let original = DecodeBudgetContext::new(limits(cap));
        let expected = original.with(|| read_and_restore(&bytes, &native, None));
        let supplied = DecodeBudgetContext::new(limits(cap));
        let before = validation_counts::calls();
        let actual = supplied.with(|| read_and_restore(&bytes, &native, Some(&mut validation)));
        if cap == charge {
            assert_eq!(validation_counts::calls() - before, 8);
        }
        assert_eq!(
            supplied.consumed_allocated_bytes(),
            original.consumed_allocated_bytes()
        );
        match (actual, expected) {
            (Ok(actual), Ok(expected)) => {
                assert_eq!(actual, expected);
                assert_eq!(cap, charge);
            }
            (
                Err(FinalityReadError::DecodeResource(actual)),
                Err(FinalityReadError::DecodeResource(expected)),
            ) => {
                assert_eq!(actual.kind(), DecodeAttemptErrorKind::EnclosingLimit);
                assert_eq!(expected.kind(), DecodeAttemptErrorKind::EnclosingLimit);
                assert_eq!(
                    actual.into_error().decode_resource_error(),
                    expected.into_error().decode_resource_error()
                );
                if cap == charge - 1 {
                    assert!(supplied.consumed_allocated_bytes() > 0);
                }
            }
            (actual, expected) => {
                panic!("same original admission result required: {actual:?} / {expected:?}")
            }
        }
    }
    let original = DecodeBudgetContext::new(limits(16 << 20));
    let before = validation_counts::calls();
    original
        .with(|| {
            SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint_with_validation(
                &checkpoint,
                &native,
                Some(&mut validation),
            )
        })
        .unwrap();
    assert_eq!(validation_counts::calls() - before, 4);
    let before = validation_counts::calls();
    original
        .with(|| {
            SumeragiCommitCheckpointV1::from_authenticated_genesis_with_validation(
                &native,
                Some(&mut validation),
            )
        })
        .unwrap();
    assert_eq!(validation_counts::calls() - before, 2);
    let before = validation_counts::calls();
    assert_eq!(
        read_and_restore(&bytes, &native, Some(&mut validation)).unwrap(),
        checkpoint
    );
    assert_eq!(validation_counts::calls() - before, 0);
    assert_eq!(checkpoint.encode_canonical().unwrap(), bytes);
}

/// Paired host component observations; not a Load proof or phone latency sample.
#[test]
#[ignore = "explicit compact epoch validation timing diagnostic"]
fn compact_epoch_validation_host_timing() {
    use std::time::Instant;
    let (fixture, chain, reader) = authenticated_boundary(4);
    let native = root(&fixture);
    for epoch in [0, 1] {
        let expected = reader.export_epoch_checkpoint(epoch).unwrap();
        let bytes = expected.encode_canonical().unwrap();
        let proof = certificate(&fixture, &chain[if epoch == 0 { 1 } else { 3 }]);
        let mut verifier =
            SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&expected, &native).unwrap();
        let expected_decision = verifier.verify(&proof).unwrap();
        let expected_commitment = expected_decision.commitment();
        // Two checked warmup pairs, then ten measured pairs with balanced order.
        for pair in 0..12 {
            let mut observations = Vec::with_capacity(2);
            for (position, shared) in if pair % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            }
            .into_iter()
            .enumerate()
            {
                let before = validation_counts::calls();
                let start = Instant::now();
                let mut validation = shared.then(EpochValidationScope::new);
                let actual = if epoch == 0 {
                    let checkpoint =
                        SumeragiCommitCheckpointV1::from_authenticated_genesis_with_validation(
                            &native,
                            validation.as_mut(),
                        )
                        .unwrap();
                    SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint_with_validation(
                        &checkpoint,
                        &native,
                        validation.as_mut(),
                    )
                    .unwrap();
                    checkpoint
                } else {
                    read_and_restore(&bytes, &native, validation.as_mut()).unwrap()
                };
                drop(validation);
                let wall_ns = start.elapsed().as_nanos();
                let calls = validation_counts::calls() - before;
                assert_eq!(calls, if shared { 1 << epoch } else { 4 << epoch });
                assert_eq!(actual, expected);
                assert_eq!(actual.encode_canonical().unwrap(), bytes);
                // Independent native verification stays outside the component timing cut.
                let mut restored =
                    SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&actual, &native)
                        .unwrap();
                assert_eq!(
                    restored.verify(&proof).unwrap().commitment(),
                    expected_commitment
                );
                observations.push((position, shared, wall_ns, calls));
            }
            if pair >= 2 {
                for (position, shared, wall_ns, calls) in observations {
                    println!(
                        "LOAD_EPOCH_VALIDATION epoch={epoch} sample={} position={position} variant={} wall_ns={wall_ns} context_validations={calls} checkpoint_bytes={} pair_verified=true native_certificate_verified=true full_load_proof=false phone_p95=false live_memory_measured=false",
                        pair - 2,
                        if shared { "shared" } else { "independent" },
                        bytes.len(),
                    );
                }
            }
        }
    }
}
