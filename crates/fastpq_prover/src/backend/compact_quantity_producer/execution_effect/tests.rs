//! Encode-only owner parity and complete-effect producer preflight controls.

use super::*;
use crate::backend::compact_execution_effect_batch::tests::{expected, fixture};
use iroha_data_model::fastpq::{
    FastpqOrdinaryCompactArtifactV1, execution_effect_statement_digest_v1,
};

fn limits(count: usize) -> ExecutionEffectVerificationLimits {
    let mut value = ExecutionEffectVerificationLimits::default();
    value.bundle.max_segments = count;
    value.bundle.max_total_queries = count * crate::backend::deep_geometry::QUERY_COUNT;
    value.bundle.max_wire_bytes = 16 * 1024 * 1024;
    value.bundle.max_total_segment_bytes = 16 * 1024 * 1024;
    value.transport.max_wire_bytes = 16 * 1024 * 1024;
    value.transport.max_bundle_frame_bytes = 16 * 1024 * 1024;
    value
}
#[test]
fn borrowed_artifact_and_carrier_match_the_only_owned_model_frames() {
    let (source, statement, roots) = fixture();
    let view = SourceExecutionEffectStatement::from_owned(&statement);
    let children = vec![vec![1, 2, 3]; statement.effects.effects.len()];
    let policy = limits(children.len());
    let owned_carrier = bundle::EffectBundleWire {
        version: 1,
        intermediate_roots: roots.clone(),
        segments: children.clone(),
    };
    for flags in
        (u8::MIN..=u8::MAX).filter(|&flags| norito::core::validate_header_flags(flags).is_ok())
    {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        let framed = bundle::encode_parts(
            1,
            &roots,
            &children,
            children.len(),
            policy.bundle.internal(),
        )
        .unwrap();
        assert_eq!(framed, norito::encode_canonical(&owned_carrier).unwrap());
        let borrowed = artifact(&view, &source, &framed);
        let owned = FastpqOrdinaryCompactArtifactV1 {
            profile_id: execution_effect_profile_id(),
            source: source.clone(),
            statement: statement.clone(),
            bundle_frame: framed.clone(),
        };
        let bytes = norito::encode_canonical(&borrowed).unwrap();
        assert_eq!(bytes, norito::encode_canonical(&owned).unwrap());
        let decoded = FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
            &bytes,
            execution_effect_profile_id(),
            policy.transport,
        )
        .unwrap();
        assert_eq!(decoded, owned);
        assert_eq!(norito::canonical_frame_len(&borrowed).unwrap(), bytes.len());
        assert_eq!(
            view.digest(policy.public_policy().max_public_bytes)
                .unwrap(),
            execution_effect_statement_digest_v1(&statement).unwrap()
        );
    }
    assert!(
        bundle::encode_parts(
            0,
            &roots,
            &children,
            children.len(),
            policy.bundle.internal()
        )
        .is_err()
    );
}
#[test]
fn original_credit_and_complete_expectations_refuse_before_private_expansion() {
    let (source, statement, _) = fixture();
    let n = statement.effects.effects.len();
    let view = SourceExecutionEffectStatement::from_owned(&statement);
    let limits = limits(n);
    let proving = ProvingLimits {
        private_smt:
            crate::gadgets::public_transfer_statement::TransferSmtBuildLimits::for_update_limit(
                2 * n,
            )
            .unwrap(),
        max_total_trace_cells: n
            * crate::gadgets::compact_smt_air::COLUMN_COUNT
            * crate::backend::deep_geometry::TRACE_ROWS,
        ..ProvingLimits::default()
    };
    let facts = expected(&statement).unwrap();
    let expected = ExpectedExecutionEffects {
        source: &source,
        statement: facts,
    };
    assert_eq!(preflight(&view, expected, proving, &limits).unwrap(), n);
    let mut wrong = facts;
    wrong.statement_digest = Hash::new(b"substituted statement");
    assert!(matches!(
        preflight(
            &view,
            ExpectedExecutionEffects {
                source: &source,
                statement: wrong
            },
            proving,
            &limits
        ),
        Err(Error::PublicIoMismatch {
            field: "compact_public_statement_digest"
        })
    ));
    let demand = quantity_ordinary_allocation_bytes(&statement.effects, proving, &limits).unwrap();
    let budget = AllocationBudget::new(demand);
    let foreign = AllocationBudget::new(demand);
    let mut foreign_credit = foreign.try_reserve_bytes(demand).unwrap();
    assert!(matches!(
        prove(
            &view,
            expected,
            proving,
            &limits,
            &budget,
            &mut foreign_credit
        ),
        Err(ProvingError::Prove(Error::AllocationForeignPool))
    ));
    // Foreign ownership precedes malformed expectations and semantic/work limits.
    let mut invalid_policy = limits;
    invalid_policy.public_statement.max_effects = 0;
    assert!(matches!(
        crate::offline_compact::prove_quantity_ordinary_artifact(
            &view,
            ExpectedExecutionEffects {
                source: &source,
                statement: wrong
            },
            proving,
            &invalid_policy,
            &budget,
            &mut foreign_credit
        ),
        Err(ProvingError::Prove(Error::AllocationForeignPool))
    ));
    assert_eq!(foreign_credit.remaining_bytes(), demand);
    drop(foreign_credit);
    assert_eq!(foreign.reserved_bytes(), 0);
    let mut insufficient = budget.try_reserve_bytes(demand - 1).unwrap();
    assert!(
        matches!(prove(&view, expected, proving, &limits, &budget, &mut insufficient),
        Err(ProvingError::Prove(Error::AllocationReservation(error)))
            if error.requested_bytes == demand && error.remaining_bytes == demand - 1)
    );
    assert_eq!(insufficient.remaining_bytes(), demand - 1);
    drop(insufficient);
    assert_eq!(budget.reserved_bytes(), 0);
    let _held = hold_producer_for_test();
    let mut credit = budget.try_reserve_bytes(demand).unwrap();
    assert!(matches!(
        prove(&view, expected, proving, &limits, &budget, &mut credit),
        Err(ProvingError::Busy)
    ));
    assert_eq!(credit.remaining_bytes(), demand);
}

#[test]
#[ignore = "optimized native complete-effect proof control; requires the composed source-owner and facade candidate"]
fn complete_effect_native_producer_self_verifies_and_binds_every_source_field() {
    let (source, statement, _) = fixture();
    let n = statement.effects.effects.len();
    let view = SourceExecutionEffectStatement::from_owned(&statement);
    let policy = limits(n);
    let proving = ProvingLimits {
        private_smt:
            crate::gadgets::public_transfer_statement::TransferSmtBuildLimits::for_update_limit(
                2 * n,
            )
            .unwrap(),
        max_total_trace_cells: n
            * crate::gadgets::compact_smt_air::COLUMN_COUNT
            * crate::backend::deep_geometry::TRACE_ROWS,
        ..ProvingLimits::default()
    };
    let expected = ExpectedExecutionEffects {
        source: &source,
        statement: expected(&statement).unwrap(),
    };
    let proof_credit =
        quantity_ordinary_allocation_bytes(&statement.effects, proving, &policy).unwrap();
    let verify_credit = crate::offline_compact::quantity_ordinary_verification_allocation_bytes(
        &statement.effects,
        &policy,
    )
    .unwrap();
    let budget = AllocationBudget::new(proof_credit + verify_credit);
    let mut reservation = budget
        .try_reserve_bytes(proof_credit + verify_credit)
        .unwrap();
    let produced = crate::offline_compact::prove_quantity_ordinary_artifact(
        &view,
        expected,
        proving,
        &policy,
        &budget,
        &mut reservation,
    )
    .unwrap();
    // Whole proving demand was consumed even though earlier backing has dropped;
    // mandatory verification succeeded using the same original partition.
    assert_eq!(reservation.remaining_bytes(), verify_credit);
    assert_eq!(budget.reserved_bytes(), verify_credit);
    assert_eq!(produced.verified().segments(), n);
    assert_eq!(
        produced.verified().identity().artifact_digest,
        Into::<[u8; 32]>::into(Hash::new(produced.bytes()))
    );
    let bytes_pointer = produced.bytes().as_ptr();
    let roots_pointer = produced.verified().air_row_roots().as_ptr();
    let (bytes, producer_verified) = produced.into_parts();
    assert_eq!(bytes.as_ptr(), bytes_pointer);
    assert_eq!(producer_verified.air_row_roots().as_ptr(), roots_pointer);
    let checked =
        verify_quantity_ordinary_artifact(&bytes, expected, &policy, &budget, &mut reservation)
            .unwrap();
    assert_eq!(checked, producer_verified);
    assert_eq!(checked.segments(), n);
    assert_eq!(checked.air_row_roots().len(), n);
    assert_eq!(checked.identity().profile_id, execution_effect_profile_id());
    assert_eq!(
        checked.identity().public_statement_digest,
        Into::<[u8; 32]>::into(expected.statement.statement_digest)
    );
    assert_eq!(
        checked.identity().artifact_digest,
        Into::<[u8; 32]>::into(Hash::new(&bytes))
    );
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 0);
    // Same genuine proof cannot be replayed at another authenticated position.
    let mut other = source.clone();
    other.entry_index += 1;
    let mut credit = budget.try_reserve_bytes(verify_credit).unwrap();
    assert!(matches!(
        verify_quantity_ordinary_artifact(
            &bytes,
            ExpectedExecutionEffects {
                source: &other,
                ..expected
            },
            &policy,
            &budget,
            &mut credit
        ),
        Err(crate::offline_compact::VerificationError::Verify(
            Error::PublicIoMismatch {
                field: "compact_artifact_execution_source"
            }
        ))
    ));
    assert_eq!(credit.remaining_bytes(), verify_credit);
    drop(credit);
    // A real child mutation cannot return a successfully verified prefix.
    let mut model = FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
        &bytes,
        execution_effect_profile_id(),
        policy.transport,
    )
    .unwrap();
    model.bundle_frame.pop();
    let changed = norito::encode_canonical(&model).unwrap();
    let mut credit = budget.try_reserve_bytes(verify_credit).unwrap();
    assert!(
        verify_quantity_ordinary_artifact(&changed, expected, &policy, &budget, &mut credit)
            .is_err()
    );
    drop(credit);
    assert_eq!(budget.reserved_bytes(), 0);
}
