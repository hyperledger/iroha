//! Existing semantic predicates consume actual frozen current and predecessor rows.
//!
//! These controls prove source/refusal preservation at the scoped semantic
//! boundary. They do not turn it into a retained materializer or State root.

use super::{fixture, pending, staged_block, start};
use crate::{
    execution_attempt::ExecutionAttemptError,
    state::{
        State, StateBlock, StatePublicationOutcome,
        deserialize::{
            musubi_source_read::ReadFailure,
            musubi_source_work::{SourceValidationError, SourceWorkLimits},
        },
        publication::{
            OriginalMusubiImage, RetainedMusubiGroupReadError, RetainedPackageReadError,
        },
        storage_transactions,
    },
    test_allocations::allocations_during,
};
use iroha_data_model::{
    block::BlockHeader,
    musubi::{
        MusubiContentDigestV1, MusubiOrderedPackageEntryV1, source_work::SourceGeometryLimits,
    },
};
use mv::storage::StorageReadOnly as _;

const WORK: usize = 1_000_000;
fn limits() -> SourceWorkLimits {
    SourceWorkLimits {
        geometry: SourceGeometryLimits {
            elements: 1_000_000,
            variable_bytes: 1_000_000,
        },
        table_pass_rows: 1_000_000,
        lookup_index_entries: 1_000_000,
        model_operations: 1_000_000,
        signature_checks: 1_000_000,
    }
}
fn prepare(block: &mut StateBlock<'_>) {
    let budget = block.state_ref.ivm_execution_budget();
    start(block, &budget);
    assert!(
        block
            .advance_original_musubi_group_read(WORK)
            .unwrap()
            .complete
    );
    assert!(
        block
            .advance_original_musubi_group_predecessor_read(WORK)
            .unwrap()
            .complete
    );
}

#[test]
fn original_frozen_semantic_graph_checks_both_exact_images_in_ordinary_and_replacement_modes() {
    for replacement in [false, true] {
        let (state, proposal) = fixture();
        if replacement {
            staged_block(&state, proposal.header(), false, true)
                .commit()
                .unwrap();
        }
        let mut block = pending(&state, proposal.header(), replacement);
        prepare(&mut block);
        let before = block.original_musubi_group_predecessor_progress().unwrap();
        for image in [
            OriginalMusubiImage::Current,
            OriginalMusubiImage::Predecessor,
        ] {
            block
                .with_original_musubi_rows(WORK, |mut rows, _| rows.validate_image(image, limits()))
                .unwrap()
                .unwrap();
        }
        let after = block.original_musubi_group_predecessor_progress().unwrap();
        assert_eq!(after.tables, before.tables);
        assert!(after.work > before.work);
        assert!(after.complete);
        block.retire_original_musubi_group_read().unwrap();
        assert!(matches!(
            block.try_publish(),
            StatePublicationOutcome::Published
        ));
    }
}

#[test]
fn original_frozen_semantic_work_refusal_cannot_become_absence_or_empty_iteration() {
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    prepare(&mut block);
    let before = block.original_musubi_group_read_progress().unwrap();
    let original_credit = state.ivm_execution_budget().reserved_bytes();
    let allocations = allocations_during(|| {
        let error = block
            .with_original_musubi_rows(before.work, |mut rows, _| {
                rows.validate_image(OriginalMusubiImage::Current, limits())
            })
            .unwrap()
            .unwrap_err();
        assert!(
            matches!(error, ReadFailure::Source(RetainedMusubiGroupReadError::Field {
            field: "musubi_archives",
            original: RetainedPackageReadError::Work { used, required, limit },
        }) if used == before.work && required > used && limit == before.work)
        );
    });
    assert_eq!(allocations, 0);
    assert_eq!(block.original_musubi_group_read_progress().unwrap(), before);
    assert_eq!(
        state.ivm_execution_budget().reserved_bytes(),
        original_credit
    );
    block
        .with_original_musubi_rows(WORK, |mut rows, _| {
            rows.validate_image(OriginalMusubiImage::Current, limits())
        })
        .unwrap()
        .unwrap();
}

#[test]
fn original_frozen_semantic_scratch_refusal_retains_the_actual_pool_and_original_rows() {
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    prepare(&mut block);
    let budget = state.ivm_execution_budget();
    let before = block.original_musubi_group_predecessor_progress().unwrap();
    let original_credit = budget.reserved_bytes();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - original_credit)
        .unwrap();
    let expected = budget
        .try_reserve_bytes(std::mem::size_of::<&MusubiOrderedPackageEntryV1>())
        .unwrap_err();
    let error = block
        .with_original_musubi_rows(WORK, |mut rows, _| {
            rows.validate_image(OriginalMusubiImage::Current, limits())
        })
        .unwrap()
        .unwrap_err();
    let ReadFailure::Predicate(SourceValidationError::Attempt(ExecutionAttemptError::Deferred(
        actual,
    ))) = error
    else {
        panic!("complete source admission preserves original directory allocation refusal");
    };
    assert_eq!(actual.allocation_refusal(), Some(&expected));
    let after = block.original_musubi_group_predecessor_progress().unwrap();
    assert_eq!(after.tables, before.tables);
    assert!(after.work > before.work);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    drop(occupied);
    block
        .with_original_musubi_rows(WORK, |mut rows, _| {
            rows.validate_image(OriginalMusubiImage::Current, limits())
        })
        .unwrap()
        .unwrap();
    assert_eq!(budget.reserved_bytes(), original_credit);
    assert_eq!(
        block
            .original_musubi_group_predecessor_progress()
            .unwrap()
            .tables,
        before.tables
    );
}

#[expect(
    clippy::large_types_passed_by_value,
    reason = "the original block takes ownership of its signed fixture header"
)]
fn corrupt_pending(state: &State, header: BlockHeader) -> Box<StateBlock<'_>> {
    let mut block = Box::new(staged_block(state, header, false, true));
    let (key, mut row) = block
        .world
        .musubi_resolver_index
        .iter()
        .next()
        .map(|(key, row)| (key.clone(), row.clone()))
        .unwrap();
    row.source_digest = MusubiContentDigestV1::new([0xff; 32]);
    block.world.musubi_resolver_index.insert(key, row);
    let budget = state.ivm_execution_budget();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Deferred(
            storage_transactions::TransactionsBlockError::ExecutionDeferred(_)
        )
    ));
    drop(occupied);
    block
}

#[test]
fn original_frozen_semantic_rejection_names_the_actual_current_cut_without_committed_fallback() {
    let (state, proposal) = fixture();
    let mut block = corrupt_pending(&state, proposal.header());
    prepare(&mut block);
    block
        .with_original_musubi_rows(WORK, |mut rows, _| {
            rows.validate_image(OriginalMusubiImage::Predecessor, limits())
        })
        .unwrap()
        .unwrap();
    let error = block
        .with_original_musubi_rows(WORK, |mut rows, _| {
            rows.validate_image(OriginalMusubiImage::Current, limits())
        })
        .unwrap()
        .unwrap_err();
    let ReadFailure::Predicate(SourceValidationError::Attempt(ExecutionAttemptError::Rejected(
        original,
    ))) = error
    else {
        panic!("the original changed resolver must fail its real semantic predicate");
    };
    assert_eq!(original.field(), "world.musubi_resolver_index");
    assert_eq!(
        original.reason(),
        "resolver row diverges from authoritative release/archive projections"
    );
    assert!(original.to_string().contains("current World cut"));
    assert!(state.world.musubi_resolver_index.view().is_empty());
}

#[test]
fn original_frozen_semantic_graph_rejects_invalid_undo_while_accepting_the_repaired_current_image()
{
    let (state, proposal) = fixture();
    staged_block(&state, proposal.header(), false, true)
        .commit()
        .unwrap();
    // Create an actual invalid predecessor in the test State, then stage the
    // canonical fixture again. No committed-view fallback may hide this undo.
    let (key, mut row) = state
        .world
        .musubi_resolver_index
        .view()
        .iter()
        .next()
        .map(|(key, row)| (key.clone(), row.clone()))
        .unwrap();
    row.source_digest = MusubiContentDigestV1::new([0xfe; 32]);
    let mut previous = state.world.musubi_resolver_index.block();
    previous.insert(key, row);
    previous.commit();
    let mut block = pending(&state, proposal.header(), false);
    prepare(&mut block);
    block
        .with_original_musubi_rows(WORK, |mut rows, _| {
            rows.validate_image(OriginalMusubiImage::Current, limits())
        })
        .unwrap()
        .unwrap();
    let error = block
        .with_original_musubi_rows(WORK, |mut rows, _| {
            rows.validate_image(OriginalMusubiImage::Predecessor, limits())
        })
        .unwrap()
        .unwrap_err();
    let ReadFailure::Predicate(SourceValidationError::Attempt(ExecutionAttemptError::Rejected(
        original,
    ))) = error
    else {
        panic!("the actual invalid undo must fail the same semantic predicate");
    };
    assert_eq!(original.field(), "world.musubi_resolver_index");
    assert_eq!(
        original.reason(),
        "resolver row diverges from authoritative release/archive projections"
    );
    assert!(original.to_string().contains("predecessor World cut"));
}

#[test]
fn semantic_success_is_discarded_if_the_original_state_changes_during_its_callback() {
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    prepare(&mut block);
    let before = block.original_musubi_group_predecessor_progress().unwrap();
    let result = block.with_original_musubi_rows(WORK, |mut rows, _| {
        rows.validate_image(OriginalMusubiImage::Current, limits())
            .unwrap();
        staged_block(&state, proposal.header(), false, false)
            .commit()
            .unwrap();
    });
    assert!(matches!(
        result,
        Err(RetainedMusubiGroupReadError::SourceChanged)
    ));
    let after = block.original_musubi_group_predecessor_progress().unwrap();
    assert_eq!(after.tables, before.tables);
    assert!(after.work > before.work);
    let result = block.with_original_musubi_rows(WORK, |_, _| {
        panic!("stale semantic source cannot be reentered")
    });
    assert!(matches!(
        result,
        Err(RetainedMusubiGroupReadError::SourceChanged)
    ));
}

#[test]
fn original_source_admission_retains_exact_row_prefix_and_refuses_policy_replacement() {
    use iroha_data_model::musubi::source_work::{SourceGeometry, SourceShape};
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    prepare(&mut block);
    // Measure the real original resolve, not a fabricated CPU allowance. This
    // independent read consumes its own actual native work as normal.
    let before_measurement = block.original_musubi_group_read_progress().unwrap().work;
    let archive_geometry = block
        .with_original_musubi_rows(WORK, |mut rows, _| {
            let (_, archive) = rows.musubi_archives_current_row(0).unwrap();
            let mut geometry = SourceGeometry::new(limits().geometry);
            geometry.admit(SourceShape::Archive(archive)).unwrap();
            geometry.used()
        })
        .unwrap();
    let initial_work = block.original_musubi_group_read_progress().unwrap().work;
    let one_original_resolve = initial_work.checked_sub(before_measurement).unwrap();
    assert!(one_original_resolve > 0);
    block
        .start_original_musubi_source_admission(limits())
        .unwrap();
    let control_credit = state.ivm_execution_budget().reserved_bytes();
    let partial_limit = initial_work.checked_add(one_original_resolve).unwrap();
    let error = block
        .advance_original_musubi_source_admission(OriginalMusubiImage::Current, partial_limit)
        .unwrap_err();
    assert!(matches!(
        error,
        ReadFailure::Source(RetainedMusubiGroupReadError::Field {
            original: RetainedPackageReadError::Work { .. },
            ..
        })
    ));
    let prefix = block
        .original_musubi_source_admission_progress(OriginalMusubiImage::Current)
        .unwrap();
    assert!(
        prefix.shape_table >= 1,
        "the exact archive shape must remain admitted"
    );
    assert_eq!(prefix.geometry, archive_geometry);
    assert!(!prefix.complete);
    assert_eq!(prefix.stopped, None);
    let before_retry = block.original_musubi_group_read_progress().unwrap();
    let allocations = allocations_during(|| {
        let error = block
            .advance_original_musubi_source_admission(OriginalMusubiImage::Current, partial_limit)
            .unwrap_err();
        assert!(matches!(
            error,
            ReadFailure::Source(RetainedMusubiGroupReadError::Field {
                original: RetainedPackageReadError::Work { .. },
                ..
            })
        ));
    });
    assert_eq!(allocations, 0);
    assert_eq!(
        block.original_musubi_group_read_progress().unwrap(),
        before_retry
    );
    assert_eq!(
        block
            .original_musubi_source_admission_progress(OriginalMusubiImage::Current)
            .unwrap(),
        prefix
    );
    assert_eq!(
        state.ivm_execution_budget().reserved_bytes(),
        control_credit
    );
    let mut replacement_policy = limits();
    replacement_policy.geometry.elements = 0;
    assert!(matches!(
        block.start_original_musubi_source_admission(replacement_policy),
        Err(RetainedMusubiGroupReadError::SemanticAlreadyStarted)
    ));
    assert_eq!(
        block
            .original_musubi_source_admission_progress(OriginalMusubiImage::Current)
            .unwrap(),
        prefix
    );
    let complete = block
        .advance_original_musubi_source_admission(OriginalMusubiImage::Current, WORK)
        .unwrap();
    assert!(complete.complete);
    assert!(complete.geometry.elements >= prefix.geometry.elements);
    assert!(complete.operations > 0);
    let work = block.original_musubi_group_read_progress().unwrap();
    assert_eq!(
        block
            .advance_original_musubi_source_admission(OriginalMusubiImage::Current, WORK)
            .unwrap(),
        complete
    );
    assert_eq!(block.original_musubi_group_read_progress().unwrap(), work);
    assert_eq!(
        state.ivm_execution_budget().reserved_bytes(),
        control_credit
    );
    assert!(
        block
            .advance_original_musubi_source_admission(OriginalMusubiImage::Predecessor, WORK)
            .unwrap()
            .complete
    );
    block.retire_original_musubi_group_read().unwrap();
    assert!(
        block
            .original_musubi_source_admission_progress(OriginalMusubiImage::Current)
            .is_none()
    );
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Published
    ));
}

#[test]
fn original_source_policy_refusal_is_sticky_without_replenishing_geometry_or_native_work() {
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    prepare(&mut block);
    let mut policy = limits();
    policy.geometry.elements = 0;
    block
        .start_original_musubi_source_admission(policy)
        .unwrap();
    let first = block
        .advance_original_musubi_source_admission(OriginalMusubiImage::Current, WORK)
        .unwrap_err();
    let ReadFailure::Predicate(SourceValidationError::Work(original)) = first else {
        panic!("the actual first source shape must retain its finite policy refusal");
    };
    let progress = block
        .original_musubi_source_admission_progress(OriginalMusubiImage::Current)
        .unwrap();
    assert_eq!(progress.stopped, Some(original));
    assert!(!progress.complete);
    let retained_native = block.original_musubi_group_read_progress().unwrap();
    let retained_credit = state.ivm_execution_budget().reserved_bytes();
    let second = block
        .advance_original_musubi_source_admission(OriginalMusubiImage::Current, WORK)
        .unwrap_err();
    assert!(
        matches!(second, ReadFailure::Predicate(SourceValidationError::Work(cause)) if cause == original)
    );
    assert_eq!(
        block
            .original_musubi_source_admission_progress(OriginalMusubiImage::Current)
            .unwrap(),
        progress
    );
    assert_eq!(
        block.original_musubi_group_read_progress().unwrap(),
        retained_native
    );
    assert_eq!(
        state.ivm_execution_budget().reserved_bytes(),
        retained_credit
    );
    assert!(matches!(
        block.start_original_musubi_source_admission(limits()),
        Err(RetainedMusubiGroupReadError::SemanticAlreadyStarted)
    ));
}

#[test]
fn original_source_cursor_control_admission_retains_the_exact_pool_refusal() {
    use crate::state::publication::original_musubi_admission_control_layout_for_test;
    use iroha_allocation::ChargedBufferError;
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    prepare(&mut block);
    let budget = state.ivm_execution_budget();
    let retained_credit = budget.reserved_bytes();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - retained_credit)
        .unwrap();
    let expected = budget
        .try_reserve_bytes(original_musubi_admission_control_layout_for_test().size())
        .unwrap_err();
    let error = block
        .start_original_musubi_source_admission(limits())
        .unwrap_err();
    let RetainedMusubiGroupReadError::Control(ChargedBufferError::Admission(actual)) = error else {
        panic!("both original source cursors require actual original-pool control backing");
    };
    assert_eq!(actual, expected);
    assert!(
        block
            .original_musubi_source_admission_progress(OriginalMusubiImage::Current)
            .is_none()
    );
    assert!(
        block
            .original_musubi_source_admission_progress(OriginalMusubiImage::Predecessor)
            .is_none()
    );
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    drop(occupied);
    block
        .start_original_musubi_source_admission(limits())
        .unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        retained_credit + original_musubi_admission_control_layout_for_test().size()
    );
    assert!(
        block
            .advance_original_musubi_source_admission(OriginalMusubiImage::Current, WORK)
            .unwrap()
            .complete
    );
}

#[test]
fn original_universal_cursor_retains_ordinal_scratch_and_completed_rows_on_work_refusal() {
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    prepare(&mut block);
    block
        .start_original_musubi_source_admission(limits())
        .unwrap();
    for image in [
        OriginalMusubiImage::Current,
        OriginalMusubiImage::Predecessor,
    ] {
        assert!(
            block
                .advance_original_musubi_source_admission(image, WORK)
                .unwrap()
                .complete
        );
    }
    let before_measurement = block.original_musubi_group_read_progress().unwrap().work;
    block
        .with_original_musubi_rows(WORK, |mut rows, _| {
            assert!(rows.musubi_packages_current_row(0).is_ok());
        })
        .unwrap();
    let before = block.original_musubi_group_read_progress().unwrap();
    let one_package = before.work.checked_sub(before_measurement).unwrap();
    assert!(one_package > 0);
    let limit = before
        .work
        .checked_add(one_package.checked_mul(2).unwrap())
        .unwrap();
    let credit_before = state.ivm_execution_budget().reserved_bytes();
    let error = block
        .advance_original_musubi_universal(OriginalMusubiImage::Current, limit)
        .unwrap_err();
    assert!(matches!(
        error,
        ReadFailure::Source(RetainedMusubiGroupReadError::Field {
            original: RetainedPackageReadError::Work { .. },
            ..
        })
    ));
    let prefix = block
        .original_musubi_universal_progress(OriginalMusubiImage::Current)
        .unwrap();
    assert_eq!(
        prefix.phase, 2,
        "the validated package and original accumulator are retained"
    );
    assert_eq!(prefix.package_accumulators, 1);
    assert_eq!(prefix.row, 0);
    assert!(!prefix.complete);
    let retained_credit = state.ivm_execution_budget().reserved_bytes();
    assert!(retained_credit > credit_before);
    let retained_work = block.original_musubi_group_read_progress().unwrap();
    let allocations = allocations_during(|| {
        assert!(matches!(
            block.advance_original_musubi_universal(OriginalMusubiImage::Current, limit),
            Err(ReadFailure::Source(RetainedMusubiGroupReadError::Field {
                original: RetainedPackageReadError::Work { .. },
                ..
            }))
        ));
    });
    assert_eq!(allocations, 0);
    assert_eq!(
        block.original_musubi_universal_progress(OriginalMusubiImage::Current),
        Some(prefix)
    );
    assert_eq!(
        block.original_musubi_group_read_progress().unwrap(),
        retained_work
    );
    assert_eq!(
        state.ivm_execution_budget().reserved_bytes(),
        retained_credit
    );
    for image in [
        OriginalMusubiImage::Current,
        OriginalMusubiImage::Predecessor,
    ] {
        assert!(
            block
                .advance_original_musubi_universal(image, WORK)
                .unwrap()
                .complete
        );
    }
    let complete_work = block.original_musubi_group_read_progress().unwrap();
    let complete_credit = state.ivm_execution_budget().reserved_bytes();
    assert!(
        block
            .advance_original_musubi_universal(OriginalMusubiImage::Current, WORK)
            .unwrap()
            .complete
    );
    assert_eq!(
        block.original_musubi_group_read_progress().unwrap(),
        complete_work
    );
    assert_eq!(
        state.ivm_execution_budget().reserved_bytes(),
        complete_credit
    );
    block.retire_original_musubi_group_read().unwrap();
    assert!(
        block
            .original_musubi_universal_progress(OriginalMusubiImage::Current)
            .is_none()
    );
    assert!(state.ivm_execution_budget().reserved_bytes() < complete_credit);
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Published
    ));
}

#[test]
fn original_universal_scratch_refusal_preserves_validated_package_prefix_and_exact_pool() {
    use crate::state::deserialize::musubi_universal::cursor::UniversalValidation;
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    prepare(&mut block);
    block
        .start_original_musubi_source_admission(limits())
        .unwrap();
    assert!(
        block
            .advance_original_musubi_source_admission(OriginalMusubiImage::Current, WORK)
            .unwrap()
            .complete
    );
    let budget = state.ivm_execution_budget();
    let held = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let expected = budget
        .try_reserve_bytes(UniversalValidation::<usize, usize>::scratch_bytes_for_test(
            1,
        ))
        .unwrap_err();
    let first = block
        .advance_original_musubi_universal(OriginalMusubiImage::Current, WORK)
        .unwrap_err();
    let ReadFailure::Predicate(SourceValidationError::Attempt(ExecutionAttemptError::Deferred(
        original,
    ))) = first
    else {
        panic!("scratch admission must retain the original allocation refusal");
    };
    assert_eq!(original.allocation_refusal(), Some(&expected));
    let progress = block
        .original_musubi_universal_progress(OriginalMusubiImage::Current)
        .unwrap();
    assert_eq!(progress.phase, 1);
    assert_eq!(progress.package_accumulators, 0);
    let native = block.original_musubi_group_read_progress().unwrap();
    assert!(matches!(
        block.advance_original_musubi_universal(OriginalMusubiImage::Current, WORK),
        Err(ReadFailure::Predicate(SourceValidationError::Attempt(
            ExecutionAttemptError::Deferred(_)
        )))
    ));
    assert_eq!(
        block.original_musubi_group_read_progress().unwrap(),
        native,
        "the validated package is not reread on scratch retry"
    );
    assert_eq!(
        block.original_musubi_universal_progress(OriginalMusubiImage::Current),
        Some(progress)
    );
    drop(held);
    assert!(
        block
            .advance_original_musubi_universal(OriginalMusubiImage::Current, WORK)
            .unwrap()
            .complete
    );
}

#[test]
fn original_universal_rejection_is_sticky_and_predecessor_validation_is_independent() {
    let (state, proposal) = fixture();
    let mut block = corrupt_pending(&state, proposal.header());
    prepare(&mut block);
    block
        .start_original_musubi_source_admission(limits())
        .unwrap();
    for image in [
        OriginalMusubiImage::Current,
        OriginalMusubiImage::Predecessor,
    ] {
        assert!(
            block
                .advance_original_musubi_source_admission(image, WORK)
                .unwrap()
                .complete
        );
    }
    assert!(
        block
            .advance_original_musubi_universal(OriginalMusubiImage::Predecessor, WORK)
            .unwrap()
            .complete
    );
    let error = block
        .advance_original_musubi_universal(OriginalMusubiImage::Current, WORK)
        .unwrap_err();
    let ReadFailure::Predicate(SourceValidationError::Attempt(ExecutionAttemptError::Rejected(
        original,
    ))) = error
    else {
        panic!("the same canonical resolver predicate must reject the changed current row");
    };
    assert_eq!(original.field(), "world.musubi_resolver_index");
    assert_eq!(
        original.reason(),
        "resolver row diverges from authoritative release/archive projections"
    );
    let native = block.original_musubi_group_read_progress().unwrap();
    let credit = state.ivm_execution_budget().reserved_bytes();
    assert!(
        matches!(block.advance_original_musubi_universal(OriginalMusubiImage::Current, WORK),
        Err(ReadFailure::Predicate(SourceValidationError::Attempt(ExecutionAttemptError::Rejected(retried)))) if retried == original)
    );
    assert_eq!(block.original_musubi_group_read_progress().unwrap(), native);
    assert_eq!(state.ivm_execution_budget().reserved_bytes(), credit);
    assert!(
        !block
            .original_musubi_universal_progress(OriginalMusubiImage::Current)
            .unwrap()
            .complete
    );
}

#[test]
fn configured_original_admission_keeps_the_block_policy_and_cannot_borrow_memory_as_work() {
    use crate::state::deserialize::musubi_source_work::{WorkDimension, WorkRefusal};
    let (mut state, proposal) = fixture();
    let mut configuration = state.pipeline.clone();
    configuration.state_capture.source_table_pass_rows = 0;
    configuration.ivm_execution_max_bytes = state.ivm_execution_budget().limit_bytes();
    state.install_node_pipeline(configuration).unwrap();
    let mut block = pending(&state, proposal.header(), false);
    prepare(&mut block);
    block
        .start_configured_original_musubi_source_admission()
        .unwrap();
    let error = block
        .advance_original_musubi_source_admission(OriginalMusubiImage::Current, WORK)
        .unwrap_err();
    assert!(
        matches!(error, ReadFailure::Predicate(SourceValidationError::Work(
        WorkRefusal::Limit { dimension: WorkDimension::TablePassRows, limit: 0, requested }
    )) if requested > 0)
    );
    let before = block
        .original_musubi_source_admission_progress(OriginalMusubiImage::Current)
        .unwrap();
    let native = block.original_musubi_group_read_progress().unwrap();
    let reserved = state.ivm_execution_budget().reserved_bytes();
    assert_eq!(
        allocations_during(|| {
            assert!(
                block
                    .advance_original_musubi_source_admission(OriginalMusubiImage::Current, WORK)
                    .is_err()
            );
        }),
        0
    );
    assert_eq!(
        block
            .original_musubi_source_admission_progress(OriginalMusubiImage::Current)
            .unwrap(),
        before
    );
    assert_eq!(block.original_musubi_group_read_progress().unwrap(), native);
    assert_eq!(state.ivm_execution_budget().reserved_bytes(), reserved);
}

#[test]
fn original_live_model_prefix_and_directory_scratch_survive_exact_native_refusal() {
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    prepare(&mut block);
    block
        .start_configured_original_musubi_source_admission()
        .unwrap();
    for image in [
        OriginalMusubiImage::Current,
        OriginalMusubiImage::Predecessor,
    ] {
        block
            .advance_original_musubi_source_admission(image, WORK)
            .unwrap();
    }
    let before_measure = block.original_musubi_group_read_progress().unwrap().work;
    block
        .with_original_musubi_rows(WORK, |mut rows, _| {
            rows.musubi_provider_bundle_attestations_current_row(0)
                .unwrap();
        })
        .unwrap();
    let before = block.original_musubi_group_read_progress().unwrap().work;
    let one_resolve = before - before_measure;
    assert!(one_resolve > 0);
    let limit = before + one_resolve;
    assert!(matches!(
        block.advance_original_musubi_live(OriginalMusubiImage::Current, limit),
        Err(ReadFailure::Source(_))
    ));
    let live = block
        .original_musubi_live_progress(OriginalMusubiImage::Current)
        .unwrap();
    assert_eq!(live.phase, 0);
    assert_eq!(live.row, 0);
    assert_eq!(live.step, 1);
    let reserved = state.ivm_execution_budget().reserved_bytes();
    assert_eq!(
        allocations_during(|| {
            assert!(
                block
                    .advance_original_musubi_live(OriginalMusubiImage::Current, limit)
                    .is_err()
            );
        }),
        0
    );
    assert_eq!(
        block
            .original_musubi_live_progress(OriginalMusubiImage::Current)
            .unwrap(),
        live
    );
    assert_eq!(
        block.original_musubi_group_read_progress().unwrap().work,
        limit
    );
    assert_eq!(state.ivm_execution_budget().reserved_bytes(), reserved);
    assert!(
        block
            .advance_original_musubi_live(OriginalMusubiImage::Current, WORK)
            .unwrap()
            .complete
    );
    let done = block.original_musubi_group_read_progress().unwrap().work;
    block
        .advance_original_musubi_live(OriginalMusubiImage::Current, done)
        .unwrap();
    assert_eq!(
        block.original_musubi_group_read_progress().unwrap().work,
        done
    );

    let before_measure = block.original_musubi_group_read_progress().unwrap().work;
    block
        .with_original_musubi_rows(WORK, |mut rows, _| {
            rows.musubi_public_directory_current_row(0).unwrap();
        })
        .unwrap();
    let before = block.original_musubi_group_read_progress().unwrap().work;
    let limit = before + (before - before_measure);
    assert!(matches!(
        block.advance_original_musubi_directory_revisions(OriginalMusubiImage::Current, limit),
        Err(ReadFailure::Source(_))
    ));
    let directory = block
        .original_musubi_directory_progress(OriginalMusubiImage::Current)
        .unwrap();
    assert_eq!(directory.phase, 3);
    assert_eq!(directory.captured, 1);
    let reserved = state.ivm_execution_budget().reserved_bytes();
    assert_eq!(
        allocations_during(|| {
            assert!(
                block
                    .advance_original_musubi_directory_revisions(
                        OriginalMusubiImage::Current,
                        limit
                    )
                    .is_err()
            );
        }),
        0
    );
    assert_eq!(
        block
            .original_musubi_directory_progress(OriginalMusubiImage::Current)
            .unwrap(),
        directory
    );
    assert_eq!(state.ivm_execution_budget().reserved_bytes(), reserved);
    assert!(
        block
            .advance_original_musubi_directory_revisions(OriginalMusubiImage::Current, WORK)
            .unwrap()
            .complete
    );
}

#[test]
fn zero_scheduling_quantum_retains_original_sources_without_fabricating_work_credit() {
    let (mut state, proposal) = fixture();
    let mut node = state.pipeline.clone();
    node.state_capture.native_work_per_attempt = 0;
    state.install_node_pipeline(node).unwrap();
    let mut block = pending(&state, proposal.header(), false);
    start(&mut block, &state.ivm_execution_budget());
    let original = block.original_musubi_group_read_progress().unwrap();
    for _ in 0..2 {
        assert!(matches!(
            block.advance_configured_original_musubi_validation(),
            Err(ReadFailure::Source(RetainedMusubiGroupReadError::Field {
                original: RetainedPackageReadError::Work {
                    used: 0,
                    limit: 0,
                    ..
                },
                ..
            }))
        ));
        let retained = block.original_musubi_group_read_progress().unwrap();
        assert_eq!(retained.work, original.work);
        assert!(!retained.complete);
        assert!(
            block
                .original_musubi_source_admission_progress(OriginalMusubiImage::Current)
                .is_none()
        );
    }
}

#[test]
fn one_unit_configured_grants_complete_both_original_images_without_prefix_starvation() {
    let (mut state, proposal) = fixture();
    let mut node = state.pipeline.clone();
    node.state_capture.native_work_per_attempt = 1;
    state.install_node_pipeline(node).unwrap();
    let mut block = pending(&state, proposal.header(), false);
    start(&mut block, &state.ivm_execution_budget());
    let mut refusals = 0;
    let mut previous_work = 0;
    for attempt in 1..=WORK {
        match block.advance_configured_original_musubi_validation() {
            Ok(()) => {
                assert!(refusals > 1);
                for image in [
                    OriginalMusubiImage::Current,
                    OriginalMusubiImage::Predecessor,
                ] {
                    assert!(
                        block
                            .original_musubi_source_admission_progress(image)
                            .unwrap()
                            .complete
                    );
                    assert!(block.original_musubi_live_progress(image).unwrap().complete);
                    assert!(
                        block
                            .original_musubi_directory_progress(image)
                            .unwrap()
                            .complete
                    );
                    assert!(
                        block
                            .original_musubi_universal_progress(image)
                            .unwrap()
                            .complete
                    );
                }
                let done = block.original_musubi_group_read_progress().unwrap();
                block
                    .advance_configured_original_musubi_validation()
                    .unwrap();
                assert_eq!(block.original_musubi_group_read_progress().unwrap(), done);
                return;
            }
            Err(ReadFailure::Source(RetainedMusubiGroupReadError::Field {
                original:
                    RetainedPackageReadError::Work {
                        used,
                        required,
                        limit,
                    },
                ..
            })) => {
                assert_eq!(limit, attempt, "only the pinned quantum grants work");
                assert!(required > limit);
                assert!(used >= previous_work);
                assert!(used <= limit);
                previous_work = used;
                refusals += 1;
            }
            Err(error) => panic!("unexpected original source refusal: {error:?}"),
        }
    }
    panic!("one-unit grants failed to complete original semantic prerequisites");
}

#[test]
fn configured_work_grants_accumulate_independently_of_consumed_source_work() {
    let (mut state, proposal) = fixture();
    let mut node = state.pipeline.clone();
    node.state_capture.native_work_per_attempt = 7;
    state.install_node_pipeline(node).unwrap();
    let mut block = pending(&state, proposal.header(), false);
    start(&mut block, &state.ivm_execution_budget());
    let original = block.original_musubi_group_read_progress().unwrap();
    for expected in [7, 14, 21] {
        assert_eq!(
            block.grant_original_musubi_capture_attempt().unwrap(),
            expected,
            "configured grants must accumulate from prior authority, never consumed work"
        );
        assert_eq!(
            block.original_musubi_group_read_progress().unwrap(),
            original
        );
    }
}
