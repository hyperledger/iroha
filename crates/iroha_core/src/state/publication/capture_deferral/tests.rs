//! Capture classification keeps local limits, original custody and semantic rejection distinct.

use super::*;
use crate::{
    state::deserialize::{
        musubi_rejection::{ProjectionRejection, ProjectionTable},
        musubi_source_work::WorkDimension,
    },
    sumeragi::driver::traits::PublicationDeferral,
    test_allocations::allocations_during,
};
use iroha_allocation::{AllocationBudget, InsufficientReservation};

fn deferred(error: TransactionsBlockError) -> StateCaptureDeferral {
    let TransactionsBlockError::CaptureDeferred(original) = error else {
        panic!("expected the original typed capture refusal: {error:?}");
    };
    original
}

#[test]
fn capture_native_and_encoding_work_keep_exact_observations_without_wakes() {
    let mut result = None;
    assert_eq!(
        allocations_during(|| {
            result = Some(deferred(source_refusal(
                RetainedMusubiGroupReadError::Field {
                    field: "musubi_packages",
                    original: RetainedPackageReadError::Work {
                        used: 9,
                        required: 27,
                        limit: 11,
                    },
                },
            )));
        }),
        0
    );
    let source = result.unwrap();
    assert_eq!(source.field(), Some("musubi_packages"));
    assert_eq!(source.native_work(), Some((9, 27, 11)));
    assert_eq!(source.encoding_work(), None);
    assert!(source.buffer_refusal().is_none());
    assert!(source.allocation_refusal().is_none());
    assert!(source.release_wait().is_none());
    let encoding = deferred(materialization_refusal(FrozenMusubiError::Encoding(
        RetainedSemanticError::Work {
            used: 14,
            required: 91,
            limit: 44,
        },
    )));
    assert_eq!(encoding.encoding_work(), Some((14, 91, 44)));
    assert_eq!(encoding.native_work(), None);
    assert_eq!(encoding.field(), None);
    let driver = PublicationDeferral::StateCapture(encoding);
    assert_eq!(
        driver.state_capture().unwrap().encoding_work(),
        Some((14, 91, 44))
    );
    assert!(driver.execution().is_none());
    assert!(driver.allocation_refusal().is_none());
    assert!(driver.release_wait().is_none());
}

#[test]
fn capture_actual_pool_refusal_keeps_each_original_encoding_source_and_release() {
    let budget = AllocationBudget::new(64);
    let occupied = budget.try_reserve_bytes(64).unwrap();
    for path in 0..4 {
        let original = budget.try_reserve_bytes(1).unwrap_err();
        let expected = original.clone();
        let error = match path {
            0 => source_refusal(RetainedMusubiGroupReadError::Control(
                ChargedBufferError::Admission(original),
            )),
            1 => source_refusal(RetainedMusubiGroupReadError::Field {
                field: "musubi_packages",
                original: RetainedPackageReadError::Allocation(ChargedBufferError::Admission(
                    original,
                )),
            }),
            2 => materialization_refusal(FrozenMusubiError::Encoding(
                RetainedSemanticError::Table(LeafError::Admission(original)),
            )),
            _ => {
                materialization_refusal(FrozenMusubiError::Encoding(RetainedSemanticError::Table(
                    LeafError::OrderedRange(NoritoKeyRangeError::Admission(original)),
                )))
            }
        };
        let driver = PublicationDeferral::StateCapture(deferred(error));
        assert_eq!(driver.allocation_refusal(), Some(&expected));
        let AllocationRefusal::Capacity { release, .. } = &expected else {
            panic!("actual capacity refusal")
        };
        assert_eq!(driver.release_wait(), Some(release));
        let owner = driver.state_capture().unwrap();
        let cause = std::error::Error::source(owner).expect("unchanged original error source");
        if path < 2 {
            let retained = cause.downcast_ref::<ChargedBufferError>().unwrap();
            assert!(std::ptr::eq(retained, owner.buffer_refusal().unwrap()));
        } else {
            assert!(cause.downcast_ref::<RetainedSemanticError>().is_some());
        }
        assert_eq!(budget.reserved_bytes(), 64);
    }
    drop(occupied);
    assert_eq!(budget.reserved_bytes(), 0);
    let retry = budget.try_reserve_bytes(1).unwrap();
    drop(retry);
}

#[test]
fn capture_local_readers_policy_and_fixed_limits_never_fabricate_release_events() {
    let cases = [
        source_refusal(RetainedMusubiGroupReadError::WorkGrantOverflow),
        source_refusal(RetainedMusubiGroupReadError::ReadersRetained {
            field: "musubi_packages",
        }),
        source_refusal(RetainedMusubiGroupReadError::Field {
            field: "musubi_packages",
            original: RetainedPackageReadError::ReadersRetained,
        }),
        validation_refusal(ReadFailure::Predicate(SourceValidationError::Work(
            WorkRefusal::Limit {
                dimension: WorkDimension::SignatureChecks,
                requested: 7,
                limit: 2,
            },
        ))),
        validation_refusal(ReadFailure::Predicate(SourceValidationError::Work(
            WorkRefusal::Overflow(WorkDimension::TablePassRows),
        ))),
        materialization_refusal(FrozenMusubiError::Encoding(RetainedSemanticError::Overflow)),
    ];
    for original in [
        LeafError::TableLimit,
        LeafError::RowLimit,
        LeafError::PayloadLimit,
        LeafError::StreamedTableLimit,
        LeafError::Allocation,
        LeafError::LookupAllocation(PrepaidSharedError::Allocator {
            requested_bytes: 127,
        }),
        LeafError::LookupAllocation(PrepaidSharedError::Reservation(InsufficientReservation {
            requested_bytes: 12,
            remaining_bytes: 1,
        })),
        LeafError::OrderedRange(NoritoKeyRangeError::Capacity),
        LeafError::OrderedRange(NoritoKeyRangeError::Allocation),
        LeafError::OrderedRange(NoritoKeyRangeError::PrepaidCapacity(
            InsufficientReservation {
                requested_bytes: 12,
                remaining_bytes: 1,
            },
        )),
    ] {
        let expected_shared = match &original {
            LeafError::LookupAllocation(original) => Some(*original),
            _ => None,
        };
        let owner = deferred(materialization_refusal(FrozenMusubiError::Encoding(
            RetainedSemanticError::Table(original),
        )));
        assert_eq!(owner.shared_refusal(), expected_shared.as_ref());
        assert!(owner.release_wait().is_none());
        assert!(owner.allocation_refusal().is_none());
    }
    for error in cases {
        let owner = deferred(error);
        assert!(owner.allocation_refusal().is_none());
        assert!(owner.release_wait().is_none());
        assert!(!owner.to_string().is_empty());
    }
}

#[test]
fn capture_changed_source_and_invalid_canonical_rows_require_recovery() {
    for original in [
        RetainedMusubiGroupReadError::NotFrozen,
        RetainedMusubiGroupReadError::SourceChanged,
        RetainedMusubiGroupReadError::ScopeIdentity,
        RetainedMusubiGroupReadError::SemanticAlreadyStarted,
        RetainedMusubiGroupReadError::Incomplete,
    ] {
        assert!(matches!(
            source_refusal(original),
            TransactionsBlockError::SnapshotObservationChanged
        ));
    }
    for original in [
        RetainedPackageReadError::NotFrozen,
        RetainedPackageReadError::SourceChanged,
        RetainedPackageReadError::ScopeIdentity,
        RetainedPackageReadError::Geometry,
        RetainedPackageReadError::Incomplete,
    ] {
        assert!(matches!(
            source_refusal(RetainedMusubiGroupReadError::Field {
                field: "musubi_packages",
                original,
            }),
            TransactionsBlockError::SnapshotObservationChanged
        ));
    }
    for original in [
        FrozenMusubiError::Changed,
        FrozenMusubiError::Encoding(RetainedSemanticError::ScopeIdentity),
        FrozenMusubiError::Encoding(RetainedSemanticError::Phase),
        FrozenMusubiError::Encoding(RetainedSemanticError::Table(LeafError::OrderedRange(
            NoritoKeyRangeError::UnsortedKeys,
        ))),
        FrozenMusubiError::Encoding(RetainedSemanticError::Table(LeafError::TypeMismatch(
            "world.musubi_packages",
        ))),
    ] {
        assert!(matches!(
            materialization_refusal(original),
            TransactionsBlockError::SnapshotObservationChanged
        ));
    }
}

#[test]
fn capture_semantic_rejection_is_distinct_from_the_original_execution_deferral() {
    let rejected = validation_refusal(ReadFailure::Predicate(SourceValidationError::Attempt(
        ExecutionAttemptError::Rejected(ProjectionRejection::new(
            ProjectionTable::Archives,
            "original semantic rejection",
        )),
    )));
    assert!(matches!(
        rejected,
        TransactionsBlockError::WorldCommitPreparation
    ));
    let budget = AllocationBudget::new(64);
    let occupied = budget.try_reserve_bytes(64).unwrap();
    let original = budget.try_reserve_bytes(1).unwrap_err();
    let expected = original.clone();
    let deferred = validation_refusal(ReadFailure::Predicate(SourceValidationError::Attempt(
        ExecutionAttemptError::Deferred(original.into()),
    )));
    let TransactionsBlockError::ExecutionDeferred(original) = deferred else {
        panic!("original execution cause")
    };
    assert_eq!(original.allocation_refusal(), Some(&expected));
    drop(occupied);
}
