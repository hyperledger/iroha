//! Actual StatePublication retains every original physical Musubi map on refusal.
//!
//! These controls prove exact retained revision EBR allocation identity alongside
//! the fourteen physical pairs. Ordered descriptor controls also compare complete
//! original predecessor rows; none authenticates Musubi relations or complete State.

use super::{fixture, staged_block};
use crate::{
    state::{
        State, StateBlock, StatePublicationOutcome,
        publication::{RetainedMusubiGroupReadError, RetainedPackageReadError},
        storage_transactions,
    },
    test_allocations::allocations_during,
};
use concread::bptree::BptreeMapRowPosition;
use iroha_allocation::{AllocationBudget, ChargedBufferError};
use iroha_data_model::{
    block::BlockHeader,
    musubi::{ArchiveId, MusubiArchiveAvailabilityV1, MusubiArchiveRecordV1},
};
use std::alloc::Layout;

fn pending(state: &State, header: BlockHeader, replacement: bool) -> Box<StateBlock<'_>> {
    let mut block = Box::new(staged_block(state, header, replacement, true));
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
fn start(block: &mut StateBlock<'_>, budget: &AllocationBudget) {
    block
        .start_original_musubi_group_read(budget.try_owned_refund_scope().unwrap())
        .unwrap_or_else(|(_, cause)| panic!("original group scope: {cause:?}"));
}

#[test]
fn original_musubi_group_retains_all_fourteen_pairs_and_borrows_frozen_revision() {
    for replacement in [false, true] {
        let (state, proposal) = fixture();
        if replacement {
            staged_block(&state, proposal.header(), false, true)
                .commit()
                .unwrap();
        }
        let mut block = pending(&state, proposal.header(), replacement);
        let budget = state.ivm_execution_budget();
        let original = std::ptr::from_ref(&*block);
        // Independent original-row pointer observations are test-only; production
        // never constructs this uncharged metadata or uses pointer authority.
        let expected: [(Vec<usize>, Vec<usize>); 14] = [
            {
                let images = block.world.musubi_archives.frozen_images().unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
            {
                let images = block
                    .world
                    .musubi_archive_availability
                    .frozen_images()
                    .unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
            {
                let images = block
                    .world
                    .musubi_archive_locations
                    .frozen_images()
                    .unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
            {
                let images = block.world.musubi_locations_by_pin.frozen_images().unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
            {
                let images = block
                    .world
                    .musubi_locations_by_provider
                    .frozen_images()
                    .unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
            {
                let images = block
                    .world
                    .musubi_locations_by_replication_order
                    .frozen_images()
                    .unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
            {
                let images = block.world.musubi_packages.frozen_images().unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
            {
                let images = block
                    .world
                    .musubi_provider_bundle_attestations
                    .frozen_images()
                    .unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
            {
                let images = block.world.musubi_public_directory.frozen_images().unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
            {
                let images = block.world.musubi_releases.frozen_images().unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
            {
                let images = block.world.musubi_resolver_index.frozen_images().unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
            {
                let images = block.world.pin_manifests.frozen_images().unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
            {
                let images = block.world.provider_owners.frozen_images().unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
            {
                let images = block.world.replication_orders.frozen_images().unwrap();
                (
                    images
                        .current_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                    images
                        .undo_entries()
                        .map(|(_, value)| std::ptr::from_ref(value).addr())
                        .collect(),
                )
            },
        ];
        let revision = {
            let (current, before) = block
                .world
                .musubi_resolver_index_revision
                .frozen_values()
                .unwrap();
            (
                std::ptr::from_ref(current).addr(),
                std::ptr::from_ref(before).addr(),
                current.get(),
                before.get(),
            )
        };
        start(&mut block, &budget);
        let completed = block
            .advance_original_musubi_group_read(usize::MAX)
            .unwrap();
        assert!(completed.complete);
        for (index, (current, undo)) in expected.iter().enumerate() {
            assert_eq!(completed.tables[index].current, current.len());
            assert_eq!(completed.tables[index].undo, undo.len());
            assert!(completed.tables[index].complete);
        }
        let allocations = allocations_during(|| {
            block
                .with_original_musubi_rows(usize::MAX, |mut rows, borrowed| {
                    assert_eq!(std::ptr::from_ref(borrowed.current()).addr(), revision.0);
                    assert_eq!(
                        std::ptr::from_ref(borrowed.predecessor()).addr(),
                        revision.1
                    );
                    assert_eq!(borrowed.current().get(), revision.2);
                    assert_eq!(borrowed.predecessor().get(), revision.3);
                    for (index, pointer) in expected[0].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(rows.musubi_archives_current_row(index).unwrap().1)
                                .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[0].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(rows.musubi_archives_undo_row(index).unwrap().1)
                                .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[1].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_archive_availability_current_row(index)
                                    .unwrap()
                                    .1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[1].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_archive_availability_undo_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[2].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_archive_locations_current_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[2].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_archive_locations_undo_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[3].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_locations_by_pin_current_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[3].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_locations_by_pin_undo_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[4].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_locations_by_provider_current_row(index)
                                    .unwrap()
                                    .1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[4].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_locations_by_provider_undo_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[5].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_locations_by_replication_order_current_row(index)
                                    .unwrap()
                                    .1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[5].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_locations_by_replication_order_undo_row(index)
                                    .unwrap()
                                    .1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[6].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(rows.musubi_packages_current_row(index).unwrap().1)
                                .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[6].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(rows.musubi_packages_undo_row(index).unwrap().1)
                                .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[7].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_provider_bundle_attestations_current_row(index)
                                    .unwrap()
                                    .1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[7].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_provider_bundle_attestations_undo_row(index)
                                    .unwrap()
                                    .1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[8].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_public_directory_current_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[8].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_public_directory_undo_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[9].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(rows.musubi_releases_current_row(index).unwrap().1)
                                .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[9].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(rows.musubi_releases_undo_row(index).unwrap().1)
                                .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[10].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_resolver_index_current_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[10].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_resolver_index_undo_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[11].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(rows.pin_manifests_current_row(index).unwrap().1)
                                .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[11].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(rows.pin_manifests_undo_row(index).unwrap().1)
                                .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[12].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(rows.provider_owners_current_row(index).unwrap().1)
                                .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[12].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(rows.provider_owners_undo_row(index).unwrap().1)
                                .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[13].0.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.replication_orders_current_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    for (index, pointer) in expected[13].1.iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(rows.replication_orders_undo_row(index).unwrap().1)
                                .addr(),
                            *pointer
                        );
                    }
                })
                .unwrap();
        });
        assert_eq!(
            allocations, 0,
            "borrow/resolve/callback copies no original row or map"
        );
        assert_eq!(std::ptr::from_ref(&*block), original);
        assert!(
            matches!(block.try_publish(),StatePublicationOutcome::Deferred(storage_transactions::TransactionsBlockError::ExecutionDeferred(ref cause)) if cause.reason()==ivm::error::ExecutionDeferral::LocalInvariantViolation && cause.allocation_refusal().is_none())
        );
        block.retire_original_musubi_group_read().unwrap();
        let retired = block.original_musubi_group_read_progress().unwrap();
        assert!(retired.retired);
        assert_eq!(retired.retired_tables, 14);
        assert!(matches!(
            block.try_publish(),
            StatePublicationOutcome::Published
        ));
        assert!(matches!(
            block.with_original_musubi_rows(usize::MAX, |_, _| ()),
            Err(RetainedMusubiGroupReadError::NotFrozen)
        ));
    }
}

#[test]
fn original_musubi_group_later_table_refusal_retains_completed_pair_and_exact_pool() {
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    let budget = state.ivm_execution_budget();
    let (current_count, undo_count, pointer) = {
        let images = block.world.musubi_archives.frozen_images().unwrap();
        (
            images.current_entries().len(),
            images.undo_entries().len(),
            std::ptr::from_ref(images.current_entries().next().unwrap().1),
        )
    };
    let availability_count = block
        .world
        .musubi_archive_availability
        .frozen_images()
        .unwrap()
        .current_entries()
        .len();
    assert!(current_count > 0 && undo_count > 0 && availability_count > 0);
    start(&mut block, &budget);
    let control = budget.reserved_bytes();
    let first =
        Layout::array::<BptreeMapRowPosition<ArchiveId, MusubiArchiveRecordV1>>(current_count)
            .unwrap()
            .size()
            + Layout::array::<BptreeMapRowPosition<ArchiveId, Option<MusubiArchiveRecordV1>>>(
                undo_count,
            )
            .unwrap()
            .size();
    let later = Layout::array::<BptreeMapRowPosition<ArchiveId, MusubiArchiveAvailabilityV1>>(
        availability_count,
    )
    .unwrap();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - control - first)
        .unwrap();
    let Err(RetainedMusubiGroupReadError::Field {
        field,
        original: RetainedPackageReadError::Allocation(ChargedBufferError::Admission(actual)),
    }) = block.advance_original_musubi_group_read(usize::MAX)
    else {
        panic!("later original availability backing must refuse after original archive pair");
    };
    assert_eq!(field, "musubi_archive_availability");
    assert_eq!(
        actual,
        budget.try_reserve(later).unwrap_err(),
        "actual original pool/release cause"
    );
    let prefix = block.original_musubi_group_read_progress().unwrap();
    assert!(prefix.tables[0].complete);
    assert_eq!(prefix.tables[0].current, current_count);
    assert_eq!(prefix.tables[0].undo, undo_count);
    assert_eq!(prefix.tables[1].current, 0);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    let allocations = allocations_during(|| {
        assert!(matches!(
            block.advance_original_musubi_group_read(usize::MAX),
            Err(RetainedMusubiGroupReadError::Field {
                field: "musubi_archive_availability",
                ..
            })
        ));
        assert_eq!(block.original_musubi_group_read_progress().unwrap(), prefix);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    });
    assert_eq!(
        allocations, 0,
        "no completed pair/backing is rebuilt on refusal retry"
    );
    drop(occupied);
    assert!(
        block
            .advance_original_musubi_group_read(usize::MAX)
            .unwrap()
            .complete
    );
    block
        .with_original_musubi_rows(usize::MAX, |mut rows, _| {
            assert_eq!(
                std::ptr::from_ref(rows.musubi_archives_current_row(0).unwrap().1),
                pointer
            )
        })
        .unwrap();
    block.retire_original_musubi_group_read().unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        control - crate::state::publication::retained_musubi_group_control_layout_for_test().size()
    );
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Published
    ));
}

#[test]
fn original_musubi_group_work_and_callback_refusal_keep_cumulative_original_prefix() {
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    let budget = state.ivm_execution_budget();
    let first = {
        let images = block.world.musubi_archives.frozen_images().unwrap();
        images.current_entries().len() + images.undo_entries().len()
    };
    let limit = first
        .checked_mul(3 * (usize::try_from(usize::BITS).unwrap() + 1))
        .unwrap();
    start(&mut block, &budget);
    assert!(
        matches!(block.advance_original_musubi_group_read(limit),Err(RetainedMusubiGroupReadError::Field{field:"musubi_archive_availability",original:RetainedPackageReadError::Work{used,..}}) if used==limit)
    );
    let prefix = block.original_musubi_group_read_progress().unwrap();
    let credit = budget.reserved_bytes();
    assert!(prefix.tables[0].complete);
    assert!(matches!(
        block.with_original_musubi_rows(usize::MAX, |_, _| ()),
        Err(RetainedMusubiGroupReadError::Incomplete)
    ));
    let allocations = allocations_during(|| {
        assert!(
            matches!(block.advance_original_musubi_group_read(limit),Err(RetainedMusubiGroupReadError::Field{field:"musubi_archive_availability",original:RetainedPackageReadError::Work{used,..}}) if used==limit)
        );
        assert_eq!(block.original_musubi_group_read_progress().unwrap(), prefix);
        assert_eq!(budget.reserved_bytes(), credit);
    });
    assert_eq!(allocations, 0);
    let completed = block
        .advance_original_musubi_group_read(usize::MAX)
        .unwrap();
    assert!(completed.complete && completed.work > prefix.work);
    let before = completed.work;
    let refusal = block
        .with_original_musubi_rows(before, |mut rows, _| {
            rows.musubi_archives_current_row(0).map(|_| ())
        })
        .unwrap();
    assert!(
        matches!(refusal,Err(RetainedMusubiGroupReadError::Field{field:"musubi_archives",original:RetainedPackageReadError::Work{used,..}}) if used==before)
    );
    assert_eq!(
        block.original_musubi_group_read_progress().unwrap().work,
        before
    );
    let result = block
        .with_original_musubi_rows(usize::MAX, |mut rows, _| {
            rows.musubi_archives_current_row(0)?;
            Err::<(), _>(RetainedMusubiGroupReadError::Incomplete)
        })
        .unwrap();
    assert!(matches!(
        result,
        Err(RetainedMusubiGroupReadError::Incomplete)
    ));
    let after = block.original_musubi_group_read_progress().unwrap();
    assert!(after.work > before && after.complete);
    assert_eq!(after.tables[0].current, completed.tables[0].current);
    block.retire_original_musubi_group_read().unwrap();
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Published
    ));
}

#[test]
fn original_musubi_group_foreign_scope_or_changed_source_cannot_reacquire() {
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    let budget = state.ivm_execution_budget();
    let foreign = AllocationBudget::new(budget.limit_bytes());
    let scope = foreign.try_owned_refund_scope().unwrap();
    let credit = foreign.reserved_bytes();
    let (scope, cause) = block.start_original_musubi_group_read(scope).unwrap_err();
    assert!(matches!(cause, RetainedMusubiGroupReadError::ScopeIdentity));
    assert!(scope.belongs_to(&foreign));
    assert_eq!(foreign.reserved_bytes(), credit);
    assert!(block.world.musubi_archives.frozen_images().is_some());
    drop(scope);
    assert_eq!(foreign.reserved_bytes(), 0);
    start(&mut block, &budget);
    assert!(matches!(
        block.advance_original_musubi_group_read(0),
        Err(RetainedMusubiGroupReadError::Field {
            original: RetainedPackageReadError::Work { .. },
            ..
        })
    ));
    let prefix = block.original_musubi_group_read_progress().unwrap();
    let credit = budget.reserved_bytes();
    state.with_held_view_publication_for_reader_test(|_| {});
    assert!(matches!(
        block.advance_original_musubi_group_read(usize::MAX),
        Err(RetainedMusubiGroupReadError::SourceChanged)
    ));
    assert!(matches!(
        block.retire_original_musubi_group_read(),
        Err(RetainedMusubiGroupReadError::SourceChanged)
    ));
    assert_eq!(block.original_musubi_group_read_progress().unwrap(), prefix);
    assert_eq!(budget.reserved_bytes(), credit);
}

#[test]
fn original_musubi_group_partial_thaw_retains_scope_until_actual_outside_reader_retires() {
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    let budget = state.ivm_execution_budget();
    start(&mut block, &budget);
    block
        .advance_original_musubi_group_read(usize::MAX)
        .unwrap();
    let reader = block.retain_group_package_reader_for_test().unwrap();
    let credit = budget.reserved_bytes();
    assert!(matches!(
        block.retire_original_musubi_group_read(),
        Err(RetainedMusubiGroupReadError::ReadersRetained {
            field: "musubi_packages"
        })
    ));
    let prefix = block.original_musubi_group_read_progress().unwrap();
    assert_eq!(prefix.retired_tables, 6);
    assert!(!prefix.retired);
    let retained = budget.reserved_bytes();
    assert!(
        retained < credit,
        "actual indexes/control retire before their original refund scope"
    );
    let allocations = allocations_during(|| {
        assert!(matches!(
            block.retire_original_musubi_group_read(),
            Err(RetainedMusubiGroupReadError::ReadersRetained {
                field: "musubi_packages"
            })
        ));
        assert_eq!(block.original_musubi_group_read_progress().unwrap(), prefix);
        assert_eq!(budget.reserved_bytes(), retained);
    });
    assert_eq!(allocations, 0);
    assert!(
        matches!(block.try_publish(),StatePublicationOutcome::Deferred(storage_transactions::TransactionsBlockError::ExecutionDeferred(ref cause)) if cause.reason()==ivm::error::ExecutionDeferral::LocalInvariantViolation && cause.allocation_refusal().is_none())
    );
    drop(reader);
    block.retire_original_musubi_group_read().unwrap();
    assert_eq!(
        block
            .original_musubi_group_read_progress()
            .unwrap()
            .retired_tables,
        14
    );
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Published
    ));
}

#[test]
fn original_musubi_group_foreign_frozen_revision_refuses_without_copied_authority() {
    use crate::state::MusubiResolverIndexRevisionV1;
    use crate::state::block_field::BlockField;
    let (state, proposal) = fixture();
    let foreign = mv::cell::Cell::<MusubiResolverIndexRevisionV1>::new(
        MusubiResolverIndexRevisionV1::new(2).unwrap(),
    );
    let mut block = pending(&state, proposal.header(), false);
    let current = *block
        .world
        .musubi_resolver_index_revision
        .frozen_values()
        .unwrap()
        .0;
    assert_eq!(
        *foreign.view().get(),
        current,
        "equal values cannot grant original owner authority"
    );
    let mut foreign_field = BlockField::new(foreign.block());
    foreign_field.begin_freeze();
    foreign_field.finish_freeze();
    foreign_field.retire_frozen_cleanup();
    let original = std::mem::replace(
        &mut block
            .fields
            .as_mut()
            .expect("original frozen fields for adversarial substitution")
            .world
            .musubi_resolver_index_revision,
        foreign_field,
    );
    let budget = state.ivm_execution_budget();
    let scope = budget.try_owned_refund_scope().unwrap();
    let credit = budget.reserved_bytes();
    let (scope, cause) = block.start_original_musubi_group_read(scope).unwrap_err();
    assert!(matches!(cause, RetainedMusubiGroupReadError::SourceChanged));
    assert!(scope.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), credit);
    assert!(block.world.musubi_archives.frozen_images().is_some());
    // Restore the same original field, not a copied revision or fresh acquisition.
    drop(std::mem::replace(
        &mut block
            .fields
            .as_mut()
            .expect("same original frozen fields")
            .world
            .musubi_resolver_index_revision,
        original,
    ));
    block
        .start_original_musubi_group_read(scope)
        .unwrap_or_else(|(_, cause)| panic!("original revision: {cause:?}"));
    block
        .advance_original_musubi_group_read(usize::MAX)
        .unwrap();
    block.retire_original_musubi_group_read().unwrap();
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Published
    ));
}

#[test]
fn original_musubi_group_callback_state_publication_refuses_and_drops_exact_result() {
    use std::cell::Cell;

    struct Returned<'a>(&'a Cell<usize>);
    impl Drop for Returned<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    let budget = state.ivm_execution_budget();
    let owner = std::ptr::from_ref(&*block);
    start(&mut block, &budget);
    let completed = block
        .advance_original_musubi_group_read(usize::MAX)
        .unwrap();
    assert!(completed.complete);
    let generation = state.state_view_generation();
    let stable_drops = Cell::new(0);
    let stable_result = block
        .with_original_musubi_rows(usize::MAX, |_, _| Returned(&stable_drops))
        .unwrap();
    assert_eq!(
        stable_drops.get(),
        0,
        "stable cut returns its exact original value alive"
    );
    drop(stable_result);
    assert_eq!(stable_drops.get(), 1);
    let drops = Cell::new(0);
    let calls = Cell::new(0);
    let result = block.with_original_musubi_rows(usize::MAX, |mut rows, revision| {
        calls.set(calls.get() + 1);
        let original = std::ptr::from_ref(rows.musubi_archives_current_row(0).unwrap().1);
        let original_revision = std::ptr::from_ref(revision.current());
        assert_eq!(state.committed_height(), 0);
        // This is a genuine independent publication through the existing State
        // commit path, not a synthetic generation/value or replaced read source.
        staged_block(&state, proposal.header(), false, false)
            .commit()
            .unwrap();
        assert_eq!(
            state.committed_height(),
            usize::try_from(proposal.header().height().get()).unwrap()
        );
        assert_eq!(
            state.latest_block_hash_fast(),
            Some(proposal.header().hash())
        );
        assert_ne!(state.state_view_generation(), generation);
        assert_eq!(
            std::ptr::from_ref(rows.musubi_archives_current_row(0).unwrap().1),
            original
        );
        assert_eq!(std::ptr::from_ref(revision.current()), original_revision);
        assert_eq!(drops.get(), 0);
        Returned(&drops)
    });
    assert!(
        matches!(result, Err(RetainedMusubiGroupReadError::SourceChanged)),
        "a callback spanning an actual State publication must not return success"
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(
        drops.get(),
        1,
        "the exact callback result retires on source refusal"
    );
    assert_eq!(std::ptr::from_ref(&*block), owner);
    let retained = block.original_musubi_group_read_progress().unwrap();
    assert!(retained.complete && !retained.retired && retained.work > completed.work);
    for (before, after) in completed.tables.iter().zip(retained.tables) {
        assert_eq!(before.current, after.current);
        assert_eq!(before.undo, after.undo);
        assert_eq!(before.complete, after.complete);
        assert!(!after.retired);
    }
    let credit = budget.reserved_bytes();
    let allocations = allocations_during(|| {
        assert!(matches!(
            block.with_original_musubi_rows(usize::MAX, |_, _| {
                calls.set(calls.get() + 1);
                Returned(&drops)
            }),
            Err(RetainedMusubiGroupReadError::SourceChanged)
        ));
        assert!(matches!(
            block.retire_original_musubi_group_read(),
            Err(RetainedMusubiGroupReadError::SourceChanged)
        ));
        assert_eq!(
            block.original_musubi_group_read_progress().unwrap(),
            retained
        );
        assert_eq!(budget.reserved_bytes(), credit);
    });
    assert_eq!(
        allocations, 0,
        "stale retry retains the original graph without new work/backing"
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(drops.get(), 1);
}

#[test]
fn original_musubi_group_equal_same_predecessor_revision_substitution_retains_original_pair() {
    use crate::state::block_field::BlockField;
    use std::cell::Cell;
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    let budget = state.ivm_execution_budget();
    start(&mut block, &budget);
    let completed = block
        .advance_original_musubi_group_read(usize::MAX)
        .unwrap();
    assert!(completed.complete);
    let (current, before) = block
        .world
        .musubi_resolver_index_revision
        .frozen_values()
        .unwrap();
    let original = (std::ptr::from_ref(current), std::ptr::from_ref(before));
    let value = *current;
    let identity = block
        .world
        .musubi_resolver_index_revision
        .publication_identity();
    let generation = state.state_view_generation();
    let mut equal = BlockField::new(state.world.musubi_resolver_index_revision.block());
    *equal.get_mut() = value;
    equal.begin_freeze();
    equal.finish_freeze();
    equal.retire_frozen_cleanup();
    assert_eq!(
        equal.publication_identity(),
        identity,
        "actual same target and predecessor"
    );
    assert_eq!(
        equal.frozen_values(),
        block.world.musubi_resolver_index_revision.frozen_values()
    );
    assert_ne!(
        std::ptr::from_ref(equal.frozen_values().unwrap().0),
        original.0
    );
    assert_eq!(state.state_view_generation(), generation);
    let original_field = std::mem::replace(
        &mut block
            .fields
            .as_mut()
            .expect("original frozen fields for adversarial substitution")
            .world
            .musubi_resolver_index_revision,
        equal,
    );
    let credit = budget.reserved_bytes();
    let calls = Cell::new(0);
    let allocations = allocations_during(|| {
        assert!(
            matches!(
                block.with_original_musubi_rows(usize::MAX, |_, _| {
                    calls.set(calls.get() + 1);
                }),
                Err(RetainedMusubiGroupReadError::SourceChanged)
            ),
            "equal revision under the same predecessor must not replace actual staged allocations"
        );
        assert!(matches!(
            block.advance_original_musubi_group_read(usize::MAX),
            Err(RetainedMusubiGroupReadError::SourceChanged)
        ));
        assert!(matches!(
            block.retire_original_musubi_group_read(),
            Err(RetainedMusubiGroupReadError::SourceChanged)
        ));
        assert_eq!(
            block.original_musubi_group_read_progress().unwrap(),
            completed
        );
        assert_eq!(budget.reserved_bytes(), credit);
    });
    assert_eq!(allocations, 0);
    assert_eq!(calls.get(), 0);
    drop(std::mem::replace(
        &mut block
            .fields
            .as_mut()
            .expect("same original frozen fields")
            .world
            .musubi_resolver_index_revision,
        original_field,
    ));
    block
        .with_original_musubi_rows(usize::MAX, |_, revision| {
            assert_eq!(std::ptr::from_ref(revision.current()), original.0);
            assert_eq!(std::ptr::from_ref(revision.predecessor()), original.1);
        })
        .unwrap();
    block.retire_original_musubi_group_read().unwrap();
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Published
    ));
}

#[test]
fn original_musubi_group_revision_reader_refusal_retains_completed_tables_and_exact_scope() {
    for current in [false, true] {
        let (state, proposal) = fixture();
        let mut block = pending(&state, proposal.header(), false);
        let budget = state.ivm_execution_budget();
        let foreign = AllocationBudget::new(budget.limit_bytes());
        start(&mut block, &budget);
        let completed = block
            .advance_original_musubi_group_read(usize::MAX)
            .unwrap();
        assert!(completed.complete);
        let (revision, before) = block
            .world
            .musubi_resolver_index_revision
            .frozen_values()
            .unwrap();
        let pointers = (std::ptr::from_ref(revision), std::ptr::from_ref(before));
        let identity = block
            .world
            .musubi_resolver_index_revision
            .publication_identity();
        let reader = block
            .retain_group_revision_reader_for_test(current)
            .unwrap();
        assert!(reader.scope_belongs_to(&budget));
        assert!(!reader.scope_belongs_to(&foreign));
        let credit = budget.reserved_bytes();
        assert!(
            matches!(
                block.retire_original_musubi_group_read(),
                Err(RetainedMusubiGroupReadError::ReadersRetained {
                    field: "musubi_resolver_index_revision"
                })
            ),
            "actual retained revision reader must refuse group retirement"
        );
        let prefix = block.original_musubi_group_read_progress().unwrap();
        assert_eq!(prefix.retired_tables, 14);
        assert!(!prefix.retired && prefix.complete);
        assert_eq!(prefix.work, completed.work);
        let retained = budget.reserved_bytes();
        assert!(
            retained < credit,
            "actual table indexes/control retire before original scope"
        );
        assert!(
            retained > 0,
            "original scope remains retained with the actual revision reader"
        );
        let allocations = allocations_during(|| {
            for _ in 0..3 {
                assert!(matches!(
                    block.retire_original_musubi_group_read(),
                    Err(RetainedMusubiGroupReadError::ReadersRetained {
                        field: "musubi_resolver_index_revision"
                    })
                ));
                assert_eq!(block.original_musubi_group_read_progress().unwrap(), prefix);
                assert_eq!(budget.reserved_bytes(), retained);
                let (revision, before) = block
                    .world
                    .musubi_resolver_index_revision
                    .frozen_values()
                    .unwrap();
                assert_eq!(
                    (std::ptr::from_ref(revision), std::ptr::from_ref(before)),
                    pointers
                );
                assert_eq!(
                    block
                        .world
                        .musubi_resolver_index_revision
                        .publication_identity(),
                    identity
                );
            }
        });
        assert_eq!(
            allocations, 0,
            "partial thaw retry adds neither backing nor work"
        );
        assert!(
            matches!(block.try_publish(),StatePublicationOutcome::Deferred(storage_transactions::TransactionsBlockError::ExecutionDeferred(ref cause))
            if cause.reason()==ivm::error::ExecutionDeferral::LocalInvariantViolation && cause.allocation_refusal().is_none())
        );
        drop(reader);
        let allocations = allocations_during(|| block.retire_original_musubi_group_read().unwrap());
        assert_eq!(allocations, 0);
        let retired = block.original_musubi_group_read_progress().unwrap();
        assert!(retired.retired && retired.retired_tables == 14);
        assert_eq!(retired.work, prefix.work);
        assert!(matches!(
            block.try_publish(),
            StatePublicationOutcome::Published
        ));
    }
}

// Independent test-only overlay over the actual original pair. This allocates
// outside the observed production kernel; it grants no source or State authority.
fn original_predecessor_pointers<K: mv::Key, V: mv::Value>(
    images: mv::storage::FrozenStorageImages<'_, K, V>,
) -> Vec<usize> {
    let mut expected: std::collections::BTreeMap<K, usize> = images
        .current_entries()
        .map(|(key, value)| (key.clone(), std::ptr::from_ref(value).addr()))
        .collect();
    for (key, before) in images.undo_entries() {
        if let Some(value) = before {
            expected.insert(key.clone(), std::ptr::from_ref(value).addr());
        } else {
            expected.remove(key);
        }
    }
    expected.into_values().collect()
}

#[test]
fn original_musubi_group_retained_predecessor_descriptors_use_exact_pair_and_scope() {
    for replacement in [false, true] {
        let (state, proposal) = fixture();
        // Establish a real committed original populated State. Ordinary mode
        // reads its unchanged values; replacement reads the actual pre-tip undo.
        staged_block(&state, proposal.header(), false, true)
            .commit()
            .unwrap();
        let mut block = pending(&state, proposal.header(), replacement);
        let budget = state.ivm_execution_budget();
        let expected: [Vec<usize>; 14] = [
            original_predecessor_pointers(block.world.musubi_archives.frozen_images().unwrap()),
            original_predecessor_pointers(
                block
                    .world
                    .musubi_archive_availability
                    .frozen_images()
                    .unwrap(),
            ),
            original_predecessor_pointers(
                block
                    .world
                    .musubi_archive_locations
                    .frozen_images()
                    .unwrap(),
            ),
            original_predecessor_pointers(
                block.world.musubi_locations_by_pin.frozen_images().unwrap(),
            ),
            original_predecessor_pointers(
                block
                    .world
                    .musubi_locations_by_provider
                    .frozen_images()
                    .unwrap(),
            ),
            original_predecessor_pointers(
                block
                    .world
                    .musubi_locations_by_replication_order
                    .frozen_images()
                    .unwrap(),
            ),
            original_predecessor_pointers(block.world.musubi_packages.frozen_images().unwrap()),
            original_predecessor_pointers(
                block
                    .world
                    .musubi_provider_bundle_attestations
                    .frozen_images()
                    .unwrap(),
            ),
            original_predecessor_pointers(
                block.world.musubi_public_directory.frozen_images().unwrap(),
            ),
            original_predecessor_pointers(block.world.musubi_releases.frozen_images().unwrap()),
            original_predecessor_pointers(
                block.world.musubi_resolver_index.frozen_images().unwrap(),
            ),
            original_predecessor_pointers(block.world.pin_manifests.frozen_images().unwrap()),
            original_predecessor_pointers(block.world.provider_owners.frozen_images().unwrap()),
            original_predecessor_pointers(block.world.replication_orders.frozen_images().unwrap()),
        ];
        if !replacement {
            assert!(expected.iter().any(|rows| !rows.is_empty()));
        }
        start(&mut block, &budget);
        let raw = block
            .advance_original_musubi_group_read(usize::MAX)
            .unwrap();
        assert!(raw.complete);
        let credit = budget.reserved_bytes();
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - credit)
            .unwrap();
        let allocated = allocations_during(|| {
            assert!(matches!(
                block.advance_original_musubi_group_predecessor_read(usize::MAX),
                Err(RetainedMusubiGroupReadError::Field {
                    field: "musubi_archives",
                    original: RetainedPackageReadError::Allocation(ChargedBufferError::Admission(
                        _
                    ))
                })
            ));
            assert_eq!(block.original_musubi_group_read_progress().unwrap(), raw);
        });
        assert_eq!(allocated, 0);
        drop(occupied);
        let predecessor = block
            .advance_original_musubi_group_predecessor_read(usize::MAX)
            .unwrap();
        assert!(predecessor.complete);
        assert!(predecessor.work > raw.work);
        for (table, rows) in predecessor.tables.iter().zip(&expected) {
            assert_eq!(table.rows, rows.len());
            assert!(table.complete);
        }
        let revision_pointer = block
            .with_original_musubi_rows(usize::MAX, |_, revision| {
                std::ptr::from_ref(revision.predecessor())
            })
            .unwrap();
        let charged = budget.reserved_bytes();
        let allocated = allocations_during(|| {
            assert_eq!(
                block
                    .advance_original_musubi_group_predecessor_read(usize::MAX)
                    .unwrap(),
                predecessor
            );
            block
                .with_original_musubi_rows(usize::MAX, |mut rows, revision| {
                    assert_eq!(std::ptr::from_ref(revision.predecessor()), revision_pointer);
                    for (index, pointer) in expected[0].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_archives_predecessor_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.musubi_archives_predecessor_row(expected[0].len())
                            .is_err()
                    );
                    for (index, pointer) in expected[1].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_archive_availability_predecessor_row(index)
                                    .unwrap()
                                    .1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.musubi_archive_availability_predecessor_row(expected[1].len())
                            .is_err()
                    );
                    for (index, pointer) in expected[2].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_archive_locations_predecessor_row(index)
                                    .unwrap()
                                    .1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.musubi_archive_locations_predecessor_row(expected[2].len())
                            .is_err()
                    );
                    for (index, pointer) in expected[3].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_locations_by_pin_predecessor_row(index)
                                    .unwrap()
                                    .1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.musubi_locations_by_pin_predecessor_row(expected[3].len())
                            .is_err()
                    );
                    for (index, pointer) in expected[4].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_locations_by_provider_predecessor_row(index)
                                    .unwrap()
                                    .1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.musubi_locations_by_provider_predecessor_row(expected[4].len())
                            .is_err()
                    );
                    for (index, pointer) in expected[5].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_locations_by_replication_order_predecessor_row(index)
                                    .unwrap()
                                    .1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.musubi_locations_by_replication_order_predecessor_row(
                            expected[5].len()
                        )
                        .is_err()
                    );
                    for (index, pointer) in expected[6].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_packages_predecessor_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.musubi_packages_predecessor_row(expected[6].len())
                            .is_err()
                    );
                    for (index, pointer) in expected[7].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_provider_bundle_attestations_predecessor_row(index)
                                    .unwrap()
                                    .1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.musubi_provider_bundle_attestations_predecessor_row(expected[7].len())
                            .is_err()
                    );
                    for (index, pointer) in expected[8].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_public_directory_predecessor_row(index)
                                    .unwrap()
                                    .1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.musubi_public_directory_predecessor_row(expected[8].len())
                            .is_err()
                    );
                    for (index, pointer) in expected[9].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_releases_predecessor_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.musubi_releases_predecessor_row(expected[9].len())
                            .is_err()
                    );
                    for (index, pointer) in expected[10].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.musubi_resolver_index_predecessor_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.musubi_resolver_index_predecessor_row(expected[10].len())
                            .is_err()
                    );
                    for (index, pointer) in expected[11].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.pin_manifests_predecessor_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.pin_manifests_predecessor_row(expected[11].len())
                            .is_err()
                    );
                    for (index, pointer) in expected[12].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.provider_owners_predecessor_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.provider_owners_predecessor_row(expected[12].len())
                            .is_err()
                    );
                    for (index, pointer) in expected[13].iter().enumerate() {
                        assert_eq!(
                            std::ptr::from_ref(
                                rows.replication_orders_predecessor_row(index).unwrap().1
                            )
                            .addr(),
                            *pointer
                        );
                    }
                    assert!(
                        rows.replication_orders_predecessor_row(expected[13].len())
                            .is_err()
                    );
                })
                .unwrap();
        });
        assert_eq!(
            allocated, 0,
            "original predecessor descriptors resolve without copying rows or maps"
        );
        assert_eq!(budget.reserved_bytes(), charged);
        block.retire_original_musubi_group_read().unwrap();
        assert!(
            block.original_musubi_group_predecessor_progress().is_none(),
            "retired index grants no old row authority"
        );
        assert!(matches!(
            block.try_publish(),
            StatePublicationOutcome::Published
        ));
    }
}
