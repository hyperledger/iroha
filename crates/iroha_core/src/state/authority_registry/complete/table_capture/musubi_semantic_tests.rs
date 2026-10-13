//! Actual semantic readers, original local refusals, and table-only inventory admission.

use super::*;
use crate::{
    execution_attempt::ExecutionAttemptError,
    kura::Kura,
    query::store::LiveQueryStore,
    state::{WorldReadOnly, deserialize::seeded_musubi_publication_world_for_testing},
};
use iroha_allocation::AllocationRefusal;
use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

const fn actual_field(id: &str) -> Field {
    let fields = crate::state::authority_registry::world::WORLD_FIELDS;
    let mut position = 0;
    while position < fields.len() {
        let candidate = fields[position].id.as_bytes();
        let expected = id.as_bytes();
        let mut equal = candidate.len() == expected.len();
        let mut byte = 0;
        while equal && byte < candidate.len() {
            equal = candidate[byte] == expected[byte];
            byte += 1;
        }
        if equal {
            return fields[position];
        }
        position += 1;
    }
    panic!("semantic test must borrow an actual declared field")
}

const FIELDS: &[Field] = &[
    actual_field("world.musubi_archive_availability"),
    actual_field("world.musubi_resolver_index"),
    actual_field("world.musubi_public_directory"),
];
const READERS: &[TableMaterializer] = &[
    TableMaterializer::MusubiSemantic(&MusubiSemanticTable::Availability),
    TableMaterializer::MusubiSemantic(&MusubiSemanticTable::Resolver),
    TableMaterializer::MusubiSemantic(&MusubiSemanticTable::Directory),
];

fn state() -> State {
    State::new_for_testing(
        seeded_musubi_publication_world_for_testing(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}
fn policy() -> TableCaptureLimits {
    TableCaptureLimits {
        tables: LeafLimits {
            max_tables: 3,
            max_rows: 3,
            max_payload_bytes: 4096,
            max_ordered_table_bytes: 65536,
            max_streamed_value_bytes: 65536,
        },
        membership: MembershipWorkLimits {
            max_row_visits: 0,
            max_streamed_bytes: 0,
            max_ordered_bytes: 0,
        },
        musubi: musubi_test_limits(),
    }
}
fn capture(state: &State) -> CapturedCanonicalTables {
    capture_tables_once(state, FIELDS, READERS, policy())
        .unwrap()
        .unwrap()
}

#[test]
fn actual_semantic_readers_bind_authority_and_retain_all_three_nodes_from_one_cut() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let before_bytes = budget.reserved_bytes();
    let old = capture(&state);
    assert_eq!(old.nodes().len(), 3);
    for (node, field) in old.nodes().iter().zip(FIELDS) {
        assert_eq!(node.table_id(), field.id);
        assert_eq!(node.row_count(), 1);
    }
    assert!(budget.reserved_bytes() > before_bytes);
    // Change only the independent availability anchor; its dependent resolver
    // storage projection must follow it, but the resolver's authority revision
    // and the directory authority are unchanged.
    let view = state.world.view();
    let (archive, availability) = view.musubi_archive_availability().iter().next().unwrap();
    let archive = *archive;
    let mut availability = *availability;
    availability.finalized_block_hash[0] ^= 1;
    let (release, row) = view.musubi_resolver_index().iter().next().unwrap();
    let release = release.clone();
    let mut row = row.clone();
    row.selection.storage = availability;
    drop(view);
    let mut availability_write = state.world.musubi_archive_availability.block();
    availability_write.insert(archive, availability);
    availability_write.commit();
    let mut resolver_write = state.world.musubi_resolver_index.block();
    resolver_write.insert(release, row);
    resolver_write.commit();
    let changed = capture(&state);
    assert_ne!(old.nodes()[0].root(), changed.nodes()[0].root());
    assert_eq!(old.nodes()[1].root(), changed.nodes()[1].root());
    assert_eq!(old.nodes()[2].root(), changed.nodes()[2].root());
    // Retained old nodes continue to own their original roots/backing.
    drop(changed);
    drop(old);
    assert_eq!(budget.reserved_bytes(), before_bytes);
}

#[test]
fn changed_derived_projection_refuses_all_semantic_readers_without_retaining_nodes() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let before = budget.reserved_bytes();
    let view = state.world.view();
    let (release, row) = view.musubi_resolver_index().iter().next().unwrap();
    let release = release.clone();
    let mut row = row.clone();
    row.selection.storage.finalized_block_hash[0] ^= 1;
    drop(view);
    let mut update = state.world.musubi_resolver_index.block();
    update.insert(release, row);
    update.commit();
    assert!(matches!(
        capture_tables_once(&state, FIELDS, READERS, policy()),
        Err(TableCaptureError::Musubi(SourceValidationError::Attempt(
            ExecutionAttemptError::Rejected(_)
        )))
    ));
    assert_eq!(budget.reserved_bytes(), before);
}

#[test]
fn semantic_source_work_is_explicit_and_failure_releases_aggregate_backing() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let before = budget.reserved_bytes();
    let mut limits = policy();
    limits.musubi.table_pass_rows = 0;
    assert!(matches!(
        capture_tables_once(&state, FIELDS, READERS, limits),
        Err(TableCaptureError::Musubi(SourceValidationError::Work(_)))
    ));
    assert_eq!(budget.reserved_bytes(), before);
    limits = policy();
    limits.tables.max_rows = 2;
    assert!(matches!(
        capture_tables_once(&state, FIELDS, READERS, limits),
        Err(TableCaptureError::Leaf(LeafError::RowLimit))
    ));
    assert_eq!(budget.reserved_bytes(), before);
    let successful = capture(&state);
    drop(successful);
    assert_eq!(budget.reserved_bytes(), before);
}

#[test]
fn semantic_memory_refusal_preserves_original_pool_release_owner() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let before = budget.reserved_bytes();
    let outer = 3 * std::mem::size_of::<CanonicalTablePairedSnapshot>();
    budget.set_limit_bytes(before + outer + 1024);
    let held = budget.try_reserve_bytes(1024).unwrap();
    let release = budget.with_deferred_refund_notifications(|_| {
        let error = capture_tables_once(&state, FIELDS, READERS, policy())
            .err()
            .expect("source scratch refused after exact outer admission");
        let TableCaptureError::Musubi(SourceValidationError::Attempt(
            ExecutionAttemptError::Deferred(reason),
        )) = error
        else {
            panic!("original source memory category: {error:?}")
        };
        let Some(AllocationRefusal::Capacity { release, .. }) = reason.allocation_refusal() else {
            panic!("original memory pool release")
        };
        assert_eq!(budget.reserved_bytes(), before + 1024);
        let mut waiter = pin!(release.clone().wait_for_release(&mut registration));
        let mut context = Context::from_waker(Waker::noop());
        // Aggregate cleanup actually refunds this original pool, but its
        // notification remains retained by the original scope until it exits.
        assert_eq!(waiter.as_mut().poll(&mut context), Poll::Pending);
        let unrelated = iroha_allocation::AllocationBudget::new(1);
        drop(unrelated.try_reserve_bytes(1).unwrap());
        assert_eq!(waiter.as_mut().poll(&mut context), Poll::Pending);
        release.clone()
    });
    let mut waiter = Box::pin(release.wait_for_release(&mut registration));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(waiter.as_mut().poll(&mut context), Poll::Ready(()));
    drop(held);
    assert_eq!(budget.reserved_bytes(), before);
    drop(waiter);
    drop(registration);
    assert_eq!(
        budget.reserved_bytes(),
        before - iroha_allocation::release::ReleaseRegistration::allocation_layout().size()
    );
}

#[test]
fn semantic_catalog_keeps_exact_order_and_actual_catalog_capacity_gate() {
    assert_eq!(
        (require_exact_table_materializers(FIELDS, READERS))
            .expect("exact complete catalog admitted"),
        3
    );
    assert!(matches!(
        require_exact_table_materializers(FIELDS, &[READERS[1], READERS[0], READERS[2]]),
        Err(TableCaptureError::DisplacedMaterializer(
            "world.musubi_archive_availability"
        ))
    ));
    let state = state();
    assert!(matches!(
        capture_actual_state_tables_once(&state, policy()),
        Err(TableCaptureError::MaterializerLimit)
    ));
    let mut publication = state.state_view_publication();
    let guard = publication.begin();
    assert!(
        capture_tables_once(&state, FIELDS, READERS, policy())
            .unwrap()
            .is_none()
    );
    drop(guard);
    assert!(
        capture_tables_once(&state, FIELDS, READERS, policy())
            .unwrap()
            .is_some()
    );
}

#[test]
fn static_semantic_selectors_preserve_exact_closed_catalog_without_allocation() {
    assert_eq!(
        crate::test_allocations::allocations_during(|| {
            for (reader, expected) in READERS.iter().zip(FIELDS) {
                let mut ids = reader.table_ids();
                assert_eq!(ids.next(), Some(expected.id));
                assert_eq!(ids.next(), None);
            }
        }),
        0
    );
}
