//! Exact-key lookup remains inside the original fourteen-map publication owner.

use super::{fixture, pending, staged_block, start};
use crate::{
    state::publication::{RetainedMusubiGroupReadError, RetainedPackageReadError},
    test_allocations::allocations_during,
};
use iroha_data_model::{
    musubi::{
        ArchiveId, MusubiArchiveLocationIdV1, MusubiArchiveLocationKeyV1, MusubiPackageIdV1,
        MusubiPackageScopeV1, MusubiPackageSelectorV1, MusubiProviderBundleAttestationKeyV1,
        MusubiProviderLocationKeyV1, MusubiReleaseIdV1,
    },
    sorafs::{
        capacity::ProviderId,
        pin_registry::{ManifestDigest, ReplicationOrderId},
    },
};
use iroha_model_base::topology::DataSpaceId;
use std::{cell::Cell, collections::BTreeMap};

const WORK: usize = 1_000_000;

type ExpectedRows<K> = Vec<(K, usize, usize)>;

// Independent, test-only observation of actual native key/value allocations.
// Test clones and its reference overlay are outside the observed production kernel.
fn expected<K: mv::Key, V: mv::Value>(
    images: mv::storage::FrozenStorageImages<'_, K, V>,
) -> (ExpectedRows<K>, ExpectedRows<K>) {
    let current: ExpectedRows<K> = images
        .current_entries()
        .map(|(key, value)| {
            (
                key.clone(),
                std::ptr::from_ref(key).addr(),
                std::ptr::from_ref(value).addr(),
            )
        })
        .collect();
    let mut predecessor: BTreeMap<K, (usize, usize)> = current
        .iter()
        .map(|(key, key_ptr, value_ptr)| (key.clone(), (*key_ptr, *value_ptr)))
        .collect();
    for (key, value) in images.undo_entries() {
        if let Some(value) = value {
            predecessor.insert(
                key.clone(),
                (
                    std::ptr::from_ref(key).addr(),
                    std::ptr::from_ref(value).addr(),
                ),
            );
        } else {
            predecessor.remove(key);
        }
    }
    (
        current,
        predecessor
            .into_iter()
            .map(|(key, (key_ptr, value_ptr))| (key, key_ptr, value_ptr))
            .collect(),
    )
}

#[test]
fn original_group_all_fourteen_lookup_pairs_reuse_funded_descriptors_and_revision() {
    for replacement in [false, true] {
        let (state, proposal) = fixture();
        staged_block(&state, proposal.header(), false, true)
            .commit()
            .unwrap();
        let mut block = pending(&state, proposal.header(), replacement);
        let budget = state.ivm_execution_budget();
        macro_rules! expected_fields {
            ($($field:ident),+ $(,)?) => { $(
                let $field = expected(block.world.$field.frozen_images().unwrap());
            )+ };
        }
        expected_fields!(
            musubi_archives,
            musubi_archive_availability,
            musubi_archive_locations,
            musubi_locations_by_pin,
            musubi_locations_by_provider,
            musubi_locations_by_replication_order,
            musubi_packages,
            musubi_provider_bundle_attestations,
            musubi_public_directory,
            musubi_releases,
            musubi_resolver_index,
            pin_manifests,
            provider_owners,
            replication_orders
        );
        let revision = block
            .world
            .musubi_resolver_index_revision
            .frozen_values()
            .unwrap();
        let revision_pointers = (
            std::ptr::from_ref(revision.0).addr(),
            std::ptr::from_ref(revision.1).addr(),
        );
        let archive = ArchiveId::new([0xfe; 32]);
        let location = MusubiArchiveLocationKeyV1 {
            archive_id: archive,
            location_id: MusubiArchiveLocationIdV1::new([0xfe; 32]),
        };
        let pin = ManifestDigest([0xfe; 32]);
        let order = ReplicationOrderId([0xfe; 32]);
        let provider = ProviderId::new([0xfe; 32]);
        let provider_location = MusubiProviderLocationKeyV1 {
            provider_id: provider,
            location,
        };
        let attestation = MusubiProviderBundleAttestationKeyV1 {
            archive_id: archive,
            replication_order: order,
            provider_id: provider,
        };
        let package = MusubiPackageIdV1::new(
            DataSpaceId::new(999),
            MusubiPackageScopeV1::DataspaceRoot,
            "not-present".parse().unwrap(),
        );
        let release = MusubiReleaseIdV1::new(package.clone(), "1.0.0".parse().unwrap());
        let selector: MusubiPackageSelectorV1 = "not-present/not-present".parse().unwrap();
        start(&mut block, &budget);
        block.advance_original_musubi_group_read(WORK).unwrap();
        let complete = block
            .advance_original_musubi_group_predecessor_read(WORK)
            .unwrap();
        assert!(complete.complete);
        let charged = budget.reserved_bytes();
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - charged)
            .unwrap();
        let allocation_count = allocations_during(|| {
            block
                .with_original_musubi_rows(WORK, |mut rows, revision| {
                    assert_eq!(
                        (
                            std::ptr::from_ref(revision.current()).addr(),
                            std::ptr::from_ref(revision.predecessor()).addr()
                        ),
                        revision_pointers
                    );
                    macro_rules! check {
                        ($expected:ident, $current:ident, $predecessor:ident, $missing:expr) => {{
                            for (query, key_ptr, value_ptr) in &$expected.0 {
                                let (key, value) = rows.$current(query).unwrap().unwrap();
                                assert_eq!(key, query);
                                assert_eq!(std::ptr::from_ref(key).addr(), *key_ptr);
                                assert_eq!(std::ptr::from_ref(value).addr(), *value_ptr);
                            }
                            for (query, key_ptr, value_ptr) in &$expected.1 {
                                let (key, value) = rows.$predecessor(query).unwrap().unwrap();
                                assert_eq!(key, query);
                                assert_eq!(std::ptr::from_ref(key).addr(), *key_ptr);
                                assert_eq!(std::ptr::from_ref(value).addr(), *value_ptr);
                            }
                            assert!(!$expected.0.iter().any(|(key, _, _)| key == $missing));
                            assert!(!$expected.1.iter().any(|(key, _, _)| key == $missing));
                            assert!(rows.$current($missing).unwrap().is_none());
                            assert!(rows.$predecessor($missing).unwrap().is_none());
                        }};
                    }
                    check!(
                        musubi_archives,
                        musubi_archives_current_lookup,
                        musubi_archives_predecessor_lookup,
                        &archive
                    );
                    check!(
                        musubi_archive_availability,
                        musubi_archive_availability_current_lookup,
                        musubi_archive_availability_predecessor_lookup,
                        &archive
                    );
                    check!(
                        musubi_archive_locations,
                        musubi_archive_locations_current_lookup,
                        musubi_archive_locations_predecessor_lookup,
                        &location
                    );
                    check!(
                        musubi_locations_by_pin,
                        musubi_locations_by_pin_current_lookup,
                        musubi_locations_by_pin_predecessor_lookup,
                        &pin
                    );
                    check!(
                        musubi_locations_by_provider,
                        musubi_locations_by_provider_current_lookup,
                        musubi_locations_by_provider_predecessor_lookup,
                        &provider_location
                    );
                    check!(
                        musubi_locations_by_replication_order,
                        musubi_locations_by_replication_order_current_lookup,
                        musubi_locations_by_replication_order_predecessor_lookup,
                        &order
                    );
                    check!(
                        musubi_packages,
                        musubi_packages_current_lookup,
                        musubi_packages_predecessor_lookup,
                        &package
                    );
                    check!(
                        musubi_provider_bundle_attestations,
                        musubi_provider_bundle_attestations_current_lookup,
                        musubi_provider_bundle_attestations_predecessor_lookup,
                        &attestation
                    );
                    check!(
                        musubi_public_directory,
                        musubi_public_directory_current_lookup,
                        musubi_public_directory_predecessor_lookup,
                        &selector
                    );
                    check!(
                        musubi_releases,
                        musubi_releases_current_lookup,
                        musubi_releases_predecessor_lookup,
                        &release
                    );
                    check!(
                        musubi_resolver_index,
                        musubi_resolver_index_current_lookup,
                        musubi_resolver_index_predecessor_lookup,
                        &release
                    );
                    check!(
                        pin_manifests,
                        pin_manifests_current_lookup,
                        pin_manifests_predecessor_lookup,
                        &pin
                    );
                    check!(
                        provider_owners,
                        provider_owners_current_lookup,
                        provider_owners_predecessor_lookup,
                        &provider
                    );
                    check!(
                        replication_orders,
                        replication_orders_current_lookup,
                        replication_orders_predecessor_lookup,
                        &order
                    );
                })
                .unwrap()
        });
        assert_eq!(
            allocation_count, 0,
            "lookups allocate no replacement map, key or record"
        );
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), charged);
        let after = block.original_musubi_group_predecessor_progress().unwrap();
        assert_eq!(after.tables, complete.tables);
        assert!(after.work > complete.work);
        block.retire_original_musubi_group_read().unwrap();
        let retired = block.original_musubi_group_read_progress().unwrap();
        assert!(retired.retired);
        assert_eq!(retired.retired_tables, 14);
        assert_eq!(retired.work, after.work);
        assert!(
            budget.reserved_bytes() < charged,
            "actual descriptor/control backing retires"
        );
    }
}

#[test]
fn original_group_lookup_refusal_keeps_original_work_and_stale_source_never_enters_callback() {
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    let budget = state.ivm_execution_budget();
    start(&mut block, &budget);
    block.advance_original_musubi_group_read(WORK).unwrap();
    let complete = block
        .advance_original_musubi_group_predecessor_read(WORK)
        .unwrap();
    let charged = budget.reserved_bytes();
    let query = ArchiveId::new([0xfe; 32]);
    let refused = block
        .with_original_musubi_rows(complete.work, |mut rows, _| {
            rows.musubi_archives_current_lookup(&query)
                .map(|row| row.is_some())
        })
        .unwrap();
    assert!(matches!(refused, Err(RetainedMusubiGroupReadError::Field {
        field: "musubi_archives", original: RetainedPackageReadError::Work { used, required, limit }
    }) if used == complete.work && required == used + 1 && limit == used));
    assert_eq!(
        block.original_musubi_group_predecessor_progress().unwrap(),
        complete
    );
    assert_eq!(budget.reserved_bytes(), charged);
    assert!(
        !block
            .with_original_musubi_rows(WORK, |mut rows, _| rows
                .musubi_archives_current_lookup(&query)
                .map(|row| row.is_some()))
            .unwrap()
            .unwrap()
    );
    let before_publication = block.original_musubi_group_predecessor_progress().unwrap();
    staged_block(&state, proposal.header(), false, false)
        .commit()
        .unwrap();
    let called = Cell::new(false);
    let before_refusal = budget.reserved_bytes();
    assert!(matches!(
        block.with_original_musubi_rows(WORK, |mut rows, _| {
            called.set(true);
            rows.musubi_archives_predecessor_lookup(&query)
                .map(|row| row.is_some())
        }),
        Err(RetainedMusubiGroupReadError::SourceChanged)
    ));
    assert!(!called.get());
    assert_eq!(
        block.original_musubi_group_predecessor_progress().unwrap(),
        before_publication
    );
    assert_eq!(budget.reserved_bytes(), before_refusal);
}

#[test]
fn original_group_lookup_result_is_dropped_when_state_publishes_during_callback() {
    struct Returned<'a>(&'a Cell<usize>);
    impl Drop for Returned<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    let budget = state.ivm_execution_budget();
    let (query, original_ptr) = {
        let images = block.world.musubi_archives.frozen_images().unwrap();
        let (key, value) = images.current_entries().next().unwrap();
        (*key, std::ptr::from_ref(value).addr())
    };
    start(&mut block, &budget);
    block.advance_original_musubi_group_read(WORK).unwrap();
    block
        .advance_original_musubi_group_predecessor_read(WORK)
        .unwrap();
    let before = block.original_musubi_group_predecessor_progress().unwrap();
    let drops = Cell::new(0);
    let result = block.with_original_musubi_rows(WORK, |mut rows, revision| {
        let revision_ptr = std::ptr::from_ref(revision.current());
        assert_eq!(
            std::ptr::from_ref(
                rows.musubi_archives_current_lookup(&query)
                    .unwrap()
                    .unwrap()
                    .1
            )
            .addr(),
            original_ptr
        );
        assert!(
            rows.musubi_archives_predecessor_lookup(&query)
                .unwrap()
                .is_none()
        );
        staged_block(&state, proposal.header(), false, false)
            .commit()
            .unwrap();
        assert_eq!(
            std::ptr::from_ref(
                rows.musubi_archives_current_lookup(&query)
                    .unwrap()
                    .unwrap()
                    .1
            )
            .addr(),
            original_ptr
        );
        assert!(
            rows.musubi_archives_predecessor_lookup(&query)
                .unwrap()
                .is_none()
        );
        assert_eq!(std::ptr::from_ref(revision.current()), revision_ptr);
        Returned(&drops)
    });
    assert!(matches!(
        result,
        Err(RetainedMusubiGroupReadError::SourceChanged)
    ));
    assert_eq!(drops.get(), 1);
    let after = block.original_musubi_group_predecessor_progress().unwrap();
    assert_eq!(after.tables, before.tables);
    assert!(after.work > before.work);
}
