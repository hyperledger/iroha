//! Coherent original State sources, cold Rust allocation census, and exact local refusals.

use super::*;
use crate::{
    kura::Kura, query::store::LiveQueryStore,
    state::deserialize::seeded_musubi_publication_world_for_testing,
    test_allocations::allocations_during,
};
use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

fn state() -> State {
    State::new_for_testing(
        seeded_musubi_publication_world_for_testing(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

#[test]
fn first_native_source_acquisition_on_cold_thread_allocates_no_rust_backing() {
    // State/fixture/thread construction remains outside acquisition. The new
    // thread performs no World or MV read before this observation, so a hidden
    // first-use EBR participant would be counted rather than warmed away.
    let state = state();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut result=None;
            let allocations=allocations_during(|| { result=Some(StateMusubiSourceCut::try_capture(&state)); });
            assert_eq!(allocations,0,"original acquisition must not allocate a default catalog or collector participant");
            let cut=result.unwrap().unwrap().unwrap();
            assert_eq!(cut.source_musubi_archive_availability().len(),1);
            assert_eq!(cut.source_musubi_resolver_index().len(),1);
            assert_eq!(cut.source_musubi_public_directory().len(),1);
            assert!(cut.source_musubi_resolver_index_revision()>0);
            let allocations=allocations_during(|| assert!(cut.try_matches_current().unwrap()));
            assert_eq!(allocations,0);
            assert_eq!(allocations_during(||drop(cut)),0);
        }).join().unwrap();
    });
}

#[test]
fn every_original_table_and_revision_reject_equal_republication() {
    let state = state();
    macro_rules! check {
        ($($field:ident),+ $(,)?) => { $(
            let cut=StateMusubiSourceCut::try_capture(&state).unwrap().unwrap();
            assert!(std::ptr::eq(cut.state,&state));
            state.world.$field.block().commit();
            assert!(!cut.try_matches_current().unwrap(),stringify!($field));
            assert!(StateMusubiSourceCut::try_capture(&state).unwrap().is_some());
        )+ };
    }
    check!(
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
        replication_orders,
        musubi_resolver_index_revision
    );
}

#[test]
fn retained_cut_preserves_original_rows_after_source_replacement_and_refuses_equal_foreign_state() {
    let other = state();
    let state = state();
    let cut = StateMusubiSourceCut::try_capture(&state).unwrap().unwrap();
    assert!(
        !cut.musubi_archives
            .try_matches_current(&other.world.musubi_archives)
            .unwrap()
    );
    assert!(
        !cut.revision
            .try_matches_current(&other.world.musubi_resolver_index_revision)
            .unwrap()
    );
    let (key, row) = cut.source_musubi_resolver_index().iter().next().unwrap();
    let mut changed = row.clone();
    changed.index_revision += 1;
    let mut update = state.world.musubi_resolver_index.block();
    update.insert(key.clone(), changed);
    update.commit();
    assert_eq!(cut.source_musubi_resolver_index().get(key), Some(row));
    assert!(!cut.try_matches_current().unwrap());
}

#[test]
fn source_acquisition_preserves_original_revision_busy_release_and_poison() {
    let state = state();
    let mut registration =
        crate::unit_test_support::release_registration(&state.ivm_execution_budget());
    let unrelated = mv::cell::Cell::new(1_u64);
    let held = state.world.musubi_resolver_index_revision.block();
    let Err(error) = StateMusubiSourceCut::try_capture(&state) else {
        panic!("held revision must refuse")
    };
    assert_eq!(error.field, "world.musubi_resolver_index_revision");
    let PublicationPreparationError::Busy(release) = error.original else {
        panic!("exact original revision contention")
    };
    let mut wait = pin!(release.wait_for_release(&mut registration));
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(wait.as_mut().poll(&mut cx), Poll::Pending);
    drop(unrelated.block());
    assert_eq!(wait.as_mut().poll(&mut cx), Poll::Pending);
    drop(held);
    assert_eq!(wait.as_mut().poll(&mut cx), Poll::Ready(()));
    assert!(StateMusubiSourceCut::try_capture(&state).unwrap().is_some());
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = state.world.musubi_resolver_index_revision.block();
        panic!("poison actual original revision writer");
    }));
    let Err(error) = StateMusubiSourceCut::try_capture(&state) else {
        panic!("poisoned original must refuse")
    };
    assert_eq!(error.field, "world.musubi_resolver_index_revision");
    assert_eq!(error.original, PublicationPreparationError::Poisoned);
}

#[test]
fn original_state_publication_interval_refuses_without_acquiring_or_waiting() {
    let state = state();
    let cut = StateMusubiSourceCut::try_capture(&state).unwrap().unwrap();
    let mut publication = state.state_view_publication();
    let fence = state.state_commit_lock.lock();
    let held = publication.begin();
    assert_eq!(
        allocations_during(|| assert!(
            StateMusubiSourceCut::try_capture(&state).unwrap().is_none()
        )),
        0
    );
    assert!(!cut.try_matches_current().unwrap());
    drop(held);
    drop(fence);
    drop(publication);
    assert!(!cut.try_matches_current().unwrap());
    assert!(StateMusubiSourceCut::try_capture(&state).unwrap().is_some());
}

#[test]
fn concurrent_state_publication_never_admits_mixed_table_and_revision_cut() {
    let state = state();
    let source = StateMusubiSourceCut::try_capture(&state).unwrap().unwrap();
    let archive = *source
        .source_musubi_archive_availability()
        .iter()
        .next()
        .unwrap()
        .0;
    let release = source
        .source_musubi_resolver_index()
        .iter()
        .next()
        .unwrap()
        .0
        .clone();
    let selector = source
        .source_musubi_public_directory()
        .iter()
        .next()
        .unwrap()
        .0
        .clone();
    drop(source);
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            for revision in 100..132 {
                let mut publication = state.state_view_publication();
                let fence = state.state_commit_lock.lock();
                let mut availability = state.world.musubi_archive_availability.block();
                let mut resolver = state.world.musubi_resolver_index.block();
                let mut directory = state.world.musubi_public_directory.block();
                let mut native_revision = state.world.musubi_resolver_index_revision.block();
                let row = availability.get_mut(&archive).unwrap();
                row.index_revision = revision;
                row.finalized_block_hash[0] =
                    u8::try_from(revision).expect("fixture value fits u8");
                let storage = *row;
                let row = resolver.get_mut(&release).unwrap();
                row.index_revision = revision;
                row.selection.storage = storage;
                directory.get_mut(&selector).unwrap().index_revision = revision;
                *native_revision.get_mut() = MusubiResolverIndexRevisionV1::new(revision).unwrap();
                let generation = publication.begin();
                availability.commit();
                resolver.commit();
                directory.commit();
                native_revision.commit();
                drop(generation);
                drop(fence);
                drop(publication);
            }
        });
        for _ in 0..256 {
            match StateMusubiSourceCut::try_capture(&state) {
                Ok(Some(cut)) => {
                    let availability = cut
                        .source_musubi_archive_availability()
                        .get(&archive)
                        .unwrap();
                    let resolver = cut.source_musubi_resolver_index().get(&release).unwrap();
                    assert_eq!(resolver.selection.storage, *availability);
                    if cut.source_musubi_resolver_index_revision() >= 100 {
                        assert_eq!(
                            resolver.index_revision,
                            cut.source_musubi_resolver_index_revision()
                        );
                        assert_eq!(
                            cut.source_musubi_public_directory()
                                .get(&selector)
                                .unwrap()
                                .index_revision,
                            cut.source_musubi_resolver_index_revision()
                        );
                    }
                }
                Ok(None)
                | Err(MusubiSourceAcquisitionError {
                    original:
                        PublicationPreparationError::Busy(_) | PublicationPreparationError::Changed,
                    ..
                }) => {}
                Err(other) => panic!("unexpected source refusal: {other:?}"),
            }
        }
        writer.join().unwrap();
    });
    let cut = StateMusubiSourceCut::try_capture(&state).unwrap().unwrap();
    assert_eq!(cut.source_musubi_resolver_index_revision(), 131);
    assert_eq!(
        cut.source_musubi_resolver_index()
            .get(&release)
            .unwrap()
            .index_revision,
        131
    );
}
