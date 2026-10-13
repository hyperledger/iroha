// Actual retained geometry operation ownership, including real journal I/O failures.

fn with_raw_geometry_fixture(test: impl FnOnce(&Arc<Kura>, &GeometryBindingRequest<'_>)) {
    with_raw_geometry_fixture_mode(false, MAX_DISK_USAGE_BYTES, test);
}

fn with_raw_geometry_fixture_mode(
    in_memory: bool,
    max_disk_usage_bytes: iroha_config_base::util::Bytes,
    test: impl FnOnce(&Arc<Kura>, &GeometryBindingRequest<'_>),
) {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, extended) = initial_and_extended_configs();
    let mut kura = open_kura(&root, &initial);
    Arc::get_mut(&mut kura)
        .expect("fixture owns its sole Kura")
        .max_disk_usage_bytes = max_disk_usage_bytes.get();
    let (previous_incarnations, previous_activation_heights) = initial_geometry();
    let (updated_incarnations, updated_activation_heights) = extended_geometry();
    authenticate_transition_fixture_primary(&kura, &initial, &previous_incarnations);
    let previous_lineage_root = unscoped_lineage_root(
        &kura
            .geometry_bindings(
                &initial,
                &previous_incarnations,
                &previous_activation_heights,
            )
            .unwrap(),
    );
    let updated_lineage_root = unscoped_lineage_root(
        &kura
            .geometry_bindings(
                &extended,
                &updated_incarnations,
                &updated_activation_heights,
            )
            .unwrap(),
    );
    let request = GeometryBindingRequest {
        previous: &initial,
        updated: &extended,
        previous_incarnations: &previous_incarnations,
        updated_incarnations: &updated_incarnations,
        previous_activation_heights: &previous_activation_heights,
        updated_activation_heights: &updated_activation_heights,
        previous_lineage_root,
        updated_lineage_root,
        transition_height: 9,
    };
    if in_memory {
        Arc::get_mut(&mut kura)
            .expect("fixture owns its sole Kura")
            .store_root
            .clear();
    }
    test(&kura, &request);
}

#[test]
fn raw_geometry_uses_lease_pending_capacity_without_a_held_lock_rescan() {
    let capacity = iroha_config_base::util::Bytes(u64::MAX / 4);
    with_raw_geometry_fixture_mode(false, capacity, |kura, request| {
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        kura.append_pending_block_for_bench(chain.committed(1).block().clone());
        kura.pending_budget_raw_scans.store(0, Ordering::Relaxed);
        let lease = kura.try_publication_lease().unwrap();
        assert!(lease.pending_canonical_bytes() > 0);
        assert_eq!(kura.pending_budget_raw_scans.load(Ordering::Relaxed), 1);
        let mut original = lease
            .begin_raw_geometry_attempt(request, &BTreeSet::new())
            .unwrap();
        // An invalidated global cache must not cause a metadata/sidecar scan
        // after this original lease has acquired the inner publication locks.
        kura.invalidate_pending_budget_cache();
        original.resume_under(&lease).unwrap();
        assert_eq!(original.phase(), RawGeometryPhase::FilesApplied);
        assert_eq!(kura.pending_budget_raw_scans.load(Ordering::Relaxed), 1);
        original.publish_catalog_under(&lease, None).unwrap();
        assert_eq!(original.phase(), RawGeometryPhase::CatalogPublished);
        assert_eq!(kura.pending_budget_raw_scans.load(Ordering::Relaxed), 1);
    });
}

#[test]
fn raw_geometry_capture_is_pure_and_excludes_competing_owners() {
    with_raw_geometry_fixture(|kura, request| {
        let before = fs::read(kura.lane_geometry_journal_path()).unwrap();
        let lease = kura.try_publication_lease().unwrap();
        let mut original = lease
            .begin_raw_geometry_attempt(request, &BTreeSet::new())
            .unwrap();
        assert_eq!(original.phase(), RawGeometryPhase::Captured);
        let busy = match lease.begin_raw_geometry_attempt(request, &BTreeSet::new()) {
            Err(error @ Error::LaneGeometryAttemptBusy { .. }) => error,
            _ => panic!("the original claim must exclude competing owners"),
        };
        assert!(busy.to_string().contains("release pending"));
        assert_eq!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
        original.rollback_under(&lease).unwrap();
        assert_eq!(original.phase(), RawGeometryPhase::RolledBack);
        assert!(busy.to_string().contains("released; retry acquisition"));
        let replacement = lease
            .begin_raw_geometry_attempt(request, &BTreeSet::new())
            .unwrap();
        assert!(replacement.matches_request(request, &BTreeSet::new()));
        drop(replacement);
        assert_eq!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
    });
}

#[test]
fn raw_geometry_files_applied_keeps_claim_and_original_catalog_retry() {
    with_raw_geometry_fixture(|kura, request| {
        let lease = kura.try_publication_lease().unwrap();
        let mut original = lease
            .begin_raw_geometry_attempt(request, &BTreeSet::new())
            .unwrap();
        original.resume_under(&lease).unwrap();
        assert_eq!(original.phase(), RawGeometryPhase::FilesApplied);
        drop(lease);
        let before = fs::read(kura.lane_geometry_journal_path()).unwrap();
        assert!(matches!(
            kura.mark_lane_geometry_catalog_published_with_lineage_root(
                request.updated,
                request.updated_incarnations,
                request.updated_activation_heights,
                request.updated_lineage_root,
                None
            ),
            Err(Error::LaneGeometryAttemptBusy { .. })
        ));
        assert_eq!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
        let lease = kura.try_publication_lease().unwrap();
        crate::kura::fail_bound_progress_intent_directory_sync_for_tests(0, 0);
        assert!(original.publish_catalog_under(&lease, None).is_err());
        assert_eq!(original.phase(), RawGeometryPhase::PublishingCatalog);
        assert!(original.has_pending_journal_write());
        let promoted = secure_file_metadata::from_path(&kura.lane_geometry_journal_path()).unwrap();
        assert!(original.rollback_under(&lease).is_err());
        drop(lease);
        let lease = kura.try_publication_lease().unwrap();
        original.publish_catalog_under(&lease, None).unwrap();
        assert_eq!(original.phase(), RawGeometryPhase::CatalogPublished);
        assert!(Kura::sidecar_metadata_same_object(
            &promoted,
            &secure_file_metadata::from_path(&kura.lane_geometry_journal_path()).unwrap()
        ));
        assert!(!original.has_pending_journal_write());
        assert!(
            lease
                .begin_raw_geometry_attempt(request, &BTreeSet::new())
                .is_ok()
        );
    });
}

#[test]
fn raw_geometry_pending_intent_retries_original_then_owned_rollback() {
    with_raw_geometry_fixture(|kura, request| {
        let lease = kura.try_publication_lease().unwrap();
        let mut original = lease
            .begin_raw_geometry_attempt(request, &BTreeSet::new())
            .unwrap();
        crate::kura::fail_next_bound_progress_intent_file_sync_for_tests();
        assert!(original.resume_under(&lease).is_err());
        assert!(original.has_pending_journal_write());
        assert!(original.rollback_under(&lease).is_err());
        let temporary = kura.store_root.join(JOURNAL_TEMP_FILE_NAME);
        let original_temp = secure_file_metadata::from_path(&temporary).unwrap();
        drop(lease);
        let lease = kura.try_publication_lease().unwrap();
        // Original temporary custody remains live across the physical lease release.
        assert!(Kura::sidecar_metadata_same_object(
            &original_temp,
            &secure_file_metadata::from_path(&temporary).unwrap()
        ));
        original.resume_under(&lease).unwrap();
        assert_eq!(original.phase(), RawGeometryPhase::FilesApplied);
        crate::kura::fail_bound_progress_intent_directory_sync_for_tests(0, 0);
        assert!(original.rollback_under(&lease).is_err());
        assert_eq!(original.phase(), RawGeometryPhase::RollingBack);
        assert!(original.has_pending_journal_write());
        let promoted = secure_file_metadata::from_path(&kura.lane_geometry_journal_path()).unwrap();
        original.rollback_under(&lease).unwrap();
        assert_eq!(original.phase(), RawGeometryPhase::RolledBack);
        assert!(Kura::sidecar_metadata_same_object(
            &promoted,
            &secure_file_metadata::from_path(&kura.lane_geometry_journal_path()).unwrap()
        ));
        let bindings = kura
            .geometry_bindings(
                request.previous,
                request.previous_incarnations,
                request.previous_activation_heights,
            )
            .unwrap();
        assert_eq!(kura.lane_storage_entries.lock().len(), bindings.len());
    });
}

#[test]
fn raw_geometry_abandoned_partial_operation_refuses_replacement() {
    with_raw_geometry_fixture(|kura, request| {
        let lease = kura.try_publication_lease().unwrap();
        let mut original = lease
            .begin_raw_geometry_attempt(request, &BTreeSet::new())
            .unwrap();
        crate::kura::fail_next_bound_progress_intent_file_sync_for_tests();
        assert!(original.resume_under(&lease).is_err());
        let before = fs::read(kura.store_root.join(JOURNAL_TEMP_FILE_NAME)).unwrap();
        drop(original);
        assert!(matches!(
            lease.begin_raw_geometry_attempt(request, &BTreeSet::new()),
            Err(Error::LaneGeometryAttemptAbandoned)
        ));
        assert_eq!(
            fs::read(kura.store_root.join(JOURNAL_TEMP_FILE_NAME)).unwrap(),
            before
        );
    });
}

#[test]
fn raw_geometry_in_memory_map_change_keeps_abandonment_fence() {
    with_raw_geometry_fixture_mode(true, MAX_DISK_USAGE_BYTES, |kura, request| {
        let lease = kura.try_publication_lease().unwrap();
        let mut original = lease
            .begin_raw_geometry_attempt(request, &BTreeSet::new())
            .unwrap();
        original.resume_under(&lease).unwrap();
        assert_eq!(original.phase(), RawGeometryPhase::FilesApplied);
        assert_eq!(
            kura.lane_storage_entries.lock().len(),
            request.updated.entries().len()
        );
        drop(original);
        assert!(matches!(
            lease.begin_raw_geometry_attempt(request, &BTreeSet::new()),
            Err(Error::LaneGeometryAttemptAbandoned)
        ));
    });
}

#[test]
fn raw_geometry_in_memory_catalog_and_owned_rollback_keep_exact_maps() {
    with_raw_geometry_fixture_mode(true, MAX_DISK_USAGE_BYTES, |kura, request| {
        let lease = kura.try_publication_lease().unwrap();
        let mut rollback = lease
            .begin_raw_geometry_attempt(request, &BTreeSet::new())
            .unwrap();
        rollback.resume_under(&lease).unwrap();
        rollback.rollback_under(&lease).unwrap();
        assert_eq!(rollback.phase(), RawGeometryPhase::RolledBack);
        assert_eq!(
            *kura.lane_storage_entries.lock(),
            kura.lane_storage_entries_from_geometry(
                request.previous,
                request.previous_incarnations,
                request.previous_activation_heights,
            )
            .unwrap()
        );
        let mut published = lease
            .begin_raw_geometry_attempt(request, &BTreeSet::new())
            .unwrap();
        published.resume_under(&lease).unwrap();
        published.publish_catalog_under(&lease, None).unwrap();
        assert_eq!(published.phase(), RawGeometryPhase::CatalogPublished);
        assert_eq!(
            *kura.lane_storage_entries.lock(),
            kura.lane_storage_entries_from_geometry(
                request.updated,
                request.updated_incarnations,
                request.updated_activation_heights,
            )
            .unwrap()
        );
        kura.raw_geometry_claim.ensure_unclaimed().unwrap();
    });
}

#[test]
fn raw_geometry_refuses_canonical_recovery_debt_without_consuming_it() {
    with_raw_geometry_fixture(|kura, request| {
        let before = fs::read(kura.lane_geometry_journal_path()).unwrap();
        kura.block_store.lock().deferred_da_recovery_fault =
            Some("original deferred rewrite fault".into());
        let lease = kura.try_publication_lease().unwrap();
        assert!(matches!(
            lease.begin_raw_geometry_attempt(request, &BTreeSet::new()),
            Err(Error::LaneGeometryCanonicalRecoveryRequired)
        ));
        assert_eq!(
            kura.block_store
                .lock()
                .deferred_da_recovery_fault
                .as_deref(),
            Some("original deferred rewrite fault")
        );
        assert_eq!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
    });
}

#[test]
fn raw_geometry_claim_excludes_canonical_mutation_between_leases() {
    with_raw_geometry_fixture(|kura, request| {
        let lease = kura.try_publication_lease().unwrap();
        let mut original = lease
            .begin_raw_geometry_attempt(request, &BTreeSet::new())
            .unwrap();
        original.resume_under(&lease).unwrap();
        drop(lease);
        {
            let _prune = kura.prune_lock.lock();
            let _canonical = kura.canonical_chain_lock.lock();
            assert!(matches!(
                kura.resolve_canonical_storage_before_mutation(),
                Err(Error::LaneGeometryAttemptBusy { .. })
            ));
        }
        let lease = kura.try_publication_lease().unwrap();
        original.publish_catalog_under(&lease, None).unwrap();
        drop(lease);
        let _prune = kura.prune_lock.lock();
        let _canonical = kura.canonical_chain_lock.lock();
        kura.resolve_canonical_storage_before_mutation().unwrap();
    });
}

#[test]
fn raw_geometry_partial_instance_provisioning_retains_original_recovery_cause() {
    with_raw_geometry_fixture(|kura, request| {
        let lease = kura.try_publication_lease().unwrap();
        let mut original = lease
            .begin_raw_geometry_attempt(request, &BTreeSet::new())
            .unwrap();
        FAIL_NEXT_GEOMETRY_INSTANCE_AFTER_FILES.with(|fault| fault.set(true));
        let first = original
            .resume_under(&lease)
            .expect_err("native base files exist before failure");
        let Error::LaneGeometryInstanceRecoveryRequired {
            lane_id,
            operation,
            source,
        } = first
        else {
            panic!("partial provisioning must retain typed local recovery cause: {first:?}");
        };
        assert_eq!(lane_id, LaneId::new(1));
        assert_eq!(operation, 0);
        assert!(
            matches!(source.as_ref(), Error::IO(error, _) if error.to_string().contains("original instance provisioning"))
        );
        assert_eq!(original.phase(), RawGeometryPhase::RecoveryRequired);
        let journal = fs::read(kura.lane_geometry_journal_path()).unwrap();
        let binding = kura
            .geometry_bindings(
                request.updated,
                request.updated_incarnations,
                request.updated_activation_heights,
            )
            .unwrap()
            .into_iter()
            .find(|binding| binding.lane_id == lane_id)
            .unwrap();
        let blocks = kura.binding_blocks_path(&binding);
        assert!(blocks.join(DATA_FILE_NAME).is_file());
        assert!(!blocks.join(MARKER_FILE_NAME).exists());
        let created = secure_file_metadata::from_path(&blocks).unwrap();
        drop(lease);
        let lease = kura.try_publication_lease().unwrap();
        for refusal in [
            original.recovery_refusal().unwrap(),
            original.resume_under(&lease).unwrap_err(),
            original.rollback_under(&lease).unwrap_err(),
        ] {
            let Error::LaneGeometryInstanceRecoveryRequired { source: retry, .. } = refusal else {
                panic!("recovery refusal must preserve original cause: {refusal:?}");
            };
            assert!(Arc::ptr_eq(&source, &retry));
        }
        assert!(Kura::sidecar_metadata_same_object(
            &created,
            &secure_file_metadata::from_path(&blocks).unwrap()
        ));
        assert_eq!(
            fs::read(kura.lane_geometry_journal_path()).unwrap(),
            journal
        );
        assert!(
            !blocks.join(MARKER_FILE_NAME).exists(),
            "same-process refusal cannot manufacture missing authority"
        );
    });
}

#[test]
fn raw_geometry_removal_and_replacement_refuse_before_original_claim() {
    with_raw_geometry_fixture(|kura, request| {
        let before = fs::read(kura.lane_geometry_journal_path()).unwrap();
        let lease = kura.try_publication_lease().unwrap();
        let removal = GeometryBindingRequest {
            previous: request.updated,
            updated: request.previous,
            previous_incarnations: request.updated_incarnations,
            updated_incarnations: request.previous_incarnations,
            previous_activation_heights: request.updated_activation_heights,
            updated_activation_heights: request.previous_activation_heights,
            previous_lineage_root: request.updated_lineage_root,
            updated_lineage_root: request.previous_lineage_root,
            transition_height: request.transition_height,
        };
        assert!(
            lease
                .begin_raw_geometry_attempt(&removal, &BTreeSet::new())
                .is_err()
        );
        assert!(
            lease
                .begin_raw_geometry_attempt(request, &BTreeSet::from([LaneId::SINGLE]))
                .is_err()
        );
        assert_eq!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
        let mut original = lease
            .begin_raw_geometry_attempt(request, &BTreeSet::new())
            .unwrap();
        assert_eq!(original.phase(), RawGeometryPhase::Captured);
        assert_eq!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
        original.resume_under(&lease).unwrap();
        original.publish_catalog_under(&lease, None).unwrap();
        assert_eq!(original.phase(), RawGeometryPhase::CatalogPublished);
    });
}

#[test]
fn raw_geometry_retains_current_markers_without_retired_lane_artifact_namespace() {
    with_raw_geometry_fixture(|kura, request| {
        let bindings = kura
            .geometry_bindings(
                request.previous,
                request.previous_incarnations,
                request.previous_activation_heights,
            )
            .unwrap();
        let paths: Vec<_> = bindings
            .iter()
            .map(|binding| kura.binding_blocks_path(binding))
            .collect();
        for path in &paths {
            assert!(!path.join("lane_artifacts").exists());
        }
        let lease = kura.try_publication_lease().unwrap();
        let mut original = lease
            .begin_raw_geometry_attempt(request, &BTreeSet::new())
            .unwrap();
        original.resume_under(&lease).unwrap();
        original.publish_catalog_under(&lease, None).unwrap();
        for (binding, path) in bindings.iter().zip(paths) {
            kura.require_lane_marker_at(&path, binding).unwrap();
            assert!(!path.join("lane_artifacts").exists());
        }
    });
}

mod original_watch_release_tests {
    use super::*;
    use std::{
        future::Future,
        sync::atomic::AtomicUsize,
        task::{Context, Wake, Waker},
    };

    struct Probe {
        kura: Arc<Kura>,
        calls: AtomicUsize,
        blocked: AtomicUsize,
        reentered: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            let free = self
                .kura
                .publication_fences_for_test()
                .iter()
                .all(|(_, lock)| lock.try_lock().is_some());
            self.blocked.fetch_add(usize::from(!free), Ordering::SeqCst);
            if free {
                // Reenter the real physical acquisition, on this default test stack.
                let lease = self
                    .kura
                    .try_publication_lease()
                    .expect("callback original Kura");
                self.reentered.fetch_add(1, Ordering::SeqCst);
                drop(lease);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Clone, Copy)]
    enum Completion {
        CapturedRollback,
        AppliedRollback,
        Catalog,
        PureDrop,
        PartialError,
        Unwind,
    }

    fn check_original_watch(completion: Completion) {
        with_raw_geometry_fixture(|kura, request| {
            let probe = Arc::new(Probe {
                kura: Arc::clone(kura),
                calls: AtomicUsize::new(0),
                blocked: AtomicUsize::new(0),
                reentered: AtomicUsize::new(0),
            });
            let waker = Waker::from(Arc::clone(&probe));
            let lease = kura.try_publication_lease().unwrap();
            let original = lease
                .begin_raw_geometry_attempt(request, &BTreeSet::new())
                .unwrap();
            let mut wait = match lease.begin_raw_geometry_attempt(request, &BTreeSet::new()) {
                Err(Error::LaneGeometryAttemptBusy { wait }) => wait,
                other => panic!("original claim must exclude a competitor: {other:?}"),
            };
            let mut future = Box::pin(wait.wait_for_release());
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut original = original;
                match completion {
                    Completion::CapturedRollback => original.rollback_under(&lease).unwrap(),
                    Completion::AppliedRollback => {
                        original.resume_under(&lease).unwrap();
                        original.rollback_under(&lease).unwrap();
                    }
                    Completion::Catalog => {
                        original.resume_under(&lease).unwrap();
                        original.publish_catalog_under(&lease, None).unwrap();
                    }
                    Completion::PureDrop => (),
                    Completion::PartialError => {
                        crate::kura::fail_next_bound_progress_intent_file_sync_for_tests();
                        assert!(original.resume_under(&lease).is_err());
                        assert!(original.has_pending_journal_write());
                    }
                    Completion::Unwind => {
                        std::panic::resume_unwind(Box::new("original geometry unwind"))
                    }
                }
            }));
            assert_eq!(outcome.is_err(), matches!(completion, Completion::Unwind));
            if let Err(payload) = outcome {
                assert_eq!(
                    payload.downcast_ref::<&'static str>(),
                    Some(&"original geometry unwind")
                );
            }
            if matches!(completion, Completion::PartialError) {
                assert!(matches!(
                    lease.begin_raw_geometry_attempt(request, &BTreeSet::new()),
                    Err(Error::LaneGeometryAttemptAbandoned)
                ));
            } else {
                let mut replacement = lease
                    .begin_raw_geometry_attempt(request, &BTreeSet::new())
                    .unwrap();
                replacement.rollback_under(&lease).unwrap();
            }
            drop(lease);
            assert_eq!(
                probe.blocked.load(Ordering::SeqCst),
                0,
                "original geometry watch must wait for all physical owners"
            );
            assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
            assert_eq!(probe.reentered.load(Ordering::SeqCst), 1);
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_ready()
            );
        });
    }

    #[test]
    fn original_geometry_captured_rollback_watch_follows_physical_cleanup() {
        check_original_watch(Completion::CapturedRollback);
    }
    #[test]
    fn original_geometry_applied_rollback_watch_follows_physical_cleanup() {
        check_original_watch(Completion::AppliedRollback);
    }
    #[test]
    fn original_geometry_catalog_watch_follows_physical_cleanup() {
        check_original_watch(Completion::Catalog);
    }
    #[test]
    fn original_geometry_pure_drop_watch_follows_physical_cleanup() {
        check_original_watch(Completion::PureDrop);
    }
    #[test]
    fn original_geometry_partial_error_watch_follows_physical_cleanup() {
        check_original_watch(Completion::PartialError);
    }
    #[test]
    fn original_geometry_unwind_watch_follows_physical_cleanup() {
        check_original_watch(Completion::Unwind);
    }

    fn check_capture_exit_watch(unwind: bool) {
        with_raw_geometry_fixture(|kura, request| {
            let probe = Arc::new(Probe {
                kura: Arc::clone(kura),
                calls: AtomicUsize::new(0),
                blocked: AtomicUsize::new(0),
                reentered: AtomicUsize::new(0),
            });
            let waker = Waker::from(Arc::clone(&probe));
            let parked = std::rc::Rc::new(std::cell::RefCell::new(
                None::<std::pin::Pin<Box<dyn Future<Output = ()>>>>,
            ));
            let parked_hook = std::rc::Rc::clone(&parked);
            let hook_waker = waker.clone();
            let journal = kura.lane_geometry_journal_path();
            let original_bytes = fs::read(&journal).unwrap();
            let hook_journal = journal.clone();
            super::super::raw_attempt::observe_original_capture_for_test(move |gate| {
                let mut wait = match gate.ensure_unclaimed() {
                    Err(Error::LaneGeometryAttemptBusy { wait }) => wait,
                    other => panic!("capture owns its exact original claim: {other:?}"),
                };
                let mut future = Box::pin(async move { wait.wait_for_release().await });
                assert!(
                    future
                        .as_mut()
                        .poll(&mut Context::from_waker(&hook_waker))
                        .is_pending()
                );
                *parked_hook.borrow_mut() = Some(future);
                if unwind {
                    std::panic::resume_unwind(Box::new("original capture unwind"));
                }
                // The real capture reader rejects this exact malformed source.
                fs::write(&hook_journal, [0]).unwrap();
            });
            let lease = kura.try_publication_lease().unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                lease.begin_raw_geometry_attempt(request, &BTreeSet::new())
            }));
            assert_eq!(result.is_err(), unwind);
            match result {
                Ok(result) => assert!(result.is_err()),
                Err(payload) => assert_eq!(
                    payload.downcast_ref::<&'static str>(),
                    Some(&"original capture unwind")
                ),
            }
            fs::write(&journal, original_bytes).unwrap();
            let mut replacement = lease
                .begin_raw_geometry_attempt(request, &BTreeSet::new())
                .unwrap();
            replacement.rollback_under(&lease).unwrap();
            drop(lease);
            assert_eq!(
                probe.blocked.load(Ordering::SeqCst),
                0,
                "original geometry watch must wait for all physical owners"
            );
            assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
            assert!(
                parked
                    .borrow_mut()
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_ready()
            );
        });
    }

    #[test]
    fn original_geometry_capture_error_watch_follows_physical_cleanup() {
        check_capture_exit_watch(false);
    }
    #[test]
    fn original_geometry_capture_unwind_watch_follows_physical_cleanup() {
        check_capture_exit_watch(true);
    }

    #[test]
    fn original_geometry_detached_notices_do_not_wait_for_another_cleanup_owner() {
        with_raw_geometry_fixture(|kura, request| {
            let mut futures = Vec::new();
            let mut probes = Vec::new();
            let mut cleanups = Vec::new();
            for _ in 0..2 {
                let probe = Arc::new(Probe {
                    kura: Arc::clone(kura),
                    calls: AtomicUsize::new(0),
                    blocked: AtomicUsize::new(0),
                    reentered: AtomicUsize::new(0),
                });
                let waker = Waker::from(Arc::clone(&probe));
                let lease = kura.try_publication_lease().unwrap();
                let mut original = lease
                    .begin_raw_geometry_attempt(request, &BTreeSet::new())
                    .unwrap();
                let mut wait = match lease.begin_raw_geometry_attempt(request, &BTreeSet::new()) {
                    Err(Error::LaneGeometryAttemptBusy { wait }) => wait,
                    other => panic!("original capture owns its claim: {other:?}"),
                };
                let mut future = Box::pin(async move { wait.wait_for_release().await });
                assert!(
                    future
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
                original.rollback_under(&lease).unwrap();
                drop(original);
                cleanups.push(lease.release_deferred());
                futures.push(future);
                probes.push(probe);
            }
            assert!(
                probes
                    .iter()
                    .all(|probe| probe.calls.load(Ordering::SeqCst) == 0)
            );
            drop(cleanups.remove(0));
            assert_eq!(probes[0].calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                probes[1].calls.load(Ordering::SeqCst),
                0,
                "a later original notice stays with its own cleanup"
            );
            drop(cleanups.pop());
            for (probe, mut future) in probes.into_iter().zip(futures) {
                assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
                assert_eq!(probe.blocked.load(Ordering::SeqCst), 0);
                assert!(
                    future
                        .as_mut()
                        .poll(&mut Context::from_waker(&Waker::from(probe)))
                        .is_ready()
                );
            }
        });
    }
}
