pub(super) mod original_recovery_release_tests {
    use super::*;
    use std::{
        cell::Cell,
        future::Future,
        pin::Pin,
        sync::atomic::AtomicUsize,
        task::{Context, Wake, Waker},
    };

    thread_local! {
        static UNWIND_AFTER_FENCE: Cell<Option<usize>> = const { Cell::new(None) };
    }

    // Test-only unwind at the real acquired physical boundary; no production policy changes.
    pub(in crate::kura::lane_geometry) fn fence_boundary(stage: usize) {
        if UNWIND_AFTER_FENCE.with(|fault| {
            if fault.get() == Some(stage) {
                fault.set(None);
                true
            } else {
                false
            }
        }) {
            std::panic::resume_unwind(Box::new("original geometry recovery unwind"));
        }
    }

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
                // Probe real aggregate acquisition on the ordinary test stack. A genuine
                // storage refusal remains an error, but no sibling mutex may remain Busy.
                let result = self.kura.try_publication_lease();
                if matches!(
                    result,
                    Err(crate::kura::KuraPublicationPreparationError::Busy { .. })
                ) {
                    self.blocked.fetch_add(1, Ordering::SeqCst);
                } else {
                    self.reentered.fetch_add(1, Ordering::SeqCst);
                }
                drop(result);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Clone, Copy)]
    enum RecoveryPath {
        Preflight,
        Replay,
        Startup,
    }
    impl RecoveryPath {
        fn fence_count(self) -> usize {
            match self {
                Self::Preflight => 3,
                Self::Replay | Self::Startup => 4,
            }
        }
        fn run(
            self,
            kura: &Kura,
            config: &RuntimeLaneConfig,
            incarnations: &BTreeMap<LaneId, Hash>,
            activations: &BTreeMap<LaneId, u64>,
            lineage_root: Hash,
        ) -> Result<()> {
            match self {
                Self::Preflight => kura.preflight_lane_geometry_recovery_floor_with_lineage_root(
                    config,
                    incarnations,
                    activations,
                    lineage_root,
                ),
                Self::Replay => kura.recover_lane_geometry_journal_at_height_with_lineage_root(
                    config,
                    incarnations,
                    activations,
                    0,
                    lineage_root,
                ),
                Self::Startup => kura.recover_journal_owned_lane_instances_on_startup(),
            }
        }
    }

    fn observe_original_release(kura: &Arc<Kura>, fence: usize, operation: impl FnOnce()) {
        let budget = kura.transaction_history_budget();
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let original = kura.publication_fences_for_test()[fence]
            .1
            .observe_release();
        let mut wait = original.wait_for_release(&mut registration);
        let probe = Arc::new(Probe {
            kura: Arc::clone(kura),
            calls: AtomicUsize::new(0),
            blocked: AtomicUsize::new(0),
            reentered: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&probe));
        assert!(
            Pin::new(&mut wait)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        operation();
        assert_eq!(
            probe.calls.load(Ordering::SeqCst),
            1,
            "one original physical release"
        );
        assert_eq!(
            probe.blocked.load(Ordering::SeqCst),
            0,
            "original geometry recovery notice must wait for every physical fence"
        );
        assert_eq!(probe.reentered.load(Ordering::SeqCst), 1);
        assert!(
            Pin::new(&mut wait)
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        drop(wait);
        assert!(registration.belongs_to(&budget));
        let reserved = budget.reserved_bytes();
        let charge = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
        assert!(reserved >= charge);
        drop(registration);
        assert_eq!(budget.reserved_bytes(), reserved - charge);
    }

    fn check_completion(path: RecoveryPath, refused: bool) {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("kura");
        let (initial, extended) = initial_and_extended_configs();
        let (mut incarnations, activations) = initial_geometry();
        let kura = open_kura(&root, &initial);
        authenticate_transition_fixture_primary(&kura, &initial, &incarnations);
        let bindings = kura
            .geometry_bindings(&initial, &incarnations, &activations)
            .unwrap();
        let lineage_root = unscoped_lineage_root(&bindings);
        if refused {
            match path {
                RecoveryPath::Preflight => {
                    incarnations.insert(LaneId::SINGLE, Hash::prehashed([0x62; Hash::LENGTH]));
                }
                RecoveryPath::Replay => {
                    let (extended_incarnations, extended_activations) = extended_geometry();
                    persist_create_intent(
                        &kura,
                        &initial,
                        &extended,
                        &incarnations,
                        &extended_incarnations,
                        &activations,
                        &extended_activations,
                    );
                }
                RecoveryPath::Startup => {
                    let marker = kura
                        .binding_blocks_path(&bindings[0])
                        .join(MARKER_FILE_NAME);
                    fs::write(marker, b"corrupt original instance marker").unwrap();
                }
            }
        }
        let before = native_observation_tree(&root);
        observe_original_release(&kura, path.fence_count() - 1, || {
            let result = path.run(&kura, &initial, &incarnations, &activations, lineage_root);
            if refused {
                let error = result.expect_err("original recovery source must refuse");
                match path {
                    RecoveryPath::Preflight => assert_geometry_io_error(
                        &error,
                        ErrorKind::InvalidData,
                        "configured-primary geometry binding differs from its durable anchor",
                    ),
                    RecoveryPath::Replay => assert_geometry_io_error(
                        &error,
                        ErrorKind::InvalidData,
                        "authoritative geometry identity does not match its exact transition cursor",
                    ),
                    RecoveryPath::Startup => assert!(matches!(error, Error::NoritoFrame(_))),
                }
            } else {
                result.unwrap();
            }
        });
        assert_eq!(
            native_observation_tree(&root),
            before,
            "release custody must not rewrite or discard the original retained evidence"
        );
    }

    #[test]
    fn original_geometry_preflight_success_notifies_after_all_fences() {
        check_completion(RecoveryPath::Preflight, false);
    }
    #[test]
    fn original_geometry_preflight_refusal_notifies_after_all_fences() {
        check_completion(RecoveryPath::Preflight, true);
    }
    #[test]
    fn original_geometry_replay_success_notifies_after_all_fences() {
        check_completion(RecoveryPath::Replay, false);
    }
    #[test]
    fn original_geometry_replay_refusal_notifies_after_all_fences() {
        check_completion(RecoveryPath::Replay, true);
    }
    #[test]
    fn original_geometry_startup_success_notifies_after_all_fences() {
        // The production constructor has not exposed Kura yet; this exercises the same
        // helper with an observable owner, without claiming a cold-start waiter exists.
        check_completion(RecoveryPath::Startup, false);
    }
    #[test]
    fn original_geometry_startup_refusal_notifies_after_all_fences() {
        check_completion(RecoveryPath::Startup, true);
    }

    #[test]
    fn original_geometry_recovery_partial_refusals_keep_exact_errors_and_release_sources() {
        for stage in 1..=3 {
            let temp = TempDir::new().unwrap();
            let root = temp.path().join("kura");
            let (initial, _) = initial_and_extended_configs();
            let (mut incarnations, activations) = initial_geometry();
            let kura = open_kura(&root, &initial);
            authenticate_transition_fixture_primary(&kura, &initial, &incarnations);
            let bindings = kura
                .geometry_bindings(&initial, &incarnations, &activations)
                .unwrap();
            let lineage_root = unscoped_lineage_root(&bindings);
            match stage {
                1 => kura.prune_recovery_required.store(true, Ordering::Release),
                2 => kura
                    .canonical_storage_poisoned
                    .store(true, Ordering::Release),
                3 => {
                    incarnations.remove(&LaneId::SINGLE);
                }
                _ => unreachable!(),
            }
            let before = native_observation_tree(&root);
            observe_original_release(&kura, stage - 1, || {
                let error = RecoveryPath::Replay
                    .run(&kura, &initial, &incarnations, &activations, lineage_root)
                    .expect_err("partial original acquisition must preserve its storage cause");
                match stage {
                    1 => assert!(matches!(error, Error::PruneRecoveryRequired)),
                    2 => assert!(matches!(error, Error::CanonicalStoragePoisoned)),
                    3 => assert_geometry_io_error(
                        &error,
                        ErrorKind::InvalidInput,
                        "lane geometry is missing an incarnation commitment",
                    ),
                    _ => unreachable!(),
                }
            });
            assert_eq!(native_observation_tree(&root), before);
        }
    }

    #[test]
    fn original_geometry_recovery_unwind_notifies_after_every_acquired_fence() {
        for path in [
            RecoveryPath::Preflight,
            RecoveryPath::Replay,
            RecoveryPath::Startup,
        ] {
            for stage in 1..=path.fence_count() {
                let temp = TempDir::new().unwrap();
                let root = temp.path().join("kura");
                let (initial, _) = initial_and_extended_configs();
                let (incarnations, activations) = initial_geometry();
                let kura = open_kura(&root, &initial);
                authenticate_transition_fixture_primary(&kura, &initial, &incarnations);
                let bindings = kura
                    .geometry_bindings(&initial, &incarnations, &activations)
                    .unwrap();
                let lineage_root = unscoped_lineage_root(&bindings);
                let before = native_observation_tree(&root);
                observe_original_release(&kura, stage - 1, || {
                    UNWIND_AFTER_FENCE.with(|fault| fault.set(Some(stage)));
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        path.run(&kura, &initial, &incarnations, &activations, lineage_root)
                    }));
                    UNWIND_AFTER_FENCE.with(|fault| fault.set(None));
                    let error = result.expect_err("unwind after the original acquired fence");
                    assert_eq!(
                        error.downcast_ref::<&'static str>(),
                        Some(&"original geometry recovery unwind")
                    );
                });
                assert_eq!(native_observation_tree(&root), before);
            }
        }
    }
}
