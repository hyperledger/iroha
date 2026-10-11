//! Real lifecycle index releases must follow every enclosing fence.

use super::*;
use iroha_allocation::release::{DeferredRelease, ReleaseRegistration, ReleaseWait};
use std::{
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Wake, Waker},
};

struct Probe {
    state: Arc<State>,
    calls: AtomicUsize,
    blocked: AtomicUsize,
    odd: AtomicUsize,
    unavailable: AtomicUsize,
    cleanup: Mutex<Vec<DeferredRelease>>,
}
impl Probe {
    fn new(state: Arc<State>) -> Arc<Self> {
        Arc::new(Self {
            state,
            calls: AtomicUsize::new(0),
            blocked: AtomicUsize::new(0),
            odd: AtomicUsize::new(0),
            unavailable: AtomicUsize::new(0),
            cleanup: Mutex::new(Vec::new()),
        })
    }
    fn check(&self) {
        assert!(self.calls.load(Ordering::SeqCst) > 0);
        assert_eq!(self.blocked.load(Ordering::SeqCst), 0);
        assert_eq!(self.odd.load(Ordering::SeqCst), 0);
        assert_eq!(self.unavailable.load(Ordering::SeqCst), 0);
    }
}
impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        let Ok(mut cleanup) = self.cleanup.try_lock() else {
            self.unavailable.fetch_add(1, Ordering::SeqCst);
            return;
        };
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.odd.fetch_add(
            usize::from(self.state.state_view_generation() % 2 != 0),
            Ordering::SeqCst,
        );
        macro_rules! fence {
            ($field:ident) => {
                if let Some(guard) = self.state.$field.try_lock() {
                    cleanup.push(guard.release_deferred());
                } else {
                    self.blocked.fetch_add(1, Ordering::SeqCst);
                }
            };
        }
        fence!(state_commit_lock);
        fence!(state_write_lock);
        fence!(lane_lifecycle_lock);
        if self.state.geometry_publication.try_lock().is_none() {
            self.blocked.fetch_add(1, Ordering::SeqCst);
        }
        macro_rules! index {
            ($field:ident) => {
                if let Some(guard) = self.state.$field.try_write() {
                    cleanup.push(guard.release_deferred());
                } else {
                    self.blocked.fetch_add(1, Ordering::SeqCst);
                }
            };
        }
        index!(lane_manifests);
        index!(lane_privacy_registry);
        index!(da_commitments);
        index!(da_confidential_compute);
        index!(da_receipt_cursors);
        index!(da_shard_cursors);
        index!(da_pin_intents);
        index!(da_indexes_hydrated);
        // All physical probes are nonblocking. Keep their actual cleanup outside Wake.
    }
}

fn watch<T>(
    index: &PublicationRwLock<T>,
    probe: &Arc<Probe>,
) -> (ReleaseWait, ReleaseRegistration, DeferredRelease) {
    let mut registration =
        crate::unit_test_support::release_registration(&probe.state.ivm_execution_budget());
    let guard = index.read();
    let wait = index
        .try_write_or_wait()
        .err()
        .expect("original held reader");
    let release = guard.release_deferred();
    let waker = Waker::from(Arc::clone(probe));
    assert!(
        registration
            .poll_wait(&wait, &mut Context::from_waker(&waker))
            .is_pending()
    );
    (wait, registration, release)
}

fn ready(watches: &mut [(ReleaseWait, ReleaseRegistration, DeferredRelease)], probe: &Arc<Probe>) {
    let waker = Waker::from(Arc::clone(probe));
    assert!(watches.iter_mut().all(|(wait, registration, _)| {
        registration
            .poll_wait(wait, &mut Context::from_waker(&waker))
            .is_ready()
    }));
    probe.check();
}

#[test]
fn manifest_install_and_unwind_defer_indexes_until_even_generation_and_free_fence() {
    for unwind in [false, true] {
        let state = Arc::new(blank_test_state());
        let manifests = state.lane_manifests.read().clone();
        let before = state.state_view_generation();
        let probe = Probe::new(Arc::clone(&state));
        let mut watches = vec![watch(&state.lane_manifests, &probe)];
        if !unwind {
            watches.push(watch(&state.lane_privacy_registry, &probe));
        }
        if unwind {
            lifecycle_index_publication::panic_after_manifest_write_for_test();
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.install_lane_manifests_for_testing(&manifests);
        }));
        assert_eq!(result.is_err(), unwind);
        assert_eq!(state.state_view_generation(), before + 2);
        ready(&mut watches, &probe);
    }
}

#[test]
fn compatible_manifest_refresh_defers_real_read_release_without_publication() {
    for refuse in [false, true] {
        let state = blank_test_state();
        let nexus = state.nexus_snapshot();
        let original = Arc::new(LaneManifestRegistry::from_config(
            &nexus.lane_catalog,
            &nexus.governance,
            &iroha_config::parameters::actual::LaneRegistry::default(),
        ));
        // Load a different immutable source set for the incompatible-policy branch.
        let source_dir = tempfile::tempdir().unwrap();
        let alias = &nexus.lane_catalog.lanes()[0].alias;
        std::fs::write(
            source_dir.path().join(format!("{alias}.manifest.json")),
            norito::json::to_vec(&norito::json!({"lane": alias})).unwrap(),
        )
        .unwrap();
        state.install_lane_manifests_for_testing(&original);
        let candidate = if refuse {
            Arc::new(LaneManifestRegistry::from_config(
                &nexus.lane_catalog,
                &nexus.governance,
                &iroha_config::parameters::actual::LaneRegistry {
                    manifest_directory: Some(source_dir.path().to_path_buf()),
                    ..Default::default()
                },
            ))
        } else {
            Arc::clone(&original)
        };
        assert!(candidate.is_bound_to_catalog(&nexus.lane_catalog));
        if refuse {
            assert_ne!(
                candidate.consensus_policy_digest(),
                original.consensus_policy_digest()
            );
        }
        let state = Arc::new(state);
        let probe = Probe::new(Arc::clone(&state));
        let mut watches = vec![watch(&state.lane_manifests, &probe)];
        let generation = state.state_view_generation();
        let privacy = state.lane_privacy_registry.read().clone();
        assert_eq!(
            state.install_lane_manifests_if_consensus_compatible(&candidate),
            !refuse
        );
        ready(&mut watches, &probe);
        assert_eq!(state.state_view_generation(), generation);
        assert!(Arc::ptr_eq(&state.lane_manifests.read(), &original));
        assert!(Arc::ptr_eq(&state.lane_privacy_registry.read(), &privacy));
        assert_eq!(
            state.lane_manifests.read().consensus_policy_digest(),
            original.consensus_policy_digest()
        );
    }
}

#[test]
fn lifecycle_transition_and_partial_manifest_unwind_defer_original_indexes() {
    for unwind in [false, true] {
        let state = Arc::new(blank_test_state());
        let probe = Probe::new(Arc::clone(&state));
        let mut watches = vec![
            watch(&state.lane_manifests, &probe),
            watch(&state.da_shard_cursors, &probe),
            watch(&state.da_indexes_hydrated, &probe),
        ];
        if !unwind {
            watches.extend([
                watch(&state.lane_privacy_registry, &probe),
                watch(&state.da_commitments, &probe),
                watch(&state.da_confidential_compute, &probe),
                watch(&state.da_receipt_cursors, &probe),
                watch(&state.da_pin_intents, &probe),
            ]);
        } else {
            lifecycle_index_publication::panic_after_manifest_write_for_test();
        }
        let plan = iroha_data_model::nexus::LaneLifecyclePlan {
            additions: vec![LaneConfig {
                id: LaneId::new(1),
                alias: "custody-lane".to_owned(),
                ..LaneConfig::default()
            }],
            retire: Vec::new(),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.apply_lane_lifecycle(&plan)
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            result
                .expect("normal return")
                .expect("actual lifecycle transition");
        }
        ready(&mut watches, &probe);
    }
}
