//! Native lock and deadline controls for scheduling; no owned child or Ready is fabricated.

use super::*;
use crate::managed::service_bootstrap::ManagedServiceBootstrap;
use std::sync::atomic::AtomicUsize;

fn budget() -> Budget {
    Budget {
        started: Instant::now(),
        timeout: Duration::from_secs(120),
        startup_deadline_ns: None,
        utc_ceiling_unix_ms: None,
        cancelled: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(Progress::default()),
    }
}

struct NativeSelection<'a> {
    calls: &'a AtomicUsize,
    refuse: bool,
}
impl LiveGatewayProcess for NativeSelection<'_> {
    fn validate(
        &mut self,
        prepared: &PreparedLocalnet,
        _: &RetainedGatewayCompliancePlan,
    ) -> Result<()> {
        // The callback owns the same real exclusive parent purpose used by full renderer
        // validation. The outer guard must prevent competing callbacks from colliding here.
        let parent = ManagedServiceBootstrap::open(prepared)?;
        assert!(ManagedServiceBootstrap::open(prepared).is_err());
        self.calls.fetch_add(1, Ordering::SeqCst);
        drop(parent);
        if self.refuse {
            Err(invalid("ordinary validation refusal"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn catalog_validation_serializes_original_native_owners_and_releases_on_error() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "catalog-native-lock",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let plans = prepared.provider_service_plans().unwrap().unwrap();
    let validation = Mutex::new(());
    let budget = budget();
    let calls = AtomicUsize::new(0);
    for refuse in [false, true, false] {
        let result = crate::managed::provider_round::run(
            [0, 1, 2],
            true,
            |slot| {
                let plan = prepared
                    .gateway_compliance_plan(plans[slot].provider_id())?
                    .unwrap();
                let mut actual = NativeSelection {
                    calls: &calls,
                    refuse: refuse && slot == 0,
                };
                let mut guarded = GuardedGateway {
                    gateway: &mut actual,
                    validation: &validation,
                    budget: &budget,
                };
                guarded.validate(&prepared, &plan)
            },
            || invalid("test worker did not complete"),
        );
        assert_eq!(result.is_err(), refuse);
        assert!(validation.try_lock().is_ok());
        drop(ManagedServiceBootstrap::open(&prepared).unwrap());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 9);
}

#[test]
fn waiting_validation_rejects_original_cancellation_and_expiry_without_entering_callback() {
    let validation = Mutex::new(());
    let held = validation.lock().unwrap();
    let cancelled = budget();
    cancelled.cancelled.store(true, Ordering::Release);
    assert!(acquire_validation(&validation, &cancelled).is_err());
    let expired = Budget {
        started: Instant::now() - Duration::from_secs(121),
        ..budget()
    };
    assert!(acquire_validation(&validation, &expired).is_err());
    // Cancellation while a worker waits must also finish without waiting for the holder.
    let waiting = budget();
    thread::scope(|scope| {
        let worker = scope.spawn(|| acquire_validation(&validation, &waiting).map(|_| ()));
        waiting.cancelled.store(true, Ordering::Release);
        assert!(worker.join().unwrap().is_err());
    });
    drop(held);
    assert!(acquire_validation(&validation, &budget()).is_ok());
}
