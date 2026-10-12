//! Exact AES costs retain original per-family scheduling and physical health.

use super::super::aes_tests::ScalarOverride;
use super::*;
use crate::vector::metal_owner::{DeviceRegistry, FairProgress};
use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Mutex,
};

fn winning_profile(geometry: Geometry, baseline: AesCpuBaseline) -> Profile {
    Profile::from_trials(
        geometry,
        baseline,
        [[100; TRIALS]; PATTERNS],
        [[20; TRIALS]; PATTERNS],
    )
    .unwrap()
}

#[test]
fn batch_scheduler_unwind_keeps_later_calibration_and_original_quarantine() {
    let _baseline = ScalarOverride::new();
    for work in [
        MetalBatchWork::Encrypt,
        MetalBatchWork::Decrypt,
        MetalBatchWork::EncryptRounds(2),
        MetalBatchWork::DecryptRounds(2),
    ] {
        let geometry = Geometry::new(work, 128).unwrap();
        let baseline = AesCpuBaseline::capture(work);
        let registry = DeviceRegistry::<Mutex<CostCache>>::new();
        let credit = iroha_allocation::AllocationBudget::new(16384);
        assert!(registry.prepare(2, |layout| credit.try_reserve(layout).ok()));
        for identity in [11, 22] {
            let record = registry
                .observe(identity, 2, |bytes| credit.try_reserve_bytes(bytes).ok())
                .unwrap();
            assert!(record.initialize(|| Some(Mutex::new(CostCache::default()))));
        }
        let first = registry.record(0, 2).unwrap();
        let second = registry.record(1, 2).unwrap();
        let first_cache = first.value().unwrap();
        let progress = FairProgress::new();
        let now = Instant::now();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let mut pass = progress.try_pass(2, now, MAX_CALIBRATION).unwrap();
                let start = pass.start();
                let _ = registry.select_costed(2, 2, start, |index, record, cache| {
                    cache.try_lock().ok()?.qualified_cost(
                        now,
                        geometry,
                        baseline,
                        || pass.begin_attempt(index, now),
                        |_| {
                            assert_eq!(record.health().identity(), 11);
                            record.health().quarantine(true);
                            panic!("backend unwind through actual cache and family pass")
                        },
                    )
                });
            }))
            .is_err()
        );
        assert!(!first.health().usable());
        assert!(first_cache.is_poisoned());
        {
            let untouched = second.value().unwrap().lock().unwrap();
            assert!(
                untouched.retry_after.is_none(),
                "unvisited device receives no panic penalty"
            );
            assert!(untouched.profile.is_none());
        }
        let later = now + Duration::from_millis(1);
        let mut pass = progress
            .try_pass(2, later, MAX_CALIBRATION)
            .expect("family cursor recovers its scalar state");
        assert_eq!(
            pass.start(),
            1,
            "recorded progress survives poison recovery"
        );
        assert!(
            progress.try_pass(2, later, MAX_CALIBRATION).is_none(),
            "WouldBlock remains nonblocking after recovery"
        );
        let profile = winning_profile(geometry, baseline);
        let start = pass.start();
        let selected = registry
            .select_costed(2, 1, start, |index, record, cache| {
                cache.try_lock().ok()?.qualified_cost(
                    later,
                    geometry,
                    baseline,
                    || pass.begin_attempt(index, later),
                    |_| {
                        assert_eq!(record.health().identity(), 22);
                        Ok(profile)
                    },
                )
            })
            .expect("later healthy device calibrates immediately after scheduling recovery");
        assert_eq!(selected.health().identity(), 22);
        assert!(
            !first.health().usable(),
            "scheduler recovery cannot revive physical health"
        );
        assert!(
            first_cache.is_poisoned(),
            "coupled profile mutex is never recovered as scalar state"
        );
    }
}

#[test]
fn fair_batch_sampling_defers_without_penalty_for_each_public_family() {
    let _baseline = ScalarOverride::new();
    for work in [
        MetalBatchWork::Encrypt,
        MetalBatchWork::Decrypt,
        MetalBatchWork::EncryptRounds(2),
        MetalBatchWork::DecryptRounds(2),
    ] {
        let geometry = Geometry::new(work, 128).unwrap();
        let baseline = AesCpuBaseline::capture(work);
        let registry = DeviceRegistry::<Mutex<CostCache>>::new();
        let credit = iroha_allocation::AllocationBudget::new(16384);
        assert!(registry.prepare(2, |layout| credit.try_reserve(layout).ok()));
        for identity in [11, 22] {
            let record = registry
                .observe(identity, 2, |bytes| credit.try_reserve_bytes(bytes).ok())
                .unwrap();
            assert!(record.initialize(|| Some(Mutex::new(CostCache::default()))));
        }
        let profile = winning_profile(geometry, baseline);
        let progress = FairProgress::new();
        let base = Instant::now();
        let first_attempts = Cell::new(0);
        let second_attempts = Cell::new(0);
        for turn in 0..3 {
            let now = base + RETRY_AFTER * turn;
            let clock = Cell::new(now);
            let mut pass = progress.try_pass(2, now, MAX_CALIBRATION).unwrap();
            let start = pass.start();
            let selected = registry.select_costed(2, 2, start, |index, record, cache| {
                cache.lock().unwrap().qualified_cost(
                    clock.get(),
                    geometry,
                    baseline,
                    || pass.begin_attempt(index, clock.get()),
                    |started| {
                        if record.health().identity() == 11 {
                            first_attempts.set(first_attempts.get() + 1);
                            clock.set(started + MAX_CALIBRATION);
                            Err(CalibrationFailure::Overloaded)
                        } else {
                            second_attempts.set(second_attempts.get() + 1);
                            Ok(profile)
                        }
                    },
                )
            });
            if turn == 0 {
                assert!(selected.is_none());
                let later = registry.record(1, 2).unwrap();
                let cache = later.value().unwrap().lock().unwrap();
                assert!(cache.retry_after.is_none());
                assert!(cache.profile.is_none(), "deferred work was never attempted");
            } else {
                assert_eq!(selected.unwrap().health().identity(), 22);
            }
        }
        assert_eq!(first_attempts.get(), 3);
        assert_eq!(second_attempts.get(), 1);
    }
}
