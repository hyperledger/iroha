//! Exact AES cache keys, conservative timing and original cooldown state.

use super::super::aes_tests::ScalarOverride;
use super::*;
use crate::aes::cpu::Backend;

fn profile(geometry: Geometry, baseline: AesCpuBaseline, cpu: u64, metal: u64) -> Profile {
    Profile::from_trials(
        geometry,
        baseline,
        [[cpu; TRIALS]; PATTERNS],
        [[metal; TRIALS]; PATTERNS],
    )
    .unwrap()
}

#[test]
fn exact_key_rejects_neighboring_blocks_and_distinct_families_or_rounds() {
    let work = MetalBatchWork::EncryptRounds(9);
    let geometry = Geometry::new(work, 129).unwrap();
    for neighbor in [128, 130, 513, 2_047] {
        assert_ne!(geometry, Geometry::new(work, neighbor).unwrap());
    }
    for other in [
        MetalBatchWork::Encrypt,
        MetalBatchWork::Decrypt,
        MetalBatchWork::EncryptRounds(1),
        MetalBatchWork::EncryptRounds(8),
        MetalBatchWork::DecryptRounds(9),
    ] {
        assert_ne!(geometry, Geometry::new(other, 129).unwrap());
    }
    for work in [
        MetalBatchWork::Encrypt,
        MetalBatchWork::Decrypt,
        MetalBatchWork::EncryptRounds(1),
        MetalBatchWork::DecryptRounds(64),
    ] {
        for blocks in [0, 1, 31, 2_049, usize::MAX] {
            assert!(Geometry::new(work, blocks).is_none());
        }
        for blocks in [32, 33, 129, 513, 2_047, 2_048] {
            assert!(Geometry::new(work, blocks).is_some());
        }
    }
    for rounds in [0, 65, usize::MAX] {
        assert!(Geometry::new(MetalBatchWork::EncryptRounds(rounds), 128).is_none());
        assert!(Geometry::new(MetalBatchWork::DecryptRounds(rounds), 128).is_none());
    }
}

#[test]
fn conservative_cost_uses_fastest_cpu_slowest_gpu_and_full_width_margin() {
    let _scalar = ScalarOverride::new();
    let work = MetalBatchWork::EncryptRounds(9);
    let geometry = Geometry::new(work, 129).unwrap();
    let baseline = AesCpuBaseline::capture(work);
    let measured = Profile::from_trials(
        geometry,
        baseline,
        [[80, 90, 100], [100, 110, 120]],
        [[40, 45, 50], [50, 55, 60]],
    )
    .unwrap();
    assert_eq!(
        (measured.cpu_ns, measured.metal_ns, measured.cost()),
        (80, 60, Some(60))
    );
    assert_eq!(profile(geometry, baseline, 100, 90).cost(), None);
    assert_eq!(profile(geometry, baseline, 100, 89).cost(), Some(89));
    assert_eq!(
        profile(geometry, baseline, u64::MAX, u64::MAX - 1).cost(),
        None
    );
    assert_eq!(
        profile(geometry, baseline, u64::MAX, u64::MAX / 2).cost(),
        Some(u64::MAX / 2)
    );
    for invalid in [[[0; TRIALS]; PATTERNS], [[1, 5, 1]; PATTERNS]] {
        assert_eq!(
            Profile::from_trials(geometry, baseline, invalid, [[1; TRIALS]; PATTERNS]).unwrap_err(),
            CalibrationFailure::Overloaded
        );
        assert_eq!(
            Profile::from_trials(geometry, baseline, [[1; TRIALS]; PATTERNS], invalid).unwrap_err(),
            CalibrationFailure::Overloaded
        );
    }
    let other = AesCpuBaseline::capture(MetalBatchWork::DecryptRounds(9));
    assert_eq!(
        Profile::from_trials(
            geometry,
            other,
            [[1; TRIALS]; PATTERNS],
            [[1; TRIALS]; PATTERNS]
        )
        .unwrap_err(),
        CalibrationFailure::CpuChanged
    );
}

#[test]
fn exact_hit_survives_cooldown_but_neighbor_waits_for_an_admitted_sample() {
    let _scalar = ScalarOverride::new();
    let work = MetalBatchWork::EncryptRounds(9);
    let first = Geometry::new(work, 129).unwrap();
    let second = Geometry::new(work, 130).unwrap();
    let baseline = AesCpuBaseline::capture(work);
    let now = Instant::now();
    let mut cache = CostCache::default();
    assert_eq!(
        cache.qualified_cost(now, first, baseline, || None, |_| panic!("unscheduled")),
        None
    );
    assert!(cache.retry_after.is_none());
    assert_eq!(
        cache.qualified_cost(
            now,
            first,
            baseline,
            || Some(now),
            |_| Ok(profile(first, baseline, 100, 20))
        ),
        Some(20)
    );
    assert_eq!(cache.retry_after, Some(now + RETRY_AFTER));
    assert_eq!(
        cache.qualified_cost(
            now,
            first,
            baseline,
            || panic!("warm cache"),
            |_| panic!("warm cache")
        ),
        Some(20)
    );
    assert_eq!(
        cache.qualified_cost(
            now,
            second,
            baseline,
            || panic!("cooldown"),
            |_| panic!("cooldown")
        ),
        None
    );
    let later = now + RETRY_AFTER;
    assert_eq!(
        cache.qualified_cost(
            later,
            second,
            baseline,
            || None,
            |_| panic!("busy scheduler")
        ),
        None
    );
    assert_eq!(
        cache.retry_after,
        Some(later),
        "deferral grants no new penalty"
    );
    assert_eq!(
        cache.qualified_cost(
            later,
            second,
            baseline,
            || Some(later),
            |_| Ok(profile(second, baseline, 100, 30))
        ),
        Some(30)
    );
    assert_eq!(cache.profile.unwrap().geometry, second);
    assert_eq!(
        cache.qualified_cost(
            later,
            first,
            baseline,
            || panic!("evicted exact key"),
            |_| panic!("cooldown")
        ),
        None
    );
}

#[test]
fn cpu_changes_preserve_original_cooldown_profile_and_healthy_gpu() {
    let _scalar = ScalarOverride::new();
    let work = MetalBatchWork::DecryptRounds(9);
    let first = Geometry::new(work, 129).unwrap();
    let second = Geometry::new(work, 130).unwrap();
    let baseline = AesCpuBaseline::capture(work);
    let stale = AesCpuBaseline {
        work,
        cpu: Backend::Native,
    };
    let now = Instant::now();
    let mut cache = CostCache::default();
    assert_eq!(
        cache.qualified_cost(
            now,
            first,
            baseline,
            || Some(now),
            |_| Ok(profile(first, baseline, 100, 20))
        ),
        Some(20)
    );
    assert_eq!(
        cache.qualified_cost(
            now,
            second,
            stale,
            || panic!("changed CPU"),
            |_| panic!("changed CPU")
        ),
        None
    );
    assert_eq!(cache.retry_after, Some(now + RETRY_AFTER));
    assert_eq!(
        cache.qualified_cost(
            now,
            second,
            baseline,
            || panic!("CPU toggle keeps cooldown"),
            |_| panic!("cooldown")
        ),
        None
    );
    let later = now + RETRY_AFTER;
    assert_eq!(
        cache.qualified_cost(
            later,
            second,
            baseline,
            || Some(later),
            |_| Ok(profile(second, stale, 100, 20))
        ),
        None
    );
    assert!(!cache.quarantined);
    assert_eq!(cache.retry_after, Some(later + RETRY_AFTER));
    assert_eq!(cache.profile.unwrap().geometry, first);
    assert_eq!(
        cache.qualified_cost(
            later,
            first,
            baseline,
            || panic!("original hot key"),
            |_| panic!("hot key")
        ),
        Some(20)
    );
}

#[test]
fn original_cooldown_survives_callback_unwind_and_all_transient_failures() {
    let _scalar = ScalarOverride::new();
    let work = MetalBatchWork::Encrypt;
    let geometry = Geometry::new(work, 33).unwrap();
    let baseline = AesCpuBaseline::capture(work);
    let now = Instant::now();
    let mut cache = CostCache::default();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cache.qualified_cost(
                now,
                geometry,
                baseline,
                || Some(now),
                |_| panic!("public sample unwind"),
            );
        }))
        .is_err()
    );
    assert_eq!(cache.retry_after, Some(now + RETRY_AFTER));
    assert!(!cache.quarantined);
    assert_eq!(
        cache.qualified_cost(
            now,
            geometry,
            baseline,
            || panic!("unwind cooldown"),
            |_| panic!("cooldown")
        ),
        None
    );
    let mut now = now + RETRY_AFTER;
    for failure in [
        CalibrationFailure::Deadline,
        CalibrationFailure::Allocation,
        CalibrationFailure::BackendUnavailable,
        CalibrationFailure::Overloaded,
        CalibrationFailure::CpuChanged,
    ] {
        assert_eq!(
            cache.qualified_cost(now, geometry, baseline, || Some(now), |_| Err(failure)),
            None
        );
        assert_eq!(cache.retry_after, Some(now + RETRY_AFTER));
        assert!(!cache.quarantined);
        assert_eq!(
            cache.qualified_cost(
                now,
                geometry,
                baseline,
                || panic!("failure cooldown"),
                |_| panic!("cooldown")
            ),
            None
        );
        now += RETRY_AFTER;
    }
    assert_eq!(
        cache.qualified_cost(
            now,
            geometry,
            baseline,
            || Some(now),
            |_| Ok(profile(geometry, baseline, 100, 20))
        ),
        Some(20)
    );
}

#[test]
fn quarantine_precedes_existing_exact_profile_and_no_cost_does_not_resample() {
    let _scalar = ScalarOverride::new();
    let work = MetalBatchWork::Decrypt;
    let first = Geometry::new(work, 129).unwrap();
    let second = Geometry::new(work, 130).unwrap();
    let baseline = AesCpuBaseline::capture(work);
    let now = Instant::now();
    for wrong_shape in [false, true] {
        let mut cache = CostCache::default();
        assert_eq!(
            cache.qualified_cost(
                now,
                first,
                baseline,
                || Some(now),
                |_| Ok(profile(first, baseline, 100, 20))
            ),
            Some(20)
        );
        let later = now + RETRY_AFTER;
        assert_eq!(
            cache.qualified_cost(
                later,
                second,
                baseline,
                || Some(later),
                |_| {
                    if wrong_shape {
                        Ok(profile(first, baseline, 100, 20))
                    } else {
                        Err(CalibrationFailure::ParityMismatch)
                    }
                }
            ),
            None
        );
        assert!(cache.quarantined);
        assert_eq!(
            cache.qualified_cost(
                later,
                first,
                baseline,
                || panic!("quarantined cached profile"),
                |_| panic!("quarantine")
            ),
            None
        );
    }
    let mut cache = CostCache::default();
    assert_eq!(
        cache.qualified_cost(
            now,
            first,
            baseline,
            || Some(now),
            |_| Ok(profile(first, baseline, 100, 120))
        ),
        None
    );
    assert!(cache.profile.is_some());
    assert_eq!(
        cache.qualified_cost(
            now + RETRY_AFTER,
            first,
            baseline,
            || panic!("CPU win is cached"),
            |_| panic!("CPU win")
        ),
        None
    );
}

#[test]
fn four_inline_family_slots_bound_key_churn_without_sharing_measurements() {
    let _scalar = ScalarOverride::new();
    let mut slots: [CostCache; 4] = std::array::from_fn(|_| CostCache::default());
    let now = Instant::now();
    for (family, work) in [
        MetalBatchWork::Encrypt,
        MetalBatchWork::Decrypt,
        MetalBatchWork::EncryptRounds(9),
        MetalBatchWork::DecryptRounds(64),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(work.family_index(), family);
        let geometry = Geometry::new(work, 129 + family).unwrap();
        let baseline = AesCpuBaseline::capture(work);
        assert_eq!(
            slots[family].qualified_cost(
                now,
                geometry,
                baseline,
                || Some(now),
                |_| Ok(profile(geometry, baseline, 100, 20))
            ),
            Some(20)
        );
    }
    for (family, slot) in slots.iter().enumerate() {
        assert_eq!(slot.profile.unwrap().geometry.blocks, 129 + family);
        assert_eq!(slot.retry_after, Some(now + RETRY_AFTER));
    }
    assert!(
        !std::mem::needs_drop::<Profile>(),
        "inline metadata holds no sample allocation"
    );
    assert!(
        !std::mem::needs_drop::<CostCache>(),
        "profile eviction cannot refund live sample storage"
    );
}

#[test]
fn changed_cpu_identity_invalidates_comparison_without_quarantining_any_family() {
    let _forced = ScalarOverride::new();
    for work in [
        MetalBatchWork::Encrypt,
        MetalBatchWork::Decrypt,
        MetalBatchWork::EncryptRounds(9),
        MetalBatchWork::DecryptRounds(9),
    ] {
        let geometry = Geometry::new(work, 512).unwrap();
        let baseline = AesCpuBaseline::capture(work);
        assert_eq!(baseline.cpu, Backend::Scalar);
        let stale_baseline = AesCpuBaseline {
            work,
            cpu: Backend::Native,
        };
        let expected = profile(geometry, baseline, 100, 20);
        let stale = profile(geometry, stale_baseline, 100, 20);
        let now = Instant::now();
        let mut cache = CostCache::default();
        assert_eq!(
            cache.qualified_cost(now, geometry, baseline, || Some(now), |_| Ok(stale)),
            None
        );
        assert!(!cache.quarantined);
        assert!(cache.profile.is_none());
        assert_eq!(cache.retry_after, Some(now + RETRY_AFTER));
        assert_eq!(
            cache.qualified_cost(
                now,
                geometry,
                baseline,
                || panic!("CPU-change cooldown"),
                |_| panic!("cooldown")
            ),
            None
        );
        let later = now + RETRY_AFTER;
        assert_eq!(
            cache.qualified_cost(later, geometry, baseline, || Some(later), |_| Ok(expected)),
            Some(20)
        );
        cache.profile = Some(stale);
        assert_eq!(
            cache.qualified_cost(
                later,
                geometry,
                baseline,
                || panic!("a CPU toggle cannot erase cooldown"),
                |_| panic!("cooldown")
            ),
            None
        );
        assert!(!cache.quarantined);
        let retry = later + RETRY_AFTER;
        assert_eq!(
            cache.qualified_cost(retry, geometry, baseline, || Some(retry), |_| Ok(expected)),
            Some(20),
            "stale cached CPU identity requires a later admitted comparison"
        );
        let mut cache = CostCache::default();
        assert_eq!(
            cache.qualified_cost(
                now,
                geometry,
                baseline,
                || Some(now),
                |_| Err(CalibrationFailure::CpuChanged)
            ),
            None
        );
        assert!(!cache.quarantined);
        assert_eq!(
            cache.qualified_cost(later, geometry, baseline, || Some(later), |_| Ok(expected)),
            Some(20)
        );
    }
}

#[test]
fn cost_cannot_replace_the_prescan_work_or_cpu_baseline() {
    let _forced = ScalarOverride::new();
    let work = MetalBatchWork::EncryptRounds(9);
    let geometry = Geometry::new(work, 512).unwrap();
    let captured = AesCpuBaseline::capture(work);
    let measured = profile(geometry, captured, 100, 20);
    let now = Instant::now();
    assert_eq!(captured.work(), work);
    assert!(captured.is_current());
    let mut cache = CostCache::default();
    assert_eq!(
        cache.qualified_cost(now, geometry, captured, || Some(now), |_| Ok(measured)),
        Some(20)
    );
    for other in [
        MetalBatchWork::Encrypt,
        MetalBatchWork::EncryptRounds(8),
        MetalBatchWork::DecryptRounds(9),
    ] {
        assert_eq!(
            cache.qualified_cost(
                now,
                geometry,
                AesCpuBaseline::capture(other),
                || panic!("prescan work changed"),
                |_| panic!("work changed")
            ),
            None
        );
    }
    let stale = AesCpuBaseline {
        work,
        cpu: Backend::Native,
    };
    assert!(!stale.is_current());
    assert_eq!(
        cache.qualified_cost(
            now,
            geometry,
            stale,
            || panic!("stale CPU baseline"),
            |_| panic!("stale CPU")
        ),
        None
    );
    let mut changed_measurement = CostCache::default();
    assert_eq!(
        changed_measurement.qualified_cost(
            now,
            geometry,
            captured,
            || Some(now),
            |_| Ok(profile(geometry, stale, 100, 20))
        ),
        None
    );
    assert!(!changed_measurement.quarantined);
    assert_eq!(
        changed_measurement.qualified_cost(
            now,
            geometry,
            stale,
            || panic!("replacement stale CPU"),
            |_| panic!("stale CPU")
        ),
        None
    );
    assert!(matches!(
        calibrate(geometry, stale, now),
        Err(CalibrationFailure::CpuChanged)
    ));
    assert_eq!(
        cache.qualified_cost(
            now,
            geometry,
            captured,
            || panic!("original profile remains cached"),
            |_| panic!("hot key")
        ),
        Some(20)
    );
}
