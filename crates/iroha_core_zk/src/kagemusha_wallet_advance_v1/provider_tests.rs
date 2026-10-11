//! Provider handle tests: opening a custody root, exclusivity, options, slot listing, status
//! accessors and the per-slot verified cache.

use super::*;
use crate::kagemusha_wallet_advance_v1::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletAnchorPolicyV1, KagemushaWalletSimFaultV1, KagemushaWalletSimFsV1,
    test_support::{
        BOOT_A, DeviceV1, FakePlatformV1, SCHEME, SimProviderV1, TestOwnerV1, enrolled_device,
        open_provider, test_options,
    },
};

fn device() -> DeviceV1 {
    DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 0x20)
}

#[test]
fn wallet_advance_v1_current_source_reads_preserve_custody_and_tri_state_keys() {
    let (device, fixture, slot, capsule) =
        crate::kagemusha_wallet_advance_v1::test_support::bootstrapped_device(
            KagemushaWalletAnchorPolicyV1::NotRequired,
            0x31,
        );
    let mut provider = device.open();
    let status = provider.status(&slot).unwrap();
    let calls = device
        .platform
        .with(|state| (state.generate_calls, state.sign_calls, state.delete_calls));
    assert_eq!(provider.current_capsule(&slot).unwrap(), Some(capsule));
    assert_eq!(provider.status(&slot).unwrap(), status);
    assert_eq!(
        provider.probe_payment_key(&slot).unwrap(),
        KagemushaWalletProbeV1::Present(fixture.payment_key)
    );
    device.platform.with(|state| state.probe_unavailable = true);
    assert!(matches!(
        provider.probe_payment_key(&slot),
        Ok(KagemushaWalletProbeV1::Unavailable(_))
    ));
    device.platform.with(|state| {
        state.probe_unavailable = false;
        state.storage = Err(KagemushaWalletUnavailableV1::Locked);
    });
    assert_eq!(
        provider.probe_payment_key(&slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Locked
        ))
    );
    assert_eq!(
        provider.current_capsule(&slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Locked
        ))
    );
    assert_eq!(
        device
            .platform
            .with(|state| (state.generate_calls, state.sign_calls, state.delete_calls)),
        calls
    );
}

#[test]
fn wallet_advance_v1_enrollment_source_has_no_fabricated_capsule() {
    let (device, fixture, slot) = enrolled_device(KagemushaWalletAnchorPolicyV1::NotRequired, 0x32);
    let mut provider = device.open();
    assert_eq!(provider.current_capsule(&slot).unwrap(), None);
    assert_eq!(
        provider.probe_payment_key(&slot).unwrap(),
        KagemushaWalletProbeV1::Present(fixture.payment_key)
    );
    assert_eq!(device.platform.with(|state| state.sign_calls), 0);
}

#[test]
fn wallet_advance_v1_provider_options_default_to_the_worst_case_ballast() {
    assert_eq!(
        KagemushaWalletProviderOptionsV1::default().ballast_bytes,
        KAGEMUSHA_WALLET_BALLAST_BYTES_V1
    );
}

#[test]
fn wallet_advance_v1_provider_open_creates_and_adopts_the_root() {
    let device = device();
    let provider = device.open();
    let sentinel = *provider.sentinel();
    assert_eq!(provider.scheme_id(), &SCHEME);
    assert_eq!(provider.options(), &test_options());
    assert!(
        provider
            .store()
            .fs()
            .visible_dir(&KagemushaWalletCustodyDirV1::root())
    );
    assert_eq!(provider.slots(), Ok(Vec::new()));
    assert!(
        provider
            .platform()
            .with(|state| state.violations.is_empty())
    );
    drop(provider);
    // Reopening adopts the same sentinel after a restart and after power loss.
    device.fs.restart();
    assert_eq!(*device.open().sentinel(), sentinel);
    device.power_loss(
        crate::kagemusha_wallet_advance_v1::KagemushaWalletSimPowerLossV1::DropUnsynced,
        [0xb3; 32],
    );
    assert_eq!(*device.open().sentinel(), sentinel);
}

#[test]
fn wallet_advance_v1_provider_open_refuses_custody_without_a_sentinel() {
    let device = device();
    device.fs.place_unsynced(
        &KagemushaWalletCustodyDirV1::root(),
        "ballast.bin",
        b"left behind",
    );
    assert_eq!(
        open_provider(&device.fs, &device.platform).err(),
        Some(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
            object: "root sentinel"
        })
    );
    // Lock, canary and staging files alone are a fresh root.
    let fresh = self::device();
    for name in ["canary", ".tmp-00000000000000000000000000000001"] {
        fresh
            .fs
            .place_unsynced(&KagemushaWalletCustodyDirV1::root(), name, b"x");
    }
    assert!(open_provider(&fresh.fs, &fresh.platform).is_ok());
}

#[test]
fn wallet_advance_v1_provider_open_is_exclusive_and_fail_closed() {
    let device = device();
    let first = device.open();
    assert_eq!(
        open_provider(&device.fs, &device.platform).err(),
        Some(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Busy
        ))
    );
    drop(first);
    let second = device.open();
    drop(second);
    // A lock syscall error is Unavailable, never an unlocked open.
    device
        .fs
        .inject(device.fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        open_provider(&device.fs, &device.platform).err(),
        Some(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Io(_)
        ))
    ));
    device
        .platform
        .with(|state| state.storage = Err(KagemushaWalletUnavailableV1::BeforeFirstUnlock));
    assert_eq!(
        open_provider(&device.fs, &device.platform).err(),
        Some(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::BeforeFirstUnlock
        ))
    );
    let platform = FakePlatformV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 0x21);
    assert_eq!(
        SimProviderV1::open(
            KagemushaWalletSimFsV1::new(),
            platform,
            SCHEME,
            KagemushaWalletProviderOptionsV1 { ballast_bytes: 0 },
        )
        .err(),
        Some(KagemushaWalletProviderErrorV1::Invalid {
            field: "options.ballast_bytes"
        })
    );
}

#[test]
fn wallet_advance_v1_provider_status_reconcile_and_marker_accessor() {
    let (device, f, slot) = enrolled_device(KagemushaWalletAnchorPolicyV1::NotRequired, 0x22);
    let mut provider = device.open();
    assert_eq!(provider.slots(), Ok(vec![slot]));
    let status = provider.status(&slot).expect("status");
    assert_eq!(
        status,
        provider.reconcile(&slot, &TestOwnerV1).expect("reconcile")
    );
    assert_eq!(
        status.marker().map(|record| *record.marker()),
        Some(f.enrollment)
    );
    for unmarked in [
        KagemushaWalletSlotStatusV1::Empty,
        KagemushaWalletSlotStatusV1::IntentOnly,
        KagemushaWalletSlotStatusV1::SlotAbandoned,
    ] {
        assert_eq!(unmarked.marker(), None);
    }
    let record = f.enrollment_record(BOOT_A);
    for status in [
        KagemushaWalletSlotStatusV1::Enrollment(record.clone()),
        KagemushaWalletSlotStatusV1::Pending(record.clone()),
        KagemushaWalletSlotStatusV1::Released(record.clone()),
        KagemushaWalletSlotStatusV1::Terminal(record.clone()),
    ] {
        assert_eq!(status.marker(), Some(&record));
    }
}

#[test]
fn wallet_advance_v1_provider_cache_poison_remember_and_guard() {
    let (device, _f, slot) = enrolled_device(KagemushaWalletAnchorPolicyV1::NotRequired, 0x23);
    let mut provider = device.open();
    let status = provider.status(&slot).expect("status");
    assert!(
        provider.cache.contains_key(&slot),
        "a stable status is cached"
    );
    // The cached path re-lists markers, compares the current marker's bytes, checks that no
    // abandoned-slot record conflicts with it and re-reads its verified enrollment phase and
    // the Client, Accepted and Slot originals that phase names.
    let start = device.fs.steps();
    assert_eq!(provider.status(&slot), Ok(status.clone()));
    assert_eq!(device.fs.steps() - start, 7);
    provider.poison(&slot);
    assert!(!provider.cache.contains_key(&slot));
    let start = device.fs.steps();
    assert_eq!(provider.status(&slot), Ok(status.clone()));
    assert!(
        device.fs.steps() - start > 2,
        "a poisoned slot reconciles fully"
    );
    let cached = provider.cache.get(&slot).expect("cached").clone();
    provider.poison(&slot);
    provider.remember(&slot, cached.durable.clone(), cached.status.clone());
    assert!(provider.cache.contains_key(&slot));
    assert_eq!(provider.guard(&slot, Ok::<u8, _>(7)), Ok(7));
    assert!(provider.cache.contains_key(&slot));
    let error = KagemushaWalletProviderErrorV1::Uncertain(KagemushaWalletUnavailableV1::Io(5));
    assert_eq!(provider.guard::<u8>(&slot, Err(error)), Err(error));
    assert!(!provider.cache.contains_key(&slot));
    assert_eq!(provider.boot(), Ok(BOOT_A));
    // A marker changed behind the cache is noticed and reconciled fully.
    provider.status(&slot).expect("status");
    let dir = crate::kagemusha_wallet_advance_v1::kagemusha_wallet_markers_dir_v1(&slot);
    device
        .fs
        .place_unsynced(&dir, "m-00000000000000000000000000000000.mk", b"changed");
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData { object: "marker" })
    );
}

#[test]
fn wallet_advance_v1_provider_open_after_a_lost_root_writeback_keeps_custody() {
    // Regression: a first open whose root sync lost its writeback, a same-boot reopen, an
    // enrollment and a power loss used to leave a sentinel without `slots/` (refused forever)
    // or an unreachable slot subtree.
    let base = device();
    let probe = base.fork();
    let start = probe.fs.steps();
    drop(probe.open());
    let syncs: Vec<u64> = probe
        .fs
        .trace_since(start)
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            **step == crate::kagemusha_wallet_advance_v1::KagemushaWalletSimStepV1::SyncDir
        })
        .map(|(index, _)| u64::try_from(index).expect("index"))
        .collect();
    assert!(!syncs.is_empty());
    for sync in syncs {
        let device = base.fork();
        device.fs.inject(
            device.fs.steps() + sync,
            crate::kagemusha_wallet_advance_v1::KagemushaWalletSimFaultV1::LostWriteback,
        );
        assert!(matches!(
            open_provider(&device.fs, &device.platform).err(),
            Some(KagemushaWalletProviderErrorV1::Uncertain(_))
        ));
        let mut provider = device.open();
        let slot = match provider
            .test_begin_enrollment(
                &super::super::test_support::enrollment_challenge(0x24),
                super::super::test_support::PROFILE,
                crate::kagemusha_wallet_advance_v1::KagemushaWalletEnrollmentDatesV1 {
                    issued_at_ms: 1,
                    expires_at_ms: 600_001,
                },
            )
            .expect("enroll")
        {
            KagemushaWalletEnrollmentStepV1::Enrolled { slot, .. } => slot,
            other => panic!("sync {sync}: {other:?}"),
        };
        drop(provider);
        device.power_loss(
            crate::kagemusha_wallet_advance_v1::KagemushaWalletSimPowerLossV1::DropUnsynced,
            [0xb4; 32],
        );
        let mut provider = device.open();
        assert_eq!(provider.slots(), Ok(vec![slot]), "sync {sync}");
        assert!(
            matches!(
                provider.status(&slot),
                Ok(KagemushaWalletSlotStatusV1::Enrollment(_))
            ),
            "sync {sync}"
        );
    }
}

#[test]
fn wallet_advance_v1_provider_open_accepts_an_empty_skeleton_without_a_sentinel() {
    // An interrupted first open may leave empty `probe/` and `slots/`; they are recreated.
    let device = device();
    let root = KagemushaWalletCustodyDirV1::root();
    for name in ["probe", "slots"] {
        crate::kagemusha_wallet_advance_v1::KagemushaWalletFsV1::mkdir(&device.fs, &root, name)
            .expect("mkdir");
    }
    let provider = device.open();
    assert_eq!(provider.slots(), Ok(Vec::new()));
    drop(provider);
    // A non-empty one is never adopted as an empty wallet.
    let device = self::device();
    crate::kagemusha_wallet_advance_v1::KagemushaWalletFsV1::mkdir(&device.fs, &root, "slots")
        .expect("mkdir");
    device.fs.place_unsynced(
        &crate::kagemusha_wallet_advance_v1::kagemusha_wallet_slots_dir_v1(),
        &"ab".repeat(32),
        b"x",
    );
    assert_eq!(
        open_provider(&device.fs, &device.platform).err(),
        Some(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
            object: "custody root"
        })
    );
}

#[test]
fn wallet_advance_v1_native_clock_preserves_unavailability_and_custody() {
    let device = device();
    let provider = device.open();
    device.platform.with(|state| state.monotonic = Ok(u64::MAX));
    let reading = provider.monotonic_reading().unwrap();
    assert_eq!(reading.boot_id, BOOT_A);
    assert_eq!(reading.monotonic_ms, u64::MAX);
    for boot in [Ok([0; 32]), Err(KagemushaWalletUnavailableV1::Platform(7))] {
        device.platform.with(|state| state.boot = boot);
        assert!(matches!(
            provider.monotonic_reading(),
            Err(KagemushaWalletProviderErrorV1::Unavailable(_))
        ));
    }
    device.platform.with(|state| {
        state.boot = Ok(BOOT_A);
        state.monotonic = Err(KagemushaWalletUnavailableV1::Platform(8));
    });
    assert!(matches!(
        provider.monotonic_reading(),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Platform(8)
        ))
    ));
    device.platform.with(|state| {
        state.monotonic = Ok(123);
        state.boot_after_monotonic = Some(Ok([0x42; 32]));
    });
    assert!(matches!(
        provider.monotonic_reading(),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Busy
        ))
    ));
    device.platform.with(|state| {
        state.boot = Ok(BOOT_A);
        state.storage_lock_after = Some(1);
    });
    assert!(matches!(
        provider.monotonic_reading(),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Locked
        ))
    ));
    assert_eq!(
        device
            .platform
            .with(|state| (state.generate_calls, state.sign_calls, state.delete_calls)),
        (0, 0, 0)
    );
}
