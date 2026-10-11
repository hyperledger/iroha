//! Archive metadata generations preserve the monetary head across faults and iOS anchoring.

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletAnchorPolicyV1 as Policy, KagemushaWalletLookupV1 as Lookup,
    KagemushaWalletLostCustodyV1 as Lost, KagemushaWalletSimFaultV1 as Fault,
    KagemushaWalletSimPowerLossV1 as PowerLoss,
    layout::kagemusha_wallet_markers_dir_v1,
    test_support::{
        AnchorWriteV1, BOOT_B, TestOwnerV1, advance_request, bootstrapped_device, next_capsule,
        released,
    },
};

#[test]
fn archive_checkpoint_generations_preserve_exact_head_completion_and_selection() {
    for policy in [Policy::NotRequired, Policy::Keychain] {
        let (device, f, slot, boot) = bootstrapped_device(policy, 0x60);
        let mut provider = device.open();
        let old = provider
            .status(&slot)
            .expect("status")
            .marker()
            .expect("marker")
            .clone();
        let original = provider.lookup(&slot, &boot.operation_id).expect("lookup");
        let signatures = device.platform.with(|s| s.sign_calls);
        assert!(provider.archive_checkpoint(&slot).expect("none").is_none());
        let first = provider
            .publish_archive_checkpoint(&slot, [0; 32], b"manifest one")
            .expect("publish");
        let current = provider
            .status(&slot)
            .expect("status")
            .marker()
            .expect("marker")
            .clone();
        assert_eq!(current.generation(), old.generation() + 1);
        assert_eq!(current.head(), old.head());
        assert_eq!(current.selected_generation(), old.selected_generation());
        assert_eq!(current.completion_digest(), old.completion_digest());
        assert_eq!(
            provider.lookup(&slot, &boot.operation_id).expect("lookup"),
            original
        );
        assert_eq!(
            provider
                .publish_archive_checkpoint(&slot, [0; 32], b"manifest one")
                .expect("exact retry"),
            first
        );
        assert_eq!(
            provider
                .status(&slot)
                .expect("status")
                .marker()
                .expect("marker")
                .generation(),
            current.generation()
        );
        assert!(
            provider
                .publish_archive_checkpoint(&slot, [0; 32], b"different")
                .is_err()
        );
        let second = provider
            .publish_archive_checkpoint(&slot, first, b"manifest two")
            .expect("next");
        assert_eq!(device.platform.with(|s| s.sign_calls), signatures);
        let current = provider
            .status(&slot)
            .expect("status")
            .marker()
            .expect("marker")
            .clone();
        let next = next_capsule(&f, &boot);
        let result = released(
            provider
                .advance(&slot, &TestOwnerV1, &advance_request(&current, &next))
                .expect("next head"),
        );
        assert_eq!(result.selected_generation, current.generation() + 1);
        assert_eq!(
            provider
                .status(&slot)
                .expect("status")
                .marker()
                .expect("marker")
                .archive_checkpoint(),
            second
        );
        drop(provider);
        device.power_loss(PowerLoss::DropUnsynced, BOOT_B);
        let mut reopened = device.open();
        assert_eq!(
            reopened.archive_checkpoint(&slot).expect("reopen"),
            Some((second, b"manifest two".to_vec()))
        );
        assert_eq!(
            reopened
                .lookup(&slot, &boot.operation_id)
                .expect("old retry"),
            original
        );
        assert!(device.platform.with(|s| s.violations.is_empty()));
    }
}

#[test]
fn source_marker_detects_both_copy_loss_and_ios_checkpoint_rollback() {
    let (device, _, slot, _) = bootstrapped_device(Policy::Keychain, 0x61);
    let before = device.fork();
    let mut provider = device.open();
    let digest = provider
        .publish_archive_checkpoint(&slot, [0; 32], b"sealed root")
        .expect("publish");
    for name in names(&digest) {
        device
            .fs
            .unlink(&kagemusha_wallet_archive_dir_v1(&slot), name.as_str())
            .expect("remove");
    }
    device
        .fs
        .sync_dir(&kagemusha_wallet_archive_dir_v1(&slot))
        .expect("sync");
    assert!(matches!(
        provider.archive_checkpoint(&slot),
        Err(Error::UnavailableCustodyData {
            object: "archive checkpoint"
        })
    ));
    drop(provider);
    device.power_loss(PowerLoss::DropUnsynced, BOOT_B);
    assert!(matches!(
        device.open().status(&slot),
        Err(Error::UnavailableCustodyData {
            object: "archive checkpoint"
        })
    ));
    // Old filesystem paired with the actual newer keychain anchor must be rejected.
    let old_fs = before.fs;
    let platform = device.platform.fork(Some(&old_fs));
    let mut rolled_back =
        crate::kagemusha_wallet_advance_v1::test_support::open_provider(&old_fs, &platform)
            .expect("open old root");
    assert!(matches!(
        rolled_back.status(&slot),
        Err(Error::LostCustody(Lost::RolledBack))
    ));
}

#[test]
fn archive_publication_reconciles_every_filesystem_crash_boundary() {
    for policy in [Policy::NotRequired, Policy::Keychain] {
        let (base, _, slot, boot) = bootstrapped_device(policy, 0x62);
        let probe = base.fork();
        let mut provider = probe.open();
        provider.status(&slot).expect("warm");
        let from = probe.fs.steps();
        provider
            .publish_archive_checkpoint(&slot, [0; 32], b"checkpoint")
            .expect("publish");
        let count = probe.fs.steps() - from;
        for fault in [Fault::CrashBefore, Fault::CrashAfter, Fault::LostWriteback] {
            for offset in 0..count {
                let device = base.fork();
                let mut provider = device.open();
                provider.status(&slot).expect("warm");
                let original = provider.lookup(&slot, &boot.operation_id).expect("lookup");
                let start = device.fs.steps();
                device.fs.inject(start + offset, fault);
                let _ = provider.publish_archive_checkpoint(&slot, [0; 32], b"checkpoint");
                drop(provider);
                device.power_loss(PowerLoss::DropUnsynced, BOOT_B);
                let mut provider = device.open();
                let existing = provider
                    .archive_checkpoint(&slot)
                    .expect("reconcile publication");
                if let Some((digest, bytes)) = &existing {
                    assert_eq!(
                        *digest,
                        kagemusha_wallet_archive_checkpoint_digest_v1(b"checkpoint")
                    );
                    assert_eq!(bytes, b"checkpoint");
                }
                let expected = existing.map_or([0; 32], |(digest, _)| digest);
                provider
                    .publish_archive_checkpoint(&slot, expected, b"checkpoint")
                    .expect("resume");
                assert_eq!(
                    provider
                        .lookup(&slot, &boot.operation_id)
                        .expect("exact completion"),
                    original
                );
                assert!(matches!(original, Lookup::Retained(_)));
                assert!(device.platform.with(|s| s.violations.is_empty()));
            }
        }
    }
}

#[test]
fn archive_anchor_unknown_outcomes_and_storage_unavailability_never_mean_absence() {
    for mode in [
        AnchorWriteV1::Refused,
        AnchorWriteV1::UncertainApplied,
        AnchorWriteV1::UncertainLost,
    ] {
        let (device, _, slot, _) = bootstrapped_device(Policy::Keychain, 0x63);
        let mut provider = device.open();
        provider.status(&slot).expect("warm");
        device.platform.with(|s| s.anchor_write = mode);
        let outcome = provider.publish_archive_checkpoint(&slot, [0; 32], b"checkpoint");
        if mode == AnchorWriteV1::UncertainApplied {
            assert!(
                outcome.is_ok(),
                "the anchor adapter confirms an applied write by readback"
            );
        } else {
            assert!(outcome.is_err());
        }
        device
            .platform
            .with(|s| s.anchor_write = AnchorWriteV1::Normal);
        let root = provider
            .archive_checkpoint(&slot)
            .expect("reconcile")
            .expect("selected checkpoint");
        assert_eq!(root.1, b"checkpoint");
        device
            .platform
            .with(|s| s.storage = Err(Unavailable::Locked));
        assert!(matches!(
            provider.archive_checkpoint(&slot),
            Err(Error::Unavailable(Unavailable::Locked))
        ));
        device.platform.clear_faults();
        // Even cached answers bracket protected-data availability.
        device.platform.with(|s| s.storage_lock_after = Some(1));
        assert!(matches!(
            provider.archive_checkpoint(&slot),
            Err(Error::Unavailable(_))
        ));
    }
}

#[test]
fn archive_metadata_does_not_modify_or_resign_the_g1_head() {
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0x64);
    let mut provider = device.open();
    let old = provider
        .status(&slot)
        .expect("status")
        .marker()
        .expect("marker")
        .clone();
    let record = old
        .checkpoint([9; 32], [3; 32])
        .expect("metadata successor");
    record
        .validate_successor_of(&old)
        .expect("same head successor");
    assert_eq!(record.selected_generation(), old.selected_generation());
    assert_eq!(record.marker().state, old.marker().state);
    assert_eq!(record.head(), old.head());
    let bytes = record.file_bytes().to_vec();
    assert_eq!(
        KagemushaWalletMarkerRecordV1::decode(&bytes, &slot, &old.marker().scheme_id)
            .expect("canonical"),
        record
    );
    assert_eq!(
        device
            .fs
            .visible_names(&kagemusha_wallet_markers_dir_v1(&slot))
            .len(),
        1,
        "constructing metadata publishes nothing"
    );
}

#[test]
fn scoped_archive_capability_binds_content_limits_and_protected_storage() {
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0x65);
    let mut provider = device.open();
    let digest = provider
        .with_archive(&slot, |archive| archive.write(b"immutable node", 14))
        .expect("write");
    assert_eq!(
        provider
            .with_archive(&slot, |archive| archive.read(&digest, 14))
            .expect("read"),
        b"immutable node"
    );
    assert!(
        provider
            .with_archive(&slot, |archive| archive.read(&digest, 13))
            .is_err()
    );
    assert!(
        provider
            .with_archive(&slot, |archive| archive.write(b"too large", 3))
            .is_err()
    );
    device.platform.with(|s| s.storage_lock_after = Some(1));
    assert!(matches!(
        provider.with_archive(&slot, |archive| archive.read(&digest, 14)),
        Err(Error::Unavailable(_))
    ));
    device.platform.clear_faults();
    assert_eq!(
        provider
            .with_archive(&slot, |archive| archive.read(&digest, 14))
            .expect("available again"),
        b"immutable node"
    );
}

#[test]
fn provider_archive_adapter_shares_custody_and_brackets_named_records() {
    use crate::kagemusha_wallet_state_v1::{AdvanceHandle, ArchiveKey, ArchiveStore, Custody};
    let (device, f, slot, boot) = bootstrapped_device(Policy::NotRequired, 0x66);
    let mut handle = AdvanceHandle::new(device.open(), slot);
    let mut archive = handle.archive(f.scheme_id(), f.wallet_id());
    let key = ArchiveKey::Capsule([7; 32]);
    assert!(archive.get(key, 32).expect("absent").is_none());
    archive.put(key, b"immutable witness").expect("write");
    archive.put(key, b"immutable witness").expect("exact retry");
    assert_eq!(
        archive.get(key, 32).expect("read"),
        Some(b"immutable witness".to_vec())
    );
    assert!(archive.put(key, b"changed witness").is_err());
    assert!(archive.get(key, 3).is_err());
    let original = handle.lookup(&boot.operation_id).expect("completion");
    let digest = handle
        .publish_archive_checkpoint([0; 32], b"fixed root manifest")
        .expect("anchor");
    assert_eq!(
        handle.archive_checkpoint().expect("manifest"),
        Some((digest, b"fixed root manifest".to_vec()))
    );
    assert_eq!(
        handle.lookup(&boot.operation_id).expect("completion"),
        original
    );
    for reason in [
        Unavailable::Locked,
        Unavailable::Busy,
        Unavailable::Io(5),
        Unavailable::BeforeFirstUnlock,
    ] {
        device.platform.with(|state| state.storage = Err(reason));
        assert!(archive.get(key, 32).is_err());
        assert!(handle.lookup(&[0; 32]).is_err());
        device.platform.clear_faults();
    }
    device
        .platform
        .with(|state| state.storage_lock_after = Some(1));
    assert!(archive.get(key, 32).is_err());
    device.platform.clear_faults();
    assert_eq!(
        archive.get(key, 32).expect("restored access"),
        Some(b"immutable witness".to_vec())
    );
}

#[test]
fn scoped_archive_record_collection_keeps_protected_storage_and_exact_key() {
    let (device, _, slot, _) = bootstrapped_device(Policy::Keychain, 0x75);
    let mut provider = device.open();
    provider
        .with_archive(&slot, |archive| {
            archive.write_record(&[1; 32], b"claim one")?;
            archive.write_record(&[2; 32], b"claim two")
        })
        .unwrap();
    provider
        .with_archive(&slot, |archive| archive.remove_record(&[1; 32]))
        .unwrap();
    provider
        .with_archive(&slot, |archive| archive.remove_record(&[1; 32]))
        .unwrap();
    assert_eq!(
        provider
            .with_archive(&slot, |archive| archive.read_record(&[1; 32], 9))
            .unwrap(),
        None
    );
    assert_eq!(
        provider
            .with_archive(&slot, |archive| archive.read_record(&[2; 32], 9))
            .unwrap(),
        Some(b"claim two".to_vec())
    );
    device
        .platform
        .with(|state| state.storage_lock_after = Some(1));
    assert!(matches!(
        provider.with_archive(&slot, |archive| archive.remove_record(&[2; 32])),
        Err(Error::Unavailable(_))
    ));
    device.platform.clear_faults();
    assert_eq!(
        provider
            .with_archive(&slot, |archive| archive.read_record(&[2; 32], 9))
            .unwrap(),
        Some(b"claim two".to_vec())
    );
}
