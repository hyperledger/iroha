//! Reconciliation tests: no-marker classifications (R10), key checks (R4), redundant copies
//! and the released-record regression (R5), rollback evidence (R6), staging discard (R7),
//! retirement by name (R8), offline finishing (R9), the fresh-inode rule (R3) and restore
//! simulations against the iOS anchor.

use super::*;
use crate::kagemusha_wallet_advance_v1::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletAdvanceOutcomeV1, KagemushaWalletEnrollmentStepV1, KagemushaWalletFrozenFileV1,
    KagemushaWalletLookupV1, KagemushaWalletSimFaultV1, KagemushaWalletSimPowerLossV1,
    KagemushaWalletSimStepV1, encode_envelope_v1, kagemusha_wallet_capsule_name_v1,
    kagemusha_wallet_completion_name_v1, kagemusha_wallet_prepare_slot_dirs_v1,
    test_support::{
        BOOT_B, DeviceV1, PROFILE, SimProviderV1, TestOwnerV1, advance_request,
        bootstrapped_device, enrolled_device, enrollment_challenge, next_capsule, released,
        signing_key,
    },
};

const ANDROID: KagemushaWalletAnchorPolicyV1 = KagemushaWalletAnchorPolicyV1::NotRequired;
const IOS: KagemushaWalletAnchorPolicyV1 = KagemushaWalletAnchorPolicyV1::Keychain;

/// Every visible entry of `dir`, for before/after comparisons.
fn names(device: &DeviceV1, dir: &KagemushaWalletCustodyDirV1) -> Vec<String> {
    device.fs.visible_names(dir)
}

/// A device with one slot whose intent is durable and whose key was not generated.
fn intent_only(seed: u8) -> (DeviceV1, KagemushaWalletSlotIdV1) {
    let device = DeviceV1::new(ANDROID, seed);
    device
        .platform
        .with(|state| state.generate_unavailable = Some(false));
    let mut provider = device.open();
    assert!(matches!(
        provider.test_begin_enrollment(
            &enrollment_challenge(seed),
            PROFILE,
            crate::kagemusha_wallet_advance_v1::KagemushaWalletEnrollmentDatesV1 {
                issued_at_ms: 1,
                expires_at_ms: 600_001
            }
        ),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    device
        .platform
        .with(|state| state.generate_unavailable = None);
    let slot = provider.slots().expect("slots")[0];
    (device, slot)
}

#[test]
fn wallet_advance_v1_reconcile_abandon_reason_tags() {
    for reason in [
        KagemushaWalletSlotAbandonReasonV1::KeyWithoutMarker,
        KagemushaWalletSlotAbandonReasonV1::ChallengeExpired,
    ] {
        assert_eq!(
            KagemushaWalletSlotAbandonReasonV1::from_tag(reason.tag()),
            Some(reason)
        );
    }
    assert_eq!(KagemushaWalletSlotAbandonReasonV1::from_tag(0), None);
    assert_eq!(KagemushaWalletSlotAbandonReasonV1::from_tag(3), None);
}

#[test]
fn wallet_advance_v1_reconcile_without_marker_classifies_and_never_deletes() {
    // Intent, definitively absent key: enrollment may continue.
    let (device, slot) = intent_only(0x50);
    let mut provider = device.open();
    assert_eq!(
        provider.status(&slot),
        Ok(KagemushaWalletSlotStatusV1::IntentOnly)
    );
    // Key unavailable: no inference, nothing written.
    let slot_dir = kagemusha_wallet_slot_dir_v1(&slot);
    let before = names(&device, &slot_dir);
    device.platform.with(|state| state.probe_unavailable = true);
    provider.poison(&slot);
    assert!(matches!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    assert_eq!(names(&device, &slot_dir), before);
    device
        .platform
        .with(|state| state.probe_unavailable = false);
    // Intent with a key but no marker: a used incarnation, abandoned and never used.
    device
        .platform
        .with(|state| state.keys.insert(slot, signing_key(0x51)));
    assert_eq!(
        provider.status(&slot),
        Ok(KagemushaWalletSlotStatusV1::SlotAbandoned)
    );
    assert!(names(&device, &slot_dir).contains(&KAGEMUSHA_WALLET_ABANDONED_NAME_V1.to_owned()));
    assert!(device.platform.key_of(&slot).is_some(), "the key is kept");
    assert_eq!(
        provider.test_resume_enrollment(
            &slot,
            crate::kagemusha_wallet_advance_v1::KagemushaWalletChallengeLivenessV1::Live
        ),
        Ok(KagemushaWalletEnrollmentStepV1::SlotAbandoned { slot })
    );
    assert_eq!(device.platform.with(|state| state.generate_calls), 1);
    // A journal record without any marker is lost custody, and nothing is deleted.
    let (device, slot) = intent_only(0x52);
    let mut provider = device.open();
    device.fs.place_unsynced(
        &kagemusha_wallet_slot_dir_v1(&slot),
        KAGEMUSHA_WALLET_ENROLLMENT_NAME_V1,
        b"request",
    );
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::JournalWithoutMarker
        ))
    );
    device.fs.place_unsynced(
        &kagemusha_wallet_completion_dir_v1(&slot),
        ".tmp-00000000000000000000000000000009",
        b"staging",
    );
    assert!(
        names(&device, &kagemusha_wallet_slot_dir_v1(&slot))
            .contains(&KAGEMUSHA_WALLET_ENROLLMENT_NAME_V1.to_owned())
    );
    // A slot without an intent: empty, or lost custody when a key exists for it.
    let device = DeviceV1::new(ANDROID, 0x53);
    let mut provider = device.open();
    let slot = KagemushaWalletSlotIdV1([0x53; 32]);
    kagemusha_wallet_prepare_slot_dirs_v1(provider.store(), &slot).expect("slot");
    assert_eq!(
        provider.status(&slot),
        Ok(KagemushaWalletSlotStatusV1::Empty)
    );
    device
        .platform
        .with(|state| state.keys.insert(slot, signing_key(0x53)));
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::KeyWithoutMarker
        ))
    );
    // A foreign entry in a slot directory stops classification.
    device
        .fs
        .place_unsynced(&kagemusha_wallet_slot_dir_v1(&slot), "foreign", b"x");
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "slot" })
    );
}

#[test]
fn wallet_advance_v1_reconcile_requires_the_marker_payment_key() {
    let (device, _f, slot) = enrolled_device(ANDROID, 0x54);
    let mut provider = device.open();
    provider.status(&slot).expect("status");
    let key = device
        .platform
        .with(|state| state.keys.remove(&slot))
        .expect("key");
    provider.poison(&slot);
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::KeyLost)
    );
    device
        .platform
        .with(|state| state.keys.insert(slot, signing_key(0x99)));
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::KeyLost)
    );
    device.platform.with(|state| {
        state.keys.insert(slot, key);
        state.probe_unavailable = true;
    });
    assert!(matches!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    device
        .platform
        .with(|state| state.probe_unavailable = false);
    assert!(matches!(
        provider.status(&slot),
        Ok(KagemushaWalletSlotStatusV1::Enrollment(_))
    ));
    // Locked storage at R0 is Unavailable before anything is read.
    device
        .platform
        .with(|state| state.storage = Err(KagemushaWalletUnavailableV1::Locked));
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Locked
        ))
    );
}

#[test]
fn wallet_advance_v1_reconcile_repairs_capsule_copies_and_stops_without_any() {
    let (device, _f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x55);
    let digest = bootstrap.custody_digest();
    let dir = kagemusha_wallet_capsules_dir_v1(&slot);
    let primary = kagemusha_wallet_capsule_name_v1(1, &digest, KagemushaWalletCopyV1::Primary);
    let replica = kagemusha_wallet_capsule_name_v1(1, &digest, KagemushaWalletCopyV1::Replica);
    let mut provider = device.open();
    let intact = device
        .fs
        .visible_file(&dir, primary.as_str())
        .expect("primary");
    provider.store().remove_file(&dir, &replica);
    provider.poison(&slot);
    provider.status(&slot).expect("repaired");
    assert_eq!(
        device
            .fs
            .visible_file(&dir, replica.as_str())
            .map(|bytes| bytes.len()),
        Some(intact.len())
    );
    for name in [&primary, &replica] {
        provider.store().remove_file(&dir, name);
    }
    provider.poison(&slot);
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData { object: "capsule" })
    );
}

#[test]
fn wallet_advance_v1_reconcile_released_record_loss_never_signs_again() {
    // The rev-1 bug: a released record lost in every copy must never be signed again.
    for damage in ["missing", "corrupt", "unreadable"] {
        let (device, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x56);
        let dir = kagemusha_wallet_completion_dir_v1(&slot);
        let mut provider = device.open();
        let KagemushaWalletLookupV1::Retained(retained) = provider
            .lookup(&slot, &bootstrap.body().operation_id)
            .expect("lookup")
        else {
            panic!("retained");
        };
        let signed = device.platform.with(|state| state.sign_calls);
        let originals: Vec<_> = KagemushaWalletCopyV1::BOTH
            .iter()
            .map(|copy| {
                let name =
                    kagemusha_wallet_completion_name_v1(&bootstrap.body().operation_id, *copy);
                let bytes = device.fs.visible_file(&dir, name.as_str()).expect("copy");
                (name, bytes)
            })
            .collect();
        for (name, _) in &originals {
            match damage {
                "missing" => {
                    let _ = provider.store().remove_file(&dir, name);
                }
                "corrupt" => device.fs.place_unsynced(&dir, name.as_str(), b"corrupt"),
                _ => {}
            }
        }
        provider.poison(&slot);
        if damage == "unreadable" {
            // A read error at any step, the record copies' reads included, is never absence:
            // no loss is classified and nothing is signed.
            drop(provider);
            let probe = device.fork();
            let mut probe_provider = probe.open();
            let start = probe.fs.steps();
            probe_provider.status(&slot).expect("status");
            let steps = probe.fs.steps() - start;
            for step in 0..steps {
                let faulted = device.fork();
                let mut faulted_provider = faulted.open();
                faulted
                    .fs
                    .inject(faulted.fs.steps() + step, KagemushaWalletSimFaultV1::Error);
                let result = faulted_provider.status(&slot);
                assert!(
                    matches!(
                        result,
                        Ok(KagemushaWalletSlotStatusV1::Released(_))
                            | Err(KagemushaWalletProviderErrorV1::Unavailable(_)
                                | KagemushaWalletProviderErrorV1::Uncertain(_))
                    ),
                    "step {step}: {result:?}"
                );
                assert_eq!(faulted.platform.with(|state| state.sign_calls), signed);
                assert_eq!(
                    faulted_provider.lookup(&slot, &bootstrap.body().operation_id),
                    Ok(KagemushaWalletLookupV1::Retained(retained.clone())),
                    "step {step}"
                );
            }
            assert!(steps > 5);
            continue;
        }
        let loss = KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::CompletionLost,
        );
        let lost = Err(loss);
        assert_eq!(provider.status(&slot), lost, "{damage}");
        assert_eq!(
            provider.reconcile(&slot, &TestOwnerV1),
            lost,
            "{damage}: even with an owner"
        );
        assert_eq!(
            provider.lookup(&slot, &bootstrap.body().operation_id),
            Ok(KagemushaWalletLookupV1::DeliveryDataLoss)
        );
        let enrollment = f.enrollment_record(super::super::test_support::BOOT_A);
        assert_eq!(
            provider.advance(
                &slot,
                &TestOwnerV1,
                &advance_request(&enrollment, &bootstrap)
            ),
            Err(loss),
            "{damage}: a retry never re-signs"
        );
        assert_eq!(
            device.platform.with(|state| state.sign_calls),
            signed,
            "{damage}: no signature"
        );
    }
}

/// Index of the `nth` (zero-based) step of `kind` in `trace`.
fn nth_step(trace: &[KagemushaWalletSimStepV1], kind: KagemushaWalletSimStepV1, nth: usize) -> u64 {
    let index = trace
        .iter()
        .enumerate()
        .filter(|(_, step)| **step == kind)
        .nth(nth)
        .map(|(index, _)| index)
        .expect("step");
    u64::try_from(index).expect("index")
}

#[test]
fn wallet_advance_v1_reconcile_adopts_a_record_written_before_the_release() {
    // Crash between the durable completion record and the Released marker: the record is
    // adopted under the Selected marker without a second signature.
    let (base, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x57);
    let current = base.open().status(&slot).expect("status");
    let request = advance_request(
        current.marker().expect("marker"),
        &next_capsule(&f, &bootstrap),
    );
    let probe = base.fork();
    let mut provider = probe.open();
    let start = probe.fs.steps();
    let expected = released(
        provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("advance"),
    );
    let trace = probe.fs.trace_since(start);
    // Renames: two capsule copies, the Selected marker, two record copies, the Released marker.
    let release_rename = nth_step(&trace, KagemushaWalletSimStepV1::RenameNoReplace, 5);
    let device = base.fork();
    let mut provider = device.open();
    device.fs.inject(
        device.fs.steps() + release_rename,
        KagemushaWalletSimFaultV1::CrashBefore,
    );
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &request),
        Ok(KagemushaWalletAdvanceOutcomeV1::Pending {
            operation_id: request.operation_id
        })
    );
    drop(provider);
    device.fs.restart();
    let mut provider: SimProviderV1 = device.open();
    let signed = device.platform.with(|state| state.sign_calls);
    assert!(matches!(
        provider.status(&slot),
        Ok(KagemushaWalletSlotStatusV1::Pending(_))
    ));
    assert!(matches!(
        provider.reconcile(&slot, &TestOwnerV1),
        Ok(KagemushaWalletSlotStatusV1::Released(_))
    ));
    assert_eq!(device.platform.with(|state| state.sign_calls), signed);
    let retried = released(
        provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("retry"),
    );
    // The receipt signature is randomized: equality proves the first record was adopted.
    assert_eq!(retried.frame.len(), expected.frame.len());
    assert_eq!(retried.operation_id, expected.operation_id);
    assert_ne!(
        retried.frame, expected.frame,
        "a different run signs differently"
    );
    let again = released(
        provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("again"),
    );
    assert_eq!(again, retried);
}

#[test]
fn wallet_advance_v1_reconcile_finishes_a_selected_head_offline() {
    let (device, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x58);
    let mut provider = device.open();
    let current = provider.status(&slot).expect("status");
    let request = advance_request(
        current.marker().expect("marker"),
        &next_capsule(&f, &bootstrap),
    );
    device.platform.with(|state| state.sign_unavailable = true);
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &request),
        Ok(KagemushaWalletAdvanceOutcomeV1::Pending {
            operation_id: request.operation_id
        })
    );
    let Ok(KagemushaWalletSlotStatusV1::Pending(selected)) = provider.status(&slot) else {
        panic!("selected head pending");
    };
    assert_eq!(selected.phase(), KagemushaWalletMarkerPhaseV1::Selected);
    assert_eq!(
        provider.reconcile(&slot, &TestOwnerV1),
        Ok(KagemushaWalletSlotStatusV1::Pending(selected.clone())),
        "signing still unavailable"
    );
    // Fresh-inode rule: in this boot the Selected marker is rewritten on every full reconcile;
    // after a reboot it is only synced.
    let markers = kagemusha_wallet_markers_dir_v1(&slot);
    let name = selected.file_name();
    let inode = device.fs.inode_of(&markers, name.as_str());
    provider.poison(&slot);
    provider.status(&slot).expect("status");
    assert_ne!(device.fs.inode_of(&markers, name.as_str()), inode);
    device.platform.with(|state| state.boot = Ok(BOOT_B));
    let inode = device.fs.inode_of(&markers, name.as_str());
    provider.poison(&slot);
    provider.status(&slot).expect("status");
    assert_eq!(device.fs.inode_of(&markers, name.as_str()), inode);
    device.platform.with(|state| state.sign_unavailable = false);
    let Ok(KagemushaWalletSlotStatusV1::Released(head)) = provider.reconcile(&slot, &TestOwnerV1)
    else {
        panic!("released offline");
    };
    assert_eq!(head.head(), selected.head());
    assert_eq!(head.generation(), selected.generation() + 1);
    let retained = released(
        provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("retry"),
    );
    assert_eq!(
        retained.completion_digest,
        head.completion_digest().expect("digest")
    );
}

#[test]
fn wallet_advance_v1_reconcile_journal_above_the_marker_is_rollback_evidence() {
    let (device, _f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x59);
    let mut provider = device.open();
    let above = Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
        object: "journal above current marker",
    });
    // A completion record of a later Selected generation.
    let completion = kagemusha_wallet_completion_dir_v1(&slot);
    let record = super::super::test_support::completion_for(
        &super::super::test_support::wallet_fixture(0x59),
        &bootstrap,
        7,
    );
    let frame = record.to_canonical_bytes().expect("frame");
    let envelope = encode_envelope_v1(
        &KagemushaWalletFrozenFileV1 {
            version: 1,
            written_boot_id: [0; 32],
            selected_generation: 5,
            frame,
        },
        usize::MAX,
    )
    .expect("envelope");
    let name = kagemusha_wallet_completion_name_v1(&[0x77; 32], KagemushaWalletCopyV1::Primary);
    device
        .fs
        .place_unsynced(&completion, name.as_str(), &envelope);
    provider.poison(&slot);
    assert_eq!(provider.status(&slot), above);
    assert!(
        names(&device, &completion).contains(&name.as_str().to_owned()),
        "kept"
    );
    provider.store().remove_file(&completion, &name);
    // A capsule beyond the next staging generation.
    let capsules = kagemusha_wallet_capsules_dir_v1(&slot);
    let far = kagemusha_wallet_capsule_name_v1(9, &[0x78; 32], KagemushaWalletCopyV1::Primary);
    device
        .fs
        .place_unsynced(&capsules, far.as_str(), b"later head");
    provider.poison(&slot);
    assert_eq!(provider.status(&slot), above);
    assert!(
        names(&device, &capsules).contains(&far.as_str().to_owned()),
        "kept"
    );
    provider.store().remove_file(&capsules, &far);
    // Staging of the next generation and unbound capsules of this head are discarded (R7).
    let staged = kagemusha_wallet_capsule_name_v1(3, &[0x79; 32], KagemushaWalletCopyV1::Primary);
    let unbound = kagemusha_wallet_capsule_name_v1(1, &[0x7a; 32], KagemushaWalletCopyV1::Replica);
    let older = kagemusha_wallet_capsule_name_v1(0, &[0x7b; 32], KagemushaWalletCopyV1::Primary);
    for name in [&staged, &unbound, &older] {
        device
            .fs
            .place_unsynced(&capsules, name.as_str(), b"staging");
    }
    provider.poison(&slot);
    assert!(matches!(
        provider.status(&slot),
        Ok(KagemushaWalletSlotStatusV1::Released(_))
    ));
    let remaining = names(&device, &capsules);
    assert!(!remaining.contains(&staged.as_str().to_owned()));
    assert!(!remaining.contains(&unbound.as_str().to_owned()));
    assert!(
        remaining.contains(&older.as_str().to_owned()),
        "older capsules wait for collection"
    );
    assert_eq!(remaining.len(), 3);
}

#[test]
fn wallet_advance_v1_reconcile_retires_lower_markers_by_name() {
    let (device, _f, slot, _bootstrap) = bootstrapped_device(ANDROID, 0x5a);
    let markers = kagemusha_wallet_markers_dir_v1(&slot);
    let lower = kagemusha_wallet_marker_name_v1(1);
    device
        .fs
        .place_unsynced(&markers, lower.as_str(), b"unreadable garbage");
    device.fs.place_unsynced(
        &markers,
        ".tmp-0000000000000000000000000000000a",
        b"staging",
    );
    let mut provider = device.open();
    let Ok(KagemushaWalletSlotStatusV1::Released(head)) = provider.status(&slot) else {
        panic!("released");
    };
    assert_eq!(
        names(&device, &markers),
        vec![head.file_name().as_str().to_owned()]
    );
    // A foreign entry in `markers/` stops selection.
    device.fs.place_unsynced(&markers, "foreign", b"x");
    provider.poison(&slot);
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "markers" })
    );
}

#[test]
fn wallet_advance_v1_reconcile_ios_restore_simulations() {
    let (device, f, slot, bootstrap) = bootstrapped_device(IOS, 0x5b);
    let snapshot = device.fork();
    let mut provider = device.open();
    let current = provider.status(&slot).expect("status");
    released(
        provider
            .advance(
                &slot,
                &TestOwnerV1,
                &advance_request(
                    current.marker().expect("marker"),
                    &next_capsule(&f, &bootstrap),
                ),
            )
            .expect("advance"),
    );
    drop(provider);
    // (i) Files rolled back, keychain kept: RolledBack, never resumption.
    let restored = DeviceV1 {
        fs: snapshot.fs.fork(),
        platform: device.platform.fork(None),
    };
    let before = all_slot_names(&restored, &slot);
    let signed = restored.platform.with(|state| state.sign_calls);
    let mut provider = restored.open();
    let rolled_back = Err(KagemushaWalletProviderErrorV1::LostCustody(
        KagemushaWalletLostCustodyV1::RolledBack,
    ));
    assert_eq!(provider.status(&slot), rolled_back);
    assert_eq!(provider.reconcile(&slot, &TestOwnerV1), rolled_back);
    assert_eq!(all_slot_names(&restored, &slot), before, "nothing deleted");
    assert_eq!(restored.platform.with(|state| state.sign_calls), signed);
    // (ii) Anchor definitively absent while markers exist: AnchorMissing.
    let wiped = device.fork();
    wiped.platform.with(|state| state.anchors.clear());
    let mut provider = wiped.open();
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::AnchorMissing
        ))
    );
    // A lock event between the brackets is Unavailable, never AnchorMissing.
    wiped
        .platform
        .with(|state| state.storage_lock_after = Some(1));
    assert!(matches!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    // (iii) Same generation, other digest: AnchorMismatch.
    let mismatched = device.fork();
    mismatched.platform.with(|state| {
        let bytes = state.anchors.get(&slot).cloned().expect("anchor");
        let mut anchor = KagemushaWalletAnchorV1::decode(&bytes).expect("anchor");
        anchor.marker_file_digest = [0x5b; 32];
        state.anchors.insert(slot, anchor.encode().expect("encode"));
    });
    assert_eq!(
        mismatched.open().status(&slot),
        Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::AnchorMismatch
        ))
    );
}

/// Every visible file under the slot and its custody directories.
fn all_slot_names(device: &DeviceV1, slot: &KagemushaWalletSlotIdV1) -> Vec<String> {
    let mut all = Vec::new();
    for dir in [
        kagemusha_wallet_slot_dir_v1(slot),
        kagemusha_wallet_markers_dir_v1(slot),
        kagemusha_wallet_capsules_dir_v1(slot),
        kagemusha_wallet_completion_dir_v1(slot),
        kagemusha_wallet_ops_dir_v1(slot),
    ] {
        for name in device.fs.visible_names(&dir) {
            all.push(format!("{}/{name}", dir.label()));
        }
    }
    all
}

#[test]
fn wallet_advance_v1_reconcile_android_restore_relies_on_an_empty_backup_set() {
    // Android keeps no anchor: its custody files are never in a backup or transfer set
    // (allowBackup=false, every domain excluded), and a full-data restore clears the app's
    // keys with its files. A restore that copies older files back while the keys stay is
    // outside the platform contract and is not detected here (design risk: OEM migration
    // tools; the optional Keystore anchor closes it).
    let (device, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x5c);
    let snapshot = device.fork();
    let mut provider = device.open();
    let current = provider.status(&slot).expect("status");
    released(
        provider
            .advance(
                &slot,
                &TestOwnerV1,
                &advance_request(
                    current.marker().expect("marker"),
                    &next_capsule(&f, &bootstrap),
                ),
            )
            .expect("advance"),
    );
    drop(provider);
    let restored = DeviceV1 {
        fs: snapshot.fs.fork(),
        platform: device.platform.fork(None),
    };
    let status = restored.open().status(&slot).expect("status");
    assert_eq!(
        status
            .marker()
            .map(KagemushaWalletMarkerRecordV1::generation),
        Some(2)
    );
    // Power loss leaves only durable state, which never goes backwards.
    let device = device.fork();
    device.power_loss(KagemushaWalletSimPowerLossV1::Seeded(9), BOOT_B);
    let status = device.open().status(&slot).expect("status");
    assert_eq!(
        status
            .marker()
            .map(KagemushaWalletMarkerRecordV1::generation),
        Some(4)
    );
}

#[test]
fn wallet_advance_v1_reconcile_pending_head_is_cached_without_rewrites() {
    // Regression: a selected head waiting for its receipt used to be fully reconciled (and
    // its marker, capsule and record copies rewritten) on every status call.
    let (device, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x5d);
    let mut provider = device.open();
    let current = provider.status(&slot).expect("status");
    let request = advance_request(
        current.marker().expect("marker"),
        &next_capsule(&f, &bootstrap),
    );
    device.platform.with(|state| state.sign_unavailable = true);
    assert!(matches!(
        provider.advance(&slot, &TestOwnerV1, &request),
        Ok(KagemushaWalletAdvanceOutcomeV1::Pending { .. })
    ));
    // A fresh process reconciles once (rewriting this boot's unacknowledged files) ...
    drop(provider);
    device.fs.restart();
    let mut provider = device.open();
    let Ok(KagemushaWalletSlotStatusV1::Pending(selected)) = provider.status(&slot) else {
        panic!("pending");
    };
    // ... then every later status only re-lists `markers/` and compares the marker's bytes.
    let markers = kagemusha_wallet_markers_dir_v1(&slot);
    let inode = device.fs.inode_of(&markers, selected.file_name().as_str());
    for _ in 0..3 {
        let start = device.fs.steps();
        assert_eq!(
            provider.status(&slot),
            Ok(KagemushaWalletSlotStatusV1::Pending(selected.clone()))
        );
        assert_eq!(device.fs.steps() - start, 2, "list and read only");
    }
    // A reconcile with an owner retries only the finishing steps: nothing is rewritten while
    // signing stays unavailable.
    let start = device.fs.steps();
    assert_eq!(
        provider.reconcile(&slot, &TestOwnerV1),
        Ok(KagemushaWalletSlotStatusV1::Pending(selected.clone()))
    );
    let trace = device.fs.trace_since(start);
    assert!(
        !trace.iter().any(|step| matches!(
            step,
            KagemushaWalletSimStepV1::CreateNew
                | KagemushaWalletSimStepV1::Write
                | KagemushaWalletSimStepV1::RenameReplace
                | KagemushaWalletSimStepV1::RenameNoReplace
        )),
        "{trace:?}"
    );
    assert_eq!(
        device.fs.inode_of(&markers, selected.file_name().as_str()),
        inode
    );
    device.platform.with(|state| state.sign_unavailable = false);
    assert!(matches!(
        provider.reconcile(&slot, &TestOwnerV1),
        Ok(KagemushaWalletSlotStatusV1::Released(_))
    ));
    assert!(device.platform.with(|state| state.violations.is_empty()));
}

#[test]
fn wallet_advance_v1_reconcile_storage_locking_mid_reconcile_is_unavailable() {
    // Regression: answers read after protected storage locked (Android CE names read as
    // absent) are never turned into loss, emptiness or abandonment.
    let (device, _f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x5e);
    let mut provider = device.open();
    let dir = kagemusha_wallet_completion_dir_v1(&slot);
    for copy in KagemushaWalletCopyV1::BOTH {
        let name = kagemusha_wallet_completion_name_v1(&bootstrap.body().operation_id, copy);
        let _ = provider.store().remove_file(&dir, &name);
    }
    provider.poison(&slot);
    // R0 and the key-probe brackets answer, then storage locks before the result is used.
    device
        .platform
        .with(|state| state.storage_lock_after = Some(3));
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Locked
        ))
    );
    device.platform.with(|state| state.storage = Ok(()));
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::CompletionLost
        )),
        "a real loss is reported once storage is available"
    );
    // A key probe whose bracket sees a lock is Unavailable, never a lost key.
    let (device, _f, slot) = enrolled_device(ANDROID, 0x5f);
    let mut provider = device.open();
    device.platform.with(|state| {
        state.keys.remove(&slot);
        state.storage_lock_after = Some(1);
    });
    provider.poison(&slot);
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Locked
        ))
    );
    // An intent with a present key is abandoned only while storage is available.
    let (device, slot) = intent_only(0x60);
    let mut provider = device.open();
    device.platform.with(|state| {
        state.keys.insert(slot, signing_key(0x60));
        state.storage_lock_after = Some(3);
    });
    let slot_dir = kagemusha_wallet_slot_dir_v1(&slot);
    let before = names(&device, &slot_dir);
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Locked
        ))
    );
    assert_eq!(names(&device, &slot_dir), before, "nothing abandoned");
    device.platform.with(|state| state.storage = Ok(()));
    assert_eq!(
        provider.status(&slot),
        Ok(KagemushaWalletSlotStatusV1::SlotAbandoned)
    );
}

#[test]
fn wallet_advance_v1_reconcile_anchor_check_follows_the_slot() {
    // Regression: an iOS slot enrolled with the keychain anchor is never accepted without the
    // anchor check, whatever the platform adapter answers later.
    let (device, f, slot, bootstrap) = bootstrapped_device(IOS, 0x61);
    let snapshot = device.fork();
    let mut provider = device.open();
    let current = provider.status(&slot).expect("status");
    assert_eq!(
        current.marker().expect("marker").anchor(),
        KagemushaWalletAnchorPolicyV1::Keychain
    );
    released(
        provider
            .advance(
                &slot,
                &TestOwnerV1,
                &advance_request(
                    current.marker().expect("marker"),
                    &next_capsule(&f, &bootstrap),
                ),
            )
            .expect("advance"),
    );
    drop(provider);
    let policy = Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
        object: "anchor policy",
    });
    // The adapter stops reporting the anchor: refused, never accepted unchecked.
    device
        .platform
        .with(|state| state.policy = KagemushaWalletAnchorPolicyV1::NotRequired);
    assert_eq!(device.open().status(&slot), policy);
    // Restored older files under such an adapter are refused too; the key never signs.
    let restored = DeviceV1 {
        fs: snapshot.fs.fork(),
        platform: device.platform.fork(None),
    };
    let signed = restored.platform.with(|state| state.sign_calls);
    let mut provider = restored.open();
    assert_eq!(provider.status(&slot), policy);
    assert_eq!(provider.reconcile(&slot, &TestOwnerV1), policy);
    assert_eq!(restored.platform.with(|state| state.sign_calls), signed);
    drop(provider);
    // With the keychain answer back, the restored files are a rollback.
    restored
        .platform
        .with(|state| state.policy = KagemushaWalletAnchorPolicyV1::Keychain);
    let mut provider = restored.open();
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::RolledBack
        ))
    );
    // An Android slot is refused by an adapter that suddenly reports a keychain anchor.
    let (android, _f, android_slot, _) = bootstrapped_device(ANDROID, 0x62);
    android
        .platform
        .with(|state| state.policy = KagemushaWalletAnchorPolicyV1::Keychain);
    assert_eq!(android.open().status(&android_slot), policy);
}

#[test]
fn wallet_advance_v1_reconcile_keychain_key_without_files_is_visible_and_never_recreated() {
    let device = DeviceV1::new(IOS, 0xe1);
    let mut provider = device.open();
    let slot = KagemushaWalletSlotIdV1([0xe1; 32]);
    device.platform.with(|state| {
        state.keys.insert(slot, signing_key(0xe1));
    });
    let before = names(&device, &kagemusha_wallet_slots_dir_v1());
    assert_eq!(provider.slots(), Ok(vec![slot]));
    assert_eq!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::KeyWithoutMarker
        ))
    );
    assert_eq!(names(&device, &kagemusha_wallet_slots_dir_v1()), before);
    assert!(names(&device, &kagemusha_wallet_slot_dir_v1(&slot)).is_empty());
    assert!(device.platform.key_of(&slot).is_some());
    device.platform.with(|state| {
        assert_eq!(state.generate_calls, 0);
        assert_eq!(state.delete_calls, 0);
        assert_eq!(state.sign_calls, 0);
    });
}

#[test]
fn wallet_advance_v1_reconcile_keychain_inventory_unions_file_slots_without_duplicates() {
    let device = DeviceV1::new(IOS, 0xe2);
    let provider = device.open();
    let file_only = KagemushaWalletSlotIdV1([1; 32]);
    let both = KagemushaWalletSlotIdV1([2; 32]);
    let key_only = KagemushaWalletSlotIdV1([3; 32]);
    for slot in [file_only, both] {
        kagemusha_wallet_prepare_slot_dirs_v1(provider.store(), &slot).unwrap();
    }
    device.platform.with(|state| {
        state.keys.insert(both, signing_key(0xe2));
        state.keys.insert(key_only, signing_key(0xe3));
    });
    let before = names(&device, &kagemusha_wallet_slots_dir_v1());
    assert_eq!(provider.slots(), Ok(vec![file_only, both, key_only]));
    assert_eq!(names(&device, &kagemusha_wallet_slots_dir_v1()), before);
    assert!(names(&device, &kagemusha_wallet_slot_dir_v1(&key_only)).is_empty());
}

#[test]
fn wallet_advance_v1_reconcile_keychain_inventory_error_or_lock_never_means_empty() {
    let device = DeviceV1::new(IOS, 0xe4);
    let provider = device.open();
    let slot = KagemushaWalletSlotIdV1([0xe4; 32]);
    device.platform.with(|state| {
        state.keys.insert(slot, signing_key(0xe4));
    });
    let before = names(&device, &kagemusha_wallet_slots_dir_v1());
    for reason in [
        KagemushaWalletUnavailableV1::Locked,
        KagemushaWalletUnavailableV1::BeforeFirstUnlock,
        KagemushaWalletUnavailableV1::Io(5),
        KagemushaWalletUnavailableV1::Platform(0),
    ] {
        device.platform.with(|state| {
            state.enumerate_override = Some(Err(reason));
        });
        assert_eq!(
            provider.slots(),
            Err(KagemushaWalletProviderErrorV1::Unavailable(reason))
        );
    }
    device.platform.with(|state| {
        state.enumerate_override = Some(Ok(vec![]));
        state.storage_lock_after = Some(1);
    });
    assert_eq!(
        provider.slots(),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Locked
        ))
    );
    let calls = device.platform.with(|state| state.enumerate_calls);
    assert_eq!(
        provider.slots(),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Locked
        ))
    );
    assert_eq!(
        device.platform.with(|state| state.enumerate_calls),
        calls,
        "locked precheck must not query the key namespace"
    );
    assert_eq!(names(&device, &kagemusha_wallet_slots_dir_v1()), before);
    assert!(device.platform.key_of(&slot).is_some());
}

#[test]
fn wallet_advance_v1_reconcile_keychain_inventory_zero_duplicate_order_and_overflow_refuse() {
    let device = DeviceV1::new(IOS, 0xe5);
    let provider = device.open();
    let slot = KagemushaWalletSlotIdV1([1; 32]);
    let next = KagemushaWalletSlotIdV1([2; 32]);
    for invalid in [
        vec![KagemushaWalletSlotIdV1([0; 32])],
        vec![slot, slot],
        vec![next, slot],
        vec![slot; KAGEMUSHA_WALLET_KEY_ENUMERATION_MAX_SLOTS_V1 + 1],
    ] {
        device.platform.with(|state| {
            state.enumerate_override = Some(Ok(invalid));
        });
        assert_eq!(
            provider.slots(),
            Err(KagemushaWalletProviderErrorV1::Unavailable(
                KagemushaWalletUnavailableV1::Platform(0)
            ))
        );
    }
    assert!(names(&device, &kagemusha_wallet_slots_dir_v1()).is_empty());
    device.platform.with(|state| {
        assert_eq!(state.generate_calls, 0);
        assert_eq!(state.delete_calls, 0);
        assert_eq!(state.sign_calls, 0);
    });
}

#[test]
fn wallet_advance_v1_reconcile_not_required_platform_does_not_depend_on_keychain_enumeration() {
    let device = DeviceV1::new(ANDROID, 0xe6);
    let provider = device.open();
    device.platform.with(|state| {
        state.enumerate_override = Some(Err(KagemushaWalletUnavailableV1::Platform(0)));
    });
    assert_eq!(provider.slots(), Ok(vec![]));
    assert_eq!(device.platform.with(|state| state.enumerate_calls), 0);
}
