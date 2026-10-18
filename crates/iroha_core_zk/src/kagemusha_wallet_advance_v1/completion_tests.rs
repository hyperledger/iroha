//! Completion record persistence tests: staging under a Selected marker with adoption of an
//! existing record, Released-marker digest checks, the released-completion-loss regression,
//! strict listing and a staging fault matrix.

use iroha_data_model::kagemusha::KagemushaWalletRecoveryCapsuleV1;

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletCopyStateV1, KagemushaWalletCustodyDirV1, KagemushaWalletDurableMarkerV1,
    KagemushaWalletMarkerPublicationV1, KagemushaWalletMarkerRecordV1, KagemushaWalletSimFaultV1,
    KagemushaWalletSimFsV1, KagemushaWalletSimPowerLossV1,
    KagemushaWalletStorageCountersV1 as Counters, kagemusha_wallet_publish_marker_v1,
    test_support::{
        BOOT_A, BOOT_B, SimStoreV1, WalletFixtureV1, bootstrap_capsule, completion_for,
        prepared_slot, wallet_fixture,
    },
};

type Record = KagemushaWalletCompletionRecordV1;

/// Slot whose current durable marker is the Bootstrap Selected head.
struct SelectedV1 {
    fs: KagemushaWalletSimFsV1,
    store: SimStoreV1,
    capsule: KagemushaWalletRecoveryCapsuleV1,
    selected: KagemushaWalletDurableMarkerV1,
    capability: KagemushaWalletSelectedCapabilityV1,
}

fn publish(
    store: &SimStoreV1,
    record: KagemushaWalletMarkerRecordV1,
) -> KagemushaWalletDurableMarkerV1 {
    match kagemusha_wallet_publish_marker_v1(store, record).expect("publish") {
        KagemushaWalletMarkerPublicationV1::Durable(durable) => durable,
        KagemushaWalletMarkerPublicationV1::GenerationTaken => panic!("generation taken"),
    }
}

fn selected(f: &WalletFixtureV1) -> SelectedV1 {
    let (fs, store) = prepared_slot(f);
    let enrollment = publish(&store, f.enrollment_record(BOOT_A));
    let capsule = bootstrap_capsule(f);
    let selected = publish(
        &store,
        enrollment
            .record()
            .select(capsule.head_marker_state(), BOOT_A)
            .expect("select"),
    );
    let capability = selected.selected_capability().expect("capability");
    SelectedV1 {
        fs,
        store,
        capsule,
        selected,
        capability,
    }
}

fn dir(f: &WalletFixtureV1) -> KagemushaWalletCustodyDirV1 {
    kagemusha_wallet_completion_dir_v1(&f.slot)
}

fn expectation(s: &SelectedV1) -> KagemushaWalletCompletionExpectationV1 {
    KagemushaWalletCompletionExpectationV1::for_marker(s.selected.record()).expect("selected")
}

#[test]
fn wallet_advance_v1_completion_frame_trait_matches_g1() {
    let f = wallet_fixture(0x30);
    let capsule = bootstrap_capsule(&f);
    let record = completion_for(&f, &capsule, 0x01);
    let frame = record.encode_frame().expect("frame");
    assert_eq!(
        Record::frame_digest(&frame),
        record.completion_digest().expect("digest")
    );
    assert_eq!(
        Record::decode_frame(&frame, &f.wallet_id()).ok().as_ref(),
        Some(&record)
    );
    assert!(Record::decode_frame(&frame, &[9; 32]).is_err());
    assert_eq!(
        KagemushaWalletCompletionFrameV1::operation_id(&record),
        capsule.body().operation_id
    );
    assert_eq!(
        KagemushaWalletCompletionFrameV1::capsule_digest(&record),
        capsule.custody_digest()
    );
    assert_eq!(
        <Record as KagemushaWalletFrozenFrameV1>::OBJECT,
        "completion"
    );
}

#[test]
fn wallet_advance_v1_completion_expectation_for_marker() {
    let f = wallet_fixture(0x31);
    let s = selected(&f);
    let (_, operation_id, capsule_digest) = s.selected.record().head().expect("head");
    assert_eq!(
        expectation(&s),
        KagemushaWalletCompletionExpectationV1::Selected {
            selected_generation: 1,
            operation_id,
            capsule_digest,
        }
    );
    let released = s
        .selected
        .record()
        .release([0xd1; 32], BOOT_A)
        .expect("release");
    assert_eq!(
        KagemushaWalletCompletionExpectationV1::for_marker(&released),
        Some(KagemushaWalletCompletionExpectationV1::Released {
            selected_generation: 1,
            operation_id,
            capsule_digest,
            completion_digest: [0xd1; 32],
        })
    );
    assert_eq!(
        KagemushaWalletCompletionExpectationV1::for_marker(&f.enrollment_record(BOOT_A)),
        None
    );
}

#[test]
fn wallet_advance_v1_completion_stage_load_and_release() {
    let f = wallet_fixture(0x32);
    let s = selected(&f);
    assert_eq!(
        kagemusha_wallet_load_completion_v1::<_, Record>(
            &s.store,
            &f.slot,
            &expectation(&s),
            &f.wallet_id()
        ),
        Ok(None),
        "nothing staged yet under Selected"
    );
    let record = completion_for(&f, &s.capsule, 0x02);
    let staged = kagemusha_wallet_stage_completion_v1(
        &s.store,
        &s.capability,
        &Ok(BOOT_A),
        &record,
        &f.wallet_id(),
    )
    .expect("stage");
    assert!(!staged.adopted);
    assert_eq!(staged.record, record);
    assert_eq!(staged.frame, record.to_canonical_bytes().expect("frame"));
    assert_eq!(
        staged.completion_digest,
        record.completion_digest().expect("digest")
    );
    assert_eq!(
        kagemusha_wallet_list_completions_v1(&s.store, &f.slot),
        Ok(Some(
            KagemushaWalletCopyV1::BOTH
                .map(|copy| {
                    crate::kagemusha_wallet_advance_v1::KagemushaWalletCompletionNameV1 {
                        operation_id: s.capsule.body().operation_id,
                        copy,
                    }
                })
                .to_vec()
        ))
    );
    s.fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    let released = s
        .selected
        .record()
        .release(staged.completion_digest, BOOT_A)
        .expect("release");
    let expected = KagemushaWalletCompletionExpectationV1::for_marker(&released).expect("released");
    let loaded = kagemusha_wallet_load_completion_v1::<_, Record>(
        &s.store,
        &f.slot,
        &expected,
        &f.wallet_id(),
    )
    .expect("load")
    .expect("retained");
    assert_eq!(loaded.value(), &record);
    assert_eq!(loaded.frame(), staged.frame.as_slice());
    // A Released marker binding another digest finds no valid copy: the result is lost.
    let other = s
        .selected
        .record()
        .release([0xee; 32], BOOT_A)
        .expect("release");
    assert_eq!(
        kagemusha_wallet_load_completion_v1::<_, Record>(
            &s.store,
            &f.slot,
            &KagemushaWalletCompletionExpectationV1::for_marker(&other).expect("released"),
            &f.wallet_id()
        ),
        Err(KagemushaWalletProviderErrorV1::LostCustody(
            crate::kagemusha_wallet_advance_v1::KagemushaWalletLostCustodyV1::CompletionLost
        ))
    );
}

#[test]
fn wallet_advance_v1_completion_stage_adopts_existing_record() {
    let f = wallet_fixture(0x33);
    let s = selected(&f);
    let first = completion_for(&f, &s.capsule, 0x03);
    let second = completion_for(&f, &s.capsule, 0x04);
    assert_ne!(first, second);
    // Only the replica of an earlier attempt survived.
    let names = kagemusha_wallet_completion_names_v1(&s.capsule.body().operation_id);
    let frame = first.to_canonical_bytes().expect("frame");
    s.store.write_new(
        &dir(&f),
        &names[1],
        &super::super::capsule::encode_file::<Record>(1, BOOT_B, &frame).expect("file"),
    );
    let staged = kagemusha_wallet_stage_completion_v1(
        &s.store,
        &s.capability,
        &Ok(BOOT_A),
        &second,
        &f.wallet_id(),
    )
    .expect("stage");
    assert!(staged.adopted, "the earlier record wins");
    assert_eq!(staged.record, first);
    let loaded = kagemusha_wallet_load_completion_v1::<_, Record>(
        &s.store,
        &f.slot,
        &expectation(&s),
        &f.wallet_id(),
    )
    .expect("load")
    .expect("record");
    assert_eq!(loaded.value(), &first);
    for copy in KagemushaWalletCopyV1::BOTH {
        assert_eq!(loaded.state(copy), KagemushaWalletCopyStateV1::Valid);
    }
    // Staging again is idempotent.
    let again = kagemusha_wallet_stage_completion_v1(
        &s.store,
        &s.capability,
        &Ok(BOOT_A),
        &second,
        &f.wallet_id(),
    )
    .expect("stage");
    assert!(again.adopted);
    assert_eq!(again.completion_digest, staged.completion_digest);
}

#[test]
fn wallet_advance_v1_completion_stage_replaces_invalid_unreleased_copies() {
    let f = wallet_fixture(0x34);
    let s = selected(&f);
    let names = kagemusha_wallet_completion_names_v1(&s.capsule.body().operation_id);
    s.store.write_new(&dir(&f), &names[0], b"torn");
    s.store.write_new(&dir(&f), &names[1], b"torn");
    let record = completion_for(&f, &s.capsule, 0x05);
    let staged = kagemusha_wallet_stage_completion_v1(
        &s.store,
        &s.capability,
        &Ok(BOOT_A),
        &record,
        &f.wallet_id(),
    )
    .expect("stage");
    assert!(!staged.adopted);
    assert_eq!(staged.record, record);
}

#[test]
fn wallet_advance_v1_completion_stage_removes_only_invalid_copies() {
    // Both copies absent (every fresh Advance): no removal and no removal sync, only the
    // paired create-new publication with its single directory sync.
    let f = wallet_fixture(0x3a);
    let s = selected(&f);
    let record = completion_for(&f, &s.capsule, 0x0d);
    let (staged, fresh) = Counters::observe(|| {
        kagemusha_wallet_stage_completion_v1(
            &s.store,
            &s.capability,
            &Ok(BOOT_A),
            &record,
            &f.wallet_id(),
        )
    });
    assert!(!staged.expect("stage").adopted);
    assert_eq!(
        (
            fresh.removals,
            fresh.dir_syncs,
            fresh.staged_syncs,
            fresh.publish_syncs,
            fresh.fsync_class_calls()
        ),
        (0, 0, 2, 1, 3)
    );
    // One invalid never-released copy: exactly that copy is removed durably first.
    let g = wallet_fixture(0x3b);
    let t = selected(&g);
    let names = kagemusha_wallet_completion_names_v1(&t.capsule.body().operation_id);
    t.store.write_new(&dir(&g), &names[1], b"torn");
    let record = completion_for(&g, &t.capsule, 0x0d);
    let (staged, invalid) = Counters::observe(|| {
        kagemusha_wallet_stage_completion_v1(
            &t.store,
            &t.capability,
            &Ok(BOOT_A),
            &record,
            &g.wallet_id(),
        )
    });
    assert_eq!(staged.expect("stage").record, record);
    assert_eq!((invalid.removals, invalid.dir_syncs), (1, 1));
}

#[test]
fn wallet_advance_v1_completion_stage_after_unsynced_removal_keeps_one_record() {
    // An invalid never-released copy whose earlier removal is still unsynced reads as absent
    // and is not removed again: the fresh pair's directory sync makes that removal durable
    // before any Released marker. A fault at any step, power loss (which may resurrect the
    // invalid copy) and a retry with another record leave exactly one record in both copies,
    // and a record whose staging succeeded is never replaced.
    let f = wallet_fixture(0x3c);
    let s = selected(&f);
    let names = kagemusha_wallet_completion_names_v1(&s.capsule.body().operation_id);
    assert_eq!(
        s.store.write_new(&dir(&f), &names[0], b"torn"),
        crate::kagemusha_wallet_advance_v1::KagemushaWalletPublishOutcomeV1::Published
    );
    crate::kagemusha_wallet_advance_v1::KagemushaWalletFsV1::unlink(
        &s.fs,
        &dir(&f),
        names[0].as_str(),
    )
    .expect("unsynced removal");
    assert!(s.fs.pending_dir_ops() > 0);
    let first = completion_for(&f, &s.capsule, 0x0e);
    let second = completion_for(&f, &s.capsule, 0x0f);
    let probe = s.fs.fork();
    let start = probe.steps();
    let (staged, c) = Counters::observe(|| {
        kagemusha_wallet_stage_completion_v1(
            &KagemushaWalletDurableStoreV1::new(probe.clone()),
            &s.capability,
            &Ok(BOOT_A),
            &first,
            &f.wallet_id(),
        )
    });
    staged.expect("fault-free");
    assert_eq!(c.removals, 0, "an absent copy is not removed again");
    let mut cases = 0;
    for step in 0..probe.steps() - start {
        for fault in [
            KagemushaWalletSimFaultV1::Error,
            KagemushaWalletSimFaultV1::PartialWrite,
            KagemushaWalletSimFaultV1::LostWriteback,
            KagemushaWalletSimFaultV1::CrashBefore,
            KagemushaWalletSimFaultV1::CrashAfter,
        ] {
            for seed in 0..4_u64 {
                let fs = s.fs.fork();
                fs.inject(fs.steps() + step, fault);
                let store = KagemushaWalletDurableStoreV1::new(fs.clone());
                let outcome = kagemusha_wallet_stage_completion_v1(
                    &store,
                    &s.capability,
                    &Ok(BOOT_A),
                    &first,
                    &f.wallet_id(),
                );
                fs.power_loss(if seed == 0 {
                    KagemushaWalletSimPowerLossV1::DropUnsynced
                } else {
                    KagemushaWalletSimPowerLossV1::Seeded(seed)
                });
                store.remove_staging(&dir(&f)).expect("staging");
                let retried = kagemusha_wallet_stage_completion_v1(
                    &store,
                    &s.capability,
                    &Ok(BOOT_B),
                    &second,
                    &f.wallet_id(),
                )
                .expect("retry");
                if outcome.is_ok() {
                    assert!(
                        retried.adopted,
                        "a staged record is never replaced: step {step} {fault:?}"
                    );
                    assert_eq!(retried.record, first);
                }
                assert!(retried.record == first || retried.record == second);
                let pair = kagemusha_wallet_load_completion_v1::<_, Record>(
                    &store,
                    &f.slot,
                    &expectation(&s),
                    &f.wallet_id(),
                )
                .expect("load")
                .expect("record");
                assert_eq!(pair.value(), &retried.record);
                for copy in KagemushaWalletCopyV1::BOTH {
                    assert_eq!(pair.state(copy), KagemushaWalletCopyStateV1::Valid);
                }
                cases += 1;
            }
        }
    }
    assert!(cases > 0);
}

#[test]
fn wallet_advance_v1_completion_stage_rejects_foreign_record() {
    let f = wallet_fixture(0x35);
    let s = selected(&f);
    let other = crate::kagemusha_wallet_advance_v1::test_support::next_capsule(&f, &s.capsule);
    let foreign = completion_for(&f, &other, 0x06);
    assert_eq!(
        kagemusha_wallet_stage_completion_v1(
            &s.store,
            &s.capability,
            &Ok(BOOT_A),
            &foreign,
            &f.wallet_id()
        ),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "completion.binding"
        })
    );
    assert!(s.fs.visible_names(&dir(&f)).is_empty());
    // An invalid copy that cannot be removed stops staging; nothing is written.
    let record = completion_for(&f, &s.capsule, 0x07);
    let names = kagemusha_wallet_completion_names_v1(&s.capsule.body().operation_id);
    let racing = s.fs.fork();
    let store = KagemushaWalletDurableStoreV1::new(racing.clone());
    racing.place_unsynced(&dir(&f), names[0].as_str(), b"");
    racing.inject(
        racing.steps() + 2,
        KagemushaWalletSimFaultV1::ErrorKind(std::io::ErrorKind::PermissionDenied),
    );
    assert!(
        kagemusha_wallet_stage_completion_v1(
            &store,
            &s.capability,
            &Ok(BOOT_A),
            &record,
            &f.wallet_id()
        )
        .is_err()
    );
}

#[test]
fn wallet_advance_v1_completion_released_loss_is_never_resigned() {
    // Regression for the rev-1 defect: after release, a missing or corrupt completion under a
    // Released marker is CompletionLost; an unreadable one is Unavailable.
    let f = wallet_fixture(0x36);
    let s = selected(&f);
    let record = completion_for(&f, &s.capsule, 0x08);
    let staged = kagemusha_wallet_stage_completion_v1(
        &s.store,
        &s.capability,
        &Ok(BOOT_A),
        &record,
        &f.wallet_id(),
    )
    .expect("stage");
    let released = s
        .selected
        .record()
        .release(staged.completion_digest, BOOT_A)
        .expect("release");
    let expected = KagemushaWalletCompletionExpectationV1::for_marker(&released).expect("released");
    let names = kagemusha_wallet_completion_names_v1(&s.capsule.body().operation_id);
    let load = || {
        kagemusha_wallet_load_completion_v1::<_, Record>(
            &s.store,
            &f.slot,
            &expected,
            &f.wallet_id(),
        )
    };
    let lost = Err(KagemushaWalletProviderErrorV1::LostCustody(
        crate::kagemusha_wallet_advance_v1::KagemushaWalletLostCustodyV1::CompletionLost,
    ));
    // One copy lost: repaired from the other.
    s.store.remove_file(&dir(&f), &names[0]);
    let mut pair = load().expect("load").expect("replica");
    crate::kagemusha_wallet_advance_v1::kagemusha_wallet_repair_pair_v1(
        &s.store,
        &mut pair,
        &Ok(BOOT_A),
    )
    .expect("repair");
    assert_eq!(
        load()
            .expect("load")
            .expect("both")
            .state(KagemushaWalletCopyV1::Primary),
        KagemushaWalletCopyStateV1::Valid
    );
    // One copy unreadable, the other missing: unavailable, not lost.
    s.store.remove_file(&dir(&f), &names[1]);
    s.fs.inject(s.fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        load(),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    // Both missing: lost.
    s.store.remove_file(&dir(&f), &names[0]);
    assert_eq!(load().map(|pair| pair.map(|pair| pair.into_value())), lost);
    // Both corrupt, or holding another record: lost.
    s.store.write_new(&dir(&f), &names[0], b"corrupt");
    let other = completion_for(&f, &s.capsule, 0x09)
        .to_canonical_bytes()
        .expect("frame");
    s.store.write_new(
        &dir(&f),
        &names[1],
        &super::super::capsule::encode_file::<Record>(1, BOOT_A, &other).expect("file"),
    );
    assert_eq!(load().map(|pair| pair.map(|pair| pair.into_value())), lost);
}

#[test]
fn wallet_advance_v1_completion_list_is_strict() {
    let f = wallet_fixture(0x37);
    let (fs, store) = prepared_slot(&f);
    assert_eq!(
        kagemusha_wallet_list_completions_v1(
            &store,
            &crate::kagemusha_wallet_advance_v1::KagemushaWalletSlotIdV1([4; 32])
        ),
        Ok(None)
    );
    fs.place_unsynced(&dir(&f), ".tmp-000000000000000000000000000000dd", b"x");
    assert_eq!(
        kagemusha_wallet_list_completions_v1(&store, &f.slot),
        Ok(Some(Vec::new()))
    );
    fs.place_unsynced(&dir(&f), "unknown.cr", b"x");
    assert_eq!(
        kagemusha_wallet_list_completions_v1(&store, &f.slot),
        Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "completion" })
    );
    let (fs, store) = prepared_slot(&f);
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        kagemusha_wallet_list_completions_v1(&store, &f.slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
}

#[test]
fn wallet_advance_v1_completion_stage_fault_matrix() {
    // A fault at any step of completion staging under a Selected marker, then power loss and
    // a retry with a different fresh record: exactly one record survives in both copies, and a
    // record whose staging succeeded is never replaced by the retry.
    let f = wallet_fixture(0x38);
    let s = selected(&f);
    let first = completion_for(&f, &s.capsule, 0x0a);
    let second = completion_for(&f, &s.capsule, 0x0b);
    let probe = s.fs.fork();
    let start = probe.steps();
    kagemusha_wallet_stage_completion_v1(
        &KagemushaWalletDurableStoreV1::new(probe.clone()),
        &s.capability,
        &Ok(BOOT_A),
        &first,
        &f.wallet_id(),
    )
    .expect("fault-free");
    let mut cases = 0;
    for step in 0..probe.steps() - start {
        for fault in [
            KagemushaWalletSimFaultV1::Error,
            KagemushaWalletSimFaultV1::PartialWrite,
            KagemushaWalletSimFaultV1::LostWriteback,
            KagemushaWalletSimFaultV1::CrashBefore,
            KagemushaWalletSimFaultV1::CrashAfter,
        ] {
            for seed in 0..4_u64 {
                let fs = s.fs.fork();
                fs.inject(fs.steps() + step, fault);
                let store = KagemushaWalletDurableStoreV1::new(fs.clone());
                let outcome = kagemusha_wallet_stage_completion_v1(
                    &store,
                    &s.capability,
                    &Ok(BOOT_A),
                    &first,
                    &f.wallet_id(),
                );
                fs.power_loss(if seed == 0 {
                    KagemushaWalletSimPowerLossV1::DropUnsynced
                } else {
                    KagemushaWalletSimPowerLossV1::Seeded(seed)
                });
                store.remove_staging(&dir(&f)).expect("staging");
                let retried = kagemusha_wallet_stage_completion_v1(
                    &store,
                    &s.capability,
                    &Ok(BOOT_B),
                    &second,
                    &f.wallet_id(),
                )
                .expect("retry");
                if outcome.is_ok() {
                    assert!(
                        retried.adopted,
                        "a staged record is never replaced: step {step} {fault:?}"
                    );
                    assert_eq!(retried.record, first);
                }
                assert!(retried.record == first || retried.record == second);
                let pair = kagemusha_wallet_load_completion_v1::<_, Record>(
                    &store,
                    &f.slot,
                    &expectation(&s),
                    &f.wallet_id(),
                )
                .expect("load")
                .expect("record");
                assert_eq!(pair.value(), &retried.record);
                for copy in KagemushaWalletCopyV1::BOTH {
                    assert_eq!(pair.state(copy), KagemushaWalletCopyStateV1::Valid);
                }
                cases += 1;
            }
        }
    }
    assert!(cases > 0);
}

#[test]
fn wallet_advance_v1_completion_stage_refuses_superseded_capability() {
    // A capability kept after the Released marker cannot write a second result.
    let f = wallet_fixture(0x39);
    let s = selected(&f);
    let record = completion_for(&f, &s.capsule, 0x0c);
    let staged = kagemusha_wallet_stage_completion_v1(
        &s.store,
        &s.capability,
        &Ok(BOOT_A),
        &record,
        &f.wallet_id(),
    )
    .expect("stage");
    let released = s
        .selected
        .record()
        .release(staged.completion_digest, BOOT_A)
        .expect("release");
    publish(&s.store, released);
    let names = kagemusha_wallet_completion_names_v1(&s.capsule.body().operation_id);
    s.store.remove_file(&dir(&f), &names[0]);
    s.store.remove_file(&dir(&f), &names[1]);
    let fresh = completion_for(&f, &s.capsule, 0x0d);
    assert_eq!(
        kagemusha_wallet_stage_completion_v1(
            &s.store,
            &s.capability,
            &Ok(BOOT_A),
            &fresh,
            &f.wallet_id()
        ),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "marker.superseded"
        })
    );
    assert!(s.fs.visible_names(&dir(&f)).is_empty(), "nothing written");
}
