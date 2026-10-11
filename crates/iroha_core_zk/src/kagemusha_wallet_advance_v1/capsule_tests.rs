//! Capsule persistence tests: redundant copies, digest checks, repair, fresh-inode adoption,
//! staging discard, strict listing and a staging fault matrix.

use std::io;

use iroha_data_model::kagemusha::KagemushaWalletRetainedInputRoleV1 as RetainedRole;

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletMarkerPublicationV1, KagemushaWalletMarkerRecordV1, KagemushaWalletSimFaultV1,
    KagemushaWalletSimPowerLossV1, kagemusha_wallet_publish_marker_v1,
    test_support::{
        BOOT_A, BOOT_B, SimStoreV1, WalletFixtureV1, bootstrap_capsule, next_capsule,
        prepared_slot, wallet_fixture,
    },
};

type Capsule = KagemushaWalletRecoveryCapsuleV1;

fn durable(
    store: &SimStoreV1,
    record: KagemushaWalletMarkerRecordV1,
) -> KagemushaWalletDurableMarkerV1 {
    match kagemusha_wallet_publish_marker_v1(store, record).expect("publish") {
        KagemushaWalletMarkerPublicationV1::Durable(durable) => durable,
        KagemushaWalletMarkerPublicationV1::GenerationTaken => panic!("generation taken"),
    }
}

/// Prepared slot whose current durable marker is the enrollment marker.
fn enrolled(
    f: &WalletFixtureV1,
) -> (
    crate::kagemusha_wallet_advance_v1::KagemushaWalletSimFsV1,
    SimStoreV1,
    KagemushaWalletDurableMarkerV1,
) {
    let (fs, store) = prepared_slot(f);
    let enrollment = durable(&store, f.enrollment_record(BOOT_A));
    (fs, store, enrollment)
}

fn dir(f: &WalletFixtureV1) -> KagemushaWalletCustodyDirV1 {
    kagemusha_wallet_capsules_dir_v1(&f.slot)
}

#[test]
fn wallet_advance_v1_capsule_frame_trait_matches_g1() {
    let f = wallet_fixture(0x20);
    let capsule = bootstrap_capsule(&f);
    let frame = capsule.encode_frame().expect("frame");
    assert_eq!(frame, capsule.to_canonical_bytes().expect("canonical"));
    assert_eq!(
        Capsule::frame_digest(&frame),
        capsule.capsule_digest().expect("digest")
    );
    assert_eq!(
        Capsule::decode_frame(&frame, &f.scheme_id()).ok().as_ref(),
        Some(&capsule)
    );
    assert!(Capsule::decode_frame(&frame, &[9; 32]).is_err());
    assert_eq!(<Capsule as KagemushaWalletFrozenFrameV1>::OBJECT, "capsule");
    assert_eq!(
        file_max::<Capsule>(),
        KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1 + KAGEMUSHA_WALLET_FROZEN_FILE_OVERHEAD_BYTES_V1
    );
}

#[test]
fn wallet_advance_v1_capsule_stage_and_load() {
    let f = wallet_fixture(0x21);
    let (fs, store, enrollment) = enrolled(&f);
    let capsule = bootstrap_capsule(&f);
    let digest = capsule.capsule_digest().expect("digest");
    let staged = kagemusha_wallet_stage_capsule_v1(
        &store,
        &enrollment,
        &Ok(BOOT_A),
        &capsule,
        &f.scheme_id(),
    )
    .expect("stage");
    assert_eq!(
        staged,
        KagemushaWalletStagedCapsuleV1 {
            selected_generation: 1,
            capsule_digest: digest,
        }
    );
    let names = kagemusha_wallet_capsule_names_v1(1, &digest);
    assert_eq!(
        fs.visible_names(&dir(&f)),
        names
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect::<Vec<_>>()
    );
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    let loaded =
        kagemusha_wallet_load_capsule_v1::<_, Capsule>(&store, &f.slot, 1, &digest, &f.scheme_id())
            .expect("load");
    assert_eq!(loaded.value(), &capsule);
    assert_eq!(
        loaded.frame(),
        capsule.to_canonical_bytes().expect("frame").as_slice()
    );
    assert_eq!(loaded.frame_digest(), &digest);
    assert_eq!(loaded.selected_generation(), 1);
    for copy in KagemushaWalletCopyV1::BOTH {
        assert_eq!(loaded.state(copy), KagemushaWalletCopyStateV1::Valid);
        assert!(loaded.written_this_boot(copy, &Ok(BOOT_A)));
        assert!(!loaded.written_this_boot(copy, &Ok(BOOT_B)));
    }
    assert_eq!(loaded.into_value(), capsule);
    assert_eq!(
        kagemusha_wallet_list_capsules_v1(&store, &f.slot),
        Ok(Some(vec![
            KagemushaWalletCapsuleNameV1 {
                selected_generation: 1,
                capsule_digest: digest,
                copy: KagemushaWalletCopyV1::Primary,
            },
            KagemushaWalletCapsuleNameV1 {
                selected_generation: 1,
                capsule_digest: digest,
                copy: KagemushaWalletCopyV1::Replica,
            },
        ]))
    );
}

#[test]
fn wallet_advance_v1_quota_witness_survives_power_loss_replica_repair_and_replay() {
    // This exercises the generic frozen-byte store only. No head is selected,
    // receipt signed or stand-in proof admitted by the simulated storage fixture.
    let document: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let row = document["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            row["type"].as_str() == Some("KagemushaWalletRecoveryCapsuleV1")
                && row["variant"].as_str() == Some("QuotaShare, 64 retained predecessor slots")
        })
        .unwrap();
    let original = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    let capsule: Capsule = norito::decode_canonical(&original).unwrap();
    let witness = capsule.quota_refresh_witness().unwrap().unwrap();
    assert_eq!(witness.predecessor_usage.iter().flatten().count(), 64);
    let f = wallet_fixture(0x42);
    let (fs, store, enrollment) = enrolled(&f);
    let digest = capsule.capsule_digest().unwrap();
    let staged = kagemusha_wallet_stage_capsule_v1(
        &store,
        &enrollment,
        &Ok(BOOT_A),
        &capsule,
        &capsule.scheme_id,
    )
    .unwrap();
    assert_eq!(staged.capsule_digest, digest);
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    let names = kagemusha_wallet_capsule_names_v1(1, &digest);
    store.remove_file(&dir(&f), &names[0]);
    let mut loaded = kagemusha_wallet_load_capsule_v1::<_, Capsule>(
        &store,
        &f.slot,
        1,
        &digest,
        &capsule.scheme_id,
    )
    .unwrap();
    assert_eq!(
        loaded.value().quota_refresh_witness().unwrap(),
        Some(witness)
    );
    assert_eq!(loaded.frame(), original);
    kagemusha_wallet_repair_pair_v1(&store, &mut loaded, &Ok(BOOT_B)).unwrap();
    kagemusha_wallet_settle_pair_v1(&store, &loaded, true).unwrap();
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    let replay = kagemusha_wallet_load_capsule_v1::<_, Capsule>(
        &store,
        &f.slot,
        1,
        &digest,
        &capsule.scheme_id,
    )
    .unwrap();
    assert_eq!(replay.frame(), original);
    assert_eq!(
        replay.value().quota_refresh_witness().unwrap(),
        Some(witness)
    );
    for copy in KagemushaWalletCopyV1::BOTH {
        assert_eq!(replay.state(copy), KagemushaWalletCopyStateV1::Valid);
    }
    let mut changed = capsule;
    let retained = changed
        .retained_inputs
        .iter_mut()
        .find(|input| input.role == RetainedRole::QuotaRefreshWitness)
        .unwrap();
    let mut swapped = witness;
    swapped.predecessor_usage[63].as_mut().unwrap().used += 1;
    retained.bytes = swapped.to_canonical_bytes().unwrap();
    assert_ne!(
        changed.capsule_digest().unwrap(),
        digest,
        "every retained usage value is covered by the receipt's capsule digest"
    );
}

#[test]
fn wallet_advance_v1_capsule_stage_requires_enrollment_or_released() {
    let f = wallet_fixture(0x22);
    let (_fs, store, enrollment) = enrolled(&f);
    let capsule = bootstrap_capsule(&f);
    let mut invalid = capsule.clone();
    invalid.map_openings = vec![Vec::new()];
    assert_eq!(
        kagemusha_wallet_stage_capsule_v1(
            &store,
            &enrollment,
            &Ok(BOOT_A),
            &invalid,
            &f.scheme_id()
        ),
        Err(KagemushaWalletProviderErrorV1::Invalid { field: "capsule" })
    );
    let selected = durable(
        &store,
        enrollment
            .record()
            .select(capsule.head_marker_state().expect("head"), BOOT_A)
            .expect("select"),
    );
    assert_eq!(
        kagemusha_wallet_stage_capsule_v1(&store, &selected, &Ok(BOOT_A), &capsule, &f.scheme_id()),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "marker.phase"
        })
    );
}

#[test]
fn wallet_advance_v1_capsule_stage_adopts_or_replaces_leftovers() {
    let f = wallet_fixture(0x23);
    let capsule = bootstrap_capsule(&f);
    let digest = capsule.capsule_digest().expect("digest");
    let names = kagemusha_wallet_capsule_names_v1(1, &digest);
    // A valid primary left by an interrupted attempt: adopted on a fresh inode, replica added.
    let (fs, store, enrollment) = enrolled(&f);
    let frame = capsule.to_canonical_bytes().expect("frame");
    store.write_new(
        &dir(&f),
        &names[0],
        &encode_file::<Capsule>(1, BOOT_B, &frame).expect("file"),
    );
    let inode = fs.inode_of(&dir(&f), names[0].as_str());
    kagemusha_wallet_stage_capsule_v1(&store, &enrollment, &Ok(BOOT_A), &capsule, &f.scheme_id())
        .expect("adopt");
    assert_ne!(
        fs.inode_of(&dir(&f), names[0].as_str()),
        inode,
        "fresh inode"
    );
    let loaded =
        kagemusha_wallet_load_capsule_v1::<_, Capsule>(&store, &f.slot, 1, &digest, &f.scheme_id())
            .expect("load");
    assert_eq!(
        loaded.state(KagemushaWalletCopyV1::Replica),
        KagemushaWalletCopyStateV1::Valid
    );
    // A corrupt leftover under the name is replaced.
    let (_fs, store, enrollment) = enrolled(&f);
    store.write_new(&dir(&f), &names[1], b"torn");
    kagemusha_wallet_stage_capsule_v1(&store, &enrollment, &Ok(BOOT_A), &capsule, &f.scheme_id())
        .expect("replace");
    let loaded =
        kagemusha_wallet_load_capsule_v1::<_, Capsule>(&store, &f.slot, 1, &digest, &f.scheme_id())
            .expect("load");
    for copy in KagemushaWalletCopyV1::BOTH {
        assert_eq!(loaded.state(copy), KagemushaWalletCopyStateV1::Valid);
    }
    // Both copies corrupt: removed and rewritten.
    let (_fs, store, enrollment) = enrolled(&f);
    store.write_new(&dir(&f), &names[0], b"torn");
    store.write_new(&dir(&f), &names[1], b"torn");
    kagemusha_wallet_stage_capsule_v1(&store, &enrollment, &Ok(BOOT_A), &capsule, &f.scheme_id())
        .expect("rewrite");
    kagemusha_wallet_load_capsule_v1::<_, Capsule>(&store, &f.slot, 1, &digest, &f.scheme_id())
        .expect("load");
}

#[test]
fn wallet_advance_v1_capsule_load_from_either_copy_and_classify() {
    let f = wallet_fixture(0x24);
    let (fs, store, enrollment) = enrolled(&f);
    let capsule = bootstrap_capsule(&f);
    let digest = capsule.capsule_digest().expect("digest");
    let scheme = f.scheme_id();
    kagemusha_wallet_stage_capsule_v1(&store, &enrollment, &Ok(BOOT_A), &capsule, &scheme)
        .expect("stage");
    let names = kagemusha_wallet_capsule_names_v1(1, &digest);
    let load =
        || kagemusha_wallet_load_capsule_v1::<_, Capsule>(&store, &f.slot, 1, &digest, &scheme);
    // Primary missing: the replica serves.
    store.remove_file(&dir(&f), &names[0]);
    let loaded = load().expect("replica");
    assert_eq!(
        loaded.state(KagemushaWalletCopyV1::Primary),
        KagemushaWalletCopyStateV1::Absent
    );
    assert_eq!(loaded.value(), &capsule);
    // Primary corrupt.
    store.write_new(&dir(&f), &names[0], b"corrupt");
    assert_eq!(
        load()
            .expect("replica")
            .state(KagemushaWalletCopyV1::Primary),
        KagemushaWalletCopyStateV1::Invalid
    );
    // Primary unreadable now: still served by the replica, reported unavailable.
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        load()
            .expect("replica")
            .state(KagemushaWalletCopyV1::Primary),
        KagemushaWalletCopyStateV1::Unavailable(_)
    ));
    // Replica gone too: unavailable custody data, never a fallback.
    store.remove_file(&dir(&f), &names[1]);
    assert_eq!(
        load().err(),
        Some(KagemushaWalletProviderErrorV1::UnavailableCustodyData { object: "capsule" })
    );
    // An unreadable copy with no valid copy is unavailable, not lost.
    fs.inject(fs.steps() + 1, KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        load(),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    // Wrong generation, wrong digest name and oversized copies are invalid.
    let frame = capsule.to_canonical_bytes().expect("frame");
    store.remove_file(&dir(&f), &names[0]);
    store.write_new(
        &dir(&f),
        &names[0],
        &encode_file::<Capsule>(2, BOOT_A, &frame).expect("file"),
    );
    let next = next_capsule(&f, &capsule)
        .to_canonical_bytes()
        .expect("frame");
    store.write_new(
        &dir(&f),
        &names[1],
        &encode_file::<Capsule>(1, BOOT_A, &next).expect("file"),
    );
    assert_eq!(
        load().err(),
        Some(KagemushaWalletProviderErrorV1::UnavailableCustodyData { object: "capsule" })
    );
    store.remove_file(&dir(&f), &names[1]);
    store.write_new(&dir(&f), &names[1], &vec![0; file_max::<Capsule>() + 1]);
    assert_eq!(
        load().err(),
        Some(KagemushaWalletProviderErrorV1::UnavailableCustodyData { object: "capsule" })
    );
}

#[test]
fn wallet_advance_v1_capsule_repair_and_settle() {
    let f = wallet_fixture(0x25);
    let (fs, store, enrollment) = enrolled(&f);
    let capsule = bootstrap_capsule(&f);
    let digest = capsule.capsule_digest().expect("digest");
    let scheme = f.scheme_id();
    kagemusha_wallet_stage_capsule_v1(&store, &enrollment, &Ok(BOOT_B), &capsule, &scheme)
        .expect("stage");
    let names = kagemusha_wallet_capsule_names_v1(1, &digest);
    store.remove_file(&dir(&f), &names[0]);
    store.remove_file(&dir(&f), &names[1]);
    store.write_new(
        &dir(&f),
        &names[1],
        &encode_file::<Capsule>(1, BOOT_B, &capsule.to_canonical_bytes().expect("frame"))
            .expect("file"),
    );
    store.write_new(&dir(&f), &names[0], b"corrupt");
    let mut loaded =
        kagemusha_wallet_load_capsule_v1::<_, Capsule>(&store, &f.slot, 1, &digest, &scheme)
            .expect("load");
    kagemusha_wallet_repair_pair_v1(&store, &mut loaded, &Ok(BOOT_A)).expect("repair");
    assert_eq!(
        loaded.state(KagemushaWalletCopyV1::Primary),
        KagemushaWalletCopyStateV1::Valid
    );
    assert!(loaded.written_this_boot(KagemushaWalletCopyV1::Primary, &Ok(BOOT_A)));
    assert!(!loaded.written_this_boot(KagemushaWalletCopyV1::Replica, &Ok(BOOT_A)));
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    let reloaded =
        kagemusha_wallet_load_capsule_v1::<_, Capsule>(&store, &f.slot, 1, &digest, &scheme)
            .expect("load");
    for copy in KagemushaWalletCopyV1::BOTH {
        assert_eq!(reloaded.state(copy), KagemushaWalletCopyStateV1::Valid);
    }
    // Settling by sync keeps inodes; settling by rewrite replaces them.
    let inodes = |fs: &crate::kagemusha_wallet_advance_v1::KagemushaWalletSimFsV1| {
        names
            .clone()
            .map(|name| fs.inode_of(&dir(&f), name.as_str()))
    };
    let before = inodes(&fs);
    kagemusha_wallet_settle_pair_v1(&store, &reloaded, false).expect("sync");
    assert_eq!(inodes(&fs), before);
    kagemusha_wallet_settle_pair_v1(&store, &reloaded, true).expect("rewrite");
    let after = inodes(&fs);
    assert_ne!(after[0], before[0]);
    assert_ne!(after[1], before[1]);
    // An unavailable copy blocks repair (retry), never treated as absent.
    let mut loaded = reloaded;
    loaded.states[1] = KagemushaWalletCopyStateV1::Unavailable(
        crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Locked,
    );
    assert!(matches!(
        kagemusha_wallet_repair_pair_v1(&store, &mut loaded, &Ok(BOOT_A)),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(kagemusha_wallet_settle_pair_v1(&store, &loaded, false).is_err());
}

#[test]
fn wallet_advance_v1_capsule_discard_staged_only_above_current() {
    let f = wallet_fixture(0x26);
    let (fs, store, enrollment) = enrolled(&f);
    let capsule = bootstrap_capsule(&f);
    let digest = capsule.capsule_digest().expect("digest");
    kagemusha_wallet_stage_capsule_v1(&store, &enrollment, &Ok(BOOT_A), &capsule, &f.scheme_id())
        .expect("stage");
    assert_eq!(
        kagemusha_wallet_discard_staged_capsule_v1(&store, &enrollment, 0, &digest),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "capsule.selected_generation"
        })
    );
    kagemusha_wallet_discard_staged_capsule_v1(&store, &enrollment, 1, &digest).expect("discard");
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    assert_eq!(
        kagemusha_wallet_list_capsules_v1(&store, &f.slot),
        Ok(Some(Vec::new()))
    );
    fs.inject(
        fs.steps(),
        KagemushaWalletSimFaultV1::ErrorKind(io::ErrorKind::PermissionDenied),
    );
    assert!(matches!(
        kagemusha_wallet_discard_staged_capsule_v1(&store, &enrollment, 1, &digest),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
}

#[test]
fn wallet_advance_v1_capsule_list_is_strict() {
    let f = wallet_fixture(0x27);
    let (fs, store) = prepared_slot(&f);
    assert_eq!(
        kagemusha_wallet_list_capsules_v1(
            &store,
            &crate::kagemusha_wallet_advance_v1::KagemushaWalletSlotIdV1([3; 32])
        ),
        Ok(None)
    );
    fs.place_unsynced(&dir(&f), ".tmp-000000000000000000000000000000cc", b"x");
    assert_eq!(
        kagemusha_wallet_list_capsules_v1(&store, &f.slot),
        Ok(Some(Vec::new()))
    );
    fs.place_other(&dir(&f), "c-00000000000000000000000000000001-link.cap");
    assert_eq!(
        kagemusha_wallet_list_capsules_v1(&store, &f.slot),
        Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "capsules" })
    );
    let (fs, store) = prepared_slot(&f);
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        kagemusha_wallet_list_capsules_v1(&store, &f.slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
}

#[test]
fn wallet_advance_v1_capsule_pair_write_mapping() {
    use crate::kagemusha_wallet_advance_v1::{
        KagemushaWalletNotPublishedV1 as N, KagemushaWalletPublishOutcomeV1 as P,
    };
    assert_eq!(pair_write_published(P::Published), Ok(true));
    assert_eq!(
        pair_write_published(P::NotPublished(N::DestinationExists)),
        Ok(false)
    );
    assert_eq!(
        pair_write_published(P::NotPublished(N::NoSpace)),
        Err(KagemushaWalletProviderErrorV1::NoSpace)
    );
}

#[test]
fn wallet_advance_v1_capsule_stage_fault_matrix() {
    // A fault at any step of staging, followed by power loss, leaves either nothing loadable
    // (the caller reports NotPerformed and discards) or the exact capsule; a successful stage
    // is durable. Loading never returns a torn or foreign capsule.
    let f = wallet_fixture(0x28);
    let capsule = bootstrap_capsule(&f);
    let digest = capsule.capsule_digest().expect("digest");
    let scheme = f.scheme_id();
    let (base, _store, enrollment) = enrolled(&f);
    let probe = base.fork();
    let start = probe.steps();
    kagemusha_wallet_stage_capsule_v1(
        &KagemushaWalletDurableStoreV1::new(probe.clone()),
        &enrollment,
        &Ok(BOOT_A),
        &capsule,
        &scheme,
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
                let fs = base.fork();
                fs.inject(fs.steps() + step, fault);
                let store = KagemushaWalletDurableStoreV1::new(fs.clone());
                let outcome = kagemusha_wallet_stage_capsule_v1(
                    &store,
                    &enrollment,
                    &Ok(BOOT_A),
                    &capsule,
                    &scheme,
                );
                fs.power_loss(if seed == 0 {
                    KagemushaWalletSimPowerLossV1::DropUnsynced
                } else {
                    KagemushaWalletSimPowerLossV1::Seeded(seed)
                });
                let loaded = kagemusha_wallet_load_capsule_v1::<_, Capsule>(
                    &store, &f.slot, 1, &digest, &scheme,
                );
                match &loaded {
                    Ok(pair) => assert_eq!(pair.value(), &capsule),
                    Err(error) => {
                        assert_eq!(
                            *error,
                            KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                                object: "capsule"
                            }
                        );
                        assert!(
                            outcome.is_err(),
                            "staged capsule lost: step {step} {fault:?} seed {seed}"
                        );
                    }
                }
                if outcome.is_ok() {
                    let pair = loaded.expect("durable");
                    for copy in KagemushaWalletCopyV1::BOTH {
                        assert_eq!(pair.state(copy), KagemushaWalletCopyStateV1::Valid);
                    }
                }
                // Retrying after the fault always converges on two valid copies.
                let retried = KagemushaWalletDurableStoreV1::new(fs.clone());
                retried.remove_staging(&dir(&f)).expect("staging");
                kagemusha_wallet_stage_capsule_v1(
                    &retried,
                    &enrollment,
                    &Ok(BOOT_B),
                    &capsule,
                    &scheme,
                )
                .expect("retry");
                let pair = kagemusha_wallet_load_capsule_v1::<_, Capsule>(
                    &retried, &f.slot, 1, &digest, &scheme,
                )
                .expect("retry load");
                for copy in KagemushaWalletCopyV1::BOTH {
                    assert_eq!(pair.state(copy), KagemushaWalletCopyStateV1::Valid);
                }
                cases += 1;
            }
        }
    }
    assert!(cases >= 9 * 5 * 4);
}

#[test]
fn wallet_advance_v1_capsule_refuses_superseded_current_marker() {
    let f = wallet_fixture(0x29);
    let (_fs, store, enrollment) = enrolled(&f);
    let capsule = bootstrap_capsule(&f);
    let digest = capsule.capsule_digest().expect("digest");
    kagemusha_wallet_stage_capsule_v1(&store, &enrollment, &Ok(BOOT_A), &capsule, &f.scheme_id())
        .expect("stage");
    durable(
        &store,
        enrollment
            .record()
            .select(capsule.head_marker_state().expect("head"), BOOT_A)
            .expect("select"),
    );
    let superseded = KagemushaWalletProviderErrorV1::Invalid {
        field: "marker.superseded",
    };
    // The capsule is now bound by the Selected marker: a stale view cannot discard it.
    assert_eq!(
        kagemusha_wallet_discard_staged_capsule_v1(&store, &enrollment, 1, &digest),
        Err(superseded)
    );
    assert_eq!(
        kagemusha_wallet_stage_capsule_v1(
            &store,
            &enrollment,
            &Ok(BOOT_A),
            &capsule,
            &f.scheme_id()
        )
        .err(),
        Some(superseded)
    );
    kagemusha_wallet_load_capsule_v1::<_, Capsule>(&store, &f.slot, 1, &digest, &f.scheme_id())
        .expect("bound capsule intact");
}
