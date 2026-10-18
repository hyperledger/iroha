//! Marker generation tests: phases, successor rules, strict selection of the highest
//! generation, adoption, publication, retirement and continuous coverage under crashes.

use std::io;

use iroha_data_model::kagemusha::KagemushaWalletTerminalReasonV1;

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletRemoveOutcomeV1, KagemushaWalletSimFaultV1, KagemushaWalletSimPowerLossV1,
    test_support::{
        BOOT_A, BOOT_B, SimStoreV1, WalletFixtureV1, bootstrap_capsule, next_capsule,
        prepared_slot, wallet_fixture,
    },
};

const ANDROID: KagemushaWalletAnchorPolicyV1 = KagemushaWalletAnchorPolicyV1::NotRequired;

fn durable(
    store: &SimStoreV1,
    record: KagemushaWalletMarkerRecordV1,
) -> KagemushaWalletDurableMarkerV1 {
    match kagemusha_wallet_publish_marker_v1(store, record).expect("publish") {
        KagemushaWalletMarkerPublicationV1::Durable(durable) => durable,
        KagemushaWalletMarkerPublicationV1::GenerationTaken => panic!("generation taken"),
    }
}

/// Enrollment, Selected (Bootstrap), Released, Selected (next) and their completion digests.
struct ChainV1 {
    enrollment: KagemushaWalletMarkerRecordV1,
    selected: KagemushaWalletMarkerRecordV1,
    released: KagemushaWalletMarkerRecordV1,
    next: KagemushaWalletMarkerRecordV1,
}

fn chain(f: &WalletFixtureV1) -> ChainV1 {
    let enrollment = f.enrollment_record(BOOT_A);
    let first = bootstrap_capsule(f);
    let selected = enrollment
        .select(first.head_marker_state(), BOOT_A)
        .expect("select");
    let released = selected.release([0xc1; 32], BOOT_A).expect("release");
    let next = released
        .select(next_capsule(f, &first).head_marker_state(), BOOT_A)
        .expect("next");
    ChainV1 {
        enrollment,
        selected,
        released,
        next,
    }
}

fn markers_dir(
    f: &WalletFixtureV1,
) -> crate::kagemusha_wallet_advance_v1::KagemushaWalletCustodyDirV1 {
    kagemusha_wallet_markers_dir_v1(&f.slot)
}

#[test]
fn wallet_advance_v1_marker_phases_and_accessors() {
    let f = wallet_fixture(0x10);
    let c = chain(&f);
    for (record, phase, generation, selected_generation) in [
        (
            &c.enrollment,
            KagemushaWalletMarkerPhaseV1::Enrollment,
            0,
            None,
        ),
        (
            &c.selected,
            KagemushaWalletMarkerPhaseV1::Selected,
            1,
            Some(1),
        ),
        (
            &c.released,
            KagemushaWalletMarkerPhaseV1::Released,
            2,
            Some(1),
        ),
        (&c.next, KagemushaWalletMarkerPhaseV1::Selected, 3, Some(3)),
    ] {
        assert_eq!(record.phase(), phase);
        assert_eq!(record.generation(), generation);
        assert_eq!(record.selected_generation(), selected_generation);
        assert_eq!(record.slot(), &f.slot);
        assert_eq!(record.payment_key(), &f.payment_key);
        assert_eq!(record.written_boot_id(), &BOOT_A);
        assert_eq!(
            record.file_name(),
            kagemusha_wallet_marker_name_v1(generation)
        );
        assert_eq!(record.marker().generation, generation);
        assert_eq!(
            record.marker_digest(),
            &record.marker().marker_digest().expect("digest")
        );
        assert_eq!(
            record.marker_file_digest(),
            &kagemusha_wallet_provider_digest_v1("marker-file", record.file_bytes())
        );
    }
    assert_eq!(c.enrollment.head(), None);
    assert_eq!(c.selected.head(), c.released.head());
    assert_eq!(c.selected.completion_digest(), None);
    assert_eq!(c.released.completion_digest(), Some([0xc1; 32]));
    // The phase is covered by the file digest, not by the G1 marker digest.
    let other = c.selected.release([0xc2; 32], BOOT_A).expect("release");
    assert_eq!(other.marker_digest(), c.released.marker_digest());
    assert_ne!(other.marker_file_digest(), c.released.marker_file_digest());
}

#[test]
fn wallet_advance_v1_marker_record_rejects_inconsistent_phase() {
    let f = wallet_fixture(0x11);
    let c = chain(&f);
    assert_eq!(
        KagemushaWalletMarkerRecordV1::new(f.slot, &f.enrollment, ANDROID, Some([1; 32]), BOOT_A),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "marker.completion_digest"
        })
    );
    assert_eq!(
        KagemushaWalletMarkerRecordV1::new(
            f.slot,
            c.selected.marker(),
            ANDROID,
            Some([0; 32]),
            BOOT_A
        ),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "marker.completion_digest"
        })
    );
    let terminal = c
        .released
        .terminate(KagemushaWalletTerminalReasonV1::CustodyDeleted, BOOT_A);
    let terminal = terminal.expect("terminal");
    assert!(
        KagemushaWalletMarkerRecordV1::new(
            f.slot,
            terminal.marker(),
            ANDROID,
            Some([1; 32]),
            BOOT_A
        )
        .is_err()
    );
    let mut invalid = f.enrollment;
    invalid.generation = 1;
    assert_eq!(
        KagemushaWalletMarkerRecordV1::new(f.slot, &invalid, ANDROID, None, BOOT_A),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "marker.frame"
        })
    );
}

#[test]
fn wallet_advance_v1_marker_decode_roundtrip_and_rejections() {
    let f = wallet_fixture(0x12);
    let c = chain(&f);
    let scheme = f.scheme_id();
    for record in [&c.enrollment, &c.selected, &c.released, &c.next] {
        assert_eq!(
            KagemushaWalletMarkerRecordV1::decode(record.file_bytes(), &f.slot, &scheme).as_ref(),
            Ok(record)
        );
    }
    let bytes = c.released.file_bytes();
    assert!(
        KagemushaWalletMarkerRecordV1::decode(bytes, &KagemushaWalletSlotIdV1([9; 32]), &scheme)
            .is_err()
    );
    assert!(KagemushaWalletMarkerRecordV1::decode(bytes, &f.slot, &[9; 32]).is_err());
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(KagemushaWalletMarkerRecordV1::decode(&trailing, &f.slot, &scheme).is_err());
    let mut flipped = bytes.to_vec();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert!(KagemushaWalletMarkerRecordV1::decode(&flipped, &f.slot, &scheme).is_err());
    assert!(
        KagemushaWalletMarkerRecordV1::decode(
            &vec![0; KAGEMUSHA_WALLET_MARKER_FILE_MAX_BYTES_V1 + 1],
            &f.slot,
            &scheme
        )
        .is_err()
    );
    let mut file: KagemushaWalletMarkerFileV1 =
        norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
            .expect("envelope");
    file.version = 2;
    let versioned = norito::encode_canonical(&file).expect("encode");
    assert_eq!(
        KagemushaWalletMarkerRecordV1::decode(&versioned, &f.slot, &scheme),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "marker_file.version"
        })
    );
    file.version = 1;
    file.marker.push(0);
    let noncanonical = norito::encode_canonical(&file).expect("encode");
    assert_eq!(
        KagemushaWalletMarkerRecordV1::decode(&noncanonical, &f.slot, &scheme),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "marker.frame"
        })
    );
}

#[test]
fn wallet_advance_v1_marker_successor_rules() {
    let f = wallet_fixture(0x13);
    let c = chain(&f);
    let abandoned = c
        .enrollment
        .terminate(KagemushaWalletTerminalReasonV1::Abandoned, BOOT_A)
        .expect("abandon");
    let deleted_selected = c
        .selected
        .terminate(KagemushaWalletTerminalReasonV1::CustodyDeleted, BOOT_A)
        .expect("delete from selected");
    let deleted = c
        .released
        .terminate(KagemushaWalletTerminalReasonV1::CustodyDeleted, BOOT_A)
        .expect("delete");
    for (next, previous) in [
        (&c.selected, &c.enrollment),
        (&c.released, &c.selected),
        (&c.next, &c.released),
        (&abandoned, &c.enrollment),
        (&deleted_selected, &c.selected),
        (&deleted, &c.released),
    ] {
        next.validate_successor_of(previous)
            .expect("valid successor");
    }
    for (next, previous) in [
        (&c.released, &c.enrollment),
        (&c.next, &c.selected),
        (&c.selected, &c.released),
        (&c.next, &c.enrollment),
        (&c.enrollment, &abandoned),
        (&c.next, &deleted),
        (&deleted, &c.enrollment),
        (&c.released, &c.released),
    ] {
        assert!(next.validate_successor_of(previous).is_err());
    }
    // Builders refuse other phases.
    assert!(c.selected.select(c.next.marker().state, BOOT_A).is_err());
    assert!(c.released.release([1; 32], BOOT_A).is_err());
    assert!(c.enrollment.release([1; 32], BOOT_A).is_err());
    assert!(
        deleted
            .terminate(KagemushaWalletTerminalReasonV1::CustodyDeleted, BOOT_A)
            .is_err()
    );
    assert!(
        c.enrollment
            .terminate(KagemushaWalletTerminalReasonV1::CustodyDeleted, BOOT_A)
            .is_err()
    );
    assert!(
        c.released
            .terminate(KagemushaWalletTerminalReasonV1::Abandoned, BOOT_A)
            .is_err()
    );
    assert!(c.selected.release([0; 32], BOOT_A).is_err());
    // A Released marker must keep the selected head exactly.
    let other_head = KagemushaWalletMarkerRecordV1::new(
        f.slot,
        &KagemushaWalletMarkerV1 {
            generation: 2,
            ..*c.next.marker()
        },
        ANDROID,
        Some([1; 32]),
        BOOT_A,
    )
    .expect("record");
    assert!(other_head.validate_successor_of(&c.selected).is_err());
    // Another slot breaks the chain.
    let foreign = KagemushaWalletMarkerRecordV1::new(
        KagemushaWalletSlotIdV1([0xee; 32]),
        c.selected.marker(),
        ANDROID,
        None,
        BOOT_A,
    )
    .expect("record");
    assert_eq!(
        foreign.validate_successor_of(&c.enrollment),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "marker.slot"
        })
    );
}

#[test]
fn wallet_advance_v1_marker_classify_listing_strictly() {
    use crate::kagemusha_wallet_advance_v1::{
        KagemushaWalletEntryKindV1 as K, KagemushaWalletListedEntryV1 as E,
    };
    let entry = |name: &str, kind| E {
        name: name.to_owned(),
        kind,
    };
    let listing = kagemusha_wallet_classify_markers_v1(&[
        entry(kagemusha_wallet_marker_name_v1(3).as_str(), K::File),
        entry(".tmp-000000000000000000000000000000aa", K::File),
        entry(kagemusha_wallet_marker_name_v1(1).as_str(), K::File),
    ])
    .expect("listing");
    assert_eq!(listing.generations, [1, 3]);
    assert_eq!(listing.current(), Some(3));
    assert_eq!(listing.lower(), [1]);
    assert_eq!(listing.staging.len(), 1);
    assert_eq!(KagemushaWalletMarkerListingV1::default().current(), None);
    assert!(KagemushaWalletMarkerListingV1::default().lower().is_empty());
    for foreign in [
        entry("m-00000000000000000000000000000001.mk.bak", K::File),
        entry("M-00000000000000000000000000000001.mk", K::File),
        entry(kagemusha_wallet_marker_name_v1(1).as_str(), K::Directory),
        entry(kagemusha_wallet_marker_name_v1(1).as_str(), K::Other),
        entry(".tmp-000000000000000000000000000000aa", K::Directory),
    ] {
        assert_eq!(
            kagemusha_wallet_classify_markers_v1(&[foreign]),
            Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "markers" })
        );
    }
}

#[test]
fn wallet_advance_v1_marker_load_current_selects_highest_only() {
    let f = wallet_fixture(0x14);
    let c = chain(&f);
    let scheme = f.scheme_id();
    let (fs, store) = prepared_slot(&f);
    assert_eq!(
        kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme),
        Ok(None)
    );
    let other = KagemushaWalletSlotIdV1([0x99; 32]);
    assert_eq!(kagemusha_wallet_list_markers_v1(&store, &other), Ok(None));
    assert_eq!(
        kagemusha_wallet_load_current_marker_v1(&store, &other, &scheme),
        Ok(None)
    );
    durable(&store, c.enrollment.clone());
    durable(&store, c.selected.clone());
    // A lower generation is never read: garbage there cannot stall selection.
    assert_eq!(
        store.remove_file(&markers_dir(&f), &c.enrollment.file_name()),
        KagemushaWalletRemoveOutcomeV1::Removed
    );
    store.write_new(&markers_dir(&f), &c.enrollment.file_name(), b"unreadable");
    let current = kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme)
        .expect("load")
        .expect("marker");
    assert_eq!(current.record(), &c.selected);
    assert_eq!(current.lower(), [0]);
    fs.place_unsynced(
        &markers_dir(&f),
        ".tmp-000000000000000000000000000000bb",
        b"x",
    );
    // Staging files never take part in selection.
    assert_eq!(
        kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme)
            .expect("load")
            .expect("marker")
            .record(),
        &c.selected
    );
    assert_eq!(
        kagemusha_wallet_list_markers_v1(&store, &f.slot)
            .expect("list")
            .expect("markers")
            .staging
            .len(),
        1
    );
}

#[test]
fn wallet_advance_v1_marker_load_current_never_falls_back() {
    let f = wallet_fixture(0x15);
    let c = chain(&f);
    let scheme = f.scheme_id();
    let corrupt = Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData { object: "marker" });
    let (fs, store) = prepared_slot(&f);
    durable(&store, c.enrollment.clone());
    // A corrupt highest generation is unavailable custody data, never the lower marker.
    store.write_new(&markers_dir(&f), &c.selected.file_name(), b"corrupt");
    assert_eq!(
        kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme),
        corrupt
    );
    // Oversized.
    store.remove_file(&markers_dir(&f), &c.selected.file_name());
    store.write_new(
        &markers_dir(&f),
        &c.selected.file_name(),
        &vec![0; KAGEMUSHA_WALLET_MARKER_FILE_MAX_BYTES_V1 + 1],
    );
    assert_eq!(
        kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme),
        corrupt
    );
    // A valid marker under another generation's name.
    store.remove_file(&markers_dir(&f), &c.selected.file_name());
    store.write_new(
        &markers_dir(&f),
        &c.next.file_name(),
        c.selected.file_bytes(),
    );
    assert_eq!(
        kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme),
        corrupt
    );
    store.remove_file(&markers_dir(&f), &c.next.file_name());
    // Read and listing errors are unavailable, never absence.
    for step in 0..2 {
        fs.inject(fs.steps() + step, KagemushaWalletSimFaultV1::Error);
        assert!(matches!(
            kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme),
            Err(KagemushaWalletProviderErrorV1::Unavailable(_))
        ));
    }
    fs.inject(
        fs.steps() + 1,
        KagemushaWalletSimFaultV1::ErrorKind(io::ErrorKind::PermissionDenied),
    );
    assert!(matches!(
        kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    // A foreign entry stops selection.
    fs.place_unsynced(&markers_dir(&f), "notes.txt", b"x");
    assert_eq!(
        kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme),
        Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "markers" })
    );
}

#[test]
fn wallet_advance_v1_marker_fresh_inode_rule() {
    let f = wallet_fixture(0x16);
    let c = chain(&f);
    let this_boot = Ok(BOOT_A);
    let later_boot = Ok(BOOT_B);
    let unknown =
        Err(crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Platform(0));
    let terminal = c
        .released
        .terminate(KagemushaWalletTerminalReasonV1::CustodyDeleted, BOOT_A)
        .expect("terminal");
    for (record, lower, boot, expected) in [
        (&c.selected, false, &this_boot, true),
        (&c.enrollment, false, &this_boot, true),
        (&c.released, false, &this_boot, false),
        (&c.released, true, &this_boot, true),
        (&terminal, false, &this_boot, false),
        (&terminal, true, &this_boot, true),
        (&c.selected, true, &later_boot, false),
        (&c.released, true, &later_boot, false),
        (&c.released, true, &unknown, true),
        (&c.released, false, &unknown, false),
        (&c.selected, false, &unknown, true),
    ] {
        assert_eq!(
            kagemusha_wallet_marker_needs_fresh_inode_v1(record, boot, lower),
            expected,
            "{:?} lower {lower} boot {boot:?}",
            record.phase()
        );
    }
    let unstamped = KagemushaWalletMarkerRecordV1::new(
        f.slot,
        c.released.marker(),
        ANDROID,
        Some([0xc1; 32]),
        [0; 32],
    )
    .expect("record");
    assert!(kagemusha_wallet_marker_needs_fresh_inode_v1(
        &unstamped,
        &later_boot,
        true
    ));
}

#[test]
fn wallet_advance_v1_marker_publish_and_generation_taken() {
    let f = wallet_fixture(0x17);
    let c = chain(&f);
    let (fs, store) = prepared_slot(&f);
    durable(&store, c.enrollment.clone());
    let abandoned = c
        .enrollment
        .terminate(KagemushaWalletTerminalReasonV1::Abandoned, BOOT_A)
        .expect("abandon");
    let selected = durable(&store, c.selected.clone());
    assert_eq!(selected.record(), &c.selected);
    // Abandon competes with Bootstrap for generation 1 and loses without changing anything.
    assert_eq!(
        kagemusha_wallet_publish_marker_v1(&store, abandoned),
        Ok(KagemushaWalletMarkerPublicationV1::GenerationTaken)
    );
    assert_eq!(
        fs.visible_file(&markers_dir(&f), c.selected.file_name().as_str())
            .as_deref(),
        Some(c.selected.file_bytes())
    );
    fs.inject(fs.steps() + 4, KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        kagemusha_wallet_publish_marker_v1(&store, c.released.clone()),
        Err(KagemushaWalletProviderErrorV1::Uncertain(_))
    ));
    let (fs, store) = prepared_slot(&f);
    fs.set_capacity(Some(0));
    assert_eq!(
        kagemusha_wallet_publish_marker_v1(&store, c.enrollment.clone()),
        Err(KagemushaWalletProviderErrorV1::NoSpace)
    );
}

#[test]
fn wallet_advance_v1_marker_adopt_rewrites_or_syncs() {
    let f = wallet_fixture(0x18);
    let c = chain(&f);
    let scheme = f.scheme_id();
    let (fs, store) = prepared_slot(&f);
    durable(&store, c.enrollment.clone());
    durable(&store, c.selected.clone());
    let load = |store: &SimStoreV1| {
        kagemusha_wallet_load_current_marker_v1(store, &f.slot, &scheme)
            .expect("load")
            .expect("marker")
    };
    let dir = markers_dir(&f);
    let name = c.selected.file_name();
    // Selected in the current boot: rewritten to a fresh inode.
    let before = fs.inode_of(&dir, name.as_str());
    let adopted =
        kagemusha_wallet_adopt_marker_v1(&store, &load(&store), &Ok(BOOT_A)).expect("adopt");
    assert_eq!(adopted.record(), &c.selected);
    assert_ne!(fs.inode_of(&dir, name.as_str()), before);
    // From an earlier boot: synced in place.
    let before = fs.inode_of(&dir, name.as_str());
    kagemusha_wallet_adopt_marker_v1(&store, &load(&store), &Ok(BOOT_B)).expect("adopt");
    assert_eq!(fs.inode_of(&dir, name.as_str()), before);
    // A failing sync is unavailable; a failing rewrite is uncertain.
    let current = load(&store);
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        kagemusha_wallet_adopt_marker_v1(&store, &current, &Ok(BOOT_B)),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    let current = load(&store);
    fs.inject(fs.steps() + 4, KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        kagemusha_wallet_adopt_marker_v1(&store, &current, &Ok(BOOT_A)),
        Err(KagemushaWalletProviderErrorV1::Uncertain(_))
    ));
}

#[test]
fn wallet_advance_v1_marker_adopt_repairs_lost_directory_writeback() {
    let f = wallet_fixture(0x19);
    let c = chain(&f);
    let scheme = f.scheme_id();
    let (fs, store) = prepared_slot(&f);
    durable(&store, c.enrollment.clone());
    // The Selected marker's directory sync loses its writeback: the publication is uncertain.
    fs.inject(fs.steps() + 4, KagemushaWalletSimFaultV1::LostWriteback);
    assert!(matches!(
        kagemusha_wallet_publish_marker_v1(&store, c.selected.clone()),
        Err(KagemushaWalletProviderErrorV1::Uncertain(_))
    ));
    let current = kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme)
        .expect("load")
        .expect("marker");
    assert_eq!(current.record(), &c.selected);
    let adopted = kagemusha_wallet_adopt_marker_v1(&store, &current, &Ok(BOOT_A)).expect("adopt");
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    let after = kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme)
        .expect("load")
        .expect("marker");
    assert_eq!(
        after.record(),
        adopted.record(),
        "adopted marker survives power loss"
    );
}

#[test]
fn wallet_advance_v1_marker_selected_capability_only_for_selected() {
    let f = wallet_fixture(0x1a);
    let c = chain(&f);
    let (_fs, store) = prepared_slot(&f);
    assert!(
        durable(&store, c.enrollment.clone())
            .selected_capability()
            .is_none()
    );
    let selected = durable(&store, c.selected.clone());
    let capability = selected.selected_capability().expect("capability");
    let (_, operation_id, capsule_digest) = c.selected.head().expect("head");
    assert_eq!(capability.slot(), &f.slot);
    assert_eq!(capability.generation(), 1);
    assert_eq!(capability.payment_key(), &f.payment_key);
    assert_eq!(capability.operation_id(), &operation_id);
    assert_eq!(capability.capsule_digest(), &capsule_digest);
    assert!(
        durable(&store, c.released.clone())
            .selected_capability()
            .is_none()
    );
}

#[test]
fn wallet_advance_v1_marker_retire_by_name() {
    let f = wallet_fixture(0x1b);
    let c = chain(&f);
    let scheme = f.scheme_id();
    let (fs, store) = prepared_slot(&f);
    durable(&store, c.enrollment.clone());
    // Lower generations are retired without being read.
    store.remove_file(&markers_dir(&f), &c.enrollment.file_name());
    store.write_new(&markers_dir(&f), &c.enrollment.file_name(), b"unreadable");
    let selected = durable(&store, c.selected.clone());
    assert_eq!(
        kagemusha_wallet_retire_markers_v1(&store, &selected, &[1]),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "marker.retired_generation"
        })
    );
    fs.inject(fs.steps() + 1, KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        kagemusha_wallet_retire_markers_v1(&store, &selected, &[0]),
        Err(KagemushaWalletProviderErrorV1::Uncertain(_))
    ));
    fs.inject(
        fs.steps(),
        KagemushaWalletSimFaultV1::ErrorKind(io::ErrorKind::PermissionDenied),
    );
    assert!(matches!(
        kagemusha_wallet_retire_markers_v1(&store, &selected, &[0]),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    kagemusha_wallet_retire_markers_v1(&store, &selected, &[0]).expect("retire");
    kagemusha_wallet_retire_markers_v1(&store, &selected, &[]).expect("nothing to retire");
    fs.power_loss(KagemushaWalletSimPowerLossV1::DropUnsynced);
    let current = kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme)
        .expect("load")
        .expect("marker");
    assert_eq!(current.record(), &c.selected);
    assert!(current.lower().is_empty());
}

/// One step of the normal coverage sequence; errors are the injected faults.
fn coverage_step(
    store: &SimStoreV1,
    c: &ChainV1,
    step: usize,
) -> Result<(), KagemushaWalletProviderErrorV1> {
    let publish = |record: &KagemushaWalletMarkerRecordV1| {
        kagemusha_wallet_publish_marker_v1(store, record.clone()).map(|_| ())
    };
    let retire = |generation: u128| {
        let current = kagemusha_wallet_load_current_marker_v1(
            store,
            c.enrollment.slot(),
            &c.enrollment.marker().scheme_id,
        )?
        .ok_or(KagemushaWalletProviderErrorV1::Invalid { field: "missing" })?;
        let adopted = kagemusha_wallet_adopt_marker_v1(store, &current, &Ok(BOOT_A))?;
        kagemusha_wallet_retire_markers_v1(store, &adopted, &[generation])
    };
    match step {
        0 => publish(&c.enrollment),
        1 => publish(&c.selected),
        2 => retire(0),
        3 => publish(&c.released),
        _ => retire(1),
    }
}

#[test]
fn wallet_advance_v1_marker_coverage_under_crashes() {
    // {0} -> {0, 1:S} -> {1:S} -> {1:S, 2:R} -> {2:R}: after a fault at any step of any
    // transition and a power loss, exactly one valid current marker is selected: the one
    // before the transition or the one after it. Generation 0 is the only uncovered start.
    let f = wallet_fixture(0x1c);
    let c = chain(&f);
    let scheme = f.scheme_id();
    let after = [
        &c.enrollment,
        &c.selected,
        &c.selected,
        &c.released,
        &c.released,
    ];
    let mut cases = 0;
    for transition in 0..after.len() {
        let (base, store) = prepared_slot(&f);
        for done in 0..transition {
            coverage_step(&store, &c, done).expect("fault-free prefix");
        }
        let probe = base.fork();
        let start = probe.steps();
        coverage_step(
            &KagemushaWalletDurableStoreV1::new(probe.clone()),
            &c,
            transition,
        )
        .expect("fault-free transition");
        for step in 0..probe.steps() - start {
            for fault in [
                KagemushaWalletSimFaultV1::Error,
                KagemushaWalletSimFaultV1::CrashBefore,
                KagemushaWalletSimFaultV1::CrashAfter,
                KagemushaWalletSimFaultV1::LostWriteback,
            ] {
                for seed in 0..4_u64 {
                    let fs = base.fork();
                    fs.inject(fs.steps() + step, fault);
                    let store = KagemushaWalletDurableStoreV1::new(fs.clone());
                    let outcome = coverage_step(&store, &c, transition);
                    fs.power_loss(if seed == 0 {
                        KagemushaWalletSimPowerLossV1::DropUnsynced
                    } else {
                        KagemushaWalletSimPowerLossV1::Seeded(seed)
                    });
                    let current = kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme)
                        .expect("readable after power loss");
                    let label = format!(
                        "transition {transition} step {step} fault {fault:?} seed {seed} outcome {outcome:?}"
                    );
                    let Some(current) = current else {
                        assert_eq!(transition, 0, "uncovered: {label}");
                        continue;
                    };
                    if outcome.is_ok() {
                        assert_eq!(current.record(), after[transition], "{label}");
                    } else if transition > 0 {
                        assert!(
                            current.record() == after[transition - 1]
                                || current.record() == after[transition],
                            "{label}"
                        );
                    } else {
                        assert_eq!(current.record(), &c.enrollment, "{label}");
                    }
                    cases += 1;
                }
            }
        }
    }
    assert!(cases > 100);
}

#[test]
fn wallet_advance_v1_marker_require_current_detects_superseded() {
    let f = wallet_fixture(0x1d);
    let c = chain(&f);
    let scheme = f.scheme_id();
    let (fs, store) = prepared_slot(&f);
    let superseded = Err(KagemushaWalletProviderErrorV1::Invalid {
        field: "marker.superseded",
    });
    assert_eq!(
        kagemusha_wallet_require_current_marker_v1(
            &store,
            &f.slot,
            &scheme,
            c.enrollment.marker_file_digest()
        ),
        superseded,
        "no marker at all"
    );
    let enrollment = durable(&store, c.enrollment.clone());
    enrollment.require_current(&store).expect("current");
    let selected = durable(&store, c.selected.clone());
    let capability = selected.selected_capability().expect("capability");
    capability.require_current(&store).expect("current");
    assert_eq!(enrollment.require_current(&store), superseded);
    durable(&store, c.released.clone());
    assert_eq!(selected.require_current(&store), superseded);
    assert_eq!(capability.require_current(&store), superseded);
    fs.inject(fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        capability.require_current(&store),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
}

#[test]
fn wallet_advance_v1_marker_adopt_refuses_a_record_that_is_not_on_disk() {
    // Regression: adoption proves the exact bytes under the record's name on both paths, so a
    // forged Selected record never becomes durable and never yields a receipt capability.
    let f = wallet_fixture(0x1e);
    let c = chain(&f);
    let scheme = f.scheme_id();
    let (fs, store) = prepared_slot(&f);
    durable(&store, c.enrollment.clone());
    let selected = durable(&store, c.selected.clone());
    kagemusha_wallet_retire_markers_v1(&store, &selected, &[0]).expect("retire");
    let released = durable(&store, c.released.clone());
    kagemusha_wallet_retire_markers_v1(&store, &released, &[1]).expect("retire");
    // A Selected head forged at the Released file's generation, stamped by an earlier boot
    // (sync path) or by this boot (rewrite path).
    let forged_marker = KagemushaWalletMarkerV1 {
        generation: 2,
        ..*c.next.marker()
    };
    for (stamp, expected) in [
        (
            BOOT_B,
            KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Busy),
        ),
        (
            BOOT_A,
            KagemushaWalletProviderErrorV1::Invalid {
                field: "rewrite content",
            },
        ),
    ] {
        let forged =
            KagemushaWalletMarkerRecordV1::new(f.slot, &forged_marker, ANDROID, None, stamp)
                .expect("forged record");
        assert_eq!(forged.phase(), KagemushaWalletMarkerPhaseV1::Selected);
        let current = KagemushaWalletCurrentMarkerV1 {
            record: forged,
            lower: Vec::new(),
        };
        // The current boot is A: a B stamp takes the sync path, an A stamp the rewrite path.
        assert_eq!(
            kagemusha_wallet_adopt_marker_v1(&store, &current, &Ok(BOOT_A)),
            Err(expected),
            "stamp {stamp:?}"
        );
    }
    // The real current marker is untouched and still adopts.
    let current = kagemusha_wallet_load_current_marker_v1(&store, &f.slot, &scheme)
        .expect("load")
        .expect("marker");
    assert_eq!(current.record(), &c.released);
    let adopted = kagemusha_wallet_adopt_marker_v1(&store, &current, &Ok(BOOT_B)).expect("adopt");
    assert!(adopted.selected_capability().is_none());
    assert_eq!(
        fs.visible_names(&markers_dir(&f)),
        vec![c.released.file_name().as_str().to_owned()]
    );
    // A missing file is a concurrent change on the sync path, never adopted.
    store.remove_file(&markers_dir(&f), &c.released.file_name());
    assert_eq!(
        kagemusha_wallet_adopt_marker_v1(&store, &current, &Ok(BOOT_B)),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Busy
        ))
    );
}

#[test]
fn wallet_advance_v1_marker_anchor_kind_is_bound_to_the_slot() {
    let f = wallet_fixture(0x1f);
    let keychain = f.enrollment_record_with(BOOT_A, KagemushaWalletAnchorPolicyV1::Keychain);
    assert_eq!(keychain.anchor(), KagemushaWalletAnchorPolicyV1::Keychain);
    assert_eq!(f.enrollment_record(BOOT_A).anchor(), ANDROID);
    // The kind is covered by the file digest and survives the round trip.
    assert_ne!(
        keychain.marker_file_digest(),
        f.enrollment_record(BOOT_A).marker_file_digest()
    );
    assert_eq!(
        KagemushaWalletMarkerRecordV1::decode(keychain.file_bytes(), &f.slot, &f.scheme_id())
            .as_ref(),
        Ok(&keychain)
    );
    // Every successor inherits it.
    let head = bootstrap_capsule(&f).head_marker_state();
    let selected = keychain.select(head, BOOT_A).expect("select");
    let released = selected.release([0xc9; 32], BOOT_A).expect("release");
    let terminal = released
        .terminate(KagemushaWalletTerminalReasonV1::CustodyDeleted, BOOT_A)
        .expect("terminal");
    for record in [&selected, &released, &terminal] {
        assert_eq!(record.anchor(), KagemushaWalletAnchorPolicyV1::Keychain);
    }
    // A successor of another kind is refused.
    let unanchored =
        KagemushaWalletMarkerRecordV1::new(f.slot, selected.marker(), ANDROID, None, BOOT_A)
            .expect("record");
    assert_eq!(
        unanchored.validate_successor_of(&keychain),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "marker.anchor_kind"
        })
    );
    // An unknown kind never decodes.
    let mut file: KagemushaWalletMarkerFileV1 = norito::decode_canonical_with_limits(
        keychain.file_bytes(),
        norito::canonical_decode_limits(keychain.file_bytes().len()),
    )
    .expect("envelope");
    file.anchor_kind = 2;
    let unknown = norito::encode_canonical(&file).expect("encode");
    assert_eq!(
        KagemushaWalletMarkerRecordV1::decode(&unknown, &f.slot, &f.scheme_id()),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "marker_file.anchor_kind"
        })
    );
}
