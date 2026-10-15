//! Archive phases: one reconcile per phase, a protected-storage probe after every access that
//! touches storage, the exact-bytes write memo, single-copy object reads and the phase's
//! authenticated objects.

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletAnchorPolicyV1 as Policy, KagemushaWalletSimFaultV1 as Fault,
    KagemushaWalletSimFsV1 as SimFs, KagemushaWalletSimStepV1 as Step,
    KagemushaWalletStorageCountersV1 as Counters,
    test_support::{DeviceV1, FakePlatformV1, bootstrapped_device},
};
use crate::kagemusha_wallet_state_v1::{
    AdvanceHandle, ArchiveKey, ArchiveStore, Custody, Error as StateError, ObjectStore,
    ProviderArchive,
};

type Handle = AdvanceHandle<SimFs, FakePlatformV1>;
type Archive = ProviderArchive<SimFs, FakePlatformV1>;

fn wallet(seed: u8) -> (DeviceV1, Slot, Handle, Archive) {
    let (device, f, slot, _) = bootstrapped_device(Policy::NotRequired, seed);
    let mut handle = AdvanceHandle::new(device.open(), slot);
    Custody::status(&mut handle).expect("verified slot");
    let archive = handle.archive(f.scheme_id(), f.wallet_id());
    (device, slot, handle, archive)
}

fn record_names(device: &DeviceV1, slot: &Slot) -> Vec<String> {
    device
        .fs
        .visible_names(&kagemusha_wallet_archive_dir_v1(slot))
        .into_iter()
        .filter(|name| name.starts_with("w-"))
        .collect()
}

// End the phase with a custody call, then open a fresh one with an unrelated absent read, so
// a measurement sees only its own archive access.
fn fresh_phase(handle: &mut Handle, archive: &mut Archive) {
    Custody::status(handle).expect("status");
    assert!(
        archive
            .get(ArchiveKey::Capsule([0x55; 32]), 8)
            .expect("phase entry")
            .is_none()
    );
}

fn provider_error(result: Result<impl std::fmt::Debug, StateError>) -> Error {
    match result {
        Err(StateError::Provider(error)) => error,
        other => panic!("expected a provider error, got {other:?}"),
    }
}

#[test]
fn archive_phase_reconciles_once_and_probes_after_each_storage_access() {
    let (_device, _slot, mut handle, mut archive) = wallet(0x91);
    let (_, status) = Counters::observe(|| Custody::status(&mut handle).expect("status"));
    let first = ArchiveKey::Capsule([1; 32]);
    let second = ArchiveKey::Capsule([2; 32]);
    let ((), opened) = Counters::observe(|| archive.put(first, b"first record").expect("put"));
    assert_eq!(
        (
            opened.reconciles,
            opened.write_new,
            opened.fsync_class_calls()
        ),
        (1, 2, 4)
    );
    assert_eq!(
        opened.storage_probes,
        status.storage_probes + 2,
        "the phase entry reconcile, then a probe after the absent read and after the access"
    );
    let ((), next) = Counters::observe(|| archive.put(second, b"second record").expect("put"));
    assert_eq!(
        (
            next.reconciles,
            next.write_new,
            next.fsync_class_calls(),
            next.storage_probes
        ),
        (0, 2, 4, 2),
        "within the phase a create-new put keeps both durability syncs and both probes"
    );
    let ((), memo) =
        Counters::observe(|| archive.put(second, b"second record").expect("exact repeat"));
    assert_eq!(
        (
            memo.archive_puts,
            memo.archive_put_memo_hits,
            memo.reads,
            memo.fsync_class_calls(),
            memo.storage_probes,
            memo.reconciles,
        ),
        (1, 1, 0, 0, 0, 0),
        "an exact re-put of durably published bytes is answered from the write memo"
    );
    let (conflict, refused) =
        Counters::observe(|| provider_error(archive.put(second, b"changed record")));
    assert_eq!(
        conflict,
        Error::Invalid {
            field: "archive.immutable_record"
        }
    );
    assert_eq!(
        (refused.reads, refused.fsync_class_calls()),
        (0, 0),
        "other bytes at a remembered key remain the immutable conflict"
    );
    // The conflict poisoned the slot: the next operation reconciles fully, which forgets the
    // slot's write memo, and the original bytes are then adopted again on fresh inodes.
    let (_, full) = Counters::observe(|| Custody::status(&mut handle).expect("full reconcile"));
    assert_eq!(full.full_reconciles, 1);
    let ((), adopted) = Counters::observe(|| archive.put(second, b"second record").expect("adopt"));
    assert_eq!(
        (
            adopted.full_reconciles,
            adopted.archive_put_memo_hits,
            adopted.write_new,
            adopted.rewrite_same,
            adopted.fsync_class_calls()
        ),
        (0, 0, 0, 2, 4)
    );
    let (read, get) = Counters::observe(|| archive.get(first, 64).expect("get"));
    assert_eq!(read.as_deref(), Some(b"first record".as_slice()));
    assert_eq!(
        (get.reads, get.storage_probes, get.reconciles),
        (2, 1, 0),
        "a named record reads and compares both copies, then probes"
    );
    let (absent, miss) = Counters::observe(|| {
        archive
            .get(ArchiveKey::Capsule([3; 32]), 64)
            .expect("absent")
    });
    assert!(absent.is_none());
    assert_eq!(
        (miss.reads, miss.storage_probes),
        (2, 1),
        "absence is answered only after a successful probe"
    );
    Custody::status(&mut handle).expect("custody call");
    let (_, after) = Counters::observe(|| archive.get(first, 64).expect("get"));
    assert_eq!(after.reconciles, 1, "every custody call ends the phase");
}

#[test]
fn archive_phase_never_reports_absence_or_publication_from_locked_storage() {
    let (device, slot, _handle, mut archive) = wallet(0x92);
    let key = ArchiveKey::Capsule([4; 32]);
    archive.put(key, b"record").expect("put");
    // The probe after an absent read answers locked: Unavailable, and the slot is poisoned.
    device
        .platform
        .with(|state| state.storage_lock_after = Some(0));
    assert!(matches!(
        provider_error(archive.get(ArchiveKey::Capsule([9; 32]), 64)),
        Error::Unavailable(Unavailable::Locked)
    ));
    device.platform.clear_faults();
    let (_, again) = Counters::observe(|| {
        archive
            .get(ArchiveKey::Capsule([9; 32]), 64)
            .expect("available")
    });
    assert_eq!(again.full_reconciles, 1, "an error ends the phase");
    // A create-new choice rests on an absent read only after a successful probe.
    let names = record_names(&device, &slot);
    device
        .platform
        .with(|state| state.storage_lock_after = Some(0));
    assert!(matches!(
        provider_error(archive.put(ArchiveKey::Capsule([10; 32]), b"new record")),
        Error::Unavailable(Unavailable::Locked)
    ));
    assert_eq!(
        record_names(&device, &slot),
        names,
        "nothing is published after the failed probe"
    );
    device.platform.clear_faults();
    archive
        .put(ArchiveKey::Capsule([10; 32]), b"new record")
        .expect("available again");
    assert_eq!(record_names(&device, &slot).len(), names.len() + 2);
}

#[test]
fn archive_write_memo_never_remembers_an_uncertain_put() {
    let (device, _slot, mut handle, mut archive) = wallet(0x93);
    fresh_phase(&mut handle, &mut archive);
    // Steps of one create-new put inside an open phase; the last is its final directory sync.
    let start = device.fs.steps();
    archive
        .put(ArchiveKey::Capsule([5; 32]), b"same sized record")
        .expect("put");
    let steps = device.fs.trace_since(start);
    assert_eq!(steps.last(), Some(&Step::SyncDir));
    let key = ArchiveKey::Capsule([6; 32]);
    device.fs.inject(
        device.fs.steps() + u64::try_from(steps.len() - 1).expect("steps"),
        Fault::LostWriteback,
    );
    assert!(matches!(
        provider_error(archive.put(key, b"same sized record")),
        Error::Uncertain(_)
    ));
    // The retry, after the full reconcile the poison requires, is not a memo hit: both visible
    // copies are adopted on fresh inodes.
    let (_, full) = Counters::observe(|| Custody::status(&mut handle).expect("full reconcile"));
    assert_eq!(full.full_reconciles, 1);
    let ((), retry) = Counters::observe(|| archive.put(key, b"same sized record").expect("retry"));
    assert_eq!(
        (
            retry.archive_put_memo_hits,
            retry.write_new,
            retry.rewrite_same,
            retry.fsync_class_calls()
        ),
        (0, 0, 2, 4)
    );
    let ((), memo) =
        Counters::observe(|| archive.put(key, b"same sized record").expect("remembered"));
    assert_eq!(
        (memo.archive_put_memo_hits, memo.fsync_class_calls()),
        (1, 0)
    );
}

#[test]
fn object_reads_accept_one_verified_copy_and_fail_closed() {
    let (device, slot, mut handle, mut archive) = wallet(0x94);
    let dir = kagemusha_wallet_archive_dir_v1(&slot);
    let before = record_names(&device, &slot);
    let digest = archive.write_object(b"index node", 64).expect("write");
    let names: Vec<String> = record_names(&device, &slot)
        .into_iter()
        .filter(|name| !before.contains(name))
        .collect();
    assert_eq!(names.len(), 2);
    // Written durably in this phase: read back from memory, with no storage access.
    let (bytes, kept) = Counters::observe(|| archive.read_object(&digest, 64).expect("kept"));
    assert_eq!(bytes, b"index node");
    assert_eq!(
        (
            kept.reads,
            kept.storage_probes,
            kept.archive_object_cache_hits
        ),
        (0, 0, 1)
    );
    // A new phase reads only the first copy that passes every check.
    fresh_phase(&mut handle, &mut archive);
    let (bytes, cold) = Counters::observe(|| archive.read_object(&digest, 64).expect("read"));
    assert_eq!(bytes, b"index node");
    assert_eq!(
        (
            cold.reads,
            cold.storage_probes,
            cold.archive_object_cache_hits
        ),
        (1, 1, 0)
    );
    let (_, warm) = Counters::observe(|| archive.read_object(&digest, 64).expect("read"));
    assert_eq!((warm.reads, warm.archive_object_cache_hits), (0, 1));
    // A larger bound than the caller's is never answered from memory.
    let (small, bounded) = Counters::observe(|| archive.read_object(&digest, 4));
    assert!(matches!(
        small,
        Err(StateError::WitnessLost("provider archive authentication"))
    ));
    assert_eq!((bounded.reads, bounded.archive_object_cache_hits), (1, 0));
    // A torn primary is skipped for the redundant copy.
    let replica = device.fs.visible_file(&dir, &names[1]).expect("replica");
    device.fs.place_unsynced(&dir, &names[0], b"torn");
    fresh_phase(&mut handle, &mut archive);
    let (bytes, fallback) =
        Counters::observe(|| archive.read_object(&digest, 64).expect("replica read"));
    assert_eq!(bytes, b"index node");
    assert_eq!(fallback.reads, 2);
    // A primary whose prefix verifies but that is another object's record fails closed: the
    // redundant copy is never consulted.
    let other_before = record_names(&device, &slot);
    archive.write_object(b"other node", 64).expect("other");
    let other = record_names(&device, &slot)
        .into_iter()
        .find(|name| !other_before.contains(name) && !name.ends_with(".r"))
        .expect("other primary");
    let foreign = device.fs.visible_file(&dir, &other).expect("other record");
    device.fs.place_unsynced(&dir, &names[0], &foreign);
    fresh_phase(&mut handle, &mut archive);
    let (result, closed) = Counters::observe(|| archive.read_object(&digest, 64));
    assert!(matches!(
        result,
        Err(StateError::WitnessLost("provider archive authentication"))
    ));
    assert_eq!(closed.reads, 1, "the redundant copy is not read");
    let (_, reentry) = Counters::observe(|| {
        archive
            .get(ArchiveKey::Capsule([0x55; 32]), 8)
            .expect("absent")
    });
    assert_eq!(reentry.reconciles, 1, "an archive error ends the phase");
    // Restore the primary; a removed object is forgotten by the phase and the write memo.
    device.fs.place_unsynced(&dir, &names[0], &replica);
    assert_eq!(
        archive.read_object(&digest, 64).expect("restored"),
        b"index node"
    );
    archive
        .remove(ArchiveKey::Object(digest))
        .expect("collect object");
    assert!(matches!(
        archive.read_object(&digest, 64),
        Err(StateError::WitnessLost("index object"))
    ));
    let (_, rewritten) = Counters::observe(|| {
        archive
            .write_object(b"index node", 64)
            .expect("write again")
    });
    assert_eq!(
        (rewritten.archive_put_memo_hits, rewritten.write_new),
        (0, 2),
        "a removed record is published again"
    );
}

#[test]
fn archive_write_memo_is_bounded_oldest_first_and_forgets_exactly() {
    let mut memo = ArchiveWritesV1::default();
    let slot = Slot([1; 32]);
    let other = Slot([2; 32]);
    let key = |index: usize| {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&u64::try_from(index).expect("index").to_le_bytes());
        key
    };
    let frame = |index: usize| [u8::try_from(index % 251).expect("byte"); 32];
    let limit = KAGEMUSHA_WALLET_ARCHIVE_WRITES_MAX_V1;
    for index in 0..limit + 10 {
        memo.insert(&slot, &key(index), frame(index));
    }
    assert_eq!(memo.len(), limit);
    assert_eq!(
        memo.get(&slot, &key(9)),
        None,
        "the oldest are forgotten first"
    );
    assert_eq!(memo.get(&slot, &key(10)), Some(frame(10)));
    assert_eq!(memo.get(&slot, &key(limit + 9)), Some(frame(limit + 9)));
    memo.forget(&slot, &key(limit + 9));
    assert_eq!(memo.get(&slot, &key(limit + 9)), None);
    memo.insert(&other, &key(1), [7; 32]);
    memo.forget_slot(&slot);
    assert_eq!(memo.len(), 1);
    assert_eq!(memo.get(&other, &key(1)), Some([7; 32]));
}

#[test]
fn archive_phase_objects_are_bounded() {
    let mut phase = ArchivePhaseV1 {
        slot: Slot([1; 32]),
        marker: Vec::new(),
        enrollment: None,
        objects: BTreeMap::new(),
        order: VecDeque::new(),
        bytes: 0,
    };
    let content = vec![7; KAGEMUSHA_WALLET_ARCHIVE_PHASE_OBJECT_MAX_V1];
    let count = KAGEMUSHA_WALLET_ARCHIVE_PHASE_OBJECT_BYTES_V1 / content.len();
    for index in 0..=count {
        phase
            .keep([[u8::try_from(index).expect("index"); 32]; 3], &content)
            .expect("retain bounded object");
    }
    assert!(phase.bytes <= KAGEMUSHA_WALLET_ARCHIVE_PHASE_OBJECT_BYTES_V1);
    assert_eq!(phase.objects.len(), count);
    assert!(!phase.objects.contains_key(&[[0; 32]; 3]));
    phase
        .keep(
            [[0xff; 32]; 3],
            &[0; KAGEMUSHA_WALLET_ARCHIVE_PHASE_OBJECT_MAX_V1 + 1],
        )
        .expect("oversized objects are ignored");
    assert!(
        !phase.objects.contains_key(&[[0xff; 32]; 3]),
        "oversized objects are never kept"
    );
    phase.forget(&[[1; 32]; 3]);
    assert_eq!(phase.objects.len(), count - 1);
}

#[test]
fn archive_cache_returns_separate_private_owners_across_phase_invalidation_and_removal() {
    let (_device, _slot, mut handle, mut archive) = wallet(0x95);
    let payload = b"private cache payload";
    let digest = archive.write_object(payload, 64).expect("durable payload");
    let (first, warm) = Counters::observe(|| {
        archive
            .get_object(digest, 64)
            .expect("cache hit")
            .expect("present")
    });
    let second = archive
        .get_object(digest, 64)
        .expect("second cache hit")
        .expect("present");
    assert_eq!(first.as_slice(), payload);
    assert_eq!(second.as_slice(), payload);
    assert_ne!(
        first.as_ptr(),
        second.as_ptr(),
        "each reader owns its clearing allocation"
    );
    assert_eq!((warm.reads, warm.archive_object_cache_hits), (0, 1));
    assert_eq!(
        format!("{first:?}"),
        "PrivateArchiveBytes(PrivateWitnessBytes { private: [REDACTED] })"
    );

    // A custody call drops the phase's owners; caller-owned copies remain independent.
    fresh_phase(&mut handle, &mut archive);
    let (cold, counts) = Counters::observe(|| {
        archive
            .get_object(digest, 64)
            .expect("new phase read")
            .expect("present")
    });
    assert_eq!(cold.as_slice(), payload);
    assert_ne!(cold.as_ptr(), first.as_ptr());
    assert_eq!((counts.reads, counts.archive_object_cache_hits), (1, 0));
    assert_eq!(first.as_slice(), payload);
    drop(cold);

    // Collection drops only the retained phase owner and forgets its write memo.
    archive.remove(ArchiveKey::Object(digest)).expect("collect");
    assert!(archive.get_object(digest, 64).expect("absent").is_none());
    assert_eq!(second.as_slice(), payload);
    drop(first);
    drop(second);
}
