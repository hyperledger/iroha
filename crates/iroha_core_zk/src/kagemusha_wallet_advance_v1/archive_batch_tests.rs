//! Group commit of the provider archive (ML W2): records staged inside an open call, read back
//! with the checks of a disk read, published at every barrier and authority entry with one
//! directory sync, conflicts found before any rename, uncertain drains, discards, bounds and the
//! archive staging residue of a full reconcile.

use iroha_data_model::kagemusha::{
    KagemushaDevicePublicKeyV1, KagemushaWalletLedgerControlActionV1,
    KagemushaWalletLedgerControlBodyV1, KagemushaWalletRecoveryCapsuleV1,
    KagemushaWalletSigningDomainV1,
};

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletAdvanceRequestV1, KagemushaWalletAnchorPolicyV1 as Policy,
    KagemushaWalletDestructiveConfirmationV1, KagemushaWalletLookupV1 as Lookup,
    KagemushaWalletSimFaultV1 as Fault, KagemushaWalletSimPowerLossV1 as PowerLoss,
    KagemushaWalletSimStepV1 as Step, KagemushaWalletStorageCountersV1 as Counters,
    layout::{
        KAGEMUSHA_WALLET_STAGING_PREFIX_V1, kagemusha_wallet_capsules_dir_v1,
        kagemusha_wallet_completion_dir_v1, kagemusha_wallet_is_staging_name_v1,
        kagemusha_wallet_markers_dir_v1, kagemusha_wallet_ops_dir_v1,
    },
    test_support::{
        DeviceV1, SimProviderV1, TestOwnerV1, advance_request, bootstrapped_device,
        enrolled_device, next_capsule, released,
    },
};

/// One archive record: its key and exact bytes.
pub(super) type RecordV1 = ([u8; 32], Vec<u8>);

/// `count` distinct records whose keys start at `[first; 32]`.
pub(super) fn records(first: u8, count: u8) -> Vec<RecordV1> {
    (first..first + count)
        .map(|index| {
            (
                [index; 32],
                format!("staged archive record {index:03}").into_bytes(),
            )
        })
        .collect()
}

/// The exact bytes of each copy of a record: its digest prefix, then its payload.
pub(super) fn framed(bytes: &[u8]) -> Vec<u8> {
    let mut framed = kagemusha_wallet_archive_object_digest_v1(bytes).to_vec();
    framed.extend_from_slice(bytes);
    framed
}

/// File names of both copies of record `key`.
pub(super) fn copies(key: &[u8; 32]) -> [String; 2] {
    record_names(key).map(|name| name.as_str().to_owned())
}

/// Stage every record in the open call of `slot`.
pub(super) fn stage(provider: &mut SimProviderV1, slot: &Slot, staged: &[RecordV1]) {
    for (key, bytes) in staged {
        provider
            .stage_archive_record(slot, key, bytes, None)
            .expect("stage");
    }
}

/// Visible bytes of both copies of record `key`.
pub(super) fn copy_states(device: &DeviceV1, slot: &Slot, key: &[u8; 32]) -> [Option<Vec<u8>>; 2] {
    let dir = kagemusha_wallet_archive_dir_v1(slot);
    copies(key).map(|name| device.fs.visible_file(&dir, &name))
}

/// Both copies of every record hold its exact framed bytes.
pub(super) fn assert_exact(device: &DeviceV1, slot: &Slot, staged: &[RecordV1], label: &str) {
    for (key, bytes) in staged {
        let expected = framed(bytes);
        for copy in copy_states(device, slot, key) {
            assert_eq!(
                copy.as_deref(),
                Some(expected.as_slice()),
                "{label}: record {:02x} copy",
                key[0]
            );
        }
    }
}

/// No copy of any record is visible.
pub(super) fn assert_absent(device: &DeviceV1, slot: &Slot, staged: &[RecordV1], label: &str) {
    for (key, _) in staged {
        assert_eq!(
            copy_states(device, slot, key),
            [None, None],
            "{label}: record {:02x}",
            key[0]
        );
    }
}

/// Every visible copy of every record holds its exact framed bytes (no torn or foreign name).
pub(super) fn assert_absent_or_exact(
    device: &DeviceV1,
    slot: &Slot,
    staged: &[RecordV1],
    label: &str,
) {
    for (key, bytes) in staged {
        let expected = framed(bytes);
        for copy in copy_states(device, slot, key) {
            assert!(
                copy.as_ref().is_none_or(|copy| *copy == expected),
                "{label}: record {:02x} copy torn or foreign",
                key[0]
            );
        }
    }
}

/// What survives a power loss now.
pub(super) fn durable_view(device: &DeviceV1) -> DeviceV1 {
    let view = device.fork();
    view.fs.power_loss(PowerLoss::DropUnsynced);
    view
}

/// No staging name remains in the archive directory of `slot`.
pub(super) fn assert_no_archive_residue(device: &DeviceV1, slot: &Slot, label: &str) {
    let names = device
        .fs
        .visible_names(&kagemusha_wallet_archive_dir_v1(slot));
    assert!(
        !names
            .iter()
            .any(|name| kagemusha_wallet_is_staging_name_v1(name)),
        "{label}: archive staging residue {names:?}"
    );
}

/// Index of the batch's directory sync: the first directory sync after the first create-new
/// rename of `trace` (every provider entry publishes its batch before any other rename).
fn batch_sync(trace: &[Step]) -> u64 {
    let rename = trace
        .iter()
        .position(|step| *step == Step::RenameNoReplace)
        .expect("batch renames");
    let sync = rename
        + trace[rename..]
            .iter()
            .position(|step| *step == Step::SyncDir)
            .expect("batch directory sync");
    u64::try_from(sync).expect("step")
}

#[test]
fn staged_records_read_back_with_disk_authentication_before_drain() {
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xb0);
    let mut provider = device.open();
    let staged = records(0x10, 2);
    let (key, bytes) = &staged[0];
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    assert_absent(&device, &slot, &staged, "staged only");
    let start = device.fs.steps();
    let (read, named) = Counters::observe(|| {
        provider.with_archive_phase(&slot, |archive| archive.read_record(key, bytes.len()))
    });
    assert_eq!(
        read.expect("staged read").as_deref(),
        Some(bytes.as_slice())
    );
    let (first, object) = Counters::observe(|| {
        provider.with_archive_phase(&slot, |archive| archive.read_record_first(key, bytes.len()))
    });
    assert_eq!(
        first.expect("staged first-copy read").as_deref(),
        Some(bytes.as_slice())
    );
    assert_eq!(
        device.fs.steps(),
        start,
        "a staged record is answered without a storage access"
    );
    for counts in [named, object] {
        assert_eq!(
            (
                counts.archive_gets,
                counts.archive_overlay_hits,
                counts.reads,
                counts.storage_probes,
                counts.reconciles
            ),
            (1, 1, 0, 0, 0)
        );
    }
    // The bound and its error are those of a disk read of the same record.
    let bound = Err(Error::UnavailableCustodyData {
        object: "archive record",
    });
    assert_eq!(
        provider.with_archive_phase(&slot, |archive| archive.read_record(key, bytes.len() - 1)),
        bound
    );
    assert_eq!(
        provider.with_archive_phase(&slot, |archive| {
            archive.read_record_first(key, bytes.len() - 1)
        }),
        bound
    );
    assert!(
        !provider.archive_batch_is_empty(&slot),
        "a read error never discards the batch"
    );
    provider.drain_archive(&slot).expect("drain");
    assert_exact(&device, &slot, &staged, "drained");
    provider.end_archive_phase();
    assert_eq!(
        provider.with_archive_phase(&slot, |archive| archive.read_record(key, bytes.len() - 1)),
        bound
    );
    assert_eq!(
        provider.with_archive_phase(&slot, |archive| {
            archive.read_record_first(key, bytes.len() - 1)
        }),
        bound
    );
    // A disk read inside an open phase reads and compares both copies.
    provider.status(&slot).expect("verified");
    provider
        .with_archive_phase(&slot, |_| Ok(()))
        .expect("phase entry");
    let (disk, counts) = Counters::observe(|| {
        provider.with_archive_phase(&slot, |archive| archive.read_record(key, bytes.len()))
    });
    assert_eq!(disk.expect("disk read").as_deref(), Some(bytes.as_slice()));
    assert_eq!(
        (counts.reads, counts.archive_overlay_hits, counts.reconciles),
        (2, 0, 0)
    );
}

#[test]
fn batch_survives_every_custody_call_and_phase_end() {
    let (device, _, slot, boot) = bootstrapped_device(Policy::NotRequired, 0xb1);
    let mut provider = device.open();
    let staged = records(0x20, 2);
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    provider.status(&slot).expect("status");
    provider
        .lookup(&slot, &boot.operation_id())
        .expect("lookup");
    provider.archive_checkpoint(&slot).expect("checkpoint read");
    provider.runtime_resources().expect("resources");
    provider.end_archive_phase();
    provider.poison(&slot);
    let (_, full) = Counters::observe(|| provider.status(&slot).expect("full reconcile"));
    assert_eq!(full.full_reconciles, 1);
    assert!(!provider.archive_batch_is_empty(&slot));
    assert_absent(
        &device,
        &slot,
        &staged,
        "no custody call, phase end, poison or reconcile publishes the batch",
    );
    for (key, bytes) in &staged {
        assert_eq!(
            provider
                .with_archive_phase(&slot, |archive| archive.read_record(key, bytes.len()))
                .expect("staged read")
                .as_deref(),
            Some(bytes.as_slice())
        );
    }
    provider.drain_archive(&slot).expect("barrier");
    assert!(provider.archive_batch_is_empty(&slot));
    assert_exact(
        &durable_view(&device),
        &slot,
        &staged,
        "the barrier publishes the batch durably",
    );
}

#[test]
fn staged_put_never_fills_phase_objects_and_the_drain_does() {
    let (device, f, slot, _) = bootstrapped_device(Policy::NotRequired, 0xb2);
    let mut provider = device.open();
    let key = [0x30; 32];
    let object = [f.scheme_id(), f.wallet_id(), key];
    let content: &[u8] = b"authenticated object content";
    provider.open_archive_call(&slot);
    provider
        .stage_archive_record(&slot, &key, b"object envelope", Some((object, content)))
        .expect("stage");
    assert_eq!(
        provider
            .archive_phase_object(&slot, &object, 64)
            .expect("phase"),
        None
    );
    // Content of a staged record is never kept, even when offered: it is not durable.
    provider
        .keep_archive_phase_object(&slot, object, content)
        .expect("keep");
    assert_eq!(
        provider
            .archive_phase_object(&slot, &object, 64)
            .expect("phase"),
        None
    );
    provider.drain_archive(&slot).expect("drain");
    assert_eq!(
        provider
            .archive_phase_object(&slot, &object, 64)
            .expect("phase")
            .as_deref(),
        Some(content),
        "a durable drain keeps the object for the phase"
    );
    assert_exact(
        &device,
        &slot,
        &[(key, b"object envelope".to_vec())],
        "drained",
    );
    // The same bytes staged again in a later phase are remembered as durable: their object is
    // kept for that phase as after a synchronous put.
    provider.end_archive_phase();
    let ((), remembered) = Counters::observe(|| {
        provider
            .stage_archive_record(&slot, &key, b"object envelope", Some((object, content)))
            .expect("remembered");
    });
    assert_eq!(
        (
            remembered.archive_put_memo_hits,
            remembered.fsync_class_calls()
        ),
        (1, 0)
    );
    assert_eq!(
        provider
            .archive_phase_object(&slot, &object, 64)
            .expect("phase")
            .as_deref(),
        Some(content),
        "a remembered put keeps its durable object for the phase"
    );
    assert!(provider.archive_batch_is_empty(&slot));
}

#[test]
fn conflicting_restage_fails_at_put_without_io() {
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xb3);
    let mut provider = device.open();
    let key = [0x40; 32];
    provider.open_archive_call(&slot);
    provider
        .stage_archive_record(&slot, &key, b"first bytes", None)
        .expect("stage");
    let start = device.fs.steps();
    let (again, coalesced) =
        Counters::observe(|| provider.stage_archive_record(&slot, &key, b"first bytes", None));
    again.expect("an exact restage coalesces");
    assert_eq!(
        (
            coalesced.archive_puts,
            coalesced.archive_put_batch_hits,
            coalesced.reads,
            coalesced.fsync_class_calls()
        ),
        (1, 1, 0, 0)
    );
    let (changed, refused) =
        Counters::observe(|| provider.stage_archive_record(&slot, &key, b"other bytes", None));
    assert_eq!(
        changed,
        Err(Error::Invalid {
            field: "archive.immutable_record"
        })
    );
    assert_eq!((refused.reads, refused.fsync_class_calls()), (0, 0));
    assert_eq!(
        device.fs.steps(),
        start,
        "a staged conflict touches no storage"
    );
    assert!(
        !provider.archive_batch_is_empty(&slot),
        "the conflict keeps the staged bytes"
    );
    // Published, the bytes are remembered: the same bytes are answered from memory and other
    // bytes are the remembered conflict, still without a storage access.
    provider.drain_archive(&slot).expect("drain");
    let start = device.fs.steps();
    let (remembered, hit) =
        Counters::observe(|| provider.stage_archive_record(&slot, &key, b"first bytes", None));
    remembered.expect("remembered");
    assert_eq!(
        (hit.archive_put_memo_hits, hit.archive_put_batch_hits),
        (1, 0)
    );
    assert_eq!(
        provider.stage_archive_record(&slot, &key, b"other bytes", None),
        Err(Error::Invalid {
            field: "archive.immutable_record"
        })
    );
    assert_eq!(device.fs.steps(), start);
    assert!(provider.archive_batch_is_empty(&slot));
}

/// One drain whose P0 finds the disk state `place` left at the second staged record.
fn drain_conflict(seed: u8, place: &dyn Fn(&DeviceV1, &Slot, &[u8; 32], &[u8]), expected: Error) {
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, seed);
    let mut provider = device.open();
    provider.status(&slot).expect("verified");
    let staged = records(0x50, 2);
    let (key, bytes) = &staged[1];
    place(&device, &slot, key, bytes.as_slice());
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    let start = device.fs.steps();
    let result = provider.drain_archive(&slot);
    assert_eq!(result, Err(expected));
    let trace = device.fs.trace_since(start);
    assert!(
        !trace.iter().any(|step| matches!(
            step,
            Step::CreateNew | Step::RenameNoReplace | Step::RenameReplace
        )),
        "{expected:?}: a conflict returns before any staging file or rename: {trace:?}"
    );
    assert!(
        !matches!(result, Err(Error::Unavailable(_) | Error::Uncertain(_))),
        "a conflict is terminal, never retryable unavailability"
    );
    assert!(!provider.cache.contains_key(&slot), "the slot is poisoned");
    assert!(
        provider.archive_batch_is_empty(&slot),
        "the batch is discarded"
    );
    assert_absent(
        &device,
        &slot,
        &staged[..1],
        "nothing of the batch is published",
    );
}

#[test]
fn drain_conflict_is_terminal_and_never_unavailable() {
    let dir = kagemusha_wallet_archive_dir_v1;
    let primary = |device: &DeviceV1, slot: &Slot, key: &[u8; 32], bytes: &[u8]| {
        device.fs.place_unsynced(&dir(slot), &copies(key)[0], bytes);
    };
    let replica = |device: &DeviceV1, slot: &Slot, key: &[u8; 32], bytes: &[u8]| {
        device.fs.place_unsynced(&dir(slot), &copies(key)[1], bytes);
    };
    // A valid copy of other bytes.
    drain_conflict(
        0xb4,
        &|device, slot, key, _| primary(device, slot, key, framed(b"other payload").as_slice()),
        Error::Invalid {
            field: "archive.immutable_record",
        },
    );
    // A torn replica beside an exact primary.
    drain_conflict(
        0xb5,
        &|device, slot, key, bytes| {
            primary(device, slot, key, framed(bytes).as_slice());
            replica(device, slot, key, b"torn".as_slice());
        },
        Error::UnavailableCustodyData {
            object: "archive immutable record",
        },
    );
    // An oversized replica beside an exact primary.
    drain_conflict(
        0xb6,
        &|device, slot, key, bytes| {
            primary(device, slot, key, framed(bytes).as_slice());
            let mut longer = framed(bytes);
            longer.extend_from_slice(b"tail");
            replica(device, slot, key, longer.as_slice());
        },
        Error::UnavailableCustodyData {
            object: "archive immutable record",
        },
    );
    // No valid copy, only a torn one.
    drain_conflict(
        0xb7,
        &|device, slot, key, _| primary(device, slot, key, b"torn".as_slice()),
        Error::UnavailableCustodyData {
            object: "archive record",
        },
    );
    // Two valid copies that differ.
    drain_conflict(
        0xb8,
        &|device, slot, key, _| {
            primary(device, slot, key, framed(b"one payload").as_slice());
            replica(device, slot, key, framed(b"two payload").as_slice());
        },
        Error::UnavailableCustodyData {
            object: "conflicting archive records",
        },
    );
    // A checkpoint copy holding other bytes.
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xb9);
    let mut provider = device.open();
    let generation = provider
        .status(&slot)
        .expect("status")
        .marker()
        .expect("marker")
        .generation();
    let manifest: &[u8] = b"conflicting checkpoint manifest";
    let [checkpoint, _] = names(&kagemusha_wallet_archive_checkpoint_digest_v1(manifest));
    device
        .fs
        .place_unsynced(&dir(&slot), checkpoint.as_str(), b"other manifest");
    let staged = records(0x58, 1);
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    let start = device.fs.steps();
    let result = provider.publish_archive_checkpoint(&slot, [0; 32], manifest);
    assert_eq!(
        result,
        Err(Error::UnavailableCustodyData {
            object: "archive checkpoint"
        })
    );
    assert!(
        !device
            .fs
            .trace_since(start)
            .iter()
            .any(|step| matches!(step, Step::CreateNew | Step::RenameNoReplace)),
        "a checkpoint conflict publishes nothing"
    );
    assert!(!provider.cache.contains_key(&slot));
    assert!(provider.archive_batch_is_empty(&slot));
    assert_absent(&device, &slot, &staged, "nothing published");
    assert_eq!(
        provider
            .status(&slot)
            .expect("status")
            .marker()
            .expect("marker")
            .generation(),
        generation,
        "the marker is unchanged"
    );
}

/// A released device with an older head, and the inputs of every provider authority entry.
struct EntriesV1 {
    device: DeviceV1,
    slot: Slot,
    request: KagemushaWalletAdvanceRequestV1<KagemushaWalletRecoveryCapsuleV1>,
    old_operation: [u8; 32],
    old_generation: u128,
    old_capsule: [u8; 32],
    source: [u8; 32],
    key: KagemushaDevicePublicKeyV1,
    activation: KagemushaWalletLedgerControlBodyV1,
    close_loads: KagemushaWalletLedgerControlBodyV1,
}

#[derive(Debug, Clone, Copy)]
enum EntryV1 {
    Advance,
    Checkpoint,
    CollectCapsule,
    CollectCapsules,
    Prune,
    SignActivation,
    SignCloseLoads,
    SignSetup,
}

const ENTRIES: [EntryV1; 8] = [
    EntryV1::Advance,
    EntryV1::Checkpoint,
    EntryV1::CollectCapsule,
    EntryV1::CollectCapsules,
    EntryV1::Prune,
    EntryV1::SignActivation,
    EntryV1::SignCloseLoads,
    EntryV1::SignSetup,
];

impl EntriesV1 {
    fn new(seed: u8) -> Self {
        let (device, f, slot, bootstrap) = bootstrapped_device(Policy::NotRequired, seed);
        let mut provider = device.open();
        let current = provider.status(&slot).expect("status");
        let head = next_capsule(&f, &bootstrap);
        released(
            provider
                .advance(
                    &slot,
                    &TestOwnerV1,
                    &advance_request(current.marker().expect("marker"), &head),
                )
                .expect("second head"),
        );
        let Lookup::Retained(old) = provider
            .lookup(&slot, &bootstrap.operation_id())
            .expect("lookup")
        else {
            panic!("retained Bootstrap result");
        };
        let marker = provider
            .status(&slot)
            .expect("status")
            .marker()
            .expect("marker")
            .clone();
        drop(provider);
        let mut package_digest = [0; 32];
        package_digest[0] = 7;
        let body = |action| KagemushaWalletLedgerControlBodyV1 {
            version: 1,
            scheme_id: marker.marker().scheme_id,
            asset_digest: marker.marker().asset_digest,
            wallet_id: marker.marker().wallet_id,
            action,
            nonce: [9; 32],
        };
        Self {
            request: advance_request(&marker, &next_capsule(&f, &head)),
            old_operation: bootstrap.operation_id(),
            old_generation: old.selected_generation,
            old_capsule: old.capsule_digest,
            source: marker.head().expect("head").2,
            key: *marker.payment_key(),
            activation: body(KagemushaWalletLedgerControlActionV1::Activate { package_digest }),
            close_loads: body(KagemushaWalletLedgerControlActionV1::CloseLoads {
                package_digest,
                next_load: 0,
            }),
            device,
            slot,
        }
    }

    fn run(&self, provider: &mut SimProviderV1, entry: EntryV1) -> Result<(), Error> {
        let slot = &self.slot;
        match entry {
            EntryV1::Advance => {
                provider
                    .advance(slot, &TestOwnerV1, &self.request)
                    .map(|outcome| {
                        released(outcome);
                    })
            }
            EntryV1::Checkpoint => provider
                .publish_archive_checkpoint(slot, [0; 32], b"entry manifest")
                .map(|_| ()),
            EntryV1::CollectCapsule => {
                provider.collect_capsule(slot, self.old_generation, &self.old_capsule)
            }
            EntryV1::CollectCapsules => provider
                .collect_capsules(slot, self.old_generation)
                .map(|_| ()),
            EntryV1::Prune => provider
                .prune_completion(slot, &self.old_operation, 1)
                .map(|_| ()),
            EntryV1::SignActivation => provider
                .sign_activation(slot, self.source, &self.key, &self.activation)
                .map(|_| ()),
            EntryV1::SignCloseLoads => provider
                .sign_close_loads(slot, self.source, &self.key, &self.close_loads)
                .map(|_| ()),
            EntryV1::SignSetup => provider
                .sign_setup(
                    slot,
                    self.source,
                    &self.key,
                    KagemushaWalletSigningDomainV1::Offer,
                    &vec![0; KagemushaWalletSigningDomainV1::Offer.transcript_bytes()],
                )
                .map(|_| ()),
        }
    }

    // A fresh provider over a fork with `staged` records in an open call.
    fn staged(&self, staged: &[RecordV1]) -> (DeviceV1, SimProviderV1) {
        let device = self.device.fork();
        let mut provider = device.open();
        provider.open_archive_call(&self.slot);
        stage(&mut provider, &self.slot, staged);
        (device, provider)
    }
}

// Everything an authority entry can change outside the archive: markers, capsules, completion
// records, tombstones and signatures.
fn effects(device: &DeviceV1, slot: &Slot) -> (Vec<Vec<String>>, usize) {
    let names = [
        kagemusha_wallet_markers_dir_v1(slot),
        kagemusha_wallet_capsules_dir_v1(slot),
        kagemusha_wallet_completion_dir_v1(slot),
        kagemusha_wallet_ops_dir_v1(slot),
    ]
    .iter()
    .map(|dir| device.fs.visible_names(dir))
    .collect();
    (names, device.platform.with(|state| state.sign_calls))
}

#[test]
fn every_authority_entry_drains_the_slot_batch_first() {
    let fixture = EntriesV1::new(0xc0);
    let slot = fixture.slot;
    let staged = records(0x60, 2);
    for entry in ENTRIES {
        let label = format!("{entry:?}");
        // Without a fault the entry publishes every staged record durably before its effect.
        let (device, mut provider) = fixture.staged(&staged);
        let start = device.fs.steps();
        let (result, counts) = Counters::observe(|| fixture.run(&mut provider, entry));
        result.unwrap_or_else(|error| panic!("{label}: {error:?}"));
        assert!(provider.archive_batch_is_empty(&slot), "{label}");
        assert_eq!(counts.batch_publishes, 1, "{label}");
        assert_exact(&durable_view(&device), &slot, &staged, &label);
        let sync = batch_sync(&device.fs.trace_since(start));
        // A failed batch directory sync: the entry reports it uncertain and has no effect.
        let (device, mut provider) = fixture.staged(&staged);
        let before = effects(&device, &slot);
        device.fs.inject(device.fs.steps() + sync, Fault::Error);
        let result = fixture.run(&mut provider, entry);
        device.fs.clear_faults();
        assert!(
            matches!(result, Err(Error::Uncertain(_))),
            "{label}: {result:?}"
        );
        assert_eq!(
            effects(&device, &slot),
            before,
            "{label}: no custody effect or signature follows an uncertain barrier"
        );
        assert!(!provider.cache.contains_key(&slot), "{label}: poisoned");
        assert!(provider.archive_batch_is_empty(&slot), "{label}: discarded");
        assert_absent_or_exact(&device, &slot, &staged, &label);
    }
}

#[test]
fn checkpoint_copies_share_the_batch_barrier_before_the_marker() {
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xc9);
    let mut provider = device.open();
    let staged = records(0x68, 2);
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    let manifest: &[u8] = b"shared barrier manifest";
    let start = device.fs.steps();
    let (digest, counts) =
        Counters::observe(|| provider.publish_archive_checkpoint(&slot, [0; 32], manifest));
    let digest = digest.expect("publish");
    let trace = device.fs.trace_since(start);
    // Four record copies and two checkpoint copies: staged and synced, renamed, one directory
    // sync; only then the marker.
    let first = usize::try_from(batch_sync(&trace)).expect("step") - 6;
    assert_eq!(
        &trace[first..first + 7],
        &[
            Step::RenameNoReplace,
            Step::RenameNoReplace,
            Step::RenameNoReplace,
            Step::RenameNoReplace,
            Step::RenameNoReplace,
            Step::RenameNoReplace,
            Step::SyncDir,
        ]
    );
    assert_eq!(
        trace[..first]
            .iter()
            .filter(|step| **step == Step::SyncFile)
            .count(),
        6
    );
    assert!(
        trace[first + 7..].contains(&Step::RenameNoReplace),
        "the marker is renamed after the shared directory sync"
    );
    assert_eq!(
        (
            counts.batch_publishes,
            counts.batch_names,
            counts.staged_syncs,
            counts.publish_syncs,
            counts.dir_syncs,
            counts.fsync_class_calls()
        ),
        (1, 6, 7, 2, 1, 10),
        "records and copies share one directory sync; the marker has its own"
    );
    let view = durable_view(&device);
    assert_exact(&view, &slot, &staged, "durable before the marker");
    let mut reopened = view.open();
    assert_eq!(
        reopened.archive_checkpoint(&slot).expect("checkpoint"),
        Some((digest, manifest.to_vec()))
    );
}

#[test]
fn remove_drains_forgets_and_reput_republishes() {
    let (device, f, slot, _) = bootstrapped_device(Policy::NotRequired, 0xc1);
    let mut provider = device.open();
    let staged = records(0x70, 2);
    let (key, _) = &staged[0];
    let object = [f.scheme_id(), f.wallet_id(), *key];
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    // A removal never runs while records are staged.
    assert_eq!(
        provider.with_archive_phase(&slot, |archive| archive.remove_record(key)),
        Err(Error::Invalid {
            field: "archive.pending_records"
        })
    );
    assert!(
        !provider.archive_batch_is_empty(&slot),
        "a refused removal keeps the batch"
    );
    assert_absent(&device, &slot, &staged, "nothing published or removed");
    let start = device.fs.steps();
    provider
        .remove_archive_record(&slot, key, &object)
        .expect("remove");
    let trace = device.fs.trace_since(start);
    let new_renames: Vec<usize> = trace
        .iter()
        .enumerate()
        .filter_map(|(index, step)| (*step == Step::RenameNoReplace).then_some(index))
        .collect();
    assert_eq!(
        new_renames.len(),
        staged.len() * 2 + 1,
        "batch copies plus Pending journal"
    );
    let last_batch_rename = new_renames[new_renames.len() - 2];
    assert_eq!(
        trace[last_batch_rename + 1..],
        [
            Step::SyncDir,
            Step::List,
            Step::CreateNew,
            Step::Write,
            Step::SyncFile,
            Step::RenameNoReplace,
            Step::SyncDir,
            Step::RenameEntry,
            Step::RenameEntry,
            Step::SyncDir,
            Step::Read,
            Step::CreateNew,
            Step::Write,
            Step::SyncFile,
            Step::RenameReplace,
            Step::SyncDir,
            Step::Unlink,
            Step::Unlink,
            Step::SyncDir
        ],
        "batch and Pending are durable before retirement; Complete is durable before cleanup"
    );
    assert_absent(&device, &slot, &staged[..1], "removed");
    assert_exact(&durable_view(&device), &slot, &staged[1..], "drained first");
    assert_eq!(
        provider.archive_writes.borrow().get(&slot, key),
        None,
        "the removed record is forgotten"
    );
    // A re-put of the removed record is staged and published again; the other is remembered.
    let ((), restaged) = Counters::observe(|| stage(&mut provider, &slot, &staged));
    assert_eq!(
        (restaged.archive_puts, restaged.archive_put_memo_hits),
        (2, 1)
    );
    let (drained, republished) = Counters::observe(|| provider.drain_archive(&slot));
    drained.expect("republish");
    assert_eq!((republished.batch_names, republished.write_new), (2, 2));
    assert_exact(&durable_view(&device), &slot, &staged, "republished");
}

#[test]
fn uncertain_drain_poisons_purges_and_retry_adopts_on_fresh_inodes() {
    let (base, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xc2);
    let staged = records(0x80, 2);
    let probe = base.fork();
    let mut provider = probe.open();
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    let start = probe.fs.steps();
    provider.drain_archive(&slot).expect("drain");
    let trace = probe.fs.trace_since(start);
    let last_rename = trace
        .iter()
        .rposition(|step| *step == Step::RenameNoReplace)
        .expect("renames");
    drop(provider);
    let device = base.fork();
    let mut provider = device.open();
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    device.fs.inject(
        device.fs.steps() + u64::try_from(last_rename).expect("step"),
        Fault::Error,
    );
    let result = provider.drain_archive(&slot);
    device.fs.clear_faults();
    assert!(matches!(result, Err(Error::Uncertain(_))), "{result:?}");
    assert!(!provider.cache.contains_key(&slot), "poisoned");
    assert!(provider.archive_batch_is_empty(&slot), "discarded");
    for (key, _) in &staged {
        assert_eq!(provider.archive_writes.borrow().get(&slot, key), None);
    }
    // Three copies were renamed (visible, not durable) before the last rename failed.
    let dir = kagemusha_wallet_archive_dir_v1(&slot);
    let visible: Vec<(String, u64)> = staged
        .iter()
        .flat_map(|(key, _)| copies(key))
        .filter_map(|name| device.fs.inode_of(&dir, &name).map(|inode| (name, inode)))
        .collect();
    assert_eq!(visible.len(), 3);
    assert_absent_or_exact(&device, &slot, &staged, "uncertain");
    // The call is failed: it stages nothing more and its successful close reports the failure.
    let (key, bytes) = &staged[0];
    assert_eq!(
        provider.stage_archive_record(&slot, key, bytes, None),
        Err(Error::Invalid {
            field: "archive.call_failed"
        })
    );
    assert_eq!(provider.close_archive_call(&slot, true), result);
    // The retry (a new call) republishes the identical bytes: every visible copy on a fresh
    // inode.
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    let (retried, counts) = Counters::observe(|| provider.drain_archive(&slot));
    retried.expect("retry");
    assert_eq!(
        (
            counts.batch_names,
            counts.rewrite_same,
            counts.write_new,
            counts.reconciles
        ),
        (4, 3, 1, 0)
    );
    for (name, inode) in &visible {
        assert_ne!(device.fs.inode_of(&dir, name), Some(*inode), "{name}");
    }
    assert_exact(
        &durable_view(&device),
        &slot,
        &staged,
        "the retry is durable",
    );
}

#[test]
fn terminal_and_deletion_discard_the_batch() {
    let staged = records(0x90, 2);
    // Custody deletion.
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xc3);
    let mut provider = device.open();
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    let status = provider.status(&slot).expect("status");
    let confirmation =
        KagemushaWalletDestructiveConfirmationV1::for_status(slot, &status).expect("confirm");
    provider
        .delete_custody(&slot, &confirmation)
        .expect("delete");
    assert!(
        !provider.archive_batches.contains_key(&slot),
        "the call is closed"
    );
    assert_absent(&durable_view(&device), &slot, &staged, "never published");
    assert_eq!(provider.close_archive_call(&slot, true), Ok(()));
    let (key, bytes) = &staged[0];
    assert_eq!(
        provider.stage_archive_record(&slot, key, bytes, None),
        Err(Error::Invalid {
            field: "archive.slot"
        }),
        "a terminal slot takes no archive record"
    );
    // Abandonment of an unused enrollment.
    let (device, _, slot) = enrolled_device(Policy::NotRequired, 0xc4);
    let mut provider = device.open();
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    provider.abandon_enrollment(&slot).expect("abandon");
    assert!(!provider.archive_batches.contains_key(&slot));
    assert_absent(&durable_view(&device), &slot, &staged, "never published");
    assert!(device.platform.with(|state| state.violations.is_empty()));
}

#[test]
fn archive_staging_residue_is_swept_at_open_and_after_a_failed_archive_access() {
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xc5);
    let dir = kagemusha_wallet_archive_dir_v1(&slot);
    let residue = |tag: &str| format!("{KAGEMUSHA_WALLET_STAGING_PREFIX_V1}{}", tag.repeat(16));
    // Residue of an earlier process: the first full reconcile of a new provider removes it.
    let earlier = residue("ab");
    assert!(kagemusha_wallet_is_staging_name_v1(&earlier));
    device
        .fs
        .place_unsynced(&dir, &earlier, b"copy of an interrupted batch");
    let mut provider = device.open();
    provider.status(&slot).expect("first reconcile");
    assert_no_archive_residue(&device, &slot, "provider open");
    let kept = records(0xa0, 1);
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &kept);
    provider.close_archive_call(&slot, true).expect("publish");
    // Later full reconciles of this provider skip the archive directory, which grows with the
    // archive...
    let later = residue("cd");
    device
        .fs
        .place_unsynced(&dir, &later, b"copy of a failed write");
    provider.status(&slot).expect("cached reconcile");
    provider.poison(&slot);
    let (_, skipped) = Counters::observe(|| provider.status(&slot).expect("full reconcile"));
    assert_eq!(skipped.full_reconciles, 1);
    assert!(device.fs.visible_names(&dir).contains(&later));
    // ...until an archive access of this provider fails on the slot.
    let (key, bytes) = &kept[0];
    let mut other = bytes.clone();
    *other.last_mut().expect("payload") ^= 1;
    assert_eq!(
        provider.stage_archive_record(&slot, key, &other, None),
        Err(Error::Invalid {
            field: "archive.immutable_record"
        })
    );
    let (_, swept) = Counters::observe(|| provider.status(&slot).expect("full reconcile"));
    assert_eq!(swept.full_reconciles, 1);
    assert_eq!(
        swept.listings,
        skipped.listings + 1,
        "one more listing: the archive directory"
    );
    assert_no_archive_residue(&device, &slot, "after a failed archive access");
    assert_exact(
        &durable_view(&device),
        &slot,
        &kept,
        "only staging names are removed",
    );
    // Swept again, the directory is skipped by the next full reconcile.
    provider.poison(&slot);
    let (_, again) = Counters::observe(|| provider.status(&slot).expect("full reconcile"));
    assert_eq!(again.listings, skipped.listings);
}

#[test]
fn unbracketed_put_is_the_held_synchronous_put() {
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xc6);
    let mut provider = device.open();
    provider.status(&slot).expect("verified");
    let staged = records(0xa8, 1);
    let (key, bytes) = &staged[0];
    let (put, counts) =
        Counters::observe(|| provider.stage_archive_record(&slot, key, bytes, None));
    put.expect("synchronous put");
    assert_eq!(
        (
            counts.archive_puts,
            counts.archive_sync_puts,
            counts.write_new,
            counts.batch_publishes,
            counts.fsync_class_calls()
        ),
        (1, 1, 2, 0, 4),
        "without an open call both copies are published one by one, as before"
    );
    let fields = counts.fields();
    for name in [
        "archive_put_batch_hits",
        "archive_overlay_hits",
        "archive_batch_abandoned",
    ] {
        assert!(fields.contains(&(name, 0)), "{name}");
    }
    assert!(fields.contains(&("archive_sync_puts", 1)));
    assert_exact(&durable_view(&device), &slot, &staged, "durable on return");
    let (again, counts) =
        Counters::observe(|| provider.stage_archive_record(&slot, key, bytes, None));
    again.expect("remembered");
    assert_eq!(
        (counts.archive_put_memo_hits, counts.fsync_class_calls()),
        (1, 0)
    );
    assert!(provider.archive_batches.is_empty(), "no call was opened");
}

#[test]
fn open_with_a_leftover_batch_purges_and_counts() {
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xc7);
    let mut provider = device.open();
    let staged = records(0xb0, 2);
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    let ((), counts) = Counters::observe(|| provider.open_archive_call(&slot));
    assert_eq!(counts.archive_batch_abandoned, 1);
    assert!(provider.archive_batch_is_empty(&slot));
    let start = device.fs.steps();
    provider.close_archive_call(&slot, true).expect("close");
    assert_eq!(
        device.fs.steps(),
        start,
        "an abandoned batch is never published"
    );
    assert_absent(&device, &slot, &staged, "abandoned");
    // An empty leftover call is replaced without being counted.
    provider.open_archive_call(&slot);
    let ((), counts) = Counters::observe(|| provider.open_archive_call(&slot));
    assert_eq!(counts.archive_batch_abandoned, 0);
}

#[test]
fn empty_drain_touches_no_storage() {
    let (base, f, slot, bootstrap) = bootstrapped_device(Policy::NotRequired, 0xc8);
    let device = base.fork();
    let mut provider = device.open();
    let current = provider.status(&slot).expect("verified");
    let request = advance_request(
        current.marker().expect("marker"),
        &next_capsule(&f, &bootstrap),
    );
    provider.open_archive_call(&slot);
    let start = device.fs.steps();
    let (drained, barrier) = Counters::observe(|| provider.drain_archive(&slot));
    drained.expect("empty drain");
    let (closed, close) = Counters::observe(|| provider.close_archive_call(&slot, true));
    closed.expect("empty close");
    assert_eq!(device.fs.steps(), start);
    for counts in [barrier, close] {
        assert_eq!(
            (
                counts.reads,
                counts.storage_probes,
                counts.fsync_class_calls(),
                counts.reconciles,
                counts.batch_publishes
            ),
            (0, 0, 0, 0, 0)
        );
    }
    drop(provider);
    // An authority entry with an open call and nothing staged takes exactly its old steps.
    let trace = |bracketed: bool| {
        let device = base.fork();
        let mut provider = device.open();
        provider.status(&slot).expect("verified");
        if bracketed {
            provider.open_archive_call(&slot);
        }
        let start = device.fs.steps();
        released(
            provider
                .advance(&slot, &TestOwnerV1, &request)
                .expect("advance"),
        );
        device.fs.trace_since(start)
    };
    assert_eq!(trace(true), trace(false));
}

#[test]
fn batch_bounds_publish_early() {
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xca);
    let dir = kagemusha_wallet_archive_dir_v1(&slot);
    let mut provider = device.open();
    provider.open_archive_call(&slot);
    for index in 0..KAGEMUSHA_WALLET_ARCHIVE_BATCH_RECORDS_MAX_V1 {
        let mut key = [0xee; 32];
        key[..8].copy_from_slice(&u64::try_from(index).expect("index").to_le_bytes());
        provider
            .stage_archive_record(&slot, &key, b"bounded record", None)
            .expect("stage");
        assert_eq!(
            provider.archive_batch_is_empty(&slot),
            index + 1 == KAGEMUSHA_WALLET_ARCHIVE_BATCH_RECORDS_MAX_V1,
            "record {index}: the batch is published once it holds the record bound"
        );
    }
    let published = device
        .fs
        .visible_names(&dir)
        .iter()
        .filter(|name| name.starts_with("w-"))
        .count();
    assert_eq!(published, 2 * KAGEMUSHA_WALLET_ARCHIVE_BATCH_RECORDS_MAX_V1);
    // A record that reaches the byte bound is published at once.
    let large = vec![7; KAGEMUSHA_WALLET_ARCHIVE_BATCH_BYTES_MAX_V1];
    provider
        .stage_archive_record(&slot, &[0xef; 32], &large, None)
        .expect("stage");
    assert!(provider.archive_batch_is_empty(&slot));
    assert_exact(
        &durable_view(&device),
        &slot,
        &[([0xef; 32], large)],
        "byte bound",
    );
}

#[test]
fn close_publishes_a_successful_call_and_discards_a_failed_one() {
    let (base, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xcb);
    let device = base.fork();
    let mut provider = device.open();
    let failed = records(0xc0, 1);
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &failed);
    assert_eq!(provider.close_archive_call(&slot, false), Ok(()));
    assert!(!provider.archive_batches.contains_key(&slot));
    assert!(
        provider.archive_phase.is_none(),
        "a failed call ends the archive phase"
    );
    assert_absent(&device, &slot, &failed, "discarded");
    let succeeded = records(0xc8, 2);
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &succeeded);
    assert_eq!(provider.close_archive_call(&slot, true), Ok(()));
    assert!(!provider.archive_batches.contains_key(&slot));
    assert_exact(
        &durable_view(&device),
        &slot,
        &succeeded,
        "published at close",
    );
    drop(provider);
    // A close whose publication fails reports it, closes the call and discards the batch.
    let pending = records(0xd0, 1);
    let probe = base.fork();
    let mut provider = probe.open();
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &pending);
    let start = probe.fs.steps();
    provider.close_archive_call(&slot, true).expect("close");
    let sync = batch_sync(&probe.fs.trace_since(start));
    drop(provider);
    let device = base.fork();
    let mut provider = device.open();
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &pending);
    device
        .fs
        .inject(device.fs.steps() + sync, Fault::LostWriteback);
    let closed = provider.close_archive_call(&slot, true);
    assert!(matches!(closed, Err(Error::Uncertain(_))), "{closed:?}");
    assert!(!provider.archive_batches.contains_key(&slot));
    assert!(!provider.cache.contains_key(&slot));
    assert_absent(
        &durable_view(&device),
        &slot,
        &pending,
        "a lost directory writeback is never durable",
    );
}

/// A provider over a fork of `base` whose open call staged `staged` (its archive phase current).
fn staged_call(base: &DeviceV1, slot: &Slot, staged: &[RecordV1]) -> (DeviceV1, SimProviderV1) {
    let device = base.fork();
    let mut provider = device.open();
    provider.status(slot).expect("verified");
    provider.open_archive_call(slot);
    stage(&mut provider, slot, staged);
    (device, provider)
}

#[test]
fn a_failed_drain_fails_the_open_call() {
    let (base, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xcc);
    let staged = records(0xe0, 2);
    let (probe, mut provider) = staged_call(&base, &slot, &staged);
    let start = probe.fs.steps();
    provider.drain_archive(&slot).expect("drain");
    let sync = batch_sync(&probe.fs.trace_since(start));
    drop(provider);
    let (device, mut provider) = staged_call(&base, &slot, &staged);
    let generation = |provider: &mut SimProviderV1| {
        provider
            .status(&slot)
            .expect("status")
            .marker()
            .expect("marker")
            .generation()
    };
    device.fs.inject(device.fs.steps() + sync, Fault::Error);
    let failed = provider.drain_archive(&slot);
    device.fs.clear_faults();
    assert!(matches!(failed, Err(Error::Uncertain(_))), "{failed:?}");
    // Records of the call were lost: nothing of it stages, passes a barrier or publishes any
    // more, and the refusals touch no storage.
    let refused = Err(Error::Invalid {
        field: "archive.call_failed",
    });
    let later = records(0xe8, 1);
    let (key, bytes) = &later[0];
    let start = device.fs.steps();
    assert_eq!(
        provider.stage_archive_record(&slot, key, bytes, None),
        refused
    );
    assert_eq!(provider.drain_archive(&slot), refused);
    assert_eq!(
        provider.publish_archive_record(&slot, key, bytes, None),
        refused
    );
    assert_eq!(provider.with_archive(&slot, |_| Ok(())), refused);
    assert_eq!(device.fs.steps(), start);
    let before = generation(&mut provider);
    assert_eq!(
        provider.publish_archive_checkpoint(&slot, [0; 32], b"failed call manifest"),
        Err(Error::Invalid {
            field: "archive.call_failed"
        }),
        "an authority entry of the call never follows its lost records"
    );
    assert_eq!(generation(&mut provider), before, "the marker is unchanged");
    assert!(provider.archive_batch_is_empty(&slot));
    // Closing it successfully reports the failure that lost its records, and closes it.
    assert_eq!(provider.close_archive_call(&slot, true), failed);
    assert!(!provider.archive_batches.contains_key(&slot));
    // A new call starts clean: the retry publishes every record.
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    provider.close_archive_call(&slot, true).expect("retry");
    assert_exact(&durable_view(&device), &slot, &staged, "retried");
    // A failed call that the embedder cancels is closed without an answer to replace.
    let (device, mut provider) = staged_call(&base, &slot, &staged);
    device.fs.inject(device.fs.steps() + sync, Fault::Error);
    assert!(provider.drain_archive(&slot).is_err());
    device.fs.clear_faults();
    assert_eq!(provider.close_archive_call(&slot, false), Ok(()));
    assert!(!provider.archive_batches.contains_key(&slot));
}

#[test]
fn a_failed_call_discards_its_staged_records_and_refuses_until_reopened() {
    // The refusal of the enrollment marker publication (`enrollment.rs`) fails the call this
    // way while records are staged.
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xdb);
    let mut provider = device.open();
    let staged = records(0xe4, 2);
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    let reason = Error::Invalid {
        field: "archive.pending_records",
    };
    provider.fail_archive_call(&slot, reason);
    assert!(
        provider.archive_batch_is_empty(&slot),
        "the staged records are discarded"
    );
    let refused = Err(Error::Invalid {
        field: "archive.call_failed",
    });
    let (key, bytes) = &staged[0];
    let start = device.fs.steps();
    assert_eq!(
        provider.stage_archive_record(&slot, key, bytes, None),
        refused
    );
    assert_eq!(provider.drain_archive(&slot), refused);
    assert_eq!(device.fs.steps(), start, "the refusals touch no storage");
    assert_eq!(provider.close_archive_call(&slot, true), Err(reason));
    assert!(!provider.archive_batches.contains_key(&slot));
    assert_absent(&durable_view(&device), &slot, &staged, "never published");
    // Without an open call nothing happens, and a new call starts clean.
    provider.fail_archive_call(&slot, reason);
    assert!(!provider.archive_batches.contains_key(&slot));
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    provider.close_archive_call(&slot, true).expect("publish");
    assert_exact(
        &durable_view(&device),
        &slot,
        &staged,
        "published by the new call",
    );
}

#[test]
fn drain_probes_protected_storage_before_create_and_after_publication() {
    let (base, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xce);
    let dir = kagemusha_wallet_archive_dir_v1(&slot);
    let staged = records(0xf0, 2);
    let storage_calls = |device: &DeviceV1| device.platform.with(|state| state.storage_calls);
    let locked = Err(Error::Unavailable(Unavailable::Locked));
    // Absent copies: one probe after the reads that choose create-new, one after publication.
    let (device, mut provider) = staged_call(&base, &slot, &staged);
    let before = storage_calls(&device);
    let (drained, counts) = Counters::observe(|| provider.drain_archive(&slot));
    drained.expect("drain");
    assert_eq!(storage_calls(&device) - before, 2);
    assert_eq!(
        (counts.storage_probes, counts.reconciles, counts.write_new),
        (2, 0, 4)
    );
    // Storage locked at the probe before any create-new: nothing is created or renamed.
    let (device, mut provider) = staged_call(&base, &slot, &staged);
    device
        .platform
        .with(|state| state.storage_lock_after = Some(0));
    let start = device.fs.steps();
    let result = provider.drain_archive(&slot);
    device.platform.clear_faults();
    assert_eq!(result, locked);
    let trace = device.fs.trace_since(start);
    assert!(
        !trace.is_empty() && trace.iter().all(|step| *step == Step::Read),
        "only the reads the create-new choice rests on: {trace:?}"
    );
    assert!(!provider.cache.contains_key(&slot), "poisoned");
    assert!(provider.archive_batch_is_empty(&slot), "discarded");
    assert_absent(&device, &slot, &staged, "nothing created");
    assert_eq!(provider.close_archive_call(&slot, true), locked);
    // Storage locked at the probe after the publication: the copies are durable, but the answer
    // is unavailable; the slot is poisoned and the retry adopts them on fresh inodes.
    let (device, mut provider) = staged_call(&base, &slot, &staged);
    device
        .platform
        .with(|state| state.storage_lock_after = Some(1));
    let start = device.fs.steps();
    let result = provider.drain_archive(&slot);
    device.platform.clear_faults();
    assert_eq!(result, locked);
    assert!(
        device.fs.trace_since(start).contains(&Step::SyncDir),
        "the probe follows the publication"
    );
    assert!(!provider.cache.contains_key(&slot), "poisoned");
    assert!(provider.archive_batch_is_empty(&slot), "discarded");
    assert_exact(
        &durable_view(&device),
        &slot,
        &staged,
        "durable before the closing probe",
    );
    assert_eq!(provider.close_archive_call(&slot, true), locked);
    let visible: Vec<(String, u64)> = staged
        .iter()
        .flat_map(|(key, _)| copies(key))
        .filter_map(|name| device.fs.inode_of(&dir, &name).map(|inode| (name, inode)))
        .collect();
    assert_eq!(visible.len(), 4);
    provider.open_archive_call(&slot);
    stage(&mut provider, &slot, &staged);
    let (retried, counts) = Counters::observe(|| provider.drain_archive(&slot));
    retried.expect("retry");
    assert_eq!(
        (
            counts.batch_names,
            counts.rewrite_same,
            counts.write_new,
            counts.storage_probes
        ),
        (4, 4, 0, 1),
        "nothing absent: no probe before create-new, one after the publication"
    );
    for (name, inode) in &visible {
        assert_ne!(device.fs.inode_of(&dir, name), Some(*inode), "{name}");
    }
}

#[test]
fn resumed_terminal_calls_discard_the_batch() {
    let staged = records(0xf8, 2);
    // A custody deletion whose terminal marker was renamed but its directory sync failed: the
    // same call resumes the deletion and discards the records it staged.
    let (base, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0xcf);
    let deletion = |device: &DeviceV1| {
        let mut provider = device.open();
        let status = provider.status(&slot).expect("status");
        let confirmation =
            KagemushaWalletDestructiveConfirmationV1::for_status(slot, &status).expect("confirm");
        provider.open_archive_call(&slot);
        stage(&mut provider, &slot, &staged);
        (provider, confirmation)
    };
    let probe = base.fork();
    let (mut provider, confirmation) = deletion(&probe);
    let start = probe.fs.steps();
    provider
        .delete_custody(&slot, &confirmation)
        .expect("delete");
    let sync = batch_sync(&probe.fs.trace_since(start));
    drop(provider);
    let device = base.fork();
    let (mut provider, confirmation) = deletion(&device);
    device.fs.inject(device.fs.steps() + sync, Fault::Error);
    let first = provider.delete_custody(&slot, &confirmation);
    device.fs.clear_faults();
    assert!(matches!(first, Err(Error::Uncertain(_))), "{first:?}");
    assert!(
        !provider.archive_batch_is_empty(&slot),
        "the call still holds its records"
    );
    let resumed = provider.delete_custody(&slot, &confirmation);
    assert!(
        matches!(resumed, Ok(KagemushaWalletSlotStatusV1::Terminal(_))),
        "{resumed:?}"
    );
    assert!(
        !provider.archive_batches.contains_key(&slot),
        "the resumed deletion discards the batch"
    );
    assert_eq!(provider.close_archive_call(&slot, true), Ok(()));
    assert_absent(&durable_view(&device), &slot, &staged, "never published");
    assert!(device.platform.with(|state| state.violations.is_empty()));
    // The same for an abandonment.
    let (base, _, slot) = enrolled_device(Policy::NotRequired, 0xda);
    let abandonment = |device: &DeviceV1| {
        let mut provider = device.open();
        provider.open_archive_call(&slot);
        stage(&mut provider, &slot, &staged);
        provider
    };
    let probe = base.fork();
    let mut provider = abandonment(&probe);
    let start = probe.fs.steps();
    provider.abandon_enrollment(&slot).expect("abandon");
    let sync = batch_sync(&probe.fs.trace_since(start));
    drop(provider);
    let device = base.fork();
    let mut provider = abandonment(&device);
    device.fs.inject(device.fs.steps() + sync, Fault::Error);
    let first = provider.abandon_enrollment(&slot);
    device.fs.clear_faults();
    assert!(matches!(first, Err(Error::Uncertain(_))), "{first:?}");
    assert!(!provider.archive_batch_is_empty(&slot));
    provider
        .abandon_enrollment(&slot)
        .expect("resumed abandonment");
    assert!(!provider.archive_batches.contains_key(&slot));
    assert_eq!(provider.close_archive_call(&slot, true), Ok(()));
    assert_absent(&durable_view(&device), &slot, &staged, "never published");
    assert!(device.platform.with(|state| state.violations.is_empty()));
}
