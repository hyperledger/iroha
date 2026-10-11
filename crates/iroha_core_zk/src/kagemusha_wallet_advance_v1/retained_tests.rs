//! Retained-result tests: tombstones, lookups of older operations, the rollback scan, pruning
//! and capsule collection.

use iroha_data_model::kagemusha::KagemushaWalletCompletionRecordV1;

use super::*;
use crate::kagemusha_wallet_advance_v1::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletAdvanceOutcomeV1, KagemushaWalletAnchorPolicyV1, KagemushaWalletLookupV1,
    KagemushaWalletSimFaultV1, kagemusha_wallet_completion_name_v1,
    test_support::{
        DeviceV1, SimProviderV1, TestOwnerV1, WalletFixtureV1, advance_request,
        bootstrapped_device, next_capsule, released,
    },
};

/// A device with two released heads: Bootstrap (selected generation 1) and one `ArchiveSent`
/// (selected generation 3).
fn two_heads(
    seed: u8,
) -> (
    DeviceV1,
    WalletFixtureV1,
    KagemushaWalletSlotIdV1,
    [[u8; 32]; 2],
) {
    let (device, f, slot, bootstrap) =
        bootstrapped_device(KagemushaWalletAnchorPolicyV1::NotRequired, seed);
    let mut provider = device.open();
    let current = provider.status(&slot).expect("status");
    let next = next_capsule(&f, &bootstrap);
    released(
        provider
            .advance(
                &slot,
                &TestOwnerV1,
                &advance_request(current.marker().expect("marker"), &next),
            )
            .expect("advance"),
    );
    (device, f, slot, [bootstrap.operation_id, next.operation_id])
}

fn tombstone() -> KagemushaWalletTombstoneV1 {
    KagemushaWalletTombstoneV1 {
        version: KAGEMUSHA_WALLET_TOMBSTONE_VERSION_V1,
        operation_id: [1; 32],
        kind: 5,
        selected_generation: 3,
        capsule_digest: [2; 32],
        completion_digest: [3; 32],
    }
}

#[test]
fn wallet_advance_v1_retained_tombstone_codec_and_status() {
    let value = tombstone();
    let bytes = value.encode().expect("encode");
    assert_eq!(KagemushaWalletTombstoneV1::decode(&bytes), Ok(value));
    assert_eq!(
        value.status(),
        KagemushaWalletRetainedStatusV1::Archived {
            capsule_digest: [2; 32],
            completion_digest: [3; 32]
        }
    );
    for invalid in [
        KagemushaWalletTombstoneV1 {
            version: 2,
            ..value
        },
        KagemushaWalletTombstoneV1 {
            operation_id: [0; 32],
            ..value
        },
        KagemushaWalletTombstoneV1 {
            capsule_digest: [0; 32],
            ..value
        },
        KagemushaWalletTombstoneV1 {
            completion_digest: [0; 32],
            ..value
        },
    ] {
        assert_eq!(
            invalid.encode(),
            Err(KagemushaWalletProviderErrorV1::Invalid { field: "tombstone" })
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(KagemushaWalletTombstoneV1::decode(&trailing).is_err());
}

#[test]
fn wallet_advance_v1_retained_older_completion_lookup_classifies() {
    let (device, f, slot, [bootstrap_op, current_op]) = two_heads(0x40);
    let store = device.open().store().clone();
    let binding = f.wallet_id();
    let OlderCompletionV1::Found(pair) = load_older_completion::<
        _,
        KagemushaWalletCompletionRecordV1,
    >(&store, &slot, &bootstrap_op, &binding)
    .expect("lookup") else {
        panic!("bootstrap record");
    };
    assert_eq!(pair.selected_generation(), 1);
    let retained = KagemushaWalletRetainedV1::from_pair(pair);
    assert_eq!(retained.operation_id, bootstrap_op);
    assert_eq!(
        retained.status(),
        KagemushaWalletRetainedStatusV1::Released {
            capsule_digest: retained.capsule_digest,
            completion_digest: retained.completion_digest
        }
    );
    assert!(matches!(
        load_older_completion::<_, KagemushaWalletCompletionRecordV1>(
            &store, &slot, &[9; 32], &binding
        ),
        Ok(OlderCompletionV1::Absent)
    ));
    // An unreadable copy is Unavailable, never absent.
    device
        .fs
        .inject(device.fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(matches!(
        load_older_completion::<_, KagemushaWalletCompletionRecordV1>(
            &store,
            &slot,
            &current_op,
            &binding
        ),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    // Both copies present but invalid: delivery-data loss, not absence.
    let dir = kagemusha_wallet_completion_dir_v1(&slot);
    for copy in KagemushaWalletCopyV1::BOTH {
        device.fs.place_unsynced(
            &dir,
            kagemusha_wallet_completion_name_v1(&bootstrap_op, copy).as_str(),
            b"corrupt",
        );
    }
    assert!(matches!(
        load_older_completion::<_, KagemushaWalletCompletionRecordV1>(
            &store,
            &slot,
            &bootstrap_op,
            &binding
        ),
        Ok(OlderCompletionV1::Invalid)
    ));
    let mut provider = device.open();
    assert_eq!(
        provider.lookup(&slot, &bootstrap_op),
        Ok(KagemushaWalletLookupV1::DeliveryDataLoss)
    );
}

#[test]
fn wallet_advance_v1_retained_highest_generation_scan() {
    let (device, _f, slot, [bootstrap_op, _]) = two_heads(0x41);
    let mut provider: SimProviderV1 = device.open();
    let store = provider.store().clone();
    assert_eq!(
        highest_retained_generation::<_, KagemushaWalletCompletionRecordV1>(&store, &slot),
        Ok(Some(3))
    );
    provider
        .prune_completion(&slot, &bootstrap_op, 1)
        .expect("prune");
    assert_eq!(
        kagemusha_wallet_list_tombstones_v1(&store, &slot),
        Ok(vec![bootstrap_op])
    );
    assert_eq!(
        highest_retained_generation::<_, KagemushaWalletCompletionRecordV1>(&store, &slot),
        Ok(Some(3))
    );
    // Undecodable copies prove nothing; foreign entries fail the listing.
    device.fs.place_unsynced(
        &kagemusha_wallet_ops_dir_v1(&slot),
        kagemusha_wallet_tombstone_name_v1(&[7; 32]).as_str(),
        b"garbage",
    );
    assert_eq!(
        highest_retained_generation::<_, KagemushaWalletCompletionRecordV1>(&store, &slot),
        Ok(Some(3))
    );
    assert_eq!(read_tombstone(&store, &slot, &[7; 32]), Ok(Some(None)));
    assert_eq!(read_tombstone(&store, &slot, &[8; 32]), Ok(None));
    device
        .fs
        .place_unsynced(&kagemusha_wallet_ops_dir_v1(&slot), "foreign", b"x");
    assert_eq!(
        kagemusha_wallet_list_tombstones_v1(&store, &slot),
        Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "ops" })
    );
}

#[test]
fn wallet_advance_v1_retained_prune_writes_tombstone_first() {
    let (device, f, slot, [bootstrap_op, current_op]) = two_heads(0x42);
    let mut provider = device.open();
    let before = provider.lookup(&slot, &bootstrap_op).expect("lookup");
    let KagemushaWalletLookupV1::Retained(retained) = before else {
        panic!("retained bootstrap result");
    };
    assert_eq!(
        provider.prune_completion(&slot, &current_op, 5),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "prune.current_head"
        })
    );
    assert_eq!(
        provider.prune_completion(&slot, &[9; 32], 5),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "prune.unknown_operation"
        })
    );
    let tombstone = provider
        .prune_completion(&slot, &bootstrap_op, 1)
        .expect("prune");
    assert_eq!(tombstone.selected_generation, 1);
    assert_eq!(tombstone.completion_digest, retained.completion_digest);
    assert_eq!(tombstone.capsule_digest, retained.capsule_digest);
    assert_eq!(
        provider.prune_completion(&slot, &bootstrap_op, 1),
        Ok(tombstone),
        "a completed prune is idempotent"
    );
    assert!(
        device
            .fs
            .visible_names(&kagemusha_wallet_completion_dir_v1(&slot))
            .iter()
            .all(|name| !name.starts_with(&super::super::layout::lower_hex(&bootstrap_op)))
    );
    assert_eq!(
        provider.lookup(&slot, &bootstrap_op),
        Ok(KagemushaWalletLookupV1::Archived(Box::new(tombstone)))
    );
    // Retrying the archived operation returns the archive, and changed inputs conflict.
    let bootstrap = super::super::test_support::bootstrap_capsule(&f);
    let enrollment = f.enrollment_record(super::super::test_support::BOOT_A);
    let request = advance_request(&enrollment, &bootstrap);
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &request),
        Ok(KagemushaWalletAdvanceOutcomeV1::Archived(Box::new(
            tombstone
        )))
    );
    let mut changed = request;
    changed.capsule = super::super::test_support::bootstrap_capsule_variant(&f, 1);
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &changed),
        Err(KagemushaWalletProviderErrorV1::OperationIdConflict {
            retained: tombstone.status()
        })
    );
    // A tombstone left by an interrupted prune is adopted; a different one is refused.
    assert_eq!(provider.write_tombstone(&slot, &tombstone), Ok(()));
    assert_eq!(
        provider.write_tombstone(
            &slot,
            &KagemushaWalletTombstoneV1 {
                kind: 9,
                ..tombstone
            }
        ),
        Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
            object: "tombstone"
        })
    );
}

#[test]
fn wallet_advance_v1_retained_collect_capsules_keeps_the_current_head() {
    let (device, _f, slot, _) = two_heads(0x43);
    let mut provider = device.open();
    let dir = kagemusha_wallet_capsules_dir_v1(&slot);
    assert_eq!(device.fs.visible_names(&dir).len(), 4);
    assert_eq!(
        provider.collect_capsules(&slot, 3),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "collect.current_capsule"
        })
    );
    assert_eq!(provider.collect_capsules(&slot, 1), Ok(2));
    assert_eq!(provider.collect_capsules(&slot, 2), Ok(0));
    let remaining = device.fs.visible_names(&dir);
    assert_eq!(remaining.len(), 2);
    assert!(remaining.iter().all(|name| {
        kagemusha_wallet_parse_capsule_name_v1(name)
            .is_some_and(|parsed| parsed.selected_generation == 3)
    }));
    provider.status(&slot).expect("the current head is intact");
}

#[test]
fn wallet_advance_v1_exact_capsule_collection_keeps_head_and_is_idempotent() {
    let (device, _f, slot, operations) = two_heads(0x74);
    let mut provider = device.open();
    let KagemushaWalletLookupV1::Retained(old) = provider.lookup(&slot, &operations[0]).unwrap()
    else {
        panic!("old completion")
    };
    let head = provider.status(&slot).unwrap();
    let generation = head.marker().unwrap().selected_generation().unwrap();
    assert!(
        provider
            .collect_capsule(&slot, generation, &old.capsule_digest)
            .is_err()
    );
    provider
        .collect_capsule(&slot, old.selected_generation, &old.capsule_digest)
        .unwrap();
    provider
        .collect_capsule(&slot, old.selected_generation, &old.capsule_digest)
        .unwrap();
    assert_eq!(
        device
            .fs
            .visible_names(&kagemusha_wallet_capsules_dir_v1(&slot))
            .len(),
        2
    );
    assert!(matches!(
        provider.lookup(&slot, &operations[0]).unwrap(),
        KagemushaWalletLookupV1::Retained(_)
    ));
    provider.status(&slot).unwrap();
    device
        .platform
        .with(|state| state.storage_lock_after = Some(1));
    assert!(matches!(
        provider.collect_capsule(&slot, old.selected_generation, &old.capsule_digest),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
}
