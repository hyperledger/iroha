//! Actual native Original recovery keeps the retained checkpoint and never reselects custody.

use super::*;
use crate::managed::native_operation::{
    attempts::metadata,
    test_support::{
        UnavailablePeers,
        native_fixture::{NativeFixture, policy, quote_instructions},
    },
};
use iroha_core::state::State;
use iroha_data_model::isi::{InstructionBox, Log};
use iroha_fs::PublishMode;
use std::{cell::Cell, time::Duration};

#[test]
fn exact_pending_original_recovers_after_newer_checkpoint_and_lost_published_files_refuse() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "metadata-original-recovery",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut owner = ManagedInitialReservePolicy::open(&prepared).unwrap();
    let policy = policy(&owner.authority);
    let mut native = NativeFixture::from_generated(&prepared, &owner.authority);
    let log = quote_instructions(
        &native,
        &owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "original checkpoint".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![log]), vec![true]);
    assert_eq!(native.chain.height(), 2);
    let directory = metadata::ensure_operation(&owner.authority.directory, "set").unwrap();
    let (original, admission) = owner
        .select_intent_using(&directory, &policy, deadline, |owner, policy, _| {
            let cut = native.observe(&owner.authority);
            let current = native
                .policy_proof(&owner.authority.config.account)
                .verify(
                    owner.authority.config.chain.as_str(),
                    owner.authority.config.network_id,
                    &owner.authority.config.account,
                    policy,
                    State::native_world_schema_hash_v1().unwrap(),
                    cut.verified_tip_ref().unwrap(),
                )
                .unwrap();
            Ok((cut, current))
        })
        .unwrap();
    assert!(admission.is_some());
    drop(admission);
    let original_bytes = directory
        .read("original.nrt", original.checkpoint.len() + 64 * 1024)
        .unwrap();
    let pristine = directory
        .read(metadata::FILE, metadata::MAX_IMAGE_BYTES)
        .unwrap();
    let digest = original.digest().unwrap();

    let log = quote_instructions(
        &native,
        &owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "newer checkpoint after interrupted publication".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![log]), vec![true]);
    assert_eq!(native.chain.height(), 3);
    let later_cut = native.observe(&owner.authority);
    assert_ne!(checkpoint_bytes(&later_cut).unwrap(), original.checkpoint);
    drop(ports);
    let mut peers = UnavailablePeers::start(&prepared);
    let observations = Cell::new(0usize);

    // A canonical pending record from another owner must not materialize Original or promote.
    let mut wrong = original.clone();
    wrong.selection.chain_id.push_str("-foreign");
    let wrong_bytes = encode(&wrong, original_bytes.len() + 1024).unwrap();
    std::fs::remove_file(directory.path().join("original.nrt")).unwrap();
    metadata::test_pending_original(&directory, &wrong_bytes, wrong_bytes.len()).unwrap();
    let pending = directory
        .read(metadata::FILE, metadata::MAX_IMAGE_BYTES)
        .unwrap();
    assert!(
        owner
            .select_intent_using(&directory, &policy, deadline, |_, _, _| {
                observations.set(observations.get() + 1);
                Err(invalid(
                    "pending recovery must not select a newer native Original",
                ))
            })
            .is_err()
    );
    assert!(!directory.path().join("original.nrt").exists());
    assert_eq!(
        directory
            .read(metadata::FILE, metadata::MAX_IMAGE_BYTES)
            .unwrap(),
        pending
    );
    assert_eq!(observations.get(), 0);
    directory
        .write_atomic("original.nrt", &original_bytes, PublishMode::CreateNew)
        .unwrap();
    directory
        .write_atomic(metadata::FILE, &pristine, PublishMode::Replace)
        .unwrap();

    for original_present in [false, true] {
        metadata::test_pending_original(&directory, &original_bytes, original_bytes.len()).unwrap();
        if !original_present {
            std::fs::remove_file(directory.path().join("original.nrt")).unwrap();
        }
        let (recovered, admission) = owner
            .select_intent_using(&directory, &policy, deadline, |_, _, _| {
                observations.set(observations.get() + 1);
                Err(invalid("retained pending Original must not be reselected"))
            })
            .unwrap();
        assert!(
            admission.is_none(),
            "recovery grants no fresh native proof receipt"
        );
        assert_eq!(recovered.digest().unwrap(), digest);
        assert_eq!(recovered.checkpoint, original.checkpoint);
        assert_eq!(
            directory
                .read("original.nrt", original_bytes.len())
                .unwrap(),
            original_bytes
        );
        assert_eq!(
            directory
                .read(metadata::FILE, metadata::MAX_IMAGE_BYTES)
                .unwrap(),
            pristine
        );
        assert_eq!(observations.get(), 0);
        assert!(!directory.path().join("attempts").exists());
        assert!(peers.requests.lock().unwrap().is_empty());
    }

    for name in [metadata::FILE, "original.nrt"] {
        let path = directory.path().join(name);
        let held = temporary.path().join(format!("held-{name}"));
        std::fs::rename(&path, &held).unwrap();
        assert!(
            owner
                .select_intent_using(&directory, &policy, deadline, |_, _, _| {
                    observations.set(observations.get() + 1);
                    Err(invalid(
                        "lost published custody must refuse before native selection",
                    ))
                })
                .is_err()
        );
        assert!(
            !path.exists(),
            "promoted custody cannot be republished after deletion"
        );
        assert_eq!(observations.get(), 0);
        assert!(!directory.path().join("attempts").exists());
        assert!(peers.requests.lock().unwrap().is_empty());
        std::fs::rename(&held, &path).unwrap();
        assert_eq!(
            directory
                .read("original.nrt", original_bytes.len())
                .unwrap(),
            original_bytes
        );
        assert_eq!(
            directory
                .read(metadata::FILE, metadata::MAX_IMAGE_BYTES)
                .unwrap(),
            pristine
        );
    }
    // The exact published directory itself remains live; losing both files cannot look new.
    let directory_identity = directory.identity().unwrap();
    std::fs::remove_file(directory.path().join(metadata::FILE)).unwrap();
    std::fs::remove_file(directory.path().join("original.nrt")).unwrap();
    assert!(
        owner
            .select_intent_using(&directory, &policy, deadline, |_, _, _| {
                observations.set(observations.get() + 1);
                Err(invalid("double deletion must not restart native selection"))
            })
            .is_err()
    );
    assert_eq!(directory.identity().unwrap(), directory_identity);
    assert!(directory.entries(0).unwrap().is_empty());
    assert!(metadata::ensure_operation(&owner.authority.directory, "set").is_err());
    assert_eq!(observations.get(), 0);
    assert!(peers.requests.lock().unwrap().is_empty());
    directory
        .write_atomic("original.nrt", &original_bytes, PublishMode::CreateNew)
        .unwrap();
    directory
        .write_atomic(metadata::FILE, &pristine, PublishMode::CreateNew)
        .unwrap();
    let (retried, admission) = owner
        .select_intent_using(&directory, &policy, deadline, |_, _, _| {
            observations.set(observations.get() + 1);
            Err(invalid("restored Original cannot be reselected"))
        })
        .unwrap();
    assert_eq!(retried.digest().unwrap(), digest);
    assert!(admission.is_none());
    assert_eq!(observations.get(), 0);
    assert_eq!(native.chain.height(), 3);
    peers.finish();
}
