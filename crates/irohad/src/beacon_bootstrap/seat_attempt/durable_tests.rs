//! Real durable generation files and inherited-stream owner drop/reload controls.

use super::tests::{prepare_restartable, prepare_with_sources, root, through_publication_encoding};
use super::*;
use std::os::unix::{ffi::OsStrExt as _, fs::PermissionsExt as _};

const HANDLE: &str = "software://iroha/consensus-threshold/retained-attempt";

#[test]
fn original_generation_head_reloads_only_after_every_original_file_boundary() {
    // Fresh claim, intent, private ciphertext, public output and complete head are
    // separate actual filesystem boundaries. Only the last has a restorable graph.
    for boundary in 0..=4 {
        let (_temporary, root) = root();
        let budget = AllocationBudget::new(16 * 1024 * 1024);
        let (mut original, _writers, inherited) = prepare_restartable(&root, &budget).unwrap();
        let expiry = original.deadline;
        original.step().unwrap();
        let directory = original.claim.directory().unwrap().path.clone();
        if boundary >= 1 {
            original.step().unwrap();
        }
        let mut expected_public = Vec::new();
        let mut expected_private = Vec::new();
        if boundary >= 2 {
            original.step().unwrap();
            original.step().unwrap();
            assert_eq!(original.phase, Phase::PublicationEncoded);
            expected_public = original
                .local
                .as_ref()
                .unwrap()
                .encoded_public_frame()
                .to_vec();
            original.seal_and_publish_checkpoint(1).unwrap();
            expected_private = fs::read(directory.join("private-checkpoint-1.norito")).unwrap();
        }
        if boundary >= 3 {
            original.publish_phase(1).unwrap();
        }
        if boundary == 4 {
            original.publish_checkpoint_head(1).unwrap();
        }
        let original_expiry = if boundary == 4 {
            Some(
                norito::decode_canonical::<durable::Intent>(
                    original.durable.intent_bytes(1).unwrap(),
                )
                .unwrap()
                .expiry,
            )
        } else {
            None
        };
        let identities = original.claim_and_fifo_identity().unwrap();
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
        let mut restored = prepare_with_sources(&root, &budget, inherited, HANDLE, 7).unwrap();
        let receiver = std::ptr::from_ref(&*restored);
        let admitted = budget.reserved_bytes();
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - admitted)
            .unwrap();
        if boundary < 4 {
            assert!(matches!(
                restored.step(),
                Err(AttemptError::Claim(ClaimError::AlreadyClaimed(_)))
            ));
            assert!(restored.prepared.is_some());
            assert!(restored.local.is_none());
            assert_eq!(restored.phase, Phase::RestoringGeneration);
        } else {
            restored.step().unwrap();
            assert_eq!(restored.phase, Phase::PublicationDurable);
            assert!(restored.prepared.is_none());
            assert!(restored.deadline <= expiry);
            assert_eq!(
                Some(
                    norito::decode_canonical::<durable::Intent>(
                        restored.durable.intent_bytes(1).unwrap()
                    )
                    .unwrap()
                    .expiry
                ),
                original_expiry
            );
            assert_eq!(restored.claim_and_fifo_identity().unwrap(), identities);
            assert_eq!(std::ptr::from_ref(&*restored), receiver);
            assert!(restored.receiver.belongs_to(&budget));
            assert!(restored.durable.belongs_to(&budget));
            assert!(
                restored.original_publications[0]
                    .as_ref()
                    .unwrap()
                    .belongs_to(&budget)
            );
            assert!(
                restored.original_publications[1..]
                    .iter()
                    .all(Option::is_none)
            );
            assert_eq!(
                restored.local.as_ref().unwrap().encoded_public_frame(),
                expected_public
            );
            assert_eq!(restored.durable.private_source(), expected_private);
            let public_inode = fs::metadata(directory.join("publication.norito"))
                .unwrap()
                .ino();
            restored.publish_phase(1).unwrap();
            assert_eq!(
                fs::metadata(directory.join("publication.norito"))
                    .unwrap()
                    .ino(),
                public_inode
            );
            for name in [
                "producer-1-intent.norito",
                "private-checkpoint-1.norito",
                "phase-head-1.norito",
            ] {
                assert_eq!(
                    fs::metadata(directory.join(name)).unwrap().mode() & 0o7777,
                    0o600
                );
            }
            assert_eq!(
                fs::metadata(directory.join("publication.norito"))
                    .unwrap()
                    .mode()
                    & 0o7777,
                0o644
            );
            assert!(!directory.join("attempt-journal.json").exists());
        }
        if boundary == 4 {
            // Canonical publication extraction retires prepared row containers;
            // all original retained rows, sources and the blocker still live.
            assert!(budget.reserved_bytes() < budget.limit_bytes());
        } else {
            assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        }
        drop(restored);
        assert_eq!(budget.reserved_bytes(), blocker.remaining_bytes());
        drop(blocker);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn input_marker_or_later_intent_cannot_restore_generation_or_grant_a_new_interval() {
    for name in [
        "input-consumption.norito",
        "producer-2-intent.norito",
        "producer-3-intent.norito",
        "producer-extraction-intent.norito",
        "private-checkpoint-2.norito",
        "private-checkpoint-3.norito",
        "deliveries.norito",
        "acceptances.norito",
        "public-session.norito",
        "provider.json",
        GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1,
        ROTATION_PENDING_SHARE_NAME,
    ] {
        let (_temporary, root) = root();
        let budget = AllocationBudget::new(16 * 1024 * 1024);
        let (mut original, _writers, inherited) = prepare_restartable(&root, &budget).unwrap();
        through_publication_encoding(&mut original);
        original.step().unwrap();
        let directory = original.claim.directory().unwrap().path.clone();
        if name == "input-consumption.norito" {
            original.close_generation_restore_before_input().unwrap();
        } else {
            // Any interrupted later producer intent is enough to close this
            // deliberately bounded restoration path, even before it is decoded.
            fs::write(directory.join(name), b"interrupted later producer boundary").unwrap();
            fs::set_permissions(directory.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let files = fs::read_dir(&directory).unwrap().count();
        drop(original);
        let mut restored = prepare_with_sources(&root, &budget, inherited, HANDLE, 7).unwrap();
        assert!(matches!(restored.step(), Err(AttemptError::Binding)));
        assert!(restored.prepared.is_some());
        assert!(restored.local.is_none());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), files);
        drop(restored);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn generation_reload_rejects_foreign_provider_original_cutoff_fake_h1_result_and_replaced_input() {
    for mutation in 0..5 {
        let (_temporary, root) = root();
        let budget = AllocationBudget::new(16 * 1024 * 1024);
        let (mut original, _writers, inherited) = prepare_restartable(&root, &budget).unwrap();
        through_publication_encoding(&mut original);
        original.step().unwrap();
        let directory = original.claim.directory().unwrap().path.clone();
        let original_cipher = fs::read(directory.join("private-checkpoint-1.norito")).unwrap();
        if mutation == 2 || mutation == 3 {
            let path = directory.join("phase-head-1.norito");
            let mut head: durable::Head =
                norito::decode_canonical(&fs::read(&path).unwrap()).unwrap();
            if mutation == 2 {
                head.context.cutoff_height = head.context.acceptances_end_height;
            } else {
                // Signed H1 authorization carries no execution result. These
                // caller-created hashes never become a Core checked native source.
                head.context.source = iroha_crypto::threshold_bls::checkpoint::DkgCheckpointSourceV1::ExecutedNativeTip {
                    height: 1, block_hash: [0x41; 32], core_hash: [0x42; 32], result_hash: [0x43; 32],
                };
            }
            fs::write(path, norito::encode_canonical(&head).unwrap()).unwrap();
        }
        drop(original);
        let sources = if mutation == 4 {
            let (foreign_read, foreign_write) = rustix::pipe::pipe().unwrap();
            // Keep the foreign writer alive until validation finishes; an EOF
            // must not be confused with the exact source identity rejection.
            let _foreign_writer = File::from(foreign_write);
            let [old_public, old_finality] = inherited;
            drop(old_public);
            let sources = [File::from(foreign_read), old_finality];
            let mut restored = prepare_with_sources(&root, &budget, sources, HANDLE, 7).unwrap();
            assert!(matches!(restored.step(), Err(AttemptError::Binding)));
            assert!(restored.local.is_none());
            drop(restored);
            assert_eq!(
                fs::read(directory.join("private-checkpoint-1.norito")).unwrap(),
                original_cipher
            );
            assert_eq!(budget.reserved_bytes(), 0);
            continue;
        } else {
            inherited
        };
        let (handle, revision) = match mutation {
            0 => ("software://iroha/consensus-threshold/foreign-attempt", 7),
            1 => (HANDLE, 8),
            _ => (HANDLE, 7),
        };
        let mut restored = prepare_with_sources(&root, &budget, sources, handle, revision).unwrap();
        assert!(matches!(restored.step(), Err(AttemptError::Binding)));
        assert!(restored.local.is_none());
        assert!(restored.prepared.is_some());
        assert_eq!(
            fs::read(directory.join("private-checkpoint-1.norito")).unwrap(),
            original_cipher
        );
        drop(restored);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn private_checkpoint_refusal_retains_original_ciphertext_pointer_before_head_publication() {
    let (_temporary, root) = root();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let (mut attempt, _writers, _inherited) = prepare_restartable(&root, &budget).unwrap();
    through_publication_encoding(&mut attempt);
    let directory = attempt.claim.directory().unwrap().path.clone();
    let path = directory.join("private-checkpoint-1.norito");
    fs::write(&path, b"unrelated original destination").unwrap();
    let public_pointer = attempt
        .local
        .as_ref()
        .unwrap()
        .encoded_public_frame()
        .as_ptr();
    assert!(matches!(
        attempt.step(),
        Err(AttemptError::Export(seat_export::ExportError::Io(_)))
    ));
    assert_eq!(attempt.phase, Phase::PublicationEncoded);
    assert!(!directory.join("publication.norito").exists());
    assert!(!directory.join("phase-head-1.norito").exists());
    let context = attempt
        .context(
            1,
            Hash::new(attempt.local.as_ref().unwrap().encoded_public_frame()).into(),
            attempt.durable.intent_hash(1).unwrap(),
        )
        .unwrap();
    let private = {
        let attempt = &mut *attempt;
        attempt
            .local
            .as_mut()
            .unwrap()
            .seal_private_checkpoint(&context, &attempt.signer)
            .unwrap()
    };
    let private_pointer = private.as_ptr();
    let expected = private.to_vec();
    let retained = budget.reserved_bytes();
    fs::remove_file(&path).unwrap();
    attempt.step().unwrap();
    assert_eq!(attempt.phase, Phase::PublicationDurable);
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(
        attempt
            .local
            .as_ref()
            .unwrap()
            .encoded_public_frame()
            .as_ptr(),
        public_pointer
    );
    let private = {
        let attempt = &mut *attempt;
        attempt
            .local
            .as_mut()
            .unwrap()
            .seal_private_checkpoint(&context, &attempt.signer)
            .unwrap()
    };
    assert_eq!(private.as_ptr(), private_pointer);
    assert_eq!(private, expected);
    assert_eq!(fs::read(&path).unwrap(), expected);
    drop(attempt);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn fresh_claim_sync_boundary_resumes_original_claiming_phase_and_pinned_inode() {
    let (_temporary, root) = root();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let (mut attempt, _writers, _inherited) = prepare_restartable(&root, &budget).unwrap();
    // Stop at the genuine filesystem boundary before file/root fsync. No
    // synthetic successful fsync or retry source is supplied to protocol code.
    attempt.phase = Phase::Claiming;
    attempt.claim.stop_before_sync().unwrap();
    let directory = attempt.claim.read_directory().unwrap();
    let inode = directory.file.metadata().unwrap().ino();
    let pointer = directory.path.as_os_str().as_bytes().as_ptr();
    let retained = budget.reserved_bytes();
    attempt.step().unwrap();
    assert_eq!(attempt.phase, Phase::Claimed);
    let directory = attempt.claim.directory().unwrap();
    assert_eq!(directory.file.metadata().unwrap().ino(), inode);
    assert_eq!(directory.path.as_os_str().as_bytes().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), retained);
    assert!(attempt.prepared.is_some());
    assert!(attempt.local.is_none());
    assert!(!directory.path.join("producer-1-intent.norito").exists());
    drop(attempt);
    assert_eq!(budget.reserved_bytes(), 0);
}
