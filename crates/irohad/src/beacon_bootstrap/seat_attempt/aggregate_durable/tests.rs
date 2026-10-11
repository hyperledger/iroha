//! Actual original aggregate file barriers, immutable source refusals and context tampering.

use super::*;
use crate::beacon_bootstrap::seat_attempt::{
    aggregate_tests::{through_original_aggregate_head, through_original_extraction_intent},
    tests::{prepare_with_sources, root},
};
use std::os::{fd::AsRawFd as _, unix::fs::FileExt as _};

const HANDLE: &str = "software://iroha/consensus-threshold/retained-attempt";

fn prepare_loaded(original: &mut SeatDkgAttempt) {
    let directory = original.claim.read_directory().unwrap();
    let [head, intent] = original.durable.aggregate_prefix_record_bounds();
    let proof = original.finality.clock().limits().journal_bytes;
    original
        .aggregate_durable
        .prepare_restore(
            directory,
            [
                PreparedGlobalBeaconAggregateRestoreV1::aggregate_checkpoint_bytes().unwrap(),
                original.input_bounds[2],
                proof,
                head,
                PreparedGlobalBeaconAggregateRestoreV1::phase_checkpoint_bytes().unwrap(),
                intent,
                proof,
                intent,
                original.input_bounds[2],
            ],
        )
        .unwrap();
    original.aggregate_durable.load(directory).unwrap();
}

#[test]
fn actual_original_complete_aggregate_head_interrupted_before_sync_restores_through_every_held_file_and_directory_barrier()
 {
    let (_temporary, path) = root();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let (mut original, _writers, inherited, chain, _admitted_deadline) =
        through_original_extraction_intent(&path, &budget);
    let context = original
        .aggregate_context(original.aggregate_durable.intent_hash().unwrap())
        .unwrap();
    {
        let original = &mut *original;
        let encrypted = original
            .local
            .as_mut()
            .unwrap()
            .produce_aggregate_checkpoint(
                &context,
                original.sealed.as_ref().unwrap(),
                &original.signer,
            )
            .unwrap();
        let directory = original.claim.directory().unwrap();
        original
            .aggregate_durable
            .publish_checkpoint(directory, context.binding(), encrypted)
            .unwrap();
        original
            .aggregate_durable
            .prepare_head_record(context.binding())
            .unwrap();
        // The production encoder and exact publication helper write the complete
        // original bytes. Interruption precedes the actual head fsync, not encoding.
        seat_export::prepare_file_bytes(
            directory,
            HEAD,
            true,
            original.aggregate_durable.head.as_slice(),
            &mut original.aggregate_durable.head_progress,
        )
        .unwrap();
    }
    assert!(!original.aggregate_durable.head_progress.is_synced());
    assert!(!original.aggregate_durable.head_progress.complete());
    assert!(
        original.local.is_some(),
        "all original contribution owners still live"
    );
    let head_path = original.claim.directory().unwrap().path.join(HEAD);
    let head_bytes = fs::read(&head_path).unwrap();
    let inode = original
        .aggregate_durable
        .head_progress
        .retained_inode()
        .unwrap();
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
    let mut restored = prepare_with_sources(&path, &budget, inherited, HANDLE, 7).unwrap();
    restored.step().unwrap();
    assert_eq!(restored.phase, Phase::ShareExtracted);
    assert!(restored.aggregate_durable.restored_sources_synced());
    assert_eq!(
        restored.aggregate_durable.loaded[1]
            .descriptor
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        inode
    );
    assert!(
        restored
            .aggregate_durable
            .loaded
            .iter()
            .all(|source| source.synced)
    );
    assert_eq!(
        restored.finality.clock().tip().unwrap().result(),
        chain.committed(4).result()
    );
    assert_eq!(fs::read(&head_path).unwrap(), head_bytes);
    drop(restored);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn actual_aggregate_sync_completion_refusal_keeps_all_original_descriptors_and_same_ciphertext_before_retry()
 {
    let (_temporary, path) = root();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let (original, _writers, inherited, _chain, _admitted_deadline) =
        through_original_aggregate_head(&path, &budget);
    drop(original);
    let mut restored = prepare_with_sources(&path, &budget, inherited, HANDLE, 7).unwrap();
    prepare_loaded(&mut restored);
    let before = restored
        .aggregate_durable
        .loaded
        .each_ref()
        .map(|source| source.descriptor.as_ref().unwrap().as_raw_fd());
    let ciphertext = restored.aggregate_durable.source(0).unwrap().to_vec();
    let reserved = budget.reserved_bytes();
    let original_error = restored.aggregate_durable.loaded[0]
        .descriptor
        .as_ref()
        .unwrap()
        .write_at(b"x", 0)
        .unwrap_err();
    let mut refused = false;
    let error = {
        let restored = &mut *restored;
        restored
            .aggregate_durable
            .sync_restored_with(restored.claim.read_directory().unwrap(), |held| {
                held.sync_all()?;
                if !refused {
                    refused = true;
                    // Execute the original sync, then induce a genuine descriptor
                    // operation refusal before the completion marker can be set.
                    held.write_at(b"x", 0)?;
                }
                Ok(())
            })
            .unwrap_err()
    };
    let AttemptError::Export(seat_export::ExportError::Io(error)) = error else {
        panic!("exact original I/O cause")
    };
    assert_eq!(error.raw_os_error(), original_error.raw_os_error());
    assert!(!restored.aggregate_durable.restored_sources_synced());
    assert!(restored.claim.directory().is_none());
    assert!(restored.aggregate_owner.is_none());
    assert_eq!(
        restored
            .aggregate_durable
            .loaded
            .each_ref()
            .map(|source| source.descriptor.as_ref().unwrap().as_raw_fd()),
        before
    );
    assert_eq!(restored.aggregate_durable.source(0).unwrap(), ciphertext);
    assert_eq!(budget.reserved_bytes(), reserved);
    {
        let restored = &mut *restored;
        restored
            .aggregate_durable
            .sync_restored(restored.claim.read_directory().unwrap())
            .unwrap();
    }
    assert!(restored.aggregate_durable.restored_sources_synced());
    assert_eq!(
        restored
            .aggregate_durable
            .loaded
            .each_ref()
            .map(|source| source.descriptor.as_ref().unwrap().as_raw_fd()),
        before
    );
    restored.step().unwrap();
    assert_eq!(restored.phase, Phase::ShareExtracted);
    assert_eq!(
        restored
            .export
            .as_ref()
            .unwrap()
            .source_checkpoint()
            .unwrap(),
        ciphertext
    );
    drop(restored);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn aggregate_source_name_replacement_during_original_directory_sync_never_adopts_equal_bytes_or_reopens_source()
 {
    use std::os::unix::fs::PermissionsExt as _;
    let (_temporary, path) = root();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let (original, _writers, inherited, _chain, _admitted_deadline) =
        through_original_aggregate_head(&path, &budget);
    drop(original);
    let mut restored = prepare_with_sources(&path, &budget, inherited, HANDLE, 7).unwrap();
    prepare_loaded(&mut restored);
    let replaced_path = restored
        .claim
        .read_directory()
        .unwrap()
        .path
        .join(CHECKPOINT);
    let held_path = restored
        .claim
        .read_directory()
        .unwrap()
        .path
        .join("retained-original-aggregate");
    let bytes = restored.aggregate_durable.source(0).unwrap().to_vec();
    let source_pointer = restored.aggregate_durable.source(0).unwrap().as_ptr();
    let reserved = budget.reserved_bytes();
    let original_fd = restored.aggregate_durable.loaded[2]
        .descriptor
        .as_ref()
        .unwrap()
        .as_raw_fd();
    let directory_inode = restored
        .claim
        .read_directory()
        .unwrap()
        .file
        .metadata()
        .unwrap()
        .ino();
    let error = {
        let restored = &mut *restored;
        restored
            .aggregate_durable
            .sync_restored_with(restored.claim.read_directory().unwrap(), |held| {
                held.sync_all()?;
                if held.metadata()?.ino() == directory_inode {
                    fs::rename(&replaced_path, &held_path)?;
                    fs::write(&replaced_path, &bytes)?;
                    fs::set_permissions(&replaced_path, fs::Permissions::from_mode(0o600))?;
                }
                Ok(())
            })
            .unwrap_err()
    };
    assert!(matches!(error, AttemptError::Binding));
    assert!(!restored.aggregate_durable.restored_sources_synced());
    assert_eq!(
        restored.aggregate_durable.loaded[2]
            .descriptor
            .as_ref()
            .unwrap()
            .as_raw_fd(),
        original_fd
    );
    assert_eq!(fs::read(&replaced_path).unwrap(), bytes);
    assert_eq!(fs::read(&held_path).unwrap(), bytes);
    assert!(restored.claim.directory().is_none());
    assert!(restored.aggregate_owner.is_none());
    assert!(matches!(restored.step(), Err(AttemptError::Binding)));
    assert_eq!(
        restored.aggregate_durable.source(0).unwrap().as_ptr(),
        source_pointer
    );
    assert_eq!(restored.aggregate_durable.source(0).unwrap(), bytes);
    assert_eq!(budget.reserved_bytes(), reserved);
    drop(restored);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_aggregate_reload_rejects_foreign_provider_widened_cutoff_and_fake_h4_result_before_private_restore()
 {
    for mutation in [0, 1, 2] {
        let (_temporary, path) = root();
        let budget = AllocationBudget::new(64 * 1024 * 1024);
        let (original, _writers, inherited, _chain, _admitted_deadline) =
            through_original_aggregate_head(&path, &budget);
        let directory = original.claim.directory().unwrap().path.clone();
        if mutation > 0 {
            let mut head: AggregateHead =
                norito::decode_canonical(&fs::read(directory.join(HEAD)).unwrap()).unwrap();
            let mut intent: AggregateIntent =
                norito::decode_canonical(&fs::read(directory.join(INTENT)).unwrap()).unwrap();
            if mutation == 1 {
                head.binding.cutoff_height += 1;
            } else {
                let iroha_crypto::threshold_bls::checkpoint::DkgCheckpointSourceV1::ExecutedNativeTip { result_hash, .. } = &mut head.binding.source else { panic!("genuine original H4 source") };
                result_hash[0] ^= 1;
            }
            intent.binding = head.binding;
            intent.binding.extraction_intent_hash = [0; 32];
            let intent_bytes = norito::encode_canonical(&intent).unwrap();
            head.binding.extraction_intent_hash = Hash::new(&intent_bytes).into();
            fs::write(directory.join(INTENT), intent_bytes).unwrap();
            fs::write(
                directory.join(HEAD),
                norito::encode_canonical(&head).unwrap(),
            )
            .unwrap();
        }
        let files = [INTENT, HEAD, CHECKPOINT].map(|name| fs::read(directory.join(name)).unwrap());
        drop(original);
        let handle = if mutation == 0 {
            "software://iroha/consensus-threshold/foreign-aggregate"
        } else {
            HANDLE
        };
        let mut restored = prepare_with_sources(&path, &budget, inherited, handle, 7).unwrap();
        let error = restored.step().unwrap_err();
        assert!(
            matches!(error, AttemptError::Binding),
            "immutable source/context refusal: {error}"
        );
        assert!(restored.aggregate_owner.is_none());
        assert!(restored.aggregate_restore.is_none());
        assert!(restored.local.is_none());
        assert!(restored.prepared.is_none());
        assert!(restored.claim.directory().is_none());
        for (name, bytes) in [INTENT, HEAD, CHECKPOINT].into_iter().zip(files) {
            assert_eq!(fs::read(directory.join(name)).unwrap(), bytes);
        }
        drop(restored);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn retired_phase_four_extraction_format_has_no_encoder_or_writer_beside_the_original_final_aggregate_intent()
 {
    let (_temporary, path) = root();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let (mut original, _writers, _inherited, _chain, _admitted_deadline) =
        through_original_extraction_intent(&path, &budget);
    let context = *original.durable.latest_context().unwrap();
    let (claim, root_hash, fifos) = original.claim_and_fifo_identity().unwrap();
    let reserved = budget.reserved_bytes();
    let directory = original.claim.directory().unwrap().path.clone();
    let intent = fs::read(directory.join(INTENT)).unwrap();
    let generations = original.stream_generations();
    assert!(matches!(
        original.durable.prepare_intent(
            4,
            &context,
            claim,
            root_hash,
            fifos,
            None,
            [[0; 32]; 2],
            generations
        ),
        Err(AttemptError::Phase)
    ));
    assert!(matches!(
        original.durable.intent_hash(4),
        Err(AttemptError::Phase)
    ));
    {
        let original = &mut *original;
        assert!(matches!(
            original
                .durable
                .publish_intent(original.claim.directory().unwrap(), 4),
            Err(AttemptError::Phase)
        ));
    }
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(fs::read(directory.join(INTENT)).unwrap(), intent);
    assert_eq!(original.phase, Phase::AggregateIntentDurable);
    assert!(original.local.is_some());
    assert!(!original.aggregate_durable.complete());
    original.step().unwrap();
    assert_eq!(original.phase, Phase::AggregateProduced);
    assert!(original.aggregate_durable.complete());
    assert_eq!(fs::read(directory.join(INTENT)).unwrap(), intent);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}
