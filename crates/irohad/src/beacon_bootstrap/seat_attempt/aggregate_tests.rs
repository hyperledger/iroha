//! Genuine finalized H4 aggregate publication, original-owner reload and closed export controls.

use super::later_restore_tests::through_original_later_phase;
use super::tests::{prepare_with_sources, root};
use super::*;

const HANDLE: &str = "software://iroha/consensus-threshold/retained-attempt";

pub(super) fn through_original_extraction_intent(
    root: &Path,
    budget: &AllocationBudget,
) -> (
    SeatDkgAttemptOwner,
    [File; 2],
    [File; 2],
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
    Instant,
) {
    let (mut original, writers, inherited, chain, admitted_deadline) =
        through_original_later_phase(root, budget, 4);
    assert_eq!(original.phase, Phase::ExportPrepared);
    assert_eq!(original.finality.height(), 4);
    assert_eq!(
        original.finality.clock().tip().unwrap().result(),
        chain.committed(4).result()
    );
    original.step().unwrap();
    assert_eq!(original.phase, Phase::AggregateIntentDurable);
    (original, writers, inherited, chain, admitted_deadline)
}

pub(super) fn through_original_aggregate_head(
    root: &Path,
    budget: &AllocationBudget,
) -> (
    SeatDkgAttemptOwner,
    [File; 2],
    [File; 2],
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
    Instant,
) {
    let (mut original, writers, inherited, chain, admitted_deadline) =
        through_original_extraction_intent(root, budget);
    for expected in [Phase::AggregateProduced, Phase::AggregateDurable] {
        original.step().unwrap();
        assert_eq!(original.phase, expected);
    }
    assert!(original.aggregate_durable.complete());
    assert!(original.local.is_some());
    assert!(original.export.as_ref().unwrap().source_is_empty());
    (original, writers, inherited, chain, admitted_deadline)
}

/// Move only the actual completed producer after its original H4/private/head barriers.
/// This helper never constructs private components, a fake native result or a checked source.
pub(crate) fn genuine_aggregate_owner(
    budget: &AllocationBudget,
) -> (
    ValidatedGlobalThresholdBeaconSessionV1,
    GlobalBeaconAggregateOwnerV1,
) {
    let (_temporary, path) = root();
    let (mut original, _writers, _inherited, _chain, _admitted_deadline) =
        through_original_aggregate_head(&path, budget);
    let context = original
        .aggregate_context(original.aggregate_durable.intent_hash().unwrap())
        .unwrap();
    let public = original.sealed.as_ref().unwrap().clone();
    let source = {
        let original = &mut *original;
        original
            .local
            .as_mut()
            .unwrap()
            .retire_durably_published_aggregate(&context, &public, &original.signer)
            .unwrap()
    };
    assert!(source.authenticated_session().ptr_eq(&public));
    assert!(source.belongs_to(budget));
    assert_eq!(source.binding(), context.binding());
    drop(original);
    (public, source)
}

#[test]
fn finalized_original_aggregate_writer_refusal_retains_once_produced_ciphertext_and_receiver_until_same_head_retry()
 {
    let (_temporary, path) = root();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let (mut original, _writers, _inherited, chain, _admitted_deadline) =
        through_original_extraction_intent(&path, &budget);
    let directory = original.claim.directory().unwrap().path.clone();
    let checkpoint = directory.join("private-aggregate-checkpoint.norito");
    fs::write(&checkpoint, b"unrelated original destination").unwrap();
    let receiver = std::ptr::from_ref(&*original);
    let context = original
        .aggregate_context(original.aggregate_durable.intent_hash().unwrap())
        .unwrap();
    let (pointer, bytes) = {
        let original = &mut *original;
        let bytes = original
            .local
            .as_mut()
            .unwrap()
            .produce_aggregate_checkpoint(
                &context,
                original.sealed.as_ref().unwrap(),
                &original.signer,
            )
            .unwrap();
        (bytes.as_ptr(), bytes.to_vec())
    };
    let retained = budget.reserved_bytes();
    let error = original.step().unwrap_err();
    assert!(matches!(
        error,
        AttemptError::Export(seat_export::ExportError::Io(_))
    ));
    assert_eq!(original.phase, Phase::AggregateIntentDurable);
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(std::ptr::from_ref(&*original), receiver);
    assert!(original.local.is_some());
    assert!(original.export.as_ref().unwrap().source_is_empty());
    assert_eq!(
        original.finality.clock().tip().unwrap().result(),
        chain.committed(4).result()
    );
    let retry = {
        let original = &mut *original;
        original
            .local
            .as_mut()
            .unwrap()
            .produce_aggregate_checkpoint(
                &context,
                original.sealed.as_ref().unwrap(),
                &original.signer,
            )
            .unwrap()
    };
    assert_eq!(retry.as_ptr(), pointer);
    assert_eq!(retry, bytes);
    assert_eq!(
        fs::read(&checkpoint).unwrap(),
        b"unrelated original destination"
    );
    fs::remove_file(&checkpoint).unwrap();
    original.step().unwrap();
    assert_eq!(original.phase, Phase::AggregateProduced);
    assert!(original.aggregate_durable.complete());
    assert_eq!(fs::read(&checkpoint).unwrap(), bytes);
    original.step().unwrap();
    original.step().unwrap();
    assert_eq!(original.phase, Phase::ShareExtracted);
    assert!(original.local.is_none());
    assert_eq!(original.public_input.generation(), 3);
    assert!(original.public_input.frame().is_none());
    assert_eq!(
        original
            .export
            .as_ref()
            .unwrap()
            .source_checkpoint()
            .unwrap(),
        bytes
    );
    assert_eq!(std::ptr::from_ref(&*original), receiver);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_complete_aggregate_and_four_output_heads_restore_genuine_h3_h4_ancestry_same_claim_and_exact_private_bytes()
 {
    for complete_export in [false, true] {
        let (_temporary, path) = root();
        let budget = AllocationBudget::new(64 * 1024 * 1024);
        let (mut original, writers, inherited, chain, admitted_deadline) =
            through_original_aggregate_head(&path, &budget);
        original.step().unwrap();
        assert_eq!(original.phase, Phase::ShareExtracted);
        let ciphertext = original
            .export
            .as_ref()
            .unwrap()
            .source_checkpoint()
            .unwrap()
            .to_vec();
        let identity = original.claim_and_fifo_identity().unwrap();
        let generations = original.stream_generations();
        let deadline = admitted_deadline;
        let directory = original.claim.directory().unwrap().path.clone();
        let original_expiry = norito::decode_canonical::<aggregate_durable::AggregateIntent>(
            &fs::read(directory.join("producer-extraction-intent.norito")).unwrap(),
        )
        .unwrap()
        .expiry;
        let output_bytes = if complete_export {
            original.step().unwrap();
            assert_eq!(original.phase, Phase::Complete);
            Some(seat_export::output_names().map(|name| fs::read(directory.join(name)).unwrap()))
        } else {
            None
        };
        let files = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (path.clone(), fs::read(path).unwrap())
            })
            .collect::<Vec<_>>();
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
        let mut restored = prepare_with_sources(&path, &budget, inherited, HANDLE, 7).unwrap();
        assert_eq!(restored.restore_target, Some(4));
        assert!(matches!(restored.inputs, AttemptInputBanks::Final(_)));
        assert!(restored.prepared.is_none());
        assert!(restored.local.is_none());
        assert!(restored.original_publications.iter().all(Option::is_none));
        let receiver = std::ptr::from_ref(&*restored);
        restored.step().unwrap();
        assert!(restored.aggregate_durable.restored_sources_synced());
        assert!(restored.aggregate_accepted_context.is_some());
        assert_eq!(restored.finality.height(), 4);
        assert_eq!(
            restored.finality.clock().tip().unwrap().result(),
            chain.committed(4).result()
        );
        assert_eq!(
            restored
                .export
                .as_ref()
                .unwrap()
                .source_checkpoint()
                .unwrap(),
            ciphertext
        );
        assert_eq!(restored.claim_and_fifo_identity().unwrap(), identity);
        assert_eq!(restored.stream_generations(), generations);
        assert!(restored.deadline <= deadline);
        let restored_expiry = {
            let attempt = &mut *restored;
            attempt
                .aggregate_durable
                .load(attempt.claim.directory().unwrap())
                .unwrap()
                .0
                .expiry
        };
        assert_eq!(restored_expiry, original_expiry);
        assert!(restored.prepared.is_none());
        assert!(restored.local.is_none());
        assert_eq!(
            restored.phase,
            if complete_export {
                Phase::RestoringExport
            } else {
                Phase::ShareExtracted
            }
        );
        restored.step().unwrap();
        assert_eq!(restored.phase, Phase::Complete);
        if let Some(output_bytes) = output_bytes {
            for (name, expected) in seat_export::output_names().into_iter().zip(output_bytes) {
                assert_eq!(fs::read(directory.join(name)).unwrap(), expected);
            }
        }
        for (path, bytes) in files {
            assert_eq!(
                fs::read(path).unwrap(),
                bytes,
                "every original durable source remains unchanged"
            );
        }
        assert_eq!(std::ptr::from_ref(&*restored), receiver);
        drop(restored);
        assert_eq!(budget.reserved_bytes(), 0);
        drop(writers);
    }
}

#[test]
fn aggregate_reload_all_source_extents_are_paid_together_before_any_private_adoption_and_refusal_retains_original_fds()
 {
    let (_temporary, path) = root();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let (original, _writers, inherited, _chain, _admitted_deadline) =
        through_original_aggregate_head(&path, &budget);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
    let mut restored = prepare_with_sources(&path, &budget, inherited, HANDLE, 7).unwrap();
    let receiver = std::ptr::from_ref(&*restored);
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let error = restored.step().unwrap_err();
    assert!(
        matches!(
            error,
            AttemptError::Admission(AllocationRefusal::Capacity { .. })
        ),
        "original source admission cause: {error}"
    );
    assert!(restored.aggregate_owner.is_none());
    assert!(restored.aggregate_restore.is_none());
    assert!(restored.sealed.is_none());
    assert!(restored.local.is_none());
    assert!(restored.prepared.is_none());
    assert!(restored.claim.directory().is_none());
    assert_eq!(restored.finality.height(), 1);
    let fds = restored.aggregate_durable.source_descriptor_ids();
    assert!(fds.iter().all(Option::is_some));
    assert!(restored.aggregate_durable.sources_unadmitted());
    let public_fifo = restored.public_input.source_identity().unwrap();
    drop(blocker);
    restored.step().unwrap();
    assert_eq!(restored.phase, Phase::ShareExtracted);
    assert!(restored.aggregate_durable.restored_sources_synced());
    assert_eq!(restored.aggregate_durable.source_descriptor_ids(), fds);
    assert_eq!(
        restored.public_input.source_identity().unwrap(),
        public_fifo
    );
    assert_eq!(std::ptr::from_ref(&*restored), receiver);
    drop(restored);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_aggregate_head_rejects_partial_final_output_prefix_before_private_export_adoption() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_temporary, path) = root();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let (original, _writers, inherited, _chain, _admitted_deadline) =
        through_original_aggregate_head(&path, &budget);
    let directory = original.claim.directory().unwrap().path.clone();
    let partial = directory.join(seat_export::output_names()[0]);
    fs::write(&partial, b"original incomplete final output").unwrap();
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).unwrap();
    let original_bytes = fs::read(&partial).unwrap();
    drop(original);
    let mut restored = prepare_with_sources(&path, &budget, inherited, HANDLE, 7).unwrap();
    let error = restored.step().unwrap_err();
    assert!(
        matches!(
            error,
            AttemptError::Export(seat_export::ExportError::Custody)
        ),
        "actual closed partial prefix: {error}"
    );
    assert_eq!(restored.phase, Phase::RestoringAggregate);
    assert!(restored.export.is_none());
    assert!(restored.aggregate_owner.is_none());
    assert!(restored.aggregate_restore.is_none());
    assert!(restored.claim.directory().is_none());
    assert!(restored.local.is_none());
    assert!(restored.prepared.is_none());
    assert_eq!(fs::read(partial).unwrap(), original_bytes);
    drop(restored);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_extraction_intent_without_complete_aggregate_head_never_falls_back_to_phase_three_or_generates_again()
 {
    let (_temporary, path) = root();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let (original, _writers, inherited, _chain, _admitted_deadline) =
        through_original_extraction_intent(&path, &budget);
    let intent_path = original
        .claim
        .directory()
        .unwrap()
        .path
        .join("producer-extraction-intent.norito");
    let intent = fs::read(&intent_path).unwrap();
    drop(original);
    let mut restored = prepare_with_sources(&path, &budget, inherited, HANDLE, 7).unwrap();
    assert!(matches!(restored.step(), Err(AttemptError::Binding)));
    assert!(restored.local.is_none());
    assert!(restored.aggregate_owner.is_none());
    assert!(restored.claim.directory().is_none());
    assert_eq!(restored.finality.height(), 1);
    assert_eq!(fs::read(intent_path).unwrap(), intent);
    drop(restored);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn actual_aggregate_handoff_checks_prepared_destination_before_retiring_original_contributions() {
    let (_temporary, path) = root();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let (mut original, _writers, _inherited, _chain, _admitted_deadline) =
        through_original_aggregate_head(&path, &budget);
    let destination = original.export.take().unwrap();
    let context = original
        .aggregate_context(original.aggregate_durable.intent_hash().unwrap())
        .unwrap();
    let (pointer, bytes) = {
        let original = &mut *original;
        let bytes = original
            .local
            .as_mut()
            .unwrap()
            .produce_aggregate_checkpoint(
                &context,
                original.sealed.as_ref().unwrap(),
                &original.signer,
            )
            .unwrap();
        (bytes.as_ptr(), bytes.to_vec())
    };
    let retained = budget.reserved_bytes();
    assert!(matches!(original.step(), Err(AttemptError::Phase)));
    assert_eq!(original.phase, Phase::AggregateDurable);
    assert_eq!(original.public_input.generation(), 2);
    assert!(original.public_input.frame().is_some());
    assert!(original.local.is_some());
    assert!(original.rejected_aggregate.is_none());
    assert_eq!(budget.reserved_bytes(), retained);
    let retry = {
        let original = &mut *original;
        original
            .local
            .as_mut()
            .unwrap()
            .produce_aggregate_checkpoint(
                &context,
                original.sealed.as_ref().unwrap(),
                &original.signer,
            )
            .unwrap()
    };
    assert_eq!(retry.as_ptr(), pointer);
    assert_eq!(retry, bytes);
    original.export = Some(destination);
    original.step().unwrap();
    assert_eq!(original.phase, Phase::ShareExtracted);
    assert!(original.local.is_none());
    assert_eq!(
        original
            .export
            .as_ref()
            .unwrap()
            .source_checkpoint()
            .unwrap(),
        bytes
    );
    assert_eq!(original.public_input.generation(), 3);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}
