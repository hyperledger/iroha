//! Accelerator cardinality, pending-preimage identity and atomic digest installation.

use super::*;
use iroha_data_model::fastpq::TransferSmtWitness;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use std::{cell::Cell, rc::Rc};

fn transcript(tag: u8) -> TransferTranscript {
    TransferTranscript {
        batch_hash: Hash::prehashed([tag; 32]),
        deltas: vec![TransferDeltaTranscript {
            from_account: (*ALICE_ID).clone(),
            to_account: (*BOB_ID).clone(),
            asset_definition: AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            ),
            amount: Quantity::from(u32::from(tag) + 1),
            from_balance_before: Quantity::from(200u32),
            from_balance_after: Quantity::from(200 - u32::from(tag) - 1),
            to_balance_before: Quantity::zero(),
            to_balance_after: Quantity::from(u32::from(tag) + 1),
            from_smt_witness: TransferSmtWitness::default(),
            to_smt_witness: TransferSmtWitness::default(),
        }],
        authority_digest: authority_digest(&ALICE_ID),
        poseidon_preimage_digest: None,
    }
}

fn batch(transcripts: &[TransferTranscript]) -> PoseidonDigestBatch {
    let mut batch = PoseidonDigestBatch::default();
    collect_transfer_transcript_digests(transcripts, &mut batch);
    batch
}

fn scalar_digests(transcripts: &[TransferTranscript]) -> Vec<Hash> {
    transcripts
        .iter()
        .filter(|transcript| needs_transfer_transcript_digest(transcript))
        .map(|transcript| poseidon_preimage_digest(&transcript.deltas[0], &transcript.batch_hash))
        .collect()
}

#[test]
fn acceleration_test_guard_serializes_and_restores_shared_lane_state() {
    let guard = DigestAccelerationTestGuard::new();
    let previous = poseidon_digest_acceleration_enabled();
    set_poseidon_digest_acceleration_enabled(!previous);
    let (contended, observed_contention) = std::sync::mpsc::channel();
    let competing_worker = std::thread::spawn(move || {
        assert!(matches!(
            DIGEST_ACCELERATION_TEST_LOCK.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        contended.send(()).expect("report held acceleration guard");
        let _guard = DigestAccelerationTestGuard::new();
        assert_eq!(poseidon_digest_acceleration_enabled(), previous);
        set_poseidon_digest_acceleration_enabled(!previous);
    });
    observed_contention
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("contender observes the shared acceleration lock");
    drop(guard);
    competing_worker
        .join()
        .expect("contending acceleration test joins");
    let _guard = DigestAccelerationTestGuard::new();
    assert_eq!(poseidon_digest_acceleration_enabled(), previous);
}

#[test]
fn accelerator_results_require_exact_cardinality_before_acceptance() {
    let _guard = DigestAccelerationTestGuard::new();
    let batch = batch(&[transcript(1), transcript(2)]);
    for output in [
        None,
        Some(vec![]),
        Some(vec![[3; 32]]),
        Some(vec![[3; 32]; 3]),
    ] {
        set_poseidon_digest_acceleration_enabled(true);
        assert!(batch.accept_gpu_digests(output).is_none());
        assert!(!poseidon_digest_acceleration_enabled());
    }
    set_poseidon_digest_acceleration_enabled(true);
    let output = vec![[3; 32], [4; 32]];
    assert_eq!(
        batch.accept_gpu_digests(Some(output.clone())),
        Some(output.into_iter().map(Hash::prehashed).collect()),
    );
    assert!(poseidon_digest_acceleration_enabled());
}

#[test]
fn pending_result_failure_recomputes_the_complete_cpu_batch() {
    let _guard = DigestAccelerationTestGuard::new();
    let transcripts = [transcript(1), transcript(2)];
    let original = batch(&transcripts);
    let current = batch(&transcripts);
    let expected = scalar_digests(&transcripts);
    for output in [
        None,
        Some(vec![]),
        Some(vec![[3; 32]]),
        Some(vec![[3; 32]; 3]),
    ] {
        set_poseidon_digest_acceleration_enabled(true);
        let called = Cell::new(false);
        let actual = original.resolve_pending_or_cpu(&current, || {
            called.set(true);
            output
        });
        assert!(called.get());
        assert_eq!(actual, expected);
        assert!(!poseidon_digest_acceleration_enabled());
    }
    set_poseidon_digest_acceleration_enabled(true);
    let called = Cell::new(false);
    assert_eq!(
        original.resolve_pending_or_cpu(&current, || {
            called.set(true);
            Some(vec![[3; 32], [4; 32]])
        }),
        vec![Hash::prehashed([3; 32]), Hash::prehashed([4; 32])],
    );
    assert!(called.get());
    assert!(poseidon_digest_acceleration_enabled());
}

#[test]
fn same_count_pending_inputs_bind_every_preimage_field_and_occurrence_order() {
    let _guard = DigestAccelerationTestGuard::new();
    let original_transcripts = [transcript(1), transcript(2)];
    let original = batch(&original_transcripts);
    for changed_field in 0..6 {
        let mut current_transcripts = original_transcripts.clone();
        match changed_field {
            0 => current_transcripts[0].deltas[0].from_account = (*BOB_ID).clone(),
            1 => current_transcripts[0].deltas[0].to_account = (*ALICE_ID).clone(),
            2 => {
                current_transcripts[0].deltas[0].asset_definition =
                    AssetDefinitionId::derive_from_components(
                        DomainId::try_new("wonderland", "universal").unwrap(),
                        "lily".parse().unwrap(),
                    );
            }
            3 => current_transcripts[0].deltas[0].amount = Quantity::from(17u32),
            4 => current_transcripts[0].batch_hash = Hash::prehashed([19; 32]),
            5 => current_transcripts.swap(0, 1),
            _ => unreachable!(),
        }
        let current = batch(&current_transcripts);
        assert_eq!(original.slices.len(), current.slices.len());
        assert_ne!(original, current, "changed field {changed_field}");
        set_poseidon_digest_acceleration_enabled(true);
        let called = Cell::new(false);
        assert_eq!(
            original.resolve_pending_or_cpu(&current, || {
                called.set(true);
                Some(vec![[3; 32]; 2])
            }),
            scalar_digests(&current_transcripts),
            "changed field {changed_field}",
        );
        assert!(!called.get(), "stale result must not be collected");
        assert!(
            poseidon_digest_acceleration_enabled(),
            "stale input is not a GPU fault"
        );
    }
}

#[test]
fn pending_identity_includes_slice_order_and_missing_digest_membership() {
    let _guard = DigestAccelerationTestGuard::new();
    let transcripts = [transcript(1), transcript(2)];
    let original = batch(&transcripts);
    let mut reordered = batch(&transcripts);
    reordered.slices.swap(0, 1);
    assert_eq!(original.words, reordered.words);
    assert_ne!(original, reordered);
    let mut expected = scalar_digests(&transcripts);
    expected.reverse();
    assert_eq!(
        original.resolve_pending_or_cpu(&reordered, || panic!("stale slice order")),
        expected
    );
    let current = batch(&transcripts[1..]);
    assert_eq!(
        original.resolve_pending_or_cpu(&current, || panic!("stale occurrence count")),
        scalar_digests(&transcripts[1..]),
    );
}

#[test]
fn stale_pending_capture_is_dropped_without_collecting_result_bytes() {
    struct DropProbe(Rc<Cell<bool>>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    let _guard = DigestAccelerationTestGuard::new();
    let original = batch(&[transcript(1)]);
    let current = batch(&[transcript(2)]);
    let dropped = Rc::new(Cell::new(false));
    let probe = DropProbe(Rc::clone(&dropped));
    let called = Cell::new(false);
    let actual = original.resolve_pending_or_cpu(&current, || {
        called.set(true);
        drop(probe);
        Some(vec![[3; 32]])
    });
    assert!(!called.get());
    assert!(dropped.get());
    assert_eq!(actual, scalar_digests(&[transcript(2)]));
}

fn grouped_map() -> BTreeMap<Hash, Vec<TransferTranscript>> {
    let first = transcript(1);
    let mut precomputed = transcript(1);
    precomputed.poseidon_preimage_digest = Some(poseidon_preimage_digest(
        &precomputed.deltas[0],
        &precomputed.batch_hash,
    ));
    let mut multi = transcript(2);
    multi.deltas.push(multi.deltas[0].clone());
    BTreeMap::from([
        (first.batch_hash, vec![first, precomputed]),
        (multi.batch_hash, vec![multi, transcript(2)]),
    ])
}

#[test]
fn map_installer_rejects_short_and_extra_outputs_without_any_mutation() {
    let original = grouped_map();
    for output in [
        vec![],
        vec![Hash::prehashed([3; 32])],
        vec![Hash::prehashed([3; 32]); 3],
    ] {
        let mut actual = original.clone();
        assert!(!apply_transfer_transcript_digests_in_map(
            &mut actual,
            output
        ));
        assert_eq!(actual, original);
    }
    let mut expected = original.clone();
    let output = [Hash::prehashed([3; 32]), Hash::prehashed([4; 32])];
    let first = *expected.keys().next().unwrap();
    let last = *expected.keys().next_back().unwrap();
    expected.get_mut(&first).unwrap()[0].poseidon_preimage_digest = Some(output[0]);
    expected.get_mut(&last).unwrap()[1].poseidon_preimage_digest = Some(output[1]);
    let mut actual = original;
    assert!(apply_transfer_transcript_digests_in_map(
        &mut actual,
        output.to_vec()
    ));
    assert_eq!(actual, expected);
}

#[test]
fn bundle_installer_rejects_cardinality_errors_and_preserves_bundle_order() {
    let mut original = grouped_map()
        .into_iter()
        .map(|(entry_hash, transcripts)| TransferTranscriptBundle {
            entry_hash,
            transcripts,
        })
        .collect::<Vec<_>>();
    original.reverse();
    for output in [
        vec![],
        vec![Hash::prehashed([3; 32])],
        vec![Hash::prehashed([3; 32]); 3],
    ] {
        let mut actual = original.clone();
        assert!(!apply_transfer_transcript_bundle_digests(
            &mut actual,
            output
        ));
        assert_eq!(actual, original);
    }
    let mut expected = original.clone();
    let output = [Hash::prehashed([3; 32]), Hash::prehashed([4; 32])];
    expected[0].transcripts[1].poseidon_preimage_digest = Some(output[0]);
    expected[1].transcripts[0].poseidon_preimage_digest = Some(output[1]);
    let mut actual = original;
    assert!(apply_transfer_transcript_bundle_digests(
        &mut actual,
        output.to_vec()
    ));
    assert_eq!(actual, expected);
}

#[test]
fn slice_installer_checks_remaining_length_before_writing_first_digest() {
    let original = vec![transcript(1), transcript(2)];
    let mut actual = original.clone();
    let mut output = vec![Hash::prehashed([3; 32])].into_iter();
    assert!(!apply_transfer_transcript_digests(&mut actual, &mut output));
    assert_eq!(output.len(), 1);
    assert_eq!(actual, original);
}

#[test]
fn malformed_pending_output_installs_a_complete_ordered_cpu_fallback() {
    let _guard = DigestAccelerationTestGuard::new();
    let original = grouped_map();
    let mut prepared = PoseidonDigestBatch::default();
    for transcripts in original.values() {
        collect_transfer_transcript_digests(transcripts, &mut prepared);
    }
    let mut expected = original.clone();
    for transcripts in expected.values_mut() {
        finalize_transfer_transcripts_serial(transcripts);
    }
    for output in [None, Some(vec![[3; 32]]), Some(vec![[3; 32]; 3])] {
        set_poseidon_digest_acceleration_enabled(true);
        let digests = prepared.resolve_pending_or_cpu(&prepared, || output);
        let mut actual = original.clone();
        assert!(apply_transfer_transcript_digests_in_map(
            &mut actual,
            digests
        ));
        assert_eq!(actual, expected);
        assert!(!poseidon_digest_acceleration_enabled());
    }
}
