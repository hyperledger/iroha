//! Regressions for exact final map/bundle reconciliation without witness materialization.

use super::super::tests::{cache_canonical_test_transaction_set, delta, header, state};
use super::*;
use iroha_data_model::fastpq::TransferSmtWitness;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::ALICE_ID;

fn fixture(
    key_count: usize,
    occurrences: usize,
    deltas_per_occurrence: usize,
) -> (
    FastpqSourceInventoryV1,
    BTreeMap<Hash, Vec<TransferTranscript>>,
) {
    let _guard = crate::exec_witness::exec_witness_guard();
    let state = state();
    let mut block = state.block(header());
    cache_canonical_test_transaction_set(&mut block, &[]);
    for key_index in 0..key_count {
        let hash = Hash::new([u8::try_from(key_index).expect("fixture value fits u8"), 91]);
        // This component fixture owns a bounded invocation before staging
        // occurrences; it does not claim authenticated carrier publication.
        let mut tx = block.transaction_for_fastpq_testing(hash);
        for occurrence in 0..occurrences {
            let mut deltas = Vec::new();
            for delta_index in 0..deltas_per_occurrence {
                let ordinal =
                    u32::try_from(occurrence * deltas_per_occurrence + delta_index).unwrap();
                let mut current = delta();
                current.from_balance_before = Quantity::from(100_u32 - ordinal);
                current.from_balance_after = Quantity::from(99_u32 - ordinal);
                current.to_balance_before = Quantity::from(ordinal);
                current.to_balance_after = Quantity::from(ordinal + 1);
                deltas.push(current);
            }
            tx.record_test_transfer_transcripts(&ALICE_ID, hash, deltas);
        }
        tx.apply();
    }
    block
        .finalize_fastpq_source_inventory(&[], &[], &[])
        .unwrap();
    let inventory = block.fastpq_source_inventory().unwrap().unwrap().clone();
    let transcripts = block.drain_transfer_transcripts_with_pending(None);
    (inventory, transcripts)
}

fn bundles(transcripts: &BTreeMap<Hash, Vec<TransferTranscript>>) -> Vec<TransferTranscriptBundle> {
    transcripts
        .iter()
        .map(|(entry_hash, transcripts)| TransferTranscriptBundle {
            entry_hash: *entry_hash,
            transcripts: transcripts.clone(),
        })
        .collect()
}

fn assert_both_reject(
    inventory: &FastpqSourceInventoryV1,
    transcripts: &BTreeMap<Hash, Vec<TransferTranscript>>,
) {
    assert!(
        inventory
            .verify_finalized_transcript_map(transcripts)
            .is_err()
    );
    assert!(
        inventory
            .verify_ordinary_witness_bundles(&bundles(transcripts))
            .is_err()
    );
}

#[test]
fn exact_empty_single_and_multiple_owned_archives_accept_both_borrowed_views() {
    for (keys, occurrences, deltas) in [(0, 0, 0), (1, 1, 1), (2, 2, 2)] {
        let (inventory, transcripts) = fixture(keys, occurrences, deltas);
        let witness = bundles(&transcripts);
        let before = witness.clone();
        inventory
            .verify_finalized_transcript_map(&transcripts)
            .unwrap();
        inventory.verify_ordinary_witness_bundles(&witness).unwrap();
        assert_eq!(witness, before);
    }
}

#[test]
fn final_views_reject_missing_extra_duplicate_and_unordered_keys() {
    let (inventory, original) = fixture(2, 2, 1);
    let key = *original.keys().next().unwrap();
    let mut missing = original.clone();
    missing.remove(&key);
    assert_both_reject(&inventory, &missing);
    let mut extra = original.clone();
    extra.insert(
        Hash::new(b"extra final recorder key"),
        original[&key].clone(),
    );
    assert_both_reject(&inventory, &extra);
    let mut reversed = bundles(&original);
    reversed.reverse();
    assert!(
        inventory
            .verify_ordinary_witness_bundles(&reversed)
            .is_err()
    );
    let mut duplicate = bundles(&original);
    duplicate[1] = duplicate[0].clone();
    assert!(
        inventory
            .verify_ordinary_witness_bundles(&duplicate)
            .is_err()
    );
    assert_both_reject(&inventory, &BTreeMap::new());
}

#[test]
fn final_views_check_counts_and_ordinary_identity_before_public_hashing() {
    let (inventory, original) = fixture(1, 2, 1);
    let key = *original.keys().next().unwrap();
    for mutation in 0..5 {
        let mut changed = original.clone();
        let bundle = changed.get_mut(&key).unwrap();
        let expected = match mutation {
            0 => {
                bundle.push(bundle[0].clone());
                "transcript count exceeds"
            }
            1 => {
                let duplicate = bundle[0].deltas[0].clone();
                bundle[0].deltas.push(duplicate);
                "delta count exceeds"
            }
            2 => {
                bundle[0].batch_hash = Hash::new(b"inner identity is not the ordinary key");
                "ordinary identity"
            }
            3 => {
                bundle[0].deltas.clear();
                "delta shape"
            }
            _ => {
                bundle.clear();
                "empty transcript bundle"
            }
        };
        assert!(
            inventory
                .verify_finalized_transcript_map(&changed)
                .unwrap_err()
                .contains(expected)
        );
        assert!(
            inventory
                .verify_ordinary_witness_bundles(&bundles(&changed))
                .unwrap_err()
                .contains(expected)
        );
    }
    let mut truncated = original.clone();
    truncated.get_mut(&key).unwrap().pop();
    assert!(
        inventory
            .verify_finalized_transcript_map(&truncated)
            .unwrap_err()
            .contains("occurrence counts")
    );
    assert_both_reject(&inventory, &truncated);
}

#[test]
fn final_views_reject_public_substitution_without_repairing_digests() {
    let (inventory, original) = fixture(1, 2, 1);
    let key = *original.keys().next().unwrap();
    for mutation in 0..5 {
        let mut changed = original.clone();
        let bundle = changed.get_mut(&key).unwrap();
        match mutation {
            0 => bundle.swap(0, 1),
            1 => bundle[0].authority_digest = Hash::new(b"replacement final authority"),
            2 => bundle[0].poseidon_preimage_digest = None,
            3 => bundle[0].poseidon_preimage_digest = Some(Hash::new(b"wrong final digest")),
            _ => {
                let transcript = &mut bundle[0];
                let delta = &mut transcript.deltas[0];
                delta.amount = Quantity::from(2_u32);
                delta.from_balance_after = Quantity::from(98_u32);
                delta.to_balance_after = Quantity::from(2_u32);
                transcript.poseidon_preimage_digest = Some(
                    crate::fastpq::poseidon_preimage_digest(delta, &transcript.batch_hash),
                );
            }
        }
        let before = changed.clone();
        assert!(
            inventory
                .verify_finalized_transcript_map(&changed)
                .unwrap_err()
                .contains("public content")
        );
        assert!(
            inventory
                .verify_ordinary_witness_bundles(&bundles(&changed))
                .unwrap_err()
                .contains("public content")
        );
        assert_eq!(
            changed, before,
            "rejected mutation {mutation} must remain unrepaired"
        );
    }
}

#[test]
fn final_views_bind_grouping_even_with_all_keys_and_counts_unchanged() {
    let (inventory, original) = fixture(1, 2, 2);
    let key = *original.keys().next().unwrap();
    let mut changed = original.clone();
    let bundle = changed.get_mut(&key).unwrap();
    let moved = bundle[0].deltas.pop().unwrap();
    bundle[1].deltas.insert(0, moved);
    // Both original headers keep None. This checker must compare exact grouping rather
    // than normalize the optional digest of the now-single-delta first occurrence.
    assert_eq!(bundle.len(), 2);
    assert_eq!(
        bundle.iter().map(|entry| entry.deltas.len()).sum::<usize>(),
        4
    );
    assert!(
        inventory
            .verify_finalized_transcript_map(&changed)
            .unwrap_err()
            .contains("public content")
    );
    assert_both_reject(&inventory, &changed);
}

#[test]
fn final_views_exclude_private_paths_and_preserve_supplied_ownership() {
    let (inventory, mut transcripts) = fixture(2, 2, 2);
    for transcript in transcripts.values_mut().flatten() {
        for delta in &mut transcript.deltas {
            delta.from_smt_witness =
                TransferSmtWitness::new([1; 32], [2; 32], vec![3; 128], vec![[4; 32]; 128]);
            delta.to_smt_witness =
                TransferSmtWitness::new([5; 32], [6; 32], vec![7; 129], vec![[8; 32]; 129]);
        }
    }
    let before = transcripts.clone();
    inventory
        .verify_finalized_transcript_map(&transcripts)
        .unwrap();
    let witness = bundles(&transcripts);
    inventory.verify_ordinary_witness_bundles(&witness).unwrap();
    assert_eq!(transcripts, before);
}

#[test]
fn owned_count_addition_rejects_overflow_and_above_sealed_limits() {
    assert_eq!(checked_owned_count(0, 0, 0, "transcript").unwrap(), 0);
    assert_eq!(
        checked_owned_count(u64::MAX - 1, 1, u64::MAX, "delta").unwrap(),
        u64::MAX
    );
    assert!(checked_owned_count(u64::MAX, 1, u64::MAX, "delta").is_err());
    assert!(checked_owned_count(1, 1, 1, "transcript").is_err());
}
