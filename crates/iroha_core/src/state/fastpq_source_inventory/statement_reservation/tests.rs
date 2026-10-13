//! Whole-entry reservation, canonical sizing and failure-atomicity source regressions.

use super::super::tests::{cache_canonical_test_transaction_set, delta, header, state};
use super::*;
use crate::{
    exec_witness,
    fastpq::{
        FastpqPublicInputsTemplate, quantity_materializer_invocations_for_testing,
        quantity_statement_from_finalized_transcripts_for_testing,
    },
};
use fastpq_prover::gadgets::public_transfer_statement::{
    PublicTransferLimits, TransferSmtBuildLimits,
};
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::ALICE_ID;

type Archive = BTreeMap<Hash, Vec<TransferTranscript>>;

fn limits() -> FastpqSourceStatementBuildLimits {
    // Test-only construction bounds, never a source policy or encryption profile.
    FastpqSourceStatementBuildLimits {
        max_executed_entries: 8,
        max_transcripts: 8,
        max_deltas: 16,
        max_input_transcript_bytes: 1_000_000,
        max_statement_bytes: 1_000_000,
        max_total_statement_bytes: 4_000_000,
    }
}

fn seal(block: &mut StateBlock<'_>, sources: &[Hash], empty_entries: &[Hash]) -> Archive {
    cache_canonical_test_transaction_set(block, &[]);
    for hash in empty_entries {
        block.admit_fastpq_source_for_testing(*hash);
    }
    for hash in sources {
        let mut transaction = block.transaction_for_fastpq_testing(*hash);
        for before in [10_u32, 9] {
            let mut transfer = delta();
            transfer.from_balance_before = Quantity::from(before);
            transfer.from_balance_after = Quantity::from(before - 1);
            transfer.to_balance_before = Quantity::from(10 - before);
            transfer.to_balance_after = Quantity::from(11 - before);
            transaction.record_test_transfer_transcripts(&ALICE_ID, *hash, vec![transfer]);
        }
        transaction.apply();
    }
    block
        .finalize_fastpq_source_inventory(&[], &[], empty_entries)
        .unwrap();
    block.drain_transfer_transcripts_with_pending(None)
}

fn exact(usage: FastpqSourceStatementUsageV1) -> FastpqSourceStatementBuildLimits {
    FastpqSourceStatementBuildLimits {
        max_executed_entries: usage.executed_entries,
        max_transcripts: usage.transcripts,
        max_deltas: usage.deltas,
        max_input_transcript_bytes: usage.input_transcript_bytes,
        max_statement_bytes: usage.max_statement_bytes,
        max_total_statement_bytes: usage.total_statement_bytes,
    }
}

fn encoded_bundle(bundle: &[TransferTranscript]) -> usize {
    // Independent expected length comes from the actual materialized model encoder.
    // These explicit generous fixture limits are not taken from the measured result.
    let public = PublicTransferLimits {
        max_transcripts: 8,
        max_deltas: 16,
        max_rows: 32,
        max_public_bytes: 4_000_000,
        max_unique_keys: 32,
        max_allocation_steps: 128,
    };
    let produced = quantity_statement_from_finalized_transcripts_for_testing(
        FastpqPublicInputsTemplate {
            dsid: [0; 16],
            slot: 0,
            old_root: [0; 32],
            new_root: [0; 32],
            perm_root: [0; 32],
        }
        .with_tx_set_hash([7; 32]),
        bundle,
        public,
        TransferSmtBuildLimits::for_update_limit(32).unwrap(),
    )
    .unwrap();
    norito::encode_canonical(produced.statement())
        .unwrap()
        .len()
}

#[test]
fn complete_same_entry_measurement_matches_actual_frames_and_retry_replaces_usage() {
    let _guard = exec_witness::exec_witness_guard();
    exec_witness::start_block();
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"reservation ordered entry");
    let archive = seal(&mut block, &[hash], &[Hash::new(b"entry without transfer")]);
    let canonical_input = norito::encode_canonical(&archive).unwrap();
    let mut budget = block.fastpq_source_statement_budget(limits()).unwrap();
    assert_eq!(budget.committed_usage(), None);
    let calls = quantity_materializer_invocations_for_testing();
    let attempt = budget.prepare(&block, &archive).unwrap();
    let usage = attempt.usage();
    assert_eq!(usage.executed_entries, 2);
    assert_eq!(usage.transcripts, 2);
    assert_eq!(usage.deltas, 2);
    assert_eq!(quantity_materializer_invocations_for_testing(), calls);
    assert_eq!(budget.committed_usage(), None);
    let bundle = &archive[&hash];
    let bytes = encoded_bundle(bundle);
    let fragments: Vec<_> = bundle
        .iter()
        .map(|transcript| encoded_bundle(std::slice::from_ref(transcript)))
        .collect();
    assert!(bytes > *fragments.iter().max().unwrap());
    assert_ne!(bytes, fragments.iter().sum::<usize>());
    assert_eq!(usage.max_statement_bytes, bytes);
    assert_eq!(usage.total_statement_bytes, bytes);
    assert_eq!(
        usage.input_transcript_bytes,
        bundle
            .iter()
            .map(|t| norito::encode_canonical(t).unwrap().len())
            .sum::<usize>()
    );
    let inventory = block.fastpq_source_inventory().unwrap().unwrap().clone();
    let expected = inventory
        .prepare_transfer_diagnostic(
            block._curr_block.creation_time_ms.saturating_mul(1_000_000),
            crate::fastpq::permission_table_root(block.world.roles.iter()),
            &archive,
            exact(usage),
        )
        .unwrap();
    let mut budget = block.fastpq_source_statement_budget(exact(usage)).unwrap();
    for _ in 0..2 {
        let actual = budget
            .prepare(&block, &archive)
            .unwrap()
            .materialize_diagnostic(&block)
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(budget.committed_usage(), Some(usage));
        assert_eq!(actual.0.executed_entry_count, 2);
        assert_eq!(actual.0.statement_count, 1);
        assert_eq!(actual.1[0].entry_transcript_count, 2);
        assert_eq!(actual.1[0].entry_index, 1);
    }
    assert_eq!(norito::encode_canonical(&archive).unwrap(), canonical_input);
    assert!(block.exec_witness.is_none());
    assert!(block.fastpq_witness_context.is_none());
    assert_eq!(block.fastpq_source_inventory().unwrap(), Some(&inventory));
}

#[test]
fn all_six_inclusive_caps_precede_private_work_and_preserve_state() {
    let _guard = exec_witness::exec_witness_guard();
    exec_witness::start_block();
    let state = state();
    let mut block = state.block(header());
    let archive = seal(
        &mut block,
        &[Hash::new(b"entry A"), Hash::new(b"entry B")],
        &[Hash::new(b"empty time")],
    );
    let mut budget = block.fastpq_source_statement_budget(limits()).unwrap();
    let usage = budget.prepare(&block, &archive).unwrap().usage();
    assert_eq!(usage.executed_entries, 3);
    assert_eq!(usage.transcripts, 4);
    assert_eq!(usage.deltas, 4);
    assert!(usage.total_statement_bytes > usage.max_statement_bytes);
    let exact = exact(usage);
    let before = norito::encode_canonical(&archive).unwrap();
    let inventory = block.fastpq_source_inventory().unwrap().unwrap().clone();
    let calls = quantity_materializer_invocations_for_testing();
    for dimension in 0..6 {
        let mut low = exact;
        let label = match dimension {
            0 => {
                low.max_executed_entries -= 1;
                "executed-entry"
            }
            1 => {
                low.max_transcripts -= 1;
                "transcript occurrence"
            }
            2 => {
                low.max_deltas -= 1;
                "transfer-delta"
            }
            3 => {
                low.max_input_transcript_bytes -= 1;
                "canonical input transcript"
            }
            4 => {
                low.max_statement_bytes -= 1;
                "canonical individual statement bytes"
            }
            _ => {
                low.max_total_statement_bytes -= 1;
                "canonical total statement bytes"
            }
        };
        let result = block
            .fastpq_source_statement_budget(low)
            .and_then(|mut owner| {
                owner
                    .prepare(&block, &archive)?
                    .materialize_diagnostic(&block)
            });
        let error = result.unwrap_err();
        assert!(error.contains(label), "dimension {dimension}: {error}");
        assert_eq!(quantity_materializer_invocations_for_testing(), calls);
        assert_eq!(norito::encode_canonical(&archive).unwrap(), before);
        assert_eq!(block.fastpq_source_inventory().unwrap(), Some(&inventory));
        assert!(block.exec_witness.is_none());
        assert!(block.fastpq_witness_context.is_none());
    }
    let mut exact_owner = block.fastpq_source_statement_budget(exact).unwrap();
    exact_owner
        .prepare(&block, &archive)
        .unwrap()
        .materialize_diagnostic(&block)
        .unwrap();
    assert_eq!(exact_owner.committed_usage(), Some(usage));
}

#[test]
fn empty_archives_count_owned_nontransfer_entries_with_zero_transcript_caps() {
    let _guard = exec_witness::exec_witness_guard();
    let state = state();
    for entries in [0_u32, 1] {
        exec_witness::start_block();
        let mut block = state.block(header());
        let times = if entries == 0 {
            Vec::new()
        } else {
            vec![Hash::new(b"empty entry")]
        };
        let archive = seal(&mut block, &[], &times);
        assert!(archive.is_empty());
        let zero = FastpqSourceStatementBuildLimits {
            max_executed_entries: entries,
            max_transcripts: 0,
            max_deltas: 0,
            max_input_transcript_bytes: 0,
            max_statement_bytes: 0,
            max_total_statement_bytes: 0,
        };
        let mut owner = block.fastpq_source_statement_budget(zero).unwrap();
        let attempt = owner.prepare(&block, &archive).unwrap();
        let usage = attempt.usage();
        assert_eq!(
            usage,
            FastpqSourceStatementUsageV1::from_measured(
                entries,
                FastpqSourceTranscriptUsage::default()
            )
        );
        let calls = quantity_materializer_invocations_for_testing();
        let (manifest, leaves) = attempt.materialize_diagnostic(&block).unwrap();
        assert_eq!(manifest.executed_entry_count, entries);
        assert_eq!(manifest.statement_count, 0);
        assert!(leaves.is_empty());
        assert_eq!(owner.committed_usage(), Some(usage));
        assert_eq!(quantity_materializer_invocations_for_testing(), calls);
        if entries != 0 {
            assert!(
                block
                    .fastpq_source_statement_budget(FastpqSourceStatementBuildLimits {
                        max_executed_entries: 0,
                        ..zero
                    })
                    .is_err()
            );
        }
    }
}

#[test]
fn aborted_failed_and_retried_attempts_preserve_the_previous_complete_reservation() {
    let _guard = exec_witness::exec_witness_guard();
    exec_witness::start_block();
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"atomic reservation");
    let archive = seal(&mut block, &[hash], &[]);
    let mut owner = block.fastpq_source_statement_budget(limits()).unwrap();
    let first = owner.prepare(&block, &archive).unwrap();
    let usage = first.usage();
    first.materialize_diagnostic(&block).unwrap();
    let calls = quantity_materializer_invocations_for_testing();
    let _prepared = owner.prepare(&block, &archive).unwrap();
    assert_eq!(owner.committed_usage(), Some(usage));
    let injected: Result<(), String> = owner
        .prepare(&block, &archive)
        .unwrap()
        .publish_if_success(Err("retained materializer failure".into()));
    assert_eq!(injected.unwrap_err(), "retained materializer failure");
    assert_eq!(owner.committed_usage(), Some(usage));
    let mut omitted = archive.clone();
    omitted.get_mut(&hash).unwrap().pop();
    assert!(owner.prepare(&block, &omitted).is_err());
    assert_eq!(owner.committed_usage(), Some(usage));
    let mut changed = archive.clone();
    changed.get_mut(&hash).unwrap()[0].authority_digest = Hash::new(b"changed authority");
    assert!(owner.prepare(&block, &changed).is_err());
    assert_eq!(owner.committed_usage(), Some(usage));
    assert_eq!(quantity_materializer_invocations_for_testing(), calls);
    owner
        .prepare(&block, &archive)
        .unwrap()
        .materialize_diagnostic(&block)
        .unwrap();
    assert_eq!(owner.committed_usage(), Some(usage));
}

#[test]
fn changed_private_paths_are_remeasured_and_failed_growth_keeps_prior_usage() {
    let _guard = exec_witness::exec_witness_guard();
    exec_witness::start_block();
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"private input accounting");
    let archive = seal(&mut block, &[hash], &[]);
    let mut broad = block.fastpq_source_statement_budget(limits()).unwrap();
    let usage = broad.prepare(&block, &archive).unwrap().usage();
    let mut owner = block.fastpq_source_statement_budget(exact(usage)).unwrap();
    let original_output = owner
        .prepare(&block, &archive)
        .unwrap()
        .materialize_diagnostic(&block)
        .unwrap();
    let mut grown = archive.clone();
    grown.get_mut(&hash).unwrap()[0].deltas[0]
        .from_smt_witness
        .siblings = vec![[9; 32]; 65];
    let calls = quantity_materializer_invocations_for_testing();
    let error = owner.prepare(&block, &grown).unwrap_err();
    assert!(error.contains("canonical input transcript"), "{error}");
    assert_eq!(owner.committed_usage(), Some(usage));
    let attempt = broad.prepare(&block, &grown).unwrap();
    let grown_usage = attempt.usage();
    assert!(grown_usage.input_transcript_bytes > usage.input_transcript_bytes);
    assert_eq!(grown_usage.max_statement_bytes, usage.max_statement_bytes);
    assert_eq!(
        grown_usage.total_statement_bytes,
        usage.total_statement_bytes
    );
    assert_eq!(quantity_materializer_invocations_for_testing(), calls);
    assert_eq!(
        attempt.materialize_diagnostic(&block).unwrap(),
        original_output
    );
    assert_eq!(broad.committed_usage(), Some(grown_usage));
    let retry = broad.prepare(&block, &archive).unwrap();
    assert_eq!(retry.usage(), usage);
    assert_eq!(broad.committed_usage(), Some(grown_usage));
}

#[test]
fn same_entry_discontinuity_is_rejected_without_splitting_or_private_work() {
    let _guard = exec_witness::exec_witness_guard();
    exec_witness::start_block();
    let state = state();
    let mut block = state.block(header());
    cache_canonical_test_transaction_set(&mut block, &[]);
    let hash = Hash::new(b"intervening nontransfer relation remains unavailable");
    let mut tx = block.transaction_for_fastpq_testing(hash);
    // Both single occurrences are arithmetically valid. Together they require an
    // intervening balance change that the current transfer-only relation cannot prove.
    for _ in 0..2 {
        tx.record_test_transfer_transcripts(&ALICE_ID, hash, vec![delta()]);
    }
    tx.apply();
    block
        .finalize_fastpq_source_inventory(&[], &[], &[])
        .unwrap();
    let archive = block.drain_transfer_transcripts_with_pending(None);
    assert_eq!(archive[&hash].len(), 2);
    let mut owner = block.fastpq_source_statement_budget(limits()).unwrap();
    let calls = quantity_materializer_invocations_for_testing();
    let error = owner.prepare(&block, &archive).unwrap_err();
    assert!(
        error.contains("repeated-key balances do not chain"),
        "{error}"
    );
    assert_eq!(quantity_materializer_invocations_for_testing(), calls);
    assert_eq!(owner.committed_usage(), None);
    assert!(block.fastpq_source_inventory().unwrap().is_some());
}

#[test]
fn foreign_equal_inventory_and_late_owner_replacement_fail_before_materialization() {
    let _guard = exec_witness::exec_witness_guard();
    exec_witness::start_block();
    let state = state();
    let mut block = state.block(header());
    let archive = seal(&mut block, &[Hash::new(b"allocation ownership")], &[]);
    let original = block
        .verified_fastpq_source_inventory_for_capture()
        .unwrap();
    // A legitimate independent budget can materialize and publish its usage
    // before any State custody failure has been observed.
    let mut successful = block.fastpq_source_statement_budget(limits()).unwrap();
    successful
        .prepare(&block, &archive)
        .unwrap()
        .materialize_diagnostic(&block)
        .unwrap();
    assert!(successful.committed_usage().is_some());
    let mut owner = block.fastpq_source_statement_budget(limits()).unwrap();
    let calls = quantity_materializer_invocations_for_testing();
    let replacement = Arc::new((*original).clone());
    assert_eq!(replacement.as_ref(), original.as_ref());
    assert!(!Arc::ptr_eq(&replacement, &original));
    // Keep State authentic while testing the reservation's own allocation
    // check, then restore that local owner without poisoning the quota seal.
    owner.inventory = Arc::clone(&replacement);
    assert_eq!(
        owner.prepare(&block, &archive).unwrap_err(),
        "FASTPQ source reservation inventory owner changed"
    );
    assert_eq!(owner.committed_usage(), None);
    assert_eq!(quantity_materializer_invocations_for_testing(), calls);
    owner.inventory = Arc::clone(&original);
    let attempt = owner.prepare(&block, &archive).unwrap();

    // Equal public content in another allocation is not the original State
    // owner. Its quota seal rejects before materialization and fails closed.
    block.fastpq_source_inventory = Some(Ok(replacement));
    assert_eq!(
        attempt.materialize_diagnostic(&block).unwrap_err(),
        "FASTPQ source quota ownership changed after inventory finalization"
    );
    assert_eq!(owner.committed_usage(), None);
    assert!(owner.prepare(&block, &archive).is_err());
    assert_eq!(quantity_materializer_invocations_for_testing(), calls);
    block.fastpq_source_inventory = Some(Ok(original));
    assert_eq!(
        owner.prepare(&block, &archive).unwrap_err(),
        "FASTPQ source quota ownership changed after inventory finalization"
    );
    assert_eq!(owner.committed_usage(), None);
    assert_eq!(quantity_materializer_invocations_for_testing(), calls);
}

#[test]
fn missing_failed_and_stale_state_owners_are_not_reservation_authority() {
    let _guard = exec_witness::exec_witness_guard();
    exec_witness::start_block();
    let state = state();
    let mut block = state.block(header());
    assert!(block.fastpq_source_statement_budget(limits()).is_err());
    let hash = Hash::new(b"source ownership lifecycle");
    let archive = seal(&mut block, &[hash], &[]);
    let mut owner = block.fastpq_source_statement_budget(limits()).unwrap();
    let original = block.fastpq_source_inventory.clone();
    block.fastpq_source_inventory = Some(Err("original latched source failure".into()));
    assert!(block.fastpq_source_statement_budget(limits()).is_err());
    assert!(owner.prepare(&block, &archive).is_err());
    assert_eq!(
        block
            .fastpq_source_inventory
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap_err(),
        "original latched source failure"
    );
    block.fastpq_source_inventory = original;
    let mut late = block.transaction();
    late.tx_call_hash = Some(hash);
    late.record_test_transfer_transcripts(&ALICE_ID, hash, vec![delta()]);
    late.apply();
    assert!(block.fastpq_source_statement_budget(limits()).is_err());
    assert!(owner.prepare(&block, &archive).is_err());
    assert_eq!(owner.committed_usage(), None);
}

#[test]
fn counts_and_derived_construction_ceilings_reject_overflow_atomically() {
    assert_eq!(checked_entry_count(0).unwrap(), 0);
    assert_eq!(checked_entry_count(u32::MAX as usize).unwrap(), u32::MAX);
    if let Some(over) = (u32::MAX as usize).checked_add(1) {
        assert!(checked_entry_count(over).is_err());
    }
    let _guard = exec_witness::exec_witness_guard();
    exec_witness::start_block();
    let state = state();
    let mut block = state.block(header());
    let archive = seal(&mut block, &[], &[]);
    let calls = quantity_materializer_invocations_for_testing();
    for dimension in 0..3 {
        let mut huge = limits();
        match dimension {
            0 => {
                let Some(over) = (u32::MAX as usize).checked_add(1) else {
                    continue;
                };
                huge.max_transcripts = over;
            }
            1 => huge.max_deltas = usize::MAX,
            _ => huge.max_input_transcript_bytes = usize::MAX,
        }
        let result = block
            .fastpq_source_statement_budget(huge)
            .and_then(|mut owner| {
                owner
                    .prepare(&block, &archive)
                    .map(|attempt| attempt.usage())
            });
        assert!(result.is_err(), "dimension {dimension}");
        assert_eq!(quantity_materializer_invocations_for_testing(), calls);
        assert!(block.exec_witness.is_none());
    }
}

#[test]
fn strict_producer_failure_after_successful_preparation_does_not_commit_usage() {
    let _guard = exec_witness::exec_witness_guard();
    exec_witness::start_block();
    let state = state();
    let mut block = state.block(header());
    let archive = seal(&mut block, &[], &[]);
    // The public preparation's checked 2D rows and 4*rows allocation accounting
    // fit. The actual producer's 64*rows tree-hash bound does not. This is an
    // actual strict producer error after a successful cap/seal preparation.
    let huge = FastpqSourceStatementBuildLimits {
        max_deltas: usize::MAX / 16,
        ..limits()
    };
    let mut owner = block.fastpq_source_statement_budget(huge).unwrap();
    let calls = quantity_materializer_invocations_for_testing();
    let attempt = owner.prepare(&block, &archive).unwrap();
    assert_eq!(attempt.usage().executed_entries, 0);
    let error = attempt.materialize_diagnostic(&block).unwrap_err();
    assert_eq!(error, "FASTPQ source tree limits overflow");
    assert_eq!(owner.committed_usage(), None);
    assert_eq!(quantity_materializer_invocations_for_testing(), calls);
    assert!(block.exec_witness.is_none());
    assert!(block.fastpq_witness_context.is_none());
}
