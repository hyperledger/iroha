//! Pure output encoding/identity controls; none of these fixtures authenticate execution.

#[path = "execution_output_ballot_tests.rs"]
mod anonymous_ballot;

use super::*;
use crate::{
    NetworkId, ValidationFail,
    account::AccountId,
    events::{
        data::prelude::{AssetBatchTransferLegStatus, AssetBatchTransferOutcome},
        time::TimeInterval,
    },
    transaction::{
        FeePaymentIntent, TransactionBuilder, error::TransactionRejectionReason,
        signed::SealedTransactionReveal,
    },
    trigger::DataTriggerStep,
};
use iroha_crypto::{Algorithm, KeyPair};

fn input() -> TransactionEntrypoint {
    let key = KeyPair::from_seed(vec![0x42; 32], Algorithm::Ed25519);
    let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"output fixture genesis",
    )));
    let mut builder = TransactionBuilder::new(
        network,
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(std::time::Duration::from_millis(123));
    TransactionEntrypoint::External(builder.sign(key.private_key()))
}

fn proposal() -> HashOf<BlockHeader> {
    HashOf::from_untyped_unchecked(Hash::new(b"immutable proposal identity"))
}

fn trigger() -> TriggerUseV1 {
    TriggerUseV1 {
        trigger_id: "output-root".parse().unwrap(),
        registered_at_height: 3,
        action_hash: Hash::new(b"untrusted model action digest, not State evidence"),
    }
}

fn step() -> ExecutionStep {
    ExecutionStep(iroha_primitives::const_vec::ConstVec::new_empty())
}

fn root_result(trigger: &TriggerUseV1) -> TransactionResult {
    TransactionResult::new(Ok(vec![DataTriggerStep {
        id: trigger.trigger_id.clone(),
        instructions: step(),
    }]))
}

fn pipeline_invocation() -> PipelineInvocationV1 {
    PipelineInvocationV1 {
        event: PipelineEventPositionV1::BlockApproved,
        candidate_index: 4,
        trigger: trigger(),
    }
}

fn time_invocation() -> TimeInvocationV1 {
    TimeInvocationV1 {
        schedule_index: 2,
        event: TimeEvent {
            interval: TimeInterval {
                since_ms: 100,
                length_ms: 20,
            },
        },
        trigger: trigger(),
    }
}

fn completion(trigger: &TriggerUseV1) -> InvocationCompletionV1 {
    InvocationCompletionV1 {
        callback_index: 0,
        trigger_id: trigger.trigger_id.clone(),
        outcome: TriggerCompletedOutcome::Success,
    }
}

fn pipeline() -> ExecutionOutputV1 {
    let invocation = pipeline_invocation();
    ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 {
        result: root_result(&invocation.trigger),
        completions: vec![completion(&invocation.trigger)],
        invocation,
        failure_root: None,
    })
}

fn time() -> ExecutionOutputV1 {
    let invocation = time_invocation();
    ExecutionOutputV1::Time(TimeExecutionOutputV1 {
        result: root_result(&invocation.trigger),
        completions: vec![completion(&invocation.trigger)],
        invocation,
        failure_root: None,
    })
}

fn network() -> ExecutionOutputV1 {
    ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
        input_index: 0,
        result: TransactionResult::new(Ok(Vec::new())),
        completions: Vec::new(),
    })
}

fn rejected() -> TransactionResult {
    TransactionResult::new(Err(TransactionRejectionReason::Validation(
        ValidationFail::NotPermitted("model rejection".into()),
    )))
}

fn receipt() -> AssetBatchTransferOutcome {
    let authority = input().authority_opt().expect("signed fixture").clone();
    AssetBatchTransferOutcome {
        leg_index: 0,
        leg_id: "owned-leg".into(),
        asset: crate::asset::AssetId::new(
            crate::asset::AssetDefinitionId::derive_from_components(
                iroha_model_base::domain::DomainId::try_new("output-test", "universal").unwrap(),
                "coin".parse().unwrap(),
            ),
            authority.clone(),
        ),
        destination: authority,
        amount: iroha_primitives::numeric::Quantity::from(1_u32),
        status: AssetBatchTransferLegStatus::Applied,
    }
}

#[test]
fn execution_output_roundtrips_all_owners_diagnostics_and_exact_receipts() {
    let mut network = network();
    if let ExecutionOutputV1::Network(NetworkExecutionOutputV1 { result, .. }) = &mut network {
        result.set_batch_transfer_outcomes(vec![receipt()]);
    }
    let mut failed = time();
    if let ExecutionOutputV1::Time(TimeExecutionOutputV1 {
        result,
        failure_root,
        completions,
        ..
    }) = &mut failed
    {
        *result = rejected();
        *failure_root = Some(TriggerFailureRootV1::ReturnedBeforeRollback(step()));
        completions[0].outcome = TriggerCompletedOutcome::Failure("rolled back".into());
    }
    let mut declared = failed.clone();
    if let ExecutionOutputV1::Time(TimeExecutionOutputV1 { failure_root, .. }) = &mut declared {
        *failure_root = Some(TriggerFailureRootV1::DeclaredInstructionProjection(step()));
    }
    let mut network_event = pipeline();
    if let ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 { invocation, .. }) =
        &mut network_event
    {
        invocation.event = PipelineEventPositionV1::Network(0);
    }
    for row in [network, pipeline(), network_event, time(), failed, declared] {
        row.validate_structure(8, &[input()]).unwrap();
        let bytes = norito::encode_canonical(&row).unwrap();
        assert_eq!(
            norito::decode_canonical::<ExecutionOutputV1>(&bytes).unwrap(),
            row
        );
        let json = norito::json::to_json(&row).unwrap();
        assert_eq!(
            norito::json::from_str::<ExecutionOutputV1>(&json).unwrap(),
            row
        );
        assert_eq!(
            row.result().batch_transfer_outcomes(),
            row.result().1.as_slice()
        );
        assert_eq!(
            row.completions().len(),
            usize::from(!matches!(
                row,
                ExecutionOutputV1::Network(NetworkExecutionOutputV1 { .. })
            ))
        );
    }
}

#[test]
fn execution_output_json_requires_null_slot_and_rejects_unknown_owner_fields() {
    let original = norito::json::to_value(&time()).unwrap();
    let detail = original.as_object().unwrap().get("detail").unwrap();
    assert!(detail.as_object().unwrap().contains_key("failure_root"));
    let mut omitted = original.clone();
    omitted
        .as_object_mut()
        .unwrap()
        .get_mut("detail")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("failure_root")
        .unwrap();
    assert!(norito::json::from_value::<ExecutionOutputV1>(omitted).is_err());
    let mut foreign = original.clone();
    foreign
        .as_object_mut()
        .unwrap()
        .get_mut("detail")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("entrypoint".into(), norito::json::Value::Null);
    assert!(norito::json::from_value::<ExecutionOutputV1>(foreign).is_err());
    let mut kind = original;
    kind.as_object_mut().unwrap().insert(
        "kind".into(),
        norito::json::Value::String("legacy_time_entrypoint".into()),
    );
    assert!(norito::json::from_value::<ExecutionOutputV1>(kind).is_err());
    let mut action = norito::json::to_value(&trigger()).unwrap();
    action
        .as_object_mut()
        .unwrap()
        .remove("action_hash")
        .unwrap();
    assert!(norito::json::from_value::<TriggerUseV1>(action).is_err());
}

#[test]
fn invocation_identity_commits_every_prebody_field_and_distinct_domains() {
    let original = pipeline_invocation();
    let hash = original.execution_call_hash(proposal()).unwrap();
    assert_eq!(
        hash,
        Hash::new_from_chunks(&[
            PIPELINE_CALL_DOMAIN,
            proposal().as_ref(),
            &norito::encode_canonical(&original).unwrap()
        ])
    );
    let mut mutations = Vec::new();
    let mut changed = original.clone();
    changed.candidate_index += 1;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.event = PipelineEventPositionV1::Network(0);
    mutations.push(changed);
    let mut changed = original.clone();
    changed.trigger.trigger_id = "other-root".parse().unwrap();
    mutations.push(changed);
    let mut changed = original.clone();
    changed.trigger.registered_at_height += 1;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.trigger.action_hash = Hash::new(b"other action");
    mutations.push(changed);
    // Authority is committed inside the actual State-owned action_hash. The Core
    // helper's rekey regression checks that preimage and both invocation calls;
    // there is no independent model authority claim to mutate here.
    for changed in mutations {
        assert_ne!(changed.execution_call_hash(proposal()).unwrap(), hash);
    }
    assert_ne!(
        original
            .execution_call_hash(HashOf::from_untyped_unchecked(Hash::new(
                b"another proposal"
            )))
            .unwrap(),
        hash
    );
    let time = time_invocation();
    assert_eq!(
        time.execution_call_hash(proposal()).unwrap(),
        Hash::new_from_chunks(&[
            TIME_CALL_DOMAIN,
            proposal().as_ref(),
            &norito::encode_canonical(&time).unwrap()
        ])
    );
    assert_ne!(time.execution_call_hash(proposal()).unwrap(), hash);
    assert_ne!(
        invocation_hash(PIPELINE_CALL_DOMAIN, proposal(), &time).unwrap(),
        time.execution_call_hash(proposal()).unwrap()
    );
    let alternative =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let _guard = norito::core::DecodeFlagsGuard::enter(alternative);
    assert_eq!(original.execution_call_hash(proposal()).unwrap(), hash);
}

#[test]
fn equal_time_displays_have_distinct_actual_occurrence_owners() {
    let first = time();
    let mut second = first.clone();
    if let ExecutionOutputV1::Time(TimeExecutionOutputV1 { invocation, .. }) = &mut second {
        invocation.schedule_index = 9;
    }
    assert_eq!(first.result(), second.result());
    assert_ne!(
        first.execution_call_hash(proposal(), &[]).unwrap(),
        second.execution_call_hash(proposal(), &[]).unwrap()
    );
    validate_execution_outputs_v1(&[first, second], proposal(), 8, &[]).unwrap();
    let original = time_invocation();
    let mut changed = original.clone();
    changed.event.interval.since_ms += 1;
    assert_ne!(
        original.execution_call_hash(proposal()).unwrap(),
        changed.execution_call_hash(proposal()).unwrap()
    );
    changed = original.clone();
    changed.event.interval.length_ms += 1;
    assert_ne!(
        original.execution_call_hash(proposal()).unwrap(),
        changed.execution_call_hash(proposal()).unwrap()
    );
}

#[test]
fn output_result_and_receipt_mutation_never_changes_prebody_identity() {
    let mut row = pipeline();
    let original = row.clone();
    let call = row.execution_call_hash(proposal(), &[]).unwrap();
    if let ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 {
        result,
        completions,
        ..
    }) = &mut row
    {
        result.set_batch_transfer_outcomes(vec![receipt()]);
        result.0.as_mut().unwrap().push(DataTriggerStep {
            id: "chained".parse().unwrap(),
            instructions: step(),
        });
        completions.push(InvocationCompletionV1 {
            callback_index: 3,
            trigger_id: "chained".parse().unwrap(),
            outcome: TriggerCompletedOutcome::Success,
        });
    }
    row.validate_structure(8, &[]).unwrap();
    assert_eq!(row.execution_call_hash(proposal(), &[]).unwrap(), call);
    assert_ne!(HashOf::new(&row), HashOf::new(&original));
    assert_ne!(
        norito::encode_canonical(&row).unwrap(),
        norito::encode_canonical(&original).unwrap()
    );
    // Structural acceptance of changed claims is deliberate; only actual Core
    // execution and exact global executed-wire finality authenticate their truth.
}

#[test]
fn execution_output_preserves_sealed_outer_source_and_inner_call_identity() {
    let TransactionEntrypoint::External(signed) = input() else {
        unreachable!()
    };
    let inner = signed.hash_as_entrypoint();
    let first = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
        Hash::new(b"first commitment"),
        signed.clone(),
        [1; 32],
    ));
    let second = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
        Hash::new(b"second commitment"),
        signed,
        [2; 32],
    ));
    assert_ne!(first.hash(), inner);
    assert_ne!(first.hash(), second.hash());
    assert_eq!(
        network()
            .execution_call_hash(proposal(), std::slice::from_ref(&first))
            .unwrap(),
        Hash::from(inner)
    );
    validate_execution_outputs_v1(&[network()], proposal(), 8, std::slice::from_ref(&first))
        .unwrap();
    let mut second_row = network();
    if let ExecutionOutputV1::Network(NetworkExecutionOutputV1 { input_index, .. }) =
        &mut second_row
    {
        *input_index = 1;
    }
    assert!(
        validate_execution_outputs_v1(&[network(), second_row], proposal(), 8, &[first, second])
            .unwrap_err()
            .contains("one execution call")
    );
}

#[test]
fn execution_output_rejects_foreign_sources_phases_and_duplicate_candidates() {
    let inputs = vec![input()];
    let valid = vec![network(), pipeline(), time()];
    validate_execution_outputs_v1(&valid, proposal(), 8, &inputs).unwrap();
    for rows in [
        vec![pipeline(), time()],
        vec![network(), network()],
        vec![pipeline(), network()],
        vec![network(), time(), pipeline()],
        vec![network(), pipeline(), pipeline()],
    ] {
        assert!(validate_execution_outputs_v1(&rows, proposal(), 8, &inputs).is_err());
    }
    let mut foreign = network();
    if let ExecutionOutputV1::Network(NetworkExecutionOutputV1 { input_index, .. }) = &mut foreign {
        *input_index = 1;
    }
    assert!(foreign.validate_structure(8, &inputs).is_err());
    let mut candidate = pipeline();
    if let ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 { invocation, .. }) =
        &mut candidate
    {
        invocation.candidate_index += 1;
    }
    assert!(
        validate_execution_outputs_v1(&[network(), pipeline(), candidate], proposal(), 8, &inputs)
            .is_err()
    );
    let mut wrong_event = pipeline();
    if let ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 { invocation, .. }) =
        &mut wrong_event
    {
        invocation.event = PipelineEventPositionV1::Network(9);
    }
    assert!(wrong_event.validate_structure(8, &inputs).is_err());
}

#[test]
fn execution_output_allows_real_candidate_gaps_but_not_event_order_reversal() {
    let inputs = vec![input()];
    let mut first = pipeline();
    if let ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 { invocation, .. }) = &mut first {
        invocation.event = PipelineEventPositionV1::Network(0);
    }
    let last = pipeline();
    validate_execution_outputs_v1(
        &[network(), first.clone(), last.clone()],
        proposal(),
        8,
        &inputs,
    )
    .unwrap();
    assert!(
        validate_execution_outputs_v1(&[network(), last, first], proposal(), 8, &inputs).is_err()
    );
    validate_execution_outputs_v1(&[pipeline()], proposal(), 8, &[]).unwrap();
    validate_execution_outputs_v1(&[], proposal(), 8, &[]).unwrap();
}

#[test]
fn execution_output_rejects_root_diagnostic_and_rollback_receipt_substitutions() {
    let mut row = time();
    if let ExecutionOutputV1::Time(TimeExecutionOutputV1 { result, .. }) = &mut row {
        result.0 = Ok(Vec::new());
    }
    assert!(row.validate_structure(8, &[]).is_err());
    row = time();
    if let ExecutionOutputV1::Time(TimeExecutionOutputV1 { result, .. }) = &mut row {
        result.0.as_mut().unwrap()[0].id = "wrong-root".parse().unwrap();
    }
    assert!(row.validate_structure(8, &[]).is_err());
    row = time();
    if let ExecutionOutputV1::Time(TimeExecutionOutputV1 { failure_root, .. }) = &mut row {
        *failure_root = Some(TriggerFailureRootV1::ReturnedBeforeRollback(step()));
    }
    assert!(row.validate_structure(8, &[]).is_err());
    row = time();
    if let ExecutionOutputV1::Time(TimeExecutionOutputV1 { result, .. }) = &mut row {
        *result = rejected();
    }
    assert!(row.validate_structure(8, &[]).is_err());
    if let ExecutionOutputV1::Time(TimeExecutionOutputV1 {
        failure_root,
        completions,
        ..
    }) = &mut row
    {
        *failure_root = Some(TriggerFailureRootV1::DeclaredInstructionProjection(step()));
        completions[0].outcome = TriggerCompletedOutcome::Failure("whole invocation failed".into());
    }
    row.validate_structure(8, &[]).unwrap();
    if let ExecutionOutputV1::Time(TimeExecutionOutputV1 { result, .. }) = &mut row {
        result.set_batch_transfer_outcomes(vec![receipt()]);
    }
    assert!(row.validate_structure(8, &[]).is_err());
}

#[test]
fn rejected_network_output_cannot_retain_rolled_back_callback_completions() {
    let inputs = vec![input()];
    let mut row = network();
    let ExecutionOutputV1::Network(output) = &mut row else {
        unreachable!("Network fixture");
    };
    output.completions.push(completion(&trigger()));
    row.validate_structure(8, &inputs).unwrap();
    validate_execution_outputs_v1(std::slice::from_ref(&row), proposal(), 8, &inputs).unwrap();

    let ExecutionOutputV1::Network(output) = &mut row else {
        unreachable!("Network fixture");
    };
    output.result = rejected();
    assert!(row.validate_structure(8, &inputs).is_err());
    assert!(
        validate_execution_outputs_v1(std::slice::from_ref(&row), proposal(), 8, &inputs).is_err()
    );

    let ExecutionOutputV1::Network(output) = &mut row else {
        unreachable!("Network fixture");
    };
    output.completions[0].outcome = TriggerCompletedOutcome::Failure("rolled back".into());
    assert!(row.validate_structure(8, &inputs).is_err());
    assert!(
        validate_execution_outputs_v1(std::slice::from_ref(&row), proposal(), 8, &inputs).is_err()
    );

    let ExecutionOutputV1::Network(output) = &mut row else {
        unreachable!("Network fixture");
    };
    output.completions.clear();
    row.validate_structure(8, &inputs).unwrap();
    validate_execution_outputs_v1(&[row], proposal(), 8, &inputs).unwrap();
}

#[test]
fn rejected_internal_output_retains_only_the_whole_invocation_root_failure() {
    for row in [pipeline(), time()] {
        for diagnostic in [
            TriggerFailureRootV1::ReturnedBeforeRollback(step()),
            TriggerFailureRootV1::DeclaredInstructionProjection(step()),
        ] {
            let mut failed = row.clone();
            let (result, failure_root, completions) = match &mut failed {
                ExecutionOutputV1::Pipeline(output) => (
                    &mut output.result,
                    &mut output.failure_root,
                    &mut output.completions,
                ),
                ExecutionOutputV1::Time(output) => (
                    &mut output.result,
                    &mut output.failure_root,
                    &mut output.completions,
                ),
                ExecutionOutputV1::Network(_) => unreachable!("internal fixture"),
            };
            *result = rejected();
            *failure_root = Some(diagnostic);
            completions[0].outcome =
                TriggerCompletedOutcome::Failure("whole invocation failed".into());
            failed.validate_structure(8, &[]).unwrap();
            validate_execution_outputs_v1(std::slice::from_ref(&failed), proposal(), 8, &[])
                .unwrap();

            for mutation in 0..6 {
                let mut invalid = failed.clone();
                let completions = match &mut invalid {
                    ExecutionOutputV1::Pipeline(output) => &mut output.completions,
                    ExecutionOutputV1::Time(output) => &mut output.completions,
                    ExecutionOutputV1::Network(_) => unreachable!("internal fixture"),
                };
                match mutation {
                    0 => completions[0].outcome = TriggerCompletedOutcome::Success,
                    1 => completions[0].callback_index = 1,
                    2 => completions[0].trigger_id = "different-root".parse().unwrap(),
                    3 => completions.clear(),
                    4 | 5 => completions.push(InvocationCompletionV1 {
                        callback_index: 1,
                        trigger_id: "rolled-back-nested-callback".parse().unwrap(),
                        outcome: if mutation == 4 {
                            TriggerCompletedOutcome::Success
                        } else {
                            TriggerCompletedOutcome::Failure("nested failure".into())
                        },
                    }),
                    _ => unreachable!(),
                }
                assert!(
                    invalid.validate_structure(8, &[]).is_err(),
                    "mutation {mutation}"
                );
                assert!(
                    validate_execution_outputs_v1(&[invalid], proposal(), 8, &[]).is_err(),
                    "mutation {mutation}"
                );
            }
        }
    }
}

#[test]
fn execution_output_rejects_invalid_chronology_intervals_and_completion_positions() {
    let mut row = time();
    if let ExecutionOutputV1::Time(TimeExecutionOutputV1 { invocation, .. }) = &mut row {
        invocation.trigger.registered_at_height = 8;
    }
    assert!(row.validate_structure(8, &[]).is_err());
    row = time();
    if let ExecutionOutputV1::Time(TimeExecutionOutputV1 { invocation, .. }) = &mut row {
        invocation.event.interval.since_ms = u64::MAX;
    }
    assert!(row.validate_structure(8, &[]).is_err());
    assert!(row.execution_call_hash(proposal(), &[]).is_err());
    row = pipeline();
    if let ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 { completions, .. }) = &mut row {
        completions.push(completions[0].clone());
    }
    assert!(row.validate_structure(8, &[]).is_err());
    row = pipeline();
    if let ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 { completions, .. }) = &mut row {
        completions[0].trigger_id = "foreign-root".parse().unwrap();
    }
    assert!(row.validate_structure(8, &[]).is_err());
    let mut invocation = pipeline_invocation();
    invocation.trigger.action_hash = Hash::prehashed([0; Hash::LENGTH]);
    assert!(invocation.execution_call_hash(proposal()).is_err());
    assert!(
        pipeline_invocation()
            .execution_call_hash(HashOf::from_untyped_unchecked(Hash::prehashed(
                [0; Hash::LENGTH]
            )))
            .is_err()
    );
    assert!(validate_execution_outputs_v1(&[], proposal(), 0, &[]).is_err());
    let mut other_interval = time();
    if let ExecutionOutputV1::Time(TimeExecutionOutputV1 { invocation, .. }) = &mut other_interval {
        invocation.schedule_index += 1;
        invocation.event.interval.length_ms += 1;
    }
    assert!(validate_execution_outputs_v1(&[time(), other_interval], proposal(), 8, &[]).is_err());
    assert!(validate_execution_outputs_v1(&[time(), time()], proposal(), 8, &[]).is_err());
}

#[test]
fn synthetic_time_entrypoint_cannot_decode_or_own_a_network_output() {
    // Reproduce the retired bytes locally; no production compatibility type or
    // decoder remains merely to keep this negative wire test constructible.
    #[derive(Encode, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::trigger::time::TimeTriggerEntrypoint")]
    struct RetiredTimeEntrypoint {
        id: TriggerId,
        instructions: ExecutionStep,
        authority: AccountId,
    }
    #[derive(Encode, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::signed::model::TransactionEntrypoint")]
    enum RetiredNetworkTime {
        #[codec(index = 3)]
        Time(RetiredTimeEntrypoint),
    }
    let old = RetiredTimeEntrypoint {
        id: trigger().trigger_id,
        authority: input().authority_opt().expect("signed fixture").clone(),
        instructions: step(),
    };
    assert!(
        norito::decode_canonical::<ExecutionOutputV1>(&norito::encode_canonical(&old).unwrap())
            .is_err()
    );
    let retired_network = norito::encode_canonical(&RetiredNetworkTime::Time(old)).unwrap();
    assert!(norito::decode_canonical::<TransactionEntrypoint>(&retired_network).is_err());
    // A scheduled output supplies no network input at all.
    assert!(network().validate_structure(8, &[]).is_err());
    assert!(network().execution_call_hash(proposal(), &[]).is_err());
    let mut bytes = norito::encode_canonical(&time()).unwrap();
    bytes.push(0);
    assert!(norito::decode_canonical::<ExecutionOutputV1>(&bytes).is_err());
}

#[test]
fn bounded_output_limit_terminals_roundtrip_and_preserve_invocation_identity() {
    let inputs = [input()];
    let cases = [
        (
            network(),
            ExecutionOutputV1::network_output_limit_rejection(0),
        ),
        (
            pipeline(),
            ExecutionOutputV1::pipeline_output_limit_rejection(pipeline_invocation()),
        ),
        (
            time(),
            ExecutionOutputV1::time_output_limit_rejection(time_invocation()),
        ),
    ];
    for (original, terminal) in cases {
        assert!(terminal.is_output_limit_rejection());
        terminal.validate_structure(8, &inputs).unwrap();
        assert_eq!(
            terminal.execution_call_hash(proposal(), &inputs).unwrap(),
            original.execution_call_hash(proposal(), &inputs).unwrap()
        );
        let bytes = norito::encode_canonical(&terminal).unwrap();
        assert_eq!(norito::canonical_frame_len(&terminal).unwrap(), bytes.len());
        assert_eq!(
            norito::decode_canonical::<ExecutionOutputV1>(&bytes).unwrap(),
            terminal
        );
        assert!(terminal.result().batch_transfer_outcomes().is_empty());
    }
}

#[test]
fn omitted_failure_root_requires_exact_typed_terminal_and_only_root_completion() {
    let terminal = ExecutionOutputV1::pipeline_output_limit_rejection(pipeline_invocation());
    for fault in 0..6 {
        let mut altered = terminal.clone();
        let ExecutionOutputV1::Pipeline(output) = &mut altered else {
            unreachable!()
        };
        match fault {
            0 => {
                output.result = TransactionResult::new(Err(ValidationFail::NotPermitted(
                    EXECUTION_OUTPUT_LIMIT_REASON.into(),
                )
                .into()))
            }
            1 => output.completions.clear(),
            2 => output.completions[0].callback_index = 1,
            3 => output.completions[0].trigger_id = "foreign-root".parse().unwrap(),
            4 => output.completions[0].outcome = TriggerCompletedOutcome::Success,
            _ => output.completions.push(output.completions[0].clone()),
        }
        assert!(!altered.is_output_limit_rejection(), "fault {fault}");
        assert!(altered.validate_structure(8, &[]).is_err(), "fault {fault}");
    }
}

#[test]
fn bounded_terminal_does_not_hide_receipts_or_ordinary_failure_diagnostics() {
    let mut receipt_terminal =
        ExecutionOutputV1::pipeline_output_limit_rejection(pipeline_invocation());
    let ExecutionOutputV1::Pipeline(output) = &mut receipt_terminal else {
        unreachable!()
    };
    output.result.set_batch_transfer_outcomes(vec![receipt()]);
    assert!(!receipt_terminal.is_output_limit_rejection());
    assert!(receipt_terminal.validate_structure(8, &[]).is_err());

    let mut terminal = ExecutionOutputV1::time_output_limit_rejection(time_invocation());
    let ExecutionOutputV1::Time(output) = &mut terminal else {
        unreachable!()
    };
    output.failure_root = Some(TriggerFailureRootV1::ReturnedBeforeRollback(step()));
    assert!(!terminal.is_output_limit_rejection());

    let mut network_terminal = ExecutionOutputV1::network_output_limit_rejection(0);
    let ExecutionOutputV1::Network(output) = &mut network_terminal else {
        unreachable!()
    };
    output.completions.push(completion(&trigger()));
    assert!(!network_terminal.is_output_limit_rejection());

    let mut failed = pipeline();
    let ExecutionOutputV1::Pipeline(output) = &mut failed else {
        unreachable!()
    };
    output.failure_root = Some(TriggerFailureRootV1::OmittedByOutputLimit);
    assert!(failed.validate_structure(8, &[]).is_err());
}

#[test]
fn pipeline_network_event_requires_actual_signed_transaction_source_kind() {
    use crate::transaction::signed::{
        SealedTransactionCommitmentPayload, SignedSealedTransactionCommitment,
    };

    let key = KeyPair::from_seed(vec![0x24; 32], Algorithm::Ed25519);
    let payload = SealedTransactionCommitmentPayload::new(
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"sealed output fixture network",
        ))),
        AccountId::new(key.public_key().clone()),
        Hash::new(b"sealed output fixture commitment"),
        4,
        10,
        None,
    );
    let sealed = TransactionEntrypoint::SealedCommitment(SignedSealedTransactionCommitment::sign(
        payload,
        key.private_key(),
    ));
    validate_execution_outputs_v1(
        &[network(), pipeline()],
        proposal(),
        8,
        std::slice::from_ref(&sealed),
    )
    .unwrap();
    let mut event = pipeline();
    if let ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 { invocation, .. }) = &mut event {
        invocation.event = PipelineEventPositionV1::Network(0);
    }
    assert!(
        event
            .validate_structure(8, &[sealed])
            .unwrap_err()
            .contains("no signed transaction event")
    );
    let TransactionEntrypoint::External(signed) = input() else {
        unreachable!()
    };
    let reveal = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
        Hash::new(b"revealed output fixture commitment"),
        signed,
        [9; 32],
    ));
    validate_execution_outputs_v1(&[network(), event], proposal(), 8, &[reveal]).unwrap();
}

#[test]
fn execution_inputs_borrow_slices_arrays_vectors_and_block_sources() {
    fn check<S: ExecutionInputs + ?Sized>(source: &S, expected: &TransactionEntrypoint) {
        assert_eq!(source.input_count(), 1);
        assert!(std::ptr::eq(source.input_at(0).unwrap(), expected));
        assert!(source.input_at(1).is_none());
        validate_execution_outputs_v1(&[network(), pipeline(), time()], proposal(), 8, source)
            .unwrap();
    }
    let array = [input()];
    check(&array, &array[0]);
    check(array.as_slice(), &array[0]);
    let vector = Vec::from(array);
    check(&vector, &vector[0]);

    let header = BlockHeader::new(8.try_into().unwrap(), None, None, 123, 0);
    let mut builder = crate::block::builder::BlockBuilder::new(header);
    let TransactionEntrypoint::External(signed) = input() else {
        unreachable!()
    };
    builder.push_transaction(signed);
    let block = builder.build(crate::block::BlockSignatures::default());
    check(&block, block.network_entrypoint_at(0).unwrap());
}

#[test]
fn execution_input_validation_uses_bounded_random_access() {
    struct CountedInput {
        entry: TransactionEntrypoint,
        lookups: std::cell::Cell<usize>,
    }
    impl ExecutionInputs for CountedInput {
        fn input_count(&self) -> usize {
            1
        }
        fn input_at(&self, index: usize) -> Option<&TransactionEntrypoint> {
            self.lookups.set(self.lookups.get() + 1);
            (index == 0).then_some(&self.entry)
        }
    }
    let source = CountedInput {
        entry: input(),
        lookups: std::cell::Cell::new(0),
    };
    let mut rows = vec![network()];
    for candidate_index in 0..32 {
        let mut row = pipeline();
        let ExecutionOutputV1::Pipeline(value) = &mut row else {
            unreachable!()
        };
        value.invocation.event = PipelineEventPositionV1::Network(0);
        value.invocation.candidate_index = candidate_index;
        value.invocation.trigger.trigger_id = format!("root-{candidate_index}").parse().unwrap();
        value.result = root_result(&value.invocation.trigger);
        value.completions = vec![completion(&value.invocation.trigger)];
        rows.push(row);
    }
    validate_execution_outputs_v1(&rows, proposal(), 8, &source).unwrap();
    assert_eq!(
        source.lookups.get(),
        34,
        "two network checks, one lookup per event"
    );
}

#[test]
fn trigger_use_rejects_retired_parallel_authority_slot() {
    use norito::codec::DecodeAll as _;

    #[derive(Encode, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::block::execution_output::TriggerUseV1")]
    struct RetiredTriggerUse {
        trigger_id: TriggerId,
        authority: AccountId,
        registered_at_height: u64,
        action_hash: Hash,
    }
    let current = trigger();
    let json = norito::json::to_value(&current).unwrap();
    assert!(!json.as_object().unwrap().contains_key("authority"));
    for value in [
        norito::json::Value::Null,
        norito::json::to_value(input().authority_opt().expect("signed fixture")).unwrap(),
    ] {
        let mut retired = json.clone();
        retired
            .as_object_mut()
            .unwrap()
            .insert("authority".into(), value);
        assert!(norito::json::from_value::<TriggerUseV1>(retired).is_err());
    }

    let retired = RetiredTriggerUse {
        trigger_id: current.trigger_id.clone(),
        authority: input().authority_opt().expect("signed fixture").clone(),
        registered_at_height: current.registered_at_height,
        action_hash: current.action_hash,
    };
    let payload = retired.encode();
    assert!(TriggerUseV1::decode_all(&mut payload.as_slice()).is_err());
    assert!(
        norito::decode_canonical::<TriggerUseV1>(&norito::encode_canonical(&retired).unwrap())
            .is_err()
    );
    let payload = current.encode();
    assert_eq!(
        TriggerUseV1::decode_all(&mut payload.as_slice()).unwrap(),
        current
    );
}

#[test]
fn bounded_terminals_roundtrip_maximum_trigger_name_and_scalar_positions() {
    let trigger = TriggerUseV1 {
        trigger_id: "x"
            .repeat(iroha_model_base::name::MAX_NAME_BYTES)
            .parse()
            .unwrap(),
        registered_at_height: u64::MAX - 1,
        action_hash: Hash::new(b"bounded descriptor test; no authority claim"),
    };
    assert!(
        "x".repeat(iroha_model_base::name::MAX_NAME_BYTES + 1)
            .parse::<TriggerId>()
            .is_err()
    );
    let rows = [
        ExecutionOutputV1::pipeline_output_limit_rejection(PipelineInvocationV1 {
            event: PipelineEventPositionV1::Network(u32::MAX),
            candidate_index: u32::MAX,
            trigger: trigger.clone(),
        }),
        ExecutionOutputV1::time_output_limit_rejection(TimeInvocationV1 {
            schedule_index: u32::MAX,
            event: TimeEvent {
                interval: TimeInterval {
                    since_ms: u64::MAX - 1,
                    length_ms: 1,
                },
            },
            trigger,
        }),
    ];
    // These are sizing/codec fixtures, not admissible source positions or a live
    // capacity policy. Model source validation still rejects absent Network input.
    for row in rows {
        assert!(row.is_output_limit_rejection());
        let bytes = norito::encode_canonical(&row).unwrap();
        assert_eq!(
            norito::decode_canonical::<ExecutionOutputV1>(&bytes).unwrap(),
            row
        );
        let mut changed = row.clone();
        match &mut changed {
            ExecutionOutputV1::Pipeline(row) => {
                row.invocation.trigger.action_hash = Hash::new(b"different actual action digest");
            }
            ExecutionOutputV1::Time(row) => {
                row.invocation.trigger.action_hash = Hash::new(b"different actual action digest");
            }
            ExecutionOutputV1::Network(_) => unreachable!(),
        }
        assert_eq!(
            norito::encode_canonical(&changed).unwrap().len(),
            bytes.len()
        );
        assert_ne!(changed, row);
    }
}

fn omitted_internal_rejection(mut row: ExecutionOutputV1) -> ExecutionOutputV1 {
    let (result, root, completions) = match &mut row {
        ExecutionOutputV1::Pipeline(row) => {
            (&mut row.result, &mut row.failure_root, &mut row.completions)
        }
        ExecutionOutputV1::Time(row) => {
            (&mut row.result, &mut row.failure_root, &mut row.completions)
        }
        ExecutionOutputV1::Network(_) => panic!("internal fixture"),
    };
    *result = TransactionResult::new(Err(TransactionRejectionReason::LimitCheck(
        crate::transaction::error::TransactionLimitError {
            reason: INTERNAL_REJECTION_DIAGNOSTIC_OMITTED.into(),
        },
    )));
    *root = Some(TriggerFailureRootV1::OmittedAfterRejection);
    completions[0].outcome =
        TriggerCompletedOutcome::Failure(INTERNAL_REJECTION_DIAGNOSTIC_OMITTED.into());
    row
}

#[test]
fn omitted_internal_rejection_has_a_distinct_exact_roundtrip_shape() {
    for terminal in [
        ExecutionOutputV1::pipeline_output_limit_rejection(pipeline_invocation()),
        ExecutionOutputV1::time_output_limit_rejection(time_invocation()),
    ] {
        assert!(!terminal.is_internal_rejection_diagnostic_omitted());
        let row = omitted_internal_rejection(terminal.clone());
        assert!(row.is_internal_rejection_diagnostic_omitted());
        assert!(!row.is_output_limit_rejection());
        row.validate_structure(8, &[input()]).unwrap();
        assert_eq!(
            row.execution_call_hash(proposal(), &[input()]).unwrap(),
            terminal
                .execution_call_hash(proposal(), &[input()])
                .unwrap()
        );
        let bytes = norito::encode_canonical(&row).unwrap();
        assert_eq!(
            norito::decode_canonical::<ExecutionOutputV1>(&bytes).unwrap(),
            row
        );
        assert!(bytes.len() <= norito::encode_canonical(&terminal).unwrap().len());
        let json = norito::json::to_json(&row).unwrap();
        assert!(json.contains("omitted_after_rejection"));
        assert_eq!(
            norito::json::from_str::<ExecutionOutputV1>(&json).unwrap(),
            row
        );
    }
    assert!(!network().is_internal_rejection_diagnostic_omitted());
    let variant = TriggerFailureRootV1::OmittedAfterRejection;
    let bytes = norito::encode_canonical(&variant).unwrap();
    assert_eq!(
        norito::decode_canonical::<TriggerFailureRootV1>(&bytes).unwrap(),
        variant
    );
}

#[test]
fn omitted_internal_rejection_refuses_tampered_result_root_completion_and_receipts() {
    for terminal in [
        ExecutionOutputV1::pipeline_output_limit_rejection(pipeline_invocation()),
        ExecutionOutputV1::time_output_limit_rejection(time_invocation()),
    ] {
        let valid = omitted_internal_rejection(terminal);
        for fault in 0..12 {
            let mut invalid = valid.clone();
            let (result, root, completions) = match &mut invalid {
                ExecutionOutputV1::Pipeline(row) => {
                    (&mut row.result, &mut row.failure_root, &mut row.completions)
                }
                ExecutionOutputV1::Time(row) => {
                    (&mut row.result, &mut row.failure_root, &mut row.completions)
                }
                ExecutionOutputV1::Network(_) => unreachable!(),
            };
            match fault {
                0 => *result = rejected(),
                1 => {
                    *result = TransactionResult::new(Err(TransactionRejectionReason::Validation(
                        ValidationFail::NotPermitted(INTERNAL_REJECTION_DIAGNOSTIC_OMITTED.into()),
                    )))
                }
                2 => *result = TransactionResult::new(Ok(Vec::new())),
                3 => *root = None,
                4 => *root = Some(TriggerFailureRootV1::OmittedByOutputLimit),
                5 => completions.clear(),
                6 => completions[0].outcome = TriggerCompletedOutcome::Success,
                7 => {
                    completions[0].outcome =
                        TriggerCompletedOutcome::Failure("different diagnostic".into())
                }
                8 => completions[0].callback_index = 1,
                9 => completions[0].trigger_id = "foreign-root".parse().unwrap(),
                10 => completions.push(completions[0].clone()),
                _ => result.set_batch_transfer_outcomes(vec![receipt()]),
            }
            assert!(
                !invalid.is_internal_rejection_diagnostic_omitted(),
                "fault {fault}"
            );
            assert!(
                invalid.validate_structure(8, &[input()]).is_err(),
                "fault {fault}"
            );
        }
    }
}
