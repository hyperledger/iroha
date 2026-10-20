//! Anonymous output shape controls using codec-only, unverified ballot fixtures.

use super::*;
use crate::{
    block::{
        BlockSignatures, SetExecutionOutputsError, SignedBlock,
        builder::BlockBuilder,
        consensus::{NexusFeeReceipt, NexusFeeScheduleInputs, NexusFeeSettlementV1},
        decode_framed_signed_block,
        output_budget::ExecutionOutputLimits,
    },
    governance::anonymous_ballot::{
        AnonymousBallotRejectionV1, BallotChoiceV1, CanonicalAnonymousBallotEnvelopeV1,
        test_fixtures::envelope,
    },
    nexus::FeeDebitSource,
    smart_contract::{
        entrypoint::{
            EntrypointReturnRecordV1, EntrypointStructTypeNodeV1, EntrypointValueTypeNodeV1,
            EntrypointValueTypeV1, entrypoint_return_schema_hash_v1,
        },
        event::{ContractEmissionV1, ContractEmissionsV1, ContractEventDescriptorV1},
    },
    transaction::{
        FeeChargeKind, FeeChargeLimit,
        error::TriggerExecutionFail,
        signed::{SealedTransactionCommitmentPayload, SignedSealedTransactionCommitment},
    },
};
use iroha_model_base::topology::{DataSpaceId, LaneId};
use iroha_primitives::numeric::Quantity;
use std::num::NonZeroU64;

fn anonymous_input() -> TransactionEntrypoint {
    TransactionEntrypoint::AnonymousBallot(
        CanonicalAnonymousBallotEnvelopeV1::from_envelope(&envelope(BallotChoiceV1::Aye, 1))
            .unwrap(),
    )
}

fn anonymous_outcomes() -> [ExecutionOutputV1; 3] {
    [
        network(),
        ballot_rejection(AnonymousBallotRejectionV1::OutsideCastingWindow),
        ballot_rejection(AnonymousBallotRejectionV1::DuplicateNullifier),
    ]
}

fn ballot_rejection(reason: AnonymousBallotRejectionV1) -> ExecutionOutputV1 {
    ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
        input_index: 0,
        result: TransactionResult::new(Err(TransactionRejectionReason::AnonymousBallot(reason))),
        completions: vec![],
    })
}

fn fee_fixture() -> (TransactionEntrypoint, NexusFeeReceipt) {
    let key = KeyPair::from_seed(vec![0x67; 32], Algorithm::Ed25519);
    let authority = AccountId::new(key.public_key().clone());
    let asset: crate::asset::AssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa".parse().unwrap();
    let intent = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            asset.clone(),
            Quantity::from(10_u32),
        )],
        None,
    );
    let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"anonymous output fee control",
    )));
    let mut builder = TransactionBuilder::new(network, authority.clone(), intent);
    builder.set_creation_time(std::time::Duration::from_millis(123));
    let signed = builder.sign(key.private_key());
    let tx_bytes_len = norito::canonical_frame_len(signed.payload()).unwrap() as u64;
    let input = TransactionEntrypoint::External(signed);
    let receipt = NexusFeeReceipt {
        version: NexusFeeReceipt::VERSION,
        source_id: *Hash::from(input.hash()).as_ref(),
        dataspace_id: DataSpaceId::UNIVERSAL,
        lane_id: LaneId::new(1),
        block_height: 8,
        debit_source: FeeDebitSource::Account(authority),
        fee_asset_id: asset,
        program_revision: None,
        lease_id: None,
        fee_amount: Quantity::from(2_u32),
        settlement: NexusFeeSettlementV1::Burn,
        schedule: NexusFeeScheduleInputs {
            tx_bytes_len,
            instruction_count: 0,
            gas_used: 0,
            base_fee: Quantity::from(2_u32),
            per_byte_fee: Quantity::zero(),
            per_instruction_fee: Quantity::zero(),
            per_gas_unit_fee: Quantity::zero(),
        },
    };
    (input, receipt)
}

fn emissions() -> ContractEmissionsV1 {
    let payload_type = EntrypointValueTypeV1 {
        nodes: vec![EntrypointValueTypeNodeV1::Struct(
            EntrypointStructTypeNodeV1 {
                name: "Fixture::Accepted".into(),
                fields: vec![],
            },
        )],
    };
    let schema = norito::encode_canonical(&payload_type).unwrap();
    ContractEmissionsV1::from_untrusted(vec![ContractEmissionV1 {
        contract: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .unwrap(),
        code_hash: Hash::new(b"untrusted output emission fixture"),
        entrypoint: 0,
        event: 0,
        caller: input().authority_opt().expect("signed fixture").clone(),
        definition: ContractEventDescriptorV1 {
            name: "Accepted".parse().unwrap(),
            payload_type,
        },
        payload: EntrypointReturnRecordV1 {
            schema_hash: entrypoint_return_schema_hash_v1(&schema),
            atoms: vec![],
        },
    }])
}

#[test]
fn anonymous_ballot_outputs_roundtrip_all_three_canonical_outcomes() {
    let inputs = [anonymous_input()];
    let mut hashes = BTreeSet::new();
    for row in anonymous_outcomes() {
        row.validate_structure(8, &inputs).unwrap();
        validate_execution_outputs_v1(std::slice::from_ref(&row), proposal(), 8, &inputs).unwrap();
        let bytes = norito::encode_canonical(&row).unwrap();
        let decoded = norito::decode_canonical::<ExecutionOutputV1>(&bytes).unwrap();
        assert_eq!(decoded, row);
        decoded.validate_structure(8, &inputs).unwrap();
        let json = norito::json::to_json(&row).unwrap();
        assert_eq!(
            norito::json::from_str::<ExecutionOutputV1>(&json).unwrap(),
            row
        );
        assert!(hashes.insert(row.result().hash()));
        assert!(row.completions().is_empty());
        assert!(row.result().batch_transfer_outcomes().is_empty());
        assert!(row.result().nexus_fee_receipt().is_none());
        assert!(row.result().contract_events().is_empty());
        assert!(!row.is_output_limit_rejection());
    }
    assert_eq!(hashes.len(), 3);
}

#[test]
fn identical_anonymous_inputs_keep_distinct_results_and_canonical_source_positions() {
    let TransactionEntrypoint::AnonymousBallot(carrier) = anonymous_input() else {
        unreachable!()
    };
    let mut builder = BlockBuilder::new(BlockHeader::new(
        NonZeroU64::new(8).unwrap(),
        None,
        None,
        1_000,
        0,
    ));
    assert_eq!(builder.push_anonymous_ballot(carrier.clone()), 0);
    assert_eq!(builder.push_anonymous_ballot(carrier), 1);
    let mut block = builder.build(BlockSignatures::default());
    let mut duplicate = ballot_rejection(AnonymousBallotRejectionV1::DuplicateNullifier);
    let ExecutionOutputV1::Network(row) = &mut duplicate else {
        unreachable!()
    };
    row.input_index = 1;
    let rows = vec![network(), duplicate];
    assert_eq!(
        rows[0].execution_call_hash(block.hash(), &block).unwrap(),
        rows[1].execution_call_hash(block.hash(), &block).unwrap()
    );
    let limits = ExecutionOutputLimits {
        max_outputs: 2,
        max_output_bytes: 16 * 1024,
        max_total_output_bytes: 32 * 1024,
        max_executed_wire_bytes: 1024 * 1024,
    };
    let install = |block: &mut SignedBlock, rows| {
        block.set_execution_outputs(
            rows,
            0,
            BTreeMap::new(),
            vec![],
            Default::default(),
            BTreeSet::new(),
            &limits,
        )
    };
    // These codec fixtures assert source/result shape, not proof verification or
    // the execution verdict. Core must establish the first-accepted/second-rejected facts.
    install(&mut block, rows.clone()).expect("two occurrences of one anonymous envelope");
    let wire = block.encode_wire().unwrap();
    let decoded = decode_framed_signed_block(&wire).unwrap();
    assert_eq!(decoded, block);
    decoded.validate_execution_result_structure().unwrap();
    assert_eq!(decoded.execution_outputs(), rows);
    assert_eq!(
        decoded.network_entrypoint_at(0),
        decoded.network_entrypoint_at(1)
    );
    assert_ne!(HashOf::new(&rows[0]), HashOf::new(&rows[1]));
    for index in [0, 1] {
        let (output_index, row) = decoded.network_output_at(index).unwrap();
        assert_eq!(output_index, index);
        assert_eq!(row.input_index, index);
        assert_eq!(&row.result, rows[index as usize].result());
    }

    // Hash repetition does not authorize duplicated, reordered, missing or foreign
    // source positions. Refused replacement leaves the existing executed wire intact.
    for mutation in 0..4 {
        let mut invalid = rows.clone();
        match mutation {
            0 | 3 => {
                let ExecutionOutputV1::Network(row) = &mut invalid[1] else {
                    unreachable!()
                };
                row.input_index = if mutation == 0 { 0 } else { 2 };
            }
            1 => invalid.swap(0, 1),
            2 => {
                invalid.pop();
            }
            _ => unreachable!(),
        }
        let mut candidate = block.clone();
        assert!(matches!(
            install(&mut candidate, invalid),
            Err(SetExecutionOutputsError::InvalidOutputs(_))
        ));
        assert_eq!(candidate.encode_wire().unwrap(), wire);
    }
}

#[test]
fn anonymous_ballot_outputs_refuse_each_side_output_on_success_and_rejection() {
    let inputs = [anonymous_input()];
    let (ordinary_input, fee) = fee_fixture();
    // The same side-output values are well-formed on an ordinary signed owner.
    // Their refusal below comes from the anonymous ownership rule.
    let mut ordinary = network();
    let ExecutionOutputV1::Network(output) = &mut ordinary else {
        unreachable!()
    };
    output.completions.push(completion(&trigger()));
    output.result.set_batch_transfer_outcomes(vec![receipt()]);
    output.result.set_nexus_fee_receipt(Some(fee.clone()));
    output.result.set_contract_events(emissions());
    ordinary.validate_structure(8, &[ordinary_input]).unwrap();

    for original in anonymous_outcomes() {
        for mutation in 0..5 {
            let mut row = original.clone();
            let ExecutionOutputV1::Network(output) = &mut row else {
                unreachable!()
            };
            match mutation {
                0 | 1 => {
                    let mut callback = completion(&trigger());
                    if mutation == 1 {
                        callback.outcome = TriggerCompletedOutcome::Failure("failed".into());
                    }
                    output.completions.push(callback);
                }
                2 => output.result.set_batch_transfer_outcomes(vec![receipt()]),
                3 => output.result.set_nexus_fee_receipt(Some(fee.clone())),
                4 => output.result.set_contract_events(emissions()),
                _ => unreachable!(),
            }
            let expected = "anonymous ballot output cannot retain side outputs";
            assert_eq!(row.validate_structure(8, &inputs).unwrap_err(), expected);
            assert_eq!(
                validate_execution_outputs_v1(&[row], proposal(), 8, &inputs).unwrap_err(),
                expected
            );
        }
    }
}

#[test]
fn anonymous_ballot_outputs_refuse_trigger_success_and_ordinary_rejections() {
    let inputs = [anonymous_input()];
    let ExecutionOutputV1::Network(limit) = ExecutionOutputV1::network_output_limit_rejection(0)
    else {
        unreachable!()
    };
    for result in [
        root_result(&trigger()),
        rejected(),
        limit.result,
        TransactionResult::new(Err(TransactionRejectionReason::TriggerExecution(
            TriggerExecutionFail::MaxDepthExceeded,
        ))),
    ] {
        let row = ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
            input_index: 0,
            result,
            completions: vec![],
        });
        let expected =
            "anonymous ballot output must be an empty success or a canonical ballot rejection";
        assert_eq!(row.validate_structure(8, &inputs).unwrap_err(), expected);
        assert_eq!(
            validate_execution_outputs_v1(&[row], proposal(), 8, &inputs).unwrap_err(),
            expected
        );
    }
}

#[test]
fn ordinary_network_and_internal_outputs_refuse_ballot_rejection_reasons() {
    let TransactionEntrypoint::External(signed) = input() else {
        unreachable!()
    };
    let reveal = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
        Hash::new(b"ballot result ordinary reveal control"),
        signed,
        [9; 32],
    ));
    let key = KeyPair::from_seed(vec![0x24; 32], Algorithm::Ed25519);
    let payload = SealedTransactionCommitmentPayload::new(
        crate::governance::anonymous_ballot::test_fixtures::network_id(),
        AccountId::new(key.public_key().clone()),
        Hash::new(b"ballot result ordinary commitment control"),
        4,
        10,
        None,
    );
    let sealed = TransactionEntrypoint::SealedCommitment(SignedSealedTransactionCommitment::sign(
        payload,
        key.private_key(),
    ));
    for reason in [
        AnonymousBallotRejectionV1::OutsideCastingWindow,
        AnonymousBallotRejectionV1::DuplicateNullifier,
    ] {
        for source in [input(), sealed.clone(), reveal.clone()] {
            let inputs = [source];
            network().validate_structure(8, &inputs).unwrap();
            let row = ballot_rejection(reason);
            let expected = "ordinary Network output cannot contain an anonymous ballot rejection";
            assert_eq!(row.validate_structure(8, &inputs).unwrap_err(), expected);
            assert_eq!(
                validate_execution_outputs_v1(&[row], proposal(), 8, &inputs).unwrap_err(),
                expected
            );
        }
        for mut row in [pipeline(), time()] {
            let (result, diagnostic, completions) = match &mut row {
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
                ExecutionOutputV1::Network(_) => unreachable!(),
            };
            *result =
                TransactionResult::new(Err(TransactionRejectionReason::AnonymousBallot(reason)));
            *diagnostic = Some(TriggerFailureRootV1::DeclaredInstructionProjection(step()));
            completions[0].outcome = TriggerCompletedOutcome::Failure("failed".into());
            let expected = "internal output cannot contain an anonymous ballot rejection";
            assert_eq!(row.validate_structure(8, &[]).unwrap_err(), expected);
            assert_eq!(
                validate_execution_outputs_v1(&[row], proposal(), 8, &[]).unwrap_err(),
                expected
            );
        }
    }
}

#[test]
fn anonymous_ballot_cannot_be_a_pipeline_network_event_source() {
    let inputs = [input(), anonymous_input()];
    let second = ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
        input_index: 1,
        result: TransactionResult::new(Ok(vec![])),
        completions: vec![],
    });
    validate_execution_outputs_v1(
        &[network(), second.clone(), pipeline(), time()],
        proposal(),
        8,
        &inputs,
    )
    .unwrap();
    let mut event = pipeline();
    let ExecutionOutputV1::Pipeline(output) = &mut event else {
        unreachable!()
    };
    output.invocation.event = PipelineEventPositionV1::Network(1);
    let expected = "pipeline event source has no signed transaction event";
    assert_eq!(event.validate_structure(8, &inputs).unwrap_err(), expected);
    assert_eq!(
        validate_execution_outputs_v1(
            &[network(), second.clone(), event.clone()],
            proposal(),
            8,
            &inputs,
        )
        .unwrap_err(),
        expected
    );
    let ExecutionOutputV1::Pipeline(output) = &mut event else {
        unreachable!()
    };
    output.invocation.event = PipelineEventPositionV1::Network(0);
    validate_execution_outputs_v1(&[network(), second, event], proposal(), 8, &inputs).unwrap();
}
