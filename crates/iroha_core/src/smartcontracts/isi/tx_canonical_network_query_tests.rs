//! Structural query-producer controls over canonical model carriers.
//!
//! These tests grant no State, execution or finality authority. The canonical history owner must
//! supply those facts; actual State/Kura indexed and resumed query qualification remains required.

use super::*;
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    ValidationFail,
    block::{
        SignedBlock,
        builder::BlockBuilder as ModelBlockBuilder,
        execution_output::{
            ExecutionOutputV1, InvocationCompletionV1, NetworkExecutionOutputV1,
            TimeExecutionOutputV1, TimeInvocationV1, TriggerUseV1,
        },
        output_budget::ExecutionOutputLimits,
    },
    events::{
        time::{TimeEvent, TimeInterval},
        trigger_completed::TriggerCompletedOutcome,
    },
    prelude::{AccountId, DataTriggerSequence, InstructionBox, NetworkId, TransactionBuilder},
    transaction::{
        FeePaymentIntent,
        error::TransactionRejectionReason,
        signed::{ExecutionStep, SealedTransactionReveal},
    },
    trigger::DataTriggerStep,
};
use std::num::NonZeroU64;

fn fixture_limits() -> ExecutionOutputLimits {
    ExecutionOutputLimits {
        max_outputs: 8,
        max_output_bytes: 64 * 1024,
        max_total_output_bytes: 256 * 1024,
        max_executed_wire_bytes: 1024 * 1024,
    }
}

fn install(block: &mut SignedBlock, outputs: Vec<ExecutionOutputV1>) {
    block
        .set_execution_outputs(
            outputs,
            3,
            std::collections::BTreeMap::default(),
            vec![],
            iroha_data_model::nexus::AxtPolicySnapshot::default(),
            std::collections::BTreeSet::default(),
            &fixture_limits(),
        )
        .expect("bounded structural output fixture");
}

fn fixture() -> SignedBlock {
    let key = KeyPair::try_from_seed(vec![0x46; 32], Algorithm::Ed25519).unwrap();
    let authority = AccountId::new(key.public_key().clone());
    let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"canonical query test genesis",
    )));
    let header = BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        Some(HashOf::from_untyped_unchecked(Hash::new(b"query parent"))),
        None,
        1_000,
        0,
    );
    let mut builder = ModelBlockBuilder::new(header);
    for index in 0..2 {
        let mut transaction = TransactionBuilder::new(
            network,
            authority.clone(),
            FeePaymentIntent::authority(vec![], None),
        );
        transaction.set_creation_time(std::time::Duration::from_millis(900 + index));
        let signed = transaction
            .with_instructions::<InstructionBox>([])
            .sign(key.private_key());
        if index == 0 {
            builder.push_transaction(signed);
        } else {
            builder.push_sealed_transaction_reveal(SealedTransactionReveal::new(
                Hash::new(b"query sealed commitment"),
                signed,
                [0x35; 32],
            ));
        }
    }
    let mut block = builder.build_with_signature(0, key.private_key());
    let trigger_id: iroha_data_model::trigger::TriggerId = "query_timer".parse().unwrap();
    let outputs = vec![
        ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
            input_index: 0,
            result: TransactionResult::new(Ok(DataTriggerSequence::default())),
            completions: vec![InvocationCompletionV1 {
                callback_index: 0,
                trigger_id: "query_callback".parse().unwrap(),
                outcome: TriggerCompletedOutcome::Success,
            }],
        }),
        ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
            input_index: 1,
            result: TransactionResult::new(Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted("query fixture rejection".into()),
            ))),
            completions: vec![],
        }),
        ExecutionOutputV1::Time(TimeExecutionOutputV1 {
            invocation: TimeInvocationV1 {
                schedule_index: 4,
                event: TimeEvent {
                    interval: TimeInterval {
                        since_ms: 999,
                        length_ms: 1,
                    },
                },
                trigger: TriggerUseV1 {
                    trigger_id: trigger_id.clone(),
                    registered_at_height: 1,
                    action_hash: Hash::new(b"structural fixture action; not State authority"),
                },
            },
            result: TransactionResult::new(Ok(vec![DataTriggerStep {
                id: trigger_id,
                instructions: ExecutionStep(vec![].into()),
            }])),
            failure_root: None,
            completions: vec![],
        }),
    ];
    install(&mut block, outputs);
    block
}

#[test]
fn canonical_query_network_rows_keep_full_output_and_distinct_proof_domains() {
    let block = fixture();
    let rows = block_committed_transactions(&block).unwrap();
    assert_eq!(rows.len(), 2, "internal Time output has no transaction row");
    assert_eq!(block.execution_outputs().len(), 3);
    let inputs = block.network_input_merkle_commitment().unwrap();
    let outputs = block.output_merkle_commitment().unwrap();
    assert_eq!(inputs.leaf_count().get(), 2);
    assert_eq!(outputs.leaf_count().get(), 3);
    for (transaction, input_index) in rows.iter().zip([1, 0]) {
        let ExecutionOutputV1::Network(row) = &transaction.output else {
            panic!("internal output was exposed as a Network transaction");
        };
        assert_eq!(row.input_index, input_index);
        assert_eq!(transaction.entrypoint_proof.leaf_index(), input_index);
        assert_eq!(transaction.output_proof.leaf_index(), input_index);
        assert_eq!(transaction.output_hash, HashOf::new(&transaction.output));
        assert_eq!(
            transaction.output,
            block.execution_outputs()[input_index as usize]
        );
        assert!(
            transaction
                .entrypoint_proof
                .verify(&transaction.entrypoint_hash, &inputs)
        );
        assert!(
            transaction
                .output_proof
                .verify(&transaction.output_hash, &outputs)
        );
        assert!(transaction.verify_inclusion_in_block(&block));
    }
    assert_eq!(rows[1].output.completions().len(), 1);
    assert!(rows[0].result().is_err());
    assert!(rows[1].result().is_ok());
}

#[test]
fn canonical_query_keeps_sealed_outer_identity_authority_time_and_result_filters() {
    let block = fixture();
    let rows = block_committed_transactions(&block).unwrap();
    let sealed = &rows[0];
    let TransactionEntrypoint::SealedReveal(reveal) = &sealed.entrypoint else {
        panic!("newest input must remain sealed");
    };
    assert_eq!(sealed.entrypoint_hash, sealed.entrypoint.hash());
    assert_ne!(
        sealed.entrypoint_hash,
        reveal.signed_transaction().hash_as_entrypoint()
    );
    for (field, value) in [
        (
            "entrypoint_hash",
            norito::json::to_value(&sealed.entrypoint_hash).unwrap(),
        ),
        (
            "authority",
            norito::json::to_value(sealed.entrypoint.authority()).unwrap(),
        ),
        (
            "creation_time_ms",
            norito::json::to_value(&901_u64).unwrap(),
        ),
        ("result_ok", norito::json::to_value(&false).unwrap()),
    ] {
        assert!(
            transaction_field_equals(sealed, field, &value, None),
            "field {field}"
        );
    }
    assert!(!transaction_field_equals(
        sealed,
        "entrypoint_hash",
        &norito::json::to_value(&reveal.signed_transaction().hash_as_entrypoint()).unwrap(),
        None,
    ));
}

fn replace_outputs_untrusted(block: &SignedBlock, rows: Vec<ExecutionOutputV1>) -> SignedBlock {
    let mut value = norito::json::to_value(block).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .get_mut("result")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("outputs".into(), norito::json::to_value(&rows).unwrap());
    norito::json::from_value(value).unwrap()
}

#[test]
fn canonical_query_refuses_resultless_missing_foreign_and_internal_substituted_rows() {
    let block = fixture();
    assert!(matches!(
        block_committed_transactions(
            &block
                .canonical_resultless_proposal()
                .expect("valid fixture proposal projection")
        ),
        Err(QueryExecutionFail::Conversion(_))
    ));
    for mutation in 0..4 {
        let mut rows = block.execution_outputs().to_vec();
        match mutation {
            0 => {
                rows.remove(1);
            }
            1 => {
                let ExecutionOutputV1::Network(row) = &mut rows[1] else {
                    unreachable!()
                };
                row.input_index = 0;
            }
            2 => {
                rows[0] = rows[2].clone();
            }
            _ => {
                rows.swap(0, 1);
            }
        }
        let untrusted = replace_outputs_untrusted(&block, rows);
        let before = untrusted.encode_wire().unwrap();
        assert!(
            matches!(
                block_committed_transactions(&untrusted),
                Err(QueryExecutionFail::Conversion(_))
            ),
            "mutation {mutation}"
        );
        assert_eq!(untrusted.encode_wire().unwrap(), before);
    }
}

#[test]
fn canonical_query_refuses_stale_output_tree_without_repairing_it() {
    let block = fixture();
    let mut value = norito::json::to_value(&block).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .get_mut("result")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "output_merkle".into(),
            norito::json::to_value(&MerkleTree::<ExecutionOutputV1>::default()).unwrap(),
        );
    let stale: SignedBlock = norito::json::from_value(value).unwrap();
    let before = stale.encode_wire().unwrap();
    assert!(matches!(
        block_committed_transactions(&stale),
        Err(QueryExecutionFail::Conversion(_))
    ));
    assert_eq!(stale.encode_wire().unwrap(), before);
}

#[test]
fn canonical_query_internal_output_substitution_cannot_verify_as_transaction() {
    let block = fixture();
    let mut row = block_committed_transactions(&block).unwrap().remove(0);
    row.output = block.execution_outputs()[2].clone();
    row.output_hash = HashOf::new(&row.output);
    row.output_proof = block.output_proof(2).unwrap();
    assert!(!row.verify_inclusion_in_block(&block));
}

#[test]
fn canonical_query_measures_full_projected_row_before_cloning() {
    let block = fixture();
    let projection = NetworkCarrierProjection::new(
        crate::block::reserve_block_for_tests().initialize(block.clone()),
    )
    .expect("valid carrier");
    for index in 0..projection.count {
        let mut charged = None;
        let transaction = projection
            .transaction_at(index, TRANSACTION_HISTORY_MAX_BYTES, |bytes| {
                charged = Some(bytes);
                Ok(())
            })
            .expect("admitted row");
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let actual = super::super::query::bounded_bare_encoded_len(&transaction, charged.unwrap())
            .expect("owned row has exactly the admitted borrowed layout");
        assert_eq!(charged, Some(actual));
    }
}

#[test]
fn canonical_query_refuses_a_row_before_materialization_and_preserves_carrier() {
    let block = fixture();
    let before = block.encode_wire().unwrap();
    let projection = NetworkCarrierProjection::new(
        crate::block::reserve_block_for_tests().initialize(block.clone()),
    )
    .expect("valid carrier");
    let mut admission_calls = 0;
    let error = projection
        .transaction_at(1, TRANSACTION_HISTORY_MAX_BYTES, |bytes| {
            assert!(bytes > 0);
            admission_calls += 1;
            Err(QueryExecutionFail::GasBudgetExceeded)
        })
        .unwrap_err();
    assert!(matches!(error, QueryExecutionFail::GasBudgetExceeded));
    assert_eq!(admission_calls, 1);
    assert_eq!(block.encode_wire().unwrap(), before);
    assert!(
        projection
            .transaction_at(0, TRANSACTION_HISTORY_MAX_BYTES, |_| Ok(()))
            .is_ok()
    );
}

#[test]
fn canonical_query_projects_only_the_requested_row_after_full_validation() {
    let block = fixture();
    let projection = NetworkCarrierProjection::new(
        crate::block::reserve_block_for_tests().initialize(block.clone()),
    )
    .expect("valid carrier");
    let mut admitted = 0;
    let selected = projection
        .transaction_at(1, TRANSACTION_HISTORY_MAX_BYTES, |_| {
            admitted += 1;
            Ok(())
        })
        .expect("one selected Network row");
    assert_eq!(admitted, 1);
    assert_eq!(
        selected.entrypoint_hash,
        block.network_entrypoint_at(1).unwrap().hash()
    );
    assert!(selected.result().is_err());
    assert!(
        projection
            .transaction_at(2, TRANSACTION_HISTORY_MAX_BYTES, |_| panic!(
                "internal output has no input admission"
            ))
            .is_err()
    );
}

#[test]
fn history_byte_allowance_is_finite_and_derived_from_work_cap() {
    assert_eq!(transaction_history_byte_limit(0), 0);
    assert_eq!(transaction_history_byte_limit(1), 64 * 1024);
    assert_eq!(transaction_history_byte_limit(u64::MAX), 64 * 1024 * 1024);
}
