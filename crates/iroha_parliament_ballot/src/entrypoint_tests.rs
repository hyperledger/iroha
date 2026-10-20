//! Genuine candidate proofs through the canonical block carrier. These fixtures
//! establish serialization and local result shape, not node execution or finality.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
};

use iroha_data_model::{
    block::{
        BlockHeader, BlockSignatures, SignedBlock,
        builder::BlockBuilder,
        decode_framed_signed_block,
        execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
        output_budget::ExecutionOutputLimits,
    },
    governance::anonymous_ballot::{
        ANONYMOUS_BALLOT_ENTRYPOINT_WIRE_MAX_BYTES_V1, AnonymousBallotRejectionV1,
        CanonicalAnonymousBallotEnvelopeV1, digests::verify_stamp_v1,
    },
    transaction::{
        TransactionEntrypoint, error::TransactionRejectionReason, signed::TransactionResult,
    },
};

use crate::{
    ballot::verify_ballot_proof_v1,
    test_support::{AYE_0, fixture_envelope, scoped_context},
};

fn proposal() -> SignedBlock {
    let envelope = CanonicalAnonymousBallotEnvelopeV1::from_envelope(&fixture_envelope(AYE_0))
        .expect("genuine canonical fixture");
    let mut builder = BlockBuilder::new(BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        None,
        None,
        1_000,
        0,
    ));
    assert_eq!(builder.push_anonymous_ballot(envelope), 0);
    builder.build(BlockSignatures::default())
}

fn install(block: &mut SignedBlock, result: TransactionResult) {
    block
        .set_execution_outputs(
            vec![ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                input_index: 0,
                result,
                completions: vec![],
            })],
            0,
            BTreeMap::new(),
            vec![],
            Default::default(),
            BTreeSet::new(),
            &ExecutionOutputLimits {
                max_outputs: 1,
                max_output_bytes: 16 * 1024,
                max_total_output_bytes: 16 * 1024,
                max_executed_wire_bytes: 1024 * 1024,
            },
        )
        .expect("install structural result");
}

#[test]
fn genuine_ballot_entrypoint_roundtrips_proposal_and_each_permitted_output() {
    let envelope = fixture_envelope(AYE_0);
    let context = scoped_context();
    verify_ballot_proof_v1(&context, &envelope).expect("real candidate proof");
    assert!(
        verify_stamp_v1(
            &envelope.authorization(),
            context.context(),
            &envelope.ballot.stamp.nonce
        )
        .expect("real stamp")
    );
    let proposed = proposal();
    let input = proposed.network_entrypoint_at(0).expect("anonymous input");
    assert!(input.authority_opt().is_none());
    assert!(input.creation_time_ms().is_none());
    assert!(input.metadata().is_none());
    assert_eq!(input.execution_call_hash(), input.hash());
    assert!(input.encode_wire_v1().unwrap().len() <= ANONYMOUS_BALLOT_ENTRYPOINT_WIRE_MAX_BYTES_V1);
    assert!(proposed.external_signed_transaction_at(0).is_none());
    assert!(proposed.external_signed_transaction_ref_at(0).is_none());
    assert_eq!(proposed.external_transactions().len(), 0);
    let proposal_wire = proposed.encode_wire().unwrap();
    assert_eq!(
        decode_framed_signed_block(&proposal_wire).unwrap(),
        proposed
    );
    for outcome in [
        Ok(vec![]),
        Err(TransactionRejectionReason::AnonymousBallot(
            AnonymousBallotRejectionV1::OutsideCastingWindow,
        )),
        Err(TransactionRejectionReason::AnonymousBallot(
            AnonymousBallotRejectionV1::DuplicateNullifier,
        )),
    ] {
        let mut executed = proposed.clone();
        install(&mut executed, TransactionResult::new(outcome));
        let wire = executed.encode_wire().expect("canonical executed wire");
        let decoded = decode_framed_signed_block(&wire).expect("canonical roundtrip");
        assert_eq!(decoded, executed);
        decoded
            .validate_execution_result_structure()
            .expect("output shape");
        assert_eq!(decoded.network_entrypoint_at(0), Some(input));
        assert_eq!(decoded.header(), proposed.header());
        let TransactionEntrypoint::AnonymousBallot(carrier) =
            decoded.network_entrypoint_at(0).unwrap()
        else {
            panic!("entrypoint kind changed");
        };
        assert_eq!(carrier.envelope().unwrap(), envelope);
        verify_ballot_proof_v1(&context, &carrier.envelope().unwrap()).expect("decoded real proof");
    }
}

#[test]
fn anonymous_block_decoding_preserves_enclosing_resource_refusal() {
    let mut block = proposal();
    install(&mut block, TransactionResult::new(Ok(vec![])));
    let wire = block.encode_wire().unwrap();
    let enclosing = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 1, usize::MAX);
    let (refused, _) =
        norito::core::with_decode_limits_measured(enclosing, || decode_framed_signed_block(&wire));
    assert_eq!(
        refused.expect_err("enclosing budget must apply").kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert_eq!(decode_framed_signed_block(&wire).unwrap(), block);
}

#[test]
fn anonymous_block_refuses_ordinary_rejection_without_mutating_the_proposal() {
    let mut block = proposal();
    let original = block.encode_wire().unwrap();
    let error = block
        .set_execution_outputs(
            vec![ExecutionOutputV1::network_output_limit_rejection(0)],
            0,
            BTreeMap::new(),
            vec![],
            Default::default(),
            BTreeSet::new(),
            &ExecutionOutputLimits {
                max_outputs: 1,
                max_output_bytes: 16 * 1024,
                max_total_output_bytes: 16 * 1024,
                max_executed_wire_bytes: 1024 * 1024,
            },
        )
        .expect_err("ordinary rejection is not a ballot result");
    assert!(matches!(
        error,
        iroha_data_model::block::SetExecutionOutputsError::InvalidOutputs(_)
    ));
    assert_eq!(block.encode_wire().unwrap(), original);
    assert!(!block.has_results());
}
