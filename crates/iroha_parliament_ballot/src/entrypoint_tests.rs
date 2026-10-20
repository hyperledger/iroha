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
fn identical_genuine_ballots_keep_verified_duplicate_results_in_canonical_block() {
    use std::sync::Arc;

    use iroha_data_model::{
        NetworkId,
        governance::anonymous_ballot::{BallotChoiceV1, BallotScopeV1, NullifierV1},
    };

    use crate::{
        ballot::{
            BlockBallotDecisionV1, BlockBallotStateV1, CastingWindowV1, decide_block_ballot_v1,
        },
        context::ScopedBallotContextV1,
        corpus::CorpusAccumulatorV1,
    };

    // This fixture supplies an open scope and applies the real corpus update.
    // It is not the pending Core State adapter and grants no finality.
    struct State {
        context: Arc<ScopedBallotContextV1>,
        corpus: CorpusAccumulatorV1,
        height: NonZeroU64,
        timestamp_ms: u64,
    }

    impl BlockBallotStateV1 for State {
        fn network_id(&self) -> NetworkId {
            *self.context.network_id()
        }

        fn scope_context(&self, scope: &BallotScopeV1) -> Option<Arc<ScopedBallotContextV1>> {
            (scope == self.context.scope()).then(|| Arc::clone(&self.context))
        }

        fn casting_open(&self, scope: &BallotScopeV1) -> bool {
            scope == self.context.scope()
                && CastingWindowV1 {
                    opening_height: self.height.get(),
                    closing_ms: None,
                    closure_height: None,
                }
                .is_open_at(self.height.get(), self.timestamp_ms)
        }

        fn nullifier_accepted(&self, scope: &BallotScopeV1, nullifier: &NullifierV1) -> bool {
            scope == self.corpus.scope() && self.corpus.index_of(nullifier).is_some()
        }
    }

    let envelope = fixture_envelope(AYE_0);
    let carrier = CanonicalAnonymousBallotEnvelopeV1::from_envelope(&envelope).unwrap();
    let height = NonZeroU64::new(100).unwrap();
    let timestamp_ms = 1_000_000;
    let mut builder = BlockBuilder::new(BlockHeader::new(height, None, None, timestamp_ms, 0));
    assert_eq!(builder.push_anonymous_ballot(carrier.clone()), 0);
    assert_eq!(builder.push_anonymous_ballot(carrier), 1);
    let mut block = builder.build(BlockSignatures::default());
    let original_header = block.header();
    let context = scoped_context();
    let mut state = State {
        corpus: CorpusAccumulatorV1::new(&context).unwrap(),
        context,
        height,
        timestamp_ms,
    };
    let mut rows = Vec::new();
    for index in [0_u32, 1] {
        let TransactionEntrypoint::AnonymousBallot(input) =
            block.network_entrypoint_at(index as usize).unwrap()
        else {
            panic!("anonymous source");
        };
        let before = state.corpus.clone();
        // Both occurrences pass encoding, stamp and genuine proof verification.
        let decision = decide_block_ballot_v1(&state, input.as_bytes(), height, index)
            .expect("real fixture verification completes");
        let result = match decision {
            BlockBallotDecisionV1::Accepted(entry) => {
                assert_eq!(index, 0);
                assert_eq!(entry.position(), (height.get(), index));
                assert_eq!(entry.vote, BallotChoiceV1::Aye);
                assert_eq!(state.corpus.append(&entry), Ok(0));
                Ok(vec![])
            }
            BlockBallotDecisionV1::Rejected(reason) => {
                assert_eq!(index, 1);
                assert_eq!(reason, AnonymousBallotRejectionV1::DuplicateNullifier);
                assert_eq!(state.corpus, before);
                Err(TransactionRejectionReason::AnonymousBallot(reason))
            }
            BlockBallotDecisionV1::BlockInvalid(reason) => {
                panic!("genuine fixture invalidated the block: {reason}");
            }
        };
        rows.push(ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
            input_index: index,
            result: TransactionResult::new(result),
            completions: vec![],
        }));
    }
    assert_eq!(state.corpus.accepted(), 1);
    assert_eq!(state.corpus.counts().aye, 1);
    assert_eq!(state.corpus.index_of(&envelope.ballot.nullifier), Some(0));
    assert_eq!(
        rows[0].execution_call_hash(block.hash(), &block).unwrap(),
        rows[1].execution_call_hash(block.hash(), &block).unwrap()
    );
    assert_ne!(rows[0].result(), rows[1].result());
    block
        .set_execution_outputs(
            rows.clone(),
            0,
            BTreeMap::new(),
            vec![],
            Default::default(),
            BTreeSet::new(),
            &ExecutionOutputLimits {
                max_outputs: 2,
                max_output_bytes: 16 * 1024,
                max_total_output_bytes: 32 * 1024,
                max_executed_wire_bytes: 1024 * 1024,
            },
        )
        .expect("install outcomes from the actual typed decisions");
    let wire = block.encode_wire().unwrap();
    let decoded = decode_framed_signed_block(&wire).unwrap();
    assert_eq!(decoded, block);
    assert_eq!(decoded.header(), original_header);
    decoded.validate_execution_result_structure().unwrap();
    assert_eq!(decoded.execution_outputs(), rows);
    assert_eq!(
        decoded.network_entrypoint_at(0),
        decoded.network_entrypoint_at(1)
    );
    for index in [0, 1] {
        let (output_index, row) = decoded.network_output_at(index).unwrap();
        assert_eq!(output_index, index);
        assert_eq!(row.input_index, index);
        assert_eq!(&row.result, rows[index as usize].result());
        assert!(row.completions.is_empty());
        assert!(row.result.batch_transfer_outcomes().is_empty());
        assert!(row.result.nexus_fee_receipt().is_none());
        assert!(row.result.contract_events().is_empty());
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
