// Canonical genesis output structure, caches and minimum applied-fragment controls.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::block::valid::tests::MutableGenesisBlockWire")]
#[derive(norito::codec::Decode, norito::codec::Encode)]
struct MutableGenesisBlockWire {
    signatures: iroha_data_model::block::BlockSignatures,
    payload: BlockPayload,
    result: Option<BlockResult>,
    commit_certificate: Option<iroha_data_model::block::CommitCertificate>,
}

fn install_genesis_outputs(
    block: &mut SignedBlock,
    outputs: Vec<iroha_data_model::block::execution_output::ExecutionOutputV1>,
    fragments: u64,
) {
    let limits = iroha_data_model::block::output_budget::ExecutionOutputLimits {
        max_outputs: 16,
        max_output_bytes: 65_536,
        max_total_output_bytes: 262_144,
        max_executed_wire_bytes: 1_048_576,
    };
    let proposal = block
        .canonical_resultless_proposal()
        .expect("valid fixture proposal projection");
    block
        .set_execution_outputs(
            outputs,
            fragments,
            Default::default(),
            Vec::new(),
            Default::default(),
            Default::default(),
            &limits,
        )
        .expect("structural genesis outputs must fit their explicit finite fixture policy");
    assert_eq!(
        block
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection"),
        proposal
    );
}

fn canonical_executed_genesis_fixture() -> SignedBlock {
    use iroha_data_model::{
        block::execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
        prelude::*,
    };
    use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
    let transaction = TransactionBuilder::new_genesis(
        SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "genesis".to_owned())])
    .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key());
    let mut block = SignedBlock::genesis(
        vec![transaction],
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
        None,
        None,
    );
    install_genesis_outputs(
        &mut block,
        vec![ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
            input_index: 0,
            result: iroha_data_model::transaction::TransactionResult::new(Ok(Vec::new())),
            completions: Vec::new(),
        })],
        1,
    );
    let mut signatures = block.signatures();
    let signature = signatures.next().expect("canonical genesis signature");
    assert_eq!(signature.index(), 0);
    assert!(signatures.next().is_none());
    signature
        .signature()
        .verify_hash(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(), block.hash())
        .expect("output attachment preserves the original genesis signature");
    drop(signatures);
    block
}

fn mutate_genesis_result(
    block: &SignedBlock,
    mutate: impl FnOnce(&mut BlockPayload, &mut BlockResult),
) -> SignedBlock {
    use norito::codec::DecodeAll as _;
    let encoded = norito::codec::Encode::encode(block);
    let mut wire = MutableGenesisBlockWire::decode_all(&mut encoded.as_slice())
        .expect("canonical genesis fixture must decode into mutable wire parts");
    let result = wire
        .result
        .as_mut()
        .expect("canonical genesis fixture carries outputs");
    mutate(&mut wire.payload, result);
    let encoded = norito::codec::Encode::encode(&wire);
    SignedBlock::decode_all(&mut encoded.as_slice())
        .expect("adversarial genesis fixture remains structurally decodable")
}

fn genesis_internal_outputs() -> Vec<iroha_data_model::block::execution_output::ExecutionOutputV1> {
    use iroha_data_model::{
        block::execution_output::*,
        events::{
            time::{TimeEvent, TimeInterval},
            trigger_completed::TriggerCompletedOutcome,
        },
        transaction::{TransactionResult, signed::ExecutionStep},
        trigger::{DataTriggerStep, TriggerId},
    };
    let make_use = |name: &str| TriggerUseV1 {
        trigger_id: name.parse().unwrap(),
        registered_at_height: 0,
        action_hash: iroha_crypto::Hash::new(name.as_bytes()),
    };
    let result = |id: &TriggerId| {
        TransactionResult::new(Ok(vec![DataTriggerStep {
            id: id.clone(),
            instructions: ExecutionStep(Vec::new().into()),
        }]))
    };
    let completions = |id: &TriggerId| {
        vec![InvocationCompletionV1 {
            callback_index: 0,
            trigger_id: id.clone(),
            outcome: TriggerCompletedOutcome::Success,
        }]
    };
    let pipeline = make_use("genesis_pipeline");
    let time = make_use("genesis_time");
    vec![
        ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 {
            result: result(&pipeline.trigger_id),
            completions: completions(&pipeline.trigger_id),
            invocation: PipelineInvocationV1 {
                event: PipelineEventPositionV1::BlockApproved,
                candidate_index: 0,
                trigger: pipeline,
            },
            failure_root: None,
        }),
        ExecutionOutputV1::Time(TimeExecutionOutputV1 {
            result: result(&time.trigger_id),
            completions: completions(&time.trigger_id),
            invocation: TimeInvocationV1 {
                schedule_index: 0,
                event: TimeEvent {
                    interval: TimeInterval {
                        since_ms: 0,
                        length_ms: 1,
                    },
                },
                trigger: time,
            },
            failure_root: None,
        }),
    ]
}

#[test]
fn check_genesis_block_requires_canonical_execution_results() {
    use iroha_data_model::block::execution_output::ExecutionOutputV1;
    use iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID;
    let genesis_account = SAMPLE_GENESIS_ACCOUNT_ID.clone();
    let canonical = canonical_executed_genesis_fixture();
    assert_eq!(check_genesis_block(&canonical, &genesis_account), Ok(()));
    assert_eq!(
        check_genesis_block(
            &canonical
                .canonical_resultless_proposal()
                .expect("valid fixture proposal projection"),
            &genesis_account
        ),
        Err(InvalidGenesisError::MissingResults)
    );

    let missing_output =
        mutate_genesis_result(&canonical, |_, result| *result = BlockResult::default());
    assert_eq!(
        check_genesis_block(&missing_output, &genesis_account),
        Err(InvalidGenesisError::NetworkOutputCountMismatch {
            expected: 1,
            actual: 0
        })
    );

    let mut rejected = canonical.clone();
    let mut outputs = rejected.execution_outputs().to_vec();
    let ExecutionOutputV1::Network(row) = &mut outputs[0] else {
        unreachable!()
    };
    row.result = iroha_data_model::transaction::TransactionResult::new(Err(
        iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::NotPermitted("genesis rejection fixture".to_owned()),
        ),
    ));
    install_genesis_outputs(&mut rejected, outputs, 1);
    assert_eq!(
        check_genesis_block(&rejected, &genesis_account),
        Err(InvalidGenesisError::RejectedOutput(
            GenesisOutputRejection {
                output_index: 0,
                reason: Box::new(
                    iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                        iroha_data_model::ValidationFail::NotPermitted(
                            "genesis rejection fixture".to_owned()
                        ),
                    )
                ),
            }
        ))
    );

    // There is no parallel input cache. Validate the real proposal-input commitment.
    let source_mismatch =
        mutate_genesis_result(&canonical, |payload, _| payload.header.merkle_root = None);
    assert_eq!(
        check_genesis_execution_results(&source_mismatch),
        Err(InvalidGenesisError::ProposalCommitmentMismatch)
    );
    let cache_mismatch = mutate_genesis_result(&canonical, |_, result| {
        result.output_merkle = MerkleTree::default()
    });
    assert_eq!(
        check_genesis_block(&cache_mismatch, &genesis_account),
        Err(InvalidGenesisError::OutputMerkleCacheMismatch)
    );
    // The retired Header result root is replaced by the sole full-output cache;
    // a well-formed foreign tree of the same cardinality must also be refused.
    let foreign_tree = mutate_genesis_result(&canonical, |_, result| {
        result.output_merkle = rejected.output_hashes().collect();
    });
    assert_eq!(
        check_genesis_block(&foreign_tree, &genesis_account),
        Err(InvalidGenesisError::OutputMerkleCacheMismatch)
    );
    let wrong_join = mutate_genesis_result(&canonical, |_, result| {
        let ExecutionOutputV1::Network(row) = &mut result.outputs[0] else {
            unreachable!()
        };
        row.input_index = 1;
        result.output_merkle = result.outputs.iter().map(HashOf::new).collect();
    });
    assert_eq!(
        check_genesis_block(&wrong_join, &genesis_account),
        Err(InvalidGenesisError::OutputStructureMismatch)
    );

    let mut extra_fragments = canonical.clone();
    install_genesis_outputs(
        &mut extra_fragments,
        canonical.execution_outputs().to_vec(),
        3,
    );
    assert_eq!(
        check_genesis_block(&extra_fragments, &genesis_account),
        Ok(()),
        "protocol fragments can exceed the output count"
    );
    let too_few =
        mutate_genesis_result(&canonical, |_, result| result.committed_fragment_count = 0);
    assert_eq!(
        check_genesis_block(&too_few, &genesis_account),
        Err(
            InvalidGenesisError::CommittedFragmentCountBelowOutputCount {
                minimum: 1,
                actual: Some(0)
            }
        )
    );
}

#[test]
fn genesis_checks_all_internal_outputs_without_equating_input_and_output_counts() {
    use iroha_data_model::block::execution_output::ExecutionOutputV1;
    use iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID;
    let mut block = canonical_executed_genesis_fixture();
    let mut outputs = block.execution_outputs().to_vec();
    outputs.extend(genesis_internal_outputs());
    install_genesis_outputs(&mut block, outputs.clone(), 3);
    assert_eq!(block.network_entrypoint_count(), 1);
    assert_eq!(block.execution_outputs().len(), 3);
    assert_eq!(
        check_genesis_block(&block, &SAMPLE_GENESIS_ACCOUNT_ID),
        Ok(())
    );
    let too_few = mutate_genesis_result(&block, |_, result| result.committed_fragment_count = 2);
    assert_eq!(
        check_genesis_execution_results(&too_few),
        Err(
            InvalidGenesisError::CommittedFragmentCountBelowOutputCount {
                minimum: 3,
                actual: Some(2)
            }
        )
    );
    for index in [1, 2] {
        let mut rejected_outputs = outputs.clone();
        rejected_outputs[index] = match &outputs[index] {
            ExecutionOutputV1::Pipeline(row) => {
                ExecutionOutputV1::pipeline_output_limit_rejection(row.invocation.clone())
            }
            ExecutionOutputV1::Time(row) => {
                ExecutionOutputV1::time_output_limit_rejection(row.invocation.clone())
            }
            ExecutionOutputV1::Network(_) => unreachable!(),
        };
        let reason = rejected_outputs[index]
            .result()
            .as_ref()
            .unwrap_err()
            .clone();
        let mut rejected = block.clone();
        install_genesis_outputs(&mut rejected, rejected_outputs, 3);
        assert_eq!(
            check_genesis_block(&rejected, &SAMPLE_GENESIS_ACCOUNT_ID),
            Err(InvalidGenesisError::RejectedOutput(
                GenesisOutputRejection {
                    output_index: index,
                    reason: Box::new(reason),
                }
            )),
            "an internal failure cannot hide behind successful Network outputs"
        );
    }
    let stale = mutate_genesis_result(&block, |_, result| {
        let ExecutionOutputV1::Time(row) = &mut result.outputs[2] else {
            unreachable!()
        };
        row.invocation.trigger.action_hash = iroha_crypto::Hash::new(b"changed internal action");
    });
    assert_eq!(
        check_genesis_execution_results(&stale),
        Err(InvalidGenesisError::OutputMerkleCacheMismatch)
    );
}

// The executor upgrade is optional; a genesis without it must still pass static checks.
#[test]
fn resultless_genesis_without_upgrade_authenticates_intents() {
    use iroha_data_model::prelude::*;
    use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
    let genesis_account = SAMPLE_GENESIS_ACCOUNT_ID.clone();
    let tx = TransactionBuilder::new_genesis(
        genesis_account.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "genesis".to_owned())])
    .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key());
    let block = SignedBlock::genesis(
        vec![tx],
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
        None,
        None,
    );
    assert!(authenticate_genesis_block_intents(&block, &genesis_account).is_ok());
}
#[test]
fn check_genesis_block_rejects_proof_policy_sidecar_substitution() {
    use iroha_data_model::prelude::*;
    use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
    let genesis_account = SAMPLE_GENESIS_ACCOUNT_ID.clone();
    let tx = TransactionBuilder::new_genesis(
        genesis_account.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "genesis".to_owned())])
    .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key());
    let mut block = SignedBlock::genesis(
        vec![tx],
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
        None,
        None,
    );
    let signed_header = block.header();
    block.set_da_proof_policies(Some(
        iroha_data_model::da::commitment::DaProofPolicyBundle::new(Vec::new()),
    ));
    block.replace_header_for_testing(signed_header);
    assert_eq!(
        check_genesis_block(&block, &genesis_account),
        Err(InvalidGenesisError::DaProofPolicyMismatch)
    );
}
#[test]
fn check_genesis_block_rejects_height_above_one() {
    use iroha_data_model::prelude::*;
    use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
    let genesis_account = SAMPLE_GENESIS_ACCOUNT_ID.clone();
    let tx = TransactionBuilder::new_genesis(
        genesis_account.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "genesis".to_owned())])
    .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key());
    let mut block = SignedBlock::genesis(
        vec![tx],
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
        None,
        None,
    );
    let mut header = block.header();
    header.set_height(nonzero!(2_u64));
    block.replace_header_for_testing(header);
    let signature = BlockSignature::new(
        0,
        checked_block_signature(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(), block.hash()),
    );
    block
        .replace_signatures(
            iroha_data_model::block::BlockSignatures::try_from_iter([signature])
                .expect("at most 31 block signatures"),
        )
        .expect("replace signature after changing test header");
    assert_eq!(
        check_genesis_block(&block, &genesis_account),
        Err(InvalidGenesisError::InvalidHeader)
    );
}

#[test]
fn configured_genesis_execution_capability_rejects_foreign_key_header_and_inputs() {
    use iroha_test_samples::{ALICE_ID, SAMPLE_GENESIS_ACCOUNT_ID};
    let block = canonical_executed_genesis_fixture();
    let capability =
        authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    assert_eq!(
        capability.account_for(&block).unwrap(),
        &*SAMPLE_GENESIS_ACCOUNT_ID
    );
    assert!(authenticate_genesis_block_intents(&block, &ALICE_ID).is_err());
    let changed = mutate_genesis_result(&block, |payload, _| {
        payload.header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 2, 0);
    });
    assert!(capability.account_for(&changed).is_err());
    let changed_input = mutate_genesis_result(&block, |payload, _| {
        payload.external_entrypoints.clear();
    });
    assert!(capability.account_for(&changed_input).is_err());
}

#[test]
fn authenticated_genesis_transaction_capability_binds_the_original_input_and_empty_history() {
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};

    let prepared = CertifiedTestChain::prepare(TestChainConfig::new(World::new(), 1_000))
        .expect("original signed genesis and its pristine State");
    let genesis = prepared.genesis.block().clone();
    let transactions = genesis.external_transactions().cloned().collect::<Vec<_>>();
    assert!(
        transactions.len() >= 2,
        "the signed bootstrap has distinct original inputs"
    );
    let first = &transactions[0];
    let second = &transactions[1];
    let source = authenticate_genesis_block_intents(&genesis, first.authority()).unwrap();
    let token = source.transaction_for(&genesis, 0).unwrap();
    let mut changed_proof = first.clone();
    changed_proof.set_signature(second.signature().clone());
    assert_eq!(
        changed_proof.hash_as_entrypoint(),
        first.hash_as_entrypoint()
    );
    assert!(changed_proof.verify_signature().is_err());
    let mut changed_inputs = genesis.clone();
    changed_inputs.set_external_entrypoints(
        std::iter::once(TransactionEntrypoint::External(changed_proof.clone()))
            .chain(
                transactions
                    .iter()
                    .skip(1)
                    .cloned()
                    .map(TransactionEntrypoint::External),
            )
            .collect(),
    );
    assert_eq!(changed_inputs.header(), genesis.header());
    assert!(source.transaction_for(&changed_inputs, 0).is_err());
    assert!(
        source
            .transaction_for(&genesis, transactions.len())
            .is_err()
    );
    {
        let mut block = prepared.state.block(genesis.header());
        let mut transaction = block.transaction();
        transaction.current_entrypoint_index = Some(0);
        transaction.current_network_entrypoint_hash = Some(first.hash_as_entrypoint());
        token
            .validate(first, &transaction)
            .expect("exact original bootstrap input");
        assert!(token.validate(&changed_proof, &transaction).is_err());
        assert!(token.validate(second, &transaction).is_err());
        transaction.current_entrypoint_index = Some(1);
        assert!(token.validate(first, &transaction).is_err());
        transaction.current_entrypoint_index = Some(0);
        transaction.current_network_entrypoint_hash = Some(second.hash_as_entrypoint());
        assert!(token.validate(first, &transaction).is_err());
        transaction.current_network_entrypoint_hash = None;
        assert!(token.validate(first, &transaction).is_err());
    }
    let changed_header = BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        Some(genesis.hash()),
        genesis.header().merkle_root(),
        1_001,
        0,
    );
    let mut changed = genesis.clone();
    changed.replace_header_for_testing(changed_header);
    assert!(source.transaction_for(&changed, 0).is_err());
    {
        let mut block = prepared.state.block(changed_header);
        let mut transaction = block.transaction();
        transaction.current_entrypoint_index = Some(0);
        transaction.current_network_entrypoint_hash = Some(first.hash_as_entrypoint());
        assert!(token.validate(first, &transaction).is_err());
    }
    assert_eq!(prepared.state.view().height(), 0);
    let chain = CertifiedTestChain::from_prepared(prepared).expect("original genesis commits");
    assert_eq!(chain.height(), 1);
    // Even an overlay carrying the original height-one header cannot replay this authority
    // after the original genesis is committed. No fabricated history enters the test.
    let mut block = chain.state().block(genesis.header());
    let mut transaction = block.transaction();
    transaction.current_entrypoint_index = Some(0);
    transaction.current_network_entrypoint_hash = Some(first.hash_as_entrypoint());
    assert!(token.validate(first, &transaction).is_err());
}

#[test]
fn authenticated_genesis_uses_the_actual_whole_output_owner() {
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let prepared = CertifiedTestChain::prepare(TestChainConfig::new(World::new(), 1_000))
        .expect("original signed genesis binds its executed native policy");
    let original = prepared.genesis.block().clone();
    let account = original
        .external_transactions()
        .next()
        .unwrap()
        .authority()
        .clone();
    let topology = Topology::new(
        prepared
            .validator_keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone())),
    );
    let (_, clock) = TimeSource::new_mock(original.header().creation_time());
    let (valid, block) = {
        let selected_genesis = original.clone();
        let selected_scope = crate::sumeragi::epoch::authenticated_genesis(&selected_genesis)
            .expect("signed fixture root scope")
            .into_parts()
            .1;
        ValidBlock::validate_signed_genesis(
            selected_genesis,
            &topology,
            &account,
            &clock,
            &prepared.state,
            iroha_data_model::parameter::system::ConsensusMode::Permissioned,
            selected_scope,
        )
    }
    .unpack(|_| {})
    .unwrap();
    let source = valid.as_ref();
    source.validate_output_merkle_cache().unwrap();
    let count = original.network_entrypoint_count();
    assert!(count > 0);
    assert_eq!(source.execution_outputs().len(), count);
    for index in 0..count {
        let index = u32::try_from(index).unwrap();
        let (position, output) = source.network_output_at(index).unwrap();
        assert_eq!(position, index);
        assert!(output.result.is_ok());
        assert!(output.completions.is_empty());
    }
    assert!(block.committed_fragment_count() >= count);
    assert_eq!(
        source
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection"),
        original
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection")
    );
    assert_eq!(source.header(), original.header());
    block.verify_execution_output_seal(source).unwrap();
    assert!(
        matches!(
            block.commit().unwrap_err(),
            crate::state::storage_transactions::TransactionsBlockError::ExecutionOutputCapacity
        ),
        "execution does not invent the unfinished publication authority"
    );
    assert_eq!(prepared.state.view().height(), 0);
    assert_eq!(prepared.kura.blocks_count(), 0);
}

#[test]
fn genesis_rejection_selects_first_complete_output_and_retains_typed_source() {
    use iroha_data_model::block::execution_output::ExecutionOutputV1;
    use iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID;
    use std::error::Error as _;

    let mut block = canonical_executed_genesis_fixture();
    let mut outputs = block.execution_outputs().to_vec();
    outputs.extend(genesis_internal_outputs());
    let ExecutionOutputV1::Pipeline(pipeline) = &outputs[1] else {
        unreachable!()
    };
    outputs[1] = ExecutionOutputV1::pipeline_output_limit_rejection(pipeline.invocation.clone());
    let first_reason = outputs[1].result().as_ref().unwrap_err().clone();
    let ExecutionOutputV1::Time(time) = &outputs[2] else {
        unreachable!()
    };
    outputs[2] = ExecutionOutputV1::time_output_limit_rejection(time.invocation.clone());
    install_genesis_outputs(&mut block, outputs, 3);
    let InvalidGenesisError::RejectedOutput(rejection) =
        check_genesis_block(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap_err()
    else {
        panic!("two internal rejections must retain their first canonical output");
    };
    assert_eq!(rejection.output_index, 1);
    assert_eq!(*rejection.reason, first_reason);
    assert_eq!(
        rejection
            .source()
            .unwrap()
            .downcast_ref::<TransactionRejectionReason>(),
        Some(&first_reason),
        "the original typed reason remains available through Error::source"
    );
}

#[test]
fn check_genesis_block_intents_accepts_resultless_source_and_checks_all_payload_commitments() {
    use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};

    let original = canonical_executed_genesis_fixture()
        .canonical_resultless_proposal()
        .expect("valid fixture proposal projection");
    let wire = original.encode_wire().unwrap();
    assert_eq!(
        check_genesis_block_intents(&original, &SAMPLE_GENESIS_ACCOUNT_ID),
        Ok(())
    );
    assert_eq!(
        check_genesis_block(&original, &SAMPLE_GENESIS_ACCOUNT_ID),
        Err(InvalidGenesisError::MissingResults)
    );
    let absent = iroha_crypto::Hash::new(b"absent original committed payload");
    for component in 0..3 {
        let mut payload = original.payload().clone();
        match component {
            0 => {
                payload.header.execution_context_hash = Some(HashOf::from_untyped_unchecked(absent))
            }
            1 => payload.header.npos_effects_hash = Some(HashOf::from_untyped_unchecked(absent)),
            _ => {
                payload.header.global_beacon_pulse_hash =
                    Some(HashOf::from_untyped_unchecked(absent))
            }
        }
        let signature = BlockSignature::new(
            0,
            SignatureOf::try_from_hash(
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
                payload.header.hash(),
            )
            .unwrap(),
        );
        let mismatch = SignedBlock::presigned_with_payload(signature, payload);
        assert_eq!(
            check_genesis_block_intents(&mismatch, &SAMPLE_GENESIS_ACCOUNT_ID),
            Err(InvalidGenesisError::ProposalCommitmentMismatch)
        );
    }
    assert_eq!(original.encode_wire().unwrap(), wire);
}
