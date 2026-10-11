use super::*;
use crate::kura::tests::CommittedNetworkProofFixture;
use iroha_crypto::MerkleTree as CanonMerkleTree;
use iroha_data_model::{
    block::{
        BlockPayload, BlockResult, execution_output::*,
        proofs::TrustedBlockProofAnchor,
    },
    events::time::Schedule,
    transaction::signed::TransactionEntrypoint,
};
use nonzero_ext::nonzero;
use norito::codec::DecodeAll as _;

#[derive(norito::NoritoSchema, norito::codec::Decode, norito::codec::Encode)]
#[norito_schema(name = "iroha_core::state::block_proof_tests::MutableSignedBlockWire")]
struct MutableSignedBlockWire {
    signatures: iroha_data_model::block::BlockSignatures,
    payload: BlockPayload,
    result: Option<BlockResult>,
    commit_certificate: Option<iroha_data_model::block::CommitCertificate>,
}

fn proof_limits() -> BlockProofLimits {
    BlockProofLimits {
        max_source_blocks: 8,
        max_source_wire_bytes: 32 * 1024 * 1024,
        max_block_wire_bytes: 4 * 1024 * 1024,
        max_work_items: 128,
        max_response_bytes: 4 * 1024 * 1024,
    }
}
fn proof_chain(sealed: bool) -> crate::sumeragi::test_chain::CertifiedTestChain {
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_data_model::{
        events::pipeline::{BlockEventFilter, BlockStatus},
        isi::Log,
        trigger::{
            Trigger,
            action::{Action, Repeats},
        },
    };
    // Genesis timestamps span its instruction batches; keep the one-shot
    // schedule ahead of the actual parent rather than inside that span.
    let mut config = TestChainConfig::new(World::new(), 0);
    if sealed {
        // A sealed input has no public transaction timestamp. Its original
        // signed cadence carries this block past the same one-shot schedule.
        config.genesis_block_cadence_ms = nonzero!(1001_u64);
    }
    let signer = config.genesis_key.clone();
    let authority = AccountId::new(signer.public_key().clone());
    config.genesis_instructions = vec![
        Register::trigger(Trigger::new(
            "proof_pipeline".parse().unwrap(),
            Action::new(
                [InstructionBox::from(Log::new(
                    Level::INFO,
                    "pipeline proof".into(),
                ))],
                Repeats::Exactly(1),
                authority.clone(),
                BlockEventFilter::new().for_status(BlockStatus::Approved),
            )
            .unwrap(),
        ))
        .into(),
        Register::trigger(Trigger::new(
            "proof_time".parse().unwrap(),
            Action::new(
                [InstructionBox::from(Log::new(
                    Level::INFO,
                    "time proof".into(),
                ))],
                Repeats::Exactly(1),
                authority.clone(),
                TimeEventFilter::new(ExecutionTime::Schedule(Schedule {
                    start_ms: 1001,
                    period_ms: None,
                })),
            )
            .unwrap(),
        ))
        .into(),
    ];
    let mut chain = CertifiedTestChain::start(config).unwrap();
    assert!(
        chain.state().view().genesis_timestamp().unwrap().unwrap() < Duration::from_millis(1001)
    );
    let successful = chain.sign(
        &signer,
        [Log::new(Level::INFO, "network proof".into()).into()],
        1001,
    );
    if sealed {
        use iroha_data_model::transaction::signed::{
            SealedTransactionCommitmentPayload, SignedSealedTransactionCommitment,
            compute_sealed_transaction_commitment,
        };
        let commitment = SignedSealedTransactionCommitment::sign(
            SealedTransactionCommitmentPayload {
                network_id: chain.network_id(),
                authority,
                commitment: compute_sealed_transaction_commitment(
                    &chain.network_id(),
                    &successful,
                    [0xA5; 32],
                    5,
                ),
                reveal_after_height: 3,
                reveal_deadline_height: 5,
                nonce: None,
            },
            signer.private_key(),
        );
        chain.commit_entrypoints(vec![TransactionEntrypoint::SealedCommitment(commitment)]);
    } else {
        let rejected = chain.sign(
            &signer,
            [Unregister::domain(
                iroha_model_base::domain::DomainId::try_new("missing-proof-domain", "universal")
                    .unwrap(),
            )
            .into()],
            1002,
        );
        assert_eq!(chain.commit(vec![successful, rejected]), vec![true, false]);
    }
    chain
}

fn proof_fixture() -> CommittedNetworkProofFixture {
    CommittedNetworkProofFixture::from_chain(proof_chain(false))
}

#[test]
fn proof_fixture_runs_both_internal_phases_after_original_genesis_time() {
    let fixture = proof_fixture();
    let block = fixture.target();
    let parent = fixture
        .state
        .view()
        .block_by_height(nonzero!(1_usize))
        .expect("completed original State read")
        .unwrap();
    assert!(parent.header().creation_time() < Duration::from_millis(1001));
    assert!(block.header().creation_time() > Duration::from_millis(1001));
    assert_eq!(block.network_entrypoints().len(), 2);
    assert_eq!(block.execution_outputs().len(), 4);
    assert!(matches!(
        block.execution_outputs()[2],
        ExecutionOutputV1::Pipeline(_)
    ));
    assert!(matches!(
        block.execution_outputs()[3],
        ExecutionOutputV1::Time(_)
    ));
    assert_eq!(block.header().prev_block_hash(), Some(parent.hash()));
    assert_eq!(
        fixture.state.network_id_ref().into_genesis_hash(),
        parent.hash()
    );
}

fn proof_state(fixture: &CommittedNetworkProofFixture) -> Arc<State> {
    Arc::clone(&fixture.state)
}

fn proof_anchor(
    fixture: &CommittedNetworkProofFixture,
    input: &HashOf<TransactionEntrypoint>,
) -> TrustedBlockProofAnchor {
    let view = fixture.state.view();
    let chain = crate::sumeragi::certified_chain::CertifiedChain::new(&view).unwrap();
    let authority = chain.authenticated_execution(2).unwrap();
    let execution = &authority.committed().commitment().execution;
    TrustedBlockProofAnchor::from_committed_execution(
        fixture.target(),
        execution.executed_block_wire_len,
        execution.executed_block_wire_hash,
        input,
    )
    .unwrap()
}

fn mutate_stored_block(
    block: &SignedBlock,
    mutate: impl FnOnce(&mut BlockPayload, &mut BlockResult),
) -> SignedBlock {
    let encoded = block.encode();
    let mut wire = MutableSignedBlockWire::decode_all(&mut encoded.as_slice()).unwrap();
    mutate(&mut wire.payload, wire.result.as_mut().unwrap());
    SignedBlock::decode_all(&mut wire.encode().as_slice()).unwrap()
}

fn assert_invalid_finalized_body(mutate: impl FnOnce(&mut BlockPayload, &mut BlockResult)) {
    let fixture = proof_fixture();
    let altered = mutate_stored_block(fixture.target(), mutate);
    fixture.replace_target_wire(&altered.encode_wire().unwrap());
    let target = fixture.target();
    let entry = target.network_entrypoint_at(0).unwrap().hash();
    let error = proof_state(&fixture)
        .block_proofs_for_entry(nonzero!(2_u64), entry, proof_limits())
        .expect_err("malformed complete body must not yield any proof");
    assert!(
        matches!(error, BlockProofError::InvalidOutputs { block_height, .. }
        | BlockProofError::Storage { block_height, .. } if block_height == nonzero!(2_u64)),
        "complete structural/finality refusal, got {error:?}"
    );
}

#[test]
fn block_proofs_for_external_entry_use_distinct_input_and_output_trees() {
    let fixture = proof_fixture();
    let state = proof_state(&fixture);
    let block = fixture.target();
    for (index, input) in block.network_entrypoints().enumerate() {
        let proofs = state
            .block_proofs_for_entry(nonzero!(2_u64), input.hash(), proof_limits())
            .unwrap();
        assert_eq!(proofs.block_hash, block.hash());
        assert_eq!(
            proofs.executed_block_wire_hash,
            block.executed_block_wire_hash().unwrap()
        );
        assert_eq!(
            proofs.entry_commitment.root(),
            &block.header().merkle_root().unwrap()
        );
        assert_eq!(proofs.entry_commitment.leaf_count().get(), 2);
        assert_eq!(proofs.output_commitment.leaf_count().get(), 4);
        assert!(proofs.entry_proof.verify(&proofs.entry_commitment));
        assert!(proofs.output_proof.verify(&proofs.output_commitment));
        assert_eq!(
            proofs.output_proof.output(),
            &block.execution_outputs()[index]
        );
        let ExecutionOutputV1::Network(row) = proofs.output_proof.output() else {
            panic!("Network owner")
        };
        assert_eq!(usize::try_from(row.input_index).unwrap(), index);
        assert_eq!(row.result.is_err(), index == 1);
        let anchor = proof_anchor(&fixture, &input.hash());
        assert!(proofs.verify(&anchor));
    }
}

#[test]
fn block_proofs_do_not_reinterpret_internal_calls_as_inputs() {
    let fixture = proof_fixture();
    let state = proof_state(&fixture);
    let block = fixture.target();
    let internal = block.execution_outputs()[2..].iter().map(|output| {
        HashOf::<TransactionEntrypoint>::from_untyped_unchecked(
            output.execution_call_hash(block.hash(), block).unwrap(),
        )
    });
    for hash in internal {
        assert!(
            matches!(state.block_proofs_for_entry(nonzero!(2_u64), hash, proof_limits()),
            Err(BlockProofError::EntrypointNotFound { entry_hash, block_height })
                if entry_hash == hash && block_height == nonzero!(2_u64))
        );
    }
}

#[test]
fn block_proofs_reject_kura_body_not_committed_by_wsv() {
    let fixture = proof_fixture();
    let expected =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"different committed WSV header"));
    assert_ne!(fixture.target().hash(), expected);
    let view = fixture.state.view();
    let error = block_proofs_for_entry_from_kura(
        super::block_proofs::NativeProofSource {
            kura: &fixture.kura,
            chain_id: view.chain_id(),
            network: *view.network_id(),
            hashes: view.block_hashes(),
            budget: &view.execution_budget(),
        },
        nonzero!(2_u64),
        expected,
        fixture.target().network_entrypoint_at(0).unwrap().hash(),
        proof_limits(),
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            BlockProofError::BlockHashMismatch { .. }
                | BlockProofError::BlockNotFound(_)
                | BlockProofError::Storage { .. }
        ),
        "{error:?}"
    );
}

#[test]
fn block_proofs_reject_stored_input_root_drift() {
    assert_invalid_finalized_body(|payload, _| {
        let foreign =
            HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(b"foreign input"));
        let tree: CanonMerkleTree<TransactionEntrypoint> = [foreign].into_iter().collect();
        assert_ne!(payload.header.merkle_root, tree.root());
        payload.header.merkle_root = tree.root();
    });
}

#[test]
fn block_proofs_reject_stored_input_count_drift() {
    assert_invalid_finalized_body(|payload, _| {
        payload.external_entrypoints.pop();
    });
}

#[test]
fn block_proofs_reject_stored_output_commitment_drift() {
    assert_invalid_finalized_body(|_, result| {
        let canonical = result.output_merkle.root();
        let mut leaves = result.outputs.iter().map(HashOf::new).collect::<Vec<_>>();
        leaves[2] = HashOf::from_untyped_unchecked(Hash::new(b"foreign internal output"));
        result.output_merkle = leaves.into_iter().collect();
        assert_eq!(result.output_merkle.leaf_count(), result.outputs.len());
        assert_ne!(canonical, result.output_merkle.root());
    });
}

#[test]
fn block_proofs_reject_stored_output_count_drift() {
    assert_invalid_finalized_body(|_, result| {
        let mut leaves = result.outputs.iter().map(HashOf::new).collect::<Vec<_>>();
        leaves.push(HashOf::from_untyped_unchecked(Hash::new(b"extra output")));
        result.output_merkle = leaves.into_iter().collect();
        assert_eq!(result.output_merkle.leaf_count(), result.outputs.len() + 1);
    });
}

#[test]
fn block_proofs_reject_self_consistent_network_count_misalignment() {
    assert_invalid_finalized_body(|_, result| {
        result.outputs.remove(1);
        result.output_merkle = result.outputs.iter().map(HashOf::new).collect();
        assert_eq!(result.output_merkle.leaf_count(), 3);
    });
}

#[test]
fn block_proofs_validate_foreign_network_join_and_unrelated_internal_owner() {
    for internal in [false, true] {
        assert_invalid_finalized_body(|_, result| {
            if internal {
                let ExecutionOutputV1::Pipeline(row) = &mut result.outputs[2] else {
                    unreachable!()
                };
                row.invocation.trigger.registered_at_height = 2;
            } else {
                let ExecutionOutputV1::Network(row) = &mut result.outputs[1] else {
                    unreachable!()
                };
                row.input_index = 0;
            }
            result.output_merkle = result.outputs.iter().map(HashOf::new).collect();
        });
    }
}

#[test]
fn block_proofs_reject_retired_context_even_with_exact_finality() {
    let fixture = proof_fixture();
    let altered = mutate_stored_block(fixture.target(), |payload, _| {
        let mut context = iroha_data_model::block::BlockExecutionContextBundle::new(Vec::new());
        context.version = 0;
        payload
            .header
            .set_execution_context_hash(Some(HashOf::new(&context)));
        payload.execution_context = Some(context);
    });
    fixture.replace_target_wire(&altered.encode_wire().unwrap());
    let entry = fixture.target().network_entrypoint_at(0).unwrap().hash();
    let error = proof_state(&fixture)
        .block_proofs_for_entry(nonzero!(2_u64), entry, proof_limits())
        .unwrap_err();
    assert!(
        matches!(
            error,
            BlockProofError::InvalidOutputs { .. } | BlockProofError::Storage { .. }
        ),
        "{error:?}"
    );
}

#[test]
fn block_proofs_reject_requested_slot_header_height_mismatch() {
    let fixture = proof_fixture();
    let target = fixture.target();
    let view = fixture.state.view();
    let error = block_proofs_for_entry_from_kura(
        super::block_proofs::NativeProofSource {
            kura: &fixture.kura,
            chain_id: view.chain_id(),
            network: *view.network_id(),
            hashes: view.block_hashes(),
            budget: &view.execution_budget(),
        },
        nonzero!(1_u64),
        target.hash(),
        target.network_entrypoint_at(0).unwrap().hash(),
        proof_limits(),
    )
    .unwrap_err();
    assert!(
        matches!(error, BlockProofError::BlockHeightMismatch { requested, actual }
        if requested == nonzero!(1_u64) && actual == nonzero!(2_u64))
            || matches!(
                error,
                BlockProofError::Storage { .. } | BlockProofError::BlockHashMismatch { .. }
            ),
        "wrong slot must not reuse another height's authentic body: {error:?}"
    );
}

#[test]
fn block_proofs_require_published_finality_and_attached_outputs() {
    for resultless in [false, true] {
        let fixture = proof_fixture();
        let altered = if resultless {
            fixture
                .target()
                .canonical_resultless_proposal()
                .expect("valid fixture proposal projection")
        } else {
            let mut block = fixture.target().clone();
            block.set_commit_certificate(None);
            block
        };
        fixture.replace_target_wire(&altered.encode_wire().unwrap());
        let target = fixture.target();
        let error = proof_state(&fixture)
            .block_proofs_for_entry(
                nonzero!(2_u64),
                target.network_entrypoint_at(0).unwrap().hash(),
                proof_limits(),
            )
            .unwrap_err();
        if resultless {
            assert!(
                matches!(
                    error,
                    BlockProofError::MissingResults(_)
                        | BlockProofError::InvalidOutputs { .. }
                        | BlockProofError::Storage { .. }
                ),
                "{error:?}"
            );
        } else {
            assert!(
                matches!(error, BlockProofError::Storage { .. }),
                "{error:?}"
            );
        }
    }
}

#[test]
fn block_proofs_deny_cold_body_before_read_and_reject_finalized_wire_substitution() {
    for corrupt in [false, true] {
        let fixture = proof_fixture();
        let state = proof_state(&fixture);
        let block = fixture.target();
        let entry = block.network_entrypoint_at(0).unwrap().hash();
        let original = block.encode_wire().unwrap();
        if corrupt {
            let mut wire = original.clone();
            *wire.last_mut().unwrap() ^= 1;
            fixture.overwrite_target_wire(&wire);
        } else {
            fixture.make_target_cold();
        }
        let disk_before = fixture.target_disk_bytes();
        let index_before = fixture.index_image();
        let reads_before = fixture.kura.canonical_body_bytes_read_for_test();
        let actual = u64::try_from(original.len()).unwrap();
        let denied = BlockProofLimits {
            max_block_wire_bytes: actual - 1,
            ..proof_limits()
        };
        assert!(
            matches!(state.block_proofs_for_entry(nonzero!(2_u64), entry, denied),
            Err(BlockProofError::CapacityExceeded { block_height, resource: BlockProofResource::BlockWireBytes,
                actual: observed, limit }) if block_height == nonzero!(2_u64) && observed == actual && limit == actual - 1)
        );
        assert_eq!(
            fixture.kura.canonical_body_bytes_read_for_test(),
            reads_before
        );
        assert!(!fixture.target_cached());
        assert_eq!(fixture.index_image(), index_before);
        assert_eq!(fixture.target_disk_bytes(), disk_before);
        let admitted = state.block_proofs_for_entry(
            nonzero!(2_u64),
            entry,
            BlockProofLimits {
                max_block_wire_bytes: actual,
                ..proof_limits()
            },
        );
        assert_eq!(
            fixture.kura.canonical_body_bytes_read_for_test(),
            reads_before + native_prefix_wire_bytes(&fixture)
        );
        if corrupt {
            assert!(matches!(admitted, Err(BlockProofError::Storage { .. })));
        } else {
            assert!(admitted.is_ok());
        }
        assert!(!fixture.target_cached());
        assert_eq!(fixture.index_image(), index_before);
        assert_eq!(fixture.target_disk_bytes(), disk_before);
    }
}

#[test]
fn block_proofs_enforce_exact_work_and_response_limits() {
    let fixture = proof_fixture();
    let state = proof_state(&fixture);
    let entry = fixture.target().network_entrypoint_at(0).unwrap().hash();
    let proof = state
        .block_proofs_for_entry(nonzero!(2_u64), entry, proof_limits())
        .unwrap();
    let work = 6; // two source rows, all four outputs, no FASTPQ map/transcript rows.
    let response = u64::try_from(norito::canonical_frame_len(&proof).unwrap()).unwrap();
    for (resource, limits) in [
        (
            BlockProofResource::WorkItems,
            BlockProofLimits {
                max_work_items: work - 1,
                ..proof_limits()
            },
        ),
        (
            BlockProofResource::ResponseBytes,
            BlockProofLimits {
                max_response_bytes: response - 1,
                ..proof_limits()
            },
        ),
    ] {
        let error = state
            .block_proofs_for_entry(nonzero!(2_u64), entry, limits)
            .unwrap_err();
        assert!(
            matches!(error, BlockProofError::CapacityExceeded { resource: observed, .. }
            if observed == resource),
            "{error:?}"
        );
    }
    let exact = state
        .block_proofs_for_entry(
            nonzero!(2_u64),
            entry,
            BlockProofLimits {
                max_work_items: work,
                max_response_bytes: response,
                ..proof_limits()
            },
        )
        .unwrap();
    assert_eq!(exact, proof);
    fixture.make_target_cold();
    let reads_before = fixture.kura.canonical_body_bytes_read_for_test();
    let index_before = fixture.index_image();
    for (resource, limits) in [
        (
            BlockProofResource::BlockWireBytes,
            BlockProofLimits {
                max_block_wire_bytes: 0,
                ..proof_limits()
            },
        ),
        (
            BlockProofResource::WorkItems,
            BlockProofLimits {
                max_work_items: 0,
                ..proof_limits()
            },
        ),
        (
            BlockProofResource::ResponseBytes,
            BlockProofLimits {
                max_response_bytes: 0,
                ..proof_limits()
            },
        ),
    ] {
        assert!(
            matches!(state.block_proofs_for_entry(nonzero!(2_u64), entry, limits),
            Err(BlockProofError::CapacityExceeded { resource: observed, limit: 0, actual, .. })
                if observed == resource && actual > 0)
        );
        assert_eq!(
            fixture.kura.canonical_body_bytes_read_for_test(),
            reads_before
        );
        assert!(!fixture.target_cached());
        assert_eq!(fixture.index_image(), index_before);
    }
}

#[test]
fn executed_block_wire_returns_exact_finalized_bytes_and_enforces_admission() {
    let fixture = proof_fixture();
    let state = proof_state(&fixture);
    let expected = fixture.target().encode_wire().unwrap();
    let size = u64::try_from(expected.len()).unwrap();
    fixture.make_target_cold();
    let before = fixture.kura.canonical_body_bytes_read_for_test();
    for bound in [0, size - 1] {
        assert!(
            matches!(state.executed_block_wire(nonzero!(2_u64), BlockProofLimits {
            max_block_wire_bytes: bound, ..proof_limits()
        }), Err(BlockProofError::CapacityExceeded { resource: BlockProofResource::BlockWireBytes,
            actual, limit, .. }) if actual == if bound == 0 { 1 } else { size } && limit == bound)
        );
        assert_eq!(fixture.kura.canonical_body_bytes_read_for_test(), before);
    }
    assert_eq!(
        state
            .executed_block_wire(
                nonzero!(2_u64),
                BlockProofLimits {
                    max_block_wire_bytes: size,
                    max_response_bytes: size,
                    ..proof_limits()
                }
            )
            .unwrap()
            .as_slice(),
        expected
    );
    assert_eq!(
        fixture.kura.canonical_body_bytes_read_for_test(),
        before + native_prefix_wire_bytes(&fixture)
    );
    assert!(!fixture.target_cached());
}

/// Keep the existing sealed-commitment State regression on genuine exact-wire finality.
pub(super) fn assert_sealed_commitment_proof_uses_distinct_trees() {
    let fixture = CommittedNetworkProofFixture::from_chain(proof_chain(true));
    let state = proof_state(&fixture);
    let block = fixture.target();
    let sealed_hash = block.network_entrypoint_at(0).unwrap().hash();
    let proof = state
        .block_proofs_for_entry(nonzero!(2_u64), sealed_hash, proof_limits())
        .unwrap();
    assert_eq!(proof.block_hash, block.hash());
    assert_eq!(
        proof.executed_block_wire_hash,
        block.executed_block_wire_hash().unwrap()
    );
    assert_eq!(
        proof.entry_commitment.root(),
        &block.header().merkle_root().unwrap()
    );
    assert_eq!(proof.entry_commitment.leaf_count().get(), 1);
    assert_eq!(proof.output_commitment.leaf_count().get(), 3);
    assert!(proof.entry_proof.verify(&proof.entry_commitment));
    assert!(proof.output_proof.verify(&proof.output_commitment));
    assert_eq!(
        block.network_input_hashes().collect::<Vec<_>>(),
        vec![sealed_hash]
    );
    assert!(matches!(
        block.execution_outputs()[1],
        ExecutionOutputV1::Pipeline(_)
    ));
    assert!(matches!(
        block.execution_outputs()[2],
        ExecutionOutputV1::Time(_)
    ));
    let anchor = proof_anchor(&fixture, &sealed_hash);
    assert!(proof.verify(&anchor));
}

fn native_prefix_wire_bytes(fixture: &CommittedNetworkProofFixture) -> u64 {
    fixture
        .blocks
        .iter()
        .map(|block| block.encode_wire().unwrap().len() as u64)
        .sum()
}
