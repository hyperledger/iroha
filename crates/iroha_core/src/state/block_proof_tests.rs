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

// KAGEMUSHA ledger-finality inclusion source (direct finality, DF-2).

fn kagemusha_paths_built() -> u64 {
    super::block_proofs::kagemusha_ledger_paths_built_for_test()
}

/// The ledger reads' own off-chain custody: a frame pool and a cumulative decoder allowance.
fn kagemusha_read_budget(
    frames: &iroha_allocation::AllocationBudget,
) -> CanonicalHistoryReadBudget {
    CanonicalHistoryReadBudget::new(
        frames.clone(),
        norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            1_000_000,
            48 * 1024 * 1024,
            1_000_000,
            48 * 1024 * 1024,
            64,
        )),
    )
}

fn kagemusha_frames() -> iroha_allocation::AllocationBudget {
    iroha_allocation::AllocationBudget::new(48 * 1024 * 1024)
}

fn kagemusha_owner(
    state: &State,
    height: NonZeroU64,
    entry: HashOf<TransactionEntrypoint>,
    limits: BlockProofLimits,
) -> Result<KagemushaLedgerEntryOwnerV1, BlockProofError> {
    state.kagemusha_ledger_entry_owner(
        height,
        entry,
        limits,
        &kagemusha_read_budget(&kagemusha_frames()),
    )
}

fn kagemusha_inclusion(
    state: &State,
    height: NonZeroU64,
    entry: HashOf<TransactionEntrypoint>,
    limits: BlockProofLimits,
) -> Result<Option<KagemushaLedgerEntryInclusionV1>, BlockProofError> {
    state.kagemusha_ledger_inclusion_for_entry(
        height,
        entry,
        limits,
        &kagemusha_read_budget(&kagemusha_frames()),
        |_| true,
    )
}

/// Run one finalized read on a cold target and return it with its body bytes read.
fn kagemusha_cold_read<T>(
    fixture: &CommittedNetworkProofFixture,
    read: impl FnOnce() -> T,
) -> (T, u64) {
    fixture.make_target_cold();
    let before = fixture.kura.canonical_body_bytes_read_for_test();
    let value = read();
    let read_bytes = fixture.kura.canonical_body_bytes_read_for_test() - before;
    assert!(!fixture.target_cached());
    (value, read_bytes)
}

/// [`kagemusha_cold_read`] after forgetting every node-local checkpoint, so the read walks
/// down from the native tip.
fn kagemusha_cold_walk<T>(
    fixture: &CommittedNetworkProofFixture,
    read: impl FnOnce() -> T,
) -> (T, u64) {
    fixture.kura.history_checkpoints().clear();
    kagemusha_cold_read(fixture, read)
}

/// The proof fixture's target H2 below one more committed block, so a cold ledger read walks
/// H3 then H2.
fn kagemusha_walk_fixture() -> CommittedNetworkProofFixture {
    let mut chain = proof_chain(false);
    chain.commit(Vec::new());
    let fixture = CommittedNetworkProofFixture::from_chain(chain);
    assert_eq!(fixture.blocks.len(), 3);
    fixture
}

fn kagemusha_frame_bytes(fixture: &CommittedNetworkProofFixture, height: usize) -> u64 {
    u64::try_from(fixture.blocks[height - 1].encode_wire().unwrap().len()).unwrap()
}

#[test]
fn block_proofs_kagemusha_owner_projects_external_signers_without_paths() {
    let fixture = proof_fixture();
    let state = proof_state(&fixture);
    let block = fixture.target();
    let height = nonzero!(2_u64);
    let frames = kagemusha_frames();
    let budget = kagemusha_read_budget(&frames);
    // The target is the native tip: the checkpoint-resumed read authenticates its frame only.
    let target_bytes = kagemusha_frame_bytes(&fixture, 2);
    for (index, input) in block.network_entrypoints().enumerate() {
        let TransactionEntrypoint::External(signed) = input else {
            panic!("the proof fixture inputs are External")
        };
        let entry = input.hash();
        let paths = kagemusha_paths_built();
        let (owner, owner_reads) = kagemusha_cold_walk(&fixture, || {
            state.kagemusha_ledger_entry_owner(height, entry, proof_limits(), &budget)
        });
        let owner = owner.unwrap();
        assert_eq!(&owner.authority, signed.authority());
        assert!(
            owner.attempts.is_empty(),
            "Log and Unregister name no KAGEMUSHA attempt"
        );
        assert!(!owner.is_attempt_of(signed.authority(), &[1; 32], &[2; 32]));
        // One authenticated frame read, no Merkle path and no retained frame charge.
        assert_eq!(owner_reads, target_bytes);
        assert_eq!(kagemusha_paths_built(), paths);
        assert_eq!(frames.reserved_bytes(), 0);

        // An owner the caller refuses builds no path and copies no output.
        let (refused, refused_reads) = kagemusha_cold_walk(&fixture, || {
            state.kagemusha_ledger_inclusion_for_entry(
                height,
                entry,
                proof_limits(),
                &budget,
                |_| false,
            )
        });
        assert!(refused.unwrap().is_none());
        assert_eq!(refused_reads, owner_reads);
        assert_eq!(kagemusha_paths_built(), paths);

        let (found, inclusion_reads) = kagemusha_cold_walk(&fixture, || {
            state.kagemusha_ledger_inclusion_for_entry(
                height,
                entry,
                proof_limits(),
                &budget,
                |candidate| *candidate == owner,
            )
        });
        let found = found.unwrap().expect("the caller admits this owner");
        assert_eq!(inclusion_reads, owner_reads);
        assert_eq!(kagemusha_paths_built(), paths + 2);
        assert_eq!(frames.reserved_bytes(), 0);
        assert_eq!(found.owner, owner);
        let inclusion = &found.inclusion;
        let row = inclusion
            .joined_network_output()
            .expect("both leaf indices equal the Network row's input index");
        assert_eq!(usize::try_from(row.input_index).unwrap(), index);
        assert_eq!(inclusion.entry_proof.leaf_index(), row.input_index);
        assert_eq!(inclusion.output_proof.leaf_index(), row.input_index);
        assert_eq!(row.result.is_err(), index == 1);
        // The same entry path, complete output row and output path as the genesis-rooted
        // full proof.
        let proofs = state
            .block_proofs_for_entry(height, entry, proof_limits())
            .unwrap();
        assert_eq!(&inclusion.entry_proof, proofs.entry_proof.proof());
        assert_eq!(&inclusion.output, proofs.output_proof.output());
        assert_eq!(&inclusion.output_proof, proofs.output_proof.proof());
        assert!(
            inclusion
                .entry_proof
                .verify(&entry, &proofs.entry_commitment)
        );
        assert!(
            inclusion
                .output_proof
                .verify(&HashOf::new(&inclusion.output), &proofs.output_commitment)
        );
    }
}

#[test]
fn block_proofs_kagemusha_refuse_genesis_internal_calls_and_sealed_inputs_before_paths() {
    let height = nonzero!(2_u64);
    let fixture = proof_fixture();
    let state = proof_state(&fixture);
    let block = fixture.target();
    let paths = kagemusha_paths_built();
    for output in &block.execution_outputs()[2..] {
        let hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(
            output.execution_call_hash(block.hash(), block).unwrap(),
        );
        assert!(
            matches!(kagemusha_owner(&state, height, hash, proof_limits()),
            Err(BlockProofError::EntrypointNotFound { entry_hash, block_height })
                if entry_hash == hash && block_height == height)
        );
        assert!(
            matches!(kagemusha_inclusion(&state, height, hash, proof_limits()),
            Err(BlockProofError::EntrypointNotFound { entry_hash, block_height })
                if entry_hash == hash && block_height == height)
        );
    }
    // Genesis carries no wallet attempt and has no compact certificate: nothing is read.
    let genesis =
        HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::prehashed([0x47; 32]));
    for read in [
        kagemusha_cold_walk(&fixture, || {
            kagemusha_owner(&state, NonZeroU64::MIN, genesis, proof_limits()).map(drop)
        }),
        kagemusha_cold_walk(&fixture, || {
            kagemusha_inclusion(&state, NonZeroU64::MIN, genesis, proof_limits()).map(drop)
        }),
    ] {
        assert!(
            matches!(read, (Err(BlockProofError::EntrypointNotFound { entry_hash, block_height }), 0)
                if entry_hash == genesis && block_height == NonZeroU64::MIN),
            "{read:?}"
        );
    }
    // A sealed commitment is a Network input the full proof serves, but it has no External
    // signer and therefore no KAGEMUSHA attempt.
    let fixture = CommittedNetworkProofFixture::from_chain(proof_chain(true));
    let state = proof_state(&fixture);
    let sealed = fixture.target().network_entrypoint_at(0).unwrap();
    assert!(matches!(sealed, TransactionEntrypoint::SealedCommitment(_)));
    let hash = sealed.hash();
    assert!(
        state
            .block_proofs_for_entry(height, hash, proof_limits())
            .is_ok()
    );
    assert!(
        matches!(kagemusha_owner(&state, height, hash, proof_limits()),
        Err(BlockProofError::EntrypointNotFound { entry_hash, .. }) if entry_hash == hash)
    );
    assert!(
        matches!(kagemusha_inclusion(&state, height, hash, proof_limits()),
        Err(BlockProofError::EntrypointNotFound { entry_hash, .. }) if entry_hash == hash)
    );
    assert_eq!(kagemusha_paths_built(), paths);
}

#[test]
fn block_proofs_kagemusha_refuse_a_body_without_the_exact_output_join() {
    let fixture = proof_fixture();
    let altered = mutate_stored_block(fixture.target(), |_, result| {
        result.outputs.remove(1);
        result.output_merkle = result.outputs.iter().map(HashOf::new).collect();
    });
    fixture.replace_target_wire(&altered.encode_wire().unwrap());
    let state = proof_state(&fixture);
    let entry = fixture.target().network_entrypoint_at(1).unwrap().hash();
    let height = nonzero!(2_u64);
    for error in [
        kagemusha_owner(&state, height, entry, proof_limits()).unwrap_err(),
        kagemusha_inclusion(&state, height, entry, proof_limits()).unwrap_err(),
    ] {
        assert!(
            matches!(error, BlockProofError::InvalidOutputs { block_height, .. }
            | BlockProofError::Storage { block_height, .. } if block_height == height),
            "{error:?}"
        );
    }
}

#[test]
fn block_proofs_kagemusha_admit_each_limit_before_its_read() {
    let height = nonzero!(2_u64);
    let fixture = kagemusha_walk_fixture();
    let state = proof_state(&fixture);
    let entry = fixture.target().network_entrypoint_at(0).unwrap().hash();
    let (target, above) = (
        kagemusha_frame_bytes(&fixture, 2),
        kagemusha_frame_bytes(&fixture, 3),
    );
    let work = 6; // two source rows, all four outputs, no FASTPQ map/transcript rows.
    let capacity = |resource, actual, limit| BlockProofError::CapacityExceeded {
        block_height: height,
        resource,
        actual,
        limit,
    };
    let paths = kagemusha_paths_built();
    for (limits, refusal, reads) in [
        // A zero allowance and an oversized target refuse before any body I/O.
        (
            BlockProofLimits {
                max_source_blocks: 0,
                ..proof_limits()
            },
            capacity(BlockProofResource::SourceBlocks, 1, 0),
            0,
        ),
        (
            BlockProofLimits {
                max_source_wire_bytes: 0,
                ..proof_limits()
            },
            capacity(BlockProofResource::SourceWireBytes, 1, 0),
            0,
        ),
        (
            BlockProofLimits {
                max_block_wire_bytes: 0,
                ..proof_limits()
            },
            capacity(BlockProofResource::BlockWireBytes, 1, 0),
            0,
        ),
        (
            BlockProofLimits {
                max_work_items: 0,
                ..proof_limits()
            },
            capacity(BlockProofResource::WorkItems, 1, 0),
            0,
        ),
        (
            BlockProofLimits {
                max_response_bytes: 0,
                ..proof_limits()
            },
            capacity(BlockProofResource::ResponseBytes, 1, 0),
            0,
        ),
        (
            BlockProofLimits {
                max_block_wire_bytes: target - 1,
                ..proof_limits()
            },
            capacity(BlockProofResource::BlockWireBytes, target, target - 1),
            0,
        ),
        // The walk admits each frame before reading it: H3 is read, H2 is not.
        (
            BlockProofLimits {
                max_source_blocks: 1,
                ..proof_limits()
            },
            capacity(BlockProofResource::SourceBlocks, 2, 1),
            above,
        ),
        (
            BlockProofLimits {
                max_source_wire_bytes: above + target - 1,
                ..proof_limits()
            },
            capacity(
                BlockProofResource::SourceWireBytes,
                above + target,
                above + target - 1,
            ),
            above,
        ),
        // Rows are admitted after the authenticated read, before validation.
        (
            BlockProofLimits {
                max_work_items: work - 1,
                ..proof_limits()
            },
            capacity(BlockProofResource::WorkItems, work, work - 1),
            above + target,
        ),
    ] {
        let (owner, owner_reads) =
            kagemusha_cold_walk(&fixture, || kagemusha_owner(&state, height, entry, limits));
        assert_eq!(format!("{:?}", owner.unwrap_err()), format!("{refusal:?}"));
        assert_eq!(owner_reads, reads, "{refusal:?}");
        let (found, found_reads) = kagemusha_cold_walk(&fixture, || {
            kagemusha_inclusion(&state, height, entry, limits)
        });
        assert_eq!(format!("{:?}", found.unwrap_err()), format!("{refusal:?}"));
        assert_eq!(found_reads, reads, "{refusal:?}");
    }
    assert_eq!(kagemusha_paths_built(), paths);
}

#[test]
fn block_proofs_kagemusha_read_from_the_nearest_checkpoint_never_from_genesis() {
    let height = nonzero!(2_u64);
    let fixture = kagemusha_walk_fixture();
    let state = proof_state(&fixture);
    let entry = fixture.target().network_entrypoint_at(0).unwrap().hash();
    let (genesis, target, above) = (
        kagemusha_frame_bytes(&fixture, 1),
        kagemusha_frame_bytes(&fixture, 2),
        kagemusha_frame_bytes(&fixture, 3),
    );
    let frames = kagemusha_frames();
    let budget = kagemusha_read_budget(&frames);
    // The genesis-rooted full proof authenticates H1 and H2.
    let (_, full_reads) = kagemusha_cold_read(&fixture, || {
        state
            .block_proofs_for_entry(height, entry, proof_limits())
            .unwrap()
    });
    assert_eq!(full_reads, genesis + target);
    // Cold: the ledger read walks down from the tip through H3 to H2, never to genesis, and
    // fits exactly two frames.
    let exact = BlockProofLimits {
        max_source_blocks: 2,
        max_source_wire_bytes: above + target,
        ..proof_limits()
    };
    let (owner, cold_reads) = kagemusha_cold_walk(&fixture, || {
        state.kagemusha_ledger_entry_owner(height, entry, exact, &budget)
    });
    let owner = owner.unwrap();
    assert_eq!(cold_reads, above + target);
    assert_eq!(frames.reserved_bytes(), 0);
    // Warm: the walk retained H2's verified identity, so the next read starts at the target
    // and fits one frame.
    let single = BlockProofLimits {
        max_source_blocks: 1,
        max_source_wire_bytes: target,
        ..proof_limits()
    };
    let (found, warm_reads) = kagemusha_cold_read(&fixture, || {
        state.kagemusha_ledger_inclusion_for_entry(height, entry, single, &budget, |_| true)
    });
    assert_eq!(found.unwrap().unwrap().owner, owner);
    assert_eq!(warm_reads, target);
    assert_eq!(frames.reserved_bytes(), 0);
}

#[test]
fn block_proofs_kagemusha_read_budget_refusal_stays_deferred_never_absent() {
    let height = nonzero!(2_u64);
    let fixture = proof_fixture();
    let state = proof_state(&fixture);
    let entry = fixture.target().network_entrypoint_at(0).unwrap().hash();
    let frames = kagemusha_frames();
    // The request's own cumulative decoder allowance cannot admit the target frame.
    let tight = CanonicalHistoryReadBudget::new(
        frames.clone(),
        norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            1_000_000,
            48 * 1024 * 1024,
            1_000_000,
            1,
            64,
        )),
    );
    let paths = kagemusha_paths_built();
    for read in [
        kagemusha_cold_walk(&fixture, || {
            state
                .kagemusha_ledger_entry_owner(height, entry, proof_limits(), &tight)
                .map(drop)
        }),
        kagemusha_cold_walk(&fixture, || {
            state
                .kagemusha_ledger_inclusion_for_entry(height, entry, proof_limits(), &tight, |_| {
                    true
                })
                .map(drop)
        }),
    ] {
        // A local refusal is a retry, never an absent entry (the 404-shaped answer).
        assert!(
            matches!(read.0, Err(BlockProofError::Deferred(_))),
            "{read:?}"
        );
    }
    assert_eq!(kagemusha_paths_built(), paths);
    assert_eq!(frames.reserved_bytes(), 0);
    // The same read under an admitted allowance projects the signer.
    assert!(kagemusha_owner(&state, height, entry, proof_limits()).is_ok());
}

#[test]
fn block_proofs_kagemusha_inclusion_admits_its_frame_before_copying_the_output() {
    let height = nonzero!(2_u64);
    let fixture = proof_fixture();
    let state = proof_state(&fixture);
    let entry = fixture.target().network_entrypoint_at(1).unwrap().hash();
    let found = kagemusha_inclusion(&state, height, entry, proof_limits())
        .unwrap()
        .unwrap();
    let frame = u64::try_from(norito::canonical_frame_len(&found.inclusion).unwrap()).unwrap();
    let tight = BlockProofLimits {
        max_response_bytes: frame - 1,
        ..proof_limits()
    };
    assert!(matches!(kagemusha_inclusion(&state, height, entry, tight),
        Err(BlockProofError::CapacityExceeded {
            resource: BlockProofResource::ResponseBytes, actual, limit, ..
        }) if actual == frame && limit == frame - 1));
    // The owner projection copies no output and is not bounded by the inclusion frame.
    assert_eq!(
        kagemusha_owner(&state, height, entry, tight).unwrap(),
        found.owner
    );
    let exact = kagemusha_inclusion(
        &state,
        height,
        entry,
        BlockProofLimits {
            max_response_bytes: frame,
            ..proof_limits()
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(exact, found);
}

/// One canonical frame of the KAGEMUSHA wallet vectors.
fn kagemusha_vector_frame(name: &str) -> Vec<u8> {
    let vectors: norito::json::Value = norito::json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/kagemusha/wallet_v1_vectors.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let row = vectors["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"].as_str() == Some(name))
        .unwrap();
    hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()
}

#[test]
fn block_proofs_kagemusha_owner_names_only_explicit_activate_and_unload_frames() {
    use iroha_data_model::{
        isi::{
            InstructionBox, Log,
            kagemusha_wallet::{KagemushaWalletLedgerActionV1 as Action, KagemushaWalletLedgerV1},
        },
        kagemusha::{
            KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1, KagemushaWalletActivationV1,
            KagemushaWalletUnloadClaimV1,
        },
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    let activation_frame = kagemusha_vector_frame("KagemushaWalletActivationV1");
    let claim_frame = kagemusha_vector_frame("KagemushaWalletUnloadClaimV1");
    let activation: KagemushaWalletActivationV1 = norito::decode_canonical_with_limits(
        &activation_frame,
        norito::canonical_decode_limits(activation_frame.len()),
    )
    .unwrap();
    let claim: KagemushaWalletUnloadClaimV1 = norito::decode_canonical_with_limits(
        &claim_frame,
        norito::canonical_decode_limits(claim_frame.len()),
    )
    .unwrap();
    let (scheme, wallet) = (
        activation.credential.body.scheme_id,
        activation.credential.body.wallet_id,
    );
    let (unload_scheme, unload_wallet) = (
        claim.credential.body.scheme_id,
        claim.credential.body.wallet_id,
    );
    let mut foreign_scheme = scheme;
    foreign_scheme[0] ^= 1;
    let mut truncated = activation_frame.clone();
    truncated.pop();
    let oversized = [
        claim_frame.clone(),
        vec![0; KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1],
    ]
    .concat();
    let ledger = |scheme: [u8; 32], action: Action| {
        InstructionBox::from(KagemushaWalletLedgerV1::new(scheme, action))
    };
    let key = iroha_crypto::KeyPair::from_seed(vec![7; 32], iroha_crypto::Algorithm::Ed25519);
    let authority = AccountId::new(key.public_key().clone());
    let network = iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        Hash::prehashed([0x5A; 32]),
    ));
    let signed = TransactionBuilder::new(
        network,
        authority.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([
        InstructionBox::from(Log::new(
            iroha_logger::Level::INFO,
            "not a ledger instruction".into(),
        )),
        ledger(scheme, Action::Activate(activation_frame.clone())),
        ledger(unload_scheme, Action::Unload(claim_frame)),
        // Another action, another scheme, a noncanonical frame and an oversized frame
        // name no attempt.
        ledger(scheme, Action::Abandon(activation_frame.clone())),
        ledger(foreign_scheme, Action::Activate(activation_frame)),
        ledger(scheme, Action::Activate(truncated)),
        ledger(unload_scheme, Action::Unload(oversized)),
    ])
    .sign(key.private_key());
    let owner = KagemushaLedgerEntryOwnerV1::from_signed(&signed).unwrap();
    assert_eq!(owner.authority, authority);
    assert_eq!(
        owner.attempts,
        vec![
            KagemushaLedgerAttemptV1 {
                scheme,
                kind: KagemushaLedgerAttemptKindV1::Activate,
                wallet,
            },
            KagemushaLedgerAttemptV1 {
                scheme: unload_scheme,
                kind: KagemushaLedgerAttemptKindV1::Unload {
                    account: claim.account.clone(),
                },
                wallet: unload_wallet,
            },
        ]
    );
    assert!(owner.is_attempt_of(&authority, &scheme, &wallet));
    assert!(owner.is_attempt_of(&authority, &unload_scheme, &unload_wallet));
    // The authority relays this claim; the account the claim pays owns the Unload too.
    assert_ne!(claim.account, authority);
    assert!(owner.is_attempt_of(&claim.account, &unload_scheme, &unload_wallet));
    let other = iroha_crypto::KeyPair::from_seed(vec![8; 32], iroha_crypto::Algorithm::Ed25519);
    assert!(!owner.is_attempt_of(
        &AccountId::new(other.public_key().clone()),
        &scheme,
        &wallet
    ));
    assert!(!owner.is_attempt_of(&authority, &foreign_scheme, &wallet));
    let mut other_wallet = wallet;
    other_wallet[0] ^= 1;
    assert!(!owner.is_attempt_of(&authority, &scheme, &other_wallet));
    // A refusal by the caller's own decode budget is local: never an absent attempt (a
    // 404-shaped answer), always a deferred retry.
    let tight = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        1_000_000,
        48 * 1024 * 1024,
        1_000_000,
        1,
        64,
    ));
    let deferred = tight.with(|| KagemushaLedgerEntryOwnerV1::from_signed(&signed));
    assert!(
        matches!(deferred, Err(BlockProofError::Deferred(_))),
        "{deferred:?}"
    );
    assert_eq!(
        KagemushaLedgerEntryOwnerV1::from_signed(&signed).unwrap(),
        owner
    );
}

#[test]
fn block_proofs_kagemusha_relayed_unload_is_owned_by_its_signer_and_its_claim_account() {
    use iroha_data_model::{
        isi::{
            InstructionBox,
            kagemusha_wallet::{KagemushaWalletLedgerActionV1 as Action, KagemushaWalletLedgerV1},
        },
        kagemusha::KagemushaWalletUnloadClaimV1,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    let activation_frame = kagemusha_vector_frame("KagemushaWalletActivationV1");
    let claim_frame = kagemusha_vector_frame("KagemushaWalletUnloadClaimV1");
    let claim: KagemushaWalletUnloadClaimV1 = norito::decode_canonical_with_limits(
        &claim_frame,
        norito::canonical_decode_limits(claim_frame.len()),
    )
    .unwrap();
    let (scheme, wallet) = (
        claim.credential.body.scheme_id,
        claim.credential.body.wallet_id,
    );
    let key = |seed: u8| {
        iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
    };
    let relayer_key = key(9);
    let relayer = AccountId::new(relayer_key.public_key().clone());
    let third = AccountId::new(key(10).public_key().clone());
    let claimant = claim.account.clone();
    assert_ne!(claimant, relayer, "the signer only relays this claim");
    assert_ne!(claimant, third);
    assert_ne!(relayer, third);
    let network = iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        Hash::prehashed([0x5A; 32]),
    ));
    // One External input of the relayer carrying `actions` under the claim's scheme.
    let owner_of = |actions: Vec<Action>| {
        let signed = TransactionBuilder::new(
            network,
            relayer.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(
            actions
                .into_iter()
                .map(|action| InstructionBox::from(KagemushaWalletLedgerV1::new(scheme, action))),
        )
        .sign(relayer_key.private_key());
        KagemushaLedgerEntryOwnerV1::from_signed(&signed).unwrap()
    };
    let mut other_scheme = scheme;
    other_scheme[0] ^= 1;
    let mut other_wallet = wallet;
    other_wallet[0] ^= 1;

    // A relayed Unload: its claim pays another account than the input's signer.
    let unload = owner_of(vec![Action::Unload(claim_frame)]);
    assert_eq!(unload.authority, relayer);
    assert_eq!(
        unload.attempts,
        vec![KagemushaLedgerAttemptV1 {
            scheme,
            kind: KagemushaLedgerAttemptKindV1::Unload {
                account: claimant.clone(),
            },
            wallet,
        }]
    );
    // The claim account owns it, and the claim naming another account does not make the
    // relayer's own query fail. A third account, another scheme or another wallet does not.
    assert!(unload.is_attempt_of(&claimant, &scheme, &wallet));
    assert!(unload.is_attempt_of(&relayer, &scheme, &wallet));
    assert!(!unload.is_attempt_of(&third, &scheme, &wallet));
    for caller in [&claimant, &relayer, &third] {
        assert!(!unload.is_attempt_of(caller, &other_scheme, &wallet));
        assert!(!unload.is_attempt_of(caller, &scheme, &other_wallet));
    }

    // An Activate names no paid account and stays signer-only, even though its credential
    // is the claim account's own.
    let activate = owner_of(vec![Action::Activate(activation_frame.clone())]);
    assert_eq!(
        activate.attempts,
        vec![KagemushaLedgerAttemptV1 {
            scheme,
            kind: KagemushaLedgerAttemptKindV1::Activate,
            wallet,
        }]
    );
    assert!(activate.is_attempt_of(&relayer, &scheme, &wallet));
    assert!(!activate.is_attempt_of(&claimant, &scheme, &wallet));
    assert!(!activate.is_attempt_of(&third, &scheme, &wallet));

    // In one input the claim account owns only the Unload its claim names, never the input's
    // other attempts; the signer owns both. The changed claim is DATA: no validation runs.
    let mut elsewhere = claim.clone();
    elsewhere.credential.body.wallet_id = other_wallet;
    let both = owner_of(vec![
        Action::Activate(activation_frame),
        Action::Unload(norito::encode_canonical(&elsewhere).unwrap()),
    ]);
    assert_eq!(both.attempts.len(), 2);
    for named in [wallet, other_wallet] {
        assert!(both.is_attempt_of(&relayer, &scheme, &named));
        assert!(!both.is_attempt_of(&third, &scheme, &named));
    }
    assert!(both.is_attempt_of(&claimant, &scheme, &other_wallet));
    assert!(!both.is_attempt_of(&claimant, &scheme, &wallet));
}
