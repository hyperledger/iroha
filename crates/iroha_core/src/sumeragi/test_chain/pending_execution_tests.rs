// Actual Worker source ownership, native preparation and strict signed genesis controls.

fn chain() -> CertifiedTestChain {
    CertifiedTestChain::start(TestChainConfig::new(World::new(), 1000)).unwrap()
}

#[test]
fn pending_execution_retains_one_source_and_publishes_once() {
    let mut chain = chain();
    let state = Arc::clone(chain.state());
    let kura = Arc::clone(chain.kura());
    let proposal = chain.proposal(Some(2000), Vec::new());
    let source_hash = proposal.hash();
    let mut pending = chain
        .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default())
        .unwrap();
    let result = pending.result();
    let inspect = |original: super::super::super::executor::PendingExecutionView<'_, '_>| {
        original
            .state
            .verify_sumeragi_execution_witness(original.block.as_ref(), original.witness.wire())
            .unwrap();
        (
            original.block.as_ref().hash(),
            iroha_crypto::HashOf::new(original.witness.wire()),
        )
    };
    let first = pending.inspect(inspect).unwrap();
    let second = pending.inspect(inspect).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.0, source_hash);
    assert_eq!(
        kura.blocks_count(),
        1,
        "execution has not persisted anything"
    );
    pending.prepare(Signers::Quorum).unwrap();
    pending.prepare(Signers::Quorum).unwrap();
    assert!(
        pending
            .inspect(|_| ())
            .unwrap_err()
            .contains("cannot be mutated")
    );
    assert_eq!(
        kura.blocks_count(),
        1,
        "preparation alone is not durable publication"
    );
    let published = pending.publish(Signers::Quorum).unwrap();
    let repeated = pending.publish(Signers::Quorum).unwrap();
    assert_eq!(
        published.block().encode_wire().unwrap(),
        repeated.block().encode_wire().unwrap()
    );
    assert_eq!(published.result(), result);
    assert!(pending.publish(Signers::LastThree).is_err());
    drop(pending);
    assert_eq!(kura.blocks_count(), 2);
    assert_eq!(state.view().height(), 2);
    assert_eq!(chain.committed(2).result(), result);
    assert!(!chain.take_events().unwrap().is_empty());
    assert!(
        chain.take_events().unwrap().is_empty(),
        "publication delivers each event once"
    );
}

#[test]
fn original_wire_witness_and_world_tampering_fail_before_durable_staging() {
    for mutation in 0..4 {
        let mut chain = chain();
        let state = Arc::clone(chain.state());
        let kura = Arc::clone(chain.kura());
        let budget = state.ivm_execution_budget();
        let parent = chain.committed(1).block().encode_wire().unwrap();
        let proposal = chain.proposal(Some(2000), Vec::new());
        let mut pending = chain
            .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default())
            .unwrap();
        let original_result = pending.result();
        pending
            .inspect(move |mut original| {
                original
                    .state
                    .verify_sumeragi_execution_witness(
                        original.block.as_ref(),
                        original.witness.wire(),
                    )
                    .unwrap();
                match mutation {
                    0 => {
                        use iroha_data_model::block::{BlockSignatures, PreparedBlockSignatures};
                        use norito::{
                            SerializePayload,
                            core::{DecodeFlagsGuard, Encoder, SequenceSpan},
                        };
                        let hash = original.block.as_ref().hash();
                        let wire = original.block.as_ref().encode_wire().unwrap();
                        let key = KeyPair::from_seed(vec![0x91; 32], Algorithm::Ed25519);

                        assert!(original.block.as_ref().signatures_admitted_to(&budget));
                        let signature = iroha_data_model::block::BlockSignature::new(
                            1,
                            iroha_crypto::SignatureOf::from_hash(key.private_key(), hash),
                        );
                        let before = budget.reserved_bytes();
                        assert!(matches!(
                            original.block.as_mut().add_signature(signature.clone()),
                            Err(iroha_crypto::Error::Signing(reason))
                                if reason == "admitted block signatures are immutable"
                        ));
                        assert_eq!(original.block.as_ref().encode_wire().unwrap(), wire);
                        assert_eq!(budget.reserved_bytes(), before);

                        // Construct altered offered bytes through the genuine bounded
                        // signature producer; admission keeps the original State pool.
                        let offered = BlockSignatures::try_from_iter(
                            original
                                .block
                                .as_ref()
                                .signatures()
                                .cloned()
                                .chain([signature]),
                        )
                        .unwrap();
                        assert!(!offered.admitted_to(&budget));
                        assert!(matches!(
                            original.block.as_mut().replace_signatures(offered.clone()),
                            Err(iroha_crypto::Error::Signing(reason))
                                if reason == "block signature replacement changed original custody"
                        ));
                        assert_eq!(original.block.as_ref().encode_wire().unwrap(), wire);
                        assert_eq!(budget.reserved_bytes(), before);
                        let _flags = DecodeFlagsGuard::enter(0);
                        let mut offered_wire = Vec::new();
                        offered
                            .serialize(&mut Encoder::for_buffer(&mut offered_wire))
                            .unwrap();
                        let mut source =
                            iroha_allocation::ChargedBuffer::new(offered_wire.len(), &budget)
                                .unwrap();
                        source.append(&offered_wire).unwrap();
                        assert!(source.belongs_to(&budget));
                        let source_pointer = source.as_slice().as_ptr();
                        let span = SequenceSpan {
                            start: 0,
                            end: offered_wire.len(),
                        };
                        let mut prepared =
                            PreparedBlockSignatures::from_source(&source, span, &budget).unwrap();
                        prepared.prepare(&source).unwrap();
                        let replacement = prepared
                            .finish(&source)
                            .unwrap_or_else(|(_, error)| panic!("{error}"));
                        assert!(replacement.admitted_to(&budget));
                        assert_eq!(replacement, offered);
                        let retained = original
                            .block
                            .as_mut()
                            .replace_signatures(replacement)
                            .unwrap();
                        assert!(retained.admitted_to(&budget));
                        assert!(original.block.as_ref().signatures_admitted_to(&budget));
                        assert_eq!(source.as_slice().as_ptr(), source_pointer);
                        let signature_backing: usize =
                            BlockSignatures::backing_layouts(offered.len())
                                .unwrap()
                                .iter()
                                .map(std::alloc::Layout::size)
                                .sum();
                        let signature_bytes: usize = offered
                            .iter()
                            .map(|value| value.signature().payload().len())
                            .sum();
                        assert_eq!(
                            budget.reserved_bytes(),
                            before
                                + offered_wire.len()
                                + signature_backing
                                + signature_bytes
                                + BlockSignatures::allocation_layout().size()
                        );
                        assert_eq!(original.block.as_ref().hash(), hash);
                        assert_ne!(original.block.as_ref().encode_wire().unwrap(), wire);
                    }
                    1 => {
                        // Reconstruct altered offered bytes; the exact funded original
                        // remains protected and its original credits stay retained.
                        original.witness.offer_reconstructed_tamper(|offered| {
                            let write = offered
                                .writes
                                .first_mut()
                                .expect("genuine native witness has writes");
                            write.value.push(0xFF);
                        });
                    }
                    2 => original.state.world.sumeragi_lanes.get_mut().incarnations += 1,
                    _ => {
                        let hash = original.block.as_ref().hash();
                        let wire = original.block.as_ref().encode_wire().unwrap();
                        let key = KeyPair::from_seed(vec![0x91; 32], Algorithm::Ed25519);
                        let signature = iroha_data_model::block::BlockSignature::new(
                            1,
                            iroha_crypto::SignatureOf::from_hash(key.private_key(), hash),
                        );
                        // The actual admitted owner cannot be edited or downgraded.
                        let kept_original = original.block.as_ref().clone();
                        assert!(
                            original
                                .block
                                .as_ref()
                                .same_signature_custody(&kept_original)
                        );
                        assert!(matches!(
                            original.block.as_mut().add_signature(signature.clone()),
                            Err(iroha_crypto::Error::Signing(message))
                                if message == "admitted block signatures are immutable"
                        ));
                        assert_eq!(original.block.as_ref().encode_wire().unwrap(), wire);
                        // Offer a genuinely reconstructed, untrusted altered wire through
                        // the existing test-only view. Keep the original custody alive
                        // through the production witness rejection; it grants no custody
                        // to this equal-header replacement.
                        let mut offered =
                            iroha_data_model::block::decode_framed_signed_block(&wire).unwrap();
                        assert!(!offered.same_signature_custody(&kept_original));
                        offered.add_signature(signature).unwrap();
                        assert_eq!(offered.hash(), hash);
                        assert_ne!(offered.encode_wire().unwrap(), wire);
                        *original.block.as_mut() = offered;
                        assert!(
                            original
                                .state
                                .verify_sumeragi_execution_witness(
                                    original.block.as_ref(),
                                    original.witness.wire(),
                                )
                                .is_err()
                        );
                        assert_eq!(kept_original.encode_wire().unwrap(), wire);
                    }
                }
                assert!(
                    original
                        .state
                        .verify_sumeragi_execution_witness(
                            original.block.as_ref(),
                            original.witness.wire()
                        )
                        .is_err()
                );
            })
            .unwrap();
        assert!(pending.prepare(Signers::Quorum).is_err());
        assert!(pending.publish(Signers::Quorum).is_err());
        assert_eq!(
            pending.result(),
            original_result,
            "failure never re-executes or replaces R"
        );
        assert_eq!(kura.blocks_count(), 1);
        assert_eq!(
            kura.get_block(
                std::num::NonZeroUsize::new(1).unwrap(),
                &state.ivm_execution_budget()
            )
            .expect("original block read attempt")
            .unwrap()
            .encode_wire()
            .unwrap(),
            parent
        );
        drop(pending);
        assert_eq!(state.view().height(), 1);
    }
}

#[test]
fn pending_execution_rejects_inexact_quorum_without_publication() {
    for signers in [Signers::BelowQuorum, Signers::All] {
        let mut chain = chain();
        let kura = Arc::clone(chain.kura());
        let proposal = chain.proposal(Some(2000), Vec::new());
        let mut pending = chain
            .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default())
            .unwrap();
        assert!(pending.prepare(signers).is_err());
        assert!(
            pending
                .prepare(Signers::Quorum)
                .unwrap_err()
                .contains("cannot be replaced")
        );
        assert_eq!(kura.blocks_count(), 1);
    }
}

#[test]
fn discarded_unprepared_execution_leaves_original_state_unchanged() {
    let mut chain = chain();
    let state = Arc::clone(chain.state());
    let proposal = chain.proposal(Some(2000), Vec::new());
    let pending = chain
        .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default())
        .unwrap();
    drop(pending);
    let next = chain.proposal(Some(2000), Vec::new());
    assert_eq!(state.view().height(), 1);
    assert_eq!(state.kura().blocks_count(), 1);
    chain.commit_proposal(
        next,
        Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    assert_eq!(state.view().height(), 2);
}

#[test]
fn prepared_genesis_derives_then_enforces_both_signed_native_policies() {
    let prepared = CertifiedTestChain::prepare(TestChainConfig::new(World::new(), 1000)).unwrap();
    let topology = super::super::super::network_topology::Topology::new(
        prepared
            .validator_keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone())),
    );
    let account = AccountId::new(prepared.genesis.public_key().clone());
    let result = {
        let selected_genesis = prepared.genesis.block().clone();
        let selected_scope = crate::sumeragi::epoch::authenticated_genesis(&selected_genesis)
            .expect("signed fixture root scope")
            .into_parts()
            .1;
        crate::block::ValidBlock::validate_signed_genesis(
            selected_genesis,
            &topology,
            &account,
            &TimeSource::new_system(),
            &prepared.state,
            ConsensusMode::Permissioned,
            selected_scope,
        )
    }
    .unpack(|_| {});
    let (_, overlay) =
        result.unwrap_or_else(|(_, error)| panic!("final signed policies must execute: {error}"));
    let metadata = prepared.genesis.consensus_metadata();
    assert_eq!(
        iroha_crypto::Hash::prehashed(metadata.sumeragi_context.execution_policy_hash),
        super::super::super::staged_genesis_execution_policy_hash(&overlay).unwrap(),
    );
    assert_eq!(
        iroha_crypto::Hash::prehashed(metadata.sumeragi_context.nexus_amx_context_hash),
        super::super::super::staged_genesis_nexus_amx_context_hash(&overlay),
    );
    drop(overlay);
    assert_eq!(prepared.state.view().height(), 0);
    assert_eq!(prepared.kura.blocks_count(), 0);
    assert_eq!(
        prepared.state.view().network_id(),
        &NetworkId::from_genesis_hash(prepared.genesis.expected_hash())
    );
}

#[test]
fn changed_original_genesis_configuration_is_rejected_before_publication() {
    let mut prepared =
        CertifiedTestChain::prepare(TestChainConfig::new(World::new(), 1000)).unwrap();
    Arc::get_mut(&mut prepared.state)
        .unwrap()
        .edit_pipeline_for_testing(|pipeline| pipeline.amx_group_budget_ms += 1);
    let topology = super::super::super::network_topology::Topology::new(
        prepared
            .validator_keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone())),
    );
    let error = {
        let selected_genesis = prepared.genesis.block().clone();
        let selected_scope = crate::sumeragi::epoch::authenticated_genesis(&selected_genesis)
            .expect("signed fixture root scope")
            .into_parts()
            .1;
        crate::block::ValidBlock::validate_signed_genesis(
            selected_genesis,
            &topology,
            &AccountId::new(prepared.genesis.public_key().clone()),
            &TimeSource::new_system(),
            &prepared.state,
            ConsensusMode::Permissioned,
            selected_scope,
        )
    }
    .unpack(|_| {})
    .err()
    .expect("configured policy mismatch must reject")
    .1;
    assert!(
        matches!(*error, crate::block::BlockValidationError::GenesisPolicyMismatch {
        expected_execution, actual_execution, expected_nexus, actual_nexus,
    } if expected_execution != actual_execution || expected_nexus != actual_nexus)
    );
    assert_eq!(prepared.state.view().height(), 0);
    assert_eq!(prepared.kura.blocks_count(), 0);
}
