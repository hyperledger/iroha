//! Original completed proposal ownership across actual decoder, prevalidation and return boundaries.
//!
//! These controls use the real four-validator signed genesis, State pool and signed RS16 body.
//! They do not establish full transaction/DA/result allocation admission or panic recovery.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_sumeragi::preimage::payload_hash;
use norito::core::EncodeValueDepthGuard;

fn original_attempt(worker: &Worker<'_>, block: &AvailableBody) -> SignatureDecodeAttempt {
    let budget = worker.state.ivm_execution_budget();
    SignatureDecodeAttempt {
        block_hash: block.hash(&**worker.context.crypto.as_ref().unwrap()),
        source: block.clone(),
        decoder: iroha_data_model::block::PreparedSignedBlockSignaturesDecode::new(&budget)
            .unwrap(),
        decoded: None,
        returned_refusal: None,
        amx_legs: None,
        parent_service: crate::sumeragi::certified_chain::ParentServicePreparation::default(),
    }
}

#[test]
fn completed_decoded_retry_borrows_original_graph_without_canonical_reentry() {
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let block = publication_tests::proposal(chain, worker);
        let budget = worker.state.ivm_execution_budget();
        let mut attempt = original_attempt(worker, &block);
        let original = attempt.original_decoded(&budget).unwrap();
        assert!(!original.external_entrypoints_slice().is_empty());
        let entries = original.external_entrypoints_slice().as_ptr();
        let header = original.header();
        let entry_hash = original.external_entrypoints_slice()[0].hash();
        let source = block.payload().as_slice().as_ptr();
        let occupied = budget.reserved_bytes();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        // The original code calls decode_prepared again here and really refuses under
        // this inherited scope. No decoder or fresh pool is substituted on the fixed path.
        norito::with_decode_limits_scope(limits, || {
            let retry = attempt
                .original_decoded(&budget)
                .expect("completed original retry must not reenter canonical decoding");
            assert_eq!(retry.external_entrypoints_slice().as_ptr(), entries);
            assert_eq!(retry.header(), header);
            assert_eq!(retry.external_entrypoints_slice()[0].hash(), entry_hash);
            assert!(retry.signatures_admitted_to(&budget));
        });
        assert_eq!(attempt.source.payload().as_slice().as_ptr(), source);
        assert_eq!(budget.reserved_bytes(), occupied);
        assert!(events.try_recv().is_err());
        assert!(worker.live.is_none());
        assert!(worker.finishing.is_none());
        assert_eq!(worker.state.view().height(), 1);
        let original = attempt.decoded.take().unwrap();
        assert!(
            original
                .matches_resultless_proposal_wire(block.payload().as_slice())
                .unwrap()
        );
    });
}

#[test]
fn completed_decoded_foreign_pool_refusal_retains_exact_original_graph() {
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let block = publication_tests::proposal(chain, worker);
        let budget = worker.state.ivm_execution_budget();
        let mut attempt = original_attempt(worker, &block);
        let entries = attempt
            .original_decoded(&budget)
            .unwrap()
            .external_entrypoints_slice()
            .as_ptr();
        let occupied = budget.reserved_bytes();
        let foreign = AllocationBudget::new(budget.limit_bytes());
        assert!(!foreign.same_pool(&budget));
        assert!(matches!(attempt.original_decoded(&foreign),
            Err(payload::PayloadError::SignatureCustodyInvariant(ref reason))
                if reason == "completed proposal decoder belongs to another original pool"));
        assert_eq!(
            attempt
                .decoded
                .as_ref()
                .unwrap()
                .external_entrypoints_slice()
                .as_ptr(),
            entries
        );
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(budget.reserved_bytes(), occupied);
        assert_eq!(
            attempt
                .original_decoded(&budget)
                .unwrap()
                .external_entrypoints_slice()
                .as_ptr(),
            entries
        );
        assert!(events.try_recv().is_err());
    });
}

#[test]
fn completed_decoded_same_bytes_new_physical_source_cannot_replace_original() {
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let block = publication_tests::proposal(chain, worker);
        let budget = worker.state.ivm_execution_budget();
        let mut attempt = original_attempt(worker, &block);
        let entries = attempt
            .original_decoded(&budget)
            .unwrap()
            .external_entrypoints_slice()
            .as_ptr();
        // A second genuinely signed authoring owns equal canonical bytes in another actual
        // allocation. Equal content is not the retained decoder's original source identity.
        let replacement =
            chain.author_payload(block.header().clone(), block.payload().as_slice().to_vec());
        assert_eq!(replacement.payload().as_slice(), block.payload().as_slice());
        assert_ne!(
            replacement.payload().as_slice().as_ptr(),
            block.payload().as_slice().as_ptr()
        );
        let occupied = budget.reserved_bytes();
        let original_source = std::mem::replace(&mut attempt.source, replacement);
        assert!(matches!(
            attempt.original_decoded(&budget),
            Err(payload::PayloadError::SignatureCustodyInvariant(_))
        ));
        assert_eq!(
            attempt
                .decoded
                .as_ref()
                .unwrap()
                .external_entrypoints_slice()
                .as_ptr(),
            entries
        );
        assert_eq!(budget.reserved_bytes(), occupied);
        attempt.source = original_source;
        assert_eq!(
            attempt
                .original_decoded(&budget)
                .unwrap()
                .external_entrypoints_slice()
                .as_ptr(),
            entries
        );
        assert!(events.try_recv().is_err());
    });
}

#[test]
fn original_decoded_graph_survives_actual_prevalidation_policy_refusal_and_retry() {
    publication_tests::with_worker_from(
        || {
            let mut config = crate::sumeragi::test_chain::TestChainConfig::new(
                crate::state::World::new(),
                1_000,
            );
            config
                .genesis_parameters
                .push(iroha_data_model::parameter::Parameter::Custom(
                    iroha_data_model::sumeragi_lanes::SumeragiLanePolicy::for_chain(
                        iroha_data_model::parameter::system::SumeragiParameters::default(),
                        iroha_sumeragi::availability::recommended_data_availability_layout(),
                    )
                    .into_custom_parameter(),
                ));
            crate::sumeragi::test_chain::CertifiedTestChain::start(config)
                .expect("original signed lane policy")
        },
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, events| {
            let block = publication_tests::proposal(chain, worker);
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            let budget = worker.state.ivm_execution_budget();
            let mut attempt = original_attempt(worker, &block);
            let entries = attempt
                .original_decoded(&budget)
                .unwrap()
                .external_entrypoints_slice()
                .as_ptr();
            worker.signature_decode = Some(attempt);
            // Routing now authenticates the root metadata before the lane policy.
            // Fund only that exact completed prefix so this control still reaches
            // the policy reader rather than comparing two different JSON operations.
            let prefix = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                usize::MAX,
                64,
            ));
            prefix.with(|| {
                assert!(worker.state.view().latest_block().unwrap().is_some());
                assert!(
                    super::super::lanes::routing::read_routing_root_scope(
                        worker.state.view().world(),
                    )
                    .unwrap()
                    .is_some()
                );
            });
            let prefix_bytes = usize::try_from(prefix.consumed_allocated_bytes()).unwrap();
            assert!(
                prefix_bytes > 0,
                "the actual root reader consumes its measured prefix"
            );
            let limits =
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, prefix_bytes, 64);
            let original = norito::with_decode_limits_scope(limits, || {
                assert!(worker.state.view().latest_block().unwrap().is_some());
                assert!(
                    super::super::lanes::routing::read_routing_root_scope(
                        worker.state.view().world(),
                    )
                    .unwrap()
                    .is_some()
                );
                super::super::lanes::lane_policy(worker.state.view().world()).unwrap_err()
            });
            assert_eq!(
                original.reason(),
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity
            );
            let routed_budget = norito::core::DecodeBudgetContext::new(limits);
            let failure = routed_budget
                .with(|| worker.run_execution(&block, hash, false))
                .unwrap_err();
            assert_eq!(
                routed_budget.consumed_allocated_bytes(),
                u64::try_from(prefix_bytes).unwrap(),
                "the actual root prefix completes before the lane policy refuses"
            );
            let PublicationError::Deferred(ref source) = failure else {
                panic!("actual typed original policy refusal");
            };
            let retained = source.execution().unwrap();
            assert_eq!(retained.reason(), original.reason());
            assert_eq!(
                retained.decode_refusal().unwrap().resource_error(),
                original.decode_refusal().unwrap().resource_error()
            );
            assert_ne!(
                retained.decode_refusal(),
                original.decode_refusal(),
                "separate actual operations retain separate scope identity"
            );
            let attempt = worker.signature_decode.as_ref().unwrap();
            assert_eq!(
                attempt
                    .decoded
                    .as_ref()
                    .unwrap()
                    .external_entrypoints_slice()
                    .as_ptr(),
                entries
            );
            assert_eq!(
                attempt.source.payload().as_slice().as_ptr(),
                block.payload().as_slice().as_ptr()
            );
            assert!(worker.live.is_none());
            assert!(worker.finishing.is_none());
            assert!(worker.recovery.is_none());
            assert!(worker.quarantine_context.is_none());
            assert!(!worker.results.contains_key(&hash));
            assert!(worker.context.staging.get(&hash).is_none());
            assert!(events.try_recv().is_err());
            assert_eq!(worker.state.view().height(), 1);
            assert!(matches!(
                worker.execute(&block, hash, false),
                Ok(Some(ExecOutcome::Valid { .. }))
            ));
            let PublicationPhase::Executed { valid, .. } = &worker.live.as_ref().unwrap().phase
            else {
                panic!("same original graph completes actual validation");
            };
            assert_eq!(
                valid.as_ref().external_entrypoints_slice().as_ptr(),
                entries
            );
            assert!(worker.signature_decode.is_none());

            assert_eq!(worker.state.view().height(), 1);
        },
    );
}

struct EncoderParents(Vec<EncodeValueDepthGuard>);
impl EncoderParents {
    fn full() -> Self {
        Self(
            (0..norito::core::MAX_VALUE_NESTING_DEPTH)
                .map(|_| EncodeValueDepthGuard::enter().unwrap())
                .collect(),
        )
    }
}
impl Drop for EncoderParents {
    fn drop(&mut self) {
        while self.0.pop().is_some() {}
    }
}

#[test]
fn original_validation_return_projection_refusal_keeps_typed_error_and_same_graph() {
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let block = publication_tests::proposal(chain, worker);
        let budget = worker.state.ivm_execution_budget();
        let mut attempt = original_attempt(worker, &block);
        let entries = attempt
            .original_decoded(&budget)
            .unwrap()
            .external_entrypoints_slice()
            .as_ptr();
        let original = attempt.decoded.take().unwrap();
        let occupied = budget.reserved_bytes();
        let parents = EncoderParents::full();
        assert!(matches!(
            attempt.retain_validation_return(original, &budget),
            Err(PublicationError::RecoveryRequired(_))
        ));
        assert!(matches!(attempt.returned_refusal.as_ref(),
            Some(ReturnedDecodedRefusal::Codec(norito::Error::NestingDepthExceeded { depth, limit, context }))
                if *depth == norito::core::MAX_VALUE_NESTING_DEPTH + 1
                && *limit == norito::core::MAX_VALUE_NESTING_DEPTH && *context == "encode budget"));
        let retained = attempt.decoded.as_ref().unwrap();
        assert_eq!(retained.external_entrypoints_slice().as_ptr(), entries);
        assert!(retained.signatures_admitted_to(&budget));
        assert_eq!(budget.reserved_bytes(), occupied);
        drop(parents);
        // No ordinary retry can silently discard the unfinished original projection.
        assert!(matches!(
            attempt.original_decoded(&budget),
            Err(payload::PayloadError::SignatureCustodyInvariant(_))
        ));
        assert_eq!(
            attempt
                .decoded
                .as_ref()
                .unwrap()
                .external_entrypoints_slice()
                .as_ptr(),
            entries
        );
        assert!(events.try_recv().is_err());
        assert_eq!(worker.state.view().height(), 1);
    });
}

#[test]
fn original_validation_return_cannot_rebind_changed_header_to_authenticated_wire() {
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let block = publication_tests::proposal(chain, worker);
        let budget = worker.state.ivm_execution_budget();
        let mut attempt = original_attempt(worker, &block);
        let entries = attempt
            .original_decoded(&budget)
            .unwrap()
            .external_entrypoints_slice()
            .as_ptr();
        let mut original = attempt.decoded.take().unwrap();
        let mut header = original.header();
        header.set_view_change_index(header.view_change_index() + 1);
        original.replace_header_for_testing(header);
        assert!(matches!(
            attempt.retain_validation_return(original, &budget),
            Err(PublicationError::RecoveryRequired(_))
        ));
        assert!(matches!(
            attempt.returned_refusal,
            Some(ReturnedDecodedRefusal::SourceMismatch)
        ));
        assert_eq!(
            attempt
                .decoded
                .as_ref()
                .unwrap()
                .external_entrypoints_slice()
                .as_ptr(),
            entries
        );
        assert!(matches!(
            attempt.original_decoded(&budget),
            Err(payload::PayloadError::SignatureCustodyInvariant(_))
        ));
        assert!(events.try_recv().is_err());
    });
}

#[test]
fn explicit_completed_decoded_rejection_retires_only_original_height_view_hash() {
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let block = publication_tests::proposal(chain, worker);
        let budget = worker.state.ivm_execution_budget();
        let mut attempt = original_attempt(worker, &block);
        let entries = attempt
            .original_decoded(&budget)
            .unwrap()
            .external_entrypoints_slice()
            .as_ptr();
        let hash = attempt.block_hash;
        worker.signature_decode = Some(attempt);
        worker.reject(block.header().height, block.header().origin_view + 1, hash);
        assert_eq!(
            worker
                .signature_decode
                .as_ref()
                .unwrap()
                .decoded
                .as_ref()
                .unwrap()
                .external_entrypoints_slice()
                .as_ptr(),
            entries
        );
        worker.reject(block.header().height + 1, block.header().origin_view, hash);
        assert_eq!(
            worker
                .signature_decode
                .as_ref()
                .unwrap()
                .decoded
                .as_ref()
                .unwrap()
                .external_entrypoints_slice()
                .as_ptr(),
            entries
        );
        worker.reject(block.header().height, block.header().origin_view, hash);
        assert!(worker.signature_decode.is_none());

        assert!(worker.results.is_empty());
        assert!(events.try_recv().is_err());
        assert_eq!(worker.state.view().height(), 1);
    });
}

#[test]
fn same_source_same_pool_distinct_prepared_signature_owner_is_refused_at_both_boundaries() {
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let block = publication_tests::proposal(chain, worker);
        let budget = worker.state.ivm_execution_budget();
        let mut attempt = original_attempt(worker, &block);
        attempt.original_decoded(&budget).unwrap();
        let original = attempt.decoded.take().unwrap();
        let original_entries = original.external_entrypoints_slice().as_ptr();
        let source = block.payload().charged_source(&budget).unwrap();
        let mut second_decoder =
            iroha_data_model::block::PreparedSignedBlockSignaturesDecode::new(&budget).unwrap();
        let distinct = payload::decode_prepared(source, &mut second_decoder).unwrap();
        assert!(original.signatures_admitted_to(&budget));
        assert!(distinct.signatures_admitted_to(&budget));
        assert!(
            original
                .matches_resultless_proposal_wire(source.as_slice())
                .unwrap()
        );
        assert!(
            distinct
                .matches_resultless_proposal_wire(source.as_slice())
                .unwrap()
        );
        assert!(!original.same_signature_custody(&distinct));
        assert!(
            attempt
                .decoder
                .retains_signature_custody(source, &original)
                .unwrap()
        );
        assert!(
            !attempt
                .decoder
                .retains_signature_custody(source, &distinct)
                .unwrap()
        );
        let distinct_entries = distinct.external_entrypoints_slice().as_ptr();
        let occupied = budget.reserved_bytes();
        attempt.decoded = Some(distinct);
        assert!(matches!(attempt.original_decoded(&budget),
            Err(payload::PayloadError::SignatureCustodyInvariant(ref reason))
                if reason == "completed proposal lost its original signature custody"));
        assert_eq!(
            attempt
                .decoded
                .as_ref()
                .unwrap()
                .external_entrypoints_slice()
                .as_ptr(),
            distinct_entries
        );
        assert_eq!(budget.reserved_bytes(), occupied);
        let distinct = attempt.decoded.take().unwrap();
        attempt.decoded = Some(original);
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        norito::with_decode_limits_scope(limits, || {
            assert_eq!(
                attempt
                    .original_decoded(&budget)
                    .unwrap()
                    .external_entrypoints_slice()
                    .as_ptr(),
                original_entries
            );
        });
        let original = attempt.decoded.take().unwrap();
        // The actual returned-block branch must independently enforce the same original
        // physical control. Exact canonical bytes and same pool alone would accept this.
        assert!(
            matches!(attempt.retain_validation_return(distinct, &budget),
            Err(PublicationError::RecoveryRequired(ref reason))
                if reason == "returned proposal lost its original decoder source custody")
        );
        assert!(matches!(
            attempt.returned_refusal,
            Some(ReturnedDecodedRefusal::SourceMismatch)
        ));
        let retained = attempt.decoded.as_ref().unwrap();
        assert_eq!(
            retained.external_entrypoints_slice().as_ptr(),
            distinct_entries
        );
        assert!(!original.same_signature_custody(retained));
        assert!(retained.signatures_admitted_to(&budget));
        assert_eq!(budget.reserved_bytes(), occupied);
        assert!(matches!(
            attempt.original_decoded(&budget),
            Err(payload::PayloadError::SignatureCustodyInvariant(_))
        ));
        assert_eq!(
            original.external_entrypoints_slice().as_ptr(),
            original_entries
        );
        assert!(events.try_recv().is_err());
        assert!(worker.live.is_none());
        assert!(worker.finishing.is_none());
        assert_eq!(worker.state.view().height(), 1);
    });
}

#[test]
fn same_wire_distinct_action_owner_is_refused_at_original_lend_and_validation_return() {
    use iroha_data_model::consensus::{NposConsensusEffects, NposPenaltyActions};
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let carrier = publication_tests::proposal(chain, worker);
        let mut proposal = payload::decode(carrier.payload().as_slice()).unwrap();
        let mut effects = proposal
            .npos_consensus_effects()
            .cloned()
            .unwrap_or_else(NposConsensusEffects::default);
        // Transport/custody fixture only; no execution or penalty authority is granted.
        if effects.penalty_actions.is_empty() {
            effects.penalty_actions = NposPenaltyActions::from_untrusted(vec![
                iroha_data_model::consensus::NposPenaltyAction::MarkConsensusEvidenceApplied(
                    iroha_data_model::consensus::NposMarkConsensusEvidenceAppliedAction {
                        evidence_key: iroha_crypto::Hash::new([0x5a; 32]),
                        height: proposal.header().height().get(),
                    },
                ),
            ]);
        }
        proposal.set_npos_consensus_effects(Some(effects));
        let bytes = payload::encode(&proposal).unwrap();
        let mut header = carrier.header().clone();
        header.payload_hash = payload_hash(&**worker.context.crypto.as_ref().unwrap(), &bytes);
        header.payload_len = u32::try_from(bytes.len()).unwrap();
        let block = chain.author_payload(header, bytes);
        let budget = worker.state.ivm_execution_budget();
        let mut attempt = original_attempt(worker, &block);
        attempt.original_decoded(&budget).unwrap();
        let original = attempt.decoded.take().unwrap();
        let source = block.payload().charged_source(&budget).unwrap();
        let mut second =
            iroha_data_model::block::PreparedSignedBlockSignaturesDecode::new(&budget).unwrap();
        let separately_decoded = payload::decode_prepared(source, &mut second).unwrap();
        let mut substituted = original.clone();
        let mut effects = substituted.npos_consensus_effects().unwrap().clone();
        effects.penalty_actions = separately_decoded
            .npos_consensus_effects()
            .unwrap()
            .penalty_actions
            .clone();
        substituted.set_npos_consensus_effects(Some(effects));
        assert!(original.same_signature_custody(&substituted));
        assert_eq!(
            original.encode_wire().unwrap(),
            substituted.encode_wire().unwrap()
        );
        assert!(
            substituted
                .matches_resultless_proposal_wire(source.as_slice())
                .unwrap()
        );
        assert!(
            substituted
                .npos_consensus_effects()
                .unwrap()
                .penalty_actions
                .admitted_to(&budget)
        );
        assert!(!NposPenaltyActions::ptr_eq(
            &original.npos_consensus_effects().unwrap().penalty_actions,
            &substituted
                .npos_consensus_effects()
                .unwrap()
                .penalty_actions
        ));
        assert!(
            attempt
                .decoder
                .retains_npos_penalty_action_custody(source, &original)
                .unwrap()
        );
        assert!(
            !attempt
                .decoder
                .retains_npos_penalty_action_custody(source, &substituted)
                .unwrap()
        );
        let occupied = budget.reserved_bytes();
        attempt.decoded = Some(substituted);
        assert!(
            matches!(attempt.original_decoded(&budget), Err(payload::PayloadError::SignatureCustodyInvariant(ref reason)) if reason == "completed proposal lost its original penalty-action custody"),
            "same-wire action substitution must fail original lend"
        );
        assert_eq!(budget.reserved_bytes(), occupied);
        let substituted = attempt.decoded.take().unwrap();
        let expected_actions = original
            .npos_consensus_effects()
            .unwrap()
            .penalty_actions
            .clone();
        attempt.decoded = Some(original);
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        norito::with_decode_limits_scope(limits, || {
            let original = attempt
                .original_decoded(&budget)
                .expect("original actions must lend without canonical reentry");
            assert!(NposPenaltyActions::ptr_eq(
                &expected_actions,
                &original.npos_consensus_effects().unwrap().penalty_actions
            ));
        });
        let original = attempt.decoded.take().unwrap();
        assert!(
            matches!(attempt.retain_validation_return(substituted, &budget), Err(PublicationError::RecoveryRequired(ref reason)) if reason == "returned proposal lost its original penalty-action custody"),
            "same-wire action substitution must fail validation return"
        );
        assert!(matches!(
            attempt.returned_refusal,
            Some(ReturnedDecodedRefusal::SourceMismatch)
        ));
        let retained = attempt.decoded.as_ref().unwrap();
        assert!(original.same_signature_custody(retained));
        assert!(!NposPenaltyActions::ptr_eq(
            &original.npos_consensus_effects().unwrap().penalty_actions,
            &retained.npos_consensus_effects().unwrap().penalty_actions
        ));
        assert_eq!(budget.reserved_bytes(), occupied);
        assert!(matches!(
            attempt.original_decoded(&budget),
            Err(payload::PayloadError::SignatureCustodyInvariant(_))
        ));
        assert!(events.try_recv().is_err());
        assert!(worker.live.is_none() && worker.finishing.is_none());
        assert_eq!(worker.state.view().height(), 1);
    });
}

#[test]
fn same_wire_parent_qc_substitution_preserving_actions_and_signatures_is_refused_at_both_boundaries()
 {
    use iroha_data_model::consensus::{
        NposConsensusEffects, NposParentServiceCommitQc, NposPenaltyActions,
    };
    fn parent(block: &SignedBlock) -> &NposParentServiceCommitQc {
        block
            .npos_consensus_effects()
            .unwrap()
            .parent_service_commit_qc
            .as_ref()
            .unwrap()
    }
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let carrier = publication_tests::proposal(chain, worker);
        let mut proposal = payload::decode(carrier.payload().as_slice()).unwrap();
        let mut effects = proposal
            .npos_consensus_effects()
            .cloned()
            .unwrap_or_else(NposConsensusEffects::default);
        // Transport/custody fixture only. The decoder grants no native QC authority.
        effects.parent_service_commit_qc =
            Some(NposParentServiceCommitQc::from_untrusted(vec![0x21, 0x32]));
        proposal.set_npos_consensus_effects(Some(effects));
        let bytes = payload::encode(&proposal).unwrap();
        let mut header = carrier.header().clone();
        header.payload_hash = payload_hash(&**worker.context.crypto.as_ref().unwrap(), &bytes);
        header.payload_len = u32::try_from(bytes.len()).unwrap();
        let block = chain.author_payload(header, bytes);
        let budget = worker.state.ivm_execution_budget();
        let mut attempt = original_attempt(worker, &block);
        attempt.original_decoded(&budget).unwrap();
        let original = attempt.decoded.take().unwrap();
        let source = block.payload().charged_source(&budget).unwrap();
        let mut second =
            iroha_data_model::block::PreparedSignedBlockSignaturesDecode::new(&budget).unwrap();
        let separately_decoded = payload::decode_prepared(source, &mut second).unwrap();
        let mut substituted = original.clone();
        let mut effects = substituted.npos_consensus_effects().unwrap().clone();
        effects.parent_service_commit_qc = Some(parent(&separately_decoded).clone());
        substituted.set_npos_consensus_effects(Some(effects));
        assert!(original.same_signature_custody(&substituted));
        assert!(NposPenaltyActions::ptr_eq(
            &original.npos_consensus_effects().unwrap().penalty_actions,
            &substituted
                .npos_consensus_effects()
                .unwrap()
                .penalty_actions
        ));
        assert_eq!(
            original.encode_wire().unwrap(),
            substituted.encode_wire().unwrap()
        );
        assert!(
            substituted
                .matches_resultless_proposal_wire(source.as_slice())
                .unwrap()
        );
        assert!(parent(&substituted).admitted_to(&budget));
        assert!(!NposParentServiceCommitQc::ptr_eq(
            parent(&original),
            parent(&substituted)
        ));
        assert!(
            attempt
                .decoder
                .retains_parent_service_custody(source, &original)
                .unwrap()
        );
        assert!(
            !attempt
                .decoder
                .retains_parent_service_custody(source, &substituted)
                .unwrap()
        );
        let occupied = budget.reserved_bytes();
        attempt.decoded = Some(substituted);
        assert!(
            matches!(attempt.original_decoded(&budget), Err(payload::PayloadError::SignatureCustodyInvariant(ref reason)) if reason == "completed proposal lost its original parent-QC custody"),
            "same-wire parent-QC substitution must fail original lend"
        );
        assert_eq!(budget.reserved_bytes(), occupied);
        let substituted = attempt.decoded.take().unwrap();
        let expected = parent(&original).clone();
        attempt.decoded = Some(original);
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
            || {
                assert!(NposParentServiceCommitQc::ptr_eq(
                    &expected,
                    parent(attempt.original_decoded(&budget).unwrap())
                ));
            },
        );
        let original = attempt.decoded.take().unwrap();
        assert!(
            matches!(attempt.retain_validation_return(substituted, &budget), Err(PublicationError::RecoveryRequired(ref reason)) if reason == "returned proposal lost its original parent-QC custody")
        );
        assert!(matches!(
            attempt.returned_refusal,
            Some(ReturnedDecodedRefusal::SourceMismatch)
        ));
        let refused = attempt.decoded.as_ref().unwrap();
        assert!(original.same_signature_custody(refused));
        assert!(!NposParentServiceCommitQc::ptr_eq(
            parent(&original),
            parent(refused)
        ));
        assert_eq!(budget.reserved_bytes(), occupied);
        assert!(events.try_recv().is_err());
        assert!(worker.live.is_none() && worker.finishing.is_none());
        assert_eq!(worker.state.view().height(), 1);
    });
}
