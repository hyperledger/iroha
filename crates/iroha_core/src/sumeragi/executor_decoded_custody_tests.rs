//! Original completed proposal ownership across actual decoder, prevalidation and return boundaries.
//!
//! These controls use the real four-validator signed genesis, State pool and signed RS16 body.
//! They do not establish full transaction/DA/result allocation admission or panic recovery.

use super::*;
use iroha_allocation::AllocationBudget;
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
            let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
            let original = norito::with_decode_limits_scope(limits, || {
                super::super::lanes::lane_policy(worker.state.view().world()).unwrap_err()
            });
            assert_eq!(
                original.reason(),
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity
            );
            assert!(
                matches!(norito::with_decode_limits_scope(limits, || worker.run_execution(&block, hash)),
                Err(PublicationError::Deferred(ref source)) if source.execution() == Some(&original))
            );
            assert_eq!(worker.routing_refusal.as_ref(), Some(&original));
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
                worker.execute(&block, hash),
                Some(ExecOutcome::Valid(_))
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
            assert!(worker.routing_refusal.is_none());
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
        assert!(worker.routing_refusal.is_none());
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
