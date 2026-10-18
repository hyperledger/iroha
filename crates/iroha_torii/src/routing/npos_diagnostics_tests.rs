//! Original `NPoS` policy reads remain retryable at the operator diagnostics boundary.

use super::*;
use iroha_core::{
    state::{World, WorldReadOnly},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_data_model::parameter::{
    CustomParameter, Parameter,
    system::{SumeragiConsensusMode, SumeragiNposParameters},
};

#[test]
fn original_npos_diagnostics_refusal_is_capacity_and_same_source_retries() {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_parameters.push(Parameter::Custom(
        SumeragiNposParameters::default().into_custom_parameter(),
    ));
    let chain = CertifiedTestChain::start(config).unwrap();
    let view = chain.state().view();
    let custom = view
        .world()
        .parameters()
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .unwrap();
    let bytes = custom.payload().get().to_owned();
    let before = norito::json::to_json(&sumeragi_npos_diagnostics(view.world()).unwrap()).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    let producer = norito::with_decode_limits_scope(limits, || {
        SumeragiNposParameters::from_custom_parameter(custom)
    })
    .unwrap_err();
    assert!(
        matches!(
            producer,
            norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            )
        ),
        "{producer:?}"
    );
    let error =
        norito::with_decode_limits_scope(limits, || sumeragi_npos_diagnostics(view.world()))
            .unwrap_err();
    assert!(
        matches!(
            &error,
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded
            ))
        ),
        "{error:?}"
    );
    assert_eq!(
        error.into_response().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(custom.payload().get(), &bytes);
    assert_eq!(
        norito::json::to_json(&sumeragi_npos_diagnostics(view.world()).unwrap()).unwrap(),
        before
    );
}

#[test]
fn npos_diagnostics_distinguishes_absence_from_malformed_original_policy() {
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    assert!(
        sumeragi_npos_diagnostics(chain.state().view().world())
            .unwrap()
            .is_none()
    );
    let proposal = chain.proposal(Some(2_000), vec![]);
    let mut block = chain.state().block(proposal.header());
    let mut tx = block.transaction();
    tx.world
        .parameters_mut_for_testing()
        .get_mut()
        .set_parameter(Parameter::Custom(CustomParameter::new(
            SumeragiNposParameters::parameter_id(),
            iroha_primitives::json::Json::new(norito::json!({"unexpected": "shape"})),
        )))
        .expect("valid fixture parameters");
    let error = sumeragi_npos_diagnostics(&tx.world).unwrap_err();
    assert!(
        matches!(
            error,
            Error::Query(iroha_data_model::ValidationFail::InternalError(_))
        ),
        "{error:?}"
    );
}

#[test]
fn native_evidence_response_keeps_original_decoder_owner_and_capacity_status() {
    use iroha_allocation::AllocationBudget;
    use iroha_data_model::block::consensus::Evidence;
    use iroha_sumeragi::{
        message::{Evidence as NativeEvidence, Qc, VoteKind},
        types::{AggregateSignature, Bitmap, EpochId, Hash32, SIGNATURE_LEN},
    };
    use norito::core::PreparedDecodeWorkspace;
    let first = Qc {
        kind: VoteKind::Commit,
        instance: Hash32([1; 32]),
        epoch: EpochId {
            epoch: 1,
            context: Hash32([2; 32]),
        },
        height: 2,
        view: 0,
        block_hash: Hash32([3; 32]),
        result: Hash32([4; 32]),
        signers: Bitmap::from_bytes(vec![7]),
        agg_sig: AggregateSignature([5; SIGNATURE_LEN]),
    };
    let second = Qc {
        block_hash: Hash32([6; 32]),
        ..first.clone()
    };
    let proof =
        Evidence::from_native(&NativeEvidence::ConflictingCertificates(first, second)).unwrap();
    let pool = AllocationBudget::new(4096);
    let mut workspace = PreparedDecodeWorkspace::from_reservation(
        &pool,
        &mut pool
            .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
            .unwrap(),
    )
    .unwrap();
    let mut decoder = PreparedDecodeWorkspace::from_reservation(
        &pool,
        &mut pool
            .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
            .unwrap(),
    )
    .unwrap();
    let narrow = norito::DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, usize::MAX);
    let protocol = norito::canonical_decode_limits(proof.native_frame().len());
    let refusal = workspace
        .with_limits(narrow, narrow, || {
            norito::core::classify_decode_attempt(|| {
                decoder
                    .with_limits(protocol, protocol, || {
                        proof.decode_native().map_err(norito::Error::from)
                    })
                    .unwrap()
            })
        })
        .unwrap()
        .unwrap_err();
    let error = native_evidence_decode_error(iroha_sumeragi::message::CodecError::from(refusal));
    assert_eq!(error.status_code(), StatusCode::TOO_MANY_REQUESTS);
    assert!(std::error::Error::source(&error).is_some());
    drop(decoder);
    drop(workspace);
    assert_eq!(
        pool.reserved_bytes(),
        PreparedDecodeWorkspace::allocation_layouts()[0].size()
    );
    assert_eq!(
        error.into_response().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(proof.decode_native().is_ok());
}

#[test]
fn native_evidence_response_rejects_resource_diagnostics_without_captured_provenance() {
    for raw in [
        norito::Error::SequenceLengthExceeded {
            length: 2,
            limit: 1,
        },
        norito::Error::AllocationFailed { bytes: 2048 },
        norito::Error::ChecksumMismatch,
    ] {
        let error = native_evidence_decode_error(iroha_sumeragi::message::CodecError::from(raw));
        assert!(matches!(
            &error,
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(_)
            ))
        ));
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
    }
}
