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
        )));
    let error = sumeragi_npos_diagnostics(&tx.world).unwrap_err();
    assert!(
        matches!(
            error,
            Error::Query(iroha_data_model::ValidationFail::InternalError(_))
        ),
        "{error:?}"
    );
}
