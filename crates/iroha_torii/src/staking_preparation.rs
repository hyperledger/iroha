//! Bounded read-only staking monetary plan preparation.

use super::*;
use iroha_data_model::nexus::PublicLanePreparationRequestV1;

/// Resolve exact current monetary inputs from one committed state snapshot.
pub async fn handler_staking_preparation(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    crate::utils::extractors::Norito(request): crate::utils::extractors::Norito<
        PublicLanePreparationRequestV1,
    >,
) -> Result<Response, Error> {
    validate_api_token(app.as_ref(), &headers)?;
    let format = match negotiate_heavy_query_response_format(&headers) {
        Ok(format) => format,
        Err(response) => return Ok(response),
    };
    let key = rate_limit_key(
        &headers,
        Some(remote.ip()),
        iroha_torii_shared::route_catalog::core::NEXUS_STAKING_PREPARATION_POST.path(),
        app.authenticated_api_token_principal(&headers),
    );
    rate_limit_requests_with_cost(&app, &key, FINALITY_HEAVY_QUERY_RATE_COST).await?;
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    let state = app.state.clone();
    let response =
        routing::run_admitted_blocking(admission, "staking preparation worker failed", move || {
            let view = state.view();
            let payload =
                iroha_core::smartcontracts::isi::staking::preparation::prepare_public_lane_plan(
                    &view, request,
                )
                .map_err(staking_preparation_error)?;
            Ok(crate::utils::respond_with_format(payload, format))
        })
        .await?;
    proof_response_with_exact_egress(
        app.as_ref(),
        &headers,
        Some(remote.ip()),
        "v1/nexus/staking/prepare",
        response,
        true,
    )
    .await
}

fn staking_preparation_error(
    error: iroha_core::execution_attempt::ExecutionAttemptError<
        iroha_data_model::isi::error::InstructionExecutionError,
    >,
) -> Error {
    match error {
        iroha_core::execution_attempt::ExecutionAttemptError::Deferred(_) => {
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded,
            ))
        }
        iroha_core::execution_attempt::ExecutionAttemptError::Rejected(error) => Error::Query(
            iroha_data_model::ValidationFail::InternalError(error.to_string()),
        ),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::{
        execution_attempt::ExecutionAttemptError,
        smartcontracts::isi::staking::preparation::prepare_public_lane_plan,
        state::{World, WorldReadOnly as _},
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        nexus::{PublicLanePreparationOperationV1, PublicLanePrepareRegistrationV1},
        parameter::{
            Parameter,
            system::{SumeragiConsensusMode, SumeragiNposParameters},
        },
        prelude::*,
    };
    use iroha_model_base::{domain::DomainId, peer::PeerId, topology::LaneId};

    #[test]
    fn original_staking_history_refusal_maps_to_http_capacity_and_same_source_retries() {
        let key = KeyPair::from_seed(vec![0x31; 32], Algorithm::Ed25519);
        let owner = AccountId::new(key.public_key().clone());
        let staking = iroha_config::parameters::actual::NexusStaking::default();
        let definition: AssetDefinitionId = staking.stake_asset_id.parse().unwrap();
        let escrow = AccountId::parse_encoded(&staking.stake_escrow_account_id).unwrap();
        let mut keys = (0x71..=0x74)
            .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
        let peer = PeerId::new(keys[0].public_key().clone());
        let world = World::with_assets(
            [Domain::new(DomainId::try_new("nexus", "universal").unwrap()).build(&owner)],
            [
                Account::new(owner.clone()).build(&owner),
                Account::new(escrow.clone()).build(&escrow),
            ],
            [AssetDefinition::numeric(
                definition.clone(),
                "Staked XOR",
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&owner)],
            [Asset::new(
                AssetId::new(definition, owner.clone()),
                Quantity::from(2_000_u32),
            )],
            [],
        );
        let mut config = TestChainConfig::new(world, 1_000);
        config.validator_keys = Some(keys);
        config.consensus_mode = SumeragiConsensusMode::Npos;
        config.genesis_parameters.push(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        ));
        let chain = CertifiedTestChain::start(config).unwrap();
        let view = chain.state().view();
        let request = PublicLanePreparationRequestV1 {
            lane_id: LaneId::SINGLE,
            valid_for_blocks: 1,
            operation: PublicLanePreparationOperationV1::Registration(
                PublicLanePrepareRegistrationV1 {
                    validator: owner,
                    peer_id: peer,
                    amount: Quantity::from(1_000_u32),
                    candidate: false,
                },
            ),
        };
        let expected = prepare_public_lane_plan(&view, request.clone()).unwrap();
        let original_parameter = view
            .world()
            .parameters()
            .custom()
            .get(&SumeragiNposParameters::parameter_id())
            .unwrap()
            .payload()
            .get()
            .to_owned();
        let limits = norito::DecodeLimits::new(2_048, usize::MAX, usize::MAX, usize::MAX, 64);
        let error = norito::with_decode_limits_scope(limits, || {
            // This bound leaves the preceding signed policy readable; the larger original
            // committed history frame, rather than policy absence, refuses the attempt.
            assert!(
                view.world()
                    .sumeragi_npos_parameters()
                    .expect("original policy remains readable")
                    .is_some()
            );
            prepare_public_lane_plan(&view, request.clone())
        })
        .unwrap_err();
        assert!(
            matches!(error, ExecutionAttemptError::Deferred(_)),
            "{error:?}"
        );
        let response = staking_preparation_error(error).into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        drop(response);
        assert_eq!(
            view.world()
                .parameters()
                .custom()
                .get(&SumeragiNposParameters::parameter_id())
                .unwrap()
                .payload()
                .get(),
            &original_parameter
        );
        assert_eq!(
            prepare_public_lane_plan(&view, request.clone()).unwrap(),
            expected
        );
        let invalid = PublicLanePreparationRequestV1 {
            valid_for_blocks: 0,
            ..request
        };
        let terminal = prepare_public_lane_plan(&view, invalid).unwrap_err();
        assert!(matches!(terminal, ExecutionAttemptError::Rejected(_)));
        assert_ne!(
            staking_preparation_error(terminal).into_response().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
