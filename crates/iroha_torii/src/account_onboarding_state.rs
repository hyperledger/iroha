//! Atomic current-state proof for first-release sponsored account onboarding.

use crate::{AxResponse, Error, SharedAppState};
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method, StatusCode, Uri},
};
use iroha_core::{
    queue::{RoutingDecision, RoutingResolveError},
    state::{StateReadOnly as _, WorldReadOnly as _},
    torii_proxy::ToriiReadEndpointV1,
};
use iroha_torii_shared::{
    AccountOnboardingCurrentStateRequestV1, AccountOnboardingCurrentStateResponseV1,
};

fn conversion_error(message: impl Into<String>) -> Error {
    Error::Query(iroha_data_model::ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::Conversion(message.into()),
    ))
}

fn invariant_error(message: impl Into<String>) -> Error {
    Error::Query(iroha_data_model::ValidationFail::InternalError(
        message.into(),
    ))
}

fn unavailable(message: impl Into<String>) -> Error {
    Error::AppServiceUnavailable {
        code: "account_onboarding_current_state_unavailable",
        message: message.into(),
    }
}

fn resolved_alias_for_view(
    view: &iroha_core::state::StateQueryView<'_>,
    alias: iroha_data_model::alias_setup::AccountAliasName,
    ledger_time_ms: u64,
) -> Result<iroha_data_model::alias_setup::ResolvedAccountAliasV1, Error> {
    let dataspace_id = iroha_core::sns::resolve_active_dataspace_id_by_alias(
        view.world(),
        &view.nexus().dataspace_catalog,
        alias.dataspace.as_ref(),
        ledger_time_ms,
    )
    .map_err(super::live_dataspace_resolution_error)?;
    Ok(iroha_data_model::alias_setup::ResolvedAccountAliasV1::new(
        alias,
        dataspace_id,
    ))
}

/// Read every consensus-derived field from one generation-consistent state snapshot.
pub fn read_account_onboarding_current_state(
    app: &SharedAppState,
    request: &AccountOnboardingCurrentStateRequestV1,
    expected_route: Option<RoutingDecision>,
) -> Result<AccountOnboardingCurrentStateResponseV1, Error> {
    let (account_id, alias) = request.validate_exact().map_err(conversion_error)?;
    let view = app.state.query_view();
    let observed_block_height = u64::try_from(view.height())
        .map_err(|_| invariant_error("committed block height does not fit in u64"))?;
    if observed_block_height == 0 {
        return Err(unavailable(
            "no committed block anchors account onboarding current state",
        ));
    }
    let observed_block_hash = view.latest_block_hash().ok_or_else(|| {
        invariant_error(
            "nonzero account onboarding current-state height has no committed block hash",
        )
    })?;
    let ledger_time_ms = view.authenticated_query_ledger_time_ms().ok_or_else(|| {
        unavailable("no authenticated committed ledger time anchors account onboarding state")
    })?;
    let resolved_alias = resolved_alias_for_view(&view, alias, ledger_time_ms)?;
    if let Some(route) = expected_route
        && route.dataspace_id != resolved_alias.dataspace_id
    {
        return Err(invariant_error(format!(
            "routed account onboarding current-state request targeted dataspace {} but the alias resolves to {}",
            route.dataspace_id.as_u64(),
            resolved_alias.dataspace_id.as_u64(),
        )));
    }
    let account_exists = view.world().account(&account_id).is_ok();
    let alias_target_account_id = iroha_core::sns::resolve_active_account_alias(
        view.world(),
        &view.nexus().dataspace_catalog,
        &resolved_alias.account_alias(),
        ledger_time_ms,
    )
    .map_err(|error| invariant_error(error.to_string()))?
    .map(|target| target.to_string());
    let response = AccountOnboardingCurrentStateResponseV1 {
        version: AccountOnboardingCurrentStateResponseV1::VERSION,
        network_id: view.network_id,
        account_id: request.account_id.clone(),
        alias: request.alias.clone(),
        account_exists,
        alias_target_account_id,
        observed_block_height,
        observed_block_hash,
    };
    response
        .validate_for(request, &view.network_id)
        .map_err(invariant_error)?;
    Ok(response)
}

pub fn execute_account_onboarding_current_state_local_read(
    app: &SharedAppState,
    request: &AccountOnboardingCurrentStateRequestV1,
    expected_route: Option<RoutingDecision>,
) -> Result<AxResponse, Error> {
    super::json_ok(read_account_onboarding_current_state(
        app,
        request,
        expected_route,
    )?)
}

pub fn sanitize_routed_account_onboarding_current_state(
    app: &SharedAppState,
    _route: RoutingDecision,
    request_body: &[u8],
    response_body: &[u8],
) -> Result<Vec<u8>, String> {
    let request: AccountOnboardingCurrentStateRequestV1 = norito::json::from_slice(request_body)
        .map_err(|error| format!("invalid routed onboarding current-state request: {error}"))?;
    request.validate_exact()?;
    let response: AccountOnboardingCurrentStateResponseV1 = norito::json::from_slice(response_body)
        .map_err(|error| {
            format!("invalid routed onboarding current-state response schema: {error}")
        })?;
    response.validate_for(&request, app.state.network_id_ref())?;
    norito::json::to_vec(&response)
        .map_err(|error| format!("failed to encode onboarding current-state response: {error}"))
}

pub async fn handler_account_onboarding_current_state(
    State(app): State<SharedAppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    body: axum::body::Bytes,
) -> Result<AxResponse, Error> {
    super::check_public_contract_read_route_rate_limit(
        &app,
        &headers,
        remote.ip(),
        "v1/accounts/onboarding/current-state",
        "account_onboarding_current_state",
        None,
    )
    .await?;
    let request: AccountOnboardingCurrentStateRequestV1 =
        match super::decode_current_app_routed_read_json(body.as_ref()) {
            Some(Ok(request)) => request,
            Some(Err(response)) => return Ok(response),
            None => norito::json::from_slice(body.as_ref()).map_err(|error| {
                conversion_error(format!(
                    "invalid account onboarding current-state request: {error}"
                ))
            })?,
        };
    request.validate_exact().map_err(conversion_error)?;
    let alias = super::parse_exact_account_alias_label_with_live_state(&app, &request.alias)?;
    let visibility = super::torii_visibility_account_from_headers(
        &app,
        &headers,
        &method,
        &uri,
        body.as_ref(),
        "account_onboarding_current_state",
    )?;
    if !super::torii_public_dataspace_ids(app.as_ref()).contains(&alias.label.dataspace) {
        let Some(caller) = visibility.caller() else {
            return Err(Error::AppUnauthorized {
                code: "alias_auth_required",
                message: "canonical signed account headers are required for a restricted dataspace"
                    .to_owned(),
            });
        };
        if !super::torii_authority_can_resolve_resolved_account_alias(
            app.state.query_view().world(),
            caller,
            &alias.resolved,
        )? {
            return Ok(super::torii_alias_permission_denied_response(
                "exact Alias or applicable Domain/Dataspace resolve permission is required for the requested alias scope",
            ));
        }
    }
    let candidate_routes =
        match super::resolve_torii_target_alias_routes(app.as_ref(), &alias.label) {
            Ok(routes) => routes,
            Err(
                RoutingResolveError::UnknownDataspace { .. }
                | RoutingResolveError::NoLaneForDataspace { .. },
            ) => {
                return execute_account_onboarding_current_state_local_read(&app, &request, None);
            }
            Err(error) => {
                return Ok(super::torii_proxy_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "route_unavailable",
                    format!("failed to resolve onboarding current-state route: {error}"),
                ));
            }
        };
    if candidate_routes.len() == 1 {
        return Ok(super::execute_torii_single_route_read(
            &app,
            candidate_routes[0],
            ToriiReadEndpointV1::AccountOnboardingCurrentState,
            Vec::new(),
            None,
            body.to_vec(),
        )
        .await);
    }
    Ok(super::torii_proxy_error_response(
        StatusCode::CONFLICT,
        "route_conflict",
        "multiple routes matched the onboarding account alias dataspace",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_runtime_handlers::{
        bind_account_alias_for_test, checked_torii_test_ed25519_keypair,
        mk_app_state_for_tests_with_world,
    };
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        Registrable as _,
        account::{Account, AccountId},
        alias_setup::AccountAliasName,
        block::BlockHeader,
    };
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use std::sync::Arc;

    fn fixture_app(account_id: Option<&AccountId>) -> SharedAppState {
        let accounts = account_id
            .map(|account_id| Account::new(account_id.clone()).build(account_id))
            .into_iter()
            .collect::<Vec<_>>();
        mk_app_state_for_tests_with_world(iroha_core::state::World::with([], accounts, []))
    }

    fn anchor_state(app: &mut SharedAppState, creation_time_ms: u64) -> HashOf<BlockHeader> {
        let app = Arc::get_mut(app).expect("unique onboarding app");
        let state = Arc::get_mut(&mut app.state).expect("unique onboarding fixture world");
        let world = std::mem::take(&mut state.world);
        let mut chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::start(
            iroha_core::sumeragi::test_chain::TestChainConfig::new(world, 1),
        )
        .expect("original onboarding snapshot genesis");
        chain.commit_at(creation_time_ms, Vec::new());
        let hash = chain.committed(2).block_hash();
        app.state = chain.state().clone();
        app.kura = chain.kura().clone();
        hash
    }
    fn request(account_id: &AccountId, alias: &str) -> AccountOnboardingCurrentStateRequestV1 {
        let alias = alias
            .parse::<AccountAliasName>()
            .expect("canonical account-onboarding alias");
        AccountOnboardingCurrentStateRequestV1::new(account_id, &alias)
    }

    #[test]
    fn route_catalog_declares_one_public_read_only_post() {
        use iroha_torii_shared::route_catalog::{
            AdmissionPolicy, AuthenticationPolicy, HttpMethod, RouteEffect,
        };
        let route = iroha_torii_shared::route_catalog::application_api::ACCOUNTS_ONBOARDING_CURRENT_STATE_POST;
        assert_eq!(route.method(), HttpMethod::Post);
        assert_eq!(route.effect(), RouteEffect::ReadOnly);
        assert_eq!(route.admission(), AdmissionPolicy::Public);
        assert_eq!(route.authentication(), AuthenticationPolicy::ToriiDefault);
    }

    #[test]
    fn snapshot_proves_account_and_domain_qualified_alias_from_one_anchor() {
        let account_key = checked_torii_test_ed25519_keypair(
            0xe2,
            "derive account-onboarding current-state account key",
        );
        let account_id = AccountId::new(account_key.public_key().clone());
        let mut app = fixture_app(Some(&account_id));
        let alias = "merchant@banka.universal";
        bind_account_alias_for_test(&app, &account_id, alias);
        let observed_block_hash = anchor_state(&mut app, 1_234);

        let exact_request = request(&account_id, alias);
        let response = read_account_onboarding_current_state(
            &app,
            &exact_request,
            Some(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)),
        )
        .expect("one-view onboarding state");
        assert_eq!(response.account_id, exact_request.account_id);
        assert_eq!(response.alias, alias);
        assert!(response.account_exists);
        assert_eq!(
            response.alias_target_account_id,
            Some(account_id.to_string())
        );
        assert_eq!(response.observed_block_height, 2);
        assert_eq!(response.observed_block_hash, observed_block_hash);
        assert_eq!(response.network_id, *app.state.network_id_ref());

        let absent_key = checked_torii_test_ed25519_keypair(
            0xe3,
            "derive absent account-onboarding current-state account key",
        );
        let absent_account = AccountId::new(absent_key.public_key().clone());
        let absent_request = request(&absent_account, alias);
        let absent_response = read_account_onboarding_current_state(&app, &absent_request, None)
            .expect("same-view absent account and live alias target");
        assert!(!absent_response.account_exists);
        assert_eq!(
            absent_response.alias_target_account_id,
            Some(account_id.to_string())
        );
        assert_eq!(absent_response.observed_block_hash, observed_block_hash);
    }

    #[test]
    fn snapshot_requires_a_committed_anchor_and_exact_route() {
        let account_key = checked_torii_test_ed25519_keypair(
            0xe4,
            "derive unanchored account-onboarding current-state account key",
        );
        let account_id = AccountId::new(account_key.public_key().clone());
        let mut app = fixture_app(Some(&account_id));
        let exact_request = request(&account_id, "merchant@universal");
        assert!(matches!(
            read_account_onboarding_current_state(&app, &exact_request, None),
            Err(Error::AppServiceUnavailable { .. })
        ));

        bind_account_alias_for_test(&app, &account_id, "merchant@universal");
        anchor_state(&mut app, 2_000);
        assert!(matches!(
            read_account_onboarding_current_state(
                &app,
                &exact_request,
                Some(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::new(9),)),
            ),
            Err(Error::Query(
                iroha_data_model::ValidationFail::InternalError(_)
            ))
        ));
    }

    #[test]
    fn routed_sanitizer_is_strict_without_ingress_snapshot_coupling() {
        let account_key = checked_torii_test_ed25519_keypair(
            0xe5,
            "derive routed account-onboarding current-state account key",
        );
        let account_id = AccountId::new(account_key.public_key().clone());
        let app = fixture_app(None);
        let request = request(&account_id, "merchant@banka.universal");
        let request_body = norito::json::to_vec(&request).expect("request JSON");
        let response = AccountOnboardingCurrentStateResponseV1 {
            version: AccountOnboardingCurrentStateResponseV1::VERSION,
            network_id: *app.state.network_id_ref(),
            account_id: request.account_id.clone(),
            alias: request.alias.clone(),
            account_exists: false,
            alias_target_account_id: None,
            observed_block_height: 7,
            observed_block_hash: HashOf::from_untyped_unchecked(Hash::new(
                b"routed account-onboarding current-state anchor",
            )),
        };
        let response_body = norito::json::to_vec(&response).expect("response JSON");
        let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
        assert_eq!(
            sanitize_routed_account_onboarding_current_state(
                &app,
                route,
                &request_body,
                &response_body,
            )
            .expect("strict remote snapshot without an ingress anchor or alias binding"),
            response_body
        );

        let mut substituted = response.clone();
        substituted.alias = "other@universal".to_owned();
        let substituted_body =
            norito::json::to_vec(&substituted).expect("substituted response JSON");
        assert!(
            sanitize_routed_account_onboarding_current_state(
                &app,
                route,
                &request_body,
                &substituted_body,
            )
            .is_err()
        );

        let mut zero_height = response;
        zero_height.observed_block_height = 0;
        let zero_height_body =
            norito::json::to_vec(&zero_height).expect("zero-height response JSON");
        assert!(
            sanitize_routed_account_onboarding_current_state(
                &app,
                route,
                &request_body,
                &zero_height_body,
            )
            .is_err()
        );
    }
}
