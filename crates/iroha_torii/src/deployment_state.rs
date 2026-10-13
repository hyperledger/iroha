//! Authenticated, atomic smart-contract deployment compare-and-swap state.
use crate::{
    AxResponse, Error, SharedAppState,
    routing::{ContractDeploymentStateRequestDto, ContractDeploymentStateResponseDto},
};
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method, Uri},
};
use iroha_core::{queue::RoutingDecision, state::StateReadOnly as _};
use iroha_data_model::{
    account::{AccountId, address::chain_discriminant},
    smart_contract::{CONTRACT_DEPLOY_NONCE_METADATA_KEY, ContractAlias},
};
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use mv::storage::StorageReadOnly as _;
use std::str::FromStr as _;
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
fn parse_exact_contract_alias(literal: &str) -> Result<ContractAlias, Error> {
    if literal.is_empty() || literal.trim() != literal {
        return Err(conversion_error(
            "contract_alias must be a non-empty canonical literal without surrounding whitespace",
        ));
    }
    let alias = ContractAlias::from_str(literal)
        .map_err(|error| conversion_error(format!("invalid contract_alias: {error}")))?;
    if alias.as_ref() != literal {
        return Err(conversion_error(
            "contract_alias must use its exact canonical literal",
        ));
    }
    Ok(alias)
}
fn deployment_dataspace_id(
    view: &iroha_core::state::StateView<'_>,
    alias: &ContractAlias,
    ledger_time_ms: u64,
) -> Result<(DataSpaceId, String), Error> {
    let segment = alias.dataspace_segment();
    let dataspace_id = iroha_core::sns::active_dataspace_id_by_alias(
        view.world(),
        &view.nexus().dataspace_catalog,
        segment,
        ledger_time_ms,
    )
    .map_err(super::live_dataspace_resolution_error)?
    .ok_or_else(|| {
        conversion_error(format!(
            "unknown or inactive dataspace alias `{segment}` in contract_alias"
        ))
    })?;
    let canonical_alias = view
        .nexus()
        .dataspace_catalog
        .by_id(dataspace_id)
        .map_or_else(|| segment.to_owned(), |entry| entry.alias.clone());
    Ok((dataspace_id, canonical_alias))
}
fn anchoring_block(
    view: &iroha_core::state::StateView<'_>,
) -> Result<
    (
        u64,
        iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
        u64,
    ),
    Error,
> {
    let observed_height = u64::try_from(view.height())
        .map_err(|_| invariant_error("committed block height does not fit in u64"))?;
    let observed_hash = view
        .latest_block_hash()
        .ok_or_else(|| Error::AppServiceUnavailable {
            code: "contract_deployment_state_unavailable",
            message: "no committed block anchors contract deployment state".to_owned(),
        })?;
    let block = view
        .latest_block()
        .map_err(crate::canonical_history::canonical_attempt_error)?
        .ok_or_else(|| {
            invariant_error(format!(
                "committed block {observed_height} is unavailable from the authoritative ledger"
            ))
        })?;
    let header = block.header();
    if header.height().get() != observed_height || header.hash() != observed_hash {
        return Err(invariant_error(
            "latest committed block header disagrees with the state-view block-hash journal",
        ));
    }
    let ledger_time_ms = u64::try_from(header.creation_time().as_millis())
        .map_err(|_| invariant_error("latest committed block timestamp does not fit in u64"))?;
    Ok((observed_height, observed_hash, ledger_time_ms))
}
fn reserved_deploy_nonce(
    world: &impl iroha_core::state::WorldReadOnly,
    authority: &AccountId,
) -> Result<u64, Error> {
    let account = world.account(authority).map_err(|_| Error::AppNotFound {
        code: "contract_deployment_authority_not_found",
        message: format!("deployment authority `{authority}` does not exist"),
    })?;
    let nonce_key = Name::from_str(CONTRACT_DEPLOY_NONCE_METADATA_KEY)
        .expect("reserved contract deployment nonce key must remain a valid Name");
    let nonce = account.metadata().get(&nonce_key).map_or(Ok(0_u64), |value| {
        value.clone().try_into_any_norito::<u64>().map_err(|_| {
            invariant_error(format!(
                "account metadata key `{nonce_key}` contains an invalid native contract deployment nonce"
            ))
        })
    })?;
    nonce.checked_add(1).ok_or_else(|| {
        invariant_error("contract deployment nonce is exhausted and cannot be incremented")
    })?;
    Ok(nonce)
}
fn live_previous_contract_address(
    world: &impl iroha_core::state::WorldReadOnly,
    alias: &ContractAlias,
    alias_dataspace_id: DataSpaceId,
    ledger_time_ms: u64,
) -> Result<Option<iroha_data_model::smart_contract::ContractAddress>, Error> {
    let Some(raw_previous) = world.contract_aliases().get(alias).cloned() else {
        return Ok(None);
    };
    let binding = world
        .contract_alias_bindings()
        .get(&raw_previous)
        .ok_or_else(|| {
            invariant_error(format!(
                "contract alias `{alias}` has no canonical binding record"
            ))
        })?;
    if binding.alias != *alias {
        return Err(invariant_error(format!(
            "contract alias `{alias}` has an inconsistent canonical binding record"
        )));
    }
    if binding.is_grace_expired_at(ledger_time_ms) {
        return Ok(None);
    }
    let previous_dataspace_id = raw_previous.dataspace_id().map_err(|error| {
        invariant_error(format!(
            "current contract alias target `{raw_previous}` has an invalid dataspace: {error}"
        ))
    })?;
    if previous_dataspace_id != alias_dataspace_id {
        return Err(invariant_error(format!(
            "current contract alias target `{raw_previous}` belongs to the wrong dataspace"
        )));
    }
    if world.contract_instances().get(&raw_previous).is_none() {
        return Err(invariant_error(format!(
            "current contract alias target `{raw_previous}` is not an active contract"
        )));
    }
    Ok(Some(raw_previous))
}
pub fn read_contract_deployment_state(
    app: &SharedAppState,
    request: &ContractDeploymentStateRequestDto,
    expected_route: Option<RoutingDecision>,
) -> Result<ContractDeploymentStateResponseDto, Error> {
    let (authority, canonical_authority) =
        super::parse_exact_account_id_literal(&request.authority)?;
    let contract_alias = parse_exact_contract_alias(&request.contract_alias)?;
    // Every consensus-derived response field below is read from this one retry-consistent view.
    let view = app.state.view();
    let (observed_block_height, observed_block_hash, ledger_time_ms) = anchoring_block(&view)?;
    let (dataspace_id, dataspace_alias) =
        deployment_dataspace_id(&view, &contract_alias, ledger_time_ms)?;
    if let Some(route) = expected_route
        && route.dataspace_id != dataspace_id
    {
        return Err(invariant_error(format!(
            "routed deployment-state request targeted dataspace {} but the active alias resolves to {}",
            route.dataspace_id.as_u64(),
            dataspace_id.as_u64()
        )));
    }
    let deploy_nonce = reserved_deploy_nonce(view.world(), &authority)?;
    let previous_contract_address = live_previous_contract_address(
        view.world(),
        &contract_alias,
        dataspace_id,
        ledger_time_ms,
    )?;
    Ok(ContractDeploymentStateResponseDto {
        authority: canonical_authority,
        contract_alias: contract_alias.to_string(),
        deploy_nonce: deploy_nonce.to_string(),
        dataspace_alias,
        dataspace_id: dataspace_id.as_u64().to_string(),
        previous_contract_address: previous_contract_address.map(|address| address.to_string()),
        observed_block_height: observed_block_height.to_string(),
        observed_block_hash: observed_block_hash.to_string(),
        ledger_time_ms: ledger_time_ms.to_string(),
        chain_discriminant: chain_discriminant().to_string(),
    })
}
pub fn execute_contract_deployment_state_local_read(
    app: &SharedAppState,
    request: &ContractDeploymentStateRequestDto,
    expected_route: Option<RoutingDecision>,
) -> Result<AxResponse, Error> {
    super::json_ok(read_contract_deployment_state(
        app,
        request,
        expected_route,
    )?)
}
fn canonical_decimal_u64(value: &str, field: &str) -> Result<u64, String> {
    if value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{field} must be a decimal u64 string"))?;
    if parsed.to_string() != value {
        return Err(format!("{field} must use canonical decimal u64 text"));
    }
    Ok(parsed)
}
pub fn sanitize_routed_contract_deployment_state(
    route: RoutingDecision,
    request_body: &[u8],
    response_body: &[u8],
) -> Result<Vec<u8>, String> {
    let request: ContractDeploymentStateRequestDto = norito::json::from_slice(request_body)
        .map_err(|error| format!("invalid routed deployment-state request: {error}"))?;
    let response: ContractDeploymentStateResponseDto = norito::json::from_slice(response_body)
        .map_err(|error| format!("invalid routed deployment-state response schema: {error}"))?;
    let (_, canonical_authority) = super::parse_exact_account_id_literal(&request.authority)
        .map_err(|error| format!("invalid routed deployment authority: {error}"))?;
    let contract_alias = parse_exact_contract_alias(&request.contract_alias)
        .map_err(|error| format!("invalid routed deployment alias: {error}"))?;
    if response.authority != canonical_authority
        || response.contract_alias != contract_alias.as_ref()
    {
        return Err(
            "routed deployment-state response does not bind the exact request authority and alias"
                .to_owned(),
        );
    }
    let deploy_nonce = canonical_decimal_u64(&response.deploy_nonce, "deploy_nonce")?;
    if deploy_nonce == u64::MAX {
        return Err("deploy_nonce is exhausted".to_owned());
    }
    let dataspace_id = canonical_decimal_u64(&response.dataspace_id, "dataspace_id")?;
    if dataspace_id != route.dataspace_id.as_u64() {
        return Err("routed deployment-state response names the wrong dataspace".to_owned());
    }
    let expected_dataspace_alias = if contract_alias
        .dataspace_segment()
        .eq_ignore_ascii_case("universal")
    {
        "universal"
    } else {
        contract_alias.dataspace_segment()
    };
    if response.dataspace_alias != expected_dataspace_alias {
        return Err(
            "routed deployment-state response names a non-canonical dataspace alias".to_owned(),
        );
    }
    if let Some(previous) = response.previous_contract_address.as_deref() {
        let address = iroha_data_model::smart_contract::ContractAddress::from_str(previous)
            .map_err(|error| format!("invalid previous_contract_address: {error}"))?;
        if address.as_ref() != previous
            || address
                .dataspace_id()
                .map_err(|error| format!("invalid previous contract dataspace: {error}"))?
                != route.dataspace_id
        {
            return Err(
                "previous_contract_address is non-canonical or belongs to the wrong dataspace"
                    .to_owned(),
            );
        }
    }
    let observed_height =
        canonical_decimal_u64(&response.observed_block_height, "observed_block_height")?;
    if observed_height == 0 {
        return Err("observed_block_height must be non-zero".to_owned());
    }
    canonical_decimal_u64(&response.ledger_time_ms, "ledger_time_ms")?;
    let response_chain = canonical_decimal_u64(&response.chain_discriminant, "chain_discriminant")?;
    if response_chain != u64::from(chain_discriminant()) {
        return Err(
            "routed deployment-state response uses the wrong chain discriminant".to_owned(),
        );
    }
    let observed_hash = response
        .observed_block_hash
        .parse::<iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>>()
        .map_err(|error| format!("invalid observed_block_hash: {error}"))?;
    if observed_hash.to_string() != response.observed_block_hash {
        return Err("observed_block_hash must use its canonical Rust literal".to_owned());
    }
    norito::json::to_vec(&response)
        .map_err(|error| format!("failed to encode sanitized deployment-state response: {error}"))
}
pub async fn handler_contract_deployment_state(
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
        "v1/contracts/deployment-state",
        "contract_deployment_state",
        None,
    )
    .await?;
    let caller = super::require_signed_account_request(
        &app,
        &headers,
        &method,
        &uri,
        body.as_ref(),
        "contract_deployment_state_auth_required",
        "canonical signed account headers are required to read contract deployment state",
    )?;
    let request: ContractDeploymentStateRequestDto =
        match super::decode_current_app_routed_read_json(body.as_ref()) {
            Some(Ok(request)) => request,
            Some(Err(response)) => return Ok(response),
            None => norito::json::from_slice(body.as_ref()).map_err(|error| {
                conversion_error(format!("invalid deployment-state request: {error}"))
            })?,
        };
    let (authority, _) = super::parse_exact_account_id_literal(&request.authority)?;
    if caller != authority {
        return Err(Error::AppForbidden {
            code: "contract_deployment_state_authority_mismatch",
            message: "authenticated account must equal the requested deployment authority"
                .to_owned(),
        });
    }
    let alias = parse_exact_contract_alias(&request.contract_alias)?;
    if let Some(route) = super::torii_contract_target_read_route(app.as_ref(), None, Some(&alias))?
    {
        return Ok(super::execute_torii_single_route_read(
            &app,
            route,
            iroha_core::torii_proxy::ToriiReadEndpointV1::ContractDeploymentState,
            Vec::new(),
            None,
            body.to_vec(),
        )
        .await);
    }
    execute_contract_deployment_state_local_read(&app, &request, None)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app_auth::CanonicalRequestAuthConfig,
        tests_runtime_handlers::{
            app_auth_test_guard, checked_torii_test_ed25519_keypair,
            mk_app_state_for_tests_with_world, signed_network_app_headers,
        },
    };
    use axum::{body::Bytes, http::StatusCode, response::IntoResponse as _};
    use iroha_crypto::Hash;
    use iroha_data_model::{
        Registrable as _,
        account::{Account, AccountAddress, AccountId},
        block::BlockHeader,
        smart_contract::{ContractAddress, ContractAlias},
        sns::{NameControllerV1, NameRecordV1},
    };
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;
    use iroha_primitives::json::Json;
    use norito::codec::Encode as _;
    use std::{num::NonZeroU64, sync::Arc};
    enum NonceFixture {
        Missing,
        U64(u64),
        Invalid,
    }
    fn fixture_world(
        authority: &AccountId,
        other: Option<&AccountId>,
        nonce: NonceFixture,
    ) -> iroha_core::state::World {
        let mut metadata = Metadata::default();
        let nonce_key = Name::from_str(CONTRACT_DEPLOY_NONCE_METADATA_KEY).expect("nonce key");
        match nonce {
            NonceFixture::Missing => {}
            NonceFixture::U64(value) => {
                metadata.insert(nonce_key, Json::new(value));
            }
            NonceFixture::Invalid => {
                metadata.insert(nonce_key, Json::new("not-a-native-u64".to_owned()));
            }
        }
        let authority_account = Account::new(authority.clone())
            .with_metadata(metadata)
            .build(authority);
        let mut accounts = vec![authority_account];
        if let Some(other) = other {
            accounts.push(Account::new(other.clone()).build(authority));
        }
        iroha_core::state::World::with([], accounts, [])
    }
    fn fixture_app(
        authority: &AccountId,
        other: Option<&AccountId>,
        nonce: NonceFixture,
    ) -> SharedAppState {
        mk_app_state_for_tests_with_world(fixture_world(authority, other, nonce))
    }
    fn anchor_state(
        app: &mut SharedAppState,
        creation_time_ms: u64,
        binding: Option<(
            ContractAddress,
            ContractAlias,
            Option<u64>,
            Option<u64>,
            u64,
        )>,
    ) -> iroha_crypto::HashOf<BlockHeader> {
        let app = Arc::get_mut(app).expect("unique deployment app");
        let state = Arc::get_mut(&mut app.state).expect("unique deployment fixture world");
        let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, creation_time_ms, 0);
        let mut state_block = state.block(header);
        if let Some((address, alias, lease_expiry_ms, grace_until_ms, bound_at_ms)) = binding {
            let mut transaction = state_block.transaction();
            transaction
                .world_mut_for_testing()
                .bind_active_contract_subject_for_testing(
                    address.clone(),
                    Hash::new(b"deployment-state active contract fixture"),
                );
            transaction
                .world_mut_for_testing()
                .bind_contract_alias(
                    &address,
                    alias,
                    lease_expiry_ms,
                    grace_until_ms,
                    bound_at_ms,
                )
                .expect("bind deployment-state contract alias fixture");
            transaction.apply();
        }
        state_block
            .commit_world_overlay_for_testing()
            .expect("seed deployment alias state");
        let world = std::mem::take(&mut state.world);
        let mut chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::start(
            iroha_core::sumeragi::test_chain::TestChainConfig::new(world, 1),
        )
        .expect("original deployment snapshot genesis");
        chain.commit_at(creation_time_ms, Vec::new());
        let block_hash = chain.committed(2).block_hash();
        app.state = chain.state().clone();
        app.kura = chain.kura().clone();
        app.local_peer_id = Some(chain.validators()[0].0.clone());
        assert_eq!(app.state.view().latest_block_hash(), Some(block_hash));
        block_hash
    }

    fn request(authority: &AccountId) -> ContractDeploymentStateRequestDto {
        ContractDeploymentStateRequestDto {
            authority: authority.to_string(),
            contract_alias: "deploy::universal".to_owned(),
        }
    }
    #[test]
    fn route_catalog_declares_canonical_account_signature_authentication() {
        use iroha_torii_shared::route_catalog::{AuthenticationPolicy, HttpMethod};
        let route = iroha_torii_shared::route_catalog::contracts_and_verification_keys::CONTRACTS_DEPLOYMENT_STATE_POST;
        assert_eq!(route.method(), HttpMethod::Post);
        assert_eq!(route.path(), "/v1/contracts/deployment-state");
        assert_eq!(
            route.authentication(),
            AuthenticationPolicy::CanonicalAccountSignature
        );
    }
    #[test]
    fn snapshot_uses_active_sns_dataspace_resolution_before_commit_fallbacks() {
        let authority_key = checked_torii_test_ed25519_keypair(
            0xd7,
            "derive dynamic-dataspace deployment-state authority fixture key",
        );
        let authority = AccountId::new(authority_key.public_key().clone());
        let dataspace_alias = "alpha";
        let selector = iroha_core::sns::selector_for_dataspace_alias(dataspace_alias)
            .expect("dynamic dataspace selector");
        let expected_dataspace_id = iroha_core::sns::dataspace_id_for_sns_alias(dataspace_alias)
            .expect("dynamic dataspace id");
        let authority_address =
            AccountAddress::from_account_id(&authority).expect("authority address");
        let record = NameRecordV1::new(
            selector.clone(),
            authority.clone(),
            vec![NameControllerV1::account(&authority_address)],
            0,
            10,
            2_000,
            3_000,
            4_000,
            Metadata::default(),
        );
        let mut world = fixture_world(&authority, None, NonceFixture::Missing);
        world.smart_contract_state_mut_for_testing().insert(
            iroha_core::sns::record_storage_key(&selector),
            record.encode(),
        );
        let mut app = mk_app_state_for_tests_with_world(world);
        anchor_state(&mut app, 1_000, None);
        let response = read_contract_deployment_state(
            &app,
            &ContractDeploymentStateRequestDto {
                authority: authority.to_string(),
                contract_alias: format!("deploy::{dataspace_alias}"),
            },
            None,
        )
        .expect("deployment state for active SNS dataspace");
        assert_eq!(response.dataspace_alias, dataspace_alias);
        assert_eq!(
            response.dataspace_id,
            expected_dataspace_id.as_u64().to_string()
        );
    }
    #[test]
    fn snapshot_matches_commit_nonce_and_live_alias_cas_semantics() {
        let authority_key = checked_torii_test_ed25519_keypair(
            0xd1,
            "derive deployment-state authority fixture key",
        );
        let authority = AccountId::new(authority_key.public_key().clone());
        let mut app = fixture_app(&authority, None, NonceFixture::U64(7));
        let alias: ContractAlias = "deploy::universal".parse().expect("contract alias");
        let previous = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            6,
            DataSpaceId::UNIVERSAL,
        )
        .expect("previous contract address");
        let observed_hash = anchor_state(
            &mut app,
            1_000,
            Some((previous.clone(), alias, Some(900), Some(1_100), 100)),
        );
        let response = read_contract_deployment_state(&app, &request(&authority), None)
            .expect("deployment state");
        assert_eq!(response.authority, authority.to_string());
        assert_eq!(response.contract_alias, "deploy::universal");
        assert_eq!(response.deploy_nonce, "7");
        assert_eq!(response.dataspace_alias, "universal");
        assert_eq!(response.dataspace_id, "0");
        assert_eq!(
            response.previous_contract_address.as_deref(),
            Some(previous.as_ref())
        );
        assert_eq!(response.observed_block_height, "2");
        assert_eq!(response.observed_block_hash, observed_hash.to_string());
        assert_eq!(response.ledger_time_ms, "1000");
        assert_eq!(
            response.chain_discriminant,
            chain_discriminant().to_string()
        );
        let new_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            response.deploy_nonce.parse().expect("decimal deploy nonce"),
            DataSpaceId::new(response.dataspace_id.parse().expect("decimal dataspace id")),
        )
        .expect("next CAS address");
        assert_ne!(new_address, previous);
    }
    #[test]
    fn snapshot_treats_grace_expired_raw_binding_as_no_live_previous_target() {
        let authority_key = checked_torii_test_ed25519_keypair(
            0xd2,
            "derive grace-expired deployment-state authority fixture key",
        );
        let authority = AccountId::new(authority_key.public_key().clone());
        let mut app = fixture_app(&authority, None, NonceFixture::U64(1));
        let previous = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("previous contract address");
        anchor_state(
            &mut app,
            1_000,
            Some((
                previous,
                "deploy::universal".parse().expect("contract alias"),
                Some(800),
                Some(900),
                100,
            )),
        );
        let response = read_contract_deployment_state(&app, &request(&authority), None)
            .expect("deployment state");
        assert_eq!(response.deploy_nonce, "1");
        assert_eq!(response.previous_contract_address, None);
    }
    #[test]
    fn snapshot_fails_closed_on_invalid_reserved_nonce_and_wrong_route() {
        let authority_key = checked_torii_test_ed25519_keypair(
            0xd3,
            "derive malformed deployment-state authority fixture key",
        );
        let authority = AccountId::new(authority_key.public_key().clone());
        let mut invalid_app = fixture_app(&authority, None, NonceFixture::Invalid);
        anchor_state(&mut invalid_app, 1_000, None);
        let error = read_contract_deployment_state(&invalid_app, &request(&authority), None)
            .expect_err("invalid native nonce must fail closed");
        assert!(matches!(
            error,
            Error::Query(iroha_data_model::ValidationFail::InternalError(_))
        ));
        let mut valid_app = fixture_app(&authority, None, NonceFixture::Missing);
        anchor_state(&mut valid_app, 1_000, None);
        let error = read_contract_deployment_state(
            &valid_app,
            &request(&authority),
            Some(RoutingDecision::new(
                iroha_model_base::topology::LaneId::SINGLE,
                DataSpaceId::new(9),
            )),
        )
        .expect_err("wrong authoritative route must fail closed");
        assert!(matches!(
            error,
            Error::Query(iroha_data_model::ValidationFail::InternalError(_))
        ));
    }
    #[test]
    fn routed_response_sanitizer_rejects_unknown_fields_and_noncanonical_anchor() {
        let authority_key = checked_torii_test_ed25519_keypair(
            0xd6,
            "derive deployment-state sanitizer authority fixture key",
        );
        let authority = AccountId::new(authority_key.public_key().clone());
        let request_body = norito::json::to_vec(&request(&authority)).expect("request JSON");
        let block_hash = iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"deployment-state sanitizer block",
        ));
        let response = ContractDeploymentStateResponseDto {
            authority: authority.to_string(),
            contract_alias: "deploy::universal".to_owned(),
            deploy_nonce: "0".to_owned(),
            dataspace_alias: "universal".to_owned(),
            dataspace_id: "0".to_owned(),
            previous_contract_address: None,
            observed_block_height: "1".to_owned(),
            observed_block_hash: block_hash.to_string(),
            ledger_time_ms: "1000".to_owned(),
            chain_discriminant: chain_discriminant().to_string(),
        };
        let response_body = norito::json::to_vec(&response).expect("response JSON");
        let route = RoutingDecision::new(
            iroha_model_base::topology::LaneId::SINGLE,
            DataSpaceId::UNIVERSAL,
        );
        assert_eq!(
            sanitize_routed_contract_deployment_state(route, &request_body, &response_body)
                .expect("canonical routed response"),
            response_body
        );
        let mut unknown = String::from_utf8(response_body).expect("UTF-8 response");
        assert_eq!(unknown.pop(), Some('}'));
        unknown.push_str(",\"unknown\":true}");
        assert!(
            sanitize_routed_contract_deployment_state(route, &request_body, unknown.as_bytes())
                .is_err(),
            "deny-unknown response DTO must reject injected fields"
        );
        let mut noncanonical = response;
        noncanonical.observed_block_hash = noncanonical.observed_block_hash.to_ascii_lowercase();
        if noncanonical.observed_block_hash != block_hash.to_string() {
            let body = norito::json::to_vec(&noncanonical).expect("noncanonical response JSON");
            assert!(
                sanitize_routed_contract_deployment_state(route, &request_body, &body).is_err(),
                "noncanonical Rust hash literal must be rejected"
            );
        }
    }
    #[tokio::test]
    async fn handler_requires_exact_authority_bound_canonical_auth_and_strict_body() {
        let _guard = app_auth_test_guard(CanonicalRequestAuthConfig::default());
        let authority_key = checked_torii_test_ed25519_keypair(
            0xd4,
            "derive authenticated deployment-state authority fixture key",
        );
        let other_key = checked_torii_test_ed25519_keypair(
            0xd5,
            "derive mismatched deployment-state caller fixture key",
        );
        let authority = AccountId::new(authority_key.public_key().clone());
        let other = AccountId::new(other_key.public_key().clone());
        let mut app = fixture_app(&authority, Some(&other), NonceFixture::Missing);
        anchor_state(&mut app, 1_234, None);
        let method = Method::POST;
        let uri: Uri = "/v1/contracts/deployment-state".parse().expect("uri");
        let body = norito::json::to_vec(&request(&authority)).expect("request JSON");
        let missing_auth = handler_contract_deployment_state(
            State(app.clone()),
            method.clone(),
            uri.clone(),
            HeaderMap::new(),
            crate::loopback_connect_info(),
            Bytes::from(body.clone()),
        )
        .await
        .expect_err("anonymous deployment-state read must fail");
        assert!(matches!(missing_auth, Error::AppUnauthorized { .. }));
        let mismatched_headers = signed_network_app_headers(
            app.state.network_id_ref(),
            &other,
            &other_key,
            &method,
            &uri,
            &body,
        );
        let mismatch = handler_contract_deployment_state(
            State(app.clone()),
            method.clone(),
            uri.clone(),
            mismatched_headers,
            crate::loopback_connect_info(),
            Bytes::from(body.clone()),
        )
        .await
        .expect_err("caller/authority mismatch must fail");
        assert!(matches!(mismatch, Error::AppForbidden { .. }));
        let unknown_body = format!(
            r#"{{"authority":"{}","contract_alias":"deploy::universal","unknown":true}}"#,
            authority
        )
        .into_bytes();
        let unknown_headers = signed_network_app_headers(
            app.state.network_id_ref(),
            &authority,
            &authority_key,
            &method,
            &uri,
            &unknown_body,
        );
        let unknown = handler_contract_deployment_state(
            State(app.clone()),
            method.clone(),
            uri.clone(),
            unknown_headers,
            crate::loopback_connect_info(),
            Bytes::from(unknown_body),
        )
        .await
        .expect_err("unknown request fields must fail");
        assert!(matches!(
            unknown,
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(_)
            ))
        ));
        let headers = signed_network_app_headers(
            app.state.network_id_ref(),
            &authority,
            &authority_key,
            &method,
            &uri,
            &body,
        );
        let response = handler_contract_deployment_state(
            State(app),
            method,
            uri,
            headers,
            crate::loopback_connect_info(),
            Bytes::from(body),
        )
        .await
        .expect("authenticated deployment-state response")
        .into_response();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let value: norito::json::Value =
            norito::json::from_slice(&body).expect("strict response JSON");
        let object = value.as_object().expect("response object");
        assert_eq!(
            object
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([
                "authority",
                "chain_discriminant",
                "contract_alias",
                "dataspace_alias",
                "dataspace_id",
                "deploy_nonce",
                "ledger_time_ms",
                "observed_block_hash",
                "observed_block_height",
                "previous_contract_address",
            ])
        );
        let dto: ContractDeploymentStateResponseDto =
            norito::json::from_slice(&body).expect("response DTO");
        assert_eq!(dto.deploy_nonce, "0");
        assert_eq!(dto.previous_contract_address, None);
        assert_eq!(dto.ledger_time_ms, "1234");
    }
}
