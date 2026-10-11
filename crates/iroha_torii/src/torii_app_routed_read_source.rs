// Source-bounded materialization for application-API routed reads.
use norito::core::{DecodeFlagsGuard, Encoder, NoritoDeserialize};
use std::marker::PhantomData;
/// Borrowed wire-equivalent of a derived struct in declaration order.
///
/// App routes use this adapter when world state stores an identifier separately
/// from its value. It writes the target DTO directly into the admitted
/// canonical frame, avoiding an unmetered deep clone before the first bounded
/// decode.
struct ToriiBorrowedRoutedReadStruct<'a, T, const N: usize> {
    fields: [&'a dyn norito::core::SerializePayload; N],
    marker: PhantomData<T>,
}
impl<'a, T, const N: usize> ToriiBorrowedRoutedReadStruct<'a, T, N> {
    const fn new(fields: [&'a dyn norito::core::SerializePayload; N]) -> Self {
        Self {
            fields,
            marker: PhantomData,
        }
    }
}
impl<T: norito::NoritoSchema, const N: usize> norito::NoritoSchema
    for ToriiBorrowedRoutedReadStruct<'_, T, N>
{
    fn nominal_name() -> String {
        norito::schema::identity::generic_name(
            "iroha_torii::ToriiBorrowedRoutedReadStruct",
            &["'_".to_owned(), T::nominal_name(), N.to_string()],
        )
    }
    fn frame_name() -> String {
        T::frame_name()
    }
}
impl<T, const N: usize> norito::core::SerializePayload for ToriiBorrowedRoutedReadStruct<'_, T, N> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::core::Error> {
        for value in self.fields.iter().copied() {
            norito::core::write_len_prefixed(writer, value)?;
        }
        Ok(())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.fields.iter().try_fold(0usize, |total, value| {
            let value_len = value.encoded_len_exact()?;
            total
                .checked_add(norito::core::len_prefix_len(value_len))?
                .checked_add(value_len)
        })
    }
}
/// Materialize the first owned route result through the admitted E/D corridor.
///
/// `source` may borrow arbitrarily nested world-state fields. The only
/// source-sized allocation made here is the hard-capped canonical frame. Its
/// owned replacement is then decoded with explicit Norito limits and charged
/// to the routed-read accumulator before it can escape this function.
fn torii_bounded_routed_read_source_payload<T, S>(
    source: &S,
    budget: &mut ToriiRoutedReadMemoryBudget,
) -> Result<ToriiBoundedNoritoPayload<T>, Response>
where
    S: norito::core::NoritoSerialize,
    T: norito::core::NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    let plan = budget.decode_plan(0)?;
    let _canonical_flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let canonical_bytes = norito::core::to_bytes_bounded(source, plan.canonical_limit_bytes)
        .map_err(|_| torii_routed_read_norito_encode_response())?;
    let (value, usage) = norito::core::with_decode_limits_measured(plan.limits, || {
        norito::decode_from_bytes_with_limits::<T>(&canonical_bytes, plan.limits)
    });
    let value = value.map_err(torii_routed_read_norito_decode_response)?;
    budget.retain_decode_usage(usage)?;
    budget.retain_canonical_capacity(canonical_bytes.capacity())?;
    Ok(ToriiBoundedNoritoPayload {
        value,
        canonical_bytes,
    })
}
fn torii_bounded_routed_read_payload_response<T>(
    payload: ToriiBoundedNoritoPayload<T>,
    format: ResponseFormat,
    budget: ToriiRoutedReadMemoryBudget,
) -> Result<Response, Response>
where
    T: JsonSerialize,
{
    match format {
        ResponseFormat::Norito => {
            torii_routed_read_ensure(
                "local route response body",
                payload.canonical_bytes.len(),
                budget.route_body_limit(),
            )?;
            drop(payload.value);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
                )
                .body(Body::from(payload.canonical_bytes))
                .expect("build preflighted source-bounded routed-read response"))
        }
        ResponseFormat::Json => {
            let ToriiBoundedNoritoPayload {
                value,
                canonical_bytes,
            } = payload;
            drop(canonical_bytes);
            let body = budget.json_body(&value)?;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )
                .body(Body::from(Bytes::from(body)))
                .expect("build preflighted source-bounded routed-read JSON response"))
        }
    }
}
fn torii_bounded_routed_read_source_response<T, S>(
    source: &S,
    format: ResponseFormat,
    mut budget: ToriiRoutedReadMemoryBudget,
) -> Result<Response, Response>
where
    S: norito::core::NoritoSerialize,
    T: JsonSerialize + norito::core::NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    let payload = torii_bounded_routed_read_source_payload::<T, S>(source, &mut budget)?;
    torii_bounded_routed_read_payload_response(payload, format, budget)
}
fn torii_local_routed_read_budget(
    app: &SharedAppState,
) -> Result<ToriiRoutedReadMemoryBudget, Response> {
    Ok(ToriiRoutedReadMemoryBudget::from_envelope(
        current_routed_read_memory_envelope(app)?,
        app.torii_proxy_max_response_bytes,
    ))
}
/// A native source entry acquires or borrows exactly one complete owner before parsing.
fn with_query_fanout_source_owner(
    app: &SharedAppState,
    work: impl FnOnce() -> Response,
) -> Response {
    let reservation = match try_acquire_query_fanout_memory(app) {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let response = COLLECTION_READ_MEMORY_RESERVATION.sync_scope(reservation.clone(), work);
    hold_query_fanout_memory_in_response_body(response, reservation)
}
fn execute_torii_account_local_source_read(
    app: &SharedAppState,
    account_literal: &str,
    format: ResponseFormat,
) -> Response {
    with_query_fanout_source_owner(app, || {
        execute_torii_account_local_source_read_admitted(app, account_literal, format)
    })
}
fn execute_torii_account_local_source_read_admitted(
    app: &SharedAppState,
    account_literal: &str,
    format: ResponseFormat,
) -> Response {
    let telemetry = app.telemetry_handle();
    let (account_id, _) = match routing::parse_account_path_segment_with_state(
        app.state.as_ref(),
        account_literal,
        &telemetry,
        routing::ENDPOINT_ACCOUNTS_GET,
    ) {
        Ok(parsed) => parsed,
        Err(error) => return error_response_with_format(error, format),
    };
    let state_view = app.state.view();
    let world = state_view.world();
    let account = match world.account(&account_id) {
        Ok(account) => account,
        Err(_) => {
            return error_response_with_format(
                Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                    iroha_data_model::query::error::QueryExecutionFail::NotFound,
                )),
                format,
            );
        }
    };
    let details = account.value().as_ref();
    let no_label = None::<iroha_data_model::account::AccountAlias>;
    let source = ToriiBorrowedRoutedReadStruct::<AccountReadResponse, 4>::new([
        account.id(),
        &no_label,
        &details.uaid,
        &details.opaque_ids,
    ]);
    let budget = match torii_local_routed_read_budget(app) {
        Ok(budget) => budget,
        Err(response) => return response,
    };
    torii_bounded_routed_read_source_response::<AccountReadResponse, _>(&source, format, budget)
        .unwrap_or_else(|response| response)
}
fn execute_torii_internal_account_local_source_read(
    app: &SharedAppState,
    account_literal: &str,
    format: ResponseFormat,
) -> Response {
    with_query_fanout_source_owner(app, || {
        execute_torii_internal_account_local_source_read_admitted(app, account_literal, format)
    })
}
fn execute_torii_internal_account_local_source_read_admitted(
    app: &SharedAppState,
    account_literal: &str,
    format: ResponseFormat,
) -> Response {
    let (account_id, _) = match parse_exact_account_id_literal(account_literal) {
        Ok(parsed) => parsed,
        Err(error) => return error_response_with_format(error, format),
    };
    let state_view = app.state.view();
    let world = state_view.world();
    let account = match world.account(&account_id) {
        Ok(account) => account,
        Err(_) => {
            return trusted_internal_read_error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "the exact canonical account was not found on this route",
                format,
            );
        }
    };
    let details = account.value().as_ref();
    let source = ToriiBorrowedRoutedReadStruct::<InternalAccountReadResponse, 4>::new([
        account.id(),
        &details.metadata,
        &details.uaid,
        &details.opaque_ids,
    ]);
    let budget = match torii_local_routed_read_budget(app) {
        Ok(budget) => budget,
        Err(response) => return response,
    };
    torii_bounded_routed_read_source_response::<InternalAccountReadResponse, _>(
        &source, format, budget,
    )
    .unwrap_or_else(|response| response)
}
fn execute_torii_internal_account_asset_local_source_read(
    app: &SharedAppState,
    account_literal: &str,
    asset_definition_literal: &str,
    scope_literal: &str,
    format: ResponseFormat,
) -> Response {
    with_query_fanout_source_owner(app, || {
        execute_torii_internal_account_asset_local_source_read_admitted(
            app,
            account_literal,
            asset_definition_literal,
            scope_literal,
            format,
        )
    })
}
fn execute_torii_internal_account_asset_local_source_read_admitted(
    app: &SharedAppState,
    account_literal: &str,
    asset_definition_literal: &str,
    scope_literal: &str,
    format: ResponseFormat,
) -> Response {
    let (account_id, _) = match parse_exact_account_id_literal(account_literal) {
        Ok(parsed) => parsed,
        Err(error) => return error_response_with_format(error, format),
    };
    let asset_definition_id =
        match parse_exact_asset_definition_id_literal(asset_definition_literal) {
            Ok(definition) => definition,
            Err(error) => return error_response_with_format(error, format),
        };
    let scope = match parse_exact_asset_balance_scope_literal(scope_literal) {
        Ok(scope) => scope,
        Err(error) => return error_response_with_format(error, format),
    };
    let asset_id = AssetId::with_scope(asset_definition_id, account_id, scope);
    let state_view = app.state.view();
    let world = state_view.world();
    let asset = match world.asset(&asset_id) {
        Ok(asset) => asset,
        Err(_) => {
            return trusted_internal_read_error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "the exact account asset bucket was not found on this route",
                format,
            );
        }
    };
    let source =
        ToriiBorrowedRoutedReadStruct::<Asset, 2>::new([asset.id(), asset.value().as_ref()]);
    let budget = match torii_local_routed_read_budget(app) {
        Ok(budget) => budget,
        Err(response) => return response,
    };
    torii_bounded_routed_read_source_response::<Asset, _>(&source, format, budget)
        .unwrap_or_else(|response| response)
}
/// Borrowed JSON projection for the single asset-definition route.
///
/// The public shape historically passed the definition through a native JSON
/// `Value` so an active alias binding could replace `alias` and add
/// `alias_binding`. Writing the same sorted object directly avoids cloning the
/// complete definition and materializing that intermediate value graph before
/// the routed-read body cap is enforced.
struct ToriiAssetDefinitionJsonSource<'a> {
    definition: &'a iroha_data_model::asset::definition::AssetDefinition,
    owning_dataspace: Option<DataSpaceId>,
    alias_binding: Option<&'a iroha_core::state::AssetDefinitionAliasBindingRecord>,
    observation_time_ms: u64,
}
impl norito::json::FastJsonWrite for ToriiAssetDefinitionJsonSource<'_> {
    fn write_json(&self, output: &mut String) {
        norito::json::write_json_unbounded(self, output);
    }
    fn write_json_to(
        &self,
        output: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        use norito::json::JsonSerialize as _;
        output.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            output.push_str("{\"alias\":")?;
            if let Some(binding) = self.alias_binding {
                norito::json::write_json_string_to(binding.alias.as_ref(), output)?;
                output.push_str(",\"alias_binding\":")?;
                write_torii_asset_alias_binding_json(binding, self.observation_time_ms, output)?;
            } else {
                self.definition.alias.json_serialize_to(output)?;
            }
            output.push_str(",\"balance_scope_policy\":")?;
            self.definition
                .balance_scope_policy
                .json_serialize_to(output)?;
            output.push_str(",\"confidential_policy\":")?;
            write_torii_asset_confidential_policy_json(
                &self.definition.confidential_policy,
                output,
            )?;
            output.push_str(",\"description\":")?;
            self.definition.description.json_serialize_to(output)?;
            output.push_str(",\"id\":")?;
            self.definition.id.json_serialize_to(output)?;
            output.push_str(",\"logo\":")?;
            self.definition.logo.json_serialize_to(output)?;
            output.push_str(",\"metadata\":")?;
            iroha_data_model::HasMetadata::metadata(self.definition).json_serialize_to(output)?;
            output.push_str(",\"mintable\":")?;
            self.definition.mintable.json_serialize_to(output)?;
            output.push_str(",\"name\":")?;
            self.definition.name.json_serialize_to(output)?;
            output.push_str(",\"owned_by\":")?;
            self.definition.owned_by.json_serialize_to(output)?;
            output.push_str(",\"owning_dataspace\":")?;
            write_torii_definition_dataspace_json(self.owning_dataspace, output)?;
            output.push_str(",\"owning_domain\":")?;
            self.definition.owning_domain.json_serialize_to(output)?;
            output.push_str(",\"spec\":")?;
            self.definition.spec.json_serialize_to(output)?;
            output.push_str(",\"total_quantity\":")?;
            self.definition.total_quantity.json_serialize_to(output)?;
            output.push('}')?;
            Ok(())
        })();
        output.end_container();
        result?;
        Ok(())
    }
}
/// Write a direct definition's exact home without converting it through a JSON number.
fn write_torii_definition_dataspace_json(
    dataspace: Option<DataSpaceId>,
    output: &mut dyn norito::json::JsonWriteSink,
) -> Result<(), norito::json::BoundedJsonError> {
    use norito::json::JsonSerialize as _;
    if let Some(dataspace) = dataspace {
        output.push('"')?;
        dataspace.as_u64().json_serialize_to(output)?;
        output.push('"')
    } else {
        output.push_str("null")
    }
}
/// Preserve the sorted nested projection without allocating an intermediate JSON graph.
fn write_torii_asset_confidential_policy_json(
    policy: &iroha_data_model::asset::definition::AssetConfidentialPolicy,
    output: &mut dyn norito::json::JsonWriteSink,
) -> Result<(), norito::json::BoundedJsonError> {
    use norito::json::JsonSerialize as _;
    output.begin_container()?;
    let result = (|| -> Result<(), norito::json::BoundedJsonError> {
        output.push_str("{\"mode\":")?;
        policy.mode.json_serialize_to(output)?;
        output.push_str(",\"pedersen_params_id\":")?;
        policy.pedersen_params_id.json_serialize_to(output)?;
        output.push_str(",\"pending_transition\":")?;
        if let Some(transition) = &policy.pending_transition {
            output.begin_container()?;
            let result = (|| -> Result<(), norito::json::BoundedJsonError> {
                output.push_str("{\"conversion_window\":")?;
                transition.conversion_window.json_serialize_to(output)?;
                output.push_str(",\"effective_height\":")?;
                transition.effective_height.json_serialize_to(output)?;
                output.push_str(",\"new_mode\":")?;
                transition.new_mode.json_serialize_to(output)?;
                output.push_str(",\"previous_mode\":")?;
                transition.previous_mode.json_serialize_to(output)?;
                output.push_str(",\"transition_id\":")?;
                transition.transition_id.json_serialize_to(output)?;
                output.push('}')?;
                Ok(())
            })();
            output.end_container();
            result?;
        } else {
            output.push_str("null")?;
        }
        output.push_str(",\"poseidon_params_id\":")?;
        policy.poseidon_params_id.json_serialize_to(output)?;
        output.push_str(",\"vk_set_hash\":")?;
        policy.vk_set_hash.json_serialize_to(output)?;
        output.push('}')?;
        Ok(())
    })();
    output.end_container();
    result?;
    Ok(())
}
fn write_torii_asset_alias_binding_json(
    binding: &iroha_core::state::AssetDefinitionAliasBindingRecord,
    observation_time_ms: u64,
    output: &mut dyn norito::json::JsonWriteSink,
) -> Result<(), norito::json::BoundedJsonError> {
    use iroha_core::state::AssetDefinitionAliasLeaseStatus;
    use norito::json::JsonSerialize as _;
    let status = match binding.status_at(observation_time_ms) {
        AssetDefinitionAliasLeaseStatus::Permanent => "permanent",
        AssetDefinitionAliasLeaseStatus::LeasedActive => "leased_active",
        AssetDefinitionAliasLeaseStatus::LeasedGrace => "leased_grace",
        AssetDefinitionAliasLeaseStatus::ExpiredPendingCleanup => "expired_pending_cleanup",
    };
    output.begin_container()?;
    let result = (|| -> Result<(), norito::json::BoundedJsonError> {
        output.push_str("{\"alias\":")?;
        norito::json::write_json_string_to(binding.alias.as_ref(), output)?;
        output.push_str(",\"bound_at_ms\":")?;
        binding.bound_at_ms.json_serialize_to(output)?;
        if let Some(grace_until_ms) = binding.grace_until_ms {
            output.push_str(",\"grace_until_ms\":")?;
            grace_until_ms.json_serialize_to(output)?;
        }
        if let Some(lease_expiry_ms) = binding.lease_expiry_ms {
            output.push_str(",\"lease_expiry_ms\":")?;
            lease_expiry_ms.json_serialize_to(output)?;
        }
        output.push_str(",\"status\":")?;
        norito::json::write_json_string_to(status, output)?;
        output.push('}')?;
        Ok(())
    })();
    output.end_container();
    result?;
    Ok(())
}
fn resolve_torii_asset_definition_source_selector(
    world: &impl iroha_core::state::WorldReadOnly,
    asset_literal: &str,
    observation_time_ms: u64,
) -> Result<iroha_data_model::asset::AssetDefinitionId, Error> {
    const INVALID_SELECTOR_MSG: &str = "invalid asset selector; expected a canonical Base58 asset id or an on-chain asset alias `<name>#<domain>.<dataspace>` / `<name>#<dataspace>`";
    let selector = asset_literal.trim();
    if selector.is_empty() {
        return Err(Error::Query(
            iroha_data_model::ValidationFail::NotPermitted(INVALID_SELECTOR_MSG.to_owned()),
        ));
    }
    if let Ok(id) = selector.parse::<iroha_data_model::asset::AssetDefinitionId>() {
        return world
            .asset_definitions()
            .get(&id)
            .map(|_| id)
            .ok_or_else(|| {
                Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                    iroha_data_model::query::error::QueryExecutionFail::NotFound,
                ))
            });
    }
    let alias: iroha_data_model::asset::AssetDefinitionAlias = selector.parse().map_err(|_| {
        Error::Query(iroha_data_model::ValidationFail::NotPermitted(
            INVALID_SELECTOR_MSG.to_owned(),
        ))
    })?;
    world
        .asset_definition_id_by_alias_at(&alias, observation_time_ms)
        .ok_or_else(|| {
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::NotFound,
            ))
        })
}
fn execute_torii_asset_definition_local_source_read(
    app: &SharedAppState,
    asset_literal: &str,
    visibility: &routing::DataspaceReadVisibility,
) -> Response {
    with_query_fanout_source_owner(app, || {
        execute_torii_asset_definition_local_source_read_admitted(app, asset_literal, visibility)
    })
}
fn execute_torii_asset_definition_local_source_read_admitted(
    app: &SharedAppState,
    asset_literal: &str,
    visibility: &routing::DataspaceReadVisibility,
) -> Response {
    let state_view = app.state.view();
    let world = state_view.world();
    let observation_time_ms = routing::asset_alias_observation_time_ms(app.state.as_ref());
    let definition_id = match resolve_torii_asset_definition_source_selector(
        world,
        asset_literal,
        observation_time_ms,
    ) {
        Ok(id) => id,
        Err(error) => return error_response_with_format(error, ResponseFormat::Json),
    };
    let Some(definition) = world.asset_definitions().get(&definition_id) else {
        return error_response_with_format(
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::NotFound,
            )),
            ResponseFormat::Json,
        );
    };
    if !visibility.allows_asset_definition(world, &definition_id) {
        return error_response_with_format(
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::NotFound,
            )),
            ResponseFormat::Json,
        );
    }
    let source = ToriiAssetDefinitionJsonSource {
        definition,
        owning_dataspace: match routing::asset_definition_dataspace_for_read(world, &definition_id)
        {
            Ok(home) => home,
            Err(error) => return error_response_with_format(error, ResponseFormat::Json),
        },
        alias_binding: world.asset_definition_alias_bindings().get(&definition_id),
        observation_time_ms,
    };
    let budget = match torii_local_routed_read_budget(app) {
        Ok(budget) => budget,
        Err(response) => return response,
    };
    budget
        .json_response(&source)
        .unwrap_or_else(|response| response)
}
struct ToriiSpaceDirectoryBindingsJsonSource<'a> {
    uaid: &'a iroha_data_model::nexus::UniversalAccountId,
    bindings: Option<&'a iroha_core::nexus::space_directory::UaidDataspaceBindings>,
    catalog: &'a iroha_data_model::nexus::DataSpaceCatalog,
    visibility: &'a routing::DataspaceReadVisibility,
}
impl norito::json::FastJsonWrite for ToriiSpaceDirectoryBindingsJsonSource<'_> {
    fn write_json(&self, output: &mut String) {
        norito::json::write_json_unbounded(self, output);
    }
    fn write_json_to(
        &self,
        output: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        use norito::json::JsonSerialize as _;
        output.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            output.push_str("{\"dataspaces\":[")?;
            if let Some(bindings) = self.bindings {
                let mut emitted = 0usize;
                for (dataspace_id, accounts) in bindings.iter() {
                    if !self.visibility.allows_dataspace(*dataspace_id) {
                        continue;
                    }
                    if emitted != 0 {
                        output.push(',')?;
                    }
                    emitted = emitted.saturating_add(1);
                    output.begin_container()?;
                    let result = (|| -> Result<(), norito::json::BoundedJsonError> {
                        output.push_str("{\"accounts\":[")?;
                        for (account_index, account_id) in accounts.iter().enumerate() {
                            if account_index != 0 {
                                output.push(',')?;
                            }
                            account_id.json_serialize_to(output)?;
                        }
                        output.push_str("],\"dataspace_alias\":")?;
                        self.catalog
                            .entries()
                            .iter()
                            .find(|entry| entry.id == *dataspace_id)
                            .map(|entry| entry.alias.as_str())
                            .json_serialize_to(output)?;
                        output.push_str(",\"dataspace_id\":")?;
                        dataspace_id.as_u64().json_serialize_to(output)?;
                        output.push('}')?;
                        Ok(())
                    })();
                    output.end_container();
                    result?;
                }
            }
            output.push_str("],\"uaid\":")?;
            // The route publishes the canonical UAID literal, not the model's
            // derived JSON representation. Its display length is fixed and bounded.
            self.uaid.to_string().json_serialize_to(output)?;
            output.push('}')?;
            Ok(())
        })();
        output.end_container();
        result?;
        Ok(())
    }
}
fn parse_torii_space_directory_uaid_literal(
    raw: &str,
) -> Result<iroha_data_model::nexus::UniversalAccountId, Error> {
    use core::str::FromStr as _;
    iroha_data_model::nexus::UniversalAccountId::from_str(raw).map_err(|_| {
        Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::InvalidSingularParameters,
        ))
    })
}
fn execute_torii_space_directory_bindings_local_source_read(
    app: &SharedAppState,
    uaid_literal: &str,
    visibility: &routing::DataspaceReadVisibility,
) -> Response {
    with_query_fanout_source_owner(app, || {
        execute_torii_space_directory_bindings_local_source_read_admitted(
            app,
            uaid_literal,
            visibility,
        )
    })
}
fn execute_torii_space_directory_bindings_local_source_read_admitted(
    app: &SharedAppState,
    uaid_literal: &str,
    visibility: &routing::DataspaceReadVisibility,
) -> Response {
    let uaid = match parse_torii_space_directory_uaid_literal(uaid_literal) {
        Ok(uaid) => uaid,
        Err(error) => return error_response_with_format(error, ResponseFormat::Json),
    };
    let state_view = app.state.view();
    let world = state_view.world();
    let source = ToriiSpaceDirectoryBindingsJsonSource {
        uaid: &uaid,
        bindings: world.uaid_dataspaces().get(&uaid),
        catalog: world.dataspace_catalog(),
        visibility,
    };
    let budget = match torii_local_routed_read_budget(app) {
        Ok(budget) => budget,
        Err(response) => return response,
    };
    budget
        .json_response(&source)
        .unwrap_or_else(|response| response)
}
struct ToriiContractAliasJsonSource<'a> {
    contract_alias: &'a iroha_data_model::smart_contract::ContractAlias,
    contract_address: &'a iroha_data_model::smart_contract::ContractAddress,
    contract_subject: &'a iroha_data_model::account::AccountId,
    dataspace_alias: &'a str,
    binding: &'a iroha_core::state::ContractAliasBindingRecord,
    observation_time_ms: u64,
}
impl norito::json::FastJsonWrite for ToriiContractAliasJsonSource<'_> {
    fn write_json(&self, output: &mut String) {
        norito::json::write_json_unbounded(self, output);
    }
    fn write_json_to(
        &self,
        output: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        use norito::json::JsonSerialize as _;
        output.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            output.push_str("{\"contract_alias\":")?;
            self.contract_alias.json_serialize_to(output)?;
            output.push_str(",\"contract_address\":")?;
            self.contract_address.json_serialize_to(output)?;
            output.push_str(",\"contract_subject_account\":")?;
            self.contract_subject.json_serialize_to(output)?;
            output.push_str(",\"dataspace\":")?;
            norito::json::write_json_string_to(self.dataspace_alias, output)?;
            output.push_str(",\"contract_alias_binding\":")?;
            write_torii_contract_alias_binding_json(
                self.binding,
                self.observation_time_ms,
                output,
            )?;
            output.push_str(",\"source\":\"world_state\"}")?;
            Ok(())
        })();
        output.end_container();
        result?;
        Ok(())
    }
}
fn write_torii_contract_alias_binding_json(
    binding: &iroha_core::state::ContractAliasBindingRecord,
    observation_time_ms: u64,
    output: &mut dyn norito::json::JsonWriteSink,
) -> Result<(), norito::json::BoundedJsonError> {
    use iroha_core::state::ContractAliasLeaseStatus;
    use norito::json::JsonSerialize as _;
    let status = match binding.status_at(observation_time_ms) {
        ContractAliasLeaseStatus::Permanent => "permanent",
        ContractAliasLeaseStatus::LeasedActive => "leased_active",
        ContractAliasLeaseStatus::LeasedGrace => "leased_grace",
        ContractAliasLeaseStatus::ExpiredPendingCleanup => "expired_pending_cleanup",
    };
    output.begin_container()?;
    let result = (|| -> Result<(), norito::json::BoundedJsonError> {
        output.push_str("{\"alias\":")?;
        binding.alias.json_serialize_to(output)?;
        output.push_str(",\"status\":")?;
        norito::json::write_json_string_to(status, output)?;
        if let Some(lease_expiry_ms) = binding.lease_expiry_ms {
            output.push_str(",\"lease_expiry_ms\":")?;
            lease_expiry_ms.json_serialize_to(output)?;
        }
        if let Some(grace_until_ms) = binding.grace_until_ms {
            output.push_str(",\"grace_until_ms\":")?;
            grace_until_ms.json_serialize_to(output)?;
        }
        output.push_str(",\"bound_at_ms\":")?;
        binding.bound_at_ms.json_serialize_to(output)?;
        output.push('}')?;
        Ok(())
    })();
    output.end_container();
    result?;
    Ok(())
}
fn execute_torii_contract_alias_local_source_read(
    app: &SharedAppState,
    alias_input: &str,
) -> Response {
    with_query_fanout_source_owner(app, || {
        execute_torii_contract_alias_local_source_read_admitted(app, alias_input)
    })
}
fn execute_torii_contract_alias_local_source_read_admitted(
    app: &SharedAppState,
    alias_input: &str,
) -> Response {
    use core::str::FromStr as _;
    if alias_input.is_empty() {
        return error_response_with_format(
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(
                    "contract alias must not be empty".to_owned(),
                ),
            )),
            ResponseFormat::Json,
        );
    }
    if alias_input.trim() != alias_input {
        return error_response_with_format(
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(
                    "contract alias must be a canonical literal without surrounding whitespace"
                        .to_owned(),
                ),
            )),
            ResponseFormat::Json,
        );
    }
    let contract_alias =
        match iroha_data_model::smart_contract::ContractAlias::from_str(alias_input) {
            Ok(alias) => alias,
            Err(error) => {
                return error_response_with_format(
                    Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                        iroha_data_model::query::error::QueryExecutionFail::Conversion(
                            error.to_string(),
                        ),
                    )),
                    ResponseFormat::Json,
                );
            }
        };
    let Some(dataspace_id) =
        (match dataspace_id_for_alias_segment(app, contract_alias.dataspace_segment()) {
            Ok(id) => id,
            Err(error) => return error_response_with_format(error, ResponseFormat::Json),
        })
    else {
        return error_response_with_format(
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(format!(
                    "unknown or inactive dataspace alias `{}` in contract alias",
                    contract_alias.dataspace_segment()
                )),
            )),
            ResponseFormat::Json,
        );
    };
    let observation_time_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let state_view = app.state.view();
    let world = state_view.world();
    let Some(contract_address) = world.contract_aliases().get(&contract_alias) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(binding) = world
        .contract_alias_bindings()
        .get(contract_address)
        .filter(|binding| {
            binding.alias == contract_alias && !binding.is_grace_expired_at(observation_time_ms)
        })
    else {
        return error_response_with_format(
            Error::Query(iroha_data_model::ValidationFail::InternalError(
                "contract alias index has no matching active consensus binding".to_owned(),
            )),
            ResponseFormat::Json,
        );
    };
    if contract_address.dataspace_id().ok() != Some(dataspace_id) {
        return error_response_with_format(
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(
                    "contract alias dataspace does not match bound contract address".to_owned(),
                ),
            )),
            ResponseFormat::Json,
        );
    }
    let Some(contract_subject) =
        iroha_core::smartcontracts::code::borrow_bound_contract_subject_from_world(
            world,
            contract_address,
        )
    else {
        return error_response_with_format(
            Error::Query(iroha_data_model::ValidationFail::InternalError(
                "active contract alias has no valid consensus subject binding".to_owned(),
            )),
            ResponseFormat::Json,
        );
    };
    let dataspace_alias = world
        .dataspace_catalog()
        .by_id(dataspace_id)
        .map(|entry| entry.alias.as_str())
        .unwrap_or_else(|| contract_alias.dataspace_segment());
    let source = ToriiContractAliasJsonSource {
        contract_alias: &contract_alias,
        contract_address,
        contract_subject,
        dataspace_alias,
        binding,
        observation_time_ms,
    };
    let budget = match torii_local_routed_read_budget(app) {
        Ok(budget) => budget,
        Err(response) => return response,
    };
    budget
        .json_response(&source)
        .unwrap_or_else(|response| response)
}
struct ToriiExplorerAssetDefinitionJsonSource<'a> {
    definition: &'a iroha_data_model::asset::definition::AssetDefinition,
    owning_dataspace: Option<DataSpaceId>,
    assets: u32,
    locked_quantity: Option<&'a iroha_primitives::numeric::Quantity>,
    circulating_quantity: Option<&'a iroha_primitives::numeric::Quantity>,
}
impl norito::json::FastJsonWrite for ToriiExplorerAssetDefinitionJsonSource<'_> {
    fn write_json(&self, output: &mut String) {
        norito::json::write_json_unbounded(self, output);
    }
    fn write_json_to(
        &self,
        output: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        use norito::json::JsonSerialize as _;
        output.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            output.push_str("{\"id\":")?;
            self.definition.id.json_serialize_to(output)?;
            output.push_str(",\"owning_domain\":")?;
            self.definition.owning_domain.json_serialize_to(output)?;
            output.push_str(",\"owning_dataspace\":")?;
            write_torii_definition_dataspace_json(self.owning_dataspace, output)?;
            output.push_str(",\"mintable\":")?;
            self.definition.mintable.json_serialize_to(output)?;
            output.push_str(",\"logo\":")?;
            self.definition.logo.json_serialize_to(output)?;
            output.push_str(",\"metadata\":")?;
            iroha_data_model::HasMetadata::metadata(self.definition).json_serialize_to(output)?;
            output.push_str(",\"owned_by\":")?;
            self.definition.owned_by.json_serialize_to(output)?;
            output.push_str(",\"assets\":")?;
            self.assets.json_serialize_to(output)?;
            output.push_str(",\"total_quantity\":")?;
            self.definition.total_quantity.json_serialize_to(output)?;
            output.push_str(",\"locked_quantity\":")?;
            self.locked_quantity.json_serialize_to(output)?;
            output.push_str(",\"circulating_quantity\":")?;
            self.circulating_quantity.json_serialize_to(output)?;
            output.push('}')?;
            Ok(())
        })();
        output.end_container();
        result?;
        Ok(())
    }
}
fn execute_torii_explorer_asset_definition_local_source_read(
    app: &SharedAppState,
    definition_id: &iroha_data_model::asset::AssetDefinitionId,
    visibility: &routing::DataspaceReadVisibility,
) -> Response {
    with_query_fanout_source_owner(app, || {
        execute_torii_explorer_asset_definition_local_source_read_admitted(
            app,
            definition_id,
            visibility,
        )
    })
}
fn execute_torii_explorer_asset_definition_local_source_read_admitted(
    app: &SharedAppState,
    definition_id: &iroha_data_model::asset::AssetDefinitionId,
    visibility: &routing::DataspaceReadVisibility,
) -> Response {
    let world = app.state.world_view();
    if !visibility.allows_asset_definition(&world, definition_id) {
        return error_response_with_format(routing::explorer_not_found(), ResponseFormat::Json);
    }
    let Some(definition) = world.asset_definitions().get(definition_id) else {
        return error_response_with_format(
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::NotFound,
            )),
            ResponseFormat::Json,
        );
    };
    let assets = world
        .asset_definition_assets()
        .get(definition_id)
        .map_or(0, |assets| {
            u32::try_from(
                assets
                    .iter()
                    .filter(|asset_id| visibility.allows_asset(&world, asset_id))
                    .count(),
            )
            .unwrap_or(u32::MAX)
        });
    let zero_locked_quantity = iroha_primitives::numeric::Quantity::zero();
    let mut locked_quantity = None;
    let mut circulating_quantity = None;
    if definition_id == &app.state.gov.voting_asset_id {
        let locked = world
            .assets_iter()
            .find(|entry| {
                entry.id().definition() == definition_id
                    && entry.id().account() == &app.state.gov.bond_escrow_account
                    && entry.id().scope() == &iroha_data_model::asset::AssetBalanceScope::Global
            })
            .map_or(&zero_locked_quantity, |entry| entry.value.as_ref());
        let circulating = match definition.total_quantity.checked_sub(locked) {
            Ok(circulating) => circulating,
            Err(error) => {
                return error_response_with_format(
                    Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                        iroha_data_model::query::error::QueryExecutionFail::Conversion(format!(
                            "governance locked quantity exceeds total issuance: {error}"
                        )),
                    )),
                    ResponseFormat::Json,
                );
            }
        };
        locked_quantity = Some(locked);
        circulating_quantity = Some(circulating);
    }
    let source = ToriiExplorerAssetDefinitionJsonSource {
        definition,
        owning_dataspace: match routing::asset_definition_dataspace_for_read(&world, definition_id)
        {
            Ok(home) => home,
            Err(error) => return error_response_with_format(error, ResponseFormat::Json),
        },
        assets,
        locked_quantity,
        circulating_quantity: circulating_quantity.as_ref(),
    };
    let budget = match torii_local_routed_read_budget(app) {
        Ok(budget) => budget,
        Err(response) => return response,
    };
    budget
        .json_response(&source)
        .unwrap_or_else(|response| response)
}
fn torii_bounded_local_proof_record_payload(
    app: &SharedAppState,
    proof_id: &iroha_data_model::proof::ProofId,
    budget: &mut ToriiRoutedReadMemoryBudget,
) -> Result<Option<ToriiBoundedNoritoPayload<ProofRecord>>, Response> {
    let state_view = app.state.query_view();
    let Some(record) = state_view.world().proofs().get(proof_id) else {
        return Ok(None);
    };
    torii_bounded_routed_read_source_payload::<ProofRecord, _>(record, budget).map(Some)
}
fn execute_torii_proof_record_local_source_read(
    app: &SharedAppState,
    proof_id: &iroha_data_model::proof::ProofId,
    format: ResponseFormat,
) -> Response {
    with_query_fanout_source_owner(app, || {
        execute_torii_proof_record_local_source_read_admitted(app, proof_id, format)
    })
}
fn execute_torii_proof_record_local_source_read_admitted(
    app: &SharedAppState,
    proof_id: &iroha_data_model::proof::ProofId,
    format: ResponseFormat,
) -> Response {
    let mut budget = match torii_local_routed_read_budget(app) {
        Ok(budget) => budget,
        Err(response) => return response,
    };
    let payload = match torii_bounded_local_proof_record_payload(app, proof_id, &mut budget) {
        Ok(Some(payload)) => payload,
        Ok(None) => {
            return torii_proxy_error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "the requested proof record was not found on this route",
            );
        }
        Err(response) => return response,
    };
    torii_bounded_routed_read_payload_response(payload, format, budget)
        .unwrap_or_else(|response| response)
}
#[cfg(test)]
include!("tests/lib_routed_reads/routed_read_source_bounds.rs");

#[cfg(test)]
mod service_source_depth_tests {
    //! Owning checked service writers keep the caller depth on exact refusals.
    use super::*;
    use crate::service_checked_writer_test_support::audit;
    use norito::json::FastJsonWrite;

    use iroha_data_model::Registrable as _;
    use norito::json::Value;
    fn definition() -> iroha_data_model::asset::definition::AssetDefinition {
        let authority = crate::tests_runtime_handlers::checked_torii_test_account_id(
            0x71,
            "checked service source fixture",
        );
        let domain = iroha_model_base::domain::DomainId::try_new("issuer", "universal").unwrap();
        let id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            domain,
            "usd".parse().unwrap(),
        );
        iroha_data_model::asset::AssetDefinition::numeric(
            id,
            "Treasury USD",
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&authority)
    }
    fn binding() -> iroha_core::state::AssetDefinitionAliasBindingRecord {
        iroha_core::state::AssetDefinitionAliasBindingRecord {
            alias: "usd#issuer.main".parse().unwrap(),
            lease_expiry_ms: Some(50),
            grace_until_ms: Some(75),
            bound_at_ms: 10,
        }
    }
    fn configured_policy() -> iroha_data_model::asset::definition::AssetConfidentialPolicy {
        use iroha_data_model::asset::definition::{
            AssetConfidentialPolicy, ConfidentialPolicyMode, ConfidentialPolicyTransition,
        };
        AssetConfidentialPolicy {
            mode: ConfidentialPolicyMode::Convertible,
            vk_set_hash: Some(iroha_crypto::Hash::new(b"checked keys")),
            poseidon_params_id: Some(3),
            pedersen_params_id: Some(5),
            pending_transition: Some(ConfidentialPolicyTransition {
                new_mode: ConfidentialPolicyMode::ShieldedOnly,
                effective_height: 80,
                previous_mode: ConfidentialPolicyMode::Convertible,
                transition_id: iroha_crypto::Hash::new(b"checked transition"),
                conversion_window: Some(20),
            }),
        }
    }
    #[test]
    fn original_asset_definition_projection_keeps_original_record_and_refusal_depth() {
        let mut definition = definition();
        definition.confidential_policy = configured_policy();
        let binding = binding();
        for alias_binding in [None, Some(&binding)] {
            let source = ToriiAssetDefinitionJsonSource {
                definition: &definition,
                owning_dataspace: None,
                alias_binding,
                observation_time_ms: 60,
            };
            let mut expected = norito::json::to_value(&definition).unwrap();
            if let Value::Object(object) = &mut expected {
                object.insert("owning_dataspace".into(), Value::Null);
            }
            if let Some(binding) = alias_binding {
                let Value::Object(object) = &mut expected else {
                    panic!("original definition object");
                };
                object.insert("alias".into(), Value::from(binding.alias.to_string()));
                object.insert(
                    "alias_binding".into(),
                    norito::json::to_value(&routing::asset_alias_binding_dto(binding, 60)).unwrap(),
                );
            }
            let expected = norito::json::to_json(&expected).unwrap();
            audit(&expected, |sink| source.write_json_to(sink));
            assert!(std::ptr::eq(source.definition, &definition));
        }
    }
    #[test]
    fn original_confidential_projection_keeps_nested_transition_refusal_depth() {
        for policy in [
            iroha_data_model::asset::definition::AssetConfidentialPolicy::default(),
            configured_policy(),
        ] {
            let expected =
                norito::json::to_json(&norito::json::to_value(&policy).unwrap()).unwrap();
            audit(&expected, |sink| {
                write_torii_asset_confidential_policy_json(&policy, sink)
            });
        }
    }
    #[test]
    fn original_asset_alias_projection_keeps_actual_lease_status_and_refusal_depth() {
        let binding = binding();
        for observed in [10, 60, 76] {
            let expected =
                norito::json::to_json(&routing::asset_alias_binding_dto(&binding, observed))
                    .unwrap();
            audit(&expected, |sink| {
                write_torii_asset_alias_binding_json(&binding, observed, sink)
            });
        }
    }
    #[test]
    fn original_space_directory_projection_keeps_actual_bindings_and_nested_refusal_depth() {
        let uaid = "uaid:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            .parse()
            .unwrap();
        let mut bindings = iroha_core::nexus::space_directory::UaidDataspaceBindings::default();
        let account = crate::tests_runtime_handlers::checked_torii_test_account_id(
            0x71,
            "checked binding fixture",
        );
        let original_account_json = norito::json::to_value(&account).unwrap();
        let ds = iroha_model_base::topology::DataSpaceId::UNIVERSAL;
        bindings.bind_account(ds, account);
        let catalog = iroha_data_model::nexus::DataSpaceCatalog::default();
        let visibility = routing::DataspaceReadVisibility::all_for_tests();
        for bindings in [None, Some(&bindings)] {
            let source = ToriiSpaceDirectoryBindingsJsonSource {
                uaid: &uaid,
                bindings,
                catalog: &catalog,
                visibility: &visibility,
            };
            let expected_value = if bindings.is_some() {
                let alias = catalog
                    .entries()
                    .iter()
                    .find(|entry| entry.id == ds)
                    .map(|entry| entry.alias.as_str());
                norito::json!({ "dataspaces": [{ "accounts": (vec![original_account_json.clone()]), "dataspace_alias": (alias), "dataspace_id": (ds.as_u64()) }], "uaid": (uaid.to_string()) })
            } else {
                norito::json!({ "dataspaces": [], "uaid": (uaid.to_string()) })
            };
            let expected = norito::json::to_json(&expected_value).unwrap();
            audit(&expected, |sink| source.write_json_to(sink));
        }
    }
    fn contract() -> (
        iroha_data_model::smart_contract::ContractAddress,
        iroha_data_model::smart_contract::ContractAlias,
        iroha_core::state::ContractAliasBindingRecord,
    ) {
        let authority = crate::tests_runtime_handlers::checked_torii_test_account_id(
            0x72,
            "checked contract source fixture",
        );
        let address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .unwrap(),
            &authority,
            0,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .unwrap();
        let alias = "router::dex.universal"
            .parse::<iroha_data_model::smart_contract::ContractAlias>()
            .unwrap();
        let binding = iroha_core::state::ContractAliasBindingRecord {
            alias: alias.clone(),
            lease_expiry_ms: Some(50),
            grace_until_ms: Some(75),
            bound_at_ms: 10,
        };
        (address, alias, binding)
    }
    #[test]
    fn original_contract_alias_projection_keeps_actual_subject_and_refusal_depth() {
        let (address, alias, binding) = contract();
        let subject = address.subject_id();
        let source = ToriiContractAliasJsonSource {
            contract_alias: &alias,
            contract_address: &address,
            contract_subject: &subject,
            dataspace_alias: "universal",
            binding: &binding,
            observation_time_ms: 60,
        };
        let expected = routing::ContractAliasResolveResponseDto {
            contract_alias: alias.to_string(),
            contract_address: address.to_string(),
            contract_subject_account: subject.to_string(),
            dataspace: "universal".into(),
            contract_alias_binding: routing::contract_alias_binding_dto(&binding, 60),
            source: "world_state".into(),
        };
        let expected = norito::json::to_json(&expected).unwrap();
        audit(&expected, |sink| source.write_json_to(sink));
    }
    #[test]
    fn original_contract_binding_projection_keeps_lease_status_and_refusal_depth() {
        let (_, _, binding) = contract();
        for observed in [10, 60, 76] {
            let expected =
                norito::json::to_json(&routing::contract_alias_binding_dto(&binding, observed))
                    .unwrap();
            audit(&expected, |sink| {
                write_torii_contract_alias_binding_json(&binding, observed, sink)
            });
        }
    }
    #[test]
    fn direct_definition_projection_preserves_exact_home_and_bounded_refusals() {
        let definition = definition();
        let home = DataSpaceId::new(8_648_377_547_929_788_715);
        let source = ToriiAssetDefinitionJsonSource {
            definition: &definition,
            owning_dataspace: Some(home),
            alias_binding: None,
            observation_time_ms: 60,
        };
        let mut expected = norito::json::to_value(&definition).unwrap();
        let Value::Object(object) = &mut expected else {
            panic!("definition object");
        };
        object.insert(
            "owning_dataspace".into(),
            Value::from("8648377547929788715"),
        );
        let expected = norito::json::to_json(&expected).unwrap();
        audit(&expected, |sink| source.write_json_to(sink));
        let explorer_source = ToriiExplorerAssetDefinitionJsonSource {
            definition: &definition,
            owning_dataspace: Some(home),
            assets: 7,
            locked_quantity: None,
            circulating_quantity: None,
        };
        let expected =
            crate::explorer::ExplorerAssetDefinitionDto::from_definition_with_asset_count(
                &definition,
                7,
                Some(home),
            );
        let expected = norito::json::to_json(&expected).unwrap();
        audit(&expected, |sink| explorer_source.write_json_to(sink));
    }
    #[test]
    fn original_explorer_definition_projection_keeps_actual_owner_and_refusal_depth() {
        let definition = definition();
        let source = ToriiExplorerAssetDefinitionJsonSource {
            definition: &definition,
            owning_dataspace: None,
            assets: 7,
            locked_quantity: None,
            circulating_quantity: None,
        };
        let expected =
            crate::explorer::ExplorerAssetDefinitionDto::from_definition_with_asset_count(
                &definition,
                7,
                None,
            );
        let expected = norito::json::to_json(&expected).unwrap();
        audit(&expected, |sink| source.write_json_to(sink));
    }
}
