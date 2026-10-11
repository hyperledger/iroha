//! Row producers behind the collection engine ([`crate::collections`]).
//!
//! Each collection turns this node's state into JSON rows whose fields match
//! its [`CollectionSpec`]; the engine then filters, orders and pages them.
//! Execution here returns full rows: projection happens before returning the page.
use super::*;
use crate::collections::{self, CollectionError, CollectionSpec, Limits, RowPage, specs};
use iroha_torii_shared::list_query::ListQuery;

/// A collection addressed by a request path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CollectionTarget {
    /// `/v1/domains`
    Domains,
    /// `/v1/accounts`
    Accounts,
    /// `/v1/assets/definitions`
    AssetDefinitions,
    /// `/v1/nfts`
    Nfts,
    /// `/v1/rwas`
    Rwas,
    /// `/v1/accounts/{account_id}/assets` (path literal: I105 id or alias)
    AccountAssets(String),
    /// `/v1/assets/{definition_id}/holders` (path literal: id or alias)
    AssetHolders(String),
    /// `/v1/accounts/{account_id}/transactions` (path literal: I105 id or alias)
    AccountTransactions(String),
    /// `/v1/accounts/{account_id}/history`
    AccountHistory(String),
    /// `/v1/transactions/query`
    Transactions,
    /// `/v1/contracts/activity`
    ContractActivity,
    /// `/v1/contracts/events`
    ContractEvents,
    /// `/v1/repo/agreements`
    RepoAgreements,
    /// `/v1/accounts/{account_id}/permissions`
    AccountPermissions(String),
    /// `/v1/subscriptions/plans`
    SubscriptionPlans,
    /// `/v1/subscriptions`
    Subscriptions,
    /// `/v1/space-directory/uaids/{uaid}/manifests`
    UaidManifests(String),
}

impl CollectionTarget {
    /// The collection's query surface.
    pub(crate) fn spec(&self) -> &'static CollectionSpec {
        match self {
            Self::Domains => &specs::DOMAINS,
            Self::Accounts => &specs::ACCOUNTS,
            Self::AssetDefinitions => &specs::ASSET_DEFINITIONS,
            Self::Nfts => &specs::NFTS,
            Self::Rwas => &specs::RWAS,
            Self::AccountAssets(_) => &specs::ACCOUNT_ASSETS,
            Self::AssetHolders(_) => &specs::ASSET_HOLDERS,
            Self::AccountTransactions(_) => &specs::ACCOUNT_TRANSACTIONS,
            Self::AccountHistory(_) => &specs::ACCOUNT_HISTORY,
            Self::Transactions => &specs::TRANSACTIONS,
            Self::ContractActivity => &specs::CONTRACT_ACTIVITY,
            Self::ContractEvents => &specs::CONTRACT_EVENTS,
            Self::RepoAgreements => &specs::REPO_AGREEMENTS,
            Self::AccountPermissions(_) => &specs::ACCOUNT_PERMISSIONS,
            Self::SubscriptionPlans => &specs::SUBSCRIPTION_PLANS,
            Self::Subscriptions => &specs::SUBSCRIPTIONS,
            Self::UaidManifests(_) => &specs::UAID_MANIFESTS,
        }
    }

    /// The path argument scoping the collection (empty for top-level
    /// collections); cursors are bound to it.
    pub(crate) fn scope(&self) -> &str {
        match self {
            Self::AccountAssets(literal)
            | Self::AssetHolders(literal)
            | Self::AccountTransactions(literal)
            | Self::AccountHistory(literal)
            | Self::AccountPermissions(literal)
            | Self::UaidManifests(literal) => literal,
            Self::Domains
            | Self::Accounts
            | Self::AssetDefinitions
            | Self::Nfts
            | Self::Rwas
            | Self::Transactions
            | Self::ContractActivity
            | Self::ContractEvents
            | Self::RepoAgreements
            | Self::SubscriptionPlans
            | Self::Subscriptions => "",
        }
    }

    /// Endpoint label used for telemetry and literal diagnostics.
    pub(crate) const fn endpoint(&self) -> &'static str {
        match self {
            Self::Domains => ENDPOINT_DOMAINS_QUERY,
            Self::Accounts => ENDPOINT_ACCOUNTS_QUERY,
            Self::AssetDefinitions => ENDPOINT_ASSET_DEFINITIONS_QUERY,
            Self::Nfts => ENDPOINT_NFTS_QUERY,
            Self::Rwas => ENDPOINT_RWAS_QUERY,
            Self::AccountAssets(_) => ENDPOINT_ACCOUNTS_ASSETS_QUERY,
            Self::AssetHolders(_) => ENDPOINT_ASSET_HOLDERS_QUERY,
            Self::AccountTransactions(_) => ENDPOINT_ACCOUNTS_TRANSACTIONS_QUERY,
            Self::AccountHistory(_) => ENDPOINT_ACCOUNTS_HISTORY,
            Self::Transactions => ENDPOINT_TRANSACTIONS_QUERY,
            Self::ContractActivity => ENDPOINT_CONTRACTS_ACTIVITY,
            Self::ContractEvents => ENDPOINT_CONTRACTS_EVENTS,
            Self::RepoAgreements => ENDPOINT_REPO_AGREEMENTS_QUERY,
            Self::AccountPermissions(_) => ENDPOINT_ACCOUNTS_PERMISSIONS,
            Self::SubscriptionPlans => ENDPOINT_SUBSCRIPTION_PLANS_LIST,
            Self::Subscriptions => ENDPOINT_SUBSCRIPTIONS_LIST,
            Self::UaidManifests(_) => ENDPOINT_SPACE_DIRECTORY_MANIFESTS,
        }
    }
}

/// Engine bounds derived from the configured app-API page limits.
pub(crate) fn collection_limits() -> Limits {
    let limits = app_query_limits();
    Limits::from_page_limits(limits.default_page_limit, limits.max_page_limit)
}

pub(crate) fn collection_execution_limits(app: Option<&crate::SharedAppState>) -> Result<Limits> {
    let mut limits = collection_limits();
    if let Some(app) = app {
        limits.bytes = collections::memory::BytePolicy::for_admitted_read(
            crate::current_routed_read_memory_envelope(app)
                .map_err(|_| collections::memory::capacity("working set"))?,
            app.torii_proxy_max_response_bytes,
        );
    }
    Ok(limits)
}

/// Storage entries in canonical key order strictly after `after` (strictly
/// before it when `descending`): the seek behind identity-ordered pages.
fn seek_entries<'a, K, V, S>(
    storage: &'a S,
    after: Option<&K>,
    descending: bool,
) -> Box<dyn Iterator<Item = (&'a K, &'a V)> + 'a>
where
    K: mv::Key,
    V: mv::Value,
    S: mv::storage::StorageReadOnly<K, V>,
{
    use std::ops::Bound::{Excluded, Unbounded};
    match (after, descending) {
        (None, false) => Box::new(storage.iter()),
        (None, true) => Box::new(storage.iter().rev()),
        (Some(after), false) => Box::new(storage.range::<K>((Excluded(after), Unbounded))),
        (Some(after), true) => Box::new(storage.range::<K>((Unbounded, Excluded(after))).rev()),
    }
}

/// [`seek_entries`] restricted to exact-`id` candidates from the filter, so a
/// point lookup reads only its keys.
fn seek_keys<'a, K, V, S>(
    storage: &'a S,
    candidates: Option<BTreeSet<K>>,
    after: Option<&'a K>,
    descending: bool,
) -> Box<dyn Iterator<Item = (&'a K, &'a V)> + 'a>
where
    K: mv::Key,
    V: mv::Value,
    S: mv::storage::StorageReadOnly<K, V>,
{
    let Some(candidates) = candidates else {
        return seek_entries(storage, after, descending);
    };
    if descending {
        Box::new(
            candidates
                .into_iter()
                .rev()
                .filter(move |key| after.is_none_or(|after| key < after))
                .filter_map(move |key| storage.get_key_value(&key)),
        )
    } else {
        Box::new(
            candidates
                .into_iter()
                .filter(move |key| after.is_none_or(|after| key > after))
                .filter_map(move |key| storage.get_key_value(&key)),
        )
    }
}

/// Whether a storage key follows the cursor in the requested order. Totals
/// scan earlier entries too, but only later entries can appear in the page.
fn entry_after_cursor<K: Ord>(key: &K, after: Option<&K>, descending: bool) -> bool {
    after.is_none_or(|after| if descending { key < after } else { key > after })
}

/// The typed key of an identity-ordered cursor.
fn cursor_key<K>(after: Option<&str>, parse: impl Fn(&str) -> Option<K>) -> Result<Option<K>> {
    after
        .map(|id| {
            parse(id).ok_or_else(|| {
                Error::from(CollectionError::new(
                    "invalid_cursor",
                    "cursor",
                    "`cursor` is not a `next_cursor` value returned by this endpoint",
                ))
            })
        })
        .transpose()
}

/// Exact `id` literals of the filter as typed keys.
fn id_candidates<K: Ord>(
    query: &ListQuery,
    parse: impl Fn(&str) -> Option<K>,
) -> Option<BTreeSet<K>> {
    exact_field_filter_candidates(query.filter.as_ref(), "id", &|value: &Value| {
        value.as_str().and_then(&parse)
    })
}

/// Feed fallible rows to the engine, keeping the first error.
fn until_error<'a, T: 'a, I>(
    rows: I,
    failure: &'a mut Option<Error>,
) -> impl Iterator<Item = T> + 'a
where
    I: Iterator<Item = Result<T>> + 'a,
{
    rows.map_while(move |row| match row {
        Ok(row) => Some(row),
        Err(error) => {
            *failure = Some(error);
            None
        }
    })
}

/// Rewrite account literals in the filter (aliases, alternate spellings) to
/// the canonical identifiers the rows carry.
pub(crate) fn canonicalize_collection_query(
    state: &CoreState,
    target: &CollectionTarget,
    query: &mut ListQuery,
    telemetry: &MaybeTelemetry,
) -> Result<()> {
    let spec = target.spec();
    let Some(filter) = query.filter.as_mut() else {
        return Ok(());
    };
    record_account_literal_selection(telemetry, target.endpoint());
    for field in spec.account_fields() {
        canonicalize_filter_account_literals(
            filter,
            field,
            Some(state),
            telemetry,
            target.endpoint(),
        )
        .map_err(|err| {
            Error::from(
                CollectionError::new("invalid_filter", "filter", err.to_string())
                    .with_actual(field),
            )
        })?;
    }
    Ok(())
}

/// Validate and execute `query` against this node's state, returning full rows.
pub(crate) async fn execute_collection_local(
    app: Option<&crate::SharedAppState>,
    state: &Arc<CoreState>,
    target: &CollectionTarget,
    mut query: ListQuery,
    telemetry: &MaybeTelemetry,
    visibility: &DataspaceReadVisibility,
) -> Result<RowPage> {
    canonicalize_collection_query(state, target, &mut query, telemetry)?;
    let limits = collection_execution_limits(app)?;
    let prepared = collections::prepare(target.spec(), target.scope(), &query, &limits)?;
    execute_prepared_collection_local(
        app, state, target, &query, telemetry, visibility, &prepared, &limits,
    )
    .await
}

/// Execute the one admitted plan without cloning its query or preparing again.
async fn execute_prepared_collection_local(
    app: Option<&crate::SharedAppState>,
    state: &Arc<CoreState>,
    target: &CollectionTarget,
    query: &ListQuery,
    telemetry: &MaybeTelemetry,
    visibility: &DataspaceReadVisibility,
    prepared: &collections::Prepared<'_>,
    limits: &Limits,
) -> Result<RowPage> {
    // Source helpers can allocate display/key scratch while the plan remains
    // alive. They must use its remaining phase, just like the engine does.
    let mut runtime_limits = *limits;
    runtime_limits.bytes = prepared.runtime_bytes();
    let limits = &runtime_limits;
    let page = match target {
        // Identity-ordered reads seek in storage order from the cursor; exact
        // `id` (and alias) constraints become direct lookups. The engine still
        // applies the whole filter.
        CollectionTarget::Domains => {
            let world = state.world_view();
            let scan = prepared.ordered_scan();
            let after = cursor_key(scan.and_then(|scan| scan.after), |id| {
                DomainId::parse_fully_qualified(id).ok()
            })?;
            let candidates = id_candidates(&query, |id| DomainId::parse_fully_qualified(id).ok());
            let rows = seek_keys(
                world.domains(),
                candidates,
                after.as_ref().filter(|_| !query.include_total),
                scan.is_some_and(|scan| scan.descending),
            )
            .map(|(id, domain)| {
                Ok((
                    entry_after_cursor(
                        id,
                        after.as_ref(),
                        scan.is_some_and(|scan| scan.descending),
                    ),
                    visibility
                        .allows_domain(&world, id)
                        .then(|| domain_row(domain, limits.bytes))
                        .transpose()?,
                ))
            });
            let mut failure = None;
            let rows = until_error(rows, &mut failure);
            let page = if scan.is_some() {
                prepared.execute_ordered(rows, &limits)
            } else {
                prepared.execute_entries(rows.map(|(_, row)| row), &limits)
            };
            if let Some(error) = failure {
                return Err(error);
            }
            page
        }
        CollectionTarget::Accounts => {
            let world = state.world_view();
            let scan = prepared.ordered_scan();
            let after = cursor_key(scan.and_then(|scan| scan.after), |id| {
                AccountId::parse_encoded(id).ok()
            })?;
            let candidates = id_candidates(&query, |id| AccountId::parse_encoded(id).ok());
            let rows = seek_keys(
                world.accounts(),
                candidates,
                after.as_ref().filter(|_| !query.include_total),
                scan.is_some_and(|scan| scan.descending),
            )
            .map(|(id, value)| {
                Ok((
                    entry_after_cursor(
                        id,
                        after.as_ref(),
                        scan.is_some_and(|scan| scan.descending),
                    ),
                    visibility
                        .allows_account(&world, id)
                        .then(|| account_row(id, value.as_ref(), limits.bytes))
                        .transpose()?,
                ))
            });
            let mut failure = None;
            let rows = until_error(rows, &mut failure);
            let page = if scan.is_some() {
                prepared.execute_ordered(rows, &limits)
            } else {
                prepared.execute_entries(rows.map(|(_, row)| row), &limits)
            };
            if let Some(error) = failure {
                return Err(error);
            }
            page
        }
        CollectionTarget::AssetDefinitions => {
            let world = state.world_view();
            let now_ms = asset_alias_observation_time_ms(state);
            let world_ref = &world;
            let scan = prepared.ordered_scan();
            let after = cursor_key(scan.and_then(|scan| scan.after), |id| {
                AssetDefinitionId::parse_address_literal(id).ok()
            })?;
            let candidates =
                asset_definition_filter_candidate_ids(world_ref, query.filter.as_ref());
            let rows = seek_keys(
                world_ref.asset_definitions(),
                candidates,
                after.as_ref().filter(|_| !query.include_total),
                scan.is_some_and(|scan| scan.descending),
            )
            .map(|(id, _)| {
                let after_cursor = entry_after_cursor(
                    id,
                    after.as_ref(),
                    scan.is_some_and(|scan| scan.descending),
                );
                if !visibility.allows_asset_definition(world_ref, id) {
                    return Ok((after_cursor, None));
                }
                let Some(definition) = world_ref.asset_definition(id).ok() else {
                    return Ok((after_cursor, None));
                };
                let binding =
                    asset_definition_alias_binding_for(world_ref, definition.id(), now_ms);
                asset_definition_to_json_value(
                    &definition,
                    binding.as_ref(),
                    asset_definition_dataspace_for_read(world_ref, definition.id())?,
                )
                .and_then(object_row_from_value)
                .map(|row| (after_cursor, Some(row)))
            });
            let mut failure = None;
            let rows = until_error(rows, &mut failure);
            let page = if scan.is_some() {
                prepared.execute_ordered(rows, &limits)
            } else {
                prepared.execute_entries(rows.map(|(_, row)| row), &limits)
            };
            if let Some(error) = failure {
                return Err(error);
            }
            page
        }
        CollectionTarget::Nfts => {
            let world = state.world_view();
            let world_ref = &world;
            let scan = prepared.ordered_scan();
            let after = cursor_key(scan.and_then(|scan| scan.after), |id| {
                id.parse::<NftId>().ok()
            })?;
            let rows = seek_keys(
                world_ref.nfts(),
                nft_filter_candidate_ids(query.filter.as_ref()),
                after.as_ref().filter(|_| !query.include_total),
                scan.is_some_and(|scan| scan.descending),
            )
            .map(|(id, value)| {
                Ok((
                    entry_after_cursor(
                        id,
                        after.as_ref(),
                        scan.is_some_and(|scan| scan.descending),
                    ),
                    visibility
                        .allows_nft(world_ref, id)
                        .then(|| nft_row(id, value.as_ref(), limits.bytes))
                        .transpose()?,
                ))
            });
            let mut failure = None;
            let rows = until_error(rows, &mut failure);
            let page = if scan.is_some() {
                prepared.execute_ordered(rows, &limits)
            } else {
                prepared.execute_entries(rows.map(|(_, row)| row), &limits)
            };
            if let Some(error) = failure {
                return Err(error);
            }
            page
        }
        CollectionTarget::Rwas => {
            let world = state.world_view();
            let scan = prepared.ordered_scan();
            let parse = |id: &str| id.parse::<iroha_data_model::rwa::RwaId>().ok();
            let after = cursor_key(scan.and_then(|scan| scan.after), parse)?;
            let rows = seek_keys(
                world.rwas(),
                id_candidates(&query, parse),
                after.as_ref().filter(|_| !query.include_total),
                scan.is_some_and(|scan| scan.descending),
            )
            .map(|(id, value)| {
                (
                    entry_after_cursor(
                        id,
                        after.as_ref(),
                        scan.is_some_and(|scan| scan.descending),
                    ),
                    visibility.allows_rwa(&world, id).then(|| {
                        dto_row(&crate::explorer::ExplorerRwaDto::from_entry(
                            iroha_data_model::rwa::RwaEntry::new(id, value),
                        ))
                    }),
                )
            });
            if scan.is_some() {
                prepared.execute_ordered(rows, &limits)
            } else {
                prepared.execute_entries(rows.map(|(_, row)| row), &limits)
            }
        }
        CollectionTarget::AccountAssets(account_literal) => {
            let (account, _) = parse_account_path_segment_with_state(
                state.as_ref(),
                account_literal,
                telemetry,
                ENDPOINT_ACCOUNTS_ASSETS_QUERY,
            )?;
            let world = state.world_view();
            let scoped_accounts = visibility.exact_account_id().map_or_else(
                || scoped_accounts_for_subject_sorted(&world, &account),
                |exact| vec![exact.clone()],
            );
            let items = projected_account_assets(&world, &scoped_accounts, None, None, visibility);
            prepared.execute_entries(
                items.map(|item| item.map(|item| account_asset_row(&item))),
                &limits,
            )
        }
        CollectionTarget::AssetHolders(definition_literal) => {
            let now_ms = asset_alias_observation_time_ms(state);
            let (definition, asset_alias) = {
                let world = state.world_view();
                let definition =
                    resolve_asset_definition_selector(&world, definition_literal, now_ms)?;
                if !visibility.allows_asset_definition(&world, &definition) {
                    return Err(explorer_not_found());
                }
                let alias = world
                    .asset_definition(&definition)
                    .ok()
                    .and_then(|record| record.alias().as_ref().map(ToString::to_string));
                (definition, alias)
            };
            if query.aggregate.is_some() {
                // Aggregates over every holder of a popular asset run on the
                // published query projection; only unit tests scan live state.
                if let Some((rows, _snapshot, _source)) = asset_holder_projection_query_rows(
                    app,
                    state.as_ref(),
                    &definition,
                    asset_alias.as_ref(),
                    None,
                    visibility,
                )
                .await?
                {
                    return prepared.execute(rows, &limits).map_err(Error::from);
                }
                if !asset_holder_live_aggregate_enabled() {
                    return Err(projection_archive_unavailable_error(
                        "asset holder aggregates require a complete published query projection archive; live holder scans are disabled",
                    ));
                }
            }
            let world = state.world_view();
            let asset_literal = definition.to_string();
            let rows = world
                .asset_entries_by_definition_iter(&definition)
                .map(|entry| {
                    visibility.allows_asset(&world, entry.id()).then(|| {
                        asset_holder_row(&live_asset_holder_item(
                            entry.id(),
                            entry.value().as_ref(),
                            &asset_literal,
                            asset_alias.as_ref(),
                        ))
                    })
                });
            prepared.execute_entries(rows, &limits)
        }
        CollectionTarget::AccountTransactions(account_literal) => {
            let (account, _) = parse_account_path_segment_with_state(
                state.as_ref(),
                account_literal,
                telemetry,
                ENDPOINT_ACCOUNTS_TRANSACTIONS_QUERY,
            )?;
            if !visibility.allows_account(&state.world_view(), &account) {
                return prepared
                    .positioned_page(Vec::new(), None)
                    .map_err(Into::into);
            }
            let allowed = app
                .map(|app| crate::resolve_tx_history_allowed_asset_definition_id(app))
                .transpose()?
                .flatten();
            return transaction_page(
                state,
                &prepared,
                Some(&account),
                allowed.as_ref(),
                visibility,
                |transaction, position| Some(transaction_row(transaction, position)),
            );
        }
        CollectionTarget::Transactions => {
            let allowed = app
                .map(|app| crate::resolve_tx_history_allowed_asset_definition_id(app))
                .transpose()?
                .flatten();
            return transaction_page(
                state,
                &prepared,
                None,
                allowed.as_ref(),
                visibility,
                |transaction, position| Some(transaction_row(transaction, position)),
            );
        }
        CollectionTarget::AccountPermissions(account_literal) => {
            let (account, _) = parse_account_path_segment_with_state(
                state,
                account_literal,
                telemetry,
                target.endpoint(),
            )?;
            let world = state.world_view();
            let permissions = if visibility.allows_account(&world, &account) {
                collect_effective_account_permissions(&world, &account, limits.max_scanned_rows)?
            } else {
                BTreeSet::new()
            };
            let rows = permissions.iter().map(|permission| {
                let payload = norito::json::from_str::<Value>(permission.payload().get()).map_err(
                    |error| conversion_error(format!("invalid permission payload: {error}")),
                )?;
                Ok(Map::from_iter([
                    ("name".to_owned(), Value::from(permission.name().to_owned())),
                    ("payload".to_owned(), payload),
                ]))
            });
            let mut failure = None;
            let page = prepared.execute(until_error(rows, &mut failure), &limits);
            if let Some(error) = failure {
                return Err(error);
            }
            page
        }
        CollectionTarget::SubscriptionPlans => {
            let world = state.world_view();
            let scan = prepared.ordered_scan();
            let after = cursor_key(scan.and_then(|scan| scan.after), |id| {
                AssetDefinitionId::parse_address_literal(id).ok()
            })?;
            let descending = scan.is_some_and(|scan| scan.descending);
            let mut failure = None;
            let rows = seek_keys(
                world.asset_definitions(),
                id_candidates(&query, |id| {
                    AssetDefinitionId::parse_address_literal(id).ok()
                }),
                after.as_ref().filter(|_| !query.include_total),
                descending,
            )
            .map_while(|(id, definition)| {
                let row = if visibility.allows_asset_definition(&world, id) {
                    subscription_plan_from_metadata(definition.metadata()).map(|plan| {
                        plan.map(|plan| {
                            let mut row = dto_row(&plan);
                            row.insert("id".to_owned(), Value::from(id.to_string()));
                            row
                        })
                    })
                } else {
                    Ok(None)
                };
                match row {
                    Ok(row) => Some((entry_after_cursor(id, after.as_ref(), descending), row)),
                    Err(error) => {
                        failure = Some(error);
                        None
                    }
                }
            });
            let page = if scan.is_some() {
                prepared.execute_ordered(rows, &limits)
            } else {
                prepared.execute_entries(rows.map(|(_, row)| row), &limits)
            };
            if let Some(error) = failure {
                return Err(error);
            }
            page
        }
        CollectionTarget::Subscriptions => {
            let world = state.world_view();
            let scan = prepared.ordered_scan();
            let after = cursor_key(scan.and_then(|scan| scan.after), |id| {
                id.parse::<NftId>().ok()
            })?;
            let descending = scan.is_some_and(|scan| scan.descending);
            let mut failure = None;
            let rows = seek_keys(
                world.nfts(),
                nft_filter_candidate_ids(query.filter.as_ref()),
                after.as_ref().filter(|_| !query.include_total),
                descending,
            )
            .map_while(|(id, nft)| {
                let row = if visibility.allows_nft(&world, id) {
                    subscription_collection_row(&world, id, &nft.owned_by, &nft.content)
                } else {
                    Ok(None)
                };
                match row {
                    Ok(row) => Some((entry_after_cursor(id, after.as_ref(), descending), row)),
                    Err(error) => {
                        failure = Some(error);
                        None
                    }
                }
            });
            let page = if scan.is_some() {
                prepared.execute_ordered(rows, &limits)
            } else {
                prepared.execute_entries(rows.map(|(_, row)| row), &limits)
            };
            if let Some(error) = failure {
                return Err(error);
            }
            page
        }
        CollectionTarget::UaidManifests(raw_uaid) => {
            let uaid = parse_uaid_literal(raw_uaid)?;
            let world = state.world_view();
            let aliases = DataspaceAliasLookup::new(state.nexus_snapshot().dataspace_catalog);
            let bindings = world.uaid_dataspaces().get(&uaid);
            let rows = world
                .space_directory_manifests()
                .get(&uaid)
                .into_iter()
                .flat_map(|set| set.iter())
                .map(|(id, record)| {
                    if !visibility.allows_dataspace(*id) {
                        return Ok(None);
                    }
                    manifest_entry_to_json(*id, record, &aliases, bindings)
                        .and_then(object_row_from_value)
                        .map(Some)
                });
            let mut failure = None;
            let rows = rows.map_while(|row| match row {
                Ok(row) => Some(row),
                Err(error) => {
                    failure = Some(error);
                    None
                }
            });
            let page = prepared.execute_entries(rows, &limits);
            if let Some(error) = failure {
                return Err(error);
            }
            page
        }
        CollectionTarget::AccountHistory(literal) => {
            let (account, _) = parse_account_path_segment_with_state(
                state,
                literal,
                telemetry,
                target.endpoint(),
            )?;
            if !visibility.allows_account(&state.world_view(), &account) {
                return prepared.subrow_page(Vec::new(), None).map_err(Into::into);
            }
            let allowed = app
                .map(|app| crate::resolve_tx_history_allowed_asset_definition_id(app))
                .transpose()?
                .flatten();
            return account_subrow_page(state, &prepared, &account, allowed.as_ref(), visibility);
        }
        CollectionTarget::ContractActivity => {
            return transaction_page(
                state,
                &prepared,
                None,
                None,
                visibility,
                contract_activity_row,
            );
        }
        CollectionTarget::ContractEvents => {
            return contract_emission_page(state, &prepared, visibility);
        }
        CollectionTarget::RepoAgreements => {
            let world = state.world_view();
            let scan = prepared.ordered_scan();
            let after = cursor_key(scan.and_then(|scan| scan.after), |id| {
                id.parse::<RepoAgreementId>().ok()
            })?;
            let rows = seek_keys(
                world.repo_agreements(),
                repo_filter_candidate_ids(&world, query.filter.as_ref()),
                after.as_ref().filter(|_| !query.include_total),
                scan.is_some_and(|scan| scan.descending),
            )
            .map(|(id, agreement)| {
                (
                    entry_after_cursor(
                        id,
                        after.as_ref(),
                        scan.is_some_and(|scan| scan.descending),
                    ),
                    Some(repo_agreement_projection_to_query_row(
                        &RepoAgreementProjection::from_agreement(agreement),
                    )),
                )
            });
            if scan.is_some() {
                prepared.execute_ordered(rows, &limits)
            } else {
                prepared.execute_entries(rows.map(|(_, row)| row), &limits)
            }
        }
    };
    Ok(page?)
}

/// Page movements inside authenticated transactions without indexing the full chain.
/// The third cursor coordinate keeps multiple movements from one transaction on
/// separate pages; only caller-visible movements may provide a continuation.
fn account_subrow_page(
    state: &Arc<CoreState>,
    prepared: &collections::Prepared<'_>,
    account: &AccountId,
    allowed_definition: Option<&AssetDefinitionId>,
    visibility: &DataspaceReadVisibility,
) -> Result<RowPage> {
    use iroha_core::smartcontracts::isi::tx::{
        TransactionHistoryPageEnd, TransactionHistoryPosition, transaction_history_byte_limit,
        visit_committed_transaction_page,
    };
    let after = prepared.resume_subrow_position();
    // Revisit the cursor transaction, then skip movements at or above its
    // exclusive coordinate. A transaction-only cursor would lose its tail.
    let resume = after
        .map(|(height, index, _)| {
            index
                .checked_add(1)
                .and_then(|index| TransactionHistoryPosition::new(height, index))
                .ok_or_else(|| {
                    Error::from(CollectionError::new(
                        "invalid_cursor",
                        "cursor",
                        "invalid history position",
                    ))
                })
        })
        .transpose()?;
    let (lowest, highest) = prepared.height_range();
    if lowest > highest {
        return prepared.subrow_page(Vec::new(), None).map_err(Into::into);
    }
    let ceiling = highest
        .checked_add(1)
        .and_then(|height| TransactionHistoryPosition::new(height, 0));
    let resume = match (resume, ceiling) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    let allowed = allowed_definition
        .cloned()
        .map(TxHistoryAssetSelector::DefinitionId);
    let view = state.view();
    let reads = HistoryVisibilityReads::new(Arc::clone(state));
    let mut items = Vec::new();
    let mut last_visible = None;
    let mut below_range = false;
    let mut expansion_exceeded = false;
    let mut scanned = 0u64;
    let account_literal = account.to_string();
    let work = app_query_limits().max_fetch_size;
    let end = visit_committed_transaction_page(
        &view,
        resume,
        work,
        transaction_history_byte_limit(work),
        |transaction, position| {
            if scanned >= work {
                return std::ops::ControlFlow::Break(());
            }
            if position.height() < lowest {
                below_range = true;
                return std::ops::ControlFlow::Break(());
            }
            if !(visibility.can_read_all()
                || reads.allows(
                    visibility,
                    position.height(),
                    Some(transaction.block_hash),
                    *transaction.entrypoint_hash(),
                ))
            {
                return std::ops::ControlFlow::Continue(());
            }
            let mut projected = AccountHistoryIndex::default();
            append_account_history_projections_for_tx(
                &mut projected,
                &transaction,
                position.height(),
            );
            // Carrier bytes bound decoding, including movements at or above the
            // resume coordinate that are decoded again but not examined again.
            // Bound each expansion before JSON projection; `scanned` charges all
            // later coordinates, including rows excluded by account or filters.
            if projected.items.len() as u64 > work {
                expansion_exceeded = true;
                return std::ops::ControlFlow::Break(());
            }
            for (index, projection) in projected.items.iter().enumerate().rev() {
                let coordinate = (position.height(), position.block_index(), index as u64);
                if after.is_some_and(|after| coordinate >= after) {
                    continue;
                }
                if scanned >= work {
                    return std::ops::ControlFlow::Break(());
                }
                scanned += 1;
                if projection.account_id != account_literal
                    || allowed.as_ref().is_some_and(|selector| {
                        !account_history_projection_matches_asset_selector(projection, selector)
                    })
                {
                    continue;
                }
                let Value::Object(mut row) =
                    account_history_projections_to_json(std::slice::from_ref(projection)).remove(0)
                else {
                    unreachable!("movement projection is an object")
                };
                row.insert("block_height".into(), Value::from(position.height()));
                row.insert("block_index".into(), Value::from(position.block_index()));
                row.insert("movement_index".into(), Value::from(index as u64));
                if prepared.matches(&row) {
                    if items.len() == prepared.limit() {
                        return std::ops::ControlFlow::Break(());
                    }
                    items.push(row);
                }
                last_visible = Some(coordinate);
            }
            std::ops::ControlFlow::Continue(())
        },
    )
    .map_err(|error| Error::Query(iroha_data_model::ValidationFail::QueryFailed(error)))?;
    drop(view);
    reads.finish()?;
    if expansion_exceeded {
        return Err(CollectionError::new(
            "query_scan_limit_exceeded",
            "filter",
            "one transaction's movement projection exceeds the page's raw-row scan budget",
        )
        .into());
    }
    let continuation = match end {
        TransactionHistoryPageEnd::Exhausted => None,
        TransactionHistoryPageEnd::Stopped(_) if below_range => None,
        TransactionHistoryPageEnd::Stopped(_) | TransactionHistoryPageEnd::BudgetSpent(_) => {
            Some(last_visible.ok_or_else(|| Error::from(CollectionError::new(
                "query_scan_limit_exceeded", "filter", "the history scan budget ended before a visible movement could provide a continuation",
            )))?)
        }
        TransactionHistoryPageEnd::OutOfReach => return Err(CollectionError::new(
            "query_scan_limit_exceeded", "cursor", "reaching this history page exceeds the node's history scan budget",
        ).into()),
    };
    prepared
        .subrow_page(items, continuation)
        .map_err(Into::into)
}

/// Page the canonical emission coordinates, including Pipeline and Time roots.
/// The exclusive cursor retains the tail of every multi-emission output. All
/// examined output/event coordinates spend the page's work budget, including
/// hidden events; only an authorized row may become a public continuation.
fn contract_emission_page(
    state: &Arc<CoreState>,
    prepared: &collections::Prepared<'_>,
    visibility: &DataspaceReadVisibility,
) -> Result<RowPage> {
    let after = prepared.resume_subrow_position();
    let (lowest, highest) = prepared.height_range();
    let tip = u64::try_from(state.committed_height()).map_err(|_| history_capacity_error())?;
    let Some(anchor) = state.committed_block_hash_at_height(tip) else {
        if tip == 0 {
            return prepared.subrow_page(Vec::new(), None).map_err(Into::into);
        }
        return Err(conversion_error(
            "native event history is missing its captured tip".into(),
        ));
    };
    let first = highest
        .min(tip)
        .min(after.map_or(u64::MAX, |position| position.0));
    let lowest = lowest.max(1);
    if first < lowest {
        return prepared.subrow_page(Vec::new(), None).map_err(Into::into);
    }
    require_history_anchor(state, tip, anchor)?;
    let mut budget = HistoryReadBudget::new();
    let work = app_query_limits().max_fetch_size;
    let mut examined = 0u64;
    let mut items = Vec::new();
    let mut last_visible = None;
    let mut stopped = false;
    'history: for height in (lowest..=first).rev() {
        if budget.work_left == 0 || examined == work {
            stopped = true;
            break;
        }
        let height_nz = usize::try_from(height)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or_else(history_capacity_error)?;
        let block = budget.read(state, height_nz)?;
        let timestamp = u64::try_from(block.header().creation_time().as_millis())
            .map_err(|_| history_capacity_error())?;
        for (output_index, output) in block.execution_outputs().iter().enumerate().rev() {
            if after.is_some_and(|(h, o, _)| (height, output_index as u64) > (h, o)) {
                continue;
            }
            if examined == work {
                stopped = true;
                break 'history;
            }
            examined += 1;
            if output.result().as_ref().is_err() && !output.result().contract_events().is_empty() {
                return Err(conversion_error(
                    "rejected output retains contract emissions".into(),
                ));
            }
            let execution_hash = output
                .execution_call_hash(block.hash(), &*block)
                .map_err(conversion_error)?;
            let fee_payment = match output {
                iroha_data_model::block::execution_output::ExecutionOutputV1::Network(network) => {
                    let entrypoint = block
                        .network_entrypoint_at(network.input_index as usize)
                        .ok_or_else(|| {
                            conversion_error("emission output lost its Network input".into())
                        })?;
                    tx_fee_projection(&BorrowedNetworkTransaction {
                        entrypoint,
                        entrypoint_hash: entrypoint.hash(),
                        result: &network.result,
                        block_hash: block.hash(),
                    })
                }
                _ => None,
            };
            for (emission_index, emission) in
                output.result().contract_events().iter().enumerate().rev()
            {
                let coordinate = (height, output_index as u64, emission_index as u64);
                if after.is_some_and(|after| coordinate >= after) {
                    continue;
                }
                if examined == work {
                    stopped = true;
                    break 'history;
                }
                examined += 1;
                if !native_contract_emission_source_is_visible(visibility, &block, output, emission)
                {
                    continue;
                }
                let projection = contract_event_projection(
                    height,
                    block.hash(),
                    timestamp,
                    output_index as u64,
                    emission_index as u64,
                    execution_hash,
                    emission,
                    fee_payment.clone(),
                )?;
                let Value::Object(row) = contract_event_projection_to_json_value(&projection)
                else {
                    unreachable!("native event projection is an object")
                };
                if prepared.matches(&row) {
                    if items.len() == prepared.limit() {
                        stopped = true;
                        break 'history;
                    }
                    items.push(row);
                }
                last_visible = Some(coordinate);
            }
        }
    }
    require_history_anchor(state, tip, anchor)?;
    let continuation = if stopped {
        Some(last_visible.ok_or_else(|| Error::from(CollectionError::new(
            "query_scan_limit_exceeded", "filter", "the native event scan budget ended before a visible emission could provide a continuation",
        )))?)
    } else {
        None
    };
    prepared
        .subrow_page(items, continuation)
        .map_err(Into::into)
}

/// One page of committed transactions, newest first, strictly before the
/// cursor's block coordinates.
///
/// Every page has its own history-scan budget. A page that spends it before
/// filling up ends early with a cursor at the last examined transaction.
/// Reads start at the nearest verified history checkpoint above the page, so
/// the budget pays for at most a checkpoint interval of extra blocks.
fn transaction_page(
    state: &Arc<CoreState>,
    prepared: &collections::Prepared<'_>,
    subject: Option<&AccountId>,
    allowed_definition: Option<&AssetDefinitionId>,
    visibility: &DataspaceReadVisibility,
    project: impl Fn(
        &iroha_data_model::query::CommittedTransaction,
        iroha_core::smartcontracts::isi::tx::TransactionHistoryPosition,
    ) -> Option<Map>,
) -> Result<RowPage> {
    use iroha_core::smartcontracts::isi::tx::{
        TransactionHistoryPageEnd, TransactionHistoryPosition, transaction_history_byte_limit,
        visit_committed_transaction_page,
    };
    let resume = prepared
        .resume_position()
        .map(|(height, index)| {
            TransactionHistoryPosition::new(height, index).ok_or_else(|| {
                Error::from(CollectionError::new(
                    "invalid_cursor",
                    "cursor",
                    "the cursor addresses a block beyond this node's range",
                ))
            })
        })
        .transpose()?;
    let (lowest, highest) = prepared.height_range();
    if lowest > highest {
        return prepared
            .positioned_page(Vec::new(), None)
            .map_err(Into::into);
    }
    // Start the walk at the top of the filter's height range.
    let ceiling = highest
        .checked_add(1)
        .and_then(|height| TransactionHistoryPosition::new(height, 0));
    let resume = match (resume, ceiling) {
        (Some(resume), Some(ceiling)) => Some(resume.min(ceiling)),
        (resume, ceiling) => resume.or(ceiling),
    };
    let allowed = allowed_definition
        .cloned()
        .map(TxHistoryAssetSelector::DefinitionId);
    // The walk's view is captured before the visibility reads so every visited
    // carrier lies inside the prefix the reads authenticate.
    let view = state.view();
    let reads = HistoryVisibilityReads::new(Arc::clone(state));
    let limit = prepared.limit();
    let mut items = Vec::new();
    let mut last_visible = None;
    let mut below_range = false;
    let work = app_query_limits().max_fetch_size;
    let end = visit_committed_transaction_page(
        &view,
        resume,
        work,
        transaction_history_byte_limit(work),
        |transaction, position| {
            if position.height() < lowest {
                below_range = true;
                return std::ops::ControlFlow::Break(());
            }
            let visible = visibility.can_read_all()
                || reads.allows(
                    visibility,
                    position.height(),
                    Some(transaction.block_hash),
                    *transaction.entrypoint_hash(),
                );
            if !visible
                || subject.is_some_and(|account| {
                    !tx_matches_account_history_subject(&transaction, account)
                })
                || allowed
                    .as_ref()
                    .is_some_and(|selector| !tx_matches_asset_selector(&transaction, selector))
            {
                return std::ops::ControlFlow::Continue(());
            }
            let Some(row) = project(&transaction, position) else {
                return std::ops::ControlFlow::Continue(());
            };
            let matches = prepared.matches(&row);
            if matches && items.len() == limit {
                return std::ops::ControlFlow::Break(());
            }
            last_visible = Some(position);
            if matches {
                items.push(row);
            }
            std::ops::ControlFlow::Continue(())
        },
    )
    .map_err(|error| Error::Query(iroha_data_model::ValidationFail::QueryFailed(error)))?;
    drop(view);
    reads.finish()?;
    let resume = match end {
        TransactionHistoryPageEnd::Stopped(_) if below_range => None,
        TransactionHistoryPageEnd::Stopped(_) | TransactionHistoryPageEnd::BudgetSpent(_) => {
            Some(last_visible.ok_or_else(|| Error::from(CollectionError::new(
                "query_scan_limit_exceeded", "filter",
                "the history scan budget ended before a visible row could provide a continuation",
            )))?)
        }
        TransactionHistoryPageEnd::OutOfReach => {
            return Err(CollectionError::new(
                "query_scan_limit_exceeded",
                if prepared.resume_position().is_some() {
                    "cursor"
                } else {
                    "filter"
                },
                format!(
                    "reaching this page's position needs more history reads than one page's \
                     scan budget ({work} blocks and transactions)"
                ),
            )
            .with_hint(
                "the per-page budget is the node's `torii.app_api_max_fetch_size`; \
                 history blocks larger than it cannot be paged",
            )
            .into());
        }
        TransactionHistoryPageEnd::Exhausted => None,
    };
    prepared
        .positioned_page(
            items,
            resume.map(|position| (position.height(), position.block_index())),
        )
        .map_err(Into::into)
}

/// Project one committed contract call without constructing a history-wide index.
fn contract_activity_row(
    transaction: &iroha_data_model::query::CommittedTransaction,
    position: iroha_core::smartcontracts::isi::tx::TransactionHistoryPosition,
) -> Option<Map> {
    let projection = contract_activity_projection_from_tx(position.height() as usize, transaction)?;
    let Value::Object(mut row) = contract_activity_projections_to_json(&[projection]).pop()? else {
        return None;
    };
    row.insert("block_height".into(), Value::from(position.height()));
    row.insert("block_index".into(), Value::from(position.block_index()));
    Some(row)
}

/// The row of one committed transaction (`specs/torii/collection_queries.md`).
fn transaction_row(
    transaction: &iroha_data_model::query::CommittedTransaction,
    position: iroha_core::smartcontracts::isi::tx::TransactionHistoryPosition,
) -> Map {
    let projection = project_tx(transaction);
    let assets = tx_collect_asset_ids(transaction);
    let strings =
        |values: BTreeSet<String>| Value::Array(values.into_iter().map(Value::from).collect());
    let mut row = Map::new();
    row.insert(
        "entrypoint_hash".into(),
        Value::from(projection.entrypoint_hash),
    );
    row.insert("block_height".into(), Value::from(position.height()));
    row.insert("block_index".into(), Value::from(position.block_index()));
    row.insert(
        "block_hash".into(),
        Value::from(transaction.block_hash.to_string()),
    );
    row.insert(
        "authority".into(),
        projection.authority.map_or(Value::Null, Value::from),
    );
    row.insert(
        "timestamp_ms".into(),
        projection.timestamp_ms.map_or(Value::Null, Value::from),
    );
    row.insert(
        "entrypoint_kind".into(),
        Value::from(projection.entrypoint_kind),
    );
    row.insert("result_ok".into(), Value::from(projection.result_ok));
    row.insert(
        "asset_ids".into(),
        strings(assets.iter().map(ToString::to_string).collect()),
    );
    row.insert(
        "asset_definition_ids".into(),
        strings(
            assets
                .iter()
                .map(|asset| asset.definition().to_string())
                .collect(),
        ),
    );
    let metadata = match transaction.entrypoint() {
        TransactionEntrypoint::External(signed) => metadata_to_json(signed.metadata()),
        _ => Value::Object(Map::new()),
    };
    row.insert("metadata".into(), metadata);
    row
}

/// Execute locally and apply `select`, for collections served without fan-out.
pub(crate) async fn execute_collection_response(
    app: Option<&crate::SharedAppState>,
    state: &Arc<CoreState>,
    target: &CollectionTarget,
    mut query: ListQuery,
    telemetry: &MaybeTelemetry,
    visibility: &DataspaceReadVisibility,
) -> Result<Response> {
    let owner = match app {
        Some(app) => {
            let reservation = crate::current_query_fanout_memory_for_state(app)
                .ok_or_else(|| Error::from(collections::memory::capacity("response owner")))?;
            Some(crate::history_producer::HistoryProducerOwner::from_reservation(&reservation)?)
        }
        None => crate::history_producer::HistoryProducerOwner::current_if_admitted()?,
    };
    canonicalize_collection_query(state, target, &mut query, telemetry)?;
    let limits = collection_execution_limits(app)?;
    let prepared = collections::prepare(target.spec(), target.scope(), &query, &limits)?;
    let page = execute_prepared_collection_local(
        app, state, target, &query, telemetry, visibility, &prepared, &limits,
    )
    .await?;
    let page = prepared.project(page)?;
    match owner {
        Some(owner) => row_page_response_owned(page, limits.bytes, &owner),
        // app=None is the explicit standalone engine/benchmark entry point. It has
        // no query-pool certification; a present invalid admission was rejected above.
        None => standalone_row_page_response(page, limits.bytes),
    }
}

/// Serialize a page as the JSON page envelope.
pub(crate) fn row_page_response(
    page: RowPage,
    bytes: collections::memory::BytePolicy,
) -> Result<Response> {
    let owner = crate::history_producer::HistoryProducerOwner::current()?;
    row_page_response_owned(page, bytes, &owner)
}

fn row_page_response_owned(
    page: RowPage,
    bytes: collections::memory::BytePolicy,
    owner: &crate::history_producer::HistoryProducerOwner,
) -> Result<Response> {
    let page = iroha_torii_shared::list_query::Page {
        items: page.items,
        next_cursor: page.next_cursor,
        total: page.total,
    };
    owner.json_with_limit(&page, bytes.response_bytes)
}

/// Independent bounded engine output; this operation grants no query owner.
fn standalone_row_page_response(
    page: RowPage,
    bytes: collections::memory::BytePolicy,
) -> Result<Response> {
    let page = iroha_torii_shared::list_query::Page {
        items: page.items,
        next_cursor: page.next_cursor,
        total: page.total,
    };
    let body = norito::json::to_json_bounded_boxed(&page, bytes.response_bytes)
        .map_err(|_| Error::from(collections::memory::capacity("response body")))?;
    // Keep the exact checked encoder layout as the HTTP body's owned buffer.
    let body = axum::body::Bytes::from(body);
    let mut response = Response::new(axum::body::Body::from(body));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

fn domain_row(
    domain: &iroha_data_model::domain::Domain,
    bytes: collections::memory::BytePolicy,
) -> Result<Map> {
    bytes
        .row_fields([
            ("id", domain.id()),
            ("owned_by", domain.owned_by()),
            ("logo", domain.logo()),
            ("metadata", &domain.metadata),
        ])
        .map_err(Into::into)
}

fn account_row(
    id: &AccountId,
    details: &iroha_data_model::account::AccountDetails,
    bytes: collections::memory::BytePolicy,
) -> Result<Map> {
    // Canonical World accounts carry their alias bindings separately; the
    // collection's existing label field is null without a resolved binding.
    let label = None::<&str>;
    // The collection exposes the canonical UAID literal, not its structural
    // Norito JSON representation. Admit its display text before allocating it.
    let uaid = details
        .uaid
        .as_ref()
        .map(|uaid| bytes.display(uaid))
        .transpose()?;
    bytes
        .row_fields([
            ("id", id),
            ("label", &label),
            ("uaid", &uaid),
            ("metadata", &details.metadata),
        ])
        .map_err(Into::into)
}

fn nft_row(
    id: &NftId,
    nft: &iroha_data_model::nft::NftData,
    bytes: collections::memory::BytePolicy,
) -> Result<Map> {
    bytes
        .row_fields([
            ("id", id),
            ("owned_by", &nft.owned_by),
            ("metadata", &nft.content),
        ])
        .map_err(Into::into)
}

/// Flatten subscription state into the common collection row contract.
fn subscription_collection_row(
    world: &impl WorldReadOnly,
    id: &NftId,
    owner: &AccountId,
    metadata: &Metadata,
) -> Result<Option<Map>> {
    let Some(subscription) = subscription_state_from_metadata(metadata)? else {
        return Ok(None);
    };
    let invoice = subscription_invoice_from_metadata(metadata)?;
    let plan = world
        .asset_definitions()
        .get(&subscription.plan_id)
        .map(|definition| subscription_plan_from_metadata(definition.metadata()))
        .transpose()?
        .flatten();
    let mut row = dto_row(&subscription);
    row.insert("id".into(), Value::from(id.to_string()));
    row.insert("owned_by".into(), Value::from(owner.to_string()));
    row.insert(
        "status".into(),
        Value::from(match subscription.status {
            SubscriptionStatus::Active => "active",
            SubscriptionStatus::Paused => "paused",
            SubscriptionStatus::PastDue => "past_due",
            SubscriptionStatus::Canceled => "canceled",
            SubscriptionStatus::Suspended => "suspended",
        }),
    );
    row.insert(
        "invoice".into(),
        norito::json::to_value(&invoice)
            .map_err(|error| conversion_error(format!("invalid subscription invoice: {error}")))?,
    );
    row.insert(
        "plan".into(),
        norito::json::to_value(&plan)
            .map_err(|error| conversion_error(format!("invalid subscription plan: {error}")))?,
    );
    Ok(Some(row))
}

fn dto_row<T: norito::json::JsonSerialize>(dto: &T) -> Map {
    match norito::json::to_value(dto) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    }
}

fn account_asset_row(item: &AccountAssetListItem) -> Map {
    let mut row = Map::new();
    row.insert("account_id".into(), Value::from(item.account_id.clone()));
    row.insert("asset".into(), Value::from(item.asset.clone()));
    row.insert("asset_name".into(), Value::from(item.asset_name.clone()));
    row.insert(
        "asset_alias".into(),
        item.asset_alias
            .as_ref()
            .map_or(Value::Null, |alias| Value::from(alias.clone())),
    );
    row.insert("scope".into(), Value::from(item.scope.clone()));
    row.insert("quantity".into(), Value::from(item.quantity.to_string()));
    row
}

fn asset_holder_row(item: &AssetHolderListItem) -> Map {
    let mut row = Map::new();
    row.insert("account_id".into(), Value::from(item.canonical_id.clone()));
    row.insert("asset".into(), Value::from(item.asset.clone()));
    row.insert(
        "asset_alias".into(),
        item.asset_alias
            .as_ref()
            .map_or(Value::Null, |alias| Value::from(alias.clone())),
    );
    row.insert("scope".into(), Value::from(item.scope.clone()));
    row.insert("quantity".into(), Value::from(item.quantity.to_string()));
    row
}

/// Bound every account membership, role membership and expanded permission before
/// materializing the deduplicated effective permission rows.
fn collect_effective_account_permissions(
    world: &impl WorldReadOnly,
    account: &AccountId,
    max_scanned_rows: usize,
) -> Result<BTreeSet<iroha_data_model::permission::Permission>> {
    let mut examined = 0usize;
    let mut charge = || -> Result<()> {
        if examined >= max_scanned_rows {
            return Err(CollectionError::new(
                "query_scan_limit_exceeded",
                "filter",
                "effective permission expansion exceeds the collection scan budget",
            )
            .into());
        }
        examined += 1;
        Ok(())
    };
    let subject = account.subject_id();
    let mut accounts = world
        .accounts_for_subject_iter(&subject)
        .map(|entry| entry.id().clone());
    let first = accounts.next().unwrap_or_else(|| account.clone());
    let mut permissions = BTreeSet::new();
    for account_id in std::iter::once(first).chain(accounts) {
        charge()?;
        match world.account_permissions_iter(&account_id) {
            Ok(direct) => {
                for permission in direct {
                    charge()?;
                    permissions.insert(permission.clone());
                }
            }
            Err(iroha_data_model::query::error::FindError::Account(_)) => {}
            Err(error) => {
                return Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                    error.into(),
                )));
            }
        }
        for role_id in world.account_roles_iter(&account_id) {
            charge()?;
            let role = world.roles().get(role_id).ok_or_else(|| {
                conversion_error(format!(
                    "account `{account_id}` has missing role `{role_id}`"
                ))
            })?;
            for permission in role.permissions() {
                charge()?;
                permissions.insert(permission.clone());
            }
        }
    }
    Ok(permissions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_crypto::Algorithm;
    use iroha_data_model::prelude as dm;
    use iroha_primitives::json::Json;
    use iroha_torii_shared::list_query::{SortKey, field};

    fn authority(seed: u8) -> dm::AccountId {
        dm::AccountId::new(
            checked_routing_fixture_keypair(seed, Algorithm::Ed25519, "collection fixture key")
                .public_key()
                .clone(),
        )
    }

    fn domain_id(name: &str) -> DomainId {
        DomainId::try_new(name, "universal").expect("fixture domain")
    }

    #[test]
    fn bounded_borrowed_collection_rows_preserve_owned_wire_fields() {
        let owner = authority(0xC1);
        let mut metadata = Metadata::default();
        metadata.insert(
            "nested".parse().unwrap(),
            Json::new(norito::json!({"text":"quoted \\\"", "values":[1,null,true]})),
        );
        let domain = dm::Domain::new(domain_id("parity"))
            .with_logo("sorafs://bafybeigdyrzt".parse().expect("logo URI"))
            .with_metadata(metadata.clone())
            .build(&owner);
        let bytes = collections::memory::BytePolicy::canonical();
        let actual = domain_row(&domain, bytes).expect("bounded domain row");
        let expected = Map::from_iter([
            ("id".to_owned(), Value::from(domain.id().to_string())),
            (
                "owned_by".to_owned(),
                Value::from(domain.owned_by().to_string()),
            ),
            (
                "logo".to_owned(),
                domain
                    .logo()
                    .as_ref()
                    .map_or(Value::Null, |logo| Value::from(logo.to_string())),
            ),
            (
                "metadata".to_owned(),
                crate::explorer::metadata_to_json(&domain.metadata),
            ),
        ]);
        assert_eq!(actual, expected);
        let uaid = "uaid:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            .parse()
            .unwrap();
        let label = iroha_data_model::account::rekey::AccountAlias::domainless(
            "source_label".parse().unwrap(),
            iroha_model_base::topology::DataSpaceId::new(0),
        );
        let details = iroha_data_model::account::AccountDetails::new(
            metadata.clone(),
            Some(label),
            Some(uaid),
            Vec::new(),
        );
        let owned = account_from_key_value(
            &owner,
            &iroha_data_model::common::Owned::new(details.clone()),
        );
        assert!(owned.label().is_none());
        let actual = account_row(&owner, &details, bytes).expect("bounded account row");
        assert_eq!(
            actual,
            Map::from_iter([
                ("id".to_owned(), Value::from(owned.id().to_string())),
                ("label".to_owned(), Value::Null),
                (
                    "uaid".to_owned(),
                    Value::from(owned.uaid().unwrap().to_string())
                ),
                (
                    "metadata".to_owned(),
                    crate::explorer::metadata_to_json(owned.metadata())
                ),
            ])
        );
        let mut tight = bytes;
        tight.scratch_bytes = owned.uaid().unwrap().to_string().len() - 1;
        assert!(matches!(
            account_row(&owner, &details, tight),
            Err(Error::CollectionQuery(error)) if error.code == "query_capacity_exceeded"
        ));
        tight.scratch_bytes += 1;
        assert_eq!(account_row(&owner, &details, tight).unwrap(), actual);
        let mut no_uaid = details.clone();
        no_uaid.uaid = None;
        tight.scratch_bytes = 0;
        assert_eq!(
            account_row(&owner, &no_uaid, tight).unwrap().get("uaid"),
            Some(&Value::Null)
        );
        let id = NftId::new(domain_id("parity"), "item".parse().unwrap());
        let nft = iroha_data_model::nft::NftData {
            content: metadata,
            owned_by: owner,
        };
        let actual = nft_row(&id, &nft, bytes).unwrap();
        assert_eq!(actual.get("id"), Some(&Value::from(id.to_string())));
        assert_eq!(
            actual.get("owned_by"),
            Some(&Value::from(nft.owned_by.to_string()))
        );
        assert_eq!(
            actual.get("metadata"),
            Some(&crate::explorer::metadata_to_json(&nft.content))
        );
    }

    fn fixture() -> (Arc<CoreState>, dm::AccountId, dm::AccountId) {
        let alice = authority(0xC1);
        let bob = authority(0xC2);
        let domain = |name: &str, owner: &dm::AccountId, tier: u64| {
            let mut metadata = Metadata::default();
            metadata.insert("tier".parse().expect("key"), Json::new(tier));
            dm::Domain::new(domain_id(name))
                .with_metadata(metadata)
                .build(owner)
        };
        let domains = vec![
            domain("delta", &bob, 2),
            domain("alpha", &alice, 1),
            domain("echo", &alice, 3),
            domain("charlie", &bob, 1),
            domain("bravo", &alice, 2),
        ];
        let accounts = vec![
            dm::Account::new(alice.account().clone()).build(&alice),
            dm::Account::new(bob.account().clone()).build(&bob),
        ];
        let state = Arc::new(State::new_for_testing(
            World::with(domains, accounts, []),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ));
        (state, alice, bob)
    }

    #[test]
    fn exact_key_seek_streams_storage_order_and_skips_missing_keys() {
        let (state, _, _) = fixture();
        let world = state.world_view();
        let candidates = || {
            BTreeSet::from([
                domain_id("echo"),
                domain_id("alpha"),
                domain_id("charlie"),
                domain_id("absent"),
            ])
        };
        let after = domain_id("bravo");
        let ids = |descending| {
            seek_keys(
                world.domains(),
                Some(candidates()),
                Some(&after),
                descending,
            )
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>()
        };
        assert_eq!(ids(false), [domain_id("charlie"), domain_id("echo")]);
        assert_eq!(ids(true), [domain_id("alpha")]);
        let all = seek_keys(world.domains(), Some(candidates()), None, true)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            all,
            [domain_id("echo"), domain_id("charlie"), domain_id("alpha")]
        );
    }

    #[tokio::test]
    async fn canonical_world_accounts_refuse_metadata_expansion_before_retention() {
        let owner = authority(0xC1);
        let mut limits = collection_limits();
        limits.bytes = collections::memory::BytePolicy {
            source_frame_bytes: 16 * 1024,
            row_bytes: 8 * 1024,
            retained_bytes: 16 * 1024,
            scratch_bytes: 16 * 1024,
            response_bytes: 16 * 1024,
        };
        let empty = iroha_data_model::account::AccountDetails::new(
            Metadata::default(),
            None,
            None,
            Vec::new(),
        );
        assert!(
            account_row(&owner, &empty, limits.bytes).is_ok(),
            "the ordinary row fits the same quota"
        );
        let mut metadata = Metadata::default();
        metadata.insert(
            "dense".parse().unwrap(),
            Json::new(Value::Array(vec![Value::Null; 1024])),
        );
        let account = dm::Account::new(owner.clone())
            .with_metadata(metadata)
            .build(&owner);
        let state = Arc::new(State::new_for_testing(
            World::with([], [account], []),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ));
        let query = ListQuery::new();
        let target = CollectionTarget::Accounts;
        let prepared =
            collections::prepare(target.spec(), target.scope(), &query, &limits).unwrap();
        let error = execute_prepared_collection_local(
            None,
            &state,
            &target,
            &query,
            &MaybeTelemetry::for_tests(),
            &DataspaceReadVisibility::all_for_tests(),
            &prepared,
            &limits,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, Error::CollectionQuery(ref error) if error.code == "query_capacity_exceeded")
        );
    }

    #[test]
    fn effective_permissions_charge_empty_role_and_account_memberships() {
        let alice = authority(0xC1);
        let account = dm::Account::new(alice.clone()).build(&alice);
        let role_ids: Vec<dm::RoleId> = (0..8)
            .map(|index| format!("empty_role_{index}").parse().expect("role id"))
            .collect();
        let roles = role_ids
            .iter()
            .map(|id| dm::Role::new(id.clone(), alice.clone()).build(&alice));
        let mut world = World::with_assets_and_roles([], [account], [], [], [], roles);
        for role_id in role_ids {
            world.grant_role_for_tests(alice.clone(), role_id);
        }
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let world = state.world_view();
        // Eight empty role bindings still require work, plus the account itself.
        assert!(collect_effective_account_permissions(&world, &alice, 8).is_err());
        assert!(
            collect_effective_account_permissions(&world, &alice, 9)
                .expect("exact account and role membership budget")
                .is_empty()
        );
    }

    async fn run(
        state: &Arc<CoreState>,
        target: &CollectionTarget,
        query: ListQuery,
    ) -> Result<RowPage> {
        execute_collection_local(
            None,
            state,
            target,
            query,
            &MaybeTelemetry::for_tests(),
            &DataspaceReadVisibility::all_for_tests(),
        )
        .await
    }

    fn ids(page: &RowPage) -> Vec<String> {
        page.items
            .iter()
            .map(|row| row["id"].as_str().expect("id").to_owned())
            .collect()
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter()
            .map(|name| domain_id(name).to_string())
            .collect()
    }

    #[tokio::test]
    async fn domains_page_through_every_row_with_cursors() {
        let (state, _, _) = fixture();
        let query = ListQuery::new().limit(2);
        let mut seen = Vec::new();
        let mut current = query.clone();
        loop {
            let page = run(&state, &CollectionTarget::Domains, current.clone())
                .await
                .expect("page");
            assert!(page.items.len() <= 2);
            seen.extend(ids(&page));
            match page.next_cursor {
                Some(cursor) => current = query.clone().cursor(cursor),
                None => break,
            }
        }
        let mut expected = names(&["alpha", "bravo", "charlie", "delta", "echo"]);
        expected.sort();
        assert_eq!(seen, expected);
    }

    async fn pages(
        state: &Arc<CoreState>,
        target: &CollectionTarget,
        query: &ListQuery,
    ) -> Vec<String> {
        let mut seen = Vec::new();
        let mut current = query.clone();
        for _ in 0..20 {
            let page = run(state, target, current.clone()).await.expect("page");
            seen.extend(ids(&page));
            match page.next_cursor {
                Some(cursor) => current = query.clone().cursor(cursor),
                None => break,
            }
        }
        seen
    }

    #[tokio::test]
    async fn identity_order_seeks_in_both_directions() {
        let (state, _, _) = fixture();
        let descending = ListQuery::new().sort_by(SortKey::desc("id")).limit(2);
        assert_eq!(
            pages(&state, &CollectionTarget::Domains, &descending).await,
            names(&["echo", "delta", "charlie", "bravo", "alpha"])
        );
    }

    #[tokio::test]
    async fn exact_id_filters_read_only_their_keys() {
        let (state, _, _) = fixture();
        let point = ListQuery::new().filter(field("id").eq(domain_id("charlie").to_string()));
        assert_eq!(
            pages(&state, &CollectionTarget::Domains, &point).await,
            names(&["charlie"])
        );
        let several = ListQuery::new()
            .filter(field("id").is_in([
                domain_id("echo").to_string(),
                domain_id("alpha").to_string(),
                domain_id("missing").to_string(),
            ]))
            .sort_by(SortKey::desc("id"))
            .limit(1);
        assert_eq!(
            pages(&state, &CollectionTarget::Domains, &several).await,
            names(&["echo", "alpha"])
        );
    }

    #[tokio::test]
    async fn accounts_stream_in_identifier_order() {
        let (state, alice, bob) = fixture();
        let mut expected = vec![alice, bob];
        expected.sort();
        let expected: Vec<String> = expected.iter().map(ToString::to_string).collect();
        let query = ListQuery::new().limit(1);
        assert_eq!(
            pages(&state, &CollectionTarget::Accounts, &query).await,
            expected
        );
    }

    #[tokio::test]
    async fn ordered_totals_stay_constant_across_pages() {
        let (state, _, _) = fixture();
        for descending in [false, true] {
            let query = ListQuery::new()
                .include_total()
                .limit(2)
                .sort_by(if descending {
                    SortKey::desc("id")
                } else {
                    SortKey::asc("id")
                });
            let mut current = query.clone();
            let mut seen = Vec::new();
            for _ in 0..4 {
                let page = run(&state, &CollectionTarget::Domains, current)
                    .await
                    .expect("page");
                assert_eq!(page.total, Some(5));
                seen.extend(ids(&page));
                let Some(cursor) = page.next_cursor else {
                    break;
                };
                current = query.clone().cursor(cursor);
            }
            let mut expected = names(&["alpha", "bravo", "charlie", "delta", "echo"]);
            if descending {
                expected.reverse();
            }
            assert_eq!(seen, expected);
        }
    }

    #[test]
    fn cursor_direction_uses_the_storage_key_order() {
        assert!(entry_after_cursor(&2, None, false));
        assert!(entry_after_cursor(&2, None, true));
        assert!(entry_after_cursor(&2, Some(&1), false));
        assert!(entry_after_cursor(&1, Some(&2), true));
        assert!(!entry_after_cursor(&1, Some(&1), false));
        assert!(!entry_after_cursor(&1, Some(&1), true));
        assert!(!entry_after_cursor(&1, Some(&2), false));
    }

    #[tokio::test]
    async fn domains_filter_sort_and_total() {
        let (state, alice, _) = fixture();
        let query = ListQuery::new()
            .filter(field("owned_by").eq(alice.to_string()) & field("metadata.tier").gte(2))
            .sort_by(SortKey::desc("metadata.tier"))
            .include_total();
        let page = run(&state, &CollectionTarget::Domains, query)
            .await
            .expect("page");
        assert_eq!(ids(&page), names(&["echo", "bravo"]));
        assert_eq!(page.total, Some(2));
        assert_eq!(page.next_cursor, None);
        let row = &page.items[0];
        assert_eq!(row["owned_by"].as_str(), Some(alice.to_string().as_str()));
        assert_eq!(row["metadata"]["tier"].as_u64(), Some(3));
        assert!(row["logo"].is_null());
    }

    #[tokio::test]
    async fn domains_reject_fields_they_do_not_have() {
        let (state, _, _) = fixture();
        let err = run(
            &state,
            &CollectionTarget::Domains,
            ListQuery::new().filter(field("owner").eq("x")),
        )
        .await
        .expect_err("unknown field");
        let Error::CollectionQuery(err) = err else {
            panic!("expected a collection error, got {err:?}");
        };
        assert_eq!(err.code, "invalid_filter");
        assert_eq!(err.actual.as_deref(), Some("owner"));
        assert!(
            err.expected
                .as_deref()
                .is_some_and(|fields| fields.contains("owned_by"))
        );
    }

    #[tokio::test]
    async fn accounts_rows_expose_identity_label_and_metadata() {
        let (state, alice, bob) = fixture();
        let page = run(
            &state,
            &CollectionTarget::Accounts,
            ListQuery::new().include_total(),
        )
        .await
        .expect("page");
        assert_eq!(page.total, Some(2));
        let mut expected = vec![alice, bob];
        expected.sort();
        let expected: Vec<String> = expected.iter().map(ToString::to_string).collect();
        assert_eq!(ids(&page), expected);
        for row in &page.items {
            assert!(row.contains_key("label"));
            assert!(row.contains_key("uaid"));
            assert!(row["metadata"].is_object());
        }
    }

    #[tokio::test]
    async fn account_transactions_page_newest_first_by_block_coordinates() {
        use iroha_core::{
            smartcontracts::Execute as _,
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
            tx::AcceptedTransaction,
        };
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::default(), 1))
            .expect("fixture genesis");
        let state = Arc::clone(chain.state());
        let keys = checked_routing_fixture_keypair(0xC3, Algorithm::Ed25519, "history fixture key");
        let alice = dm::AccountId::new(keys.public_key().clone());
        {
            let latest = state.view().latest_block_hash();
            let mut block = state.block(iroha_data_model::block::BlockHeader::new(
                core::num::NonZeroU64::new(chain.height() + 1).unwrap(),
                latest,
                None,
                1_000,
                0,
            ));
            let mut tx = block.transaction();
            dm::Register::account(dm::Account::new(alice.account().clone()))
                .execute(alice.account(), &mut tx)
                .ok();
            tx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("seed fixture account");
        }
        let network_id = *state.network_id_ref();
        let signed = |millis: u64| {
            let mut builder = dm::TransactionBuilder::new(
                network_id,
                alice.clone().into(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            );
            builder.set_creation_time(core::time::Duration::from_millis(millis));
            let signed = builder
                .with_instructions::<dm::InstructionBox>([dm::Log::new(
                    dm::Level::INFO,
                    format!("tx {millis}"),
                )
                .into()])
                .sign(keys.private_key());
            AcceptedTransaction::new_unchecked(std::borrow::Cow::Owned(signed))
        };
        for pair in [[1_000, 1_001], [2_000, 2_001], [3_000, 3_001]] {
            crate::test_utils::commit_native_accepted_inputs(
                &mut chain,
                pair.into_iter().map(signed).collect(),
            );
        }
        let target = CollectionTarget::AccountTransactions(alice.to_string());
        let coordinates = |page: &RowPage| -> Vec<(u64, u64)> {
            page.items
                .iter()
                .map(|row| {
                    assert_eq!(row["authority"].as_str(), Some(alice.to_string().as_str()));
                    (
                        row["block_height"].as_u64().unwrap(),
                        row["block_index"].as_u64().unwrap(),
                    )
                })
                .collect()
        };
        let first = run(&state, &target, ListQuery::new().limit(4))
            .await
            .expect("page");
        let second = run(
            &state,
            &target,
            ListQuery::new()
                .limit(4)
                .cursor(first.next_cursor.clone().expect("more")),
        )
        .await
        .expect("page");
        assert_eq!(second.next_cursor, None);
        let walked: Vec<(u64, u64)> = [coordinates(&first), coordinates(&second)].concat();
        assert_eq!(walked.len(), 6);
        assert!(
            walked.windows(2).all(|pair| pair[0] > pair[1]),
            "newest first: {walked:?}"
        );
        let middle = walked[2].0;
        let ranged = run(
            &state,
            &target,
            ListQuery::new().filter(field("block_height").eq(middle)),
        )
        .await
        .expect("page");
        assert_eq!(coordinates(&ranged), walked[2..4].to_vec());
        assert_eq!(
            ranged.next_cursor, None,
            "the walk stops below the height range"
        );
        let every = run(
            &state,
            &CollectionTarget::Transactions,
            ListQuery::new().limit(100),
        )
        .await
        .expect("page");
        assert!(every.items.len() >= 6);
        let err = run(
            &state,
            &target,
            ListQuery::new().sort_by(SortKey::asc("timestamp_ms")),
        )
        .await
        .expect_err("history order is fixed");
        assert!(matches!(err, Error::CollectionQuery(err) if err.code == "invalid_sort"));

        let mut builder = dm::TransactionBuilder::new(
            network_id,
            alice.clone().into(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(core::time::Duration::from_millis(4_000));
        let movement_tx = builder
            .with_instructions::<dm::InstructionBox>([
                dm::SetKeyValue::account(alice.clone(), "first".parse().unwrap(), "one").into(),
                dm::SetKeyValue::account(alice.clone(), "second".parse().unwrap(), "two").into(),
            ])
            .sign(keys.private_key());
        crate::test_utils::commit_native_accepted_inputs(
            &mut chain,
            vec![AcceptedTransaction::new_unchecked(std::borrow::Cow::Owned(
                movement_tx,
            ))],
        );
        let movements = CollectionTarget::AccountHistory(alice.to_string());
        let base = ListQuery::new()
            .filter(field("block_height").eq(chain.height()))
            .limit(1);
        let first = run(&state, &movements, base.clone())
            .await
            .expect("movement first page");
        assert_eq!(first.items.len(), 1);
        assert_eq!(first.items[0]["movement_index"].as_u64(), Some(1));
        let second = run(
            &state,
            &movements,
            base.clone()
                .cursor(first.next_cursor.expect("second movement")),
        )
        .await
        .expect("movement second page");
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.items[0]["movement_index"].as_u64(), Some(0));
        assert_ne!(first.items[0]["id"], second.items[0]["id"]);
        assert_eq!(second.next_cursor, None);
        let filtered = run(
            &state,
            &movements,
            base.filter(field("movement_index").eq(0)),
        )
        .await
        .expect("movement filter");
        assert_eq!(filtered.items[0]["id"], second.items[0]["id"]);
    }

    #[tokio::test]
    async fn account_filters_take_canonical_ids_and_never_resolve_aliases() {
        let (state, alice, _) = fixture();
        // Alias resolution is permissioned, so a generic filter must not
        // perform it: alias literals are rejected, canonical ids match.
        let err = run(
            &state,
            &CollectionTarget::Accounts,
            ListQuery::new().filter(field("id").eq("alice@wonderland.universal")),
        )
        .await
        .expect_err("alias literal");
        let Error::CollectionQuery(err) = err else {
            panic!("expected a collection error, got {err:?}");
        };
        assert_eq!(err.code, "invalid_filter");
        assert_eq!(err.actual.as_deref(), Some("id"));
        let page = run(
            &state,
            &CollectionTarget::Accounts,
            ListQuery::new().filter(field("id").eq(alice.to_string())),
        )
        .await
        .expect("canonical literal");
        assert_eq!(ids(&page), vec![alice.to_string()]);
    }

    #[tokio::test]
    async fn responses_apply_the_selection() {
        let (state, _, _) = fixture();
        let query = ListQuery::new().select(["id"]).limit(1);
        let page = run(&state, &CollectionTarget::Domains, query.clone())
            .await
            .expect("page");
        assert!(
            page.items[0].contains_key("owned_by"),
            "execution returns full rows"
        );
        let response = execute_collection_response(
            None,
            &state,
            &CollectionTarget::Domains,
            query,
            &MaybeTelemetry::for_tests(),
            &DataspaceReadVisibility::all_for_tests(),
        )
        .await
        .expect("response");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let page: norito::json::Value = norito::json::from_slice(&body).expect("json");
        let item = page["items"][0].as_object().expect("item");
        assert_eq!(item.keys().collect::<Vec<_>>(), ["id"]);
    }

    #[test]
    fn admitted_row_page_refuses_a_missing_original_query_owner() {
        let page = RowPage {
            items: Vec::new(),
            next_cursor: None,
            total: Some(0),
        };
        assert!(row_page_response(page, collections::memory::BytePolicy::canonical()).is_err());
    }

    #[tokio::test]
    async fn row_page_original_body_and_extracted_bytes_retain_the_query_owner() {
        use http_body_util::BodyExt as _;
        const WORKING: usize = 48 * 1024 * 1024;
        let pool = crate::ByteWeightedMemoryPool::new(WORKING).unwrap();
        let memory = crate::QueryFanoutMemoryReservation::from_admitted_fanout(
            pool.try_acquire_parts([WORKING as u64]).unwrap(),
            crate::QueryFanoutMemoryEnvelope::for_body_admission(WORKING).unwrap(),
            pool.generation(),
        )
        .unwrap();
        let owner =
            crate::history_producer::HistoryProducerOwner::from_reservation(&memory).unwrap();
        let page = RowPage {
            items: Vec::new(),
            next_cursor: None,
            total: Some(0),
        };
        let response = owner
            .scope(|| row_page_response(page, collections::memory::BytePolicy::canonical()))
            .unwrap();
        drop(owner);
        drop(memory);
        let (parts, mut body) = response.into_parts();
        drop(parts);
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let clone = bytes.clone();
        drop(body);
        drop(bytes);
        assert!(pool.try_acquire_parts([WORKING as u64]).is_none());
        assert!(
            norito::json::from_slice::<norito::json::Value>(&clone)
                .unwrap()
                .is_object()
        );
        drop(clone);
        assert!(pool.try_acquire_parts([WORKING as u64]).is_some());
    }
}
