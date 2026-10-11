//! Typed lowering of trigger filters, callback bindings and metadata.
//!
//! This owner validates named event matchers and constructs one canonical
//! trigger declaration before the enclosing program admits its entrypoint.

use super::*;

fn trigger_data_family_name(family: TriggerDataFamily) -> &'static str {
    match family {
        TriggerDataFamily::Peer => "peer",
        TriggerDataFamily::Domain => "domain",
        TriggerDataFamily::Account => "account",
        TriggerDataFamily::Asset => "asset",
        TriggerDataFamily::AssetDefinition => "asset_definition",
        TriggerDataFamily::Nft => "nft",
        TriggerDataFamily::Rwa => "rwa",
        TriggerDataFamily::Trigger => "trigger",
        TriggerDataFamily::Role => "role",
        TriggerDataFamily::Configuration => "configuration",
        TriggerDataFamily::Executor => "executor",
    }
}
fn named_data_event_kind(event: &TriggerDataEventKind) -> Option<&str> {
    match event {
        TriggerDataEventKind::Any => None,
        TriggerDataEventKind::Named(kind) => Some(kind.as_str()),
    }
}
fn duplicate_data_matcher_error(
    trigger_name: &str,
    family: TriggerDataFamily,
    key: &str,
) -> SemanticError {
    SemanticError {
        code: "E_TRIGGER_FILTER_DUPLICATE_MATCHER",
        message: format!(
            "trigger `{trigger_name}` has duplicate `{key}` matcher in `{}` data filter",
            trigger_data_family_name(family)
        ),
    }
}
fn invalid_data_matcher_literal<E>(
    trigger_name: &str,
    family: TriggerDataFamily,
    key: &str,
    raw: &str,
    err: E,
) -> SemanticError
where
    E: std::fmt::Display,
{
    SemanticError {
        code: "E_TRIGGER_FILTER_INVALID_LITERAL",
        message: format!(
            "trigger `{trigger_name}` has invalid `{key}` matcher literal `{raw}` in `{}` data filter: {err}",
            trigger_data_family_name(family)
        ),
    }
}
fn unsupported_data_matcher_error(
    trigger_name: &str,
    family: TriggerDataFamily,
    key: &str,
) -> SemanticError {
    SemanticError {
        code: "E_TRIGGER_FILTER_UNSUPPORTED_MATCHER",
        message: format!(
            "trigger `{trigger_name}` does not support `{key}` matcher in `{}` data filter",
            trigger_data_family_name(family)
        ),
    }
}
fn unsupported_data_event_kind_error(
    trigger_name: &str,
    family: TriggerDataFamily,
    kind: &str,
) -> SemanticError {
    SemanticError {
        code: "E_TRIGGER_FILTER_UNSUPPORTED_EVENT",
        message: format!(
            "trigger `{trigger_name}` does not support `{kind}` event kind for `{}` data filter",
            trigger_data_family_name(family)
        ),
    }
}
fn parse_peer_matcher(
    trigger_name: &str,
    family: TriggerDataFamily,
    raw: &str,
) -> Result<PeerId, SemanticError> {
    raw.parse()
        .map_err(|err| invalid_data_matcher_literal(trigger_name, family, "peer", raw, err))
}
fn parse_domain_matcher(
    trigger_name: &str,
    family: TriggerDataFamily,
    raw: &str,
) -> Result<DomainId, SemanticError> {
    DomainId::parse_fully_qualified(raw)
        .map_err(|err| invalid_data_matcher_literal(trigger_name, family, "domain", raw, err))
}
fn parse_account_matcher(
    trigger_name: &str,
    family: TriggerDataFamily,
    raw: &str,
) -> Result<AccountId, SemanticError> {
    AccountId::parse_encoded(raw)
        .map_err(|err| invalid_data_matcher_literal(trigger_name, family, "account", raw, err))
}
fn parse_asset_matcher(
    trigger_name: &str,
    family: TriggerDataFamily,
    raw: &str,
) -> Result<AssetId, SemanticError> {
    raw.parse()
        .map_err(|err| invalid_data_matcher_literal(trigger_name, family, "asset", raw, err))
}
fn parse_asset_definition_matcher(
    trigger_name: &str,
    family: TriggerDataFamily,
    raw: &str,
) -> Result<AssetDefinitionId, SemanticError> {
    raw.parse().map_err(|err| {
        invalid_data_matcher_literal(trigger_name, family, "asset_definition", raw, err)
    })
}
fn parse_nft_matcher(
    trigger_name: &str,
    family: TriggerDataFamily,
    raw: &str,
) -> Result<NftId, SemanticError> {
    raw.parse()
        .map_err(|err| invalid_data_matcher_literal(trigger_name, family, "nft", raw, err))
}
fn parse_rwa_matcher(
    trigger_name: &str,
    family: TriggerDataFamily,
    raw: &str,
) -> Result<RwaId, SemanticError> {
    raw.parse()
        .map_err(|err| invalid_data_matcher_literal(trigger_name, family, "rwa", raw, err))
}
fn parse_trigger_matcher(
    trigger_name: &str,
    family: TriggerDataFamily,
    raw: &str,
) -> Result<TriggerId, SemanticError> {
    raw.parse()
        .map_err(|err| invalid_data_matcher_literal(trigger_name, family, "trigger", raw, err))
}
fn parse_role_matcher(
    trigger_name: &str,
    family: TriggerDataFamily,
    raw: &str,
) -> Result<RoleId, SemanticError> {
    raw.parse()
        .map_err(|err| invalid_data_matcher_literal(trigger_name, family, "role", raw, err))
}
fn lower_structured_data_filter(
    trigger_name: &str,
    filter: &TriggerStructuredDataFilter,
) -> Result<DataEventFilter, SemanticError> {
    match filter.family {
        TriggerDataFamily::Peer => {
            let mut peer =
                PeerEventFilter::new().for_events(match named_data_event_kind(&filter.event) {
                    None => PeerEventSet::all(),
                    Some("added") => PeerEventSet::Added,
                    Some("removed") => PeerEventSet::Removed,
                    Some(kind) => {
                        return Err(unsupported_data_event_kind_error(
                            trigger_name,
                            filter.family,
                            kind,
                        ));
                    }
                });
            let mut seen_peer = false;
            for matcher in &filter.matchers {
                match matcher.key.as_str() {
                    "peer" => {
                        if seen_peer {
                            return Err(duplicate_data_matcher_error(
                                trigger_name,
                                filter.family,
                                "peer",
                            ));
                        }
                        peer = peer.for_peer(parse_peer_matcher(
                            trigger_name,
                            filter.family,
                            &matcher.value,
                        )?);
                        seen_peer = true;
                    }
                    key => {
                        return Err(unsupported_data_matcher_error(
                            trigger_name,
                            filter.family,
                            key,
                        ));
                    }
                }
            }
            Ok(DataEventFilter::Peer(peer))
        }
        TriggerDataFamily::Domain => {
            let mut domain =
                DomainEventFilter::new().for_events(match named_data_event_kind(&filter.event) {
                    None => DomainEventSet::all(),
                    Some("created") => DomainEventSet::Created,
                    Some("deleted") => DomainEventSet::Deleted,
                    Some("asset_definition") => DomainEventSet::AssetDefinition,
                    Some("asset") => DomainEventSet::Asset,
                    Some("nft") => DomainEventSet::AnyNft,
                    Some("account") => DomainEventSet::Account,
                    Some("account_linked") => DomainEventSet::AccountLinked,
                    Some("account_unlinked") => DomainEventSet::AccountUnlinked,
                    Some("metadata_inserted") => DomainEventSet::MetadataInserted,
                    Some("metadata_removed") => DomainEventSet::MetadataRemoved,
                    Some("owner_changed") => DomainEventSet::OwnerChanged,
                    Some("kaigi_roster_summary") => DomainEventSet::KaigiRosterSummary,
                    Some("kaigi_relay_registered") => DomainEventSet::KaigiRelayRegistered,
                    Some("kaigi_relay_manifest_updated") => {
                        DomainEventSet::KaigiRelayManifestUpdated
                    }
                    Some("kaigi_usage_summary") => DomainEventSet::KaigiUsageSummary,
                    Some("kaigi_relay_health_updated") => DomainEventSet::KaigiRelayHealthUpdated,
                    Some("streaming_ticket_ready") => DomainEventSet::StreamingTicketReady,
                    Some("streaming_ticket_revoked") => DomainEventSet::StreamingTicketRevoked,
                    Some(kind) => {
                        return Err(unsupported_data_event_kind_error(
                            trigger_name,
                            filter.family,
                            kind,
                        ));
                    }
                });
            let mut seen_domain = false;
            for matcher in &filter.matchers {
                match matcher.key.as_str() {
                    "domain" => {
                        if seen_domain {
                            return Err(duplicate_data_matcher_error(
                                trigger_name,
                                filter.family,
                                "domain",
                            ));
                        }
                        domain = domain.for_domain(parse_domain_matcher(
                            trigger_name,
                            filter.family,
                            &matcher.value,
                        )?);
                        seen_domain = true;
                    }
                    key => {
                        return Err(unsupported_data_matcher_error(
                            trigger_name,
                            filter.family,
                            key,
                        ));
                    }
                }
            }
            Ok(DataEventFilter::Domain(domain))
        }
        TriggerDataFamily::Account => {
            let mut account =
                AccountEventFilter::new().for_events(match named_data_event_kind(&filter.event) {
                    None => AccountEventSet::all(),
                    Some("created") => AccountEventSet::Created,
                    Some("deleted") => AccountEventSet::Deleted,
                    Some("permission_added") => AccountEventSet::PermissionAdded,
                    Some("permission_removed") => AccountEventSet::PermissionRemoved,
                    Some("role_granted") => AccountEventSet::RoleGranted,
                    Some("role_revoked") => AccountEventSet::RoleRevoked,
                    Some("metadata_inserted") => AccountEventSet::MetadataInserted,
                    Some("metadata_removed") => AccountEventSet::MetadataRemoved,
                    Some("repo") => AccountEventSet::AnyRepo,
                    Some(kind) => {
                        return Err(unsupported_data_event_kind_error(
                            trigger_name,
                            filter.family,
                            kind,
                        ));
                    }
                });
            let mut seen_account = false;
            for matcher in &filter.matchers {
                match matcher.key.as_str() {
                    "account" => {
                        if seen_account {
                            return Err(duplicate_data_matcher_error(
                                trigger_name,
                                filter.family,
                                "account",
                            ));
                        }
                        account = account.for_account(parse_account_matcher(
                            trigger_name,
                            filter.family,
                            &matcher.value,
                        )?);
                        seen_account = true;
                    }
                    key => {
                        return Err(unsupported_data_matcher_error(
                            trigger_name,
                            filter.family,
                            key,
                        ));
                    }
                }
            }
            Ok(DataEventFilter::Account(account))
        }
        TriggerDataFamily::Asset => {
            let mut asset =
                AssetEventFilter::new().for_events(match named_data_event_kind(&filter.event) {
                    None => AssetEventSet::all(),
                    Some("created") => AssetEventSet::Created,
                    Some("deleted") => AssetEventSet::Deleted,
                    Some("added") => AssetEventSet::Added,
                    Some("removed") => AssetEventSet::Removed,
                    Some("transferred") => AssetEventSet::Transferred,
                    Some("metadata_inserted") => AssetEventSet::MetadataInserted,
                    Some("metadata_removed") => AssetEventSet::MetadataRemoved,
                    Some(kind) => {
                        return Err(unsupported_data_event_kind_error(
                            trigger_name,
                            filter.family,
                            kind,
                        ));
                    }
                });
            let mut seen_asset = false;
            let mut seen_asset_definition = false;
            let mut seen_source_account = false;
            let mut seen_destination_account = false;
            for matcher in &filter.matchers {
                match matcher.key.as_str() {
                    "asset" => {
                        if seen_asset {
                            return Err(duplicate_data_matcher_error(
                                trigger_name,
                                filter.family,
                                "asset",
                            ));
                        }
                        asset = asset.for_asset(parse_asset_matcher(
                            trigger_name,
                            filter.family,
                            &matcher.value,
                        )?);
                        seen_asset = true;
                    }
                    "asset_definition" => {
                        if seen_asset_definition {
                            return Err(duplicate_data_matcher_error(
                                trigger_name,
                                filter.family,
                                "asset_definition",
                            ));
                        }
                        asset = asset.for_asset_definition(parse_asset_definition_matcher(
                            trigger_name,
                            filter.family,
                            &matcher.value,
                        )?);
                        seen_asset_definition = true;
                    }
                    "source_account" => {
                        if seen_source_account {
                            return Err(duplicate_data_matcher_error(
                                trigger_name,
                                filter.family,
                                "source_account",
                            ));
                        }
                        asset = asset.for_transfer_source_account(parse_account_matcher(
                            trigger_name,
                            filter.family,
                            &matcher.value,
                        )?);
                        seen_source_account = true;
                    }
                    "destination_account" => {
                        if seen_destination_account {
                            return Err(duplicate_data_matcher_error(
                                trigger_name,
                                filter.family,
                                "destination_account",
                            ));
                        }
                        asset = asset.for_transfer_destination_account(parse_account_matcher(
                            trigger_name,
                            filter.family,
                            &matcher.value,
                        )?);
                        seen_destination_account = true;
                    }
                    key => {
                        return Err(unsupported_data_matcher_error(
                            trigger_name,
                            filter.family,
                            key,
                        ));
                    }
                }
            }
            Ok(DataEventFilter::Asset(asset))
        }
        TriggerDataFamily::AssetDefinition => {
            let mut asset_definition = AssetDefinitionEventFilter::new().for_events(
                match named_data_event_kind(&filter.event) {
                    None => AssetDefinitionEventSet::all(),
                    Some("created") => AssetDefinitionEventSet::Created,
                    Some("deleted") => AssetDefinitionEventSet::Deleted,
                    Some("metadata_inserted") => AssetDefinitionEventSet::MetadataInserted,
                    Some("metadata_removed") => AssetDefinitionEventSet::MetadataRemoved,
                    Some("mintability_changed") => AssetDefinitionEventSet::MintabilityChanged,
                    Some("mintability_changed_detailed") => {
                        AssetDefinitionEventSet::MintabilityChangedDetailed
                    }
                    Some("total_quantity_changed") => AssetDefinitionEventSet::TotalQuantityChanged,
                    Some("owner_changed") => AssetDefinitionEventSet::OwnerChanged,
                    Some(kind) => {
                        return Err(unsupported_data_event_kind_error(
                            trigger_name,
                            filter.family,
                            kind,
                        ));
                    }
                },
            );
            let mut seen_asset_definition = false;
            for matcher in &filter.matchers {
                match matcher.key.as_str() {
                    "asset_definition" => {
                        if seen_asset_definition {
                            return Err(duplicate_data_matcher_error(
                                trigger_name,
                                filter.family,
                                "asset_definition",
                            ));
                        }
                        asset_definition =
                            asset_definition.for_asset_definition(parse_asset_definition_matcher(
                                trigger_name,
                                filter.family,
                                &matcher.value,
                            )?);
                        seen_asset_definition = true;
                    }
                    key => {
                        return Err(unsupported_data_matcher_error(
                            trigger_name,
                            filter.family,
                            key,
                        ));
                    }
                }
            }
            Ok(DataEventFilter::AssetDefinition(asset_definition))
        }
        TriggerDataFamily::Nft => {
            let mut nft =
                NftEventFilter::new().for_events(match named_data_event_kind(&filter.event) {
                    None => NftEventSet::all(),
                    Some("created") => NftEventSet::Created,
                    Some("deleted") => NftEventSet::Deleted,
                    Some("metadata_inserted") => NftEventSet::MetadataInserted,
                    Some("metadata_removed") => NftEventSet::MetadataRemoved,
                    Some("owner_changed") => NftEventSet::OwnerChanged,
                    Some(kind) => {
                        return Err(unsupported_data_event_kind_error(
                            trigger_name,
                            filter.family,
                            kind,
                        ));
                    }
                });
            let mut seen_nft = false;
            for matcher in &filter.matchers {
                match matcher.key.as_str() {
                    "nft" => {
                        if seen_nft {
                            return Err(duplicate_data_matcher_error(
                                trigger_name,
                                filter.family,
                                "nft",
                            ));
                        }
                        nft = nft.for_nft(parse_nft_matcher(
                            trigger_name,
                            filter.family,
                            &matcher.value,
                        )?);
                        seen_nft = true;
                    }
                    key => {
                        return Err(unsupported_data_matcher_error(
                            trigger_name,
                            filter.family,
                            key,
                        ));
                    }
                }
            }
            Ok(DataEventFilter::Nft(nft))
        }
        TriggerDataFamily::Rwa => {
            let mut rwa =
                RwaEventFilter::new().for_events(match named_data_event_kind(&filter.event) {
                    None => RwaEventSet::all(),
                    Some("created") => RwaEventSet::Created,
                    Some("metadata_inserted") => RwaEventSet::MetadataInserted,
                    Some("metadata_removed") => RwaEventSet::MetadataRemoved,
                    Some("owner_changed") => RwaEventSet::OwnerChanged,
                    Some("split") => RwaEventSet::Split,
                    Some("merged") => RwaEventSet::Merged,
                    Some("redeemed") => RwaEventSet::Redeemed,
                    Some("frozen") => RwaEventSet::Frozen,
                    Some("unfrozen") => RwaEventSet::Unfrozen,
                    Some("held") => RwaEventSet::Held,
                    Some("released") => RwaEventSet::Released,
                    Some("force_transferred") => RwaEventSet::ForceTransferred,
                    Some("controls_changed") => RwaEventSet::ControlsChanged,
                    Some(kind) => {
                        return Err(unsupported_data_event_kind_error(
                            trigger_name,
                            filter.family,
                            kind,
                        ));
                    }
                });
            let mut seen_rwa = false;
            for matcher in &filter.matchers {
                match matcher.key.as_str() {
                    "rwa" => {
                        if seen_rwa {
                            return Err(duplicate_data_matcher_error(
                                trigger_name,
                                filter.family,
                                "rwa",
                            ));
                        }
                        rwa = rwa.for_rwa(parse_rwa_matcher(
                            trigger_name,
                            filter.family,
                            &matcher.value,
                        )?);
                        seen_rwa = true;
                    }
                    key => {
                        return Err(unsupported_data_matcher_error(
                            trigger_name,
                            filter.family,
                            key,
                        ));
                    }
                }
            }
            Ok(DataEventFilter::Rwa(rwa))
        }
        TriggerDataFamily::Trigger => {
            let mut trigger =
                TriggerEventFilter::new().for_events(match named_data_event_kind(&filter.event) {
                    None => TriggerEventSet::all(),
                    Some("created") => TriggerEventSet::Created,
                    Some("deleted") => TriggerEventSet::Deleted,
                    Some("extended") => TriggerEventSet::Extended,
                    Some("shortened") => TriggerEventSet::Shortened,
                    Some("metadata_inserted") => TriggerEventSet::MetadataInserted,
                    Some("metadata_removed") => TriggerEventSet::MetadataRemoved,
                    Some(kind) => {
                        return Err(unsupported_data_event_kind_error(
                            trigger_name,
                            filter.family,
                            kind,
                        ));
                    }
                });
            let mut seen_trigger = false;
            for matcher in &filter.matchers {
                match matcher.key.as_str() {
                    "trigger" => {
                        if seen_trigger {
                            return Err(duplicate_data_matcher_error(
                                trigger_name,
                                filter.family,
                                "trigger",
                            ));
                        }
                        trigger = trigger.for_trigger(parse_trigger_matcher(
                            trigger_name,
                            filter.family,
                            &matcher.value,
                        )?);
                        seen_trigger = true;
                    }
                    key => {
                        return Err(unsupported_data_matcher_error(
                            trigger_name,
                            filter.family,
                            key,
                        ));
                    }
                }
            }
            Ok(DataEventFilter::Trigger(trigger))
        }
        TriggerDataFamily::Role => {
            let mut role =
                RoleEventFilter::new().for_events(match named_data_event_kind(&filter.event) {
                    None => RoleEventSet::all(),
                    Some("created") => RoleEventSet::Created,
                    Some("deleted") => RoleEventSet::Deleted,
                    Some("permission_added") => RoleEventSet::PermissionAdded,
                    Some("permission_removed") => RoleEventSet::PermissionRemoved,
                    Some(kind) => {
                        return Err(unsupported_data_event_kind_error(
                            trigger_name,
                            filter.family,
                            kind,
                        ));
                    }
                });
            let mut seen_role = false;
            for matcher in &filter.matchers {
                match matcher.key.as_str() {
                    "role" => {
                        if seen_role {
                            return Err(duplicate_data_matcher_error(
                                trigger_name,
                                filter.family,
                                "role",
                            ));
                        }
                        role = role.for_role(parse_role_matcher(
                            trigger_name,
                            filter.family,
                            &matcher.value,
                        )?);
                        seen_role = true;
                    }
                    key => {
                        return Err(unsupported_data_matcher_error(
                            trigger_name,
                            filter.family,
                            key,
                        ));
                    }
                }
            }
            Ok(DataEventFilter::Role(role))
        }
        TriggerDataFamily::Configuration => {
            let configuration = ConfigurationEventFilter::new().for_events(
                match named_data_event_kind(&filter.event) {
                    None => ConfigurationEventSet::all(),
                    Some("changed") => ConfigurationEventSet::Changed,
                    Some(kind) => {
                        return Err(unsupported_data_event_kind_error(
                            trigger_name,
                            filter.family,
                            kind,
                        ));
                    }
                },
            );
            if let Some(matcher) = filter.matchers.first() {
                return Err(unsupported_data_matcher_error(
                    trigger_name,
                    filter.family,
                    &matcher.key,
                ));
            }
            Ok(DataEventFilter::Configuration(configuration))
        }
        TriggerDataFamily::Executor => {
            let executor =
                ExecutorEventFilter::new().for_events(match named_data_event_kind(&filter.event) {
                    None => ExecutorEventSet::all(),
                    Some("upgraded") => ExecutorEventSet::Upgraded,
                    Some(kind) => {
                        return Err(unsupported_data_event_kind_error(
                            trigger_name,
                            filter.family,
                            kind,
                        ));
                    }
                });
            if let Some(matcher) = filter.matchers.first() {
                return Err(unsupported_data_matcher_error(
                    trigger_name,
                    filter.family,
                    &matcher.key,
                ));
            }
            Ok(DataEventFilter::Executor(executor))
        }
    }
}
pub(super) fn analyze_trigger(
    context: &SemanticContext,
    trigger: &TriggerDecl,
) -> Result<TypedTrigger, SemanticError> {
    let name =
        <Name as std::str::FromStr>::from_str(&trigger.name).map_err(|err| SemanticError {
            code: "E_TRIGGER_INVALID_NAME",
            message: format!("invalid trigger name `{}`: {}", trigger.name, err),
        })?;
    let id = TriggerId::new(name);
    let entry = &trigger.call.entrypoint;
    if entry.contains("::") {
        return Err(SemanticError {
            code: "E_TRIGGER_TARGET_NAMESPACE",
            message: "trigger callbacks must name a local kotoage function; namespaced callbacks require an authenticated seiyaku interface".into(),
        });
    }
    let modifiers = context
        .function_modifiers
        .borrow()
        .get(entry)
        .cloned()
        .ok_or_else(|| SemanticError {
            code: "K2002",
            message: format!(
                "trigger `{}` targets unknown `kotoage`/`言挙げ` function `{entry}`",
                trigger.name
            ),
        })?;
    if modifiers.kind == FunctionKind::View {
        return Err(SemanticError {
            code: "E_TRIGGER_VIEW_TARGET",
            message: format!(
                "trigger `{}` cannot target read-only `view fn` function `{entry}`",
                trigger.name
            ),
        });
    }
    if modifiers.kind != FunctionKind::Kotoage {
        return Err(SemanticError {
            code: "E_TRIGGER_TARGET_KIND",
            message: format!(
                "trigger `{}` must call a `kotoage`/`言挙げ` function `{entry}`",
                trigger.name
            ),
        });
    }
    let has_parameters = !context
        .function_params
        .borrow()
        .get(entry)
        .expect("declared trigger callback has a signature")
        .is_empty();
    if !matches!(trigger.filter, TriggerFilter::Execute { .. }) && has_parameters {
        return Err(SemanticError {
            code: "E_TRIGGER_CALLBACK_PARAMETERS",
            message: format!(
                "trigger `{}` requires `{entry}()` without parameters; time, data, and pipeline events do not provide a typed callback argument record; read event data with `context::trigger_event()`",
                trigger.name
            ),
        });
    }
    let filter = match &trigger.filter {
        TriggerFilter::Time(time) => {
            let execution = match time {
                TriggerTimeFilter::PreCommit => ExecutionTime::PreCommit,
                TriggerTimeFilter::Schedule {
                    start_ms,
                    period_ms,
                } => {
                    let start_ms = schedule_milliseconds(context, start_ms, "start_ms", false)?;
                    let period_ms = period_ms
                        .as_ref()
                        .map(|value| schedule_milliseconds(context, value, "period_ms", true))
                        .transpose()?;
                    ExecutionTime::Schedule(Schedule {
                        start_ms,
                        period_ms,
                    })
                }
            };
            EventFilterBox::Time(TimeEventFilter(execution))
        }
        TriggerFilter::Execute { trigger_id } => {
            let target =
                <Name as std::str::FromStr>::from_str(trigger_id).map_err(|err| SemanticError {
                    code: "E_TRIGGER_INVALID_ID",
                    message: format!("invalid execute trigger id `{trigger_id}`: {err}"),
                })?;
            let id = TriggerId::new(target);
            EventFilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new().for_trigger(id))
        }
        TriggerFilter::Data(data) => {
            let filter = match data {
                TriggerDataFilter::Any => DataEventFilter::Any,
                TriggerDataFilter::Structured(filter) => {
                    lower_structured_data_filter(&trigger.name, filter)?
                }
            };
            EventFilterBox::Data(filter)
        }
        TriggerFilter::Pipeline(pipeline) => {
            let filter = match pipeline {
                TriggerPipelineFilter::TransactionApproved => PipelineEventFilterBox::Transaction(
                    TransactionEventFilter::new().for_status(TransactionStatus::Approved),
                ),
                TriggerPipelineFilter::BlockApproved => PipelineEventFilterBox::Block(
                    BlockEventFilter::new().for_status(BlockStatus::Approved),
                ),
            };
            EventFilterBox::Pipeline(filter)
        }
    };
    let repeats = match trigger
        .repeats
        .clone()
        .unwrap_or(TriggerRepeats::Indefinitely)
    {
        TriggerRepeats::Indefinitely => Repeats::Indefinitely,
        TriggerRepeats::Exactly(count) => Repeats::Exactly(count),
    };
    let authority = match &trigger.authority {
        Some(raw) => Some(AccountId::parse_encoded(raw).map_err(|err| SemanticError {
            code: "E_TRIGGER_INVALID_AUTHORITY",
            message: format!("invalid trigger authority `{raw}`: {err}"),
        })?),
        None => None,
    };
    let metadata = trigger_metadata_from_entries(&trigger.metadata)?;
    Ok(TypedTrigger {
        id,
        call: trigger.call.clone(),
        filter,
        repeats,
        authority,
        metadata,
    })
}
fn schedule_milliseconds(
    context: &SemanticContext,
    expression: &Expr,
    label: &str,
    nonzero: bool,
) -> Result<u64, SemanticError> {
    let evaluated = static_integer_constant(context, expression).map_err(|_| SemanticError {
        code: "E_TRIGGER_SCHEDULE_CONSTANT",
        message: format!(
            "schedule `{label}` must be a compile-time int constant expression in milliseconds"
        ),
    });
    let result = evaluated.and_then(|typed| {
        let ExprKind::IntLiteral(value) = typed.kind() else {
            unreachable!("constant integer evaluator")
        };
        value
            .try_to_u64()
            .filter(|value| !nonzero || *value != 0)
            .ok_or_else(|| SemanticError {
                code: if nonzero {
                    "E_TRIGGER_SCHEDULE_PERIOD"
                } else {
                    "E_TRIGGER_SCHEDULE_START"
                },
                message: format!(
                    "schedule `{label}` must be in {}..=18446744073709551615 milliseconds",
                    u8::from(nonzero)
                ),
            })
    });
    if result.is_err() {
        context.capture_diagnostic(context.expression_source(expression), None);
    }
    result
}
fn trigger_metadata_from_entries(
    entries: &[TriggerMetadataEntry],
) -> Result<Metadata, SemanticError> {
    let mut metadata = Metadata::default();
    for entry in entries {
        let key =
            <Name as std::str::FromStr>::from_str(&entry.key).map_err(|err| SemanticError {
                code: "E_TRIGGER_INVALID_METADATA_KEY",
                message: format!("invalid trigger metadata key `{}`: {err}", entry.key),
            })?;
        let json = json_from_expr(&entry.value)?;
        if metadata.insert(key, json).is_some() {
            return Err(SemanticError {
                code: "K2001",
                message: format!("duplicate trigger metadata key `{}`", entry.key),
            });
        }
    }
    Ok(metadata)
}
