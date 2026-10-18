fn alias_grace_until_ms(lease_expiry_ms: Option<u64>) -> Option<u64> {
    lease_expiry_ms.map(|expiry| expiry.saturating_add(ASSET_ALIAS_GRACE_MS))
}
fn validate_alias_for_asset_definition(
    alias: Option<&AssetDefinitionAlias>,
    definition: &AssetDefinition,
) -> Result<(), InstructionExecutionError> {
    validate_asset_alias_against_names(alias, [definition.name().as_str()]).map_err(|err| {
        InstructionExecutionError::InvariantViolation(
            format!("invalid asset definition alias: {err}").into(),
        )
    })
}
fn dataspace_id_for_alias_segment(
    state_transaction: &mut StateTransaction<'_, '_>,
    dataspace_alias: &str,
) -> Result<Option<DataSpaceId>, InstructionExecutionError> {
    match crate::sns::resolve_active_dataspace_id_by_alias(
        &state_transaction.world,
        &state_transaction.nexus.dataspace_catalog,
        dataspace_alias,
        state_transaction.block_unix_timestamp_ms(),
    ) {
        Ok(id) => Ok(Some(id)),
        Err(crate::sns::SnsError::NotFound(_)) => Ok(None),
        Err(error) => Err(error.retain_in_instruction(state_transaction)),
    }
}
fn asset_definition_home_dataspace(
    state_transaction: &mut StateTransaction<'_, '_>,
    definition: &AssetDefinition,
) -> Result<Option<DataSpaceId>, InstructionExecutionError> {
    if let Some(dataspace_id) = state_transaction
        .world
        .asset_definition_dataspace(definition.id())
        .map_err(|error| {
            InstructionExecutionError::InvariantViolation(
                format!("invalid authoritative asset definition home: {error}").into(),
            )
        })?
    {
        if definition.owning_domain().is_some() {
            return Err(InstructionExecutionError::InvariantViolation(
                "asset definition has conflicting domain and dataspace homes".into(),
            ));
        }
        return Ok(Some(dataspace_id));
    }
    match definition.owning_domain() {
        Some(domain) => {
            dataspace_id_for_alias_segment(state_transaction, domain.dataspace().as_ref())
        }
        None => Ok(Some(DataSpaceId::UNIVERSAL)),
    }
}
/// General restricted-home refusal, shared by the direct and domain paths.
///
/// Keep this text stable: the post-reset replay qualification scans committed rejections for it.
const RESTRICTED_HOME_REFUSAL: &str =
    "direct-dataspace registration currently requires a public home dataspace";
/// Refuse a home that a definition with this balance policy may not use.
///
/// Global definitions never use restricted homes. A dataspace-restricted definition may
/// use the sole restricted home of its authenticated independent private root, with both
/// original route coordinates and the canonical physical geometry. General restricted
/// homes on a global root remain refused until their complete read/write boundary ships.
// TODO: general restricted homes on Global roots still need complete route-scoped read/write qualification.
fn ensure_home_admissible(
    state_transaction: &mut StateTransaction<'_, '_>,
    definition_id: &AssetDefinitionId,
    balance_scope_policy: AssetBalancePolicy,
    home_dataspace: DataSpaceId,
) -> Result<(), InstructionExecutionError> {
    if !crate::read_scope::dataspace_is_restricted(
        &state_transaction.nexus.lane_catalog,
        home_dataspace,
    ) {
        return Ok(());
    }
    let refusal = || {
        InstructionExecutionError::InvariantViolation(
            match balance_scope_policy {
                AssetBalancePolicy::Global => format!(
                    "global asset definition {definition_id} cannot be registered in restricted dataspace {}; use DataspaceRestricted balance policy",
                    home_dataspace.as_u64()
                ),
                AssetBalancePolicy::DataspaceRestricted => RESTRICTED_HOME_REFUSAL.to_owned(),
            }
            .into(),
        )
    };
    if balance_scope_policy == AssetBalancePolicy::Global {
        return Err(refusal());
    }
    // This owner retains any original local decoder refusal before the ISI error bridge.
    // No local geometry, header or SNS owner can replace the authenticated root source.
    if !cfg!(all(test, sumeragi_core_mutation = "HC207")) {
        let scope = crate::executor::root_scope::execution_root_scope(state_transaction)
            .map_err(|_| refusal())?;
        if !matches!(scope, iroha_data_model::block::consensus::SumeragiRootScope::Dataspace { dataspace_id, .. } if dataspace_id == home_dataspace)
        {
            return Err(refusal());
        }
    }
    if !cfg!(all(test, sumeragi_core_mutation = "HC208"))
        && (state_transaction.current_dataspace_id != Some(home_dataspace)
            || state_transaction.world.current_dataspace_id != Some(home_dataspace))
    {
        return Err(refusal());
    }
    if cfg!(all(test, sumeragi_core_mutation = "HC209")) {
        return Ok(());
    }
    if state_transaction.world.dataspace_catalog != state_transaction.nexus.dataspace_catalog {
        return Err(refusal());
    }
    state_transaction
        .nexus
        .validate_private_root_geometry(home_dataspace)
        .map_err(|_| refusal())
}
/// Keep an alias inside its definition's namespace whenever either side is restricted.
///
/// A public definition may carry an alias in another public namespace, but an alias that names
/// a restricted dataspace, or a definition homed in one, must name exactly the home.
fn ensure_alias_namespace_matches_home(
    state_transaction: &StateTransaction<'_, '_>,
    alias: &AssetDefinitionAlias,
    alias_dataspace: DataSpaceId,
    home_dataspace: DataSpaceId,
) -> Result<(), InstructionExecutionError> {
    let catalog = &state_transaction.nexus.lane_catalog;
    if alias_dataspace != home_dataspace
        && (crate::read_scope::dataspace_is_restricted(catalog, alias_dataspace)
            || crate::read_scope::dataspace_is_restricted(catalog, home_dataspace))
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "asset definition alias `{alias}` must use home dataspace {}: a restricted dataspace namespace cannot alias another dataspace",
                home_dataspace.as_u64()
            )
            .into(),
        ));
    }
    Ok(())
}
fn ensure_asset_definition_registered_on_authoritative_route(
    state_transaction: &mut StateTransaction<'_, '_>,
    definition: &AssetDefinition,
) -> Result<(), InstructionExecutionError> {
    let home_dataspace = asset_definition_home_dataspace(state_transaction, definition)?
        .ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                format!(
                    "asset definition {} owning domain has no active dataspace",
                    definition.id()
                )
                .into(),
            )
        })?;
    ensure_home_admissible(
        state_transaction,
        definition.id(),
        definition.balance_scope_policy(),
        home_dataspace,
    )?;
    let route_dataspace = state_transaction
        .current_dataspace_id
        .or(state_transaction.world.current_dataspace_id);
    if let Some(route_dataspace) = route_dataspace
        && route_dataspace != home_dataspace
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "global asset definition {} must be registered on its authoritative dataspace {}; current route is {}",
                definition.id(),
                home_dataspace.as_u64(),
                route_dataspace.as_u64()
            )
            .into(),
        ));
    }
    Ok(())
}
/// Restore or retarget the continuity record for an already validated alias binding.
///
/// # Errors
///
/// Returns an invariant violation when persisted continuity state is malformed.
pub(crate) fn upsert_account_rekey_record(
    state_transaction: &mut StateTransaction<'_, '_>,
    label: &AccountAlias,
    account: &AccountId,
) -> Result<(), InstructionExecutionError> {
    let record = match state_transaction
        .world
        .account_rekey_records
        .get(label)
        .cloned()
    {
        Some(record) => {
            if &record.label != label {
                return Err(InstructionExecutionError::InvariantViolation(
                    "cannot reassign an account alias with a mismatched continuity record".into(),
                ));
            }
            record
                .reassign_alias_to_account(account.clone())
                .map_err(|error| {
                    InstructionExecutionError::InvariantViolation(
                        format!("cannot reassign malformed account alias history: {error}").into(),
                    )
                })?
        }
        None => AccountRekeyRecord::new(label.clone(), account.clone()),
    };
    state_transaction.world.replace_account_rekey_record(record);
    Ok(())
}
/// Restore only the missing binding/index state of an exact account-alias setup intent.
///
/// The declarative classifier must run immediately before this helper. The checks here are
/// repeated defensively so repair can never overwrite a different binding or primary alias.
pub(crate) fn repair_account_alias_setup_state(
    state_transaction: &mut StateTransaction<'_, '_>,
    intent: &AliasAccountIntentV1,
) -> Result<(), InstructionExecutionError> {
    let alias = intent.alias.account_alias();
    if account_label_is_pii(&alias) {
        return Err(InstructionExecutionError::InvariantViolation(
            "Account alias looks like raw PII; use UAID/opaque identifiers instead"
                .to_owned()
                .into(),
        ));
    }
    let current_primary = state_transaction
        .world
        .account(&intent.target_account)?
        .label()
        .cloned();
    match (intent.role, current_primary.as_ref()) {
        (AccountAliasRoleV1::Primary, Some(existing)) if existing != &alias => {
            return Err(InstructionExecutionError::InvariantViolation(
                "alias.primary.conflict: target account has a different primary alias"
                    .to_owned()
                    .into(),
            ));
        }
        (AccountAliasRoleV1::Additional, Some(existing)) if existing == &alias => {
            return Err(InstructionExecutionError::InvariantViolation(
                "alias.primary.conflict: alias is primary but was requested as additional"
                    .to_owned()
                    .into(),
            ));
        }
        _ => {}
    }
    if let Some(existing) = state_transaction.world.account_aliases.get(&alias)
        && existing != &intent.target_account
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "alias.binding.conflict: account alias is already bound to another account"
                .to_owned()
                .into(),
        ));
    }
    if let Some(record) = state_transaction.world.account_rekey_records.get(&alias)
        && record.active_account_id != intent.target_account
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "alias.binding.conflict: account rekey record targets another account"
                .to_owned()
                .into(),
        ));
    }
    ensure_single_sbp_retail_fi_home(state_transaction, &intent.target_account, &alias)?;
    ensure_contract_alias_namespace_available(state_transaction, &alias)?;
    state_transaction
        .world
        .insert_account_alias_binding(alias.clone(), intent.target_account.clone());
    upsert_account_rekey_record(state_transaction, &alias, &intent.target_account)?;
    if matches!(intent.role, AccountAliasRoleV1::Primary) && current_primary.is_none() {
        state_transaction
            .world
            .account_mut(&intent.target_account)?
            .set_label(Some(alias));
    }
    Ok(())
}
pub(super) fn purge_stale_account_label_state(
    state_transaction: &mut StateTransaction<'_, '_>,
    label: &AccountAlias,
) -> Result<(), InstructionExecutionError> {
    let existing_binding_owner = state_transaction.world.account_aliases.get(label).cloned();
    let existing_rekey_record = state_transaction
        .world
        .account_rekey_records
        .get(label)
        .cloned();
    let stale_binding_owner = existing_binding_owner
        .as_ref()
        .filter(|existing_owner| state_transaction.world.account(existing_owner).is_err());
    let stale_rekey_record = existing_rekey_record.as_ref().filter(|record| {
        state_transaction
            .world
            .account(&record.active_account_id)
            .is_err()
    });
    if existing_binding_owner.is_some() != stale_binding_owner.is_some()
        || existing_rekey_record.is_some() != stale_rekey_record.is_some()
    {
        return Ok(());
    }
    if stale_rekey_record.is_some() {
        crate::smartcontracts::isi::kaigi::ensure_kaigi_account_rekey_records_can_be_removed(
            state_transaction,
            &BTreeSet::from([label.clone()]),
            "purging stale account-label state",
        )?;
    }
    if let Some(existing_owner) = stale_binding_owner {
        warn!(
            "purging stale account alias binding label={:?} missing_owner={}",
            label, existing_owner
        );
        state_transaction.world.remove_account_alias_binding(label);
    }
    if let Some(record) = stale_rekey_record {
        warn!(
            "purging stale account rekey record label={:?} missing_owner={}",
            label, record.active_account_id
        );
        state_transaction.world.remove_account_rekey_record(label);
    }
    Ok(())
}
/// Reject a primary-alias change while recovery state still depends on the alias.
///
/// # Errors
///
/// Returns an invariant violation for a pending recovery request or policy.
pub(crate) fn ensure_alias_can_change_recovery_binding(
    state_transaction: &StateTransaction<'_, '_>,
    label: &AccountAlias,
) -> Result<(), InstructionExecutionError> {
    if state_transaction
        .world
        .account_recovery_requests
        .get(label)
        .is_some_and(|request| request.is_pending())
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("cannot change primary account alias {label:?}: a recovery request is pending")
                .into(),
        ));
    }
    if state_transaction
        .world
        .account_recovery_policies
        .get(label)
        .is_some()
    {
        return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "cannot change primary account alias {label:?}: clear the account recovery policy first"
                )
                .into(),
            ));
    }
    Ok(())
}
fn ensure_account_alias_lease(
    state_transaction: &mut StateTransaction<'_, '_>,
    owner: &AccountId,
    label: &AccountAlias,
) -> Result<(), InstructionExecutionError> {
    crate::sns::ensure_account_alias_lease(state_transaction, owner, label)
        .map_err(|e| InstructionExecutionError::InvariantViolation(e.to_string().into()))
}
fn sbp_retail_fi_home_domain(alias: &AccountAlias, catalog: &DataSpaceCatalog) -> Option<DomainId> {
    let domain = alias.domain_id(catalog).ok().flatten()?;
    if domain.dataspace().as_ref() == "sbp" && matches!(domain.name().as_ref(), "hbl" | "ubl") {
        Some(domain)
    } else {
        None
    }
}
fn ensure_single_sbp_retail_fi_home(
    state_transaction: &StateTransaction<'_, '_>,
    account: &AccountId,
    requested_alias: &AccountAlias,
) -> Result<(), InstructionExecutionError> {
    let Some(requested_home) =
        sbp_retail_fi_home_domain(requested_alias, &state_transaction.nexus.dataspace_catalog)
    else {
        return Ok(());
    };
    for existing_alias in state_transaction.world.bound_account_aliases(account) {
        let resolved = crate::sns::resolve_active_account_alias(
            &state_transaction.world,
            &state_transaction.nexus.dataspace_catalog,
            &existing_alias,
            state_transaction.block_unix_timestamp_ms(),
        )
        .map_err(|error| InstructionExecutionError::InvariantViolation(error.to_string().into()))?;
        if existing_alias == *requested_alias || resolved.as_ref() != Some(account) {
            continue;
        }
        let Some(existing_home) =
            sbp_retail_fi_home_domain(&existing_alias, &state_transaction.nexus.dataspace_catalog)
        else {
            continue;
        };
        if existing_home != requested_home {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "account already belongs to retail FI home domain `{existing_home}`; cross-FI alias binding to `{requested_home}` requires an explicit jointly-authorized migration"
                    )
                    .into(),
                ));
        }
    }
    Ok(())
}
fn contract_alias_matches_account_label(
    alias: &ContractAlias,
    label: &AccountAlias,
    catalog: &DataSpaceCatalog,
) -> bool {
    let Some(dataspace_alias) = catalog
        .by_id(label.dataspace)
        .map(|entry| entry.alias.as_str())
    else {
        return false;
    };
    alias.name_segment() == label.label.as_ref()
        && alias.domain_segment() == label.domain.as_ref().map(|domain| domain.name().as_ref())
        && alias.dataspace_segment() == dataspace_alias
}
fn ensure_contract_alias_namespace_available(
    state_transaction: &StateTransaction<'_, '_>,
    label: &AccountAlias,
) -> Result<(), InstructionExecutionError> {
    let now_ms = state_transaction.block_unix_timestamp_ms();
    let catalog = &state_transaction.nexus.dataspace_catalog;
    let has_conflict = state_transaction
        .world
        .contract_alias_bindings()
        .iter()
        .any(|(_, binding)| {
            !binding.is_grace_expired_at(now_ms)
                && contract_alias_matches_account_label(&binding.alias, label, catalog)
        });
    if has_conflict {
        Err(InstructionExecutionError::InvariantViolation(
            "account alias collides with an active contract alias"
                .to_owned()
                .into(),
        ))
    } else {
        Ok(())
    }
}
pub(crate) fn resolve_contract_alias_components(
    state_transaction: &mut StateTransaction<'_, '_>,
    alias: &ContractAlias,
) -> Result<(Name, Option<AccountAliasDomain>, DataSpaceId), InstructionExecutionError> {
    let label_name = alias.name_segment().parse::<Name>().map_err(|_| {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            "contract alias name segment is invalid".into(),
        ))
    })?;
    let domain = alias
        .domain_segment()
        .map(str::parse::<AccountAliasDomain>)
        .map(|result| {
            result.map_err(|_| {
                InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                    "contract alias domain segment is invalid".into(),
                ))
            })
        })
        .transpose()?;
    let dataspace = dataspace_id_for_alias_segment(state_transaction, alias.dataspace_segment())?
        .ok_or_else(|| {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            format!(
                "unknown or inactive dataspace alias `{}` in contract alias",
                alias.dataspace_segment()
            )
            .into(),
        ))
    })?;
    Ok((label_name, domain, dataspace))
}
pub(crate) fn ensure_authority_can_manage_contract_alias(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    alias: &ContractAlias,
) -> Result<(), InstructionExecutionError> {
    let (label, domain, dataspace) = resolve_contract_alias_components(state_transaction, alias)?;
    let account_alias = AccountAlias::new_in_dataspace(label, domain, dataspace);
    if authority_can_manage_account_alias(&state_transaction.world, authority, &account_alias)
        .map_err(|error| error.retain_in_instruction(state_transaction))?
    {
        return Ok(());
    }
    Err(InstructionExecutionError::InvariantViolation(
        format!("authority is not permitted to manage contract alias `{alias}`").into(),
    ))
}
fn ensure_authority_can_manage_stale_contract_alias(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    contract_address: &ContractAddress,
    alias: &ContractAlias,
) -> Result<(), InstructionExecutionError> {
    let dataspace = contract_address.dataspace_id().map_err(|err| {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            err.to_string().into(),
        ))
    })?;
    let domain = alias
        .domain_segment()
        .map(|name| DomainId::try_new(name, alias.dataspace_segment()))
        .transpose()
        .map_err(|err| {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                err.to_string().into(),
            ))
        })?;
    if authority_can_manage_account_alias_scope(
        &state_transaction.world,
        authority,
        dataspace,
        domain.as_ref(),
    )
    .map_err(|error| error.retain_in_instruction(state_transaction))?
    {
        return Ok(());
    }
    Err(InstructionExecutionError::InvariantViolation(
        format!("authority is not permitted to manage contract alias `{alias}`").into(),
    ))
}
fn account_alias_selector_for_contract_alias(
    alias: &ContractAlias,
) -> Result<iroha_data_model::sns::NameSelectorV1, InstructionExecutionError> {
    let account_alias_literal = alias.domain_segment().map_or_else(
        || format!("{}@{}", alias.name_segment(), alias.dataspace_segment()),
        |domain| {
            format!(
                "{}@{}.{}",
                alias.name_segment(),
                domain,
                alias.dataspace_segment()
            )
        },
    );
    Ok(iroha_data_model::sns::NameSelectorV1 {
        version: iroha_data_model::sns::NameSelectorV1::VERSION,
        suffix_id: crate::sns::ACCOUNT_ALIAS_SUFFIX_ID,
        label: account_alias_literal,
    })
}
pub(crate) fn ensure_account_alias_namespace_available_for_contract_alias(
    state_transaction: &mut StateTransaction<'_, '_>,
    alias: &ContractAlias,
) -> Result<(), InstructionExecutionError> {
    resolve_contract_alias_components(state_transaction, alias)?;
    let selector = account_alias_selector_for_contract_alias(alias)?;
    let Some(record) = crate::sns::record_by_selector(&state_transaction.world, &selector)
        .map_err(|error| error.retain_in_instruction(state_transaction))?
    else {
        return Ok(());
    };
    let status = crate::sns::effective_status(&record, state_transaction.block_unix_timestamp_ms());
    if matches!(
        status,
        iroha_data_model::sns::NameStatus::Active | iroha_data_model::sns::NameStatus::GracePeriod
    ) {
        Err(InstructionExecutionError::InvariantViolation(
            "contract alias collides with an active account alias"
                .to_owned()
                .into(),
        ))
    } else {
        Ok(())
    }
}
fn ensure_asset_definition_human_fields(
    asset_definition: &AssetDefinition,
) -> Result<(), InstructionExecutionError> {
    validate_asset_name(asset_definition.name()).map_err(|err| {
        InstructionExecutionError::InvariantViolation(
            format!("invalid asset definition name: {err}").into(),
        )
    })?;
    validate_asset_description(asset_definition.description().as_deref()).map_err(|err| {
        InstructionExecutionError::InvariantViolation(
            format!("invalid asset definition description: {err}").into(),
        )
    })?;
    validate_alias_for_asset_definition(asset_definition.alias().as_ref(), asset_definition)?;
    Ok(())
}
/// Check an alias's namespace route against the definition's immutable home.
///
/// `home_dataspace` is `None` only when the home cannot be resolved; the caller's
/// authoritative-route check then refuses the registration.
fn validate_asset_definition_alias_route(
    state_transaction: &mut StateTransaction<'_, '_>,
    alias: Option<&AssetDefinitionAlias>,
    home_dataspace: Option<DataSpaceId>,
) -> Result<(), InstructionExecutionError> {
    let Some(alias) = alias else {
        return Ok(());
    };
    let Some(alias_dataspace) =
        dataspace_id_for_alias_segment(state_transaction, alias.dataspace_segment())?
    else {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("asset definition alias `{alias}` references an unknown or inactive dataspace")
                .into(),
        ));
    };
    if let Some(home_dataspace) = home_dataspace {
        ensure_alias_namespace_matches_home(
            state_transaction,
            alias,
            alias_dataspace,
            home_dataspace,
        )?;
    }
    let Some(domain) = alias.domain_segment() else {
        return Ok(());
    };
    let domain_id = DomainId::try_new(domain, alias.dataspace_segment()).map_err(|err| {
        InstructionExecutionError::InvariantViolation(
            format!("asset definition alias `{alias}` has invalid domain context: {err}").into(),
        )
    })?;
    if state_transaction.world.domains.get(&domain_id).is_none() {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("asset definition alias `{alias}` references missing domain {domain_id}")
                .into(),
        ));
    }
    Ok(())
}
fn ensure_authority_can_manage_asset_definition_alias(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    asset_definition_id: &AssetDefinitionId,
    alias: &AssetDefinitionAlias,
) -> Result<(), InstructionExecutionError> {
    // Genesis is the trusted namespace bootstrap. Every post-genesis mutation must carry the
    // independent asset-definition-alias capability under the single first-release policy.
    if state_transaction._curr_block.is_genesis() {
        return Ok(());
    }
    let dataspace = dataspace_id_for_alias_segment(state_transaction, alias.dataspace_segment())?
        .ok_or_else(|| {
        InstructionExecutionError::InvariantViolation(
            format!("asset definition alias `{alias}` references an unknown or inactive dataspace")
                .into(),
        )
    })?;
    let domain = alias
        .domain_segment()
        .map(|domain| DomainId::try_new(domain, alias.dataspace_segment()))
        .transpose()
        .map_err(|err| {
            InstructionExecutionError::InvariantViolation(
                format!("asset definition alias `{alias}` has invalid domain context: {err}")
                    .into(),
            )
        })?;
    if authority_can_manage_asset_definition_alias(
        &state_transaction.world,
        authority,
        asset_definition_id,
        alias,
        dataspace,
        domain.as_ref(),
    )
    .map_err(|error| error.retain_in_instruction(state_transaction))?
    {
        return Ok(());
    }
    Err(InstructionExecutionError::InvariantViolation(
            format!(
                "authority {authority} lacks exact CanManageAssetDefinitionAlias scope for asset definition alias `{alias}`"
            )
            .into(),
        ))
}
fn ensure_asset_definition_domain_context(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    asset_definition: &AssetDefinition,
) -> Result<(), InstructionExecutionError> {
    let owning_domain = asset_definition.owning_domain().as_ref();
    if asset_definition.balance_scope_policy() == AssetBalancePolicy::DataspaceRestricted
        && owning_domain.is_none()
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "dataspace-restricted asset definition {} requires an explicit owning domain",
                asset_definition.id()
            )
            .into(),
        ));
    }
    let Some(domain_id) = owning_domain else {
        return Ok(());
    };
    let domain = state_transaction.world.domain(domain_id).map_err(|_| {
        InstructionExecutionError::InvariantViolation(
            format!(
                "asset definition {} references missing owning domain {domain_id}",
                asset_definition.id(),
            )
            .into(),
        )
    })?;
    if domain.owned_by() != authority {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("authority {authority} does not own asset definition domain {domain_id}")
                .into(),
        ));
    }
    Ok(())
}
fn account_subject_matches(left: &AccountId, right: &AccountId) -> bool {
    left.subject_id() == right.subject_id()
}
pub(crate) fn is_permission_account_associated(
    permission: &Permission,
    account_id: &AccountId,
) -> bool {
    if let Ok(permission) =
        iroha_executor_data_model::permission::nexus::CanManageFeeSponsorProgram::try_from(
            permission,
        )
    {
        return account_subject_matches(&permission.sponsor, account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::nexus::CanEnrollFeeSponsorProgram::try_from(
            permission,
        )
    {
        return account_subject_matches(&permission.program_id.sponsor, account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanMintAssetToAccount::try_from(permission)
    {
        return account_subject_matches(&permission.account, account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanBurnAsset::try_from(permission)
    {
        return account_subject_matches(permission.asset.account(), account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanTransferAsset::try_from(permission)
    {
        return account_subject_matches(permission.asset.account(), account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanModifyAssetMetadata::try_from(permission)
    {
        return account_subject_matches(permission.asset.account(), account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::account::CanUnregisterAccount::try_from(permission)
    {
        return account_subject_matches(&permission.account, account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::account::CanModifyAccountMetadata::try_from(
            permission,
        )
    {
        return account_subject_matches(&permission.account, account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::account::CanReplaceAccountController::try_from(
            permission,
        )
    {
        return account_subject_matches(&permission.account, account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::query::CanReadAccountData::try_from(permission)
    {
        return account_subject_matches(&permission.account, account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::trigger::CanRegisterTrigger::try_from(permission)
    {
        return account_subject_matches(&permission.authority, account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger::try_from(
            permission,
        )
    {
        return account_subject_matches(&permission.authority, account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint::try_from(
            permission,
        )
    {
        return account_subject_matches(&permission.contract.subject_id(), account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanSetAssetTransferAvailability::try_from(
            permission,
        )
    {
        return account_subject_matches(&permission.account, account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanSetAssetHoldingLimit::try_from(permission)
    {
        return account_subject_matches(&permission.account, account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::amx::CanPrepareAmx::try_from(permission)
    {
        return account_subject_matches(permission.approval.debited_asset.account(), account_id);
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::settlement::CanExecuteSettlement::try_from(
            permission,
        )
    {
        return account_subject_matches(permission.debited_asset.account(), account_id)
            || account_subject_matches(permission.settlement_id.owner(), account_id);
    }
    false
}
pub(crate) fn remove_account_associated_permissions(
    state_transaction: &mut StateTransaction<'_, '_>,
    account_id: &AccountId,
) {
    let account_ids: Vec<AccountId> = state_transaction
        .world
        .account_permissions
        .iter()
        .map(|(holder, _)| holder.clone())
        .collect();
    for holder in account_ids {
        let should_remove = state_transaction
            .world
            .account_permissions
            .get(&holder)
            .is_some_and(|permissions| {
                permissions
                    .iter()
                    .any(|permission| is_permission_account_associated(permission, account_id))
            });
        if !should_remove {
            continue;
        }
        let remove_entry = if let Some(permissions) =
            state_transaction.world.account_permissions.get_mut(&holder)
        {
            permissions
                .retain(|permission| !is_permission_account_associated(permission, account_id));
            permissions.is_empty()
        } else {
            false
        };
        if remove_entry {
            state_transaction
                .world
                .account_permissions
                .remove(holder.clone());
        }
        state_transaction.invalidate_permission_cache_for_account(&holder);
    }
    let role_ids: Vec<RoleId> = state_transaction
        .world
        .roles
        .iter()
        .map(|(role_id, _)| role_id.clone())
        .collect();
    for role_id in role_ids {
        let should_remove = state_transaction
            .world
            .roles
            .get(&role_id)
            .is_some_and(|role| {
                role.permissions()
                    .any(|permission| is_permission_account_associated(permission, account_id))
            });
        if !should_remove {
            continue;
        }
        let impacted_accounts = state_transaction.accounts_with_role(&role_id);
        if let Some(role) = state_transaction.world.roles.get_mut(&role_id) {
            role.permissions
                .retain(|permission| !is_permission_account_associated(permission, account_id));
            role.permission_epochs
                .retain(|permission, _| role.permissions.contains(permission));
        }
        if !impacted_accounts.is_empty() {
            state_transaction.invalidate_permission_cache_for(impacted_accounts.iter());
        }
    }
}
fn is_permission_asset_definition_associated(
    permission: &Permission,
    asset_definition_id: &AssetDefinitionId,
) -> bool {
    if let Ok(permission) = iroha_executor_data_model::permission::asset_definition::CanUnregisterAssetDefinition::try_from(permission) {
            return &permission.asset_definition == asset_definition_id;
        }
    if let Ok(permission) = iroha_executor_data_model::permission::asset_definition::CanModifyAssetDefinitionMetadata::try_from(permission) {
            return &permission.asset_definition == asset_definition_id;
        }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset_definition::CanManageKagemushaWallet::try_from(
            permission,
        )
    {
        return &permission.asset_definition == asset_definition_id;
    }
    if let Ok(permission) = iroha_executor_data_model::permission::asset_definition::CanManageAssetDefinitionConfidentialPolicy::try_from(permission) {
            return &permission.asset_definition == asset_definition_id;
        }
    if let Ok(permission) = iroha_executor_data_model::permission::asset_definition::CanManageAssetDefinitionAlias::try_from(permission)
            && let iroha_executor_data_model::permission::asset_definition::AssetDefinitionAliasPermissionScope::Alias(alias) = permission.scope
        {
            return &alias.asset_definition_id == asset_definition_id;
        }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanMintAssetWithDefinition::try_from(
            permission,
        )
    {
        return &permission.asset_definition == asset_definition_id;
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanBurnAssetWithDefinition::try_from(
            permission,
        )
    {
        return &permission.asset_definition == asset_definition_id;
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition::try_from(
            permission,
        )
    {
        return &permission.asset_definition == asset_definition_id;
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanModifyAssetMetadataWithDefinition::try_from(
            permission,
        )
    {
        return &permission.asset_definition == asset_definition_id;
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanMintAssetToAccount::try_from(permission)
    {
        return &permission.asset_definition == asset_definition_id;
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanBurnAsset::try_from(permission)
    {
        return permission.asset.definition() == asset_definition_id;
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanTransferAsset::try_from(permission)
    {
        return permission.asset.definition() == asset_definition_id;
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanModifyAssetMetadata::try_from(permission)
    {
        return permission.asset.definition() == asset_definition_id;
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanSetAssetTransferAvailability::try_from(
            permission,
        )
    {
        return &permission.asset_definition == asset_definition_id;
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanSetAssetTransferDailyLimit::try_from(
            permission,
        )
    {
        return &permission.asset_definition == asset_definition_id;
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::asset::CanSetAssetHoldingLimit::try_from(permission)
    {
        return &permission.asset_definition == asset_definition_id;
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::amx::CanPrepareAmx::try_from(permission)
    {
        return permission.approval.debited_asset.definition() == asset_definition_id;
    }
    if let Ok(permission) =
        iroha_executor_data_model::permission::settlement::CanExecuteSettlement::try_from(
            permission,
        )
    {
        return permission.debited_asset.definition() == asset_definition_id;
    }
    false
}
fn remove_asset_definition_associated_permissions(
    state_transaction: &mut StateTransaction<'_, '_>,
    asset_definition_id: &AssetDefinitionId,
) {
    let account_ids: Vec<AccountId> = state_transaction
        .world
        .account_permissions
        .iter()
        .map(|(holder, _)| holder.clone())
        .collect();
    for holder in account_ids {
        let should_remove = state_transaction
            .world
            .account_permissions
            .get(&holder)
            .is_some_and(|permissions| {
                permissions.iter().any(|permission| {
                    is_permission_asset_definition_associated(permission, asset_definition_id)
                })
            });
        if !should_remove {
            continue;
        }
        let remove_entry = if let Some(permissions) =
            state_transaction.world.account_permissions.get_mut(&holder)
        {
            permissions.retain(|permission| {
                !is_permission_asset_definition_associated(permission, asset_definition_id)
            });
            permissions.is_empty()
        } else {
            false
        };
        if remove_entry {
            state_transaction
                .world
                .account_permissions
                .remove(holder.clone());
        }
        state_transaction.invalidate_permission_cache_for_account(&holder);
    }
    let role_ids: Vec<RoleId> = state_transaction
        .world
        .roles
        .iter()
        .map(|(role_id, _)| role_id.clone())
        .collect();
    for role_id in role_ids {
        let should_remove = state_transaction
            .world
            .roles
            .get(&role_id)
            .is_some_and(|role| {
                role.permissions().any(|permission| {
                    is_permission_asset_definition_associated(permission, asset_definition_id)
                })
            });
        if !should_remove {
            continue;
        }
        let impacted_accounts = state_transaction.accounts_with_role(&role_id);
        if let Some(role) = state_transaction.world.roles.get_mut(&role_id) {
            role.permissions.retain(|permission| {
                !is_permission_asset_definition_associated(permission, asset_definition_id)
            });
            role.permission_epochs
                .retain(|permission, _| role.permissions.contains(permission));
        }
        if !impacted_accounts.is_empty() {
            state_transaction.invalidate_permission_cache_for(impacted_accounts.iter());
        }
    }
}
fn resolve_config_account_literal(
    world: &impl crate::state::WorldReadOnly,
    dataspace_catalog: &iroha_data_model::nexus::DataSpaceCatalog,
    raw: &str,
    field_path: &'static str,
    now_ms: u64,
) -> Result<AccountId, Error> {
    crate::block::parse_account_literal_with_world(world, dataspace_catalog, raw, now_ms)
            .map_err(|error| {
                InstructionExecutionError::InvariantViolation(error.to_string().into())
            })?
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "invalid {field_path} account literal `{raw}`: expected canonical I105 account id or on-chain alias"
                    )
                    .into(),
                )
                .into()
            })
}
fn config_account_matches(
    world: &impl crate::state::WorldReadOnly,
    dataspace_catalog: &iroha_data_model::nexus::DataSpaceCatalog,
    raw: &str,
    account_id: &AccountId,
    field_path: &'static str,
    now_ms: u64,
) -> Result<bool, Error> {
    let configured =
        resolve_config_account_literal(world, dataspace_catalog, raw, field_path, now_ms)?;
    Ok(configured == *account_id)
}
fn parse_config_asset_definition_id(
    world: &impl crate::state::WorldReadOnly,
    raw: &str,
    now_ms: u64,
) -> Option<AssetDefinitionId> {
    crate::block::parse_asset_definition_literal_with_world(world, raw, now_ms)
}
/// Check, without mutating state, the identity rules `Register<Account>` applies to the
/// built `account` before it is inserted: reserved native metadata keys, controller
/// capabilities, an already registered id, retired rekey identities, reserved FX corridor
/// and SCCP escrow identities, and the UAID and opaque-identifier bindings.
///
/// `Register<Account>` runs exactly this check first, and SCCP settlement runs it for an
/// absent recipient (`specs/sccp.md` §4.12.3): an identity it refuses can never be
/// registered, so the message bounces instead of failing. Metadata sizes and the account
/// label (which a bare `Account::new` never carries) are checked by the execution itself.
///
/// TODO(ws41): `Register<Account>` ends with `retail_fee::reopen_account`, which can still
/// refuse an identity that has retained retail state (no active retail policy, or a
/// refused reopen). That refusal is not prechecked here, so SCCP settlement of such a
/// recipient fails instead of bouncing or holding.
///
/// # Errors
///
/// Returns the refusal `Register<Account>` would report.
pub(crate) fn precheck_register_account(
    state_transaction: &StateTransaction<'_, '_>,
    account: &Account,
) -> Result<(), Error> {
    if let Some(reserved_key) = [
        ASSET_TRANSFER_CONTROL_METADATA_KEY,
        iroha_data_model::validation_fee::RETAIL_FEE_ENROLLMENT_METADATA_KEY,
        iroha_data_model::smart_contract::CONTRACT_DEPLOY_NONCE_METADATA_KEY,
    ]
    .into_iter()
    .find(|key| account.metadata().get(*key).is_some())
    {
        return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "account metadata key `{reserved_key}` is reserved for native state; register the account without it and use the dedicated lifecycle instruction"
                )
                .into(),
            ));
    }
    ensure_controller_capabilities(
        account.controller(),
        &state_transaction.crypto.allowed_signing,
        &state_transaction.crypto.allowed_curve_ids,
    )?;
    let account_id = account.id();
    if state_transaction.world.account(account_id).is_ok() {
        return Err(RepetitionError {
            instruction: InstructionType::Register,
            id: IdBox::AccountId(account_id.clone()),
        }
        .into());
    }
    crate::retail_fee::ensure_not_rekeyed(&state_transaction.world, account_id)?;
    crate::smartcontracts::isi::kaigi::ensure_account_id_is_not_retired_rekey_predecessor(
        state_transaction,
        account_id,
    )?;
    if crate::smartcontracts::isi::asset::isi::is_fx_corridor_escrow_account(
        state_transaction,
        account_id,
    )? {
        return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "cannot register account {account_id}: its identity is reserved for deterministic FX corridor protocol escrow"
                )
                .into(),
            ));
    }
    if crate::smartcontracts::isi::sccp::escrow::is_escrow(&*state_transaction.world, account_id) {
        return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "cannot register account {account_id}: its identity is reserved for an SCCP route escrow"
                )
                .into(),
            ));
    }
    if let Some(uaid) = account.uaid() {
        if let Some(existing) = state_transaction.world.uaid_accounts.get(uaid) {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("UAID {uaid} already bound to account {existing}").into(),
            ));
        }
    } else if !account.opaque_ids().is_empty() {
        return Err(InstructionExecutionError::InvariantViolation(
            "Opaque identifiers require a UAID".to_owned().into(),
        ));
    }
    Ok(())
}
impl Execute for Register<Account> {
    #[metrics(+"register_account")]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let account: Account = self.object().clone().build(authority);
        precheck_register_account(state_transaction, &account)?;
        crate::smartcontracts::limits::enforce_metadata_value_sizes(
            state_transaction,
            account.metadata(),
        )?;
        let (account_id, account_value) = account.clone().into_key_value();
        if let Some(label) = account.label() {
            if account_label_is_pii(label) {
                return Err(InstructionExecutionError::InvariantViolation(
                    "Account label looks like raw PII; use UAID/opaque identifiers instead"
                        .to_owned()
                        .into(),
                ));
            }
            if !authority_can_manage_account_alias(&state_transaction.world, authority, label)
                .map_err(|error| error.retain_in_instruction(state_transaction))?
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    "authority is not permitted to register this account label"
                        .to_owned()
                        .into(),
                ));
            }
            ensure_account_alias_lease(state_transaction, &account_id, label)?;
            purge_stale_account_label_state(state_transaction, label)?;
            if state_transaction.world.account_aliases.get(label).is_some()
                || state_transaction
                    .world
                    .account_rekey_records
                    .get(label)
                    .is_some()
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    "Account label already registered".to_owned().into(),
                ));
            }
        }
        if account.uaid().is_some() {
            let mut seen = BTreeSet::new();
            for opaque in account.opaque_ids() {
                if !seen.insert(*opaque) {
                    return Err(InstructionExecutionError::InvariantViolation(
                        format!(
                            "Account {account_id} contains duplicate opaque identifier {opaque}"
                        )
                        .into(),
                    ));
                }
                if let Some(existing) = state_transaction.world.opaque_uaids.get(opaque) {
                    return Err(InstructionExecutionError::InvariantViolation(
                        format!("Opaque identifier {opaque} already bound to UAID {existing}")
                            .into(),
                    ));
                }
            }
        }
        state_transaction
            .world
            .accounts
            .insert(account_id.clone(), account_value);
        if let Some(uaid) = account.uaid() {
            state_transaction
                .world
                .uaid_accounts
                .insert(*uaid, account_id.clone());
            state_transaction.rebuild_space_directory_bindings(*uaid);
        }
        if let Some(label) = account.label() {
            if state_transaction
                .world
                .insert_account_alias_binding(label.clone(), account_id.clone())
                .is_some()
            {
                state_transaction.world.accounts.remove(account_id.clone());
                if let Some(uaid) = account.uaid() {
                    state_transaction.world.uaid_accounts.remove(*uaid);
                    state_transaction.rebuild_space_directory_bindings(*uaid);
                }
                return Err(InstructionExecutionError::InvariantViolation(
                    "Account label already registered".to_owned().into(),
                ));
            }
        }
        if let Some(uaid) = account.uaid() {
            for opaque in account.opaque_ids() {
                if state_transaction
                    .world
                    .opaque_uaids
                    .insert(*opaque, *uaid)
                    .is_some()
                {
                    state_transaction.world.accounts.remove(account_id.clone());
                    state_transaction.world.uaid_accounts.remove(*uaid);
                    if let Some(label) = account.label() {
                        state_transaction.world.remove_account_alias_binding(label);
                    }
                    for inserted in account.opaque_ids() {
                        state_transaction.world.opaque_uaids.remove(*inserted);
                    }
                    state_transaction.rebuild_space_directory_bindings(*uaid);
                    return Err(InstructionExecutionError::InvariantViolation(
                        "Opaque identifier already registered".to_owned().into(),
                    ));
                }
            }
        }
        if let Some(record) = AccountRekeyRecord::from_account(&account)
            && state_transaction
                .world
                .insert_account_rekey_record(record)
                .is_some()
        {
            state_transaction.world.accounts.remove(account_id.clone());
            if let Some(uaid) = account.uaid() {
                state_transaction.world.uaid_accounts.remove(*uaid);
                state_transaction.rebuild_space_directory_bindings(*uaid);
            }
            if let Some(label) = account.label() {
                state_transaction.world.remove_account_alias_binding(label);
            }
            for opaque in account.opaque_ids() {
                state_transaction.world.opaque_uaids.remove(*opaque);
            }
            return Err(InstructionExecutionError::InvariantViolation(
                "Account label already registered".to_owned().into(),
            ));
        }
        let created = AccountEvent::Created(AccountCreated::new(account));
        crate::retail_fee::reopen_account(state_transaction, &account_id)?;
        state_transaction.world.emit_events(Some(created));
        Ok(())
    }
}
impl Execute for Unregister<Account> {
    #[metrics(+"unregister_account")]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let account_id = self.object().clone();
        crate::smartcontracts::isi::asset::isi::ensure_account_not_retained_by_retail_daily_limit(
            state_transaction,
            &account_id,
        )?;
        crate::smartcontracts::isi::bond::ensure_account_not_retained_by_bonds(
            state_transaction.world(),
            &account_id,
            "unregister account",
        )?;
        if crate::smartcontracts::isi::sccp::escrow::is_escrow(
            &*state_transaction.world,
            &account_id,
        ) {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("cannot unregister account {account_id}: it is an SCCP route escrow")
                    .into(),
            )
            .into());
        }
        crate::retail_fee::close_account(state_transaction, &account_id)?;
        if let Some(contract) = crate::smartcontracts::code::historical_contract_for_subject(
            &state_transaction.world,
            &account_id,
        ) {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is the retained subject of contract `{contract}`"
                    )
                    .into(),
                )
                .into());
        }
        if let Some(contract) = crate::smartcontracts::code::contract_owned_or_pending_for_account(
            &state_transaction.world,
            &account_id,
        ) {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: transfer or cancel its lifecycle ownership of contract `{contract}` first"
                    )
                    .into(),
                )
                .into());
        }
        if crate::smartcontracts::isi::game::retained_game_account(
            state_transaction.world(),
            &account_id,
        ) || crate::smartcontracts::isi::nft_custody::retained_nft_account(
            state_transaction.world(),
            &account_id,
        ) {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!("cannot unregister account {account_id}: it is retained by a native game session or NFT custody").into(),
                ).into());
        }
        if let Some(reference) =
            crate::smartcontracts::isi::sorafs_moderation::retained_moderation_account_reference(
                state_transaction.world(),
                &account_id,
            )?
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is retained by moderation {reference}"
                    )
                    .into(),
                )
                .into());
        }
        crate::smartcontracts::isi::kaigi::ensure_kaigi_account_can_unregister(
            state_transaction,
            &account_id,
        )?;
        if let Some((proposal_id, reference_kind)) =
            crate::validation_fee::retained_enacted_validation_fee_account_reference(
                state_transaction,
                &account_id,
            )
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is retained as the enacted validation-fee {reference_kind} by proposal {}",
                        hex::encode(proposal_id)
                    )
                    .into(),
                )
                .into());
        }
        if let Some((program_id, _)) =
            state_transaction
                .world
                .fee_sponsor_programs
                .iter()
                .find(|(_, program)| {
                    program.payout_account == account_id
                        && program.lifecycle
                            != iroha_data_model::nexus::FeeSponsorProgramLifecycle::Closed
                })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is the immutable payout account for fee sponsor program {program_id}"
                    )
                    .into(),
                )
                .into());
        }
        if crate::smartcontracts::isi::asset::isi::is_fx_corridor_escrow_account(
            state_transaction,
            &account_id,
        )? {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "cannot unregister account {account_id}: it is retained FX protocol escrow"
                )
                .into(),
            )
            .into());
        }
        if crate::smartcontracts::isi::sorafs_reserve::is_reserve_custody_account(
            state_transaction.world(),
            &account_id,
        )? {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "cannot unregister account {account_id}: it is active SoraFS reserve custody"
                )
                .into(),
            )
            .into());
        }
        if crate::kagemusha_wallet_v1::custody::is_reserve_account(
            state_transaction.world(),
            &account_id,
        )
        .map_err(crate::smartcontracts::isi::asset::isi::kagemusha_custody_error)?
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!("cannot unregister account {account_id}: it is permanent KAGEMUSHA reserve custody").into(),
                ).into());
        }
        if crate::smartcontracts::isi::escrow::is_protocol_escrow_custody_account(
            state_transaction,
            &account_id,
        ) {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is retained native escrow or VPN lease custody"
                    )
                    .into(),
                )
                    .into());
        }
        if crate::smartcontracts::isi::vpn::is_active_vpn_client(
            &state_transaction.world,
            &account_id,
        ) {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it funds an active operator-signed VPN lease"
                    )
                    .into(),
                )
                .into());
        }
        let contract_deploy_nonce_key =
            Name::from_str(iroha_data_model::smart_contract::CONTRACT_DEPLOY_NONCE_METADATA_KEY)
                .expect("contract deployment nonce metadata key must remain valid");
        if state_transaction
            .world
            .account(&account_id)?
            .metadata()
            .contains(&contract_deploy_nonce_key)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has native contract deployment nonce state; retain the account to preserve deployment address monotonicity and audit history"
                    )
                    .into(),
                )
                .into());
        }
        if state_transaction
            .world
            .account(&account_id)?
            .metadata()
            .get(ASSET_TRANSFER_CONTROL_METADATA_KEY)
            .is_some()
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has native asset transfer-control state; clear every control through dedicated instructions first"
                    )
                    .into(),
                )
                .into());
        }
        let privacy_reserve_custody =
                crate::privacy_state::load_privacy_public_reserve_custody_v1(
                    &state_transaction.world.privacy_commitments,
                )
                .map_err(|message| {
                    InstructionExecutionError::InvariantViolation(
                        format!(
                            "cannot unregister account {account_id}: privacy reserve custody is invalid: {message}"
                        )
                        .into(),
                    )
                })?;
        if let Some((_, owner)) = privacy_reserve_custody
            .iter()
            .find(|(asset_id, _)| asset_id.account() == &account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is the reserve account for governed privacy pool {:?}",
                        owner.namespace()
                    )
                    .into(),
                )
                .into());
        }
        if let Some(primary_label) = state_transaction.world.account(&account_id)?.label() {
            ensure_alias_can_change_recovery_binding(state_transaction, primary_label)?;
        }
        if let Some(owned_domain_id) = state_transaction
            .world
            .domains_by_owner
            .get(&account_id)
            .and_then(|domains| domains.iter().next())
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it owns domain {owned_domain_id}; transfer ownership first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some(owned_definition_id) = state_transaction
            .world
            .asset_definitions_by_owner
            .get(&account_id)
            .and_then(|definitions| definitions.iter().next())
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it owns asset definition {owned_definition_id}; transfer ownership first"
                    )
                    .into(),
                )
                .into());
        }
        if account_id == state_transaction.gov.bond_escrow_account {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is configured as governance bond escrow account (`gov.bond_escrow_account`); update governance config first"
                    )
                    .into(),
                )
                .into());
        }
        if account_id == state_transaction.gov.citizenship_escrow_account {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is configured as governance citizenship escrow account (`gov.citizenship_escrow_account`); update governance config first"
                    )
                    .into(),
                )
                .into());
        }
        if account_id == state_transaction.gov.slash_receiver_account {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is configured as governance slash receiver account (`gov.slash_receiver_account`); update governance config first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((referendum_id, _)) =
            state_transaction
                .world
                .governance_locks
                .iter()
                .find(|(_, locks)| {
                    locks.locks.values().any(|record| {
                        record.custody.bond_escrow_account == account_id
                            || record.custody.slash_receiver_account == account_id
                    })
                })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is retained by immutable governance lock custody (referendum {referendum_id}); clear the governance locks first"
                    )
                    .into(),
                )
                .into());
        }
        if account_id
            == state_transaction
                .gov
                .viral_incentives
                .incentive_pool_account
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is configured as governance viral incentive pool account (`gov.viral_incentives.incentive_pool_account`); update governance config first"
                    )
                    .into(),
                )
                .into());
        }
        if account_id == state_transaction.gov.viral_incentives.escrow_account {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is configured as governance viral escrow account (`gov.viral_incentives.escrow_account`); update governance config first"
                    )
                    .into(),
                )
                .into());
        }
        if account_id == state_transaction.oracle.economics.reward_pool {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is configured as oracle reward pool account (`oracle.economics.reward_pool`); update oracle config first"
                    )
                    .into(),
                )
                .into());
        }
        if account_id == state_transaction.oracle.economics.slash_receiver {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is configured as oracle slash receiver account (`oracle.economics.slash_receiver`); update oracle config first"
                    )
                    .into(),
                )
                .into());
        }
        let nexus_fee_sink_matches = state_transaction.nexus.fees.fee_sink_account_id == account_id;
        let nexus_stake_escrow_matches = config_account_matches(
            &state_transaction.world,
            &state_transaction.nexus.dataspace_catalog,
            &state_transaction.nexus.staking.stake_escrow_account_id,
            &account_id,
            "nexus.staking.stake_escrow_account_id",
            state_transaction.block_unix_timestamp_ms(),
        )?;
        let nexus_slash_sink_matches = config_account_matches(
            &state_transaction.world,
            &state_transaction.nexus.dataspace_catalog,
            &state_transaction.nexus.staking.slash_sink_account_id,
            &account_id,
            "nexus.staking.slash_sink_account_id",
            state_transaction.block_unix_timestamp_ms(),
        )?;
        if nexus_fee_sink_matches {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is the committed root fee sink; commit a replacement root fee policy first"
                    )
                    .into(),
                )
                .into());
        }
        if nexus_stake_escrow_matches {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is configured as nexus staking escrow account (`nexus.staking.stake_escrow_account_id`); update nexus config first"
                    )
                    .into(),
                )
                .into());
        }
        if nexus_slash_sink_matches {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is configured as nexus staking slash sink account (`nexus.staking.slash_sink_account_id`); update nexus config first"
                    )
                    .into(),
                )
                .into());
        }
        if state_transaction
            .content
            .publish_allow_accounts
            .iter()
            .any(|publisher| publisher == &account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is configured as content publish allow-list account (`content.publish_allow_accounts`); update content config first"
                    )
                    .into(),
                )
                .into());
        }
        if state_transaction
            .gov
            .sorafs_telemetry
            .submitters
            .iter()
            .any(|submitter| submitter == &account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is configured as SoraFS telemetry submitter (`gov.sorafs_telemetry.submitters`); update governance config first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((provider_id, _)) = state_transaction
            .gov
            .sorafs_telemetry
            .per_provider_submitters
            .iter()
            .find(|(_, submitters)| submitters.iter().any(|submitter| submitter == &account_id))
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is configured as per-provider SoraFS telemetry submitter for provider {} (`gov.sorafs_telemetry.per_provider_submitters`); update governance config first",
                        hex::encode(provider_id.as_bytes())
                    )
                    .into(),
                )
                .into());
        }
        if let Some((provider_id, _)) = state_transaction
            .gov
            .sorafs_provider_owners
            .iter()
            .find(|(_, owner)| *owner == &account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is configured as SoraFS provider owner for provider {} (`gov.sorafs_provider_owners`); update governance config first",
                        hex::encode(provider_id.as_bytes())
                    )
                    .into(),
                )
                .into());
        }
        if let Some((provider_id, _)) = state_transaction
            .world
            .provider_owners
            .iter()
            .find(|(_, owner)| *owner == &account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it owns SoraFS provider {}; unregister or reassign provider owner first",
                        hex::encode(provider_id.as_bytes())
                    )
                    .into(),
                )
                .into());
        }
        if state_transaction.world.citizens.get(&account_id).is_some() {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has an active citizenship record; revoke citizenship first"
                    )
                    .into(),
                )
                .into());
        }
        if state_transaction
            .world
            .public_lane_stake_custody
            .iter()
            .any(|((_, validator), (asset, _))| {
                validator == &account_id || asset.account() == &account_id
            })
            || state_transaction
                .world
                .public_lane_stake_reserves
                .iter()
                .any(|(asset, _)| asset.account() == &account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is referenced by pinned public-lane staking custody; release all held stake first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some(((lane_id, validator), _)) = state_transaction
            .world
            .public_lane_validators
            .iter()
            .find(|(key, record)| {
                public_lane_validator_record_matches_key(key, record)
                    && (key.1 == account_id || record.stake_account == account_id)
            })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active public-lane validator stake state (lane {lane_id}, validator {validator}); exit validator first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some(((lane_id, validator, staker), _)) = state_transaction
            .world
            .public_lane_stake_shares
            .iter()
            .find(|(key, record)| {
                public_lane_stake_share_matches_key(key, record)
                    && (key.1 == account_id
                        || key.2 == account_id
                        || record.validator == account_id
                        || record.staker == account_id)
            })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active public-lane stake share state (lane {lane_id}, validator {validator}, staker {staker}); unbond first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((feed_id, _)) = state_transaction
            .world
            .oracle_feeds
            .iter()
            .find(|(_, feed)| {
                feed.providers
                    .iter()
                    .any(|provider| provider == &account_id)
            })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active oracle feed provider state (feed {feed_id}); update feed providers first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((change_id, _)) =
            state_transaction
                .world
                .oracle_changes
                .iter()
                .find(|(_, change)| {
                    change.proposer == account_id
                        || change
                            .feed
                            .providers
                            .iter()
                            .any(|provider| provider == &account_id)
                        || change.stages.iter().any(|stage| {
                            stage.approvals.contains(&account_id)
                                || stage.rejections.contains(&account_id)
                        })
                })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active oracle governance state (change {change_id:?}); resolve or prune oracle change state first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((dispute_id, _)) = state_transaction
            .world
            .oracle_disputes
            .iter()
            .find(|(_, dispute)| dispute.challenger == account_id || dispute.target == account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active oracle dispute state (dispute {dispute_id:?}); resolve dispute first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((provider_key, _)) = state_transaction
            .world
            .oracle_provider_stats
            .iter()
            .find(|(provider_key, _)| provider_key.provider_id == account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active oracle provider stats state (feed {}); clear provider stats first",
                        provider_key.feed_id
                    )
                    .into(),
                )
                .into());
        }
        if let Some((observation_key, _)) = state_transaction
            .world
            .oracle_observations
            .iter()
            .find(|(_, window)| window.observations.contains_key(&account_id))
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active oracle observation window state ({observation_key:?}); clear observation state first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((feed_id, _)) =
            state_transaction
                .world
                .oracle_history
                .iter()
                .find(|(_, history)| {
                    history.iter().any(|record| {
                        matches!(
                            &record.event.outcome,
                            iroha_data_model::oracle::FeedEventOutcome::Success(success)
                                if success
                                    .entries
                                    .iter()
                                    .any(|entry| entry.oracle_id == account_id)
                        )
                    })
                })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active oracle feed history state (feed {feed_id}); retain provider account for oracle audit references"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((agreement_id, _)) =
            state_transaction
                .world
                .repo_agreements
                .iter()
                .find(|(_, agreement)| {
                    agreement.initiator == account_id
                        || agreement.counterparty == account_id
                        || agreement
                            .custodian
                            .as_ref()
                            .is_some_and(|custodian| custodian == &account_id)
                })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is referenced by repo agreement state ({agreement_id}); retain account for settlement audit references"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((settlement_id, _)) =
            state_transaction
                .world
                .settlement_receipts
                .iter()
                .find(|(_, receipt)| {
                    receipt.authority == account_id
                        || receipt.details.movements().any(|movement| {
                            movement.source.account() == &account_id
                                || movement.destination.account() == &account_id
                        })
                })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is referenced by committed settlement receipt {settlement_id}"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((proposal_id, _)) = state_transaction
            .world
            .governance_proposals
            .iter()
            .find(|(_, record)| record.proposer == account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active governance proposal state (proposal {}); retain proposer account for governance audit references",
                        hex::encode(*proposal_id)
                    )
                    .into(),
                )
                .into());
        }
        if let Some((referendum_id, _)) =
            state_transaction
                .world
                .governance_locks
                .iter()
                .find(|(_, locks)| {
                    locks
                        .locks
                        .iter()
                        .any(|(owner, record)| owner == &account_id || record.owner == account_id)
                })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active governance lock state (referendum {referendum_id}); unlock governance bonds first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((referendum_id, _)) = state_transaction
            .world
            .governance_slashes
            .iter()
            .find(|(_, slashes)| slashes.slashes.keys().any(|owner| owner == &account_id))
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active governance slash ledger state (referendum {referendum_id}); retain account for governance audit references"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((bundle_id, _)) = state_transaction
            .world
            .content_bundles
            .iter()
            .find(|(_, bundle)| bundle.created_by == account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is referenced by content bundle state ({bundle_id}); retain account for content audit references"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((upgrade_id, _)) = state_transaction
            .world
            .runtime_upgrades
            .iter()
            .find(|(_, record)| record.proposer == account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active runtime upgrade proposal state (upgrade 0x{}); retain proposer account for governance audit references",
                        hex::encode(upgrade_id.0)
                    )
                    .into(),
                )
                .into());
        }
        if let Some((binding_digest, _)) = state_transaction
            .world
            .twitter_bindings
            .iter()
            .find(|(_, record)| record.provider == account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active twitter binding oracle provider state (binding {binding_digest}); revoke binding or rotate provider first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((binding_digest, _)) = state_transaction
            .world
            .viral_escrows
            .iter()
            .find(|(_, record)| record.sender == account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active viral escrow state (binding {binding_digest}); settle escrow first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((digest, _)) = state_transaction
            .world
            .pin_manifests
            .iter()
            .find(|(_, record)| record.submitted_by == account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active SoraFS pin manifest state (digest 0x{}); retain submitter account for storage audit references",
                        hex::encode(digest.as_bytes())
                    )
                    .into(),
                )
                .into());
        }
        if let Some((alias_id, _)) = state_transaction
            .world
            .manifest_aliases
            .iter()
            .find(|(_, record)| record.bound_by == account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active SoraFS manifest alias state (alias {}/{}) bound by this account; rotate alias binding first",
                        alias_id.namespace, alias_id.name
                    )
                    .into(),
                )
                .into());
        }
        if let Some((order_id, _)) = state_transaction
            .world
            .replication_orders
            .iter()
            .find(|(_, record)| record.issued_by == account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active SoraFS replication order state (order {}); retain issuer account for storage audit references",
                        hex::encode(order_id.as_bytes())
                    )
                    .into(),
                )
                .into());
        }
        if let Some((ticket_id, record)) = state_transaction
            .world
            .da_pin_intents_by_ticket
            .iter()
            .find(|(_, record)| record.intent.authorization.owner == account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it has active DA pin intent owner state (ticket 0x{}, block {} index {}); clear DA pin intent ownership first",
                        hex::encode(ticket_id.as_bytes()),
                        record.location.block_height,
                        record.location.index_in_bundle
                    )
                    .into(),
                )
                .into());
        }
        if state_transaction
            .world
            .parliament_member_reference_counts
            .get(&account_id)
            .copied()
            .is_some_and(crate::state::ParliamentMemberReferenceCountsV1::has_references)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it is present in Parliament attempt state; retain account for governance audit references"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((rwa_id, _)) = state_transaction
            .world
            .rwas
            .iter()
            .find(|(_, rwa)| rwa.owned_by == account_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister account {account_id}: it owns RWA {rwa_id}; transfer or redeem the lot first"
                    )
                    .into(),
                )
                .into());
        }
        remove_account_associated_permissions(state_transaction, &account_id);
        state_transaction
            .world()
            .triggers()
            .inspect_by_action(
                |action| action.authority() == &account_id,
                |trigger_id, _| trigger_id.clone(),
            )
            .collect::<Vec<_>>()
            .into_iter()
            .for_each(|trigger_id| {
                let removed = state_transaction.world.triggers.remove(&trigger_id);
                removed.then_some(()).expect("should succeed");
                crate::smartcontracts::isi::triggers::isi::remove_trigger_associated_permissions(
                    state_transaction,
                    &trigger_id,
                );
            });
        state_transaction
            .world
            .account_permissions
            .remove(account_id.clone());
        state_transaction.world.remove_account_roles(&account_id);
        let remove_assets: Vec<AssetId> = state_transaction
            .world
            .assets_in_account_iter(&account_id)
            .map(|ad| ad.id().clone())
            .collect();
        for asset_id in remove_assets {
            crate::smartcontracts::isi::asset::isi::remove_account_asset_with_quantity_candidate(
                state_transaction,
                authority,
                &asset_id,
            )?;
        }
        let mut remove_nfts: BTreeSet<NftId> = state_transaction
            .world
            .nfts_in_account_iter(&account_id)
            .map(|nft| nft.id().clone())
            .collect();
        remove_nfts.extend(
            state_transaction
                .world
                .nfts
                .iter()
                .filter(|&(_nft_id, nft)| nft.owned_by == account_id)
                .map(|(nft_id, _nft)| nft_id.clone()),
        );
        for nft_id in remove_nfts {
            crate::smartcontracts::isi::nft::isi::remove_nft_associated_permissions(
                state_transaction,
                &nft_id,
            );
            state_transaction.world.remove_nft_entry(&nft_id);
            state_transaction
                .world
                .emit_events(Some(DomainEvent::Nft(NftEvent::Deleted(nft_id))));
        }
        let removed = state_transaction.world.accounts.remove(account_id.clone());
        let Some(account_value) = removed else {
            return Err(FindError::Account(account_id).into());
        };
        state_transaction
            .world
            .tx_sequences
            .remove(account_id.clone());
        for label in state_transaction
            .world
            .remove_account_alias_bindings_for_account(&account_id)
        {
            state_transaction.world.remove_account_rekey_record(&label);
        }
        if let Some(uaid) = account_value.uaid().copied() {
            state_transaction.world.uaid_accounts.remove(uaid);
            for opaque in account_value.opaque_ids() {
                state_transaction.world.opaque_uaids.remove(*opaque);
                state_transaction.world.identifier_claims.remove(*opaque);
            }
            state_transaction.rebuild_space_directory_bindings(uaid);
        } else {
            for opaque in account_value.opaque_ids() {
                state_transaction.world.opaque_uaids.remove(*opaque);
                state_transaction.world.identifier_claims.remove(*opaque);
            }
        }
        state_transaction
            .world
            .emit_events(Some(AccountEvent::Deleted(account_id)));
        Ok(())
    }
}
impl Execute for Register<AssetDefinition> {
    #[metrics(+"register_asset_definition")]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        register_asset_definition(self.object().clone(), None, authority, state_transaction)
    }
}
impl Execute for iroha_data_model::isi::RegisterDataspaceAssetDefinition {
    #[metrics(+"register_dataspace_asset_definition")]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_dataspace_asset_definition_registration_allowed(
            state_transaction,
            authority,
            &self,
        )?;
        register_asset_definition(
            self.object,
            Some(self.dataspace_id),
            authority,
            state_transaction,
        )
    }
}
/// Authorize an immutable direct namespace against current on-chain SNS ownership.
/// This does not grant the namespace owner access to any existing monetary balance.
pub(crate) fn ensure_dataspace_asset_definition_registration_allowed(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: &iroha_data_model::isi::RegisterDataspaceAssetDefinition,
) -> Result<(), InstructionExecutionError> {
    instruction.validate().map_err(|error| {
        InstructionExecutionError::InvariantViolation(
            format!("invalid direct-dataspace asset definition: {error}").into(),
        )
    })?;
    let dataspace_id = instruction.dataspace_id;
    if dataspace_id == DataSpaceId::UNIVERSAL {
        return Err(InstructionExecutionError::InvariantViolation(
            "direct-dataspace registration requires a non-Universal dataspace".into(),
        ));
    }
    let owner = crate::sns::active_dataspace_owner_by_id(
        &state_transaction.world,
        &state_transaction.nexus.dataspace_catalog,
        dataspace_id,
        state_transaction.block_unix_timestamp_ms(),
    )
    .map_err(|error| error.retain_in_instruction(state_transaction))?;
    if owner.as_ref() != Some(authority) {
        return Err(InstructionExecutionError::InvariantViolation(
                "only the current active SNS dataspace owner may register a direct-dataspace asset definition".into(),
            ));
    }
    if state_transaction.current_dataspace_id != Some(dataspace_id)
        || state_transaction.world.current_dataspace_id != Some(dataspace_id)
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "direct-dataspace asset definition must register on its exact authoritative route"
                .into(),
        ));
    }
    ensure_home_admissible(
        state_transaction,
        &instruction.object.id,
        instruction.object.balance_scope_policy,
        dataspace_id,
    )
}
/// Register the existing definition payload and its optional direct namespace atomically.
fn register_asset_definition(
    object: iroha_data_model::asset::NewAssetDefinition,
    dataspace_id: Option<DataSpaceId>,
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let asset_definition = object.build(authority);
    crate::smartcontracts::limits::enforce_metadata_value_sizes(
        state_transaction,
        asset_definition.metadata(),
    )?;
    ensure_asset_definition_human_fields(&asset_definition)?;
    let home_dataspace = match dataspace_id {
        Some(dataspace_id) => Some(dataspace_id),
        None => asset_definition_home_dataspace(state_transaction, &asset_definition)?,
    };
    validate_asset_definition_alias_route(
        state_transaction,
        asset_definition.alias().as_ref(),
        home_dataspace,
    )?;
    if let Some(alias) = asset_definition.alias().as_ref() {
        ensure_authority_can_manage_asset_definition_alias(
            state_transaction,
            authority,
            asset_definition.id(),
            alias,
        )?;
    }
    if dataspace_id.is_none() {
        ensure_asset_definition_domain_context(state_transaction, authority, &asset_definition)?;
        ensure_asset_definition_registered_on_authoritative_route(
            state_transaction,
            &asset_definition,
        )?;
    }
    let asset_definition_id = asset_definition.id().clone();
    if state_transaction
        .world
        .asset_definition(&asset_definition_id)
        .is_ok()
    {
        return Err(RepetitionError {
            instruction: InstructionType::Register,
            id: IdBox::AssetDefinitionId(asset_definition_id),
        }
        .into());
    }
    if let Some(alias) = asset_definition.alias()
        && let Some(existing) = state_transaction
            .world
            .asset_definition_aliases
            .get(alias)
            .cloned()
        && existing != asset_definition_id
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("asset definition alias `{alias}` is already bound").into(),
        )
        .into());
    }
    let mut stored_definition = asset_definition.clone();
    stored_definition.alias = None;
    let incarnation = state_transaction
        .register_quantity_definition(asset_definition_id.clone(), stored_definition)?;
    if let Some(dataspace_id) = dataspace_id {
        state_transaction
            .register_direct_asset_definition_home(&asset_definition_id, incarnation, dataspace_id)
            .map_err(|error| {
                InstructionExecutionError::InvariantViolation(
                    format!("direct asset home registration failed: {error}").into(),
                )
            })?;
    }
    if let Some(alias) = asset_definition.alias().clone() {
        let bound_at_ms = state_transaction.block_unix_timestamp_ms();
        state_transaction.world.bind_asset_definition_alias(
            &asset_definition_id,
            alias,
            None,
            None,
            bound_at_ms,
        )?;
    }
    state_transaction
        .world
        .emit_asset_definition_event(AssetDefinitionEvent::Created(asset_definition));
    Ok(())
}
impl Execute for Unregister<AssetDefinition> {
    #[metrics(+"unregister_asset_definition")]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let asset_definition_id = self.object().clone();
        crate::sumeragi::amx::ensure_retained_definitions(
            &state_transaction.world,
            &BTreeSet::from([asset_definition_id.clone()]),
        )?;
        crate::smartcontracts::isi::asset::isi::ensure_asset_definitions_not_retained_by_retail_daily_limit(
                state_transaction,
                &BTreeSet::from([asset_definition_id.clone()]),
                &format!("unregister asset definition {asset_definition_id}"),
            )?;
        crate::smartcontracts::isi::asset::isi::ensure_asset_definitions_not_retained_by_transfer_controls(
                state_transaction,
                &BTreeSet::from([asset_definition_id.clone()]),
                &format!("unregister asset definition {asset_definition_id}"),
            )?;
        // Retiring a definition deletes every balance of it, including the
        // deterministic custody of escrows that other accounts funded.
        crate::smartcontracts::isi::escrow::ensure_asset_definitions_not_retained_by_native_escrows(
            state_transaction,
            &BTreeSet::from([asset_definition_id.clone()]),
            &format!("unregister asset definition {asset_definition_id}"),
        )?;
        // Bond records are permanent and own their bond and payment definitions.
        crate::smartcontracts::isi::bond::ensure_asset_definitions_not_retained_by_bonds(
            state_transaction.world(),
            &BTreeSet::from([asset_definition_id.clone()]),
            &format!("unregister asset definition {asset_definition_id}"),
        )?;
        if let Some(reference) = crate::smartcontracts::isi::sorafs_moderation::retained_moderation_asset_definition_reference(
                state_transaction.world(),
                &asset_definition_id,
            )? {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is retained by moderation {reference}"
                    )
                    .into(),
                )
                .into());
            }
        if let Some((proposal_id, reference_kind)) =
            crate::validation_fee::retained_enacted_validation_fee_asset_reference(
                state_transaction,
                &asset_definition_id,
            )
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is retained as the enacted validation-fee {reference_kind} by proposal {}",
                        hex::encode(proposal_id)
                    )
                    .into(),
                )
                .into());
        }
        if crate::smartcontracts::isi::asset::isi::is_fx_corridor_asset_definition(
            state_transaction,
            &asset_definition_id,
        )? {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is retained native FX corridor backing"
                    )
                    .into(),
                )
                .into());
        }
        if crate::smartcontracts::isi::sorafs_reserve::is_reserve_asset_definition(
            state_transaction.world(),
            &asset_definition_id,
        )? {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it backs active SoraFS reserve custody"
                    )
                    .into(),
                )
                    .into());
        }
        if crate::kagemusha_wallet_v1::custody::is_reserve_definition(
            state_transaction.world(),
            &asset_definition_id,
        )
        .map_err(crate::smartcontracts::isi::asset::isi::kagemusha_custody_error)?
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!("cannot unregister asset definition {asset_definition_id}: it is permanent KAGEMUSHA reserve custody").into(),
                ).into());
        }
        let privacy_reserve_custody =
                crate::privacy_state::load_privacy_public_reserve_custody_v1(
                    &state_transaction.world.privacy_commitments,
                )
                .map_err(|message| {
                    InstructionExecutionError::InvariantViolation(
                        format!(
                            "cannot unregister asset definition {asset_definition_id}: privacy reserve custody is invalid: {message}"
                        )
                        .into(),
                    )
                })?;
        if let Some((_, owner)) = privacy_reserve_custody
            .iter()
            .find(|(asset_id, _)| asset_id.definition() == &asset_definition_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it backs governed privacy pool {:?}",
                        owner.namespace()
                    )
                    .into(),
                )
                .into());
        }
        if asset_definition_id == state_transaction.gov.voting_asset_id {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is configured as governance voting asset definition (`gov.voting_asset_id`); update governance config first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((referendum_id, _)) =
            state_transaction
                .world
                .governance_locks
                .iter()
                .find(|(_, locks)| {
                    locks
                        .locks
                        .values()
                        .any(|record| record.custody.asset_definition_id == asset_definition_id)
                })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is retained by immutable governance lock custody (referendum {referendum_id}); clear the governance locks first"
                    )
                    .into(),
                )
                .into());
        }
        if asset_definition_id == state_transaction.gov.citizenship_asset_id {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is configured as governance citizenship asset definition (`gov.citizenship_asset_id`); update governance config first"
                    )
                    .into(),
                )
                .into());
        }
        if asset_definition_id
            == state_transaction
                .gov
                .viral_incentives
                .reward_asset_definition_id
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is configured as governance viral reward asset definition (`gov.viral_incentives.reward_asset_definition_id`); update governance config first"
                    )
                    .into(),
                )
                .into());
        }
        if crate::smartcontracts::isi::game::retained_game_asset(
            state_transaction.world(),
            &asset_definition_id,
        ) {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!("cannot unregister asset definition {asset_definition_id}: it secures an outstanding native game stake").into(),
                ).into());
        }
        if asset_definition_id == state_transaction.oracle.economics.reward_asset {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is configured as oracle reward asset definition (`oracle.economics.reward_asset`); update oracle config first"
                    )
                    .into(),
                )
                .into());
        }
        if asset_definition_id == state_transaction.oracle.economics.slash_asset {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is configured as oracle slash asset definition (`oracle.economics.slash_asset`); update oracle config first"
                    )
                    .into(),
                )
                .into());
        }
        if asset_definition_id == state_transaction.oracle.economics.dispute_bond_asset {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is configured as oracle dispute bond asset definition (`oracle.economics.dispute_bond_asset`); update oracle config first"
                    )
                    .into(),
                )
                .into());
        }
        if parse_config_asset_definition_id(
            &state_transaction.world,
            &state_transaction
                .nexus
                .fees
                .fee_asset_id
                .canonical_address(),
            state_transaction.block_unix_timestamp_ms(),
        )
        .is_some_and(|configured| configured == asset_definition_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is the immutable committed root fee currency"
                    )
                    .into(),
                )
                .into());
        }
        if parse_config_asset_definition_id(
            &state_transaction.world,
            &state_transaction.nexus.staking.stake_asset_id,
            state_transaction.block_unix_timestamp_ms(),
        )
        .is_some_and(|configured| configured == asset_definition_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is configured as nexus staking asset definition (`nexus.staking.stake_asset_id`); update nexus config first"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((agreement_id, _)) =
            state_transaction
                .world
                .repo_agreements
                .iter()
                .find(|(_, agreement)| {
                    agreement.cash_leg().asset_definition_id() == &asset_definition_id
                        || agreement.collateral_leg().asset_definition_id() == &asset_definition_id
                })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is referenced by repo agreement state ({agreement_id}); retain asset definition for settlement audit references"
                    )
                    .into(),
                )
                .into());
        }
        if let Some((settlement_id, _)) =
            state_transaction
                .world
                .settlement_receipts
                .iter()
                .find(|(_, receipt)| {
                    receipt.details.movements().any(|movement| {
                        movement.source.definition() == &asset_definition_id
                            || movement.destination.definition() == &asset_definition_id
                    })
                })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is referenced by committed settlement receipt {settlement_id}"
                    )
                    .into(),
                )
                .into());
        }
        if state_transaction
            .world
            .public_lane_stake_custody
            .iter()
            .any(|(_, (asset, _))| asset.definition() == &asset_definition_id)
            || state_transaction
                .world
                .public_lane_stake_reserves
                .iter()
                .any(|(asset, _)| asset.definition() == &asset_definition_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot unregister asset definition {asset_definition_id}: it is referenced by pinned public-lane staking custody; release all held stake first"
                    )
                    .into(),
                )
                .into());
        }
        if state_transaction
            .world
            .sumeragi_npos_parameters()
            .map_err(|error| {
                state_transaction.attempt_error_to_instruction_error(error.map_rejection(
                    |message| InstructionExecutionError::InvariantViolation(message.into()),
                ))
            })?
            .is_some_and(|params| params.xor_asset_definition_id == asset_definition_id)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                    format!("cannot unregister asset definition {asset_definition_id}: it is the committed network XOR identity").into(),
                ).into());
        }
        let retirement = crate::smartcontracts::isi::asset::isi::QuantityRetirementOwner::retain(
            state_transaction,
            authority,
            crate::smartcontracts::isi::asset::isi::QuantityRetirementScope::Definition(
                &asset_definition_id,
            ),
            std::iter::once(&asset_definition_id),
        );
        remove_asset_definition_associated_permissions(state_transaction, &asset_definition_id);
        let mut assets_to_remove = Vec::new();
        assets_to_remove.extend(
            state_transaction
                .world
                .assets
                .iter()
                .filter(|(asset_id, _)| asset_id.definition() == &asset_definition_id)
                .map(|(asset_id, _)| asset_id)
                .cloned(),
        );
        let domain = state_transaction
            .world
            .asset_definition_domains
            .get(&asset_definition_id)
            .cloned();
        let mut events = Vec::with_capacity(assets_to_remove.len() + 1);
        for asset_id in assets_to_remove {
            if retirement
                .remove_asset(state_transaction, &asset_id)?
                .is_none()
            {
                error!(%asset_id, "asset not found. This is a bug");
            }
            events.push(DataEvent::asset(
                AssetEvent::Deleted(asset_id),
                domain.clone(),
            ));
        }
        let removed = retirement.retire_definition(state_transaction, &asset_definition_id)?;
        drop(retirement);
        if removed.is_none() {
            return Err(FindError::AssetDefinition(asset_definition_id).into());
        }
        state_transaction
            .world
            .clear_asset_definition_alias(&asset_definition_id);
        state_transaction
            .world
            .zk_assets
            .remove(asset_definition_id.clone());
        events.push(DataEvent::asset_definition(
            AssetDefinitionEvent::Deleted(asset_definition_id),
            domain,
        ));
        state_transaction.world.emit_events(events);
        Ok(())
    }
}
impl Execute for SetAssetDefinitionAlias {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let SetAssetDefinitionAlias {
            asset_definition_id,
            alias,
            lease_expiry_ms,
        } = self;
        if alias.is_none() && lease_expiry_ms.is_some() {
            return Err(InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(
                    "lease_expiry_ms requires alias binding".into(),
                ),
            )
            .into());
        }
        // Ensure definition exists and validate the alias against the display label and any
        // explicit human-readable name carried by the stored definition.
        let definition = state_transaction
            .world
            .asset_definition(&asset_definition_id)
            .map_err(Error::from)?;
        if definition.owned_by() != authority {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "only asset-definition owner {} may change alias for {asset_definition_id}",
                    definition.owned_by()
                )
                .into(),
            )
            .into());
        }
        validate_alias_for_asset_definition(alias.as_ref(), &definition)?;
        let home_dataspace = asset_definition_home_dataspace(state_transaction, &definition)?;
        validate_asset_definition_alias_route(state_transaction, alias.as_ref(), home_dataspace)?;
        let existing_alias = state_transaction
            .world
            .asset_definition_alias_bindings
            .get(&asset_definition_id)
            .map(|binding| binding.alias.clone());
        if let Some(alias) = alias.as_ref() {
            ensure_authority_can_manage_asset_definition_alias(
                state_transaction,
                authority,
                &asset_definition_id,
                alias,
            )?;
        }
        if let Some(existing_alias) = existing_alias.as_ref()
            && alias.as_ref() != Some(existing_alias)
        {
            ensure_authority_can_manage_asset_definition_alias(
                state_transaction,
                authority,
                &asset_definition_id,
                existing_alias,
            )?;
        }
        if let Some(alias) = alias {
            let bound_at_ms = state_transaction.block_unix_timestamp_ms();
            if lease_expiry_ms.is_some_and(|lease_expiry_ms| lease_expiry_ms <= bound_at_ms) {
                return Err(InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(
                        "lease_expiry_ms must be greater than the current block timestamp".into(),
                    ),
                )
                .into());
            }
            let grace_until_ms = alias_grace_until_ms(lease_expiry_ms);
            state_transaction.world.bind_asset_definition_alias(
                &asset_definition_id,
                alias,
                lease_expiry_ms,
                grace_until_ms,
                bound_at_ms,
            )?;
        } else {
            state_transaction
                .world
                .clear_asset_definition_alias(&asset_definition_id);
        }
        Ok(())
    }
}
impl Execute for SetContractAlias {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let SetContractAlias {
            contract_address,
            alias,
            lease_expiry_ms,
        } = self;
        if alias.is_none() && lease_expiry_ms.is_some() {
            return Err(InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(
                    "lease_expiry_ms requires alias binding".into(),
                ),
            )
            .into());
        }
        if let Some(alias) = alias {
            let contract_dataspace_id = contract_address.dataspace_id().map_err(|err| {
                InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                    err.to_string().into(),
                ))
            })?;
            let contract_deployed = state_transaction
                .world
                .contract_instances()
                .get(&contract_address)
                .is_some();
            if !contract_deployed
                && state_transaction
                    .nexus
                    .dataspace_catalog
                    .by_id(contract_dataspace_id)
                    .is_none()
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    "contract address dataspace is unknown".to_owned().into(),
                )
                .into());
            }
            if !contract_deployed {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!("contract {contract_address} is not deployed").into(),
                )
                .into());
            }
            let (_, _, alias_dataspace_id) =
                resolve_contract_alias_components(state_transaction, &alias)?;
            if alias_dataspace_id != contract_dataspace_id {
                return Err(InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(
                        "contract alias dataspace must match contract address dataspace".into(),
                    ),
                )
                .into());
            }
            ensure_authority_can_manage_contract_alias(state_transaction, authority, &alias)?;
            ensure_account_alias_namespace_available_for_contract_alias(state_transaction, &alias)?;
            let bound_at_ms = state_transaction.block_unix_timestamp_ms();
            if lease_expiry_ms.is_some_and(|lease_expiry_ms| lease_expiry_ms <= bound_at_ms) {
                return Err(InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(
                        "lease_expiry_ms must be greater than the current block timestamp".into(),
                    ),
                )
                .into());
            }
            let grace_until_ms = alias_grace_until_ms(lease_expiry_ms);
            state_transaction.world.bind_contract_alias(
                &contract_address,
                alias,
                lease_expiry_ms,
                grace_until_ms,
                bound_at_ms,
            )?;
        } else {
            if let Some(binding) = state_transaction
                .world
                .contract_alias_bindings()
                .get(&contract_address)
                .cloned()
            {
                if let Err(error) = ensure_authority_can_manage_contract_alias(
                    state_transaction,
                    authority,
                    &binding.alias,
                ) {
                    if state_transaction.is_execution_deferred() {
                        return Err(error.into());
                    }
                    ensure_authority_can_manage_stale_contract_alias(
                        state_transaction,
                        authority,
                        &contract_address,
                        &binding.alias,
                    )?;
                }
            }
            state_transaction
                .world
                .clear_contract_alias(&contract_address);
        }
        Ok(())
    }
}
impl Execute for SetKeyValue<AssetDefinition> {
    #[metrics(+"set_key_value_asset_definition")]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let SetKeyValue {
            object: asset_definition_id,
            key,
            value,
        } = self;
        if key.as_ref() == ASSET_ISSUER_USAGE_POLICY_METADATA_KEY
            && !crate::executor::is_initial_genesis_context(state_transaction)
            && state_transaction
                .world
                .asset_definition(&asset_definition_id)?
                .owned_by()
                != authority
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "issuer usage policy requires asset-definition owner".into(),
            )
            .into());
        }
        crate::smartcontracts::limits::enforce_json_size(
            state_transaction,
            &value,
            "max_metadata_value_bytes",
            crate::smartcontracts::limits::DEFAULT_JSON_LIMIT,
        )?;
        state_transaction
            .world
            .asset_definition_metadata_mut(&asset_definition_id)
            .map_err(Error::from)
            .map(|mut asset_definition| {
                asset_definition
                    .metadata_mut()
                    .insert(key.clone(), value.clone())
            })?;
        state_transaction.world.emit_asset_definition_event(
            AssetDefinitionEvent::MetadataInserted(MetadataChanged {
                target: asset_definition_id,
                key,
                value,
            }),
        );
        Ok(())
    }
}
impl Execute for RemoveKeyValue<AssetDefinition> {
    #[metrics(+"remove_key_value_asset_definition")]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let asset_definition_id = self.object().clone();
        if self.key().as_ref() == ASSET_ISSUER_USAGE_POLICY_METADATA_KEY
            && !crate::executor::is_initial_genesis_context(state_transaction)
            && state_transaction
                .world
                .asset_definition(&asset_definition_id)?
                .owned_by()
                != authority
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "issuer usage policy requires asset-definition owner".into(),
            )
            .into());
        }
        let value = state_transaction
            .world
            .asset_definition_metadata_mut(&asset_definition_id)
            .and_then(|mut asset_definition| {
                asset_definition
                    .metadata_mut()
                    .remove(self.key().as_ref())
                    .ok_or_else(|| FindError::MetadataKey(self.key().clone()))
            })?;
        state_transaction
            .world
            .emit_asset_definition_event(AssetDefinitionEvent::MetadataRemoved(MetadataChanged {
                target: asset_definition_id,
                key: self.key().clone(),
                value,
            }));
        Ok(())
    }
}
impl Execute for SetKeyValue<Domain> {
    #[metrics(+"set_domain_key_value")]
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let SetKeyValue {
            object: domain_id,
            key,
            value,
        } = self;
        if crate::smartcontracts::isi::kaigi::is_reserved_kaigi_metadata_key(&key) {
            return Err(Error::InvariantViolation(
                format!("domain metadata key `{key}` is reserved for native Kaigi state").into(),
            ));
        }
        crate::smartcontracts::isi::kaigi::validate_kaigi_relay_allowlist_metadata(&key, &value)
            .map_err(|error| {
                state_transaction
                    .world
                    .attempt_error_to_instruction_error(error)
            })?;
        crate::smartcontracts::limits::enforce_json_size(
            state_transaction,
            &value,
            "max_metadata_value_bytes",
            crate::smartcontracts::limits::DEFAULT_JSON_LIMIT,
        )?;
        let domain = state_transaction.world.domain_mut(&domain_id)?;
        domain.metadata_mut().insert(key.clone(), value.clone());
        state_transaction
            .world
            .emit_events(Some(DomainEvent::MetadataInserted(MetadataChanged {
                target: domain_id,
                key,
                value,
            })));
        Ok(())
    }
}
// centralized in smartcontracts::limits
impl Execute for RemoveKeyValue<Domain> {
    #[metrics(+"remove_domain_key_value")]
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let domain_id = self.object().clone();
        if crate::smartcontracts::isi::kaigi::is_reserved_kaigi_metadata_key(self.key()) {
            return Err(Error::InvariantViolation(
                format!(
                    "domain metadata key `{}` is reserved for native Kaigi state",
                    self.key()
                )
                .into(),
            ));
        }
        let domain = state_transaction.world.domain_mut(&domain_id)?;
        let value = domain
            .metadata_mut()
            .remove(self.key().as_ref())
            .ok_or_else(|| FindError::MetadataKey(self.key().clone()))?;
        state_transaction
            .world
            .emit_events(Some(DomainEvent::MetadataRemoved(MetadataChanged {
                target: domain_id,
                key: self.key().clone(),
                value,
            })));
        Ok(())
    }
}
impl Execute for Transfer<Account, DomainId, Account> {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Transfer {
            source,
            object,
            destination,
        } = self;
        let _ = state_transaction.world.account(&source)?;
        let _ = state_transaction.world.account(&destination)?;
        let authority_is_source_owner = authority == &source;
        let authority_is_transferred_domain_owner =
            state_transaction.world.domain(&object)?.owned_by() == authority;
        if !(authority_is_source_owner || authority_is_transferred_domain_owner) {
            return Err(Error::InvariantViolation(
                "Can't transfer domain of another account".to_owned().into(),
            ));
        }
        let next_musubi_owner_generation = (source != destination)
            .then(|| {
                let current_generation = match state_transaction
                    .world
                    .musubi_domain_ownership_generations()
                    .get(&object)
                    .copied()
                {
                    None => 1,
                    Some(generation) if generation >= 2 => generation,
                    Some(_) => {
                        return Err(Error::InvariantViolation(
                            "Musubi domain ownership generation is noncanonical".into(),
                        ));
                    }
                };
                current_generation.checked_add(1).ok_or_else(|| {
                    Error::InvariantViolation("Musubi domain ownership generation overflow".into())
                })
            })
            .transpose()?;
        {
            let domain = state_transaction.world.domain_mut(&object)?;
            if domain.owned_by() != &source {
                return Err(Error::InvariantViolation(
                    format!("Can't transfer domain {domain} since {source} doesn't own it",).into(),
                ));
            }
            domain.set_owned_by(destination.clone());
        }
        if let Some(next_generation) = next_musubi_owner_generation {
            state_transaction
                .world
                .musubi_domain_ownership_generations_mut()
                .insert(object.clone(), next_generation);
        }
        state_transaction
            .world
            .replace_domain_owner_index(&object, &source, &destination);
        state_transaction
            .world
            .emit_events(Some(DomainEvent::OwnerChanged(DomainOwnerChanged {
                domain: object,
                new_owner: destination,
            })));
        Ok(())
    }
}
pub(crate) fn ensure_controller_capabilities(
    controller: &AccountController,
    allowed_algorithms: &[Algorithm],
    allowed_curve_ids: &[u8],
) -> Result<(), InstructionExecutionError> {
    if let Some(disallowed) = first_disallowed_algorithm(controller, allowed_algorithms)? {
        let allowed_summary = if allowed_algorithms.is_empty() {
            "none".to_string()
        } else {
            allowed_algorithms
                .iter()
                .copied()
                .map(Algorithm::as_static_str)
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "account controller uses signing algorithm {disallowed} which is not \
                     permitted by crypto.allowed_signing (allowed: {allowed_summary})"
            )
            .into(),
        ));
    }
    if let Some(curve) = first_disallowed_curve(controller, allowed_curve_ids)? {
        let algo = curve.algorithm();
        let curve_code: u8 = curve.into();
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "account controller uses curve id {curve_code:#04X} ({}) which is not \
                     permitted by crypto.curves.allowed_curve_ids",
                algo.as_static_str()
            )
            .into(),
        ));
    }
    Ok(())
}
fn first_disallowed_algorithm(
    controller: &AccountController,
    allowed: &[Algorithm],
) -> Result<Option<Algorithm>, InstructionExecutionError> {
    match controller {
        AccountController::Single(signatory) => Ok(algorithm_if_disallowed(
            controller_algorithm(signatory)?,
            allowed,
        )),
        AccountController::Multisig(policy) => {
            for member in policy.members() {
                if let Some(disallowed) =
                    algorithm_if_disallowed(controller_algorithm(member.public_key())?, allowed)
                {
                    return Ok(Some(disallowed));
                }
            }
            Ok(None)
        }
    }
}
fn controller_algorithm(public_key: &PublicKey) -> Result<Algorithm, InstructionExecutionError> {
    public_key.try_algorithm().map_err(|err| {
        InstructionExecutionError::InvariantViolation(
            format!("account controller public key is malformed: {err}").into(),
        )
    })
}
fn algorithm_if_disallowed(algo: Algorithm, allowed: &[Algorithm]) -> Option<Algorithm> {
    if allowed.contains(&algo) || is_bls_algorithm(algo) {
        None
    } else {
        Some(algo)
    }
}
fn first_disallowed_curve(
    controller: &AccountController,
    allowed_curve_ids: &[u8],
) -> Result<Option<CurveId>, InstructionExecutionError> {
    match controller {
        AccountController::Single(signatory) => {
            let algo = controller_algorithm(signatory)?;
            curve_if_disallowed(algo, allowed_curve_ids).map_err(|err| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "account controller uses signing algorithm {} which is not registered in \
                             the account curve registry: {err}",
                        algo.as_static_str()
                    )
                    .into(),
                )
            })
        }
        AccountController::Multisig(policy) => {
            for member in policy.members() {
                let algo = controller_algorithm(member.public_key())?;
                match curve_if_disallowed(algo, allowed_curve_ids) {
                    Ok(Some(curve)) => return Ok(Some(curve)),
                    Ok(None) => {}
                    Err(err) => {
                        return Err(InstructionExecutionError::InvariantViolation(
                                format!(
                                    "account controller uses signing algorithm {} which is not registered in \
                                     the account curve registry: {err}",
                                    algo.as_static_str()
                                )
                                .into(),
                            ));
                    }
                }
            }
            Ok(None)
        }
    }
}
fn curve_if_disallowed(
    algo: Algorithm,
    allowed_curve_ids: &[u8],
) -> Result<Option<CurveId>, CurveRegistryError> {
    if is_bls_algorithm(algo) {
        // Consensus validators rely on BLS controller keys even when admission is restricted.
        return Ok(None);
    }
    let curve = CurveId::try_from_algorithm(algo)?;
    if allowed_curve_ids.contains(&curve.as_u8()) {
        Ok(None)
    } else {
        Ok(Some(curve))
    }
}
fn is_bls_algorithm(algo: Algorithm) -> bool {
    #[cfg(feature = "bls")]
    {
        matches!(algo, Algorithm::BlsNormal | Algorithm::BlsSmall)
    }
    #[cfg(not(feature = "bls"))]
    {
        let _ = algo;
        false
    }
}

/// AMX consent cleanup follows the exact debited account and asset definition.
#[cfg(test)]
mod amx_permission_association_tests {
    use super::*;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{NetworkId, asset::AssetBalanceScope, sumeragi_amx::AmxDebitApprovalV1};
    use iroha_test_samples::{ALICE_ID, BOB_ID};

    fn approval_permission() -> (Permission, AssetDefinitionId) {
        let definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("bank", "universal").unwrap(),
            "cash".parse().unwrap(),
        );
        let dataspace = DataSpaceId::new(7);
        let approval = AmxDebitApprovalV1 {
            global_network: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"global"),
            )),
            participant_network: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"bank"),
            )),
            participant_instance: [1; 32],
            dataspace,
            transaction_id: [2; 32],
            debited_asset: AssetId::with_scope(
                definition.clone(),
                ALICE_ID.clone(),
                AssetBalanceScope::Dataspace(dataspace),
            ),
        };
        (approval.permission().unwrap(), definition)
    }

    #[test]
    fn amx_permission_is_associated_only_with_its_debited_account() {
        let (permission, _) = approval_permission();
        assert!(is_permission_account_associated(&permission, &ALICE_ID));
        assert!(!is_permission_account_associated(&permission, &BOB_ID));
    }

    #[test]
    fn amx_permission_is_associated_only_with_its_debited_definition() {
        let (permission, definition) = approval_permission();
        let other = AssetDefinitionId::derive_from_components(
            DomainId::try_new("bank", "universal").unwrap(),
            "other".parse().unwrap(),
        );
        assert!(is_permission_asset_definition_associated(
            &permission,
            &definition
        ));
        assert!(!is_permission_asset_definition_associated(
            &permission,
            &other
        ));
    }
}
