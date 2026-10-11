fn initial_permission_is_genesis_only(permission: &Permission) -> bool {
    INITIAL_GENESIS_ONLY_PERMISSION_NAMES.contains(&permission.name().as_ref())
}
fn invalid_initial_permission_payload(
    permission: &Permission,
    error: impl core::fmt::Debug,
) -> ValidationFail {
    ValidationFail::NotPermitted(format!(
        "{permission:?}: Invalid permission payload ({error:?})"
    ))
}
fn validate_initial_permission_payload_constraints(
    permission: &Permission,
) -> Result<(), ValidationFail> {
    macro_rules! validate_governance_selector {
        ($permission_ty:path) => {{
            let token = <$permission_ty>::try_from(permission)
                .map_err(|error| invalid_initial_permission_payload(permission, error))?;
            if !iroha_data_model::governance::is_valid_governance_selector_v1(&token.referendum_id)
            {
                return Err(invalid_initial_permission_payload(
                    permission,
                    format!(
                        "referendum_id must match canonical governance selector V1 `{}`",
                        iroha_data_model::governance::GOVERNANCE_SELECTOR_V1_PATTERN
                    ),
                ));
            }
        }};
    }
    macro_rules! validate_exact_unit_permission {
        ($permission_ty:path) => {{
            let _ = <$permission_ty>::try_from(permission)
                .map_err(|error| invalid_initial_permission_payload(permission, error))?;
        }};
    }
    macro_rules! validate_exact_deployment_permission {
        ($permission_ty:path) => {{
            let token = <$permission_ty>::try_from(permission)
                .map_err(|error| invalid_initial_permission_payload(permission, error))?;
            if Permission::from(token) != *permission {
                return Err(invalid_initial_permission_payload(
                    permission,
                    "permission requires the exact deployment scope",
                ));
            }
        }};
    }
    match permission.name().as_ref() {
        "CanUseContractPermission" => validate_exact_deployment_permission!(
            executor_permission::smart_contract::CanUseContractPermission
        ),
        "CanGrantDpnUserForAccountDomain" => validate_exact_deployment_permission!(
            executor_permission::dpn::CanGrantDpnUserForAccountDomain
        ),
        "CanManageSmartContractCode"
        | "CanGrantSmartContractCodeManagement"
        | "CanManageSoracloud"
        | "CanBindSorafsAlias"
        | "CanDeclareSorafsCapacity"
        | "CanSubmitSorafsTelemetry"
        | "CanFileSorafsCapacityDispute"
        | "CanIssueSorafsReplicationOrder"
        | "CanSetSorafsPricing"
        | "CanSetSorafsReservePolicy"
        | "CanManageSorafsModeration"
        | "CanManageSorafsPopRegistry"
        | "CanOperateSorafsPopIssuer"
        | "CanUpsertSorafsProviderCredit"
        | "CanManageSorafsProofOutcomePolicy"
        | "CanManageSorafsReputationJournalPolicy"
        | "CanManageSorafsStreamTokenGateway"
        | "CanRecordSorafsReputationJournal"
        | "CanResolveSorafsCapacityDispute" => {
            if permission.payload() != &Json::new(()) {
                return Err(invalid_initial_permission_payload(
                    permission,
                    "permission requires the unit payload",
                ));
            }
        }
        "CanManageSorafsFinalPromotionCustody" => validate_exact_deployment_permission!(
            executor_permission::sorafs::CanManageSorafsFinalPromotionCustody
        ),
        "CanOperateSorafsFinalPromotion" => validate_exact_deployment_permission!(
            executor_permission::sorafs::CanOperateSorafsFinalPromotion
        ),
        "CanCheckSorafsFinalPromotion" => validate_exact_deployment_permission!(
            executor_permission::sorafs::CanCheckSorafsFinalPromotion
        ),
        "CanManageSorafsFinalPromotionAccountCustody" => validate_exact_deployment_permission!(
            executor_permission::sorafs::CanManageSorafsFinalPromotionAccountCustody
        ),
        "CanCheckSorafsFinalPromotionAccountCustody" => validate_exact_deployment_permission!(
            executor_permission::sorafs::CanCheckSorafsFinalPromotionAccountCustody
        ),
        "CanOperateSorafsStreamTokenGateway" => {
            let token = executor_permission::sorafs::CanOperateSorafsStreamTokenGateway::try_from(
                permission,
            )
            .map_err(|error| invalid_initial_permission_payload(permission, error))?;
            if token.gateway_id == [0; 32] || Permission::from(token) != *permission {
                return Err(invalid_initial_permission_payload(
                    permission,
                    "permission requires the exact nonzero gateway scope",
                ));
            }
        }
        "CanCheckSorafsStreamTokenGateway" => {
            let token =
                executor_permission::sorafs::CanCheckSorafsStreamTokenGateway::try_from(permission)
                    .map_err(|error| invalid_initial_permission_payload(permission, error))?;
            if token.gateway_id == [0; 32] || Permission::from(token) != *permission {
                return Err(invalid_initial_permission_payload(
                    permission,
                    "permission requires the exact nonzero gateway scope",
                ));
            }
        }
        "CanManageSorafsStreamTokenCustody" => {
            let token = executor_permission::sorafs::CanManageSorafsStreamTokenCustody::try_from(
                permission,
            )
            .map_err(|error| invalid_initial_permission_payload(permission, error))?;
            if Permission::from(token) != *permission {
                return Err(invalid_initial_permission_payload(
                    permission,
                    "permission requires the exact provider scope",
                ));
            }
        }
        "CanCompleteSorafsReplicationOrder" => {
            let token = executor_permission::sorafs::CanCompleteSorafsReplicationOrder::try_from(
                permission,
            )
            .map_err(|error| invalid_initial_permission_payload(permission, error))?;
            if token.provider_id.as_bytes() == &[0; 32] || Permission::from(token) != *permission {
                return Err(invalid_initial_permission_payload(
                    permission,
                    "permission requires the exact nonzero provider scope",
                ));
            }
        }
        "CanOperateSorafsRepair" => {
            let token = executor_permission::sorafs::CanOperateSorafsRepair::try_from(permission)
                .map_err(|error| invalid_initial_permission_payload(permission, error))?;
            if Permission::from(token) != *permission {
                return Err(invalid_initial_permission_payload(
                    permission,
                    "permission requires the exact provider scope",
                ));
            }
        }
        "CanRecordSorafsProofOutcome" => {
            let token =
                executor_permission::sorafs::CanRecordSorafsProofOutcome::try_from(permission)
                    .map_err(|error| invalid_initial_permission_payload(permission, error))?;
            if Permission::from(token) != *permission {
                return Err(invalid_initial_permission_payload(
                    permission,
                    "permission requires the exact provider scope",
                ));
            }
        }
        "CanGovernSoracloudFhe" => {
            let scope = permission
                .payload()
                .try_into_any_norito::<iroha_data_model::soracloud::SoracloudFheGovernancePermissionScopeV1>()
                .map_err(|error| invalid_initial_permission_payload(permission, error))?;
            scope
                .validate()
                .map_err(|error| invalid_initial_permission_payload(permission, error))?;
            if permission.payload() != &Json::new(scope) {
                return Err(invalid_initial_permission_payload(
                    permission,
                    "permission requires the exact service and policy scope",
                ));
            }
        }
        "CanManageRuntimeUpgrades" => validate_exact_unit_permission!(
            executor_permission::governance::CanManageRuntimeUpgrades
        ),
        "CanManageConsensusKeys" => {
            validate_exact_unit_permission!(executor_permission::governance::CanManageConsensusKeys)
        }
        "CanManageConfidentialParams" => validate_exact_unit_permission!(
            executor_permission::governance::CanManageConfidentialParams
        ),
        "CanSubmitGovernanceBallot" => validate_governance_selector!(
            executor_permission::governance::CanSubmitGovernanceBallot
        ),
        "CanSlashGovernanceLock" => {
            validate_governance_selector!(executor_permission::governance::CanSlashGovernanceLock)
        }
        "CanRestituteGovernanceLock" => validate_governance_selector!(
            executor_permission::governance::CanRestituteGovernanceLock
        ),
        _ => {}
    }
    Ok(())
}
fn sns_permission_attempt_error(
    error: crate::sns::SnsError,
) -> crate::execution_attempt::ExecutionAttemptError<ValidationFail> {
    if cfg!(all(test, sumeragi_core_mutation = "HC35")) {
        return crate::execution_attempt::ExecutionAttemptError::Rejected(
            ValidationFail::InternalError(error.to_string()),
        );
    }
    error.into_attempt_error(|error| ValidationFail::InternalError(error.to_string()))
}

fn initial_alias_scope_owned_by(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    scope: &executor_permission::account::AccountAliasPermissionScope,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    match scope {
        executor_permission::account::AccountAliasPermissionScope::Domain(domain) => {
            authority_owns_domain(&state_transaction.world, authority, domain).map_err(Into::into)
        }
        executor_permission::account::AccountAliasPermissionScope::Dataspace(dataspace) => {
            let now_ms = state_transaction.block_unix_timestamp_ms();
            Ok(crate::sns::active_dataspace_owner_by_id(
                &state_transaction.world,
                state_transaction.world.dataspace_catalog(),
                *dataspace,
                now_ms,
            )
            .map_err(sns_permission_attempt_error)?
            .as_ref()
                == Some(authority))
        }
        executor_permission::account::AccountAliasPermissionScope::Alias(alias) => {
            Ok(state_transaction
                .world
                .account_aliases()
                .get(&alias.account_alias())
                .is_some_and(|owner| owner == authority))
        }
    }
}
fn initial_asset_definition_alias_scope_owned_by(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    scope: &executor_permission::asset_definition::AssetDefinitionAliasPermissionScope,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    match scope {
        executor_permission::asset_definition::AssetDefinitionAliasPermissionScope::Domain(
            domain,
        ) => authority_owns_domain(&state_transaction.world, authority, domain).map_err(Into::into),
        executor_permission::asset_definition::AssetDefinitionAliasPermissionScope::Dataspace(
            dataspace,
        ) => {
            let now_ms = state_transaction.block_unix_timestamp_ms();
            Ok(crate::sns::active_dataspace_owner_by_id(
                &state_transaction.world,
                state_transaction.world.dataspace_catalog(),
                *dataspace,
                now_ms,
            )
            .map_err(sns_permission_attempt_error)?
            .as_ref()
                == Some(authority))
        }
        executor_permission::asset_definition::AssetDefinitionAliasPermissionScope::Alias(_) => {
            Ok(false)
        }
    }
}
fn initial_asset_definition_alias_namespace_scope(
    alias: &ResolvedAssetDefinitionAliasV1,
) -> Result<
    executor_permission::asset_definition::AssetDefinitionAliasPermissionScope,
    ValidationFail,
> {
    match alias.parent_domain() {
        Ok(Some(domain)) => Ok(
            executor_permission::asset_definition::AssetDefinitionAliasPermissionScope::Domain(
                domain,
            ),
        ),
        Ok(None) => Ok(
            executor_permission::asset_definition::AssetDefinitionAliasPermissionScope::Dataspace(
                alias.dataspace_id,
            ),
        ),
        Err(error) => Err(ValidationFail::NotPermitted(format!(
            "invalid exact asset-definition alias namespace `{alias}`: {error}"
        ))),
    }
}
fn initial_asset_definition_alias_namespace_root_authority(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    alias: &ResolvedAssetDefinitionAliasV1,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    if !alias.matches_catalog(state_transaction.world.dataspace_catalog()) {
        return Ok(false);
    }
    initial_asset_definition_alias_scope_owned_by(
        state_transaction,
        authority,
        &initial_asset_definition_alias_namespace_scope(alias)?,
    )
}
fn initial_asset_definition_alias_namespace_authority(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    alias: &ResolvedAssetDefinitionAliasV1,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    if !alias.matches_catalog(state_transaction.world.dataspace_catalog()) {
        return Ok(false);
    }
    let scope = initial_asset_definition_alias_namespace_scope(alias)?;
    let wider: Permission = executor_permission::asset_definition::CanManageAssetDefinitionAlias {
        scope: scope.clone(),
    }
    .into();
    Ok(
        authority_has_permission(&state_transaction.world, authority, &wider)?
            || initial_asset_definition_alias_scope_owned_by(state_transaction, authority, &scope)?,
    )
}
fn initial_asset_definition_alias_exact_grant_authority(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    alias: &ResolvedAssetDefinitionAliasV1,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    if !alias.matches_catalog(state_transaction.world.dataspace_catalog()) {
        return Ok(false);
    }
    let Some(asset_definition_id) = state_transaction
        .world
        .asset_definition_aliases()
        .get(&alias.canonical_name)
    else {
        return Ok(false);
    };
    if !state_transaction
        .world
        .asset_definition_alias_bindings()
        .get(asset_definition_id)
        .is_some_and(|binding| binding.alias == alias.canonical_name)
    {
        return Ok(false);
    }
    Ok(
        authority_owns_asset_definition(&state_transaction.world, authority, asset_definition_id)?
            && initial_asset_definition_alias_namespace_authority(
                state_transaction,
                authority,
                alias,
            )?,
    )
}
fn initial_nft_transfer_authority(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    nft_id: &iroha_data_model::nft::NftId,
) -> Result<bool, ValidationFail> {
    let owner = state_transaction
        .world
        .nft(nft_id)
        .map(|nft| nft.owned_by.clone())
        .map_err(|error| {
            ValidationFail::InstructionFailed(InstructionExecutionError::Find(error))
        })?;
    Ok(owner == *authority
        || authority_owns_domain(&state_transaction.world, authority, nft_id.domain())?)
}
fn initial_trigger_authority(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    trigger_id: &iroha_data_model::trigger::TriggerId,
) -> Result<bool, ValidationFail> {
    use crate::smartcontracts::isi::triggers::set::SetReadOnly as _;
    state_transaction
        .world
        .triggers()
        .inspect_by_id(trigger_id, |action| action.authority() == authority)
        .ok_or_else(|| {
            ValidationFail::NotPermitted(format!(
                "permission references unknown trigger `{trigger_id}`"
            ))
        })
}
#[allow(clippy::too_many_lines)]
/// Return whether `authority` is a legitimate non-token root for delegating `permission`.
///
/// The root must already control the same effective capability at use time, or hold an
/// explicitly wider parent capability. Merely owning an adjacent component of a compound
/// permission scope is not a delegation root. Exact holders are handled separately by
/// [`initial_permission_delegation_allowed`].
fn initial_permission_capability_root_authority(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: &Permission,
) -> Result<Option<bool>, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    validate_initial_permission_payload_constraints(permission)?;
    macro_rules! decode {
        ($permission_ty:path) => {
            <$permission_ty>::try_from(permission)
                .map_err(|error| invalid_initial_permission_payload(permission, error))?
        };
    }
    let result = match permission.name().as_ref() {
        "CanUnregisterDomain" => {
            let token = decode!(executor_permission::domain::CanUnregisterDomain);
            authority_owns_domain(&state_transaction.world, authority, &token.domain)?
        }
        "CanModifyDomainMetadata" => {
            let token = decode!(executor_permission::domain::CanModifyDomainMetadata);
            authority_owns_domain(&state_transaction.world, authority, &token.domain)?
        }
        "CanRegisterAccount" => {
            let token = decode!(executor_permission::account::CanRegisterAccount);
            authority_owns_domain(&state_transaction.world, authority, &token.domain)?
        }
        "CanUnregisterAccount" => {
            let token = decode!(executor_permission::account::CanUnregisterAccount);
            token.account == *authority
        }
        "CanModifyAccountMetadata" => {
            let token = decode!(executor_permission::account::CanModifyAccountMetadata);
            token.account == *authority
        }
        "CanReplaceAccountController" => {
            let token = decode!(executor_permission::account::CanReplaceAccountController);
            token.account == *authority
        }
        "CanReadAccountData" => {
            let token = decode!(executor_permission::query::CanReadAccountData);
            token.account == *authority
        }
        "CanResolveAccountAlias" => {
            let token = decode!(executor_permission::account::CanResolveAccountAlias);
            let delegation: Permission =
                executor_permission::account::CanDelegateAccountAliasResolution {
                    scope: token.scope.clone(),
                }
                .into();
            authority_has_permission(&state_transaction.world, authority, &delegation)?
                || initial_alias_scope_owned_by(state_transaction, authority, &token.scope)?
        }
        "CanDelegateAccountAliasResolution" => {
            let token = decode!(executor_permission::account::CanDelegateAccountAliasResolution);
            initial_alias_scope_owned_by(state_transaction, authority, &token.scope)?
        }
        "CanManageAccountAlias" => {
            let token = decode!(executor_permission::account::CanManageAccountAlias);
            initial_alias_scope_owned_by(state_transaction, authority, &token.scope)?
        }
        "CanManageAssetDefinitionAlias" => {
            let token =
                decode!(executor_permission::asset_definition::CanManageAssetDefinitionAlias);
            match &token.scope {
                executor_permission::asset_definition::AssetDefinitionAliasPermissionScope::Alias(
                    alias,
                ) => initial_asset_definition_alias_exact_grant_authority(
                    state_transaction,
                    authority,
                    alias,
                )?,
                scope => initial_asset_definition_alias_scope_owned_by(
                    state_transaction,
                    authority,
                    scope,
                )?,
            }
        }
        "CanUnregisterAssetDefinition" => {
            let token =
                decode!(executor_permission::asset_definition::CanUnregisterAssetDefinition);
            authority_owns_asset_definition(
                &state_transaction.world,
                authority,
                &token.asset_definition,
            )?
        }
        "CanModifyAssetDefinitionMetadata" => {
            let token =
                decode!(executor_permission::asset_definition::CanModifyAssetDefinitionMetadata);
            authority_owns_asset_definition(
                &state_transaction.world,
                authority,
                &token.asset_definition,
            )?
        }
        "CanManageKagemushaWallet" => {
            let token = decode!(executor_permission::asset_definition::CanManageKagemushaWallet);
            authority_owns_asset_definition(
                &state_transaction.world,
                authority,
                &token.asset_definition,
            )?
        }
        "CanManageAssetDefinitionConfidentialPolicy" => {
            let token = decode!(
                executor_permission::asset_definition::CanManageAssetDefinitionConfidentialPolicy
            );
            authority_owns_asset_definition(
                &state_transaction.world,
                authority,
                &token.asset_definition,
            )?
        }
        "CanMintAssetWithDefinition" => {
            let token = decode!(executor_permission::asset::CanMintAssetWithDefinition);
            authority_owns_asset_definition(
                &state_transaction.world,
                authority,
                &token.asset_definition,
            )?
        }
        "CanBurnAssetWithDefinition" => {
            let token = decode!(executor_permission::asset::CanBurnAssetWithDefinition);
            authority_owns_asset_definition(
                &state_transaction.world,
                authority,
                &token.asset_definition,
            )?
        }
        "CanTransferAssetWithDefinition" => {
            let token = decode!(executor_permission::asset::CanTransferAssetWithDefinition);
            authority_owns_asset_definition(
                &state_transaction.world,
                authority,
                &token.asset_definition,
            )?
        }
        "CanModifyAssetMetadataWithDefinition" => {
            let token = decode!(executor_permission::asset::CanModifyAssetMetadataWithDefinition);
            authority_owns_asset_definition(
                &state_transaction.world,
                authority,
                &token.asset_definition,
            )?
        }
        "CanSetAssetTransferAvailability" => {
            let token = decode!(executor_permission::asset::CanSetAssetTransferAvailability);
            authority_owns_asset_definition(
                &state_transaction.world,
                authority,
                &token.asset_definition,
            )?
        }
        "CanSetAssetTransferDailyLimit" => {
            let token = decode!(executor_permission::asset::CanSetAssetTransferDailyLimit);
            authority_owns_asset_definition(
                &state_transaction.world,
                authority,
                &token.asset_definition,
            )?
        }
        "CanSetAssetHoldingLimit" => {
            let token = decode!(executor_permission::asset::CanSetAssetHoldingLimit);
            authority_owns_asset_definition(
                &state_transaction.world,
                authority,
                &token.asset_definition,
            )?
        }
        "CanMintAssetToAccount" => {
            let token = decode!(executor_permission::asset::CanMintAssetToAccount);
            authority_owns_asset_definition(
                &state_transaction.world,
                authority,
                &token.asset_definition,
            )?
        }
        "CanBurnAsset" => {
            let token = decode!(executor_permission::asset::CanBurnAsset);
            token.asset.account() == authority
                || authority_owns_asset_definition(
                    &state_transaction.world,
                    authority,
                    token.asset.definition(),
                )?
        }
        "CanTransferAsset" => {
            let token = decode!(executor_permission::asset::CanTransferAsset);
            token.asset.account() == authority
        }
        "CanModifyAssetMetadata" => {
            let token = decode!(executor_permission::asset::CanModifyAssetMetadata);
            token.asset.account() == authority
                || authority_owns_asset_definition(
                    &state_transaction.world,
                    authority,
                    token.asset.definition(),
                )?
        }
        "CanRegisterNft" => {
            let token = decode!(executor_permission::nft::CanRegisterNft);
            authority_owns_domain(&state_transaction.world, authority, &token.domain)?
        }
        "CanUnregisterNft" => {
            let token = decode!(executor_permission::nft::CanUnregisterNft);
            authority_owns_domain(&state_transaction.world, authority, token.nft.domain())?
        }
        "CanTransferNft" => {
            let token = decode!(executor_permission::nft::CanTransferNft);
            initial_nft_transfer_authority(state_transaction, authority, &token.nft)?
        }
        "CanModifyNftMetadata" => {
            let token = decode!(executor_permission::nft::CanModifyNftMetadata);
            authority_owns_domain(&state_transaction.world, authority, token.nft.domain())?
        }
        "CanRegisterTrigger" => {
            let token = decode!(executor_permission::trigger::CanRegisterTrigger);
            token.authority == *authority
        }
        "CanUnregisterTrigger" => {
            let token = decode!(executor_permission::trigger::CanUnregisterTrigger);
            initial_trigger_authority(state_transaction, authority, &token.trigger)?
        }
        "CanModifyTrigger" => {
            let token = decode!(executor_permission::trigger::CanModifyTrigger);
            initial_trigger_authority(state_transaction, authority, &token.trigger)?
        }
        "CanExecuteTrigger" => {
            let token = decode!(executor_permission::trigger::CanExecuteTrigger);
            initial_trigger_authority(state_transaction, authority, &token.trigger)?
        }
        "CanModifyTriggerMetadata" => {
            let token = decode!(executor_permission::trigger::CanModifyTriggerMetadata);
            initial_trigger_authority(state_transaction, authority, &token.trigger)?
        }
        "CanManageSmartContractCode" => {
            let _ = decode!(executor_permission::smart_contract::CanManageSmartContractCode);
            let manager: Permission =
                executor_permission::smart_contract::CanGrantSmartContractCodeManagement.into();
            authority_has_permission(&state_transaction.world, authority, &manager)?
        }
        "CanManageSorafsStreamTokenGateway" => false,
        "CanOperateSorafsStreamTokenGateway" | "CanCheckSorafsStreamTokenGateway" => {
            let gateway_id = if permission.name() == "CanOperateSorafsStreamTokenGateway" {
                decode!(executor_permission::sorafs::CanOperateSorafsStreamTokenGateway).gateway_id
            } else {
                decode!(executor_permission::sorafs::CanCheckSorafsStreamTokenGateway).gateway_id
            };
            let manager: Permission =
                executor_permission::sorafs::CanManageSorafsStreamTokenGateway.into();
            if state_transaction.world.accounts().get(authority).is_none()
                || !authority_has_permission(&state_transaction.world, authority, &manager)?
            {
                false
            } else {
                // A real same-network policy roots this exact scope. Admission eligibility is
                // deliberately separate: disabled or expired policies must still drain safely.
                crate::query::stream_token_gateway::storage::read_current(
                    state_transaction.world(),
                    state_transaction.network_id(),
                    gateway_id,
                )
                .map_err(|_| {
                    ValidationFail::NotPermitted(
                        "gateway permission requires an intact configured policy".to_owned(),
                    )
                })?
                .is_some()
            }
        }
        "CanUseContractPermission" => {
            contract_permission_delegation_allowed(state_transaction, authority, permission)?
        }
        "CanInvokeContractEntrypoint" => contract_entrypoint_authorization_delegation_allowed(
            state_transaction,
            authority,
            permission,
        )?,
        "CanExecuteSettlement" => {
            let token = decode!(executor_permission::settlement::CanExecuteSettlement);
            token.debited_asset.account() == authority
        }
        "CanSetFxCorridorPolicy" => {
            let _ = decode!(executor_permission::settlement::CanSetFxCorridorPolicy);
            let manager: Permission = executor_permission::settlement::CanManageFxCorridors.into();
            authority_has_permission(&state_transaction.world, authority, &manager)?
        }
        "CanGrantDpnUserForAccountDomain" => {
            let token = decode!(executor_permission::dpn::CanGrantDpnUserForAccountDomain);
            let admin: Permission = executor_permission::dpn::DpnAdmin.into();
            authority_has_direct_permission(&state_transaction.world, authority, &admin)?
                && authority_owns_domain(&state_transaction.world, authority, &token.domain)?
                && crate::sns::active_domain_owner(
                    &state_transaction.world,
                    &token.domain,
                    state_transaction.block_unix_timestamp_ms(),
                )
                .map_err(sns_permission_attempt_error)?
                .as_ref()
                    == Some(authority)
        }
        "DpnAdmin" => {
            let _ = decode!(executor_permission::dpn::DpnAdmin);
            let admin: Permission = executor_permission::dpn::DpnAdmin.into();
            authority_has_direct_permission(&state_transaction.world, authority, &admin)?
        }
        "DpnUser" => {
            let _ = decode!(executor_permission::dpn::DpnUser);
            let admin: Permission = executor_permission::dpn::DpnAdmin.into();
            authority_has_direct_permission(&state_transaction.world, authority, &admin)?
        }
        "DpnInori" => {
            let _ = decode!(executor_permission::dpn::DpnInori);
            let admin: Permission = executor_permission::dpn::DpnAdmin.into();
            authority_has_direct_permission(&state_transaction.world, authority, &admin)?
        }
        "DpnSettlement" => {
            let _ = decode!(executor_permission::dpn::DpnSettlement);
            let admin: Permission = executor_permission::dpn::DpnAdmin.into();
            authority_has_direct_permission(&state_transaction.world, authority, &admin)?
        }
        "DpnEprGuard" => {
            let _ = decode!(executor_permission::dpn::DpnEprGuard);
            let admin: Permission = executor_permission::dpn::DpnAdmin.into();
            authority_has_direct_permission(&state_transaction.world, authority, &admin)?
        }
        "CanPublishSpaceDirectoryManifest" => {
            let _ = decode!(executor_permission::nexus::CanPublishSpaceDirectoryManifest);
            false
        }
        "CanPublishSpaceDirectoryManifestForUaid" => {
            let token =
                decode!(executor_permission::nexus::CanPublishSpaceDirectoryManifestForUaid);
            let wide: Permission = executor_permission::nexus::CanPublishSpaceDirectoryManifest {
                dataspace: token.dataspace,
            }
            .into();
            authority_has_permission(&state_transaction.world, authority, &wide)?
        }
        "CanPublishSpaceDirectoryManifestForAccountDomain" => {
            let token = decode!(
                executor_permission::nexus::CanPublishSpaceDirectoryManifestForAccountDomain
            );
            let wide: Permission = executor_permission::nexus::CanPublishSpaceDirectoryManifest {
                dataspace: token.dataspace,
            }
            .into();
            authority_has_permission(&state_transaction.world, authority, &wide)?
        }
        "CanManageFeeSponsorProgram" => {
            let token = decode!(executor_permission::nexus::CanManageFeeSponsorProgram);
            token.sponsor == *authority
        }
        "CanEnrollFeeSponsorProgram" => {
            let token = decode!(executor_permission::nexus::CanEnrollFeeSponsorProgram);
            let manager: Permission = executor_permission::nexus::CanManageFeeSponsorProgram {
                sponsor: token.program_id.sponsor.clone(),
            }
            .into();
            token.program_id.sponsor == *authority
                || authority_has_permission(&state_transaction.world, authority, &manager)?
        }
        "CanProposeContractDeployment" => {
            let _ = decode!(executor_permission::governance::CanProposeContractDeployment);
            false
        }
        "CanProposeRuntimeUpgrade" => {
            let _ = decode!(executor_permission::governance::CanProposeRuntimeUpgrade);
            false
        }
        "CanSubmitGovernanceBallot" => {
            let _ = decode!(executor_permission::governance::CanSubmitGovernanceBallot);
            false
        }
        "CanSlashGovernanceLock" => {
            let _ = decode!(executor_permission::governance::CanSlashGovernanceLock);
            false
        }
        "CanRestituteGovernanceLock" => {
            let _ = decode!(executor_permission::governance::CanRestituteGovernanceLock);
            false
        }
        "CanIssueSoranetVpnQuote" => {
            let _ = decode!(executor_permission::soranet::CanIssueSoranetVpnQuote);
            let manager: Permission =
                executor_permission::soranet::CanManageSoranetVpnQuoteIssuers.into();
            authority_has_permission(&state_transaction.world, authority, &manager)?
        }
        _ => return Ok(None),
    };
    Ok(Some(result))
}
/// Only the current owner or exact holder may delegate a currently declared instance permission.
/// Suspension retains this declaration catalog so grants can be repaired before resumption.
fn contract_permission_delegation_allowed(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: &Permission,
) -> Result<bool, ValidationFail> {
    let token = executor_permission::smart_contract::CanUseContractPermission::try_from(permission)
        .map_err(|error| invalid_initial_permission_payload(permission, error))?;
    let manifest =
        retained_contract_authorization_manifest(&state_transaction.world, &token.contract)?;
    if !manifest.permissions.iter().any(|declaration| {
        declaration.name == token.permission
            && matches!(declaration.scope, ContractPermissionScopeV1::Instance)
    }) {
        return Err(ValidationFail::NotPermitted(
            "scoped contract grant must name an Instance permission declared by the current code"
                .to_owned(),
        ));
    }
    let binding = code::fetch_contract_lifecycle_binding(&state_transaction.world, &token.contract)
        .map_err(ValidationFail::NotPermitted)?;
    if authority_has_permission(&state_transaction.world, authority, permission)? {
        return Ok(binding.is_some());
    }
    Ok(binding.is_some_and(|binding| matches!(&binding.lifecycle.owner,
        iroha_data_model::smart_contract::ContractLifecycleOwnerV1::Account(owner) if owner == authority)))
}
/// Single native authority rule for exact contract-entrypoint permission mutation.
fn contract_entrypoint_authorization_delegation_allowed(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: &Permission,
) -> Result<bool, ValidationFail> {
    let token =
        executor_permission::smart_contract::CanInvokeContractEntrypoint::try_from(permission)
            .map_err(|error| invalid_initial_permission_payload(permission, error))?;
    if token.entrypoint.is_empty() || token.entrypoint.trim() != token.entrypoint {
        return Err(ValidationFail::NotPermitted(
            "contract entrypoint permission must use a non-empty canonical selector".to_owned(),
        ));
    }
    if !matches!(
        token.entrypoint.as_str(),
        "hajimari" | "始まり" | "kaizen" | "改善"
    ) {
        return Err(ValidationFail::NotPermitted(
            "CanInvokeContractEntrypoint authorizes only runtime lifecycle hooks".to_owned(),
        ));
    }
    let manifest =
        retained_contract_authorization_manifest(&state_transaction.world, &token.contract)?;
    if !manifest.entrypoints.as_ref().is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry.name == token.entrypoint
                && matches!(
                    entry.authorization,
                    EntrypointAuthorizationV1::RuntimeLifecycle
                )
        })
    }) {
        return Err(ValidationFail::NotPermitted(
            "lifecycle grant must name a RuntimeLifecycle hook declared by the current code"
                .to_owned(),
        ));
    }
    if is_initial_genesis_context(state_transaction)
        || authority_has_permission(&state_transaction.world, authority, permission)?
        || authority_has_permission(
            &state_transaction.world,
            authority,
            &executor_permission::smart_contract::CanManageSmartContractCode.into(),
        )?
    {
        return Ok(true);
    }
    let binding = code::fetch_contract_lifecycle_binding(&state_transaction.world, &token.contract)
        .map_err(ValidationFail::NotPermitted)?;
    Ok(binding.is_some_and(|binding| {
        matches!(&binding.lifecycle.owner,
            iroha_data_model::smart_contract::ContractLifecycleOwnerV1::Account(owner) if owner == authority)
    }))
}
fn initial_permission_delegation_allowed(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: &Permission,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    if initial_permission_is_genesis_only(permission) {
        return Ok(false);
    }
    // Resolve and validate known payloads before consulting stored state. Otherwise a malformed
    // built-in token already present in state could be copied without ever decoding its scope.
    let capability_root =
        initial_permission_capability_root_authority(state_transaction, authority, permission)?;
    if permission.name() == "CanUseContractPermission" {
        return Ok(capability_root.unwrap_or(false));
    }
    let holder_delegable = if permission.name() == "CanManageAssetDefinitionAlias" {
        let token = executor_permission::asset_definition::CanManageAssetDefinitionAlias::try_from(
            permission,
        )
        .map_err(|error| invalid_initial_permission_payload(permission, error))?;
        !matches!(
            token.scope,
            executor_permission::asset_definition::AssetDefinitionAliasPermissionScope::Alias(_)
        )
    } else {
        !matches!(
            permission.name().as_ref(),
            "CanManageSmartContractCode"
                | "CanReadAccountData"
                | "CanResolveAccountAlias"
                | "CanIssueSoranetVpnQuote"
                | "CanExecuteSettlement"
                | "CanSetFxCorridorPolicy"
                | "CanManageFeeSponsorProgram"
                | "CanGrantDpnUserForAccountDomain"
                | "DpnAdmin"
                | "DpnUser"
                | "DpnInori"
                | "DpnSettlement"
                | "DpnEprGuard"
        )
    };
    if holder_delegable
        && authority_has_permission(&state_transaction.world, authority, permission)?
    {
        return Ok(true);
    }
    Ok(capability_root.unwrap_or(false))
}
/// The enrollment capability is direct, exact-domain and evaluated against current native SNS
/// ownership. Account registration alone or a stale alias index never confers this authority.
fn authority_can_enroll_dpn_account(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    destination: &AccountId,
    now_ms: u64,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    let account = match world.account(destination) {
        Ok(account) => account,
        Err(_) => return Ok(false),
    };
    let Some(uaid) = account.value().uaid() else {
        return Ok(false);
    };
    if world.uaid_accounts().get(uaid) != Some(destination) {
        return Ok(false);
    }
    let permissions = world.account_permissions_iter(authority).map_err(|error| {
        ValidationFail::InstructionFailed(InstructionExecutionError::Find(error))
    })?;
    for permission in permissions {
        if permission.name() != "CanGrantDpnUserForAccountDomain" {
            continue;
        }
        validate_initial_permission_payload_constraints(permission)?;
        let token = executor_permission::dpn::CanGrantDpnUserForAccountDomain::try_from(permission)
            .map_err(|error| invalid_initial_permission_payload(permission, error))?;
        for alias in world.bound_account_aliases(destination) {
            if alias
                .domain_id(world.dataspace_catalog())
                .ok()
                .flatten()
                .as_ref()
                != Some(&token.domain)
            {
                continue;
            }
            if crate::sns::resolve_active_account_alias(
                world,
                world.dataspace_catalog(),
                &alias,
                now_ms,
            )
            .map_err(sns_permission_attempt_error)?
            .as_ref()
                == Some(destination)
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
fn initial_permission_revocation_allowed(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: &Permission,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    if permission.name() == "CanGrantDpnUserForAccountDomain" {
        validate_initial_permission_payload_constraints(permission)?;
        let token = executor_permission::dpn::CanGrantDpnUserForAccountDomain::try_from(permission)
            .map_err(|error| invalid_initial_permission_payload(permission, error))?;
        let admin: Permission = executor_permission::dpn::DpnAdmin.into();
        if authority_has_direct_permission(&state_transaction.world, authority, &admin)? {
            return Ok(true);
        }
        return Ok(
            authority_owns_domain(&state_transaction.world, authority, &token.domain)?
                && crate::sns::active_domain_owner(
                    &state_transaction.world,
                    &token.domain,
                    state_transaction.block_unix_timestamp_ms(),
                )
                .map_err(sns_permission_attempt_error)?
                .as_ref()
                    == Some(authority),
        );
    }
    if permission.name() == "CanManageAssetDefinitionAlias" {
        let token = executor_permission::asset_definition::CanManageAssetDefinitionAlias::try_from(
            permission,
        )
        .map_err(|error| invalid_initial_permission_payload(permission, error))?;
        if let executor_permission::asset_definition::AssetDefinitionAliasPermissionScope::Alias(
            alias,
        ) = &token.scope
        {
            // An exact token retains the alias and dataspace identity after clear, but not the
            // former definition or grant issuer. Only the native namespace root is therefore a
            // provable lifecycle authority once the active binding is gone.
            return initial_asset_definition_alias_namespace_root_authority(
                state_transaction,
                authority,
                alias,
            );
        }
    }
    initial_permission_delegation_allowed(state_transaction, authority, permission)
}
fn validate_initial_account_permission_destination(
    _state_transaction: &StateTransaction<'_, '_>,
    permission: &Permission,
    _destination: &AccountId,
    is_genesis: bool,
    _is_revoke: bool,
) -> Result<(), ValidationFail> {
    if is_genesis
        && matches!(
            permission.name().as_ref(),
            "CanOperateSorafsStreamTokenGateway" | "CanCheckSorafsStreamTokenGateway"
        )
    {
        return Err(ValidationFail::NotPermitted(
            "gateway scoped permissions require a configured post-genesis scope".to_owned(),
        ));
    }
    Ok(())
}
fn validate_initial_permission_or_role_mutation(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: &InstructionBox,
    is_genesis: bool,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    let mutation = extract_permission_or_role_mutation(instruction);
    let Some(mutation) = mutation else {
        return Ok(());
    };
    match mutation {
        PermissionOrRoleMutation::AccountPermission {
            permission,
            destination,
            is_revoke,
        } => {
            validate_initial_permission_payload_constraints(permission)?;
            validate_initial_account_permission_destination(
                state_transaction,
                permission,
                destination,
                is_genesis,
                is_revoke,
            )?;
            let allowed = if is_revoke {
                initial_permission_revocation_allowed(state_transaction, authority, permission)?
            } else {
                initial_permission_delegation_allowed(state_transaction, authority, permission)?
            };
            let scoped_enrollment = !is_genesis
                && !allowed
                && !is_revoke
                && permission == &Permission::from(executor_permission::dpn::DpnUser)
                && authority_can_enroll_dpn_account(
                    &state_transaction.world,
                    authority,
                    destination,
                    state_transaction.block_unix_timestamp_ms(),
                )?;
            if is_genesis || allowed || scoped_enrollment {
                return Ok(());
            }
            Err(ValidationFail::NotPermitted(format!(
                "authority cannot grant or revoke permission `{}`",
                permission.name()
            ))
            .into())
        }
        PermissionOrRoleMutation::AccountRole {
            role: role_id,
            is_revoke,
        } => {
            if !is_genesis && !authority_has_role(&state_transaction.world, authority, role_id) {
                return Err(ValidationFail::NotPermitted(
                    "authority cannot grant or revoke a role it does not hold".to_owned(),
                )
                .into());
            }
            let role = state_transaction
                .world
                .roles()
                .get(role_id)
                .ok_or_else(|| {
                    ValidationFail::NotPermitted("cannot delegate an unknown role".to_owned())
                })?;
            for permission in role.permissions() {
                let normalized =
                    normalize_role_permission_for_initial_executor(state_transaction, permission)?;
                if !is_genesis {
                    let allowed = if is_revoke {
                        initial_permission_revocation_allowed(
                            state_transaction,
                            authority,
                            &normalized,
                        )?
                    } else {
                        initial_permission_delegation_allowed(
                            state_transaction,
                            authority,
                            &normalized,
                        )?
                    };
                    if !allowed {
                        return Err(ValidationFail::NotPermitted(format!(
                            "authority cannot grant or revoke role `{role_id}` because it cannot delegate contained permission `{}`",
                            normalized.name()
                        )).into());
                    }
                }
            }
            Ok(())
        }
        PermissionOrRoleMutation::RolePermission {
            permission,
            role,
            is_revoke,
        } => {
            let normalized =
                normalize_role_permission_for_initial_executor(state_transaction, permission)?;
            if is_genesis {
                return Ok(());
            }
            if !authority_has_role(&state_transaction.world, authority, role) {
                return Err(ValidationFail::NotPermitted(
                    "authority cannot modify a role it does not hold".to_owned(),
                )
                .into());
            }
            let allowed = if is_revoke {
                initial_permission_revocation_allowed(state_transaction, authority, &normalized)?
            } else {
                initial_permission_delegation_allowed(state_transaction, authority, &normalized)?
            };
            if !allowed {
                return Err(ValidationFail::NotPermitted(format!(
                    "authority cannot grant or revoke role permission `{}`",
                    normalized.name()
                ))
                .into());
            }
            Ok(())
        }
    }
}
fn initial_authority_has_exact_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: Permission,
) -> Result<bool, ValidationFail> {
    authority_has_permission(&state_transaction.world, authority, &permission)
}
fn can_unregister_domain_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    domain: &DomainId,
) -> Result<bool, ValidationFail> {
    if authority_owns_domain(&state_transaction.world, authority, domain)? {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::domain::CanUnregisterDomain {
            domain: domain.clone(),
        }
        .into(),
    )
}
fn can_modify_domain_metadata_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    domain: &DomainId,
) -> Result<bool, ValidationFail> {
    if authority_owns_domain(&state_transaction.world, authority, domain)? {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::domain::CanModifyDomainMetadata {
            domain: domain.clone(),
        }
        .into(),
    )
}
fn can_unregister_account_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    account: &AccountId,
) -> Result<bool, ValidationFail> {
    if authority == account {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::account::CanUnregisterAccount {
            account: account.clone(),
        }
        .into(),
    )
}
fn can_replace_account_controller_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    account: &AccountId,
) -> Result<bool, ValidationFail> {
    if authority == account {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::account::CanReplaceAccountController {
            account: account.clone(),
        }
        .into(),
    )
}
fn initial_accounts_share_active_lineage(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    target: &AccountId,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    if authority == target {
        return Ok(true);
    }
    let now_ms = state_transaction.block_unix_timestamp_ms();
    let Some(authority) = crate::sns::resolve_active_account_id_rekey_lineage(
        &state_transaction.world,
        state_transaction.world.dataspace_catalog(),
        authority,
        now_ms,
    )
    .map_err(sns_permission_attempt_error)?
    else {
        return Ok(false);
    };
    let Some(target) = crate::sns::resolve_active_account_id_rekey_lineage(
        &state_transaction.world,
        state_transaction.world.dataspace_catalog(),
        target,
        now_ms,
    )
    .map_err(sns_permission_attempt_error)?
    else {
        return Ok(false);
    };
    Ok(authority == target)
}
fn can_unregister_asset_definition_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    asset_definition: &AssetDefinitionId,
) -> Result<bool, ValidationFail> {
    if authority_owns_asset_definition(&state_transaction.world, authority, asset_definition)? {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::asset_definition::CanUnregisterAssetDefinition {
            asset_definition: asset_definition.clone(),
        }
        .into(),
    )
}
fn can_register_nft_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    domain: &DomainId,
) -> Result<bool, ValidationFail> {
    if authority_owns_domain(&state_transaction.world, authority, domain)? {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::nft::CanRegisterNft {
            domain: domain.clone(),
        }
        .into(),
    )
}
fn can_unregister_nft_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    nft: &iroha_data_model::nft::NftId,
) -> Result<bool, ValidationFail> {
    if authority_owns_domain(&state_transaction.world, authority, nft.domain())? {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::nft::CanUnregisterNft { nft: nft.clone() }.into(),
    )
}
fn can_modify_nft_metadata_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    nft: &iroha_data_model::nft::NftId,
) -> Result<bool, ValidationFail> {
    if authority_owns_domain(&state_transaction.world, authority, nft.domain())? {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::nft::CanModifyNftMetadata { nft: nft.clone() }.into(),
    )
}
fn can_modify_trigger_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    trigger: &iroha_data_model::trigger::TriggerId,
) -> Result<bool, ValidationFail> {
    if initial_trigger_authority(state_transaction, authority, trigger)? {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::trigger::CanModifyTrigger {
            trigger: trigger.clone(),
        }
        .into(),
    )
}
fn can_unregister_trigger_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    trigger: &iroha_data_model::trigger::TriggerId,
) -> Result<bool, ValidationFail> {
    if initial_trigger_authority(state_transaction, authority, trigger)? {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::trigger::CanUnregisterTrigger {
            trigger: trigger.clone(),
        }
        .into(),
    )
}
fn can_execute_trigger_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    trigger: &iroha_data_model::trigger::TriggerId,
) -> Result<bool, ValidationFail> {
    if initial_trigger_authority(state_transaction, authority, trigger)? {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::trigger::CanExecuteTrigger {
            trigger: trigger.clone(),
        }
        .into(),
    )
}
fn can_modify_trigger_metadata_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    trigger: &iroha_data_model::trigger::TriggerId,
) -> Result<bool, ValidationFail> {
    if initial_trigger_authority(state_transaction, authority, trigger)? {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::trigger::CanModifyTriggerMetadata {
            trigger: trigger.clone(),
        }
        .into(),
    )
}
fn can_burn_asset_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    asset: &AssetId,
) -> Result<bool, ValidationFail> {
    if asset.account() == authority
        || authority_owns_asset_definition(&state_transaction.world, authority, asset.definition())?
    {
        return Ok(true);
    }
    let exact: Permission = executor_permission::asset::CanBurnAsset {
        asset: asset.clone(),
    }
    .into();
    if authority_has_permission(&state_transaction.world, authority, &exact)? {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::asset::CanBurnAssetWithDefinition {
            asset_definition: asset.definition().clone(),
        }
        .into(),
    )
}
fn can_modify_asset_metadata_initial(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    asset: &AssetId,
) -> Result<bool, ValidationFail> {
    if asset.account() == authority
        || authority_owns_asset_definition(&state_transaction.world, authority, asset.definition())?
    {
        return Ok(true);
    }
    let exact: Permission = executor_permission::asset::CanModifyAssetMetadata {
        asset: asset.clone(),
    }
    .into();
    if authority_has_permission(&state_transaction.world, authority, &exact)? {
        return Ok(true);
    }
    initial_authority_has_exact_permission(
        state_transaction,
        authority,
        executor_permission::asset::CanModifyAssetMetadataWithDefinition {
            asset_definition: asset.definition().clone(),
        }
        .into(),
    )
}
fn initial_native_instruction_is_explicitly_admitted(instruction: &InstructionBox) -> bool {
    use iroha_data_model::isi::{BurnBox, MintBox, RegisterBox, UnregisterBox};
    if let Some(admission) =
        crate::smartcontracts::isi::registered_native_instruction_initial_admission(instruction)
    {
        return admission
            == crate::smartcontracts::isi::InitialNativeInstructionAdmission::CoreAuthorized;
    }
    let any = instruction.as_any();
    macro_rules! is_any {
        ($($ty:ty),+ $(,)?) => {
            false $(|| any.downcast_ref::<$ty>().is_some())+
        };
    }
    // Standard ISIs are authorized by the native parity gates above.
    if is_any!(
        iroha_data_model::isi::SetParameter,
        iroha_data_model::isi::Log,
        iroha_data_model::isi::ExecuteTrigger,
        BurnBox,
        GrantBox,
        MintBox,
        RegisterBox,
        RemoveKeyValueBox,
        RevokeBox,
        SetKeyValueBox,
        TransferBox,
        iroha_data_model::isi::TransferAssetBatch,
        UnregisterBox,
        iroha_data_model::isi::Upgrade,
        iroha_data_model::isi::register::RegisterPeerWithPop,
        iroha_data_model::isi::register::RegisterCommitteePeerWithPop,
    ) {
        return true;
    }
    // CBDC account control, native multisig/consensus-key lifecycle, and alias lifecycle.
    // Threshold-key lifecycle certificates carry their own exact-roster quorum
    // authorization, which Core verifies before changing either key family.
    if is_any!(
        iroha_data_model::isi::AddSignatory,
        iroha_data_model::isi::RemoveSignatory,
        iroha_data_model::isi::SetAccountQuorum,
        iroha_data_model::isi::ReplaceAccountController,
        iroha_data_model::isi::SetAccountRecoveryPolicy,
        iroha_data_model::isi::ClearAccountRecoveryPolicy,
        iroha_data_model::isi::ProposeAccountRecovery,
        iroha_data_model::isi::ApproveAccountRecovery,
        iroha_data_model::isi::CancelAccountRecovery,
        iroha_data_model::isi::FinalizeAccountRecovery,
        iroha_data_model::isi::alias_setup::EnsureAlias,
        iroha_data_model::isi::alias_setup::RenewAliasLease,
        iroha_data_model::isi::alias_setup::ConfigureAliasAutoRenew,
        iroha_data_model::isi::alias_setup::RebindAccountAlias,
        iroha_data_model::isi::alias_setup::CompareAndSetPrimaryAccountAlias,
        iroha_data_model::isi::consensus_keys::RegisterConsensusKey,
        iroha_data_model::isi::consensus_keys::RotateConsensusKey,
        iroha_data_model::isi::consensus_keys::DisableConsensusKey,
        iroha_data_model::isi::consensus_keys::ApplyThresholdKeyLifecycleCertificateV1,
    ) {
        return true;
    }
    // Asset controls and CBDC policy records have Core owner/scope checks.
    if is_any!(
        iroha_data_model::isi::RegisterDataspaceAssetDefinition,
        iroha_data_model::isi::SetAssetKeyValue,
        iroha_data_model::isi::RemoveAssetKeyValue,
        iroha_data_model::isi::SetAssetTransferAvailability,
        iroha_data_model::isi::SetAssetTransferControl,
        iroha_data_model::isi::SetAssetHoldingLimit,
        iroha_data_model::isi::SetAssetTransferBlacklist,
        iroha_data_model::isi::asset_alias::SetAssetDefinitionAlias,
        iroha_data_model::isi::nexus::CreateFeeSponsorProgram,
        iroha_data_model::isi::nexus::StageFeeSponsorProgramRevision,
        iroha_data_model::isi::nexus::ActivateFeeSponsorProgramRevision,
        iroha_data_model::isi::nexus::PauseFeeSponsorProgram,
        iroha_data_model::isi::nexus::BeginCloseFeeSponsorProgram,
        iroha_data_model::isi::nexus::CloseFeeSponsorProgram,
        iroha_data_model::isi::nexus::EnrollFeeSponsorBeneficiary,
        iroha_data_model::isi::nexus::UnenrollFeeSponsorBeneficiary,
        iroha_data_model::isi::nexus::FundFeeSponsorProgram,
        iroha_data_model::isi::nexus::WithdrawFeeSponsorProgram,
    ) {
        return true;
    }
    // Smart-contract deployment and instance lifecycle enforce immutable subject,
    // code, nonce, and deployment permissions inside Core.
    if is_any!(
        iroha_data_model::isi::smart_contract_code::RegisterSmartContractCode,
        iroha_data_model::isi::smart_contract_code::DeactivateContractInstance,
        iroha_data_model::isi::smart_contract_code::ActivateContractInstance,
        iroha_data_model::isi::smart_contract_code::SetContractParliamentDelegation,
        iroha_data_model::isi::smart_contract_code::OfferContractOwnership,
        iroha_data_model::isi::smart_contract_code::AcceptContractOwnership,
        iroha_data_model::isi::smart_contract_code::CancelContractOwnershipOffer,
        iroha_data_model::isi::smart_contract_code::CommitContractDeployment,
        iroha_data_model::isi::smart_contract_code::RegisterSmartContractBytes,
        iroha_data_model::isi::smart_contract_code::UploadSmartContractCodeChunk,
        iroha_data_model::isi::smart_contract_code::FinalizeSmartContractCodeUpload,
        iroha_data_model::isi::smart_contract_code::CancelSmartContractCodeUpload,
        iroha_data_model::isi::smart_contract_code::RemoveSmartContractBytes,
        iroha_data_model::isi::contract_alias::SetContractAlias,
    ) {
        return true;
    }
    // Native race handlers enforce wallet debits, gameplay signatures and proof settlement.
    if is_any!(
        iroha_data_model::isi::game::RegisterExecutionProofProfileV1,
        iroha_data_model::isi::game::VerifyExecutionProofV1,
        iroha_data_model::isi::game::SettleGameSessionV1,
        iroha_data_model::isi::game::OpenGameSessionV1,
        iroha_data_model::isi::game::JoinGameSessionV1,
        iroha_data_model::isi::game::StartGameSessionV1,
        iroha_data_model::isi::game::CommitGameCheckpointV1,
        iroha_data_model::isi::game::ChallengeGameSessionV1,
        iroha_data_model::isi::game::CommitGameInputsV1,
        iroha_data_model::isi::game::RevealGameInputsV1,
        iroha_data_model::isi::game::AdvanceGameDeadlineV1,
        iroha_data_model::isi::game::ExpireGameSessionV1,
        iroha_data_model::isi::game::ClaimGamePayoutV1,
        iroha_data_model::isi::game::StakeGameItemV1,
    ) {
        return true;
    }
    // Marketplace escrow handlers authenticate the seller, buyer, or dispute
    // resolver in Core and enforce the native asset-transfer controls. Admit
    // the complete lifecycle so opening custody always has a terminal path.
    if is_any!(
        iroha_data_model::isi::escrow::OpenAssetEscrow,
        iroha_data_model::isi::escrow::AcceptAssetEscrow,
        iroha_data_model::isi::escrow::MarkEscrowPaymentSent,
        iroha_data_model::isi::escrow::ReleaseAssetEscrow,
        iroha_data_model::isi::escrow::CancelAssetEscrow,
        iroha_data_model::isi::escrow::OpenEscrowDispute,
        iroha_data_model::isi::escrow::ResolveEscrowDispute,
    ) {
        return true;
    }
    // Generic locks debit only the signed opener. Core checks the destination or
    // release authority for drawdowns, the opener for cancellation, exact
    // remaining amounts, and the committed deadline for permissionless expiry.
    // Admit every terminal path while retaining those native custody checks.
    if is_any!(
        iroha_data_model::isi::escrow::OpenAssetLock,
        iroha_data_model::isi::escrow::DrawdownAssetLock,
        iroha_data_model::isi::escrow::CancelAssetLock,
        iroha_data_model::isi::escrow::ExpireAssetLock,
    ) {
        return true;
    }
    // Admit the complete native VPN escrow lifecycle so every lease retains
    // its settlement and timeout-refund terminal paths.
    if is_any!(
        iroha_data_model::isi::vpn::OpenVpnLeaseEscrow,
        iroha_data_model::isi::vpn::SettleVpnLease,
        iroha_data_model::isi::vpn::RefundExpiredVpnLease,
    ) {
        return true;
    }
    // Kaigi lifecycle, usage, and relay mutations enforce their host,
    // participant, relay, proof, and governance checks inside Core. The Initial
    // executor additionally protects each domain-owned call namespace above.
    if is_any!(
        iroha_data_model::isi::kaigi::CreateKaigi,
        iroha_data_model::isi::kaigi::JoinKaigi,
        iroha_data_model::isi::kaigi::LeaveKaigi,
        iroha_data_model::isi::kaigi::EndKaigi,
        iroha_data_model::isi::kaigi::RecordKaigiUsage,
        iroha_data_model::isi::kaigi::SetKaigiRelayManifest,
        iroha_data_model::isi::kaigi::RegisterKaigiRelay,
        iroha_data_model::isi::kaigi::UnregisterKaigiRelay,
        iroha_data_model::isi::kaigi::ReportKaigiRelayHealth,
    ) {
        return true;
    }
    // Cross-border settlement, relays, scoped governance mutations, and
    // authority-bound public agenda intake reach Core only where it enforces an
    // exact permission or proof, or persists the exact signed authority after
    // canonical payload validation. Keep the signed governance draft surface
    // usable while the fail-safe Initial executor is active; the lower-level
    // `zk::SubmitBallot` vendor instruction remains IVM-latch-only below.
    if is_any!(
        iroha_data_model::isi::settlement::SettlementInstructionBox,
        iroha_data_model::isi::bridge::SubmitBridgeProof,
        iroha_data_model::isi::bridge::RecordBridgeReceipt,
        iroha_data_model::isi::governance::ProposeDeployContract,
        iroha_data_model::isi::governance::ProposeContractLifecycleGovernance,
        iroha_data_model::isi::governance::ProposeContractEmergencyHold,
        iroha_data_model::isi::governance::ProposeGlobalDataTriggerPermissionGovernance,
        iroha_data_model::isi::governance::ProposeRuntimeUpgradeProposal,
        iroha_data_model::isi::governance::ProposeSccpRouteGovernance,
        iroha_data_model::isi::governance::ProposeSorafsProviderGovernance,
        iroha_data_model::isi::governance::ProposeValidationFeePayoutLifecycle,
        iroha_data_model::isi::governance::ProposeValidationFeePolicy,
        iroha_data_model::isi::governance::CreateParliamentGovernanceAttemptV1,
        iroha_data_model::isi::governance::SubmitParliamentLifecycleTransitionV1,
        iroha_data_model::isi::governance::CastZkBallot,
        iroha_data_model::isi::governance::CastPlainBallot,
        iroha_data_model::isi::governance::UpdatePlainConviction,
        iroha_data_model::isi::governance::SlashGovernanceLock,
        iroha_data_model::isi::governance::RestituteGovernanceLock,
        iroha_data_model::isi::ministry::SubmitAgendaProposal,
        iroha_data_model::isi::nexus::RegisterVerifiedFeeSponsorVaultAllocation,
    ) {
        return true;
    }
    // Citizenship is a self-owned bonded lifecycle. Core binds the owner to the
    // signer and enforces the minimum bond, monotonic top-ups, and retained-bond
    // restrictions before allowing registration or release.
    if is_any!(
        iroha_data_model::isi::governance::RegisterCitizen,
        iroha_data_model::isi::governance::UnregisterCitizen,
    ) {
        return true;
    }
    // Retail identifier policies and claims are bound to their signed policy and
    // RAM-LFE proof state by Core.
    if is_any!(
        iroha_data_model::isi::identifier::RegisterIdentifierPolicy,
        iroha_data_model::isi::identifier::ActivateIdentifierPolicy,
        iroha_data_model::isi::identifier::ClaimIdentifier,
        iroha_data_model::isi::identifier::RevokeIdentifier,
        iroha_data_model::isi::ram_lfe::RegisterRamLfeProgramPolicy,
        iroha_data_model::isi::ram_lfe::ActivateRamLfeProgramPolicy,
        iroha_data_model::isi::ram_lfe::DeactivateRamLfeProgramPolicy,
    ) {
        return true;
    }
    // Self-owned validator lifecycle reaches the exact ownership, lane policy,
    // consensus-key, custody, and election checks in Core.
    if is_any!(
        iroha_data_model::isi::staking::RegisterPublicLaneCandidate,
        iroha_data_model::isi::staking::RegisterPublicLaneValidator,
        iroha_data_model::isi::staking::ActivatePublicLaneValidator,
        iroha_data_model::isi::staking::ExitPublicLaneValidator,
    ) {
        return true;
    }
    // User-owned staking and reward actions bind the signed authority to the
    // validator, staker, or reward recipient inside Core. They must reach those
    // exact stateful checks while the fail-safe Initial executor is installed.
    if is_any!(
        iroha_data_model::isi::staking::RebindPublicLaneValidatorPeer,
        iroha_data_model::isi::staking::BondPublicLaneStake,
        iroha_data_model::isi::staking::SchedulePublicLaneUnbond,
        iroha_data_model::isi::staking::FinalizePublicLaneUnbond,
        iroha_data_model::isi::staking::ClaimPublicLaneRewards,
    ) {
        return true;
    }
    // Archive registration enforces the registry policy/revision, exact signed
    // publisher/network/body binding, admitted provider owner and receipt proof
    // inside Core. Replay also requires the immutable original registrant.
    if is_any!(iroha_data_model::isi::musubi::RegisterMusubiArchiveV1) {
        return true;
    }
    // Sole direct signed native operations can ratchet or challenge only their authority's
    // network-bound outbox. Core owns the exact origin, lineage, floor, and current row checks.
    if is_any!(
        iroha_data_model::isi::musubi::AdvanceMusubiPinOutboxV1,
        iroha_data_model::isi::musubi::CheckMusubiPinOutboxV1
    ) {
        return true;
    }
    // The Initial executor is a deliberately narrow CBDC bootstrap profile.
    // Proof-bound social, endorsement, ZK, and other Musubi operations are not part of
    // the PK release surface and remain closed until an installed executor
    // explicitly admits them.
    false
}
fn initial_genesis_instruction_is_explicitly_admitted(instruction: &InstructionBox) -> bool {
    let any = instruction.as_any();
    macro_rules! is_any {
        ($($ty:ty),+ $(,)?) => {
            false $(|| any.downcast_ref::<$ty>().is_some())+
        };
    }
    // Genesis has a small, explicit bootstrap-only surface in addition to the
    // ordinary Initial-executor surface. Never treat "genesis" as permission to
    // execute an otherwise unclassified native instruction: several instruction
    // families consult process-local policy and would make the signed bootstrap
    // state depend on the node which happened to execute it.
    is_any!(
        iroha_data_model::isi::verifying_keys::RegisterVerifyingKey,
        iroha_data_model::isi::verifying_keys::UpdateVerifyingKey,
        iroha_data_model::isi::soradns::PublishDirectory,
        iroha_data_model::isi::soradns::RevokeResolver,
        iroha_data_model::isi::soradns::UnrevokeResolver,
        iroha_data_model::isi::soradns::AddReleaseSigner,
        iroha_data_model::isi::soradns::RemoveReleaseSigner,
        iroha_data_model::isi::soradns::SetDirectoryRotationPolicy,
        iroha_data_model::isi::content::PublishContentBundle,
        iroha_data_model::isi::content::RetireContentBundle,
        iroha_data_model::isi::zk::RegisterZkAsset,
        iroha_data_model::isi::zk::ScheduleConfidentialPolicyTransition,
        iroha_data_model::isi::zk::CancelConfidentialPolicyTransition,
        iroha_data_model::isi::staking::SlashPublicLaneValidator,
    )
}
#[allow(clippy::too_many_lines)]
fn validate_initial_native_instruction_authority(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: &InstructionBox,
    is_genesis: bool,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    use iroha_data_model::isi::{BurnBox, MintBox, RegisterBox, UnregisterBox};
    let any = instruction.as_any();
    let deny = |message: &'static str| Err(ValidationFail::NotPermitted(message.to_owned()).into());
    if let Some(mutation) =
        any.downcast_ref::<iroha_data_model::isi::sorafs::MutateSorafsStreamTokenCustody>()
    {
        let permission = executor_permission::sorafs::CanManageSorafsStreamTokenCustody {
            provider_id: mutation.provider_id,
        };
        if initial_authority_has_exact_permission(state_transaction, authority, permission.into())?
        {
            return Ok(());
        }
        return deny("Exact provider-scoped stream-token custody permission is required");
    }
    if let Some(mutation) =
        any.downcast_ref::<iroha_data_model::isi::sorafs::MutateSorafsFinalPromotionAuthority>()
    {
        use iroha_data_model::sorafs::final_promotion_authority::FinalPromotionAuthorityActionV1;
        if let FinalPromotionAuthorityActionV1::Check(check) = &mutation.action
            && authority == &check.expected_operator
        {
            return deny("Receipt observer must differ from the expected operator");
        }
        let permission: Permission = match &mutation.action {
            FinalPromotionAuthorityActionV1::Configure(_)
            | FinalPromotionAuthorityActionV1::Enroll(_)
            | FinalPromotionAuthorityActionV1::Revoke(_) => {
                executor_permission::sorafs::CanManageSorafsFinalPromotionCustody {
                    deployment_id: mutation.deployment_id.clone(),
                }
                .into()
            }
            FinalPromotionAuthorityActionV1::Reserve(_)
            | FinalPromotionAuthorityActionV1::Complete(_)
            | FinalPromotionAuthorityActionV1::Expire(_) => {
                executor_permission::sorafs::CanOperateSorafsFinalPromotion {
                    deployment_id: mutation.deployment_id.clone(),
                }
                .into()
            }
            FinalPromotionAuthorityActionV1::Check(_) => {
                executor_permission::sorafs::CanCheckSorafsFinalPromotion {
                    deployment_id: mutation.deployment_id.clone(),
                }
                .into()
            }
        };
        if initial_authority_has_exact_permission(state_transaction, authority, permission)? {
            return Ok(());
        }
        return deny("Exact deployment-scoped final-promotion action permission is required");
    }
    if let Some(mutation) = any
        .downcast_ref::<iroha_data_model::isi::sorafs::MutateSorafsFinalPromotionAccountCustody>(
    ) {
        use iroha_data_model::sorafs::final_promotion_account_custody::FinalPromotionAccountCustodyActionV1;
        if let FinalPromotionAccountCustodyActionV1::Check(check) = &mutation.action
            && authority == &check.expected_account
        {
            return deny("Account-custody observer must differ from the target account");
        }
        let permission: Permission = match &mutation.action {
            FinalPromotionAccountCustodyActionV1::Configure(_)
            | FinalPromotionAccountCustodyActionV1::Enroll(_)
            | FinalPromotionAccountCustodyActionV1::Revoke(_) => {
                executor_permission::sorafs::CanManageSorafsFinalPromotionAccountCustody {
                    deployment_id: mutation.deployment_id.clone(),
                }
                .into()
            }
            FinalPromotionAccountCustodyActionV1::Check(_) => {
                executor_permission::sorafs::CanCheckSorafsFinalPromotionAccountCustody {
                    deployment_id: mutation.deployment_id.clone(),
                }
                .into()
            }
        };
        if initial_authority_has_exact_permission(state_transaction, authority, permission)? {
            return Ok(());
        }
        return deny("Exact deployment-scoped account-custody action permission is required");
    }
    if let Some(create) = any.downcast_ref::<iroha_data_model::isi::kaigi::CreateKaigi>()
        && !is_genesis
        && !can_modify_domain_metadata_initial(
            state_transaction,
            authority,
            &create.call.id.domain_id,
        )?
    {
        return deny("authority cannot create a Kaigi in this domain");
    }
    // Direct multisig mutations are accepted only from the account being changed
    // (including its active rekey lineage), or from an exact controller delegate.
    // The transaction layer still applies the native multisig proposal/quorum flow
    // before the instruction reaches this gate.
    let direct_multisig_target = any
        .downcast_ref::<iroha_data_model::isi::AddSignatory>()
        .map(|instruction| &instruction.account)
        .or_else(|| {
            any.downcast_ref::<iroha_data_model::isi::RemoveSignatory>()
                .map(|instruction| &instruction.account)
        })
        .or_else(|| {
            any.downcast_ref::<iroha_data_model::isi::SetAccountQuorum>()
                .map(|instruction| &instruction.account)
        });
    if let Some(target) = direct_multisig_target
        && !is_genesis
        && !initial_accounts_share_active_lineage(state_transaction, authority, target)?
        && !can_replace_account_controller_initial(state_transaction, authority, target)?
    {
        return deny("authority cannot mutate another account's multisig controller");
    }
    if let Some(set_parameter) = any.downcast_ref::<iroha_data_model::isi::SetParameter>() {
        if matches!(
            set_parameter.inner(),
            iroha_data_model::parameter::Parameter::Custom(parameter)
                if parameter.id() == &iroha_data_model::nexus::ValidatorCommitteeOperationV1::parameter_id()
        ) {
            // This reserved envelope is a native preparation command. Its Core
            // handler checks the exact staked owner, generation, frozen attempt
            // and possession/readiness proofs; it never writes a generic parameter.
            return Ok(());
        }
        if matches!(
            set_parameter.inner(),
            iroha_data_model::parameter::Parameter::Custom(parameter)
                if iroha_data_model::hijiri::is_hijiri_parameter_id(parameter.id())
        ) {
            if is_genesis
                || initial_authority_has_exact_permission(
                    state_transaction,
                    authority,
                    executor_permission::parameter::CanSetHijiriParameters.into(),
                )?
            {
                return Ok(());
            }
            return deny("Can't set Hijiri parameters without CanSetHijiriParameters");
        }
        if matches!(
            set_parameter.inner(),
            iroha_data_model::parameter::Parameter::Custom(parameter)
                if iroha_data_model::validation_fee::is_reserved_validation_fee_parameter_id(
                    parameter.id()
                )
        ) {
            return deny(
                "validation-fee governance parameters can only be changed by an enacted SORA Parliament proposal",
            );
        }
        if is_genesis
            || initial_authority_has_exact_permission(
                state_transaction,
                authority,
                executor_permission::parameter::CanSetParameters.into(),
            )?
        {
            return Ok(());
        }
        return deny("Can't set network parameters without CanSetParameters");
    }
    if any
        .downcast_ref::<iroha_data_model::isi::Upgrade>()
        .is_some()
    {
        if is_genesis
            || initial_authority_has_exact_permission(
                state_transaction,
                authority,
                executor_permission::executor::CanUpgradeExecutor.into(),
            )?
        {
            return Ok(());
        }
        return deny("Can't upgrade executor without CanUpgradeExecutor");
    }
    // The default executor does not admit these authority-free administrative
    // instructions. Genesis may seed their state, but post-genesis callers must use
    // the corresponding governed lifecycle instead of falling through Core Execute.
    let default_denied_administrative_instruction =
        initial_genesis_instruction_is_explicitly_admitted(instruction);
    if !is_genesis && default_denied_administrative_instruction {
        return deny("administrative instruction requires an explicit governed lifecycle");
    }
    let validator_owner = any
        .downcast_ref::<iroha_data_model::isi::staking::RegisterPublicLaneCandidate>()
        .map(|isi| &isi.registration.validator)
        .or_else(|| {
            any.downcast_ref::<iroha_data_model::isi::staking::RegisterPublicLaneValidator>()
                .map(|isi| &isi.validator)
        })
        .or_else(|| {
            any.downcast_ref::<iroha_data_model::isi::staking::ActivatePublicLaneValidator>()
                .map(|isi| &isi.validator)
        })
        .or_else(|| {
            any.downcast_ref::<iroha_data_model::isi::staking::ExitPublicLaneValidator>()
                .map(|isi| &isi.validator)
        })
        .or_else(|| {
            any.downcast_ref::<iroha_data_model::isi::staking::RebindPublicLaneValidatorPeer>()
                .map(|isi| &isi.validator)
        });
    if !is_genesis && validator_owner.is_some_and(|owner| owner != authority) {
        return deny("public validator lifecycle requires the validator account authority");
    }

    if (any
        .downcast_ref::<iroha_data_model::isi::register::RegisterPeerWithPop>()
        .is_some()
        || any
            .downcast_ref::<iroha_data_model::isi::register::RegisterCommitteePeerWithPop>()
            .is_some())
        && !is_genesis
        && !initial_authority_has_exact_permission(
            state_transaction,
            authority,
            executor_permission::peer::CanManagePeers.into(),
        )?
    {
        return deny("peer registration requires CanManagePeers");
    }
    if let Some(register) = any.downcast_ref::<RegisterBox>() {
        if matches!(register, RegisterBox::Domain(_)) && !is_genesis {
            return deny("raw domain registration is reserved for genesis; use EnsureAlias");
        }
        let allowed = match register {
            RegisterBox::Peer(_) => {
                is_genesis
                    || initial_authority_has_exact_permission(
                        state_transaction,
                        authority,
                        executor_permission::peer::CanManagePeers.into(),
                    )?
            }
            RegisterBox::Domain(_) => true,
            RegisterBox::Nft(register) => can_register_nft_initial(
                state_transaction,
                authority,
                register.object().id().domain(),
            )?,
            RegisterBox::Account(register) => {
                if [
                    iroha_data_model::asset::ASSET_TRANSFER_CONTROL_METADATA_KEY,
                    iroha_data_model::validation_fee::RETAIL_FEE_ENROLLMENT_METADATA_KEY,
                    iroha_data_model::smart_contract::CONTRACT_DEPLOY_NONCE_METADATA_KEY,
                ]
                .into_iter()
                .any(|key| register.object().metadata.get(key).is_some())
                {
                    return deny("account registration cannot seed reserved native metadata");
                }
                true
            }
            RegisterBox::AssetDefinition(_) | RegisterBox::Role(_) | RegisterBox::Trigger(_) => {
                true
            }
        };
        if !allowed {
            return deny("authority cannot register this resource");
        }
    }
    if let Some(unregister) = any.downcast_ref::<UnregisterBox>() {
        if let UnregisterBox::Account(unregister) = unregister
            && state_transaction
                .world
                .account(unregister.object())
                .is_ok_and(|account| {
                    account
                        .metadata()
                        .get(iroha_data_model::asset::ASSET_TRANSFER_CONTROL_METADATA_KEY)
                        .is_some()
                })
        {
            return deny(
                "account with native asset transfer-control state must clear it through dedicated instructions before removal",
            );
        }
        let allowed = match unregister {
            UnregisterBox::Peer(_) => {
                is_genesis
                    || initial_authority_has_exact_permission(
                        state_transaction,
                        authority,
                        executor_permission::peer::CanManagePeers.into(),
                    )?
            }
            UnregisterBox::Domain(unregister) => {
                is_genesis
                    || can_unregister_domain_initial(
                        state_transaction,
                        authority,
                        unregister.object(),
                    )?
            }
            UnregisterBox::Account(unregister) => {
                is_genesis
                    || can_unregister_account_initial(
                        state_transaction,
                        authority,
                        unregister.object(),
                    )?
            }
            UnregisterBox::AssetDefinition(unregister) => {
                is_genesis
                    || can_unregister_asset_definition_initial(
                        state_transaction,
                        authority,
                        unregister.object(),
                    )?
            }
            UnregisterBox::Nft(unregister) => {
                is_genesis
                    || can_unregister_nft_initial(
                        state_transaction,
                        authority,
                        unregister.object(),
                    )?
            }
            UnregisterBox::Trigger(unregister) => {
                is_genesis
                    || can_unregister_trigger_initial(
                        state_transaction,
                        authority,
                        unregister.object(),
                    )?
            }
            UnregisterBox::Role(_) => true,
        };
        if !allowed {
            return deny("authority cannot remove this resource");
        }
    }
    if let Some(mint) = any.downcast_ref::<MintBox>()
        && let MintBox::TriggerRepetitions(mint) = mint
        && !is_genesis
        && !can_modify_trigger_initial(state_transaction, authority, mint.destination())?
    {
        return deny("authority cannot modify trigger repetitions");
    }
    if let Some(burn) = any.downcast_ref::<BurnBox>() {
        let allowed = match burn {
            BurnBox::Asset(burn) => {
                is_genesis
                    || can_burn_asset_initial(state_transaction, authority, burn.destination())?
            }
            BurnBox::TriggerRepetitions(burn) => {
                is_genesis
                    || can_modify_trigger_initial(state_transaction, authority, burn.destination())?
            }
        };
        if !allowed {
            return deny("authority cannot burn this resource");
        }
    }
    if let Some(execute) = any.downcast_ref::<iroha_data_model::isi::ExecuteTrigger>()
        && !is_genesis
        && !can_execute_trigger_initial(state_transaction, authority, execute.trigger())?
    {
        return deny("authority cannot execute this trigger");
    }
    if let Some(set) = any.downcast_ref::<SetKeyValueBox>() {
        let allowed = match set {
            SetKeyValueBox::Domain(set) => {
                if crate::smartcontracts::isi::kaigi::is_reserved_kaigi_metadata_key(set.key()) {
                    return deny("native Kaigi metadata keys cannot be changed directly");
                }
                is_genesis
                    || can_modify_domain_metadata_initial(
                        state_transaction,
                        authority,
                        set.object(),
                    )?
            }
            SetKeyValueBox::Account(set) => {
                if crate::smartcontracts::isi::multisig::is_reserved_multisig_metadata_key(
                    set.key(),
                ) {
                    return deny("native multisig metadata keys cannot be changed directly");
                }
                // Native enrollment validates the issuer's exact registration domain and
                // protected wallet identity. Ordinary metadata ownership cannot grant it.
                set.key().as_ref()
                    == iroha_data_model::validation_fee::RETAIL_FEE_ENROLLMENT_METADATA_KEY
                    || is_genesis
                    || can_modify_account_metadata(
                        &state_transaction.world,
                        authority,
                        set.object(),
                    )?
            }
            SetKeyValueBox::AssetDefinition(set) => {
                is_genesis
                    || can_modify_asset_definition_metadata(
                        &state_transaction.world,
                        authority,
                        set.object(),
                    )?
            }
            SetKeyValueBox::Nft(set) => {
                is_genesis
                    || can_modify_nft_metadata_initial(state_transaction, authority, set.object())?
            }
            SetKeyValueBox::Trigger(set) => {
                is_genesis
                    || can_modify_trigger_metadata_initial(
                        state_transaction,
                        authority,
                        set.object(),
                    )?
            }
        };
        if !allowed {
            return deny("authority cannot modify this metadata");
        }
    }
    if let Some(remove) = any.downcast_ref::<RemoveKeyValueBox>() {
        let allowed = match remove {
            RemoveKeyValueBox::Domain(remove) => {
                if crate::smartcontracts::isi::kaigi::is_reserved_kaigi_metadata_key(remove.key()) {
                    return deny("native Kaigi metadata keys cannot be changed directly");
                }
                is_genesis
                    || can_modify_domain_metadata_initial(
                        state_transaction,
                        authority,
                        remove.object(),
                    )?
            }
            RemoveKeyValueBox::Account(remove) => {
                if crate::smartcontracts::isi::multisig::is_reserved_multisig_metadata_key(
                    remove.key(),
                ) {
                    return deny("native multisig metadata keys cannot be changed directly");
                }
                is_genesis
                    || can_modify_account_metadata(
                        &state_transaction.world,
                        authority,
                        remove.object(),
                    )?
            }
            RemoveKeyValueBox::AssetDefinition(remove) => {
                is_genesis
                    || can_modify_asset_definition_metadata(
                        &state_transaction.world,
                        authority,
                        remove.object(),
                    )?
            }
            RemoveKeyValueBox::Nft(remove) => {
                is_genesis
                    || can_modify_nft_metadata_initial(
                        state_transaction,
                        authority,
                        remove.object(),
                    )?
            }
            RemoveKeyValueBox::Trigger(remove) => {
                is_genesis
                    || can_modify_trigger_metadata_initial(
                        state_transaction,
                        authority,
                        remove.object(),
                    )?
            }
        };
        if !allowed {
            return deny("authority cannot remove this metadata");
        }
    }
    if let Some(set) = any.downcast_ref::<iroha_data_model::isi::SetAssetKeyValue>()
        && !is_genesis
        && !can_modify_asset_metadata_initial(state_transaction, authority, set.asset())?
    {
        return deny("authority cannot modify this asset metadata");
    }
    if let Some(remove) = any.downcast_ref::<iroha_data_model::isi::RemoveAssetKeyValue>()
        && !is_genesis
        && !can_modify_asset_metadata_initial(state_transaction, authority, remove.asset())?
    {
        return deny("authority cannot remove this asset metadata");
    }
    let recovery_account = any
        .downcast_ref::<iroha_data_model::isi::ReplaceAccountController>()
        .map(|instruction| instruction.account())
        .or_else(|| {
            any.downcast_ref::<iroha_data_model::isi::SetAccountRecoveryPolicy>()
                .map(|instruction| instruction.account())
        })
        .or_else(|| {
            any.downcast_ref::<iroha_data_model::isi::ClearAccountRecoveryPolicy>()
                .map(|instruction| instruction.account())
        });
    if let Some(account) = recovery_account
        && !is_genesis
        && !can_replace_account_controller_initial(state_transaction, authority, account)?
    {
        return deny("authority cannot replace another account's controller or recovery policy");
    }
    if let Some(set_alias) =
        any.downcast_ref::<iroha_data_model::isi::asset_alias::SetAssetDefinitionAlias>()
        && !is_genesis
        && !authority_owns_asset_definition(
            &state_transaction.world,
            authority,
            &set_alias.asset_definition_id,
        )?
    {
        return deny("only the asset-definition owner may change its alias");
    }
    if matches!(
        crate::smartcontracts::isi::registered_native_instruction_initial_admission(instruction),
        Some(crate::smartcontracts::isi::InitialNativeInstructionAdmission::Closed)
    ) {
        return Err(ValidationFail::NotPermitted(
            crate::smartcontracts::isi::INITIAL_NATIVE_INSTRUCTION_CLOSED_REASON.to_owned(),
        )
        .into());
    }
    if !initial_native_instruction_is_explicitly_admitted(instruction)
        && !(is_genesis && initial_genesis_instruction_is_explicitly_admitted(instruction))
    {
        return Err(ValidationFail::NotPermitted(format!(
            "Initial executor does not admit unclassified native instruction `{}`",
            instruction.id()
        ))
        .into());
    }
    Ok(())
}
fn authority_owns_asset_definition(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    asset_definition_id: &AssetDefinitionId,
) -> Result<bool, ValidationFail> {
    world
        .asset_definition(asset_definition_id)
        .map(|definition| definition.owned_by() == authority)
        .map_err(|err| ValidationFail::InstructionFailed(InstructionExecutionError::Find(err)))
}
fn can_mint_asset(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    asset_id: &AssetId,
) -> Result<bool, ValidationFail> {
    if authority_owns_asset_definition(world, authority, asset_id.definition())? {
        return Ok(true);
    }
    let by_definition: Permission = executor_permission::asset::CanMintAssetWithDefinition {
        asset_definition: asset_id.definition().clone(),
    }
    .into();
    if authority_has_permission(world, authority, &by_definition)? {
        return Ok(true);
    }
    let exact_destination: Permission = executor_permission::asset::CanMintAssetToAccount {
        asset_definition: asset_id.definition().clone(),
        account: asset_id.account().clone(),
    }
    .into();
    authority_has_permission(world, authority, &exact_destination)
}
fn can_modify_asset_definition_metadata(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    asset_definition_id: &AssetDefinitionId,
) -> Result<bool, ValidationFail> {
    if authority_owns_asset_definition(world, authority, asset_definition_id)? {
        return Ok(true);
    }
    let required: Permission =
        executor_permission::asset_definition::CanModifyAssetDefinitionMetadata {
            asset_definition: asset_definition_id.clone(),
        }
        .into();
    authority_has_permission(world, authority, &required)
}
pub(crate) fn enforce_contract_entrypoint_authorization(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    context: &ContractCallExecutionContext,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    let authorization = context.entrypoint_authorization();
    if context.contract_address.is_none()
        && matches!(authorization, EntrypointAuthorizationV1::Anyone)
    {
        return Ok(());
    }
    let contract_address = context.contract_address.as_ref().ok_or_else(|| {
        ValidationFail::NotPermitted(
            "permissioned contract entrypoint is missing its immutable contract address".to_owned(),
        )
    })?;
    enforce_named_contract_entrypoint_authorization(
        world,
        authority,
        contract_address,
        context.entrypoint.as_deref().unwrap_or("main"),
        authorization,
    )
}
/// Authorize a prepared deployed-contract selector and capture its immutable apply snapshot.
pub(crate) fn authorize_prepared_contract_selector(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    contract: &ivm::PreparedContract,
    selector: &str,
    identity: &code::BoundContractIdentity,
) -> Result<
    ContractEntrypointAuthorizationSnapshot,
    crate::execution_attempt::ExecutionAttemptError<ValidationFail>,
> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err(ValidationFail::NotPermitted(
            "contract entrypoint must not be empty".to_owned(),
        )
        .into());
    }
    let (_, permission, _) = resolve_prepared_contract_entrypoint(contract, selector)?;
    let snapshot = ContractEntrypointAuthorizationSnapshot::new(
        authority.clone(),
        selector.to_owned(),
        permission,
        identity,
    );
    snapshot.validate(world)?;
    Ok(snapshot)
}
/// Authorize a prepared deployed-contract read-only selector and capture its immutable snapshot.
pub(crate) fn authorize_prepared_contract_view_selector(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    contract: &ivm::PreparedContract,
    selector: &str,
    identity: &code::BoundContractIdentity,
) -> Result<
    ContractEntrypointAuthorizationSnapshot,
    crate::execution_attempt::ExecutionAttemptError<ValidationFail>,
> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err(ValidationFail::NotPermitted(
            "contract entrypoint must not be empty".to_owned(),
        )
        .into());
    }
    let (_, permission, _) = resolve_prepared_contract_view_entrypoint(contract, selector)?;
    let snapshot = ContractEntrypointAuthorizationSnapshot::new(
        authority.clone(),
        selector.to_owned(),
        permission,
        identity,
    );
    snapshot.validate(world)?;
    Ok(snapshot)
}
/// Authorize a prepared raw-IVM selector and capture its immutable apply snapshot.
pub(crate) fn authorize_prepared_raw_contract_selector(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    contract: &ivm::PreparedContract,
    selector: &str,
    identity: &code::BoundContractIdentity,
) -> Result<
    ContractEntrypointAuthorizationSnapshot,
    crate::execution_attempt::ExecutionAttemptError<ValidationFail>,
> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err(ValidationFail::NotPermitted(
            "contract entrypoint must not be empty".to_owned(),
        )
        .into());
    }
    let (_, permission, _) = resolve_prepared_raw_contract_entrypoint(contract, selector)?;
    let snapshot = ContractEntrypointAuthorizationSnapshot::new(
        authority.clone(),
        selector.to_owned(),
        permission,
        identity,
    );
    snapshot.validate(world)?;
    Ok(snapshot)
}
/// Enforce the compiler-verified permission attached to a named public entrypoint.
///
/// Overlay preparation, live overlay application, direct execution, triggers, and nested calls all
/// use this helper so none of those paths can drift into a weaker authorization policy.
///
/// # Errors
/// Returns a completed permission rejection or the original local refusal when an existing
/// permission payload could not be inspected. Read-only transports must expose the latter as
/// retryable capacity, never as a completed contract denial.
pub fn enforce_named_contract_entrypoint_authorization(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    entrypoint: &str,
    authorization: &EntrypointAuthorizationV1,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    let manifest = current_contract_authorization_manifest(world, contract_address)?;
    let declared_entrypoint = manifest
        .entrypoints
        .as_ref()
        .and_then(|entries| entries.iter().find(|entry| entry.name == entrypoint))
        .ok_or_else(|| {
            ValidationFail::NotPermitted(
                "contract entrypoint is not declared by the current code".to_owned(),
            )
        })?;
    if &declared_entrypoint.authorization != authorization {
        return Err(ValidationFail::NotPermitted(
            "contract entrypoint authorization differs from the current signed declaration"
                .to_owned(),
        )
        .into());
    }
    let granted = match authorization {
        EntrypointAuthorizationV1::Anyone => true,
        EntrypointAuthorizationV1::RuntimeLifecycle => {
            if !matches!(
                declared_entrypoint.kind,
                iroha_data_model::smart_contract::manifest::EntryPointKind::Hajimari
                    | iroha_data_model::smart_contract::manifest::EntryPointKind::Kaizen
            ) {
                return Err(ValidationFail::NotPermitted(
                    "runtime lifecycle authorization requires a lifecycle hook".to_owned(),
                )
                .into());
            }
            authority_has_borrowed_permission(
                world,
                authority,
                "CanInvokeContractEntrypoint",
                |permission| {
                    #[derive(crate::json_macros::JsonDeserialize)]
                    #[norito(deny_unknown_fields)]
                    struct LifecycleGrant {
                        contract: iroha_data_model::smart_contract::ContractAddress,
                        entrypoint: String,
                    }
                    read_permission_payload::<LifecycleGrant>(permission).map(|grant| {
                        grant.is_some_and(|grant| {
                            grant.contract == *contract_address && grant.entrypoint == entrypoint
                        })
                    })
                },
            )?
        }
        EntrypointAuthorizationV1::Permission(name) => {
            let declaration = manifest
                .permissions
                .iter()
                .find(|declaration| &declaration.name == name)
                .ok_or_else(|| {
                    ValidationFail::NotPermitted(
                        "contract authorization refers to an undeclared permission".to_owned(),
                    )
                })?;
            match &declaration.scope {
                ContractPermissionScopeV1::Instance => authority_has_borrowed_permission(
                    world,
                    authority,
                    "CanUseContractPermission",
                    |permission| {
                        #[derive(crate::json_macros::JsonDeserialize)]
                        #[norito(deny_unknown_fields)]
                        struct InstanceGrant {
                            contract: iroha_data_model::smart_contract::ContractAddress,
                            permission: iroha_model_base::name::Name,
                        }
                        read_permission_payload::<InstanceGrant>(permission).map(|grant| {
                            grant.is_some_and(|grant| {
                                grant.contract == *contract_address && &grant.permission == name
                            })
                        })
                    },
                )?,
                ContractPermissionScopeV1::Chain { permission_name } => {
                    authority_has_borrowed_permission(
                        world,
                        authority,
                        permission_name.as_ref(),
                        |permission| {
                            // Chain imports denote exactly the null token, never a typed builtin payload.
                            Ok(permission.payload().get() == "null")
                        },
                    )?
                }
            }
        }
    };
    if granted {
        Ok(())
    } else {
        let required = match authorization {
            EntrypointAuthorizationV1::Permission(name) => format!("permission `{name}`"),
            EntrypointAuthorizationV1::RuntimeLifecycle => {
                "CanInvokeContractEntrypoint lifecycle grant".to_owned()
            }
            EntrypointAuthorizationV1::Anyone => {
                unreachable!("anyone authorization is granted above")
            }
        };
        Err(ValidationFail::NotPermitted(format!(
            "contract entrypoint `{entrypoint}` on `{contract_address}` requires its declared exact authorization: {required}"
        )).into())
    }
}
/// Borrow the permission catalog for an active invocation only.
fn current_contract_authorization_manifest<'a>(
    world: &'a impl WorldReadOnly,
    contract: &iroha_data_model::smart_contract::ContractAddress,
) -> Result<&'a iroha_data_model::smart_contract::manifest::ContractManifest, ValidationFail> {
    world.contract_instances().get(contract).ok_or_else(|| {
        ValidationFail::NotPermitted("contract permission requires a live instance".to_owned())
    })?;
    retained_contract_authorization_manifest(world, contract)
}
/// Borrow the last bound artifact's catalog for permission mutation, including suspension.
/// Binding validation rejects mismatched active and retained identities before any catalog read.
fn retained_contract_authorization_manifest<'a>(
    world: &'a impl WorldReadOnly,
    contract: &iroha_data_model::smart_contract::ContractAddress,
) -> Result<&'a iroha_data_model::smart_contract::manifest::ContractManifest, ValidationFail> {
    let code_hash = code::fetch_contract_lifecycle_binding(world, contract)
        .map_err(ValidationFail::NotPermitted)?
        .and_then(|binding| binding.lifecycle.retained_code_hash)
        .ok_or_else(|| {
            ValidationFail::NotPermitted(
                "contract permission requires a retained artifact binding".to_owned(),
            )
        })?;
    let dataspace = contract
        .dataspace_id()
        .map_err(|_| ValidationFail::NotPermitted("invalid contract dataspace".to_owned()))?;
    world
        .contract_manifests()
        .get(&iroha_data_model::smart_contract::ContractArtifactId::new(
            dataspace, code_hash,
        ))
        .ok_or_else(|| {
            ValidationFail::NotPermitted(
                "contract permission requires the current signed manifest".to_owned(),
            )
        })
}

fn enforce_transaction_contract_permission_before_proof_verification<R>(
    state: &R,
    authority: &AccountId,
    transaction: &SignedTransaction,
    ivm_cache: &mut IvmCache,
    execution_height: u64,
    execution_dataspace: DataSpaceId,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>>
where
    R: StateReadOnly,
{
    match transaction.instructions() {
        // Batch calls are authorized immediately before each ordered invocation. A preceding
        // item may legitimately install or update the binding which a later call observes, so
        // validating every call against the pre-batch world would break atomic state visibility.
        Executable::Instructions(_) | Executable::Batch(_) => Ok(()),
        Executable::ContractCall(call) => {
            root_scope::ensure_committed_contract_scope(state.world(), &call.contract_address)?;
            code::ensure_contract_execution_allowed(
                state.world(),
                &call.contract_address,
                execution_height,
            )
            .map_err(ValidationFail::NotPermitted)?;
            let identity = code::fetch_bound_contract_identity(state, &call.contract_address)?
                .ok_or_else(|| {
                    ValidationFail::NotPermitted(format!(
                        "contract instance `{}` not found in WSV",
                        call.contract_address
                    ))
                })?;
            ensure_contract_invocation_code_hash(call, identity.code_hash)?;
            let code_bytes = state
                .world()
                .contract_code()
                .get(&iroha_data_model::smart_contract::ContractArtifactId::new(
                    identity.contract_address.dataspace_id().map_err(|_| {
                        ValidationFail::NotPermitted("invalid contract dataspace".into())
                    })?,
                    identity.code_hash,
                ))
                .ok_or_else(|| {
                    ValidationFail::NotPermitted(format!(
                        "contract bytecode `{}` not found in WSV",
                        identity.code_hash
                    ))
                })?;
            let summary = if let Some(summary) = ivm_cache
                .cached_program_summary(identity.code_hash)
                .map_err(|error| ValidationFail::InternalError(error.to_string()))?
            {
                summary
            } else {
                ivm_cache
                    .summarize_program_with_hash(identity.code_hash, code_bytes.as_ref())
                    .map_err(|error| ValidationFail::InternalError(error.to_string()))?
            };
            if summary.prepared_contract().artifact() != code_bytes.as_slice() {
                return Err(ValidationFail::NotPermitted(format!(
                    "cached contract bytecode `{}` does not match live WSV",
                    identity.code_hash
                ))
                .into());
            }
            authorize_prepared_contract_selector(
                state.world(),
                authority,
                summary.prepared_contract(),
                &call.entrypoint,
                &identity,
            )
            .map(drop)?;
            ensure_contract_invocation_metadata_binding(
                call,
                transaction.metadata(),
                summary.prepared_contract(),
                identity.contract_alias.as_ref(),
            )?;
            validate_prepared_ivm_execution_policy(state, &summary.metadata)?;
            let manifest = state
                .world()
                .contract_manifests()
                .get(&iroha_data_model::smart_contract::ContractArtifactId::new(
                    identity.contract_address.dataspace_id().map_err(|_| {
                        ValidationFail::NotPermitted("invalid contract dataspace".into())
                    })?,
                    identity.code_hash,
                ))
                .ok_or_else(|| {
                    ValidationFail::NotPermitted(format!(
                        "contract instance `{}` has no manifest",
                        identity.contract_address
                    ))
                })?;
            crate::smartcontracts::ivm::validate_manifest_hashes(
                manifest,
                summary.code_hash,
                summary.abi_hash,
            )
            .map_err(|error| ValidationFail::IvmAdmission(error).into())
        }
        Executable::Ivm(bytecode) => {
            let admitted = ivm_cache
                .summarize_executable(bytecode.as_ref())
                .map_err(|error| {
                    crate::execution_attempt::vm_attempt_error(
                        error,
                        crate::smartcontracts::ivm::program_admission_error,
                    )
                })?;
            let summary = match admitted {
                ExecutableProgramSummary::Generic(summary) => {
                    crate::smartcontracts::ivm::validate_generic_execution_context(
                        state.world(),
                        transaction.metadata(),
                        iroha_data_model::smart_contract::ContractArtifactId::new(
                            execution_dataspace,
                            summary.code_hash,
                        ),
                    )?;
                    validate_prepared_ivm_execution_policy(state, &summary.metadata)?;
                    return Ok(());
                }
                ExecutableProgramSummary::Contract(summary) => summary,
            };
            let selector = requested_contract_entrypoint(transaction.metadata())?.ok_or_else(|| {
                ValidationFail::NotPermitted(
                    "self-describing raw-IVM contract dispatch requires explicit contract_entrypoint metadata"
                        .to_owned(),
                )
            })?;
            let identity = require_raw_contract_runtime_identity(
                state.world(),
                summary.code_hash,
                transaction.metadata(),
            )?;
            code::ensure_contract_execution_allowed(
                state.world(),
                &identity.contract_address,
                execution_height,
            )
            .map_err(ValidationFail::NotPermitted)?;
            authorize_prepared_raw_contract_selector(
                state.world(),
                authority,
                summary.prepared_contract(),
                &selector,
                &identity,
            )?;
            validate_prepared_ivm_execution_policy(state, &summary.metadata)?;
            crate::pipeline::overlay::validate_contract_binding(
                state,
                transaction.payload(),
                &summary,
            )
            .map_err(overlay_build_error_to_validation_fail)?;
            Ok(())
        }
        Executable::IvmProved(proved) => {
            let summary = ivm_cache
                .summarize_program(proved.bytecode.as_ref())
                .map_err(|error| ValidationFail::InternalError(error.to_string()))?;
            let selector = requested_contract_entrypoint(transaction.metadata())?.ok_or_else(|| {
                ValidationFail::NotPermitted(
                    "self-describing proved raw-IVM contract dispatch requires explicit contract_entrypoint metadata"
                        .to_owned(),
                )
            })?;
            let identity = require_raw_contract_runtime_identity(
                state.world(),
                summary.code_hash,
                transaction.metadata(),
            )?;
            authorize_prepared_raw_contract_selector(
                state.world(),
                authority,
                summary.prepared_contract(),
                &selector,
                &identity,
            )?;
            validate_governed_ivm_proved_execution_policy(state, &summary.metadata)?;
            crate::pipeline::overlay::validate_contract_binding(
                state,
                transaction.payload(),
                &summary,
            )
            .map_err(overlay_build_error_to_validation_fail)?;
            Ok(())
        }
    }
}
fn can_modify_account_metadata(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    account_id: &AccountId,
) -> Result<bool, ValidationFail> {
    if authority == account_id {
        return Ok(true);
    }
    let required: Permission = executor_permission::account::CanModifyAccountMetadata {
        account: account_id.clone(),
    }
    .into();
    authority_has_permission(world, authority, &required)
}
fn authority_owns_domain(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    domain_id: &DomainId,
) -> Result<bool, ValidationFail> {
    let owner = world
        .domain(domain_id)
        .map(|domain| domain.owned_by().clone())
        .map_err(|err| ValidationFail::InstructionFailed(InstructionExecutionError::Find(err)))?;
    Ok(&owner == authority)
}
fn authority_owns_any_alias_domain(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    subject: &AccountId,
    now_ms: u64,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    for alias in world.bound_account_aliases(subject) {
        if crate::sns::resolve_active_account_alias(
            world,
            world.dataspace_catalog(),
            &alias,
            now_ms,
        )
        .map_err(sns_permission_attempt_error)?
        .as_ref()
            != Some(subject)
        {
            continue;
        }
        let Some(domain_id) = alias.domain_id(world.dataspace_catalog()).map_err(|err| {
            ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(
                err.to_string().into(),
            ))
        })?
        else {
            continue;
        };
        if authority_owns_domain(world, authority, &domain_id)? {
            return Ok(true);
        }
    }
    Ok(false)
}
fn can_transfer_domain(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    transfer: &Transfer<Account, DomainId, Account>,
    now_ms: u64,
) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    if transfer.source() == authority {
        return Ok(true);
    }
    if authority_owns_any_alias_domain(world, authority, transfer.source(), now_ms)? {
        return Ok(true);
    }
    authority_owns_domain(world, authority, transfer.object()).map_err(Into::into)
}
fn can_transfer_asset_definition(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    transfer: &Transfer<Account, AssetDefinitionId, Account>,
) -> Result<bool, ValidationFail> {
    if transfer.source() == authority {
        return Ok(true);
    }
    let owner = world
        .asset_definition(transfer.object())
        .map(|definition| definition.owned_by().clone())
        .map_err(|err| ValidationFail::InstructionFailed(InstructionExecutionError::Find(err)))?;
    Ok(&owner == authority)
}
fn can_transfer_nft(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    transfer: &Transfer<Account, iroha_data_model::NftId, Account>,
) -> Result<bool, ValidationFail> {
    if transfer.source() == authority {
        return Ok(true);
    }
    if authority_owns_domain(world, authority, transfer.object().domain())? {
        return Ok(true);
    }
    let required: Permission = executor_permission::nft::CanTransferNft {
        nft: transfer.object().clone(),
    }
    .into();
    authority_has_permission(world, authority, &required)
}
fn can_transfer_asset(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    contract_runtime_context: Option<&ContractRuntimeExecutionContext>,
    transfer: &Transfer<Asset, Quantity, Account>,
) -> Result<bool, ValidationFail> {
    if !valid_contract_runtime_subject(world, authority, contract_runtime_context) {
        return Ok(false);
    }
    if transfer.source().account() == authority {
        return Ok(true);
    }
    let asset = transfer.source().clone();
    let specific: Permission = executor_permission::asset::CanTransferAsset {
        asset: asset.clone(),
    }
    .into();
    if authority_has_permission(world, authority, &specific)? {
        return Ok(true);
    }
    let by_definition: Permission = executor_permission::asset::CanTransferAssetWithDefinition {
        asset_definition: asset.definition().clone(),
    }
    .into();
    authority_has_permission(world, authority, &by_definition)
}
fn valid_contract_runtime_subject(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    contract_runtime_context: Option<&ContractRuntimeExecutionContext>,
) -> bool {
    let Some(context) = contract_runtime_context else {
        return true;
    };
    let live_subject = code::bound_contract_subject_from_world(world, &context.contract_address);
    context.contract_subject == *authority
        && context.contract_address.subject_id() == context.contract_subject
        && live_subject.as_ref() == Some(authority)
        && world.contract_subject_addresses().get(authority) == Some(&context.contract_address)
}
fn normalize_role_permission_for_initial_executor(
    state_transaction: &StateTransaction<'_, '_>,
    permission: &Permission,
) -> Result<Permission, ValidationFail> {
    let known_permission = state_transaction
        .world
        .executor_data_model
        .get()
        .permissions()
        .iter()
        .any(|known| known.as_str() == permission.name())
        || is_builtin_initial_permission_name(permission.name());
    if !known_permission {
        return Err(ValidationFail::NotPermitted(format!(
            "{permission:?}: Unknown permission"
        )));
    }
    validate_initial_permission_payload_constraints(permission)?;
    if is_initial_genesis_context(state_transaction)
        && matches!(
            permission.name().as_ref(),
            "CanOperateSorafsStreamTokenGateway" | "CanCheckSorafsStreamTokenGateway"
        )
    {
        return Err(ValidationFail::NotPermitted(
            "gateway scoped permissions require a configured post-genesis scope".to_owned(),
        ));
    }
    if permission.name() == "CanTransferAsset" {
        let normalized = executor_permission::asset::CanTransferAsset::try_from(permission)
            .map_err(|err| {
                ValidationFail::NotPermitted(format!(
                    "{permission:?}: Invalid permission payload ({err:?})"
                ))
            })?;
        return Ok(normalized.into());
    }
    Ok(permission.clone())
}
fn instruction_has_concrete_type<T: 'static>(instruction: &InstructionBox) -> bool {
    instruction.id() == core::any::type_name::<T>()
}
const INITIAL_EXECUTOR_PERMISSION_NAMES: &[&str] = &[
    "CanManagePeers",
    "CanRegisterDomain",
    "CanUnregisterDomain",
    "CanModifyDomainMetadata",
    "CanUnregisterAssetDefinition",
    "CanModifyAssetDefinitionMetadata",
    "CanManageAssetDefinitionConfidentialPolicy",
    "CanManageKagemushaWallet",
    "CanRegisterAccount",
    "CanUnregisterAccount",
    "CanModifyAccountMetadata",
    "CanReplaceAccountController",
    "CanManageAccountAlias",
    "CanManageAssetDefinitionAlias",
    "CanDelegateAccountAliasResolution",
    "CanResolveAccountAlias",
    "CanReadAllLedgerData",
    "CanReadAccountData",
    "CanReadRestrictedDataspace",
    "CanMintAssetWithDefinition",
    "CanBurnAssetWithDefinition",
    "CanTransferAssetWithDefinition",
    "CanMintAssetToAccount",
    "CanBurnAsset",
    "CanTransferAsset",
    "CanModifyAssetMetadataWithDefinition",
    "CanModifyAssetMetadata",
    "CanSetAssetTransferAvailability",
    "CanSetAssetTransferDailyLimit",
    "CanSetAssetHoldingLimit",
    "CanRegisterNft",
    "CanUnregisterNft",
    "CanTransferNft",
    "CanModifyNftMetadata",
    "CanRegisterTrigger",
    "CanUnregisterTrigger",
    "CanModifyTrigger",
    "CanExecuteTrigger",
    "CanModifyTriggerMetadata",
    "CanSetParameters",
    "CanSetHijiriParameters",
    "CanManageVerifyingKeys",
    "CanManageRuntimeUpgrades",
    "CanManageConsensusKeys",
    "CanManageConfidentialParams",
    "CanProposeSccpRouteGovernance",
    "CanManageRoles",
    "CanUpgradeExecutor",
    "CanManageSmartContractCode",
    "CanGrantSmartContractCodeManagement",
    "CanInvokeContractEntrypoint",
    "CanUseContractPermission",
    "CanExecuteSettlement",
    "CanManageFxCorridors",
    "CanSetFxCorridorPolicy",
    "CanGrantDpnUserForAccountDomain",
    "CanPublishSpaceDirectoryManifest",
    "CanPublishSpaceDirectoryManifestForUaid",
    "CanPublishSpaceDirectoryManifestForAccountDomain",
    "CanManageFeeSponsorProgram",
    "CanEnrollFeeSponsorProgram",
    "CanProposeContractDeployment",
    "CanProposeRuntimeUpgrade",
    "CanSubmitGovernanceBallot",
    "CanEnactGovernance",
    "CanManageParliament",
    "CanSlashGovernanceLock",
    "CanRestituteGovernanceLock",
    "CanManageSoracloud",
    "CanGovernSoracloudFhe",
    "CanBindSorafsAlias",
    "CanDeclareSorafsCapacity",
    "CanSubmitSorafsTelemetry",
    "CanFileSorafsCapacityDispute",
    "CanIssueSorafsReplicationOrder",
    "CanCompleteSorafsReplicationOrder",
    "CanSetSorafsPricing",
    "CanSetSorafsReservePolicy",
    "CanManageSorafsModeration",
    "CanManageSorafsPopRegistry",
    "CanOperateSorafsPopIssuer",
    "CanUpsertSorafsProviderCredit",
    "CanManageSorafsStreamTokenCustody",
    "CanManageSorafsStreamTokenGateway",
    "CanOperateSorafsStreamTokenGateway",
    "CanCheckSorafsStreamTokenGateway",
    "CanManageSorafsFinalPromotionCustody",
    "CanOperateSorafsFinalPromotion",
    "CanCheckSorafsFinalPromotion",
    "CanManageSorafsFinalPromotionAccountCustody",
    "CanCheckSorafsFinalPromotionAccountCustody",
    "CanOperateSorafsRepair",
    "CanManageSorafsProofOutcomePolicy",
    "CanRecordSorafsProofOutcome",
    "CanManageSorafsReputationJournalPolicy",
    "CanRecordSorafsReputationJournal",
    "CanResolveSorafsCapacityDispute",
    "CanManageSoranetVpnQuoteIssuers",
    "CanIssueSoranetVpnQuote",
    "CanIngestSoranetPrivacy",
    "CanRegisterOracleFeed",
    "CanProposeOracleChange",
    "CanVoteOracleChangeStage",
    "CanRollbackOracleChange",
    "CanResolveOracleDispute",
    "CanManageTwitterBindings",
    "CanResolveEscrowDispute",
];

#[cfg(test)]
mod kagemusha_permission_tests {
    use super::*;
    use iroha_data_model::{
        Registrable,
        asset::{AssetBalancePolicy, AssetDefinition},
        permission::Permissions,
    };
    #[test]
    fn kagemusha_management_delegates_only_from_exact_asset_owner_or_holder() {
        let account = |seed| {
            AccountId::new(
                iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            )
        };
        let owner = account(81);
        let delegate = account(82);
        let stranger = account(83);
        let definition = |name: &str| {
            AssetDefinitionId::derive_from_components(
                iroha_model_base::domain::DomainId::try_new("kg", "universal").unwrap(),
                name.parse().unwrap(),
            )
        };
        let asset = definition("one");
        let other = definition("two");
        let mut world = crate::state::World::with_assets(
            [],
            [
                Account::new(owner.clone()).build(&owner),
                Account::new(delegate.clone()).build(&delegate),
                Account::new(stranger.clone()).build(&stranger),
            ],
            [
                AssetDefinition::numeric(asset.clone(), "one", AssetBalancePolicy::Global, None)
                    .build(&owner),
                AssetDefinition::numeric(other.clone(), "two", AssetBalancePolicy::Global, None)
                    .build(&stranger),
            ],
            [],
            [],
        );
        let permission: Permission =
            executor_permission::asset_definition::CanManageKagemushaWallet {
                asset_definition: asset.clone(),
            }
            .into();
        let unrelated: Permission =
            executor_permission::asset_definition::CanManageKagemushaWallet {
                asset_definition: other.clone(),
            }
            .into();
        world.account_permissions.insert(
            delegate.clone(),
            Permissions::from_iter([permission.clone()]),
        );
        let state = crate::state::State::new_for_testing(
            world,
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            1.try_into().unwrap(),
            None,
            None,
            1000,
            0,
        ));
        let tx = block.transaction();
        assert!(initial_permission_delegation_allowed(&tx, &owner, &permission).unwrap());
        assert!(initial_permission_delegation_allowed(&tx, &delegate, &permission).unwrap());
        assert!(!initial_permission_delegation_allowed(&tx, &stranger, &permission).unwrap());
        assert!(!initial_permission_delegation_allowed(&tx, &delegate, &unrelated).unwrap());
        assert!(initial_permission_revocation_allowed(&tx, &owner, &permission).unwrap());
    }
}
