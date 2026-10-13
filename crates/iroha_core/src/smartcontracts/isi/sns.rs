//! SNS-backed ownership query and lease instruction handlers.
use super::prelude::*;
use crate::{
    prelude::ValidSingularQuery,
    sns::{LeasePayment, RegisterNameInput},
};
use iroha_data_model::{
    alias_setup::{
        AliasAutoRenewConfigV1, AliasAutoRenewStateV1, AliasIntentV1, AliasPlanDispositionV1,
    },
    isi::{
        alias_setup::{
            CompareAndSetPrimaryAccountAlias, ConfigureAliasAutoRenew, EnsureAlias,
            RebindAccountAlias, RenewAliasLease,
        },
        error::{InstructionExecutionError, InvalidParameterError},
    },
    query::{error::QueryExecutionFail as QueryError, sns::prelude::*},
    sns::{NameControllerV1, SuffixId},
};
use iroha_telemetry::metrics;
impl ValidSingularQuery for FindDataspaceNameOwnerById {
    #[metrics(+"find_dataspace_name_owner_by_id")]
    fn execute(&self, state_ro: &impl StateReadOnly) -> Result<AccountId, QueryError> {
        crate::sns::active_dataspace_owner_by_id(
            state_ro.world(),
            &state_ro.nexus().dataspace_catalog,
            self.dataspace_id(),
            state_ro.query_ledger_time_ms(),
        )
        .map_err(|error| match error {
            crate::sns::SnsError::Deferred(_) => QueryError::GasBudgetExceeded,
            error => QueryError::Conversion(error.to_string()),
        })?
        .ok_or(QueryError::NotFound)
    }
}
fn alias_lease_instruction_error(
    err: crate::sns::SnsError,
    state: &mut StateTransaction<'_, '_>,
) -> InstructionExecutionError {
    err.retain_in_instruction(state)
}
fn sns_mutation_instruction_error(
    err: crate::sns::SnsError,
    state: &mut StateTransaction<'_, '_>,
) -> InstructionExecutionError {
    match err {
        crate::sns::SnsError::BadRequest(message) => InstructionExecutionError::InvalidParameter(
            InvalidParameterError::SmartContract(message.into()),
        ),
        error => error.retain_in_instruction(state),
    }
}
fn alias_setup_instruction_error(
    error: crate::alias_setup::AliasSetupError,
    state: &mut StateTransaction<'_, '_>,
) -> InstructionExecutionError {
    match error.into_deferral() {
        Ok(original) => {
            let _ = state.defer_execution(original);
            InstructionExecutionError::InvariantViolation(
                "local alias setup did not complete".into(),
            )
        }
        Err(error) => InstructionExecutionError::InvalidParameter(
            InvalidParameterError::SmartContract(error.to_string().into()),
        ),
    }
}
fn namespace_from_suffix_id(
    suffix_id: SuffixId,
) -> Result<crate::sns::SnsNamespace, InstructionExecutionError> {
    // This pure numeric namespace check has no decoder or allocation scope.
    crate::sns::SnsNamespace::from_suffix_id(suffix_id).map_err(|error| {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            error.to_string().into(),
        ))
    })
}
fn ensure_configured_policy_payment_asset(
    state_transaction: &mut StateTransaction<'_, '_>,
    namespace: crate::sns::SnsNamespace,
) -> Result<(), InstructionExecutionError> {
    crate::sns::ensure_namespace_policy_payment_asset_matches_configured(
        state_transaction.world(),
        namespace,
        &state_transaction.nexus.fees.fee_asset_id,
    )
    .map_err(|error| sns_mutation_instruction_error(error, state_transaction))
}
fn account_controller_for(
    owner: &AccountId,
) -> Result<NameControllerV1, InstructionExecutionError> {
    AccountAddress::from_account_id(owner)
        .map(|address| NameControllerV1::account(&address))
        .map_err(|err| {
            InstructionExecutionError::InvariantViolation(
                format!("failed to derive account-alias controller: {err}").into(),
            )
        })
}
fn charge_sns_quote(
    quote: &crate::sns::LeaseQuote,
    payer: AccountId,
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<LeasePayment, Error> {
    let charge = quote.charge_amount.clone();
    Transfer::asset_quantity(
        AssetId::of(quote.payment_asset_definition_id.clone(), payer.clone()),
        charge,
        quote.collector_account.clone(),
    )
    .execute(authority, state_transaction)?;
    Ok(crate::sns::native_payment_for_quote(quote))
}
fn repair_alias_intent_resource(
    intent: &AliasIntentV1,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    match intent {
        AliasIntentV1::Dataspace(_) => {}
        AliasIntentV1::Domain(value) => {
            if state_transaction
                .world
                .domains
                .get(&value.domain.canonical_name)
                .is_none()
            {
                Register::domain(Domain::new(value.domain.canonical_name.clone()))
                    .execute(&value.owner, state_transaction)?;
            } else {
                state_transaction
                    .world
                    .track_domain_owner(&value.domain.canonical_name, &value.owner);
            }
        }
        AliasIntentV1::AccountAlias(value) => {
            if state_transaction
                .world
                .accounts
                .get(&value.target_account)
                .is_none()
            {
                Register::account(Account::new(value.target_account.clone()))
                    .execute(&value.target_account, state_transaction)?;
            }
            super::domain::isi::repair_account_alias_setup_state(state_transaction, value)?;
        }
    }
    Ok(())
}
fn grant_exact_alias_permissions(
    intent: &AliasIntentV1,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let owner = crate::alias_setup::alias_intent_owner(intent).clone();
    for permission in crate::alias_setup::exact_alias_permission_bundle(intent) {
        Grant::account_permission(permission, owner.clone()).execute(&owner, state_transaction)?;
    }
    Ok(())
}
fn ensure_active_alias_record(
    target: &iroha_data_model::alias_setup::AliasTargetV1,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<
    (
        iroha_data_model::sns::NameSelectorV1,
        iroha_data_model::sns::NameRecordV1,
    ),
    Error,
> {
    let now_ms = state_transaction.block_unix_timestamp_ms();
    crate::alias_setup::validate_resolved_alias_target(
        state_transaction.world(),
        &state_transaction.nexus.dataspace_catalog,
        target,
        now_ms,
    )
    .map_err(|error| alias_setup_instruction_error(error, state_transaction))?;
    let selector = crate::alias_setup::selector_for_resolved_alias_target(target)
        .map_err(|error| alias_setup_instruction_error(error, state_transaction))?;
    let record =
        crate::sns::get_name_record_by_selector(state_transaction.world(), &selector, now_ms)
            .map_err(|error| alias_lease_instruction_error(error, state_transaction))?;
    if !matches!(record.status, iroha_data_model::sns::NameStatus::Active) {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "alias.lifecycle.conflict: `{}` is not active",
                selector.normalized_label()
            )
            .into(),
        )
        .into());
    }
    Ok((selector, record))
}
fn authority_can_manage_alias_target(
    world: &impl crate::state::WorldReadOnly,
    authority: &AccountId,
    target: &iroha_data_model::alias_setup::AliasTargetV1,
) -> Result<bool, crate::sns::SnsError> {
    match target {
        iroha_data_model::alias_setup::AliasTargetV1::Dataspace(value) => {
            crate::alias::authority_can_manage_account_alias_scope(
                world,
                authority,
                value.dataspace_id,
                None,
            )
        }
        iroha_data_model::alias_setup::AliasTargetV1::Domain(value) => {
            crate::alias::authority_can_manage_account_alias_scope(
                world,
                authority,
                value.dataspace_id,
                Some(&value.canonical_name),
            )
        }
        iroha_data_model::alias_setup::AliasTargetV1::AccountAlias(value) => {
            crate::alias::authority_can_manage_resolved_account_alias(world, authority, value)
        }
    }
}
fn ensure_alias_lifecycle_authority(
    record: &iroha_data_model::sns::NameRecordV1,
    target: &iroha_data_model::alias_setup::AliasTargetV1,
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    if record.owner == *authority
        || authority_can_manage_alias_target(state_transaction.world(), authority, target)
            .map_err(|error| alias_lease_instruction_error(error, state_transaction))?
    {
        return Ok(());
    }
    Err(InstructionExecutionError::InvariantViolation(
        "authority must own or hold exact management permission for the alias target"
            .to_owned()
            .into(),
    )
    .into())
}
impl Execute for EnsureAlias {
    #[metrics(+"ensure_alias")]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Self {
            intent,
            acquisition,
            quote_guard,
        } = self;
        let now_ms = state_transaction.block_unix_timestamp_ms();
        let disposition = crate::alias_setup::classify_alias_intent_with_endorsement_policy(
            state_transaction.world(),
            &state_transaction.nexus.dataspace_catalog,
            &intent,
            now_ms,
            state_transaction.nexus.endorsement.quorum > 0,
        )
        .map_err(|error| alias_setup_instruction_error(error, state_transaction))?;
        // Classification deliberately precedes all quote-guard checks. Exact
        // replay and derived-state repair never quote or charge a lease.
        match disposition {
            AliasPlanDispositionV1::NoOp => return Ok(()),
            AliasPlanDispositionV1::Repair => {
                crate::alias_setup::validate_alias_intent_authority(
                    state_transaction.world(),
                    authority,
                    &intent,
                )
                .map_err(|error| alias_setup_instruction_error(error, state_transaction))?;
                repair_alias_intent_resource(&intent, state_transaction)?;
                grant_exact_alias_permissions(&intent, state_transaction)?;
                return Ok(());
            }
            AliasPlanDispositionV1::Create => {
                crate::alias_setup::validate_alias_intent_authority(
                    state_transaction.world(),
                    authority,
                    &intent,
                )
                .map_err(|error| alias_setup_instruction_error(error, state_transaction))?;
            }
            AliasPlanDispositionV1::Conflict => {
                return Err(InstructionExecutionError::InvariantViolation(
                    "alias.state.conflict: classifier returned a non-executable conflict"
                        .to_owned()
                        .into(),
                )
                .into());
            }
        }
        let target = intent.target();
        let namespace = namespace_from_suffix_id(crate::alias_setup::target_suffix_id(&target))?;
        ensure_configured_policy_payment_asset(state_transaction, namespace)?;
        let selector = crate::alias_setup::selector_for_resolved_alias_target(&target)
            .map_err(|error| alias_setup_instruction_error(error, state_transaction))?;
        let owner = crate::alias_setup::alias_intent_owner(&intent).clone();
        let quote = crate::sns::quote_resolved_name_registration(
            state_transaction.world(),
            selector,
            &owner,
            acquisition.term_years,
            acquisition.pricing_class_hint,
            now_ms,
        )
        .map_err(|error| alias_lease_instruction_error(error, state_transaction))?;
        crate::alias_setup::validate_alias_quote_guard(
            state_transaction.world(),
            &quote,
            &quote_guard,
            now_ms,
        )
        .map_err(|error| alias_setup_instruction_error(error, state_transaction))?;
        let controllers = vec![account_controller_for(&owner)?];
        let metadata = crate::alias_setup::alias_registration_metadata(&target)
            .map_err(|error| alias_setup_instruction_error(error, state_transaction))?;
        let payment = charge_sns_quote(&quote, authority.clone(), authority, state_transaction)?;
        crate::sns::register_resolved_name(
            state_transaction,
            RegisterNameInput {
                selector: quote.selector,
                owner,
                controllers,
                term_years: acquisition.term_years,
                pricing_class_hint: Some(quote.pricing_class),
                payment,
                metadata,
            },
        )
        .map_err(|error| alias_lease_instruction_error(error, state_transaction))?;
        repair_alias_intent_resource(&intent, state_transaction)?;
        grant_exact_alias_permissions(&intent, state_transaction)?;
        Ok(())
    }
}
impl Execute for RenewAliasLease {
    #[metrics(+"renew_alias_lease_cas")]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Self {
            target,
            expected_current_expiry_ms,
            target_expiry_ms,
            quote_guard,
        } = self;
        let (selector, record) = ensure_active_alias_record(&target, state_transaction)?;
        ensure_alias_lifecycle_authority(&record, &target, authority, state_transaction)?;
        if record.expires_at_ms != expected_current_expiry_ms {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "alias.lease.expiry_conflict: expected current expiry {expected_current_expiry_ms}, actual expiry is {}",
                    record.expires_at_ms
                )
                .into(),
            )
            .into());
        }
        let namespace = namespace_from_suffix_id(selector.suffix_id)?;
        ensure_configured_policy_payment_asset(state_transaction, namespace)?;
        let now_ms = state_transaction.block_unix_timestamp_ms();
        let quote = crate::sns::quote_resolved_name_renewal(
            state_transaction.world(),
            selector.clone(),
            expected_current_expiry_ms,
            target_expiry_ms,
            now_ms,
        )
        .map_err(|error| alias_lease_instruction_error(error, state_transaction))?;
        crate::alias_setup::validate_alias_quote_guard(
            state_transaction.world(),
            &quote,
            &quote_guard,
            now_ms,
        )
        .map_err(|error| alias_setup_instruction_error(error, state_transaction))?;
        let payment = charge_sns_quote(&quote, authority.clone(), authority, state_transaction)?;
        crate::sns::renew_resolved_name(
            state_transaction,
            selector,
            expected_current_expiry_ms,
            target_expiry_ms,
            payment,
        )
        .map(|_| ())
        .map_err(|error| alias_lease_instruction_error(error, state_transaction))
    }
}
fn validate_auto_renew_config(
    config: &AliasAutoRenewConfigV1,
    policy: &iroha_data_model::sns::SuffixPolicyV1,
) -> Result<(), Error> {
    crate::alias_setup::validate_alias_auto_renew_ranges(config).map_err(|error| {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            error.to_string().into(),
        ))
    })?;
    if config.term_years < policy.min_term_years || config.term_years > policy.max_term_years {
        return Err(InstructionExecutionError::InvalidParameter(
            InvalidParameterError::SmartContract(
                format!(
                    "auto-renew term {} is outside policy range {}..={}",
                    config.term_years, policy.min_term_years, policy.max_term_years
                )
                .into(),
            ),
        )
        .into());
    }
    if config.policy_version != policy.policy_version {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "alias.auto_renew.policy_drift: expected version {}, actual version is {}",
                config.policy_version, policy.policy_version
            )
            .into(),
        )
        .into());
    }
    let payment_asset = if let Ok(asset_id) = AssetId::parse_literal(&policy.payment_asset_id) {
        asset_id.definition().clone()
    } else {
        AssetDefinitionId::parse_address_literal(&policy.payment_asset_id).map_err(|error| {
            InstructionExecutionError::InvariantViolation(
                format!("SNS policy contains invalid payment asset: {error}").into(),
            )
        })?
    };
    if config.payment_asset != payment_asset {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "alias.auto_renew.asset_drift: expected `{}`, actual asset is `{payment_asset}`",
                config.payment_asset
            )
            .into(),
        )
        .into());
    }
    Ok(())
}
impl Execute for ConfigureAliasAutoRenew {
    #[metrics(+"configure_alias_auto_renew")]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Self {
            target,
            expected_revision,
            config,
        } = self;
        let (selector, record) = ensure_active_alias_record(&target, state_transaction)?;
        if record.owner != *authority {
            return Err(InstructionExecutionError::InvariantViolation(
                "only the exact alias resource owner may configure auto-renew"
                    .to_owned()
                    .into(),
            )
            .into());
        }
        let current = crate::sns::alias_auto_renew_state(state_transaction.world(), &target)
            .map_err(|error| alias_lease_instruction_error(error, state_transaction))?;
        let current_revision = current.as_ref().map_or(0, |state| state.revision);
        if current_revision != expected_revision {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "alias.auto_renew.revision_conflict: expected revision {expected_revision}, actual revision is {current_revision}"
                )
                .into(),
            )
            .into());
        }
        // The exact live lease owner and revision have been checked. A stale
        // persisted owner must not prevent explicit replacement or disable;
        // persist_alias_auto_renew_state still admits the new owner's complete
        // retained transfer shape before changing the original record.
        if cfg!(all(test, sumeragi_core_mutation = "HC42"))
            && let Some(current) = current.as_ref()
            && current.owner != record.owner
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "alias.auto_renew.owner_conflict: persisted owner differs from the lease owner"
                    .to_owned()
                    .into(),
            )
            .into());
        }
        if let Some(config) = config.as_ref() {
            let policy = crate::sns::policy_by_id(state_transaction.world(), selector.suffix_id)
                .map_err(|error| alias_lease_instruction_error(error, state_transaction))?
                .ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        "SNS policy is missing for the auto-renew target"
                            .to_owned()
                            .into(),
                    )
                })?;
            validate_auto_renew_config(config, &policy)?;
        }
        let revision = current_revision.checked_add(1).ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                "alias auto-renew revision overflowed".to_owned().into(),
            )
        })?;
        let state = AliasAutoRenewStateV1::new(target, record.owner, revision, config);
        crate::sns::persist_alias_auto_renew_state(state_transaction, &state)
            .map_err(|error| alias_lease_instruction_error(error, state_transaction))?;
        Ok(())
    }
}
impl Execute for RebindAccountAlias {
    #[metrics(+"rebind_account_alias_cas")]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Self {
            alias,
            expected_target_account,
            new_target_account,
        } = self;
        let target = iroha_data_model::alias_setup::AliasTargetV1::AccountAlias(alias.clone());
        let (_, record) = ensure_active_alias_record(&target, state_transaction)?;
        ensure_alias_lifecycle_authority(&record, &target, authority, state_transaction)?;
        let numeric_alias = alias.account_alias();
        let actual = state_transaction
            .world
            .account_aliases
            .get(&numeric_alias)
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    "alias.binding.conflict: account alias is not bound"
                        .to_owned()
                        .into(),
                )
            })?
            .clone();
        if actual != expected_target_account {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "alias.binding.conflict: expected target `{expected_target_account}`, actual target is `{actual}`"
                )
                .into(),
            )
            .into());
        }
        state_transaction.world.account(&new_target_account)?;
        if state_transaction
            .world
            .account(&expected_target_account)?
            .label()
            == Some(&numeric_alias)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "alias.primary.conflict: clear or replace the primary alias before rebinding"
                    .to_owned()
                    .into(),
            )
            .into());
        }
        if expected_target_account == new_target_account {
            return Ok(());
        }
        state_transaction
            .world
            .insert_account_alias_binding(numeric_alias.clone(), new_target_account.clone());
        super::domain::isi::upsert_account_rekey_record(
            state_transaction,
            &numeric_alias,
            &new_target_account,
        )?;
        Ok(())
    }
}
impl Execute for CompareAndSetPrimaryAccountAlias {
    #[metrics(+"compare_and_set_primary_account_alias")]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Self {
            account,
            expected_alias,
            new_alias,
        } = self;
        let current = state_transaction.world.account(&account)?.label().cloned();
        let expected_numeric = expected_alias
            .as_ref()
            .map(iroha_data_model::alias_setup::ResolvedAccountAliasV1::account_alias);
        if current != expected_numeric {
            return Err(InstructionExecutionError::InvariantViolation(
                "alias.primary.conflict: current primary alias differs from compare-and-set expectation"
                    .to_owned()
                    .into(),
            )
            .into());
        }
        for alias in expected_alias.iter().chain(new_alias.iter()) {
            let target = iroha_data_model::alias_setup::AliasTargetV1::AccountAlias(alias.clone());
            let (_, record) = ensure_active_alias_record(&target, state_transaction)?;
            ensure_alias_lifecycle_authority(&record, &target, authority, state_transaction)?;
        }
        if authority != &account && expected_alias.is_none() && new_alias.is_none() {
            return Err(InstructionExecutionError::InvariantViolation(
                "only the account may compare-and-set an empty primary alias"
                    .to_owned()
                    .into(),
            )
            .into());
        }
        let new_numeric = new_alias
            .as_ref()
            .map(iroha_data_model::alias_setup::ResolvedAccountAliasV1::account_alias);
        if let Some(new_numeric) = new_numeric.as_ref() {
            let binding = state_transaction
                .world
                .account_aliases
                .get(new_numeric)
                .ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        "alias.binding.conflict: new primary alias is not bound"
                            .to_owned()
                            .into(),
                    )
                })?;
            if binding != &account {
                return Err(InstructionExecutionError::InvariantViolation(
                    "alias.binding.conflict: new primary alias is bound to another account"
                        .to_owned()
                        .into(),
                )
                .into());
            }
        }
        if current == new_numeric {
            return Ok(());
        }
        if let Some(current_alias) = current.as_ref() {
            let catalog = state_transaction.world.dataspace_catalog();
            let current_domain = current_alias.domain_id(catalog).map_err(|err| {
                InstructionExecutionError::InvariantViolation(
                    format!("failed to resolve current primary alias domain: {err}").into(),
                )
            })?;
            let new_domain = new_numeric
                .as_ref()
                .map(|alias| alias.domain_id(catalog))
                .transpose()
                .map_err(|err| {
                    InstructionExecutionError::InvariantViolation(
                        format!("failed to resolve new primary alias domain: {err}").into(),
                    )
                })?
                .flatten();
            if let Some(current_domain) = current_domain.as_ref() {
                super::kaigi::ensure_kaigi_relay_home_change_allowed(
                    state_transaction,
                    &account,
                    current_domain,
                    new_domain.as_ref(),
                )?;
            }
        }
        if let Some(current) = current.as_ref() {
            super::domain::isi::ensure_alias_can_change_recovery_binding(
                state_transaction,
                current,
            )?;
        }
        state_transaction
            .world
            .account_mut(&account)?
            .set_label(new_numeric.clone());
        if let Some(new_numeric) = new_numeric {
            super::domain::isi::upsert_account_rekey_record(
                state_transaction,
                &new_numeric,
                &account,
            )?;
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "sns/rekey_auto_renew_tests.rs"]
mod rekey_auto_renew_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        sns::{
            ACCOUNT_ALIAS_SUFFIX_ID, DATASPACE_ALIAS_SUFFIX_ID, DOMAIN_NAME_SUFFIX_ID,
            SnsNamespace, get_name_record, policy_by_id, seed_default_namespace_policies,
        },
        state::{State, StateTransaction, World, WorldReadOnly},
    };
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        Registrable,
        account::{
            Account, AccountAddress,
            rekey::{AccountAlias, AccountAliasDomain},
        },
        alias_setup::{
            AccountAliasName, AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1,
            AliasDataSpaceIntentV1, AliasDomainIntentV1, AliasIntentV1, AliasLeaseAcquisitionV1,
            AliasQuoteGuardV1, AliasTargetV1, ResolvedAccountAliasV1, ResolvedDataSpaceV1,
            ResolvedDomainV1,
        },
        asset::{Asset, AssetDefinition, AssetDefinitionId, AssetId},
        block::BlockHeader,
        domain::Domain,
        isi::{
            Mint, Register,
            alias_setup::{EnsureAlias, RenewAliasLease},
        },
        nexus::{DataSpaceCatalog, DataSpaceMetadata},
        permission::Permission,
        query::sns::prelude::FindDataspaceNameOwnerById,
        sns::{NameControllerV1, NameRecordV1},
    };
    use iroha_executor_data_model::permission::account::{
        AccountAliasPermissionScope, CanManageAccountAlias,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_primitives::numeric::Quantity;
    use iroha_test_samples::ALICE_KEYPAIR;
    use mv::storage::StorageReadOnly;
    use std::num::NonZeroU64;
    fn owner() -> AccountId {
        let public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .expect("public key");
        AccountId::new(public_key)
    }
    fn another_owner() -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair");
        AccountId::new(keypair.public_key().clone())
    }
    fn next_header(state: &State) -> BlockHeader {
        let height = u64::try_from(state.view().height())
            .unwrap_or(0)
            .saturating_add(1);
        BlockHeader::new(
            NonZeroU64::new(height).expect("height > 0"),
            None,
            None,
            0,
            0,
        )
    }
    fn seed_test_call_hash(state_transaction: &mut StateTransaction<'_, '_>, byte: u8) {
        state_transaction.tx_call_hash = Some(Hash::prehashed([byte; Hash::LENGTH]));
    }
    fn configure_test_fee_asset(state: &State, asset: &AssetDefinitionId) {
        state.nexus.write().fees.fee_asset_id = asset.to_string();
    }
    fn smart_contract_error_contains(error: &InstructionExecutionError, expected: &str) -> bool {
        matches!(
            error,
            InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(message)
            ) if message.contains(expected)
        )
    }
    fn asset_balance(
        state: &State,
        payment_asset_definition_id: &AssetDefinitionId,
        account: &AccountId,
    ) -> Quantity {
        let view = state.view();
        asset_balance_in_world(view.world(), payment_asset_definition_id, account)
    }
    fn asset_balance_in_world(
        world: &impl WorldReadOnly,
        payment_asset_definition_id: &AssetDefinitionId,
        account: &AccountId,
    ) -> Quantity {
        world
            .asset(&AssetId::of(
                payment_asset_definition_id.clone(),
                account.clone(),
            ))
            .map(|asset| asset.value().clone().into_inner())
            .unwrap_or_else(|_| Quantity::zero())
    }
    fn resolved_account_alias(
        alias: &AccountAlias,
        catalog: &DataSpaceCatalog,
    ) -> ResolvedAccountAliasV1 {
        ResolvedAccountAliasV1::new(
            alias
                .to_literal(catalog)
                .expect("fixture alias must resolve through the catalog")
                .parse::<AccountAliasName>()
                .expect("fixture alias literal must be canonical"),
            alias.dataspace,
        )
    }
    fn seed_active_domain_lease(
        state_transaction: &mut StateTransaction<'_, '_>,
        domain: &DomainId,
        owner: &AccountId,
    ) {
        let selector = crate::sns::selector_for_domain(domain).expect("fixture domain selector");
        let address = AccountAddress::from_account_id(owner).expect("fixture owner address");
        let record = NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        state_transaction.world.smart_contract_state.insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
    }
    fn seed_active_dataspace_lease(
        world: &mut World,
        alias: &str,
        dataspace_id: DataSpaceId,
        owner: &AccountId,
    ) -> iroha_data_model::sns::NameSelectorV1 {
        let target = AliasTargetV1::Dataspace(ResolvedDataSpaceV1::new(
            alias.parse().expect("canonical dataspace alias"),
            dataspace_id,
        ));
        let selector = crate::alias_setup::selector_for_resolved_alias_target(&target)
            .expect("fixture dataspace selector");
        let address = AccountAddress::from_account_id(owner).expect("fixture owner address");
        let record = NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            crate::alias_setup::alias_registration_metadata(&target)
                .expect("fixture dataspace metadata"),
        );
        world.smart_contract_state_mut_for_testing().insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
        selector
    }
    fn exact_alias_quote_guard(
        state_transaction: &StateTransaction<'_, '_>,
        suffix_id: u16,
        quote: &crate::sns::LeaseQuote,
    ) -> AliasQuoteGuardV1 {
        let policy = policy_by_id(state_transaction.world(), suffix_id)
            .expect("valid fixture policy state")
            .expect("fixture namespace policy");
        AliasQuoteGuardV1 {
            expected_policy_version: policy.policy_version,
            expected_payment_asset: quote.payment_asset_definition_id.clone(),
            max_amount: quote.charge_amount.clone(),
            valid_until_ms: u64::MAX,
        }
    }
    fn exact_account_alias_quote_guard(
        state_transaction: &StateTransaction<'_, '_>,
        quote: &crate::sns::LeaseQuote,
    ) -> AliasQuoteGuardV1 {
        exact_alias_quote_guard(state_transaction, ACCOUNT_ALIAS_SUFFIX_ID, quote)
    }
    fn catalogued_dataspace_ensure(owner: AccountId, dataspace: DataSpaceId) -> EnsureAlias {
        EnsureAlias::new(
            AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
                dataspace: ResolvedDataSpaceV1::new(
                    "governance".parse().expect("catalogued alias"),
                    dataspace,
                ),
                owner,
            }),
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: 0,
                expected_payment_asset:
                    iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                        .parse()
                        .expect("syntactic payment asset"),
                max_amount: Quantity::zero(),
                valid_until_ms: 0,
            },
        )
    }
    fn governance_dataspace_catalog(dataspace: DataSpaceId) -> DataSpaceCatalog {
        DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: dataspace,
                alias: "governance".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("governance dataspace catalog")
    }
    #[test]
    fn ensure_alias_rejects_public_claim_of_catalogued_dataspace_before_mutation() {
        let authority = another_owner();
        let dataspace = DataSpaceId::new(7);
        let mut state = State::new_for_testing(
            World::with([], [Account::new(authority.clone()).build(&authority)], []),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        state.set_dataspace_catalog_for_testing(governance_dataspace_catalog(dataspace));
        let ensure = catalogued_dataspace_ensure(authority.clone(), dataspace);
        let selector =
            crate::alias_setup::selector_for_resolved_alias_target(&ensure.intent.target())
                .expect("catalogued selector");
        let permissions = crate::alias_setup::exact_alias_permission_bundle(&ensure.intent);
        let mut block = state.block(next_header(&state));
        let mut transaction = block.transaction();
        let error = ensure
            .execute(&authority, &mut transaction)
            .expect_err("a catalog entry must not become a public SNS ownership claim");
        assert!(
            smart_contract_error_contains(
                &error,
                crate::alias_setup::CATALOGUED_DATASPACE_BOOTSTRAP_REQUIRED_CODE,
            ),
            "unexpected error: {error}",
        );
        assert!(
            crate::sns::record_by_selector(transaction.world(), &selector)
                .expect("valid SNS record state")
                .is_none(),
            "rejection must not create an SNS ownership record",
        );
        assert!(
            permissions.iter().all(|permission| {
                !transaction
                    .world
                    .account_permissions
                    .get(&authority)
                    .is_some_and(|stored| stored.contains(permission))
            }),
            "rejection must not auto-grant catalog-scoped alias capabilities",
        );
    }
    #[test]
    fn ensure_alias_repairs_governed_catalogued_dataspace_bootstrap() {
        let authority = another_owner();
        let dataspace = DataSpaceId::new(7);
        let ensure = catalogued_dataspace_ensure(authority.clone(), dataspace);
        let mut world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        seed_active_dataspace_lease(&mut world, "governance", dataspace, &authority);
        let mut state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        state.set_dataspace_catalog_for_testing(governance_dataspace_catalog(dataspace));
        let permissions = crate::alias_setup::exact_alias_permission_bundle(&ensure.intent);
        let mut block = state.block(next_header(&state));
        let mut transaction = block.transaction();
        ensure
            .execute(&authority, &mut transaction)
            .expect("the authenticated bootstrap owner may repair derived permissions");
        assert!(
            permissions.iter().all(|permission| {
                transaction
                    .world
                    .account_permissions
                    .get(&authority)
                    .is_some_and(|stored| stored.contains(permission))
            }),
            "repair must restore the exact catalog-scoped alias capability bundle",
        );
    }
    fn ensure_account_alias_instruction(
        state_transaction: &StateTransaction<'_, '_>,
        alias: &AccountAlias,
        target_account: AccountId,
        provision: AccountProvisionV1,
        role: AccountAliasRoleV1,
        term_years: u8,
        pricing_class_hint: Option<u8>,
    ) -> EnsureAlias {
        let now_ms = state_transaction.block_unix_timestamp_ms();
        let quote = crate::sns::quote_account_alias_registration(
            state_transaction.world(),
            &state_transaction.nexus.dataspace_catalog,
            alias,
            &target_account,
            term_years,
            pricing_class_hint,
            now_ms,
        )
        .expect("fixture account-alias registration quote");
        EnsureAlias::new(
            AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
                alias: resolved_account_alias(alias, &state_transaction.nexus.dataspace_catalog),
                target_account,
                provision,
                role,
            }),
            AliasLeaseAcquisitionV1::new(term_years, pricing_class_hint),
            exact_account_alias_quote_guard(state_transaction, &quote),
        )
    }
    struct PspAliasFixture {
        state: State,
        authority: AccountId,
        collector: AccountId,
        target_a: AccountId,
        target_b: AccountId,
        payment_asset: AssetDefinitionId,
        dataspace: DataSpaceId,
    }
    fn psp_alias_fixture() -> PspAliasFixture {
        let authority = another_owner();
        let collector = owner();
        let target_a = AccountId::new(
            KeyPair::try_from_seed(vec![0x43; 32], Algorithm::Ed25519)
                .expect("fixture seed must derive a valid target-a keypair")
                .public_key()
                .clone(),
        );
        let target_b = AccountId::new(
            KeyPair::try_from_seed(vec![0x44; 32], Algorithm::Ed25519)
                .expect("fixture seed must derive a valid target-b keypair")
                .public_key()
                .clone(),
        );
        let payment_asset: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("payment asset definition id");
        let genesis =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&collector);
        let leumi = Domain::new(DomainId::try_new("leumi", "is").expect("leumi.is domain id"))
            .build(&authority);
        let hapoalim =
            Domain::new(DomainId::try_new("hapoalim", "is").expect("hapoalim.is domain id"))
                .build(&authority);
        let collector_account = Account::new(collector.clone()).build(&collector);
        let authority_account = Account::new(authority.clone()).build(&collector);
        let target_a_account = Account::new(target_a.clone()).build(&collector);
        let second_target_registration = Account::new(target_b.clone()).build(&collector);
        let payment_definition = AssetDefinition::numeric(
            payment_asset.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&collector);
        let mut world = World::with(
            [genesis, leumi, hapoalim],
            [
                collector_account,
                authority_account,
                target_a_account,
                second_target_registration,
            ],
            [payment_definition],
        );
        seed_default_namespace_policies(&mut world);
        let dataspace = DataSpaceId::new(10);
        let mut permissions = world
            .account_permissions
            .view()
            .get(&authority)
            .cloned()
            .unwrap_or_default();
        permissions.insert(Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Dataspace(dataspace),
        }));
        for domain in [
            DomainId::try_new("leumi", "is").expect("leumi.is domain id"),
            DomainId::try_new("hapoalim", "is").expect("hapoalim.is domain id"),
        ] {
            permissions.insert(Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(domain),
            }));
        }
        world
            .account_permissions
            .insert(authority.clone(), permissions);
        let mut state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        configure_test_fee_asset(&state, &payment_asset);
        state.set_dataspace_catalog_for_testing(
            DataSpaceCatalog::new(vec![
                DataSpaceMetadata::default(),
                DataSpaceMetadata {
                    id: dataspace,
                    alias: "is".to_owned(),
                    description: None,
                    fault_tolerance: 1,
                },
            ])
            .expect("is dataspace catalog"),
        );
        {
            let mut block = state.block(next_header(&state));
            let mut stx = block.transaction();
            Mint::asset_quantity(
                1_000_u64,
                AssetId::of(payment_asset.clone(), authority.clone()),
            )
            .execute(&authority, &mut stx)
            .expect("mint alias payer balance");
            seed_active_domain_lease(
                &mut stx,
                &DomainId::try_new("leumi", "is").expect("leumi.is domain id"),
                &authority,
            );
            seed_active_domain_lease(
                &mut stx,
                &DomainId::try_new("hapoalim", "is").expect("hapoalim.is domain id"),
                &authority,
            );
            stx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("PSP alias fixture block commits");
        }
        PspAliasFixture {
            state,
            authority,
            collector,
            target_a,
            target_b,
            payment_asset,
            dataspace,
        }
    }
    fn renew_account_alias_instruction(
        state_transaction: &StateTransaction<'_, '_>,
        alias: &AccountAlias,
        term_years: u8,
    ) -> RenewAliasLease {
        let now_ms = state_transaction.block_unix_timestamp_ms();
        let record = crate::sns::get_name_record(
            state_transaction.world(),
            SnsNamespace::AccountAlias,
            &alias
                .to_literal(&state_transaction.nexus.dataspace_catalog)
                .expect("fixture alias literal"),
            now_ms,
        )
        .expect("fixture account-alias record");
        let quote = crate::sns::quote_account_alias_renewal(
            state_transaction.world(),
            &state_transaction.nexus.dataspace_catalog,
            alias,
            term_years,
            now_ms,
        )
        .expect("fixture account-alias renewal quote");
        RenewAliasLease::new(
            iroha_data_model::alias_setup::AliasTargetV1::AccountAlias(resolved_account_alias(
                alias,
                &state_transaction.nexus.dataspace_catalog,
            )),
            record.expires_at_ms,
            quote.expires_at_ms,
            exact_account_alias_quote_guard(state_transaction, &quote),
        )
    }
    const AUTO_RENEW_YEAR_MS: u64 = 31_536_000_000;
    const AUTO_RENEW_EXPIRY_MS: u64 = 1_000_000;
    const AUTO_RENEW_WINDOW_MS: u64 = 10_000;
    const AUTO_RENEW_RETRY_MS: u64 = 1_000;
    #[test]
    fn consensus_auto_renew_validation_rejects_window_as_long_as_term() {
        let mut policy = iroha_data_model::sns::fixtures::default_policy();
        let payment_asset: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("payment asset definition id");
        policy.payment_asset_id = payment_asset.to_string();
        for tier in &mut policy.pricing {
            tier.base_price.asset_id = payment_asset.to_string();
        }
        let config = AliasAutoRenewConfigV1 {
            term_years: 1,
            policy_version: policy.policy_version,
            payment_asset,
            max_amount: Quantity::one(),
            renew_before_expiry_ms: AUTO_RENEW_YEAR_MS,
            retry_backoff_ms: 1,
            max_failures: 1,
        };
        let error = validate_auto_renew_config(&config, &policy)
            .expect_err("the consensus executor must reject a repeated-charge timing window");
        assert!(
            smart_contract_error_contains(&error, "alias.auto_renew.range_invalid"),
            "unexpected error: {error}"
        );
    }
    struct AliasAutoRenewFixture {
        state: State,
        owner: AccountId,
        collector: AccountId,
        payment_asset: AssetDefinitionId,
        target: iroha_data_model::alias_setup::AliasTargetV1,
        selector: iroha_data_model::sns::NameSelectorV1,
    }
    fn next_header_at(state: &State, creation_time_ms: u64) -> BlockHeader {
        let height = u64::try_from(state.view().height())
            .unwrap_or(0)
            .saturating_add(1);
        BlockHeader::new(
            NonZeroU64::new(height).expect("height > 0"),
            state.view().latest_block_hash(),
            None,
            creation_time_ms,
            0,
        )
    }
    fn authenticated_alias_maintenance_state(
        world: World,
        payment_asset: &AssetDefinitionId,
    ) -> State {
        use crate::sumeragi::{
            startup,
            test_chain::{CertifiedTestChain, TestChainConfig},
        };
        let mut config = TestChainConfig::new(world, 0);
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.fees.fee_asset_id = payment_asset.to_string();
        config.nexus = Some(nexus);
        let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
        let consensus_mode = config.consensus_mode;
        let prepared =
            CertifiedTestChain::prepare(config).expect("prepare signed alias maintenance genesis");
        let state = std::sync::Arc::try_unwrap(prepared.state)
            .unwrap_or_else(|_| panic!("unpublished alias maintenance State is unique"));
        startup::apply_genesis(
            &state,
            prepared.genesis.block().clone(),
            &genesis_account,
            consensus_mode.into(),
            None,
        )
        .expect("apply signed alias maintenance genesis");
        state
    }
    fn alias_auto_renew_fixture(
        owner_balance: Quantity,
        max_failures: u32,
    ) -> AliasAutoRenewFixture {
        let owner = owner();
        let collector = another_owner();
        let payment_asset: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("payment asset definition id");
        let genesis_domain =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&collector);
        let leased_domain_id =
            DomainId::try_new("renewable", "universal").expect("leased domain id");
        let leased_domain = Domain::new(leased_domain_id.clone()).build(&owner);
        let owner_account = Account::new(owner.clone()).build(&collector);
        let collector_account = Account::new(collector.clone()).build(&collector);
        let definition = AssetDefinition::numeric(
            payment_asset.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&collector);
        let owner_asset = (!owner_balance.is_zero()).then(|| {
            Asset::new(
                AssetId::of(payment_asset.clone(), owner.clone()),
                owner_balance,
            )
        });
        let mut world = World::with_assets(
            [genesis_domain, leased_domain],
            [owner_account, collector_account],
            [definition],
            owner_asset,
            [],
        );
        seed_default_namespace_policies(&mut world);
        let selector = crate::sns::selector_for_domain(&leased_domain_id).expect("selector");
        let owner_address = AccountAddress::from_account_id(&owner).expect("owner address");
        let record = NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![NameControllerV1::account(&owner_address)],
            0,
            0,
            AUTO_RENEW_EXPIRY_MS,
            AUTO_RENEW_EXPIRY_MS + 30 * 86_400_000,
            AUTO_RENEW_EXPIRY_MS + 90 * 86_400_000,
            Metadata::default(),
        );
        world.smart_contract_state_mut_for_testing().insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
        let state = authenticated_alias_maintenance_state(world, &payment_asset);
        let target = iroha_data_model::alias_setup::AliasTargetV1::Domain(ResolvedDomainV1::new(
            leased_domain_id,
            DataSpaceId::UNIVERSAL,
        ));
        let policy = {
            let view = state.view();
            policy_by_id(view.world(), crate::sns::DOMAIN_NAME_SUFFIX_ID)
                .expect("valid domain policy state")
                .expect("domain policy")
        };
        let config = AliasAutoRenewConfigV1 {
            term_years: 1,
            policy_version: policy.policy_version,
            payment_asset: payment_asset.clone(),
            max_amount: Quantity::one(),
            renew_before_expiry_ms: AUTO_RENEW_WINDOW_MS,
            retry_backoff_ms: AUTO_RENEW_RETRY_MS,
            max_failures,
        };
        {
            let header = next_header_at(&state, 0);
            let mut block = state.block(header);
            let mut transaction = block.transaction();
            crate::sns::persist_alias_auto_renew_state(
                &mut transaction,
                &AliasAutoRenewStateV1::new(target.clone(), owner.clone(), 1, Some(config)),
            )
            .expect("persist auto-renew config");
            transaction.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("auto-renew setup block commits");
        }
        AliasAutoRenewFixture {
            state,
            owner,
            collector,
            payment_asset,
            target,
            selector,
        }
    }
    fn run_alias_auto_renew_maintenance(state: &State, now_ms: u64) {
        let header = next_header_at(state, now_ms);
        // Maintenance consumes the original authenticated genesis policy and
        // actual retained parent, with no synthetic Network transaction.
        let source = iroha_data_model::block::builder::BlockBuilder::new(header)
            .build_with_signature(0, ALICE_KEYPAIR.private_key());
        let (block, _recording, outputs, _) =
            crate::state::run_empty_network_owner_fixture(state, &source);
        assert!(
            outputs.is_empty(),
            "native maintenance must not invent trigger outputs"
        );
        block
            .commit_world_overlay_for_testing()
            .expect("maintenance block commits");
    }
    fn update_domain_policy(
        state: &State,
        update: impl FnOnce(&mut iroha_data_model::sns::SuffixPolicyV1),
    ) {
        let header = next_header_at(state, 1);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        let mut policy = policy_by_id(transaction.world(), crate::sns::DOMAIN_NAME_SUFFIX_ID)
            .expect("valid domain policy state")
            .expect("domain policy");
        update(&mut policy);
        transaction.world.smart_contract_state.insert(
            crate::sns::policy_storage_key(crate::sns::DOMAIN_NAME_SUFFIX_ID),
            norito::codec::Encode::encode(&policy),
        );
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("policy update block commits");
    }
    #[test]
    fn alias_auto_renew_fixture_retains_genesis_identity_and_initial_accounting() {
        let fixture = alias_auto_renew_fixture(Quantity::from(2_u32), 3);
        assert_eq!(fixture.state.committed_height(), 1);
        assert_eq!(fixture.state.kura().blocks_count(), 1);
        let genesis = fixture
            .state
            .kura()
            .get_block(
                std::num::NonZeroUsize::new(1).unwrap(),
                &fixture.state.ivm_execution_budget(),
            )
            .expect("completed original genesis read")
            .unwrap();
        let signed_payload =
            iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(&genesis)
                .unwrap();
        let view = fixture.state.view();
        assert_eq!(
            crate::sumeragi::lanes::routing::committed_root_scope(view.world()),
            Some(signed_payload.sumeragi_context.root_scope)
        );
        assert_eq!(view.latest_block_hash(), Some(genesis.hash()));
        assert_eq!(
            asset_balance_in_world(view.world(), &fixture.payment_asset, &fixture.owner),
            Quantity::from(2_u32)
        );
        assert_eq!(
            asset_balance_in_world(view.world(), &fixture.payment_asset, &fixture.collector),
            Quantity::zero()
        );
        assert_eq!(
            crate::sns::record_by_selector(view.world(), &fixture.selector)
                .unwrap()
                .unwrap()
                .expires_at_ms,
            AUTO_RENEW_EXPIRY_MS
        );
    }
    #[test]
    fn native_auto_renew_suspends_invalid_persisted_timing_without_charge() {
        let fixture = alias_auto_renew_fixture(Quantity::from(2_u32), 3);
        let mut stored = {
            let view = fixture.state.view();
            crate::sns::alias_auto_renew_state(view.world(), &fixture.target)
                .expect("auto-renew state")
                .expect("configured state")
        };
        stored
            .config
            .as_mut()
            .expect("enabled auto-renew config")
            .renew_before_expiry_ms = AUTO_RENEW_YEAR_MS;
        {
            let header = next_header_at(&fixture.state, 1);
            let mut block = fixture.state.block(header);
            let mut transaction = block.transaction();
            crate::sns::persist_alias_auto_renew_state(&mut transaction, &stored)
                .expect("persist invalid-state compatibility fixture");
            transaction.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("invalid-state fixture block commits");
        }
        let owner_before = asset_balance(&fixture.state, &fixture.payment_asset, &fixture.owner);
        run_alias_auto_renew_maintenance(&fixture.state, 2);
        let view = fixture.state.view();
        let stored = crate::sns::alias_auto_renew_state(view.world(), &fixture.target)
            .expect("auto-renew state")
            .expect("configured state");
        assert_eq!(
            stored.suspended_reason.as_deref(),
            Some(crate::sns::ALIAS_AUTO_RENEW_RANGE_INVALID_CODE)
        );
        drop(view);
        assert_eq!(
            asset_balance(&fixture.state, &fixture.payment_asset, &fixture.owner),
            owner_before,
            "invalid persisted timing must suspend before any debit"
        );
    }
    #[test]
    fn sns_configuration_and_time_preserve_consumed_governance_capacity() {
        use crate::state::{
            GovernanceLockCustody, GovernanceLockRecord, GovernanceLocksForReferendum,
            GovernanceReferendumMode, GovernanceReferendumRecord, GovernanceReferendumStatus,
        };
        use iroha_data_model::governance::conviction::{PlainVotingContextV1, PlainVotingResultV1};
        let fixture = alias_auto_renew_fixture(Quantity::from(2_u32), 3);
        let mut retained =
            crate::sns::alias_auto_renew_state(fixture.state.view().world(), &fixture.target)
                .unwrap()
                .unwrap();
        let config = retained.config.take().unwrap();
        let cap = iroha_data_model::parameter::FastpqSourcePolicyV1::bootstrap()
            .mandatory
            .max_retained_obligations;
        {
            let mut setup = fixture.state.block(next_header_at(&fixture.state, 0));
            let mut tx = setup.transaction();
            crate::sns::persist_alias_auto_renew_state(&mut tx, &retained).unwrap();
            for index in 0..cap - 1 {
                let target =
                    iroha_data_model::alias_setup::AliasTargetV1::Domain(ResolvedDomainV1::new(
                        DomainId::try_new(format!("reserved-{index}"), "universal").unwrap(),
                        DataSpaceId::UNIVERSAL,
                    ));
                let record = AliasAutoRenewStateV1::new(
                    target,
                    fixture.owner.clone(),
                    1,
                    Some(config.clone()),
                );
                crate::sns::persist_alias_auto_renew_state(&mut tx, &record).unwrap();
            }
            tx.world.governance_referenda.insert(
                "original-release".into(),
                GovernanceReferendumRecord {
                    h_start: 1,
                    h_end: 10,
                    status: GovernanceReferendumStatus::Open,
                    mode: GovernanceReferendumMode::Zk,
                    plain_context: PlainVotingContextV1::NotApplicable,
                    plain_result: PlainVotingResultV1::NotApplicable,
                },
            );
            tx.world.put_governance_locks(
                "original-release".into(),
                GovernanceLocksForReferendum {
                    locks: std::collections::BTreeMap::from([(
                        fixture.collector.clone(),
                        GovernanceLockRecord {
                            owner: fixture.collector.clone(),
                            amount: Quantity::one(),
                            slashed: Quantity::zero(),
                            expiry_height: 1,
                            direction: 0,
                            duration_blocks: 1,
                            custody: GovernanceLockCustody {
                                escrowed: true,
                                asset_definition_id: fixture.payment_asset.clone(),
                                bond_escrow_account: fixture.owner.clone(),
                                slash_receiver_account: fixture.collector.clone(),
                            },
                        },
                    )]),
                },
            );
            tx.apply();
            setup.commit_world_overlay_for_testing().unwrap();
        }
        let source =
            iroha_data_model::block::builder::BlockBuilder::new(next_header_at(&fixture.state, 1))
                .build_with_signature(0, ALICE_KEYPAIR.private_key());
        let (mut block, _recorder) =
            crate::block::ValidBlock::start_component_execution(&source, &fixture.state).unwrap();
        assert!(
            block
                .world
                .governance_locks
                .get("original-release")
                .is_none()
        );
        let (_, consumed) = block.fastpq_source_usage_for_testing();
        assert_eq!(
            (
                consumed.executed_entries,
                consumed.transcripts,
                consumed.deltas
            ),
            (1, 1, 1)
        );
        assert_eq!(
            asset_balance_in_world(&block.world, &fixture.payment_asset, &fixture.owner),
            Quantity::one()
        );
        assert_eq!(
            asset_balance_in_world(&block.world, &fixture.payment_asset, &fixture.collector),
            Quantity::one()
        );
        let key = crate::sns::alias_auto_renew_storage_key(&fixture.target).unwrap();
        let original = block.world.smart_contract_state.get(&key).unwrap().clone();
        {
            let mut tx = block.transaction();
            ConfigureAliasAutoRenew::new(
                fixture.target.clone(),
                retained.revision,
                Some(config.clone()),
            )
            .execute(&fixture.owner, &mut tx)
            .expect("SNS configurations use the disjoint native maintenance pool");
            assert_ne!(tx.world.smart_contract_state.get(&key), Some(&original));
            assert!(!tx.is_execution_deferred());
            // Dropping this disposable configuration preserves its exact original record.
        }
        assert_eq!(block.fastpq_source_usage_for_testing().1, consumed);
        assert_eq!(
            asset_balance_in_world(&block.world, &fixture.payment_asset, &fixture.collector),
            Quantity::one()
        );
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        block.execute_ordinary_output_plan(&source, None).unwrap();
        // The genuine producer completed Time. A later configuration joins the
        // next bounded native sweep and cannot consume governance reservations.
        {
            let mut tx = block.transaction();
            ConfigureAliasAutoRenew::new(fixture.target.clone(), retained.revision, Some(config))
                .execute(&fixture.owner, &mut tx)
                .unwrap();
            tx.apply();
        }
        assert_eq!(block.fastpq_source_usage_for_testing().1, consumed);
        let configured = crate::sns::alias_auto_renew_state(&block.world, &fixture.target)
            .unwrap()
            .unwrap();
        assert_eq!(configured.revision, retained.revision + 1);
        assert!(configured.config.is_some());
        assert_eq!(
            asset_balance_in_world(&block.world, &fixture.payment_asset, &fixture.owner),
            Quantity::one()
        );
        assert_eq!(
            asset_balance_in_world(&block.world, &fixture.payment_asset, &fixture.collector),
            Quantity::one()
        );
    }

    fn sns_zero_decode_allocation() -> norito::DecodeLimits {
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX)
    }

    #[test]
    fn sns_original_signed_root_readers_preserve_local_decode_refusal_and_retry() {
        let fixture = alias_auto_renew_fixture(Quantity::from(2_u32), 3);
        let view = fixture.state.view();
        let config = crate::sns::alias_auto_renew_state(view.world(), &fixture.target)
            .unwrap()
            .unwrap();
        let record = crate::sns::record_by_selector(view.world(), &fixture.selector)
            .unwrap()
            .unwrap();
        let policy = crate::sns::policy_by_id(view.world(), fixture.selector.suffix_id)
            .unwrap()
            .unwrap();
        for reader in 0..3 {
            let error = norito::with_decode_limits_scope(sns_zero_decode_allocation(), || {
                match reader {
                    0 => crate::sns::alias_auto_renew_state(view.world(), &fixture.target)
                        .map(|_| ()),
                    1 => {
                        crate::sns::record_by_selector(view.world(), &fixture.selector).map(|_| ())
                    }
                    _ => crate::sns::policy_by_id(view.world(), fixture.selector.suffix_id)
                        .map(|_| ()),
                }
                .unwrap_err()
            });
            assert!(
                matches!(error, crate::sns::SnsError::Deferred(_)),
                "reader {reader}: {error}"
            );
            assert!(matches!(
                error.into_attempt_error::<()>(|_| panic!(
                    "local refusal is not a completed verdict"
                )),
                crate::execution_attempt::ExecutionAttemptError::Deferred(_)
            ));
        }
        assert_eq!(
            crate::sns::alias_auto_renew_state(view.world(), &fixture.target)
                .unwrap()
                .unwrap(),
            config
        );
        assert_eq!(
            crate::sns::record_by_selector(view.world(), &fixture.selector)
                .unwrap()
                .unwrap(),
            record
        );
        assert_eq!(
            crate::sns::policy_by_id(view.world(), fixture.selector.suffix_id)
                .unwrap()
                .unwrap(),
            policy
        );
        drop(view);
        let mut block = fixture.state.block(next_header_at(&fixture.state, 1));
        let mut tx = block.transaction();
        tx.world.smart_contract_state.insert(
            crate::sns::record_storage_key(&fixture.selector),
            vec![0xff],
        );
        let malformed = crate::sns::record_by_selector(tx.world(), &fixture.selector).unwrap_err();
        assert!(
            malformed.deferral().is_none(),
            "malformed authoritative bytes remain terminal"
        );
    }

    #[test]
    fn sns_configure_decode_refusal_latches_original_state_and_same_instruction_retries() {
        let fixture = alias_auto_renew_fixture(Quantity::from(2_u32), 3);
        let original =
            crate::sns::alias_auto_renew_state(fixture.state.view().world(), &fixture.target)
                .unwrap()
                .unwrap();
        let command = ConfigureAliasAutoRenew::new(
            fixture.target.clone(),
            original.revision,
            original.config.clone(),
        );
        let source =
            iroha_data_model::block::builder::BlockBuilder::new(next_header_at(&fixture.state, 1))
                .build_with_signature(0, ALICE_KEYPAIR.private_key());
        {
            let (mut block, _recorder) =
                crate::block::ValidBlock::start_component_execution(&source, &fixture.state)
                    .unwrap();
            let mut tx = block.transaction();
            norito::with_decode_limits_scope(sns_zero_decode_allocation(), || {
                command.clone().execute(&fixture.owner, &mut tx)
            })
            .unwrap_err();
            assert!(tx.is_execution_deferred());
            assert_eq!(
                crate::sns::alias_auto_renew_state(tx.world(), &fixture.target)
                    .unwrap()
                    .unwrap(),
                original
            );
            tx.apply();
            assert!(
                block.reserve_ordinary_execution_outputs(&source).is_err(),
                "a deferred transaction cannot publish"
            );
        }
        assert_eq!(
            crate::sns::alias_auto_renew_state(fixture.state.view().world(), &fixture.target)
                .unwrap()
                .unwrap(),
            original
        );
        let mut block = fixture.state.block(next_header_at(&fixture.state, 1));
        let mut tx = block.transaction();
        command.execute(&fixture.owner, &mut tx).unwrap();
        assert!(!tx.is_execution_deferred());
        tx.apply();
        let after = crate::sns::alias_auto_renew_state(&block.world, &fixture.target)
            .unwrap()
            .unwrap();
        assert_eq!(after.revision, original.revision + 1);
        assert_eq!(after.config, original.config);
        assert_eq!(
            asset_balance_in_world(&block.world, &fixture.payment_asset, &fixture.owner),
            Quantity::from(2_u32)
        );
        assert_eq!(
            asset_balance_in_world(&block.world, &fixture.payment_asset, &fixture.collector),
            Quantity::zero()
        );
    }

    #[test]
    fn sns_time_decode_refusal_cannot_publish_failure_counter_or_debit_before_retry() {
        let fixture = alias_auto_renew_fixture(Quantity::from(2_u32), 3);
        let original =
            crate::sns::alias_auto_renew_state(fixture.state.view().world(), &fixture.target)
                .unwrap()
                .unwrap();
        let now = AUTO_RENEW_EXPIRY_MS - AUTO_RENEW_WINDOW_MS;
        let source = iroha_data_model::block::builder::BlockBuilder::new(next_header_at(
            &fixture.state,
            now,
        ))
        .build_with_signature(0, ALICE_KEYPAIR.private_key());
        {
            let (mut block, _recorder) =
                crate::block::ValidBlock::start_component_execution(&source, &fixture.state)
                    .unwrap();
            block.reserve_ordinary_execution_outputs(&source).unwrap();
            let error = norito::with_decode_limits_scope(sns_zero_decode_allocation(), || {
                block.execute_ordinary_output_plan(&source, None)
            })
            .unwrap_err();
            assert!(
                matches!(
                    error,
                    crate::state::ExecutionOutputAttemptError::Deferred(_)
                ),
                "{error}"
            );
            assert!(block.retained_execution_outputs_for_test().is_err());
            assert_eq!(
                crate::sns::alias_auto_renew_state(&block.world, &fixture.target)
                    .unwrap()
                    .unwrap(),
                original
            );
            assert_eq!(
                asset_balance_in_world(&block.world, &fixture.payment_asset, &fixture.owner),
                Quantity::from(2_u32)
            );
            assert_eq!(
                asset_balance_in_world(&block.world, &fixture.payment_asset, &fixture.collector),
                Quantity::zero()
            );
        }
        assert_eq!(
            crate::sns::alias_auto_renew_state(fixture.state.view().world(), &fixture.target)
                .unwrap()
                .unwrap(),
            original
        );
        run_alias_auto_renew_maintenance(&fixture.state, now);
        let view = fixture.state.view();
        let after = crate::sns::alias_auto_renew_state(view.world(), &fixture.target)
            .unwrap()
            .unwrap();
        assert_eq!(after.revision, original.revision + 1);
        assert_eq!(after.failure_count, 0);
        assert_eq!(after.next_retry_at_ms, None);
        assert_eq!(after.suspended_reason, None);
        assert_eq!(
            crate::sns::record_by_selector(view.world(), &fixture.selector)
                .unwrap()
                .unwrap()
                .expires_at_ms,
            AUTO_RENEW_EXPIRY_MS + AUTO_RENEW_YEAR_MS
        );
        assert_eq!(
            asset_balance_in_world(view.world(), &fixture.payment_asset, &fixture.owner),
            "1.5".parse().unwrap()
        );
        assert_eq!(
            asset_balance_in_world(view.world(), &fixture.payment_asset, &fixture.collector),
            "0.5".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn native_auto_renew_debits_exact_owner_quote_once() {
        // Preserve the native retry reason if the exact debit oracle fails.
        let _logger = iroha_logger::test_logger();
        let fixture = alias_auto_renew_fixture(Quantity::from(2_u32), 3);
        let owner_before = asset_balance(&fixture.state, &fixture.payment_asset, &fixture.owner);
        let collector_before =
            asset_balance(&fixture.state, &fixture.payment_asset, &fixture.collector);
        run_alias_auto_renew_maintenance(
            &fixture.state,
            AUTO_RENEW_EXPIRY_MS - AUTO_RENEW_WINDOW_MS,
        );
        let view = fixture.state.view();
        let record = crate::sns::record_by_selector(view.world(), &fixture.selector)
            .expect("valid renewed record state")
            .expect("renewed record");
        assert_eq!(
            record.expires_at_ms,
            AUTO_RENEW_EXPIRY_MS + AUTO_RENEW_YEAR_MS
        );
        let state = crate::sns::alias_auto_renew_state(view.world(), &fixture.target)
            .expect("auto-renew state")
            .expect("configured state");
        assert_eq!(state.revision, 2);
        assert_eq!(state.failure_count, 0);
        assert_eq!(state.next_retry_at_ms, None);
        assert_eq!(state.suspended_reason, None);
        drop(view);
        let owner_after = asset_balance(&fixture.state, &fixture.payment_asset, &fixture.owner);
        let collector_after =
            asset_balance(&fixture.state, &fixture.payment_asset, &fixture.collector);
        let exact_quote: Quantity = "0.5".parse().expect("exact quote");
        assert_eq!(
            owner_after,
            owner_before.checked_sub(&exact_quote).expect("owner debit")
        );
        assert_eq!(
            collector_after,
            collector_before
                .checked_add(&exact_quote)
                .expect("collector credit")
        );
        run_alias_auto_renew_maintenance(
            &fixture.state,
            AUTO_RENEW_EXPIRY_MS - AUTO_RENEW_WINDOW_MS + 1,
        );
        assert_eq!(
            asset_balance(&fixture.state, &fixture.payment_asset, &fixture.owner),
            owner_after,
            "a renewed lease is no longer due and cannot be charged twice"
        );
    }
    #[test]
    fn native_auto_renew_retries_insufficient_funds_then_suspends() {
        let fixture = alias_auto_renew_fixture(Quantity::zero(), 2);
        let first_attempt_ms = AUTO_RENEW_EXPIRY_MS - AUTO_RENEW_WINDOW_MS;
        run_alias_auto_renew_maintenance(&fixture.state, first_attempt_ms);
        {
            let view = fixture.state.view();
            let state = crate::sns::alias_auto_renew_state(view.world(), &fixture.target)
                .expect("auto-renew state")
                .expect("configured state");
            assert_eq!(state.revision, 2);
            assert_eq!(state.failure_count, 1);
            assert_eq!(
                state.next_retry_at_ms,
                Some(first_attempt_ms + AUTO_RENEW_RETRY_MS)
            );
            assert_eq!(state.suspended_reason, None);
        }
        run_alias_auto_renew_maintenance(
            &fixture.state,
            first_attempt_ms + AUTO_RENEW_RETRY_MS - 1,
        );
        {
            let view = fixture.state.view();
            let state = crate::sns::alias_auto_renew_state(view.world(), &fixture.target)
                .expect("auto-renew state")
                .expect("configured state");
            assert_eq!(state.revision, 2, "retry backoff must be honored");
            assert_eq!(state.failure_count, 1);
        }
        run_alias_auto_renew_maintenance(&fixture.state, first_attempt_ms + AUTO_RENEW_RETRY_MS);
        let view = fixture.state.view();
        let state = crate::sns::alias_auto_renew_state(view.world(), &fixture.target)
            .expect("auto-renew state")
            .expect("configured state");
        assert_eq!(state.revision, 3);
        assert_eq!(state.failure_count, 2);
        assert_eq!(state.next_retry_at_ms, None);
        assert_eq!(
            state.suspended_reason.as_deref(),
            Some(crate::sns::ALIAS_AUTO_RENEW_FAILURES_EXHAUSTED_CODE)
        );
        assert_eq!(
            crate::sns::record_by_selector(view.world(), &fixture.selector)
                .expect("valid unchanged record state")
                .expect("unchanged record")
                .expires_at_ms,
            AUTO_RENEW_EXPIRY_MS
        );
    }
    #[test]
    fn native_auto_renew_suspends_immediately_on_policy_or_asset_drift() {
        for asset_drift in [false, true] {
            let fixture = alias_auto_renew_fixture(Quantity::from(2_u32), 3);
            update_domain_policy(&fixture.state, |policy| {
                if asset_drift {
                    let other_asset: AssetDefinitionId = "61CtjvNd9T3THAR65GsMVHr82Bjc"
                        .parse()
                        .expect("other asset definition id");
                    policy.payment_asset_id = other_asset.to_string();
                    for tier in &mut policy.pricing {
                        tier.base_price.asset_id = other_asset.to_string();
                    }
                } else {
                    policy.policy_version = policy.policy_version.saturating_add(1);
                }
            });
            let owner_before =
                asset_balance(&fixture.state, &fixture.payment_asset, &fixture.owner);
            run_alias_auto_renew_maintenance(
                &fixture.state,
                AUTO_RENEW_EXPIRY_MS - AUTO_RENEW_WINDOW_MS,
            );
            let view = fixture.state.view();
            let state = crate::sns::alias_auto_renew_state(view.world(), &fixture.target)
                .expect("auto-renew state")
                .expect("configured state");
            let expected = if asset_drift {
                crate::sns::ALIAS_AUTO_RENEW_ASSET_DRIFT_CODE
            } else {
                crate::sns::ALIAS_AUTO_RENEW_POLICY_DRIFT_CODE
            };
            assert_eq!(state.revision, 2);
            assert_eq!(state.suspended_reason.as_deref(), Some(expected));
            assert_eq!(
                crate::sns::record_by_selector(view.world(), &fixture.selector)
                    .expect("valid unchanged record state")
                    .expect("unchanged record")
                    .expires_at_ms,
                AUTO_RENEW_EXPIRY_MS
            );
            drop(view);
            assert_eq!(
                asset_balance(&fixture.state, &fixture.payment_asset, &fixture.owner),
                owner_before
            );
        }
    }
    #[test]
    fn ensure_alias_repair_rejects_unrelated_transaction_authority() {
        let resource_owner = owner();
        let authority = another_owner();
        let owner_account = Account::new(resource_owner.clone()).build(&resource_owner);
        let authority_account = Account::new(authority.clone()).build(&resource_owner);
        let mut world = World::with([], [owner_account, authority_account], []);
        let alias = ResolvedAccountAliasV1::new(
            "merchant@universal"
                .parse::<AccountAliasName>()
                .expect("canonical account alias"),
            DataSpaceId::UNIVERSAL,
        );
        let intent = AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: alias.clone(),
            target_account: resource_owner.clone(),
            provision: AccountProvisionV1::Existing,
            role: AccountAliasRoleV1::Additional,
        });
        let selector = crate::alias_setup::selector_for_resolved_alias_target(&intent.target())
            .expect("resolved selector");
        let address = AccountAddress::from_account_id(&resource_owner).expect("owner address");
        let record = NameRecordV1::new(
            selector.clone(),
            resource_owner.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        world.smart_contract_state_mut_for_testing().insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
        seed_active_dataspace_lease(
            &mut world,
            "universal",
            DataSpaceId::UNIVERSAL,
            &resource_owner,
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let ensure = EnsureAlias::new(
            intent,
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: 0,
                expected_payment_asset:
                    iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                        .parse()
                        .expect("payment asset definition id"),
                max_amount: Quantity::zero(),
                valid_until_ms: 0,
            },
        );
        let mut block = state.block(next_header(&state));
        let mut transaction = block.transaction();
        let error = ensure
            .execute(&authority, &mut transaction)
            .expect_err("an unrelated authority must not repair another owner's alias");
        assert!(
            smart_contract_error_contains(&error, "alias.setup.authority_forbidden"),
            "unexpected error: {error}"
        );
        assert!(
            transaction
                .world
                .account_aliases
                .get(&alias.account_alias())
                .is_none(),
            "authorization failure must not repair the alias binding"
        );
    }
    #[test]
    fn ensure_alias_rejects_absent_endorsement_required_domain_before_charge() {
        let collector = owner();
        let authority = another_owner();
        let payment_asset: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("payment asset definition id");
        let genesis_domain =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&collector);
        let authority_account = Account::new(authority.clone()).build(&collector);
        let collector_account = Account::new(collector.clone()).build(&collector);
        let payment_definition = AssetDefinition::numeric(
            payment_asset.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&collector);
        let payer_asset = Asset::new(
            AssetId::of(payment_asset.clone(), authority.clone()),
            Quantity::from(1_000_u64),
        );
        let mut world = World::with_assets(
            [genesis_domain],
            [authority_account, collector_account],
            [payment_definition],
            [payer_asset],
            [],
        );
        seed_default_namespace_policies(&mut world);
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        configure_test_fee_asset(&state, &payment_asset);
        {
            let mut nexus = state.nexus.write();
            nexus.endorsement.quorum = 1;
        }
        let domain_id = DomainId::try_new("protected", "universal").expect("protected domain id");
        let intent = AliasIntentV1::Domain(AliasDomainIntentV1 {
            domain: ResolvedDomainV1::new(domain_id.clone(), DataSpaceId::UNIVERSAL),
            owner: authority.clone(),
        });
        let selector = crate::alias_setup::selector_for_resolved_alias_target(&intent.target())
            .expect("protected domain selector");
        let mut block = state.block(next_header(&state));
        let mut transaction = block.transaction();
        seed_test_call_hash(&mut transaction, 0xC1);
        let quote = crate::sns::quote_resolved_name_registration(
            transaction.world(),
            selector.clone(),
            &authority,
            1,
            None,
            transaction.block_unix_timestamp_ms(),
        )
        .expect("exact protected-domain quote");
        let ensure = EnsureAlias::new(
            intent,
            AliasLeaseAcquisitionV1::new(1, None),
            exact_alias_quote_guard(&transaction, DOMAIN_NAME_SUFFIX_ID, &quote),
        );
        let payer_before = asset_balance_in_world(transaction.world(), &payment_asset, &authority);
        let collector_before =
            asset_balance_in_world(transaction.world(), &payment_asset, &collector);
        let error = ensure
            .execute(&authority, &mut transaction)
            .expect_err("endorsement-free setup must fail before acquisition");
        assert!(
            smart_contract_error_contains(&error, "alias.domain.endorsement_required"),
            "unexpected error: {error}"
        );
        assert_eq!(
            asset_balance_in_world(transaction.world(), &payment_asset, &authority),
            payer_before,
            "endorsement classification must run before any lease debit"
        );
        assert_eq!(
            asset_balance_in_world(transaction.world(), &payment_asset, &collector),
            collector_before,
            "endorsement classification must run before any collector credit"
        );
        assert!(
            transaction.world().domains().get(&domain_id).is_none(),
            "blocked setup must not create the domain"
        );
        assert!(
            crate::sns::record_by_selector(transaction.world(), &selector)
                .expect("valid SNS record state")
                .is_none(),
            "blocked setup must not acquire the domain lease"
        );
    }
    #[test]
    fn ensure_alias_create_rejects_every_stale_quote_guard_before_charge() {
        let collector = owner();
        let authority = another_owner();
        let payment_asset: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("payment asset definition id");
        let other_asset: AssetDefinitionId = "61CtjvNd9T3THAR65GsMVHr82Bjc"
            .parse()
            .expect("different payment asset definition id");
        let genesis_domain =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&collector);
        let authority_account = Account::new(authority.clone()).build(&collector);
        let collector_account = Account::new(collector.clone()).build(&collector);
        let payment_definition = AssetDefinition::numeric(
            payment_asset.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&collector);
        let payer_asset = Asset::new(
            AssetId::of(payment_asset.clone(), authority.clone()),
            Quantity::from(1_000_u64),
        );
        let mut world = World::with_assets(
            [genesis_domain],
            [authority_account, collector_account],
            [payment_definition],
            [payer_asset],
            [],
        );
        seed_default_namespace_policies(&mut world);
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        configure_test_fee_asset(&state, &payment_asset);
        let alias =
            AccountAlias::domainless("guarded".parse().expect("label"), DataSpaceId::UNIVERSAL);
        let resolved = resolved_account_alias(&alias, &state.nexus.read().dataspace_catalog);
        let selector = crate::alias_setup::selector_for_resolved_alias_target(
            &AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
                alias: resolved,
                target_account: authority.clone(),
                provision: AccountProvisionV1::Existing,
                role: AccountAliasRoleV1::Additional,
            })
            .target(),
        )
        .expect("guarded account-alias selector");
        for (case, expected_code) in [
            ("deadline", "alias.quote.expired"),
            ("asset", "alias.quote.payment_asset_mismatch"),
            ("cap", "alias.quote.cap_exceeded"),
            ("policy", "alias.quote.policy_version_mismatch"),
        ] {
            let mut block = state.block(next_header_at(&state, 10));
            let mut transaction = block.transaction();
            seed_test_call_hash(&mut transaction, 0xC6);
            let mut ensure = ensure_account_alias_instruction(
                &transaction,
                &alias,
                authority.clone(),
                AccountProvisionV1::Existing,
                AccountAliasRoleV1::Additional,
                1,
                None,
            );
            match case {
                "deadline" => ensure.quote_guard.valid_until_ms = 9,
                "asset" => ensure.quote_guard.expected_payment_asset = other_asset.clone(),
                "cap" => ensure.quote_guard.max_amount = Quantity::zero(),
                "policy" => {
                    ensure.quote_guard.expected_policy_version =
                        ensure.quote_guard.expected_policy_version.saturating_add(1);
                }
                _ => unreachable!("all quote-guard cases are enumerated"),
            }
            let payer_before =
                asset_balance_in_world(transaction.world(), &payment_asset, &authority);
            let collector_before =
                asset_balance_in_world(transaction.world(), &payment_asset, &collector);
            let error = ensure
                .execute(&authority, &mut transaction)
                .expect_err("stale create guard must fail");
            assert!(
                smart_contract_error_contains(&error, expected_code),
                "unexpected {case} guard error: {error}"
            );
            assert_eq!(
                asset_balance_in_world(transaction.world(), &payment_asset, &authority),
                payer_before,
                "{case} guard failure must precede any payer debit"
            );
            assert_eq!(
                asset_balance_in_world(transaction.world(), &payment_asset, &collector),
                collector_before,
                "{case} guard failure must precede any collector credit"
            );
            assert!(
                crate::sns::record_by_selector(transaction.world(), &selector)
                    .expect("valid SNS record state")
                    .is_none(),
                "{case} guard failure must not acquire the lease"
            );
            assert!(
                transaction.world().account_aliases().get(&alias).is_none(),
                "{case} guard failure must not create the alias binding"
            );
        }
    }
    #[test]
    fn ensure_alias_later_conflict_rolls_back_earlier_alias_indexes_and_charge() {
        let authority = another_owner();
        let collector = owner();
        let conflict_owner = {
            let keypair = KeyPair::try_from_seed(vec![0x43; 32], Algorithm::Ed25519)
                .expect("fixture seed must derive a valid keypair");
            AccountId::new(keypair.public_key().clone())
        };
        let payment_asset: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("payment asset definition id");
        let genesis_domain =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&collector);
        let authority_account = Account::new(authority.clone()).build(&collector);
        let collector_account = Account::new(collector.clone()).build(&collector);
        let conflict_account = Account::new(conflict_owner.clone()).build(&collector);
        let payment_definition = AssetDefinition::numeric(
            payment_asset.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&collector);
        let payer_asset = Asset::new(
            AssetId::of(payment_asset.clone(), authority.clone()),
            Quantity::from(100_u32),
        );
        let mut world = World::with_assets(
            [genesis_domain],
            [authority_account, collector_account, conflict_account],
            [payment_definition],
            [payer_asset],
            [],
        );
        seed_default_namespace_policies(&mut world);
        let parent_intent = AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: ResolvedDataSpaceV1::new(
                "universal".parse().expect("canonical dataspace name"),
                DataSpaceId::UNIVERSAL,
            ),
            owner: collector.clone(),
        });
        let parent_target = parent_intent.target();
        let parent_selector =
            crate::alias_setup::selector_for_resolved_alias_target(&parent_target)
                .expect("parent selector");
        let parent_address =
            AccountAddress::from_account_id(&collector).expect("collector address");
        let parent_record = NameRecordV1::new(
            parent_selector.clone(),
            collector.clone(),
            vec![NameControllerV1::account(&parent_address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            crate::alias_setup::alias_registration_metadata(&parent_target)
                .expect("parent metadata"),
        );
        world.smart_contract_state_mut_for_testing().insert(
            crate::sns::record_storage_key(&parent_selector),
            norito::codec::Encode::encode(&parent_record),
        );
        let first_alias = ResolvedAccountAliasV1::new(
            "merchant@universal"
                .parse::<AccountAliasName>()
                .expect("canonical first account alias"),
            DataSpaceId::UNIVERSAL,
        );
        let first_intent = AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: first_alias.clone(),
            target_account: authority.clone(),
            provision: AccountProvisionV1::Existing,
            role: AccountAliasRoleV1::Additional,
        });
        let first_selector =
            crate::alias_setup::selector_for_resolved_alias_target(&first_intent.target())
                .expect("first alias selector");
        let conflicting_alias = ResolvedAccountAliasV1::new(
            "occupied@universal"
                .parse::<AccountAliasName>()
                .expect("canonical conflicting account alias"),
            DataSpaceId::UNIVERSAL,
        );
        let conflicting_intent = AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: conflicting_alias,
            target_account: authority.clone(),
            provision: AccountProvisionV1::Existing,
            role: AccountAliasRoleV1::Additional,
        });
        let conflicting_target = conflicting_intent.target();
        let conflicting_selector =
            crate::alias_setup::selector_for_resolved_alias_target(&conflicting_target)
                .expect("conflicting alias selector");
        let conflict_address =
            AccountAddress::from_account_id(&conflict_owner).expect("conflict owner address");
        let conflicting_record = NameRecordV1::new(
            conflicting_selector.clone(),
            conflict_owner,
            vec![NameControllerV1::account(&conflict_address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            crate::alias_setup::alias_registration_metadata(&conflicting_target)
                .expect("conflicting alias metadata"),
        );
        world.smart_contract_state_mut_for_testing().insert(
            crate::sns::record_storage_key(&conflicting_selector),
            norito::codec::Encode::encode(&conflicting_record),
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        configure_test_fee_asset(&state, &payment_asset);
        let (quote, policy) = {
            let view = state.view();
            let quote = crate::sns::quote_resolved_name_registration(
                view.world(),
                first_selector.clone(),
                &authority,
                1,
                None,
                0,
            )
            .expect("first alias quote");
            let policy = policy_by_id(view.world(), ACCOUNT_ALIAS_SUFFIX_ID)
                .expect("valid account-alias policy state")
                .expect("account-alias policy");
            (quote, policy)
        };
        assert_eq!(quote.collector_account, collector);
        let first_ensure = EnsureAlias::new(
            first_intent,
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: policy.policy_version,
                expected_payment_asset: payment_asset.clone(),
                max_amount: quote.charge_amount.clone(),
                valid_until_ms: 1_000,
            },
        );
        let conflicting_ensure = EnsureAlias::new(
            conflicting_intent,
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: policy.policy_version,
                expected_payment_asset: payment_asset.clone(),
                max_amount: Quantity::zero(),
                valid_until_ms: 0,
            },
        );
        let payer_before = asset_balance(&state, &payment_asset, &authority);
        let collector_before = asset_balance(&state, &payment_asset, &collector);
        let first_alias_key = first_alias.account_alias();
        let mut block = state.block(next_header(&state));
        let mut transaction =
            block.transaction_for_fastpq_testing(Hash::prehashed([0x44; Hash::LENGTH]));
        seed_test_call_hash(&mut transaction, 0x44);
        first_ensure
            .execute(&authority, &mut transaction)
            .expect("the first ordered EnsureAlias must stage successfully");
        assert!(
            crate::sns::record_by_selector(transaction.world(), &first_selector)
                .expect("valid staged SNS record state")
                .is_some(),
            "the first instruction must stage its lease record before the later conflict"
        );
        assert_eq!(
            transaction.world().account_aliases().get(&first_alias_key),
            Some(&authority),
            "the first instruction must stage the forward alias index"
        );
        assert!(
            transaction
                .world()
                .account_aliases_by_account()
                .get(&authority)
                .is_some_and(|aliases| aliases.contains(&first_alias_key)),
            "the first instruction must stage the reverse alias index"
        );
        assert_eq!(
            asset_balance_in_world(transaction.world(), &payment_asset, &authority),
            payer_before
                .try_sub(&quote.charge_amount)
                .expect("funded payer covers the first quote"),
            "the first instruction must stage the exact payer debit"
        );
        assert_eq!(
            asset_balance_in_world(transaction.world(), &payment_asset, &collector),
            collector_before
                .try_add(&quote.charge_amount)
                .expect("collector balance accepts the first quote"),
            "the first instruction must stage the exact collector credit"
        );
        let error = conflicting_ensure
            .execute(&authority, &mut transaction)
            .expect_err("the later owner conflict must reject the ordered setup transaction");
        let InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) = &error
        else {
            panic!("unexpected later conflict shape: {error:?}");
        };
        assert!(
            message.contains("alias.owner.conflict"),
            "unexpected later conflict: {error:?}"
        );
        drop(transaction);
        drop(block);
        let view = state.view();
        assert!(
            crate::sns::record_by_selector(view.world(), &first_selector)
                .expect("valid rolled-back SNS record state")
                .is_none(),
            "a rejected transaction must not retain the earlier alias lease"
        );
        assert!(
            view.world()
                .account_aliases()
                .get(&first_alias_key)
                .is_none(),
            "a rejected transaction must not retain the earlier forward alias index"
        );
        assert!(
            !view
                .world()
                .account_aliases_by_account()
                .get(&authority)
                .is_some_and(|aliases| aliases.contains(&first_alias_key)),
            "a rejected transaction must not retain the earlier reverse alias index"
        );
        assert_eq!(
            asset_balance_in_world(view.world(), &payment_asset, &authority),
            payer_before,
            "a rejected transaction must roll back the earlier payer debit"
        );
        assert_eq!(
            asset_balance_in_world(view.world(), &payment_asset, &collector),
            collector_before,
            "a rejected transaction must roll back the earlier collector credit"
        );
    }
    #[test]
    fn ensure_alias_charges_once_and_repairs_with_a_stale_guard_for_free() {
        let authority = owner();
        let collector = another_owner();
        let target_account = {
            let keypair = KeyPair::try_from_seed(vec![0x43; 32], Algorithm::Ed25519)
                .expect("fixture seed must derive a valid keypair");
            AccountId::new(keypair.public_key().clone())
        };
        let payment_asset: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("payment asset definition id");
        let genesis_domain =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&collector);
        let authority_account = Account::new(authority.clone()).build(&collector);
        let collector_account = Account::new(collector.clone()).build(&collector);
        let payment_definition = AssetDefinition::numeric(
            payment_asset.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&authority);
        let mut world = World::with(
            [genesis_domain],
            [authority_account, collector_account],
            [payment_definition],
        );
        seed_default_namespace_policies(&mut world);
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        configure_test_fee_asset(&state, &payment_asset);
        {
            let mut block = state.block(next_header(&state));
            let mut transaction = block.transaction();
            Mint::asset_quantity(
                100_u64,
                AssetId::of(payment_asset.clone(), authority.clone()),
            )
            .execute(&authority, &mut transaction)
            .expect("fund alias lease payer");
            transaction.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("funding block commits");
        }
        let dataspace_name = "paynet".parse().expect("canonical dataspace name");
        let dataspace_id =
            crate::sns::dataspace_id_for_sns_alias("paynet").expect("deterministic dataspace id");
        let parent_intent = AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: ResolvedDataSpaceV1::new(dataspace_name, dataspace_id),
            owner: authority.clone(),
        });
        let alias = ResolvedAccountAliasV1::new(
            "merchant@paynet"
                .parse::<AccountAliasName>()
                .expect("canonical account alias"),
            dataspace_id,
        );
        let intent = AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: alias.clone(),
            target_account: target_account.clone(),
            provision: AccountProvisionV1::Create,
            role: AccountAliasRoleV1::Primary,
        });
        let (parent_quote, parent_policy, quote, policy) = {
            let view = state.view();
            let parent_selector =
                crate::alias_setup::selector_for_resolved_alias_target(&parent_intent.target())
                    .expect("resolved parent selector");
            let parent_quote = crate::sns::quote_resolved_name_registration(
                view.world(),
                parent_selector,
                &authority,
                1,
                None,
                0,
            )
            .expect("exact parent registration quote");
            let selector = crate::alias_setup::selector_for_resolved_alias_target(&intent.target())
                .expect("resolved alias selector");
            let quote = crate::sns::quote_resolved_name_registration(
                view.world(),
                selector,
                &target_account,
                1,
                None,
                0,
            )
            .expect("exact registration quote");
            let policy = policy_by_id(view.world(), ACCOUNT_ALIAS_SUFFIX_ID)
                .expect("valid account-alias policy state")
                .expect("account-alias policy");
            let parent_policy = policy_by_id(view.world(), DATASPACE_ALIAS_SUFFIX_ID)
                .expect("valid dataspace-alias policy state")
                .expect("dataspace-alias policy");
            (parent_quote, parent_policy, quote, policy)
        };
        let ensure_parent = EnsureAlias::new(
            parent_intent,
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: parent_policy.policy_version,
                expected_payment_asset: payment_asset.clone(),
                max_amount: parent_quote.charge_amount.clone(),
                valid_until_ms: 1_000,
            },
        );
        let ensure = EnsureAlias::new(
            intent.clone(),
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: policy.policy_version,
                expected_payment_asset: payment_asset.clone(),
                max_amount: quote.charge_amount.clone(),
                valid_until_ms: 1_000,
            },
        );
        let payer_before = asset_balance(&state, &payment_asset, &authority);
        {
            let mut block = state.block(next_header(&state));
            let mut transaction =
                block.transaction_for_fastpq_testing(Hash::prehashed([0xC9; Hash::LENGTH]));
            seed_test_call_hash(&mut transaction, 0xC9);
            ensure_parent
                .clone()
                .execute(&authority, &mut transaction)
                .expect("create parent dataspace alias first");
            ensure
                .clone()
                .execute(&authority, &mut transaction)
                .expect("create account alias and dependencies");
            ensure_parent
                .execute(&authority, &mut transaction)
                .expect("exact parent replay is a no-op in the same transaction");
            ensure
                .execute(&authority, &mut transaction)
                .expect("exact replay is a no-op in the same transaction");
            transaction.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("atomic alias setup commits");
        }
        let payer_after_create = asset_balance(&state, &payment_asset, &authority);
        let exact_total = parent_quote
            .charge_amount
            .try_add(&quote.charge_amount)
            .expect("alias quote total fits");
        assert_eq!(
            payer_after_create,
            payer_before
                .try_sub(&exact_total)
                .expect("funded payer covers exact quote"),
            "ordered parent/child creation plus exact replay must charge each authoritative quote once"
        );
        {
            let view = state.view();
            assert!(view.world().accounts().get(&target_account).is_some());
            assert_eq!(
                view.world().account_aliases().get(&alias.account_alias()),
                Some(&target_account)
            );
            assert_eq!(
                view.world()
                    .account(&target_account)
                    .expect("provisioned account")
                    .label(),
                Some(&alias.account_alias())
            );
            for permission in crate::alias_setup::exact_alias_permission_bundle(&intent) {
                assert!(
                    view.world()
                        .account_contains_inherent_permission(&target_account, &permission),
                    "setup must grant the exact owner permission bundle"
                );
            }
        }
        let missing_permission =
            crate::alias_setup::exact_alias_permission_bundle(&intent)[0].clone();
        {
            let mut block = state.block(next_header_at(&state, 10));
            let mut transaction = block.transaction();
            let mut permissions = transaction
                .world
                .account_permissions
                .view()
                .get(&target_account)
                .cloned()
                .expect("automatic owner permissions");
            assert!(permissions.remove(&missing_permission));
            transaction
                .world
                .account_permissions
                .insert(target_account.clone(), permissions);
            transaction.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("derived-state damage commits");
        }
        let payer_before_repair = asset_balance(&state, &payment_asset, &authority);
        let stale_guard_repair = EnsureAlias::new(
            intent,
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: policy.policy_version.saturating_add(1),
                expected_payment_asset: payment_asset.clone(),
                max_amount: Quantity::zero(),
                valid_until_ms: 0,
            },
        );
        {
            let mut block = state.block(next_header_at(&state, 11));
            let mut transaction = block.transaction();
            stale_guard_repair
                .execute(&authority, &mut transaction)
                .expect("repair classification must precede stale quote validation");
            transaction.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("free repair block commits");
        }
        assert_eq!(
            asset_balance(&state, &payment_asset, &authority),
            payer_before_repair,
            "repair must never charge a lease"
        );
        let view = state.view();
        assert!(
            view.world()
                .account_contains_inherent_permission(&target_account, &missing_permission),
            "repair must restore the exact missing owner permission"
        );
    }
    #[test]
    fn find_dataspace_name_owner_by_id_returns_active_owner() {
        let mut state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        state.set_dataspace_catalog_for_testing(
            DataSpaceCatalog::new(vec![
                DataSpaceMetadata::default(),
                DataSpaceMetadata {
                    id: DataSpaceId::new(9),
                    alias: "trade".to_owned(),
                    description: None,
                    fault_tolerance: 1,
                },
            ])
            .expect("catalog"),
        );
        let owner = owner();
        let selector =
            seed_active_dataspace_lease(&mut state.world, "trade", DataSpaceId::new(9), &owner);
        let view = state.view();
        let key = crate::sns::record_storage_key(&selector);
        assert!(
            view.world().smart_contract_state().get(&key).is_some(),
            "seeded SNS record must be present in raw state storage"
        );
        assert_eq!(
            (crate::sns::active_dataspace_owner_by_id(
                view.world(),
                &view.nexus.dataspace_catalog,
                DataSpaceId::new(9),
                0,
            ))
            .expect("completed fixture operation"),
            Some(owner.clone()),
            "SNS helper should resolve the active owner from the state view"
        );
        let resolved = FindDataspaceNameOwnerById::new(DataSpaceId::new(9))
            .execute(&view)
            .expect("query succeeds");
        assert_eq!(resolved, owner);
    }
    #[test]
    fn find_dataspace_name_owner_uses_cached_ledger_time_without_loading_a_block() {
        let mut state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        state.set_dataspace_catalog_for_testing(
            DataSpaceCatalog::new(vec![
                DataSpaceMetadata::default(),
                DataSpaceMetadata {
                    id: DataSpaceId::new(9),
                    alias: "trade".to_owned(),
                    description: None,
                    fault_tolerance: 1,
                },
            ])
            .expect("catalog"),
        );
        let owner = owner();
        let target = AliasTargetV1::Dataspace(ResolvedDataSpaceV1::new(
            "trade".parse().expect("canonical alias"),
            DataSpaceId::new(9),
        ));
        let selector = crate::alias_setup::selector_for_resolved_alias_target(&target)
            .expect("dataspace selector");
        let address = AccountAddress::from_account_id(&owner).expect("owner address");
        let record = NameRecordV1::new(
            selector.clone(),
            owner,
            vec![NameControllerV1::account(&address)],
            0,
            0,
            10,
            10,
            10,
            crate::alias_setup::alias_registration_metadata(&target).expect("dataspace metadata"),
        );
        state.world.smart_contract_state_mut_for_testing().insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
        state.append_committed_block_header_for_tests(BlockHeader::new(
            NonZeroU64::new(1).expect("nonzero height"),
            None,
            None,
            11,
            0,
        ));
        let view = state.query_view();
        assert!(
            matches!(
                view.latest_block(),
                Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                    iroha_data_model::query::error::CanonicalHistoryError::BodyUnavailable { .. }
                ))
            ),
            "the committed header cannot supply the missing Kura body"
        );
        assert!(matches!(
            FindDataspaceNameOwnerById::new(DataSpaceId::new(9)).execute(&view),
            Err(QueryError::NotFound)
        ));
    }
    #[test]
    fn ensure_and_renew_account_alias_lease_round_trip() {
        let authority = owner();
        let payment_asset_definition_id: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("payment asset definition id");
        let genesis_domain =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&authority);
        let authority_account = Account::new(authority.clone()).build(&authority);
        let payment_definition = AssetDefinition::numeric(
            payment_asset_definition_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&authority);
        let mut world = World::with([genesis_domain], [authority_account], [payment_definition]);
        seed_default_namespace_policies(&mut world);
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        configure_test_fee_asset(&state, &payment_asset_definition_id);
        {
            let mut block = state.block(next_header(&state));
            let mut stx = block.transaction();
            Mint::asset_quantity(
                1_000_u64,
                AssetId::of(payment_asset_definition_id.clone(), authority.clone()),
            )
            .execute(&authority, &mut stx)
            .expect("mint payment balance");
            stx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("mint block commits");
        }
        let alias =
            AccountAlias::domainless("merchant".parse().expect("label"), DataSpaceId::UNIVERSAL);
        {
            let mut block = state.block(next_header(&state));
            let mut stx =
                block.transaction_for_fastpq_testing(Hash::prehashed([0xC2; Hash::LENGTH]));
            seed_test_call_hash(&mut stx, 0xC2);
            ensure_account_alias_instruction(
                &stx,
                &alias,
                authority.clone(),
                AccountProvisionV1::Existing,
                AccountAliasRoleV1::Additional,
                1,
                None,
            )
            .execute(&authority, &mut stx)
            .expect("acquire lease");
            stx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("acquire block commits");
        }
        let view = state.view();
        let acquired = get_name_record(
            view.world(),
            SnsNamespace::AccountAlias,
            "merchant@universal",
            0,
        )
        .expect("acquired alias lease");
        let initial_expiry = acquired.expires_at_ms;
        assert_eq!(acquired.owner, authority);
        drop(view);
        {
            let mut block = state.block(next_header(&state));
            let mut stx =
                block.transaction_for_fastpq_testing(Hash::prehashed([0xC3; Hash::LENGTH]));
            seed_test_call_hash(&mut stx, 0xC3);
            renew_account_alias_instruction(&stx, &alias, 1)
                .execute(&authority, &mut stx)
                .expect("renew lease");
            stx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("renew block commits");
        }
        let view = state.view();
        let renewed = get_name_record(
            view.world(),
            SnsNamespace::AccountAlias,
            "merchant@universal",
            0,
        )
        .expect("renewed alias lease");
        assert!(
            renewed.expires_at_ms > initial_expiry,
            "renewal must extend the alias expiry"
        );
    }
    #[test]
    fn renew_alias_lease_rejects_stale_expiry_cas_before_charge() {
        let collector = owner();
        let authority = another_owner();
        let payment_asset: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("payment asset definition id");
        let genesis_domain =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&collector);
        let authority_account = Account::new(authority.clone()).build(&collector);
        let collector_account = Account::new(collector.clone()).build(&collector);
        let payment_definition = AssetDefinition::numeric(
            payment_asset.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&collector);
        let payer_asset = Asset::new(
            AssetId::of(payment_asset.clone(), authority.clone()),
            Quantity::from(1_000_u64),
        );
        let mut world = World::with_assets(
            [genesis_domain],
            [authority_account, collector_account],
            [payment_definition],
            [payer_asset],
            [],
        );
        seed_default_namespace_policies(&mut world);
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        configure_test_fee_asset(&state, &payment_asset);
        let alias = AccountAlias::domainless(
            "stale-renew".parse().expect("label"),
            DataSpaceId::UNIVERSAL,
        );
        {
            let mut block = state.block(next_header(&state));
            let mut transaction =
                block.transaction_for_fastpq_testing(Hash::prehashed([0xC4; Hash::LENGTH]));
            seed_test_call_hash(&mut transaction, 0xC4);
            ensure_account_alias_instruction(
                &transaction,
                &alias,
                authority.clone(),
                AccountProvisionV1::Existing,
                AccountAliasRoleV1::Additional,
                1,
                None,
            )
            .execute(&authority, &mut transaction)
            .expect("acquire lease");
            transaction.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("acquire block commits");
        }
        let (current_expiry, payer_before, collector_before) = {
            let view = state.view();
            let record = get_name_record(
                view.world(),
                SnsNamespace::AccountAlias,
                "stale-renew@universal",
                0,
            )
            .expect("acquired alias lease");
            (
                record.expires_at_ms,
                asset_balance_in_world(view.world(), &payment_asset, &authority),
                asset_balance_in_world(view.world(), &payment_asset, &collector),
            )
        };
        let mut block = state.block(next_header(&state));
        let mut transaction =
            block.transaction_for_fastpq_testing(Hash::prehashed([0xC5; Hash::LENGTH]));
        seed_test_call_hash(&mut transaction, 0xC5);
        let mut renewal = renew_account_alias_instruction(&transaction, &alias, 1);
        renewal.expected_current_expiry_ms = current_expiry.saturating_add(1);
        let error = renewal
            .execute(&authority, &mut transaction)
            .expect_err("stale expiry CAS must fail");
        assert!(
            error.to_string().contains("alias.lease.expiry_conflict"),
            "unexpected stale CAS error: {error}"
        );
        assert_eq!(
            asset_balance_in_world(transaction.world(), &payment_asset, &authority),
            payer_before,
            "expiry CAS must be checked before charging"
        );
        assert_eq!(
            asset_balance_in_world(transaction.world(), &payment_asset, &collector),
            collector_before,
            "expiry CAS must be checked before crediting the collector"
        );
        let record = get_name_record(
            transaction.world(),
            SnsNamespace::AccountAlias,
            "stale-renew@universal",
            0,
        )
        .expect("lease remains present after rejected renewal");
        assert_eq!(
            record.expires_at_ms, current_expiry,
            "stale renewal must not change the current expiry"
        );
    }
    #[test]
    fn register_account_and_ensure_alias_in_one_transaction() {
        let authority = owner();
        let retail_account = another_owner();
        let payment_asset_definition_id: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("payment asset definition id");
        let genesis_domain =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&authority);
        let authority_account = Account::new(authority.clone()).build(&authority);
        let payment_definition = AssetDefinition::numeric(
            payment_asset_definition_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&authority);
        let mut world = World::with([genesis_domain], [authority_account], [payment_definition]);
        seed_default_namespace_policies(&mut world);
        let mut permissions = world
            .account_permissions
            .view()
            .get(&authority)
            .cloned()
            .unwrap_or_default();
        permissions.insert(Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
        }));
        world
            .account_permissions
            .insert(authority.clone(), permissions);
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        configure_test_fee_asset(&state, &payment_asset_definition_id);
        {
            let mut block = state.block(next_header(&state));
            let mut stx = block.transaction();
            Mint::asset_quantity(
                1_000_u64,
                AssetId::of(payment_asset_definition_id.clone(), authority.clone()),
            )
            .execute(&authority, &mut stx)
            .expect("mint payment balance");
            stx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("mint block commits");
        }
        let alias = AccountAlias::domainless(
            "clearorbit3941".parse().expect("label"),
            DataSpaceId::UNIVERSAL,
        );
        {
            let mut block = state.block(next_header(&state));
            let mut stx =
                block.transaction_for_fastpq_testing(Hash::prehashed([0xD1; Hash::LENGTH]));
            Register::account(Account::new(retail_account.clone()))
                .execute(&authority, &mut stx)
                .expect("register retail account");
            seed_test_call_hash(&mut stx, 0xD1);
            ensure_account_alias_instruction(
                &stx,
                &alias,
                retail_account.clone(),
                AccountProvisionV1::Existing,
                AccountAliasRoleV1::Additional,
                1,
                None,
            )
            .execute(&authority, &mut stx)
            .expect("ensure alias for newly registered account");
            stx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("registration batch commits");
        }
        let view = state.view();
        assert!(
            view.world().account(&retail_account).is_ok(),
            "retail account should be visible after the batch"
        );
        let lease = get_name_record(
            view.world(),
            SnsNamespace::AccountAlias,
            "clearorbit3941@universal",
            0,
        )
        .expect("alias lease should be active after the batch");
        assert_eq!(lease.owner, retail_account);
        assert_eq!(
            view.world().account_aliases().get(&alias),
            Some(&retail_account),
            "alias binding should be visible after the batch"
        );
    }
    #[test]
    fn register_account_and_ensure_fi_alias_in_one_transaction() {
        let authority = owner();
        let retail_account = another_owner();
        let payment_asset_definition_id: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("payment asset definition id");
        let genesis_domain =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&authority);
        let hbl_domain = Domain::new(DomainId::try_new("hbl", "sbp").expect("hbl.sbp domain id"))
            .build(&authority);
        let authority_account = Account::new(authority.clone()).build(&authority);
        let payment_definition = AssetDefinition::numeric(
            payment_asset_definition_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&authority);
        let mut world = World::with(
            [genesis_domain, hbl_domain],
            [authority_account],
            [payment_definition],
        );
        seed_default_namespace_policies(&mut world);
        let mut permissions = world
            .account_permissions
            .view()
            .get(&authority)
            .cloned()
            .unwrap_or_default();
        let sbp = DataSpaceId::new(10);
        permissions.insert(Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Dataspace(sbp),
        }));
        permissions.insert(Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Domain(
                DomainId::try_new("hbl", "sbp").expect("hbl.sbp domain id"),
            ),
        }));
        world
            .account_permissions
            .insert(authority.clone(), permissions);
        let mut state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        configure_test_fee_asset(&state, &payment_asset_definition_id);
        state.set_dataspace_catalog_for_testing(
            DataSpaceCatalog::new(vec![
                DataSpaceMetadata::default(),
                DataSpaceMetadata {
                    id: sbp,
                    alias: "sbp".to_owned(),
                    description: None,
                    fault_tolerance: 1,
                },
            ])
            .expect("sbp dataspace catalog"),
        );
        {
            let mut block = state.block(next_header(&state));
            let mut stx = block.transaction();
            Mint::asset_quantity(
                1_000_u64,
                AssetId::of(payment_asset_definition_id.clone(), authority.clone()),
            )
            .execute(&authority, &mut stx)
            .expect("mint payment balance");
            stx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("mint block commits");
        }
        let alias = AccountAlias::new(
            "clear-orbit-3941".parse().expect("label"),
            Some(AccountAliasDomain::new("hbl".parse().expect("domain"))),
            sbp,
        );
        {
            let mut block = state.block(next_header(&state));
            let mut stx =
                block.transaction_for_fastpq_testing(Hash::prehashed([0xD2; Hash::LENGTH]));
            Register::account(Account::new(retail_account.clone()))
                .execute(&authority, &mut stx)
                .expect("register retail account");
            seed_active_domain_lease(
                &mut stx,
                &DomainId::try_new("hbl", "sbp").expect("hbl.sbp domain id"),
                &authority,
            );
            seed_test_call_hash(&mut stx, 0xD2);
            ensure_account_alias_instruction(
                &stx,
                &alias,
                retail_account.clone(),
                AccountProvisionV1::Existing,
                AccountAliasRoleV1::Additional,
                1,
                None,
            )
            .execute(&authority, &mut stx)
            .expect("ensure FI alias for newly registered account");
            stx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("FI registration batch commits");
        }
        let view = state.view();
        let lease = get_name_record(
            view.world(),
            SnsNamespace::AccountAlias,
            "clear-orbit-3941@hbl.sbp",
            0,
        )
        .expect("FI alias lease should be active after the batch");
        assert_eq!(lease.owner, retail_account);
        assert_eq!(
            view.world().account_aliases().get(&alias),
            Some(&retail_account),
            "FI alias binding should be visible after the batch"
        );
    }
    #[test]
    fn serial_psp_alias_claims_from_one_prestate_have_one_winner() {
        let PspAliasFixture {
            state,
            authority,
            collector,
            target_a,
            target_b,
            payment_asset,
            dataspace,
        } = psp_alias_fixture();
        let alias = AccountAlias::new(
            "shared3941".parse().expect("alias label"),
            Some(AccountAliasDomain::new(
                "leumi".parse().expect("PSP domain label"),
            )),
            dataspace,
        );
        let (claim_a, claim_b) = {
            let mut block = state.block(next_header(&state));
            let stx = block.transaction();
            let claim_a = ensure_account_alias_instruction(
                &stx,
                &alias,
                target_a.clone(),
                AccountProvisionV1::Existing,
                AccountAliasRoleV1::Additional,
                1,
                None,
            );
            let claim_b = ensure_account_alias_instruction(
                &stx,
                &alias,
                target_b.clone(),
                AccountProvisionV1::Existing,
                AccountAliasRoleV1::Additional,
                1,
                None,
            );
            drop(stx);
            drop(block);
            (claim_a, claim_b)
        };
        let mut successes = 0_u8;
        let mut owner_conflicts = 0_u8;
        let mut winner = None;
        for (index, (claim, target)) in [(claim_a, target_a), (claim_b, target_b)]
            .into_iter()
            .enumerate()
        {
            let payer_before = asset_balance(&state, &payment_asset, &authority);
            let collector_before = asset_balance(&state, &payment_asset, &collector);
            let mut block = state.block(next_header(&state));
            let call_hash_byte =
                0xE0_u8.saturating_add(u8::try_from(index).expect("bounded claim index"));
            let mut stx = block
                .transaction_for_fastpq_testing(Hash::prehashed([call_hash_byte; Hash::LENGTH]));
            seed_test_call_hash(&mut stx, call_hash_byte);
            match claim.execute(&authority, &mut stx) {
                Ok(()) => {
                    successes = successes.saturating_add(1);
                    winner = Some(target);
                    stx.apply();
                    block
                        .commit_world_overlay_for_testing()
                        .expect("winning PSP alias claim commits");
                }
                Err(error) => {
                    assert!(
                        smart_contract_error_contains(&error, "alias.owner.conflict"),
                        "losing PSP alias claim must return alias.owner.conflict: {error}"
                    );
                    owner_conflicts = owner_conflicts.saturating_add(1);
                    assert_eq!(
                        asset_balance_in_world(stx.world(), &payment_asset, &authority),
                        payer_before,
                        "owner conflict must precede any payer debit"
                    );
                    assert_eq!(
                        asset_balance_in_world(stx.world(), &payment_asset, &collector),
                        collector_before,
                        "owner conflict must precede any collector credit"
                    );
                    drop(stx);
                    drop(block);
                    assert_eq!(
                        asset_balance(&state, &payment_asset, &authority),
                        payer_before,
                        "rejected claim must not persist a payer debit"
                    );
                    assert_eq!(
                        asset_balance(&state, &payment_asset, &collector),
                        collector_before,
                        "rejected claim must not persist a collector credit"
                    );
                }
            }
        }
        assert_eq!(successes, 1, "exactly one serial claim must commit");
        assert_eq!(
            owner_conflicts, 1,
            "exactly one serial claim must lose with alias.owner.conflict"
        );
        let winner = winner.expect("one claim must win");
        let view = state.view();
        let lease = get_name_record(
            view.world(),
            SnsNamespace::AccountAlias,
            "shared3941@leumi.is",
            0,
        )
        .expect("winning PSP alias lease");
        assert_eq!(lease.owner, winner);
        assert_eq!(view.world().account_aliases().get(&alias), Some(&winner));
    }
    #[test]
    fn same_local_alias_isolated_by_psp_domain() {
        let PspAliasFixture {
            state,
            authority,
            target_a,
            target_b,
            dataspace,
            ..
        } = psp_alias_fixture();
        let leumi_alias = AccountAlias::new(
            "shared3941".parse().expect("alias label"),
            Some(AccountAliasDomain::new(
                "leumi".parse().expect("Leumi domain label"),
            )),
            dataspace,
        );
        let hapoalim_alias = AccountAlias::new(
            "shared3941".parse().expect("alias label"),
            Some(AccountAliasDomain::new(
                "hapoalim".parse().expect("Hapoalim domain label"),
            )),
            dataspace,
        );
        {
            let mut block = state.block(next_header(&state));
            let mut stx =
                block.transaction_for_fastpq_testing(Hash::prehashed([0xE2; Hash::LENGTH]));
            seed_test_call_hash(&mut stx, 0xE2);
            ensure_account_alias_instruction(
                &stx,
                &leumi_alias,
                target_a.clone(),
                AccountProvisionV1::Existing,
                AccountAliasRoleV1::Additional,
                1,
                None,
            )
            .execute(&authority, &mut stx)
            .expect("Leumi-scoped local alias must succeed");
            ensure_account_alias_instruction(
                &stx,
                &hapoalim_alias,
                target_b.clone(),
                AccountProvisionV1::Existing,
                AccountAliasRoleV1::Additional,
                1,
                None,
            )
            .execute(&authority, &mut stx)
            .expect("Hapoalim-scoped same local alias must succeed");
            stx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("independent PSP aliases commit");
        }
        let view = state.view();
        let leumi_lease = get_name_record(
            view.world(),
            SnsNamespace::AccountAlias,
            "shared3941@leumi.is",
            0,
        )
        .expect("Leumi alias lease");
        let hapoalim_lease = get_name_record(
            view.world(),
            SnsNamespace::AccountAlias,
            "shared3941@hapoalim.is",
            0,
        )
        .expect("Hapoalim alias lease");
        assert_eq!(leumi_lease.owner, target_a);
        assert_eq!(hapoalim_lease.owner, target_b);
        assert_eq!(
            view.world().account_aliases().get(&leumi_alias),
            Some(&target_a)
        );
        assert_eq!(
            view.world().account_aliases().get(&hapoalim_alias),
            Some(&target_b)
        );
    }
    #[test]
    fn ensure_alias_rejects_stale_policy_without_mutating_it() {
        let authority = owner();
        let payment_asset_definition_id: AssetDefinitionId = "61CtjvNd9T3THAR65GsMVHr82Bjc"
            .parse()
            .expect("deployment payment asset definition id");
        let genesis_domain =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&authority);
        let authority_account = Account::new(authority.clone()).build(&authority);
        let payment_definition = AssetDefinition::numeric(
            payment_asset_definition_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&authority);
        let mut world = World::with([genesis_domain], [authority_account], [payment_definition]);
        seed_default_namespace_policies(&mut world);
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        state.nexus.write().fees.fee_asset_id = payment_asset_definition_id.to_string();
        {
            let mut block = state.block(next_header(&state));
            let mut stx = block.transaction();
            Mint::asset_quantity(
                1_000_u64,
                AssetId::of(payment_asset_definition_id.clone(), authority.clone()),
            )
            .execute(&authority, &mut stx)
            .expect("mint payment balance");
            stx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("mint block commits");
        }
        let alias =
            AccountAlias::domainless("retail".parse().expect("label"), DataSpaceId::UNIVERSAL);
        let mut block = state.block(next_header(&state));
        let mut stx = block.transaction();
        seed_test_call_hash(&mut stx, 0xC6);
        let err = ensure_account_alias_instruction(
            &stx,
            &alias,
            authority.clone(),
            AccountProvisionV1::Existing,
            AccountAliasRoleV1::Additional,
            1,
            None,
        )
        .execute(&authority, &mut stx)
        .expect_err("lease mutation must reject a stale SNS payment policy");
        assert!(
            err.to_string()
                .contains("does not match configured Nexus fee asset"),
            "unexpected error: {err}"
        );
        drop(stx);
        drop(block);
        let view = state.view();
        let policy = policy_by_id(view.world(), ACCOUNT_ALIAS_SUFFIX_ID)
            .expect("valid policy state")
            .expect("policy");
        assert_eq!(
            policy.payment_asset_id,
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
            "rejected mutation must not silently converge policy state"
        );
        assert!(
            get_name_record(
                view.world(),
                SnsNamespace::AccountAlias,
                "retail@universal",
                0,
            )
            .is_err(),
            "rejected mutation must not persist an alias lease"
        );
    }
    #[test]
    fn ensure_alias_rejects_create_on_non_authoritative_payment_route() {
        let authority = owner();
        let collector = another_owner();
        let paynet = DataSpaceId::new(10);
        let payment_asset_definition_id: AssetDefinitionId = "6TEAJqbb8oEPmLncoNiMRbLEK6tw"
            .parse()
            .expect("deployment payment asset definition id");
        let genesis_domain =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&collector);
        let authority_account = Account::new(authority.clone()).build(&collector);
        let collector_account = Account::new(collector.clone()).build(&collector);
        let payment_definition = AssetDefinition::numeric(
            payment_asset_definition_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&collector);
        let mut world = World::with(
            vec![genesis_domain],
            vec![authority_account, collector_account],
            vec![payment_definition],
        );
        crate::sns::seed_default_namespace_policies_for_payment_asset(
            &mut world,
            &payment_asset_definition_id.to_string(),
        );
        seed_active_dataspace_lease(&mut world, "paynet", paynet, &collector);
        let mut state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        state.nexus.write().fees.fee_asset_id = payment_asset_definition_id.to_string();
        state.set_dataspace_catalog_for_testing(
            DataSpaceCatalog::new(vec![
                DataSpaceMetadata::default(),
                DataSpaceMetadata {
                    id: paynet,
                    alias: "paynet".to_owned(),
                    description: None,
                    fault_tolerance: 1,
                },
            ])
            .expect("dataspace catalog"),
        );
        let alias = AccountAlias::domainless("retail".parse().expect("label"), paynet);
        let mut block = state.block(next_header(&state));
        let mut stx = block.transaction();
        stx.current_dataspace_id = Some(paynet);
        stx.world.current_dataspace_id = Some(paynet);
        stx.tx_call_hash = Some(Hash::prehashed([0xC7; Hash::LENGTH]));
        let err = ensure_account_alias_instruction(
            &stx,
            &alias,
            authority.clone(),
            AccountProvisionV1::Existing,
            AccountAliasRoleV1::Additional,
            1,
            None,
        )
        .execute(&authority, &mut stx)
        .expect_err("lease acquisition must not bypass the exact native charge");
        assert!(
            matches!(
                &err,
                InstructionExecutionError::InvariantViolation(message)
                    if message.contains("must execute on authoritative dataspace")
            ),
            "unexpected error: {err}"
        );
        drop(stx);
        drop(block);
        let view = state.view();
        assert!(
            get_name_record(view.world(), SnsNamespace::AccountAlias, "retail@paynet", 0,).is_err(),
            "rejected acquisition must not persist an alias lease"
        );
        drop(view);
        assert_eq!(
            asset_balance(&state, &payment_asset_definition_id, &authority),
            Quantity::zero()
        );
        assert_eq!(
            asset_balance(&state, &payment_asset_definition_id, &collector),
            Quantity::zero()
        );
    }
    #[test]
    fn ensure_alias_never_debits_a_client_selected_resource_owner() {
        let authority = owner();
        let resource_owner = another_owner();
        let payment_asset_definition_id: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("payment asset definition id");
        let genesis_domain =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&authority);
        let authority_account = Account::new(authority.clone()).build(&authority);
        let resource_owner_account = Account::new(resource_owner.clone()).build(&authority);
        let payment_definition = AssetDefinition::numeric(
            payment_asset_definition_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&authority);
        let mut world = World::with(
            vec![genesis_domain],
            vec![authority_account, resource_owner_account],
            vec![payment_definition],
        );
        seed_default_namespace_policies(&mut world);
        world.account_permissions.insert(
            authority.clone(),
            [Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
            })]
            .into_iter()
            .collect(),
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        configure_test_fee_asset(&state, &payment_asset_definition_id);
        {
            let mut block = state.block(next_header(&state));
            let mut stx = block.transaction();
            Mint::asset_quantity(
                1_000_u64,
                AssetId::of(payment_asset_definition_id.clone(), resource_owner.clone()),
            )
            .execute(&authority, &mut stx)
            .expect("fund resource owner");
            stx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("funding block commits");
        }
        let alias =
            AccountAlias::domainless("merchant".parse().expect("label"), DataSpaceId::UNIVERSAL);
        let mut block = state.block(next_header(&state));
        let mut stx = block.transaction();
        stx.tx_call_hash = Some(Hash::prehashed([0xC8; Hash::LENGTH]));
        let err = ensure_account_alias_instruction(
            &stx,
            &alias,
            resource_owner.clone(),
            AccountProvisionV1::Existing,
            AccountAliasRoleV1::Additional,
            1,
            None,
        )
        .execute(&authority, &mut stx)
        .expect_err("the unfunded transaction authority must remain the only payer");
        let expected_authority_asset =
            AssetId::of(payment_asset_definition_id.clone(), authority.clone());
        assert!(
            matches!(
                &err,
                InstructionExecutionError::Find(
                    iroha_data_model::query::error::FindError::Asset(asset_id)
                ) if asset_id.as_ref() == &expected_authority_asset
            ),
            "unexpected error: {err:?}"
        );
        drop(stx);
        drop(block);
        assert_eq!(
            asset_balance(&state, &payment_asset_definition_id, &resource_owner),
            Quantity::from(1_000_u64),
            "resource owner balance must not be selected as setup payment"
        );
        let view = state.view();
        assert!(
            get_name_record(
                view.world(),
                SnsNamespace::AccountAlias,
                "merchant@universal",
                0,
            )
            .is_err(),
            "failed authority payment must not create the alias"
        );
    }
    #[test]
    fn renew_account_alias_lease_rejects_non_owner_without_permission() {
        let owner = owner();
        let authority = another_owner();
        let payment_asset_definition_id: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("payment asset definition id");
        let genesis_domain =
            Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain id"))
                .build(&owner);
        let owner_account = Account::new(owner.clone()).build(&owner);
        let authority_account = Account::new(authority.clone()).build(&owner);
        let payment_definition = AssetDefinition::numeric(
            payment_asset_definition_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&owner);
        let mut world = World::with(
            vec![genesis_domain],
            vec![owner_account, authority_account],
            vec![payment_definition],
        );
        seed_default_namespace_policies(&mut world);
        let mut state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        configure_test_fee_asset(&state, &payment_asset_definition_id);
        let alias =
            AccountAlias::domainless("merchant".parse().expect("label"), DataSpaceId::UNIVERSAL);
        let selector = {
            let view = state.view();
            crate::sns::selector_for_account_alias(&alias, &view.nexus.dataspace_catalog)
                .expect("selector")
        };
        let address = AccountAddress::from_account_id(&owner).expect("address");
        let record = NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            1,
            5_000,
            5_000 + (30 * 86_400_000),
            5_000 + (90 * 86_400_000),
            Metadata::default(),
        );
        state.world.smart_contract_state.insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
        let mut block = state.block(next_header(&state));
        let mut stx = block.transaction();
        stx.tx_call_hash = Some(Hash::prehashed([0xC9; Hash::LENGTH]));
        let err = renew_account_alias_instruction(&stx, &alias, 1)
            .execute(&authority, &mut stx)
            .expect_err("non-owner without permission must fail");
        assert!(
            matches!(err, InstructionExecutionError::InvariantViolation(_)),
            "unexpected error: {err:?}"
        );
    }

    // Actual signed native execution: the fixture only supplies initial FI
    // permissions and parent leases in the signed genesis, never a target lease
    // or caller-authored execution output. This grants no runtime authority.
    #[test]
    fn retail_registration_bare_multisig_then_existing_primary_alias_executes_atomically() {
        use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
        use iroha_allocation::AllocationBudget;
        use iroha_data_model::{
            IntoKeyValue,
            account::{MultisigMember, MultisigPolicy},
            asset::AssetBalancePolicy,
            nexus::UniversalAccountId,
            sumeragi_finality::world_state_value_hash_v1,
        };
        use iroha_executor_data_model::{
            isi::multisig::{DEFAULT_MULTISIG_TTL_MS, MultisigSpec},
            permission::query::CanReadAllLedgerData,
        };
        use iroha_primitives::json::Json;
        use std::{collections::BTreeMap, num::NonZeroU16};
        let registrar_key = KeyPair::from_seed(vec![0xCE; 32], Algorithm::Ed25519);
        let registrar = AccountId::new(registrar_key.public_key().clone());
        let collector = AccountId::new(
            KeyPair::from_seed(vec![0xCF; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let client = KeyPair::from_seed(vec![0xA1; 32], Algorithm::Ed25519);
        let signer = AccountId::new(client.public_key().clone());
        let wallet = AccountId::new_multisig(
            MultisigPolicy::new(
                1,
                vec![MultisigMember::new(client.public_key().clone(), 1).unwrap()],
            )
            .unwrap(),
        );
        let domain = DomainId::try_new("leumi", "is2").unwrap();
        let dataspace = DataSpaceId::new(77);
        let catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: dataspace,
                alias: "is2".into(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .unwrap();
        let alias = ResolvedAccountAliasV1::new("retail@leumi.is2".parse().unwrap(), dataspace);
        let payment: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .unwrap();
        let mut world = World::with(
            [
                Domain::new(DomainId::try_new("genesis", "universal").unwrap()).build(&collector),
                Domain::new(domain.clone()).build(&registrar),
            ],
            [
                Account::new(registrar.clone()).build(&registrar),
                Account::new(collector.clone()).build(&collector),
            ],
            [AssetDefinition::numeric(
                payment.clone(),
                "Fixture fee",
                AssetBalancePolicy::Global,
                None,
            )
            .build(&registrar)],
        );
        let (asset, value) = Asset::new(
            AssetId::of(payment.clone(), registrar.clone()),
            1_000_000_u64,
        )
        .into_key_value();
        world.assets.insert(asset, value);
        seed_default_namespace_policies(&mut world);
        seed_active_dataspace_lease(&mut world, "is2", dataspace, &registrar);
        let domain_selector = crate::sns::selector_for_domain(&domain).unwrap();
        let controller =
            NameControllerV1::account(&AccountAddress::from_account_id(&registrar).unwrap());
        let domain_lease = NameRecordV1::new(
            domain_selector.clone(),
            registrar.clone(),
            vec![controller],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        world.smart_contract_state_mut_for_testing().insert(
            crate::sns::record_storage_key(&domain_selector),
            norito::codec::Encode::encode(&domain_lease),
        );
        let alias_management = Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Domain(domain.clone()),
        });
        let target = AliasTargetV1::AccountAlias(alias.clone());
        let selector = crate::alias_setup::selector_for_resolved_alias_target(&target).unwrap();
        assert!(crate::sns::get_name_record_by_selector(&world.view(), &selector, 2_000).is_err());
        let quote = crate::sns::quote_resolved_name_registration(
            &world.view(),
            selector.clone(),
            &wallet,
            1,
            None,
            2_000,
        )
        .unwrap();
        let policy = policy_by_id(&world.view(), ACCOUNT_ALIAS_SUFFIX_ID)
            .unwrap()
            .unwrap();
        let uaid = UniversalAccountId::from_hash(Hash::new(
            format!(
                "retail_registration|alias={}|account_id={}",
                alias.canonical_text(),
                wallet.canonical_i105().unwrap()
            )
            .as_bytes(),
        ));
        let spec = MultisigSpec {
            signatories: BTreeMap::from([(signer.clone(), 1)]),
            quorum: NonZeroU16::new(1).unwrap(),
            transaction_ttl_ms: NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS).unwrap(),
        };
        let mut metadata = Metadata::default();
        metadata.insert("multisig/spec".parse().unwrap(), Json::new(spec));
        metadata.insert(
            "iroha:multisig_home_domain".parse().unwrap(),
            Json::new(Some(domain)),
        );
        let bare_wallet = Account::new(wallet.clone())
            .with_metadata(metadata.clone())
            .with_uaid(Some(uaid));
        assert!(bare_wallet.label.is_none());
        let ensure = EnsureAlias::new(
            AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
                alias: alias.clone(),
                target_account: wallet.clone(),
                provision: AccountProvisionV1::Existing,
                role: AccountAliasRoleV1::Primary,
            }),
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: policy.policy_version,
                expected_payment_asset: payment.clone(),
                max_amount: quote.charge_amount.clone(),
                valid_until_ms: 120_000,
            },
        );
        let exact_management = Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Domain(alias.canonical_name.domain_id().unwrap()),
        });
        // These permissions come from the original signed genesis below, not the
        // unexecuted fixture World. The positive exact-grant assertions follow startup.
        assert!(world.view().account_permissions().get(&registrar).is_none());
        assert!(
            !crate::alias::authority_can_manage_resolved_account_alias(
                &world.view(),
                &registrar,
                &alias
            )
            .unwrap()
        );
        let mut config = TestChainConfig::new(world, 1_000);
        config.genesis_key = registrar_key.clone();
        // Carry the fixture's management and snapshot-read permissions as
        // actual grants in the authenticated signed genesis source.
        config.genesis_instructions.extend([
            iroha_data_model::isi::Grant::account_permission(alias_management, registrar.clone())
                .into(),
            iroha_data_model::isi::Grant::account_permission(
                Permission::from(CanReadAllLedgerData),
                registrar.clone(),
            )
            .into(),
        ]);
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.dataspace_catalog = catalog.clone();
        // Both supplied configuration cuts describe this same pre-genesis catalog.
        nexus.configured_dataspace_catalog = catalog.clone();
        nexus.lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
            std::num::NonZeroU32::new(2).unwrap(),
            vec![
                iroha_data_model::nexus::LaneConfig::default(),
                iroha_data_model::nexus::LaneConfig {
                    id: iroha_model_base::topology::LaneId::new(1),
                    dataspace_id: dataspace,
                    alias: "is2".into(),
                    ..iroha_data_model::nexus::LaneConfig::default()
                },
            ],
        )
        .unwrap();
        nexus.configured_lane_catalog = nexus.lane_catalog.clone();
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        nexus.fees.base_fee = Quantity::zero();
        nexus.fees.per_byte_fee = Quantity::zero();
        nexus.fees.per_instruction_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        config.nexus = Some(nexus);
        let mut chain = CertifiedTestChain::start(config).unwrap();
        {
            let original = chain.state().view();
            assert!(
                original
                    .world()
                    .account_permissions()
                    .get(&registrar)
                    .is_some_and(|grants| grants.contains(&exact_management)),
                "signed genesis retains exact management grant: {:?}",
                original.world().account_permissions().get(&registrar)
            );
            assert!(
                crate::alias::authority_can_manage_resolved_account_alias(
                    original.world(),
                    &registrar,
                    &alias
                )
                .unwrap()
            );
        }
        let instructions: Vec<iroha_data_model::isi::InstructionBox> = vec![
            Register::account(Account::new(signer.clone())).into(),
            Register::account(bare_wallet.clone()).into(),
            ensure.clone().into(),
        ];
        let signed_payload = chain.sign(&registrar_key, instructions, 1_999);
        let committed = chain.commit_at(2_000, vec![signed_payload]);
        let tip = chain.committed(2);
        assert_eq!(
            committed,
            vec![true],
            "native atomic registration outputs: {:?}",
            tip.block().execution_outputs(),
        );
        let (wallet_original, signer_original, lease_original, payer_after, collector_after) = {
            let view = chain.state().view();
            let wallet_original = view.world().accounts().get(&wallet).unwrap().clone();
            let details = wallet_original.as_ref();
            assert_eq!(details.label.as_ref(), Some(&alias.account_alias()));
            assert_eq!(details.uaid.as_ref(), Some(&uaid));
            assert_eq!(details.metadata, metadata);
            assert!(details.opaque_ids.is_empty());
            let signer_original = view.world().accounts().get(&signer).unwrap().clone();
            let signer_details = signer_original.as_ref();
            assert!(signer_details.label.is_none());
            assert!(signer_details.uaid.is_none());
            assert!(signer_details.metadata.is_empty());
            assert_eq!(
                view.world().account_aliases().get(&alias.account_alias()),
                Some(&wallet)
            );
            assert_eq!(
                view.world()
                    .account_rekey_records()
                    .get(&alias.account_alias())
                    .unwrap()
                    .active_account_id,
                wallet
            );
            let lease =
                crate::sns::get_name_record_by_selector(view.world(), &selector, 2_000).unwrap();
            assert_eq!(lease.owner, wallet);
            assert_eq!(
                lease.controllers,
                vec![NameControllerV1::account(
                    &AccountAddress::from_account_id(&wallet).unwrap()
                )]
            );
            assert!(matches!(
                lease.status,
                iroha_data_model::sns::NameStatus::Active
            ));
            assert_eq!(lease.expires_at_ms, quote.expires_at_ms);
            let payer_after = asset_balance_in_world(view.world(), &payment, &registrar);
            let collector_after = asset_balance_in_world(view.world(), &payment, &collector);
            (
                wallet_original,
                signer_original,
                lease,
                payer_after,
                collector_after,
            )
        };
        assert_eq!(
            payer_after,
            Quantity::from(1_000_000_u64)
                .try_sub(&quote.charge_amount)
                .unwrap()
        );
        assert_eq!(collector_after, quote.charge_amount);
        let budget = AllocationBudget::new(128 * 1024 * 1024);
        chain
            .state()
            .with_native_resource_names_snapshot_v1(
                &tip,
                &registrar,
                &budget,
                |snapshot, _, _, _| {
                    assert_eq!(
                        snapshot.root().unwrap(),
                        tip.commitment().execution.world_state_root
                    );
                    assert_eq!(
                        snapshot.schema_hash,
                        State::native_world_schema_hash_v1().unwrap()
                    );
                    for (key, value) in [
                        (wallet.clone(), wallet_original.clone()),
                        (signer.clone(), signer_original.clone()),
                    ] {
                        assert!(
                            snapshot
                                .entries
                                .iter()
                                .any(|row| row.field_id == "world.accounts"
                                    && row.key_hash
                                        == Some(world_state_value_hash_v1(&key).unwrap())
                                    && row.value_hash
                                        == world_state_value_hash_v1(&value).unwrap())
                        );
                    }
                    let bytes = norito::codec::Encode::encode(&lease_original);
                    assert!(snapshot.entries.iter().any(|row| {
                        row.field_id == "world.smart_contract_state"
                            && row.key_hash
                                == Some(
                                    world_state_value_hash_v1(&crate::sns::record_storage_key(
                                        &selector,
                                    ))
                                    .unwrap(),
                                )
                            && row.value_hash == world_state_value_hash_v1(&bytes).unwrap()
                    }));
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(budget.reserved_bytes(), 0);
        // A failed quote in the atomic native transaction rolls back both
        // preceding Register effects; an unexecuted intent is not a final label.
        let second_client = KeyPair::from_seed(vec![0xA2; 32], Algorithm::Ed25519);
        let second_signer = AccountId::new(second_client.public_key().clone());
        let second_wallet = AccountId::new_multisig(
            MultisigPolicy::new(
                1,
                vec![MultisigMember::new(second_client.public_key().clone(), 1).unwrap()],
            )
            .unwrap(),
        );
        let second_alias_name: AccountAliasName = "other@leumi.is2".parse().unwrap();
        let second_uaid = UniversalAccountId::from_hash(Hash::new(
            format!(
                "retail_registration|alias={second_alias_name}|account_id={}",
                second_wallet.canonical_i105().unwrap()
            )
            .as_bytes(),
        ));
        let second_spec = MultisigSpec {
            signatories: BTreeMap::from([(second_signer.clone(), 1)]),
            quorum: NonZeroU16::new(1).unwrap(),
            transaction_ttl_ms: NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS).unwrap(),
        };
        let mut second_metadata = Metadata::default();
        second_metadata.insert("multisig/spec".parse().unwrap(), Json::new(second_spec));
        second_metadata.insert(
            "iroha:multisig_home_domain".parse().unwrap(),
            Json::new(Some(DomainId::try_new("leumi", "is2").unwrap())),
        );
        let second_bare_wallet = Account::new(second_wallet.clone())
            .with_metadata(second_metadata)
            .with_uaid(Some(second_uaid));
        let mut invalid_ensure = ensure;
        if let AliasIntentV1::AccountAlias(intent) = &mut invalid_ensure.intent {
            intent.alias.canonical_name = second_alias_name;
            intent.target_account = second_wallet.clone();
        }
        invalid_ensure.quote_guard.max_amount = Quantity::zero();
        let second_quote = {
            let view = chain.state().view();
            let selector = crate::alias_setup::selector_for_resolved_alias_target(
                &invalid_ensure.intent.target(),
            )
            .unwrap();
            crate::sns::quote_resolved_name_registration(
                view.world(),
                selector,
                &second_wallet,
                1,
                None,
                3_000,
            )
            .unwrap()
        };
        assert!(!second_quote.charge_amount.is_zero());
        let rejected = chain.sign(
            &registrar_key,
            vec![
                Register::account(Account::new(second_signer.clone())).into(),
                Register::account(second_bare_wallet).into(),
                invalid_ensure.into(),
            ],
            2_999,
        );
        let rejected_hash =
            iroha_data_model::transaction::TransactionEntrypoint::External(rejected.clone()).hash();
        assert_eq!(chain.commit_at(3_000, vec![rejected]), vec![false]);
        let rejected_tip = chain.committed(3);
        let rejected_block = rejected_tip.block();
        let rejected_outputs = rejected_block
            .execution_outputs()
            .iter()
            .filter_map(|output| {
                let iroha_data_model::block::execution_output::ExecutionOutputV1::Network(network) =
                    output
                else {
                    return None;
                };
                rejected_block
                    .network_entrypoint_at(network.input_index as usize)
                    .filter(|input| input.hash() == rejected_hash)
                    .map(|_| output)
            })
            .collect::<Vec<_>>();
        assert_eq!(rejected_outputs.len(), 1);
        let Err(iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::InstructionFailed(
                InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                    message,
                )),
            ),
        )) = &rejected_outputs[0].result().0
        else {
            panic!(
                "third EnsureAlias must reach its native quote guard: {:?}",
                rejected_outputs[0].result()
            );
        };
        assert_eq!(
            message.clone(),
            format!(
                "alias.quote.cap_exceeded: exact charge {} exceeds authorized cap 0",
                second_quote.charge_amount
            )
        );
        let view = chain.state().view();
        assert!(view.world().account(&second_signer).is_err());
        assert!(view.world().account(&second_wallet).is_err());
        let second_alias = AccountAlias::from_literal("other@leumi.is2", &catalog).unwrap();
        assert!(view.world().account_aliases().get(&second_alias).is_none());
    }
}
