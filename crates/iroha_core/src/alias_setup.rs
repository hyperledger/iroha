//! Read-only classification and validation for declarative alias setup intents.
use crate::{sns::SNS_DATASPACE_ID_METADATA_KEY, state::WorldReadOnly};
#[cfg(test)]
use iroha_data_model::alias_setup::ResolvedAccountAliasV1;
use iroha_data_model::{
    HasMetadata,
    account::{AccountAddress, AccountId},
    alias_setup::{
        AccountAliasRoleV1, AccountProvisionV1, AliasAutoRenewConfigV1, AliasIntentV1,
        AliasLifecyclePlanDispositionV1, AliasPlanDispositionV1, AliasQuoteGuardV1, AliasTargetV1,
    },
    asset::{AssetDefinitionId, AssetId},
    isi::alias_setup::{ConfigureAliasAutoRenew, RenewAliasLease},
    nexus::DataSpaceCatalog,
    permission::Permission,
    sns::{
        ACCOUNT_ALIAS_SUFFIX_ID, DATASPACE_ALIAS_SUFFIX_ID, DOMAIN_NAME_SUFFIX_ID,
        NameControllerV1, NameRecordV1, NameSelectorV1, NameStatus,
    },
};
use iroha_executor_data_model::permission::account::{
    AccountAliasPermissionScope, CanDelegateAccountAliasResolution, CanManageAccountAlias,
    CanResolveAccountAlias,
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::json::Json;
use mv::storage::StorageReadOnly;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
/// Error code returned when public alias setup tries to claim an operator-catalogued dataspace.
pub const CATALOGUED_DATASPACE_BOOTSTRAP_REQUIRED_CODE: &str = "alias.catalog.bootstrap_required";
/// Read an exact governed grant without allowing a malformed reservation to disappear.
fn dataspace_bootstrap_grant(
    world: &impl WorldReadOnly,
    selector: &NameSelectorV1,
) -> Result<Option<iroha_data_model::alias_setup::AliasDataspaceBootstrapGrantV1>, AliasSetupError>
{
    use iroha_data_model::alias_setup::AliasDataspaceBootstrapGrantV1;

    // Legacy targets are normalized by the SNS selector. Do not introduce a new rejection for
    // their raw spelling when no grant exists, including names outside the grant-key grammar.
    let Some(parameter_id) = selector
        .normalized_label()
        .parse()
        .ok()
        .and_then(|name| AliasDataspaceBootstrapGrantV1::parameter_id_for(&name).ok())
    else {
        return Ok(None);
    };
    let Some(custom) = world.parameters().custom().get(&parameter_id) else {
        return Ok(None);
    };
    AliasDataspaceBootstrapGrantV1::from_custom_parameter(custom)
        .map_err(|error| {
            AliasSetupError::new("alias.catalog.bootstrap_grant_invalid", error.to_string())
        })?
        .map(Some)
        .ok_or_else(|| {
            AliasSetupError::new(
                "alias.catalog.bootstrap_grant_invalid",
                "installed bootstrap grant identifier does not match its key",
            )
        })
}
/// Deterministic conflict or validation failure produced while classifying an alias intent.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct AliasSetupError {
    code: &'static str,
    message: String,
    deferred: Option<crate::execution_attempt::ExecutionDeferred>,
}
impl AliasSetupError {
    /// Construct a coded classifier failure.
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            deferred: None,
        }
    }
    /// Borrow the original local refusal; code/message never recreate this owner.
    pub fn deferral(&self) -> Option<&crate::execution_attempt::ExecutionDeferred> {
        self.deferred.as_ref()
    }

    fn from_sns_with_code(code: &'static str, error: crate::sns::SnsError) -> Self {
        if let crate::sns::SnsError::Deferred(reason) = error {
            return Self {
                code: "alias.local_deferred",
                message: String::new(),
                deferred: Some(reason),
            };
        }
        Self::new(code, error.to_string())
    }

    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
    /// Human-readable error detail with no secret material.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}
fn sns_error(error: crate::sns::SnsError) -> AliasSetupError {
    if let crate::sns::SnsError::Deferred(reason) = error {
        return AliasSetupError {
            code: "alias.local_deferred",
            message: String::new(),
            deferred: Some(reason),
        };
    }
    let text = error.to_string();
    let code = if text.contains(crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE) {
        crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE
    } else {
        match error {
            crate::sns::SnsError::NotFound(_)
            | crate::sns::SnsError::RegistrationNotFound { .. } => "alias.mapping.unknown",
            crate::sns::SnsError::BadRequest(_) => "alias.name.invalid",
            crate::sns::SnsError::Conflict(_) => "alias.state.conflict",
            crate::sns::SnsError::Internal(_) => "alias.state.invalid",
            crate::sns::SnsError::Deferred(reason) => {
                return AliasSetupError::from_sns_with_code(
                    "alias.local_deferred",
                    crate::sns::SnsError::Deferred(reason),
                );
            }
        }
    };
    AliasSetupError::new(code, text)
}
/// Build the canonical SNS selector for a resolved target without consulting a static catalog.
///
/// # Errors
///
/// Returns an error if the target name cannot form a valid SNS selector or
/// its account alias is not canonical.
pub fn selector_for_resolved_alias_target(
    target: &AliasTargetV1,
) -> Result<NameSelectorV1, AliasSetupError> {
    match target {
        AliasTargetV1::Dataspace(dataspace) => {
            crate::sns::selector_for_dataspace_alias(dataspace.canonical_name.as_ref())
                .map_err(|error| AliasSetupError::new("alias.name.invalid", error.to_string()))
        }
        AliasTargetV1::Domain(domain) => crate::sns::selector_for_domain(&domain.canonical_name)
            .map_err(|error| AliasSetupError::new("alias.name.invalid", error.to_string())),
        AliasTargetV1::AccountAlias(alias) => {
            if !alias.canonical_name.is_canonical() {
                return Err(AliasSetupError::new(
                    "alias.name.invalid",
                    "account alias text is not canonical",
                ));
            }
            Ok(NameSelectorV1 {
                version: NameSelectorV1::VERSION,
                suffix_id: ACCOUNT_ALIAS_SUFFIX_ID,
                label: alias.canonical_text(),
            })
        }
    }
}
/// Build the immutable SNS metadata committed for a resolved setup target.
///
/// # Errors
///
/// Returns [`AliasSetupError`] if the fixed dataspace-id metadata key cannot be
/// represented by the data model.
pub fn alias_registration_metadata(target: &AliasTargetV1) -> Result<Metadata, AliasSetupError> {
    let mut metadata = Metadata::default();
    if let AliasTargetV1::Dataspace(dataspace) = target {
        metadata.insert(
            SNS_DATASPACE_ID_METADATA_KEY.parse().map_err(|_| {
                AliasSetupError::new(
                    "alias.state.invalid",
                    "dataspace metadata key is not canonical",
                )
            })?,
            Json::new(dataspace.dataspace_id.as_u64()),
        );
    }
    Ok(metadata)
}
/// Borrow the explicit resource owner carried by an alias setup intent.
#[must_use]
pub fn alias_intent_owner(intent: &AliasIntentV1) -> &AccountId {
    match intent {
        AliasIntentV1::Dataspace(value) => &value.owner,
        AliasIntentV1::Domain(value) => &value.owner,
        AliasIntentV1::AccountAlias(value) => &value.target_account,
    }
}
fn expected_controller(owner: &AccountId) -> Result<NameControllerV1, AliasSetupError> {
    AccountAddress::from_account_id(owner)
        .map(|address| NameControllerV1::account(&address))
        .map_err(|error| {
            AliasSetupError::new(
                "alias.controller.invalid",
                format!("failed to derive owner account controller: {error}"),
            )
        })
}
fn validate_text_id_pair(
    world: &impl WorldReadOnly,
    catalog: &DataSpaceCatalog,
    planned_dataspaces: &BTreeMap<iroha_model_base::name::Name, DataSpaceId>,
    target: &AliasTargetV1,
    now_ms: u64,
) -> Result<bool, AliasSetupError> {
    let (name, expected, allow_unknown) = match target {
        AliasTargetV1::Dataspace(value) => {
            (value.canonical_name.as_ref(), value.dataspace_id, true)
        }
        AliasTargetV1::Domain(value) => (
            value.canonical_name.dataspace().as_ref(),
            value.dataspace_id,
            false,
        ),
        AliasTargetV1::AccountAlias(value) => (
            value.canonical_name.dataspace.as_ref(),
            value.dataspace_id,
            false,
        ),
    };
    let planned = planned_dataspaces
        .iter()
        .find_map(|(planned_name, id)| (planned_name.as_ref() == name).then_some(*id));
    match crate::sns::resolve_active_dataspace_id_by_alias(world, catalog, name, now_ms) {
        Ok(actual) if actual == expected && planned.is_none_or(|id| id == expected) => Ok(true),
        Ok(actual) => Err(AliasSetupError::new(
            crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE,
            format!(
                "dataspace alias `{name}` resolves to live id {actual} and planned id {planned:?}, not the single expected id {expected}"
            ),
        )),
        Err(crate::sns::SnsError::NotFound(_)) if allow_unknown => {
            let derived = crate::sns::dataspace_id_for_sns_alias(name).ok_or_else(|| {
                AliasSetupError::new(
                    "alias.name.invalid",
                    format!("cannot derive a numeric id for dataspace alias `{name}`"),
                )
            })?;
            if derived != expected || planned.is_some_and(|id| id != expected) {
                return Err(AliasSetupError::new(
                    crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE,
                    format!(
                        "new dataspace alias `{name}` must use deterministic id {derived}, not {expected}"
                    ),
                ));
            }
            if let Some((planned_name, _)) = planned_dataspaces
                .iter()
                .find(|(planned_name, id)| **id == expected && planned_name.as_ref() != name)
            {
                return Err(AliasSetupError::new(
                    crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE,
                    format!(
                        "new dataspace alias `{name}` derives id {expected}, which is already planned for `{planned_name}`"
                    ),
                ));
            }
            match crate::sns::resolve_active_dataspace_alias_by_id(world, catalog, expected, now_ms)
            {
                Ok(existing_name) if existing_name != name => {
                    return Err(AliasSetupError::new(
                        crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE,
                        format!(
                            "new dataspace alias `{name}` derives id {expected}, which is already mapped to `{existing_name}`"
                        ),
                    ));
                }
                Ok(_) => {
                    return Err(AliasSetupError::new(
                        crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE,
                        format!(
                            "dataspace id {expected} has live reverse mapping evidence that is missing from the forward alias lookup for `{name}`"
                        ),
                    ));
                }
                Err(crate::sns::SnsError::NotFound(_)) => {}
                Err(error) => return Err(sns_error(error)),
            }
            Ok(false)
        }
        Err(crate::sns::SnsError::NotFound(_)) if planned == Some(expected) => Ok(false),
        Err(crate::sns::SnsError::NotFound(_)) => match planned {
            Some(planned) => Err(AliasSetupError::new(
                crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE,
                format!(
                    "planned dataspace alias `{name}` maps to {planned}, not expected id {expected}"
                ),
            )),
            None => Err(AliasSetupError::new(
                "alias.catalog.unknown_mapping",
                format!("dataspace alias `{name}` is not registered"),
            )),
        },
        Err(error) => Err(sns_error(error)),
    }
}
/// Revalidate a resolved target's canonical text against its pinned dataspace ID.
///
/// # Errors
///
/// Returns [`AliasSetupError`] for unknown or conflicting live static/SNS
/// mappings, or for a non-deterministic ID on a new dataspace target.
pub fn validate_resolved_alias_target(
    world: &impl WorldReadOnly,
    catalog: &DataSpaceCatalog,
    target: &AliasTargetV1,
    now_ms: u64,
) -> Result<(), AliasSetupError> {
    validate_text_id_pair(world, catalog, &BTreeMap::new(), target, now_ms).map(|_| ())
}
/// Verify a recomputed lease quote against a caller's bounded guard.
///
/// This helper is intentionally separate from classification. Execution must
/// call it only for [`AliasPlanDispositionV1::Create`] so exact replay and
/// repair cannot fail a stale guard or incur a second charge.
///
/// # Errors
///
/// Returns [`AliasSetupError`] when the guard has expired, its policy version or payment asset
/// differs from live policy, or the exact charge exceeds the authorized cap.
pub fn validate_alias_quote_guard(
    world: &impl WorldReadOnly,
    quote: &crate::sns::LeaseQuote,
    guard: &AliasQuoteGuardV1,
    now_ms: u64,
) -> Result<(), AliasSetupError> {
    if now_ms > guard.valid_until_ms {
        return Err(AliasSetupError::new(
            "alias.quote.expired",
            format!(
                "quote guard expired at {}, current block time is {now_ms}",
                guard.valid_until_ms
            ),
        ));
    }
    let policy = crate::sns::policy_by_id(world, quote.selector.suffix_id)
        .map_err(|error| AliasSetupError::from_sns_with_code("alias.quote.policy_invalid", error))?
        .ok_or_else(|| {
            AliasSetupError::new(
                "alias.quote.policy_missing",
                format!(
                    "SNS policy {} disappeared while validating the quote",
                    quote.selector.suffix_id
                ),
            )
        })?;
    if policy.policy_version != guard.expected_policy_version {
        return Err(AliasSetupError::new(
            "alias.quote.policy_version_mismatch",
            format!(
                "expected policy version {}, actual version is {}",
                guard.expected_policy_version, policy.policy_version
            ),
        ));
    }
    if quote.payment_asset_definition_id != guard.expected_payment_asset {
        return Err(AliasSetupError::new(
            "alias.quote.payment_asset_mismatch",
            format!(
                "expected payment asset `{}`, actual asset is `{}`",
                guard.expected_payment_asset, quote.payment_asset_definition_id
            ),
        ));
    }
    if quote.charge_amount > guard.max_amount {
        return Err(AliasSetupError::new(
            "alias.quote.cap_exceeded",
            format!(
                "exact charge {} exceeds authorized cap {}",
                quote.charge_amount, guard.max_amount
            ),
        ));
    }
    Ok(())
}
fn authority_can_manage_alias_target(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    target: &AliasTargetV1,
) -> Result<bool, crate::sns::SnsError> {
    match target {
        AliasTargetV1::Dataspace(value) => crate::alias::authority_can_manage_account_alias_scope(
            world,
            authority,
            value.dataspace_id,
            None,
        ),
        AliasTargetV1::Domain(value) => crate::alias::authority_can_manage_account_alias_scope(
            world,
            authority,
            value.dataspace_id,
            Some(&value.canonical_name),
        ),
        AliasTargetV1::AccountAlias(value) => {
            crate::alias::authority_can_manage_resolved_account_alias(world, authority, value)
        }
    }
}
/// Verify that a setup transaction authority may create or repair an intent.
///
/// The explicit resource owner may always ensure its own resource. Provisioning
/// for another account requires the exact applicable alias-management scope;
/// broad dataspace authority never substitutes for a domain-qualified alias.
///
/// # Errors
///
/// Returns [`AliasSetupError`] when the authority is neither the explicit owner
/// nor an exact-scope alias manager.
pub fn validate_alias_intent_authority(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    intent: &AliasIntentV1,
) -> Result<(), AliasSetupError> {
    if alias_intent_owner(intent) == authority
        || authority_can_manage_alias_target(world, authority, &intent.target())
            .map_err(sns_error)?
    {
        return Ok(());
    }
    Err(AliasSetupError::new(
        "alias.setup.authority_forbidden",
        "authority must own or hold exact management permission for the alias intent",
    ))
}
fn active_alias_lifecycle_record(
    world: &impl WorldReadOnly,
    catalog: &DataSpaceCatalog,
    target: &AliasTargetV1,
    now_ms: u64,
) -> Result<(NameSelectorV1, NameRecordV1), AliasSetupError> {
    validate_resolved_alias_target(world, catalog, target, now_ms)?;
    let selector = selector_for_resolved_alias_target(target)?;
    let record =
        crate::sns::get_name_record_by_selector(world, &selector, now_ms).map_err(sns_error)?;
    if !matches!(record.status, NameStatus::Active) {
        return Err(AliasSetupError::new(
            "alias.lifecycle.conflict",
            format!(
                "alias `{}` is not active",
                record.selector.normalized_label()
            ),
        ));
    }
    Ok((selector, record))
}
/// Classify and quote one guarded absolute-expiry lease renewal without mutation.
///
/// The returned quote is the exact quote execution will recompute. Text/ID
/// resolution, active lease state, the expiry CAS, lifecycle authority, policy,
/// payment asset, cap, and deadline are all checked against one live state view.
///
/// # Errors
///
/// Returns [`AliasSetupError`] for mapping, ownership/permission, lifecycle,
/// expiry-CAS, policy, asset, cap, or deadline conflicts.
pub fn classify_alias_lease_renewal(
    world: &impl WorldReadOnly,
    catalog: &DataSpaceCatalog,
    authority: &AccountId,
    renewal: &RenewAliasLease,
    now_ms: u64,
) -> Result<crate::sns::LeaseQuote, AliasSetupError> {
    let (selector, record) =
        active_alias_lifecycle_record(world, catalog, &renewal.target, now_ms)?;
    if record.owner != *authority
        && !authority_can_manage_alias_target(world, authority, &renewal.target)
            .map_err(sns_error)?
    {
        return Err(AliasSetupError::new(
            "alias.lifecycle.authority_forbidden",
            "authority must own or hold exact management permission for the alias target",
        ));
    }
    let quote = crate::sns::quote_resolved_name_renewal(
        world,
        selector,
        renewal.expected_current_expiry_ms,
        renewal.target_expiry_ms,
        now_ms,
    )
    .map_err(sns_error)?;
    validate_alias_quote_guard(world, &quote, &renewal.quote_guard, now_ms)?;
    Ok(quote)
}
fn policy_payment_asset(
    policy: &iroha_data_model::sns::SuffixPolicyV1,
) -> Result<AssetDefinitionId, AliasSetupError> {
    if let Ok(asset_id) = AssetId::parse_literal(&policy.payment_asset_id) {
        return Ok(asset_id.definition().clone());
    }
    AssetDefinitionId::parse_address_literal(&policy.payment_asset_id).map_err(|error| {
        AliasSetupError::new(
            "alias.auto_renew.policy_invalid",
            format!("SNS policy contains invalid payment asset: {error}"),
        )
    })
}
pub(crate) fn validate_alias_auto_renew_ranges(
    config: &AliasAutoRenewConfigV1,
) -> Result<(), AliasSetupError> {
    let term_duration_ms = u64::from(config.term_years)
        .saturating_mul(iroha_data_model::alias_setup::ALIAS_LEASE_YEAR_MS);
    if config.term_years == 0
        || config.renew_before_expiry_ms == 0
        || config.retry_backoff_ms == 0
        || config.max_failures == 0
    {
        return Err(AliasSetupError::new(
            "alias.auto_renew.range_invalid",
            "auto-renew term, renewal window, retry interval, and failure limit must be nonzero",
        ));
    }
    if config.renew_before_expiry_ms >= term_duration_ms {
        return Err(AliasSetupError::new(
            "alias.auto_renew.range_invalid",
            format!(
                "auto-renew window {}ms must be shorter than the {}ms renewal term",
                config.renew_before_expiry_ms, term_duration_ms
            ),
        ));
    }
    Ok(())
}
fn validate_alias_auto_renew_config(
    world: &impl WorldReadOnly,
    target: &AliasTargetV1,
    config: &AliasAutoRenewConfigV1,
) -> Result<(), AliasSetupError> {
    validate_alias_auto_renew_ranges(config)?;
    let suffix_id = target_suffix_id(target);
    let policy = crate::sns::policy_by_id(world, suffix_id)
        .map_err(|error| {
            AliasSetupError::from_sns_with_code("alias.auto_renew.policy_invalid", error)
        })?
        .ok_or_else(|| {
            AliasSetupError::new(
                "alias.auto_renew.policy_missing",
                format!("SNS policy {suffix_id} is missing for the auto-renew target"),
            )
        })?;
    if config.term_years < policy.min_term_years || config.term_years > policy.max_term_years {
        return Err(AliasSetupError::new(
            "alias.auto_renew.term_out_of_range",
            format!(
                "auto-renew term {} is outside policy range {}..={}",
                config.term_years, policy.min_term_years, policy.max_term_years
            ),
        ));
    }
    if config.policy_version != policy.policy_version {
        return Err(AliasSetupError::new(
            "alias.auto_renew.policy_drift",
            format!(
                "expected policy version {}, actual version is {}",
                config.policy_version, policy.policy_version
            ),
        ));
    }
    let payment_asset = policy_payment_asset(&policy)?;
    if config.payment_asset != payment_asset {
        return Err(AliasSetupError::new(
            "alias.auto_renew.asset_drift",
            format!(
                "expected payment asset `{}`, actual asset is `{payment_asset}`",
                config.payment_asset
            ),
        ));
    }
    Ok(())
}
/// Classify one owner-only auto-renew configuration CAS without mutation.
///
/// Exact persisted configuration with clean runtime state is a no-op even when
/// replay carries the previous revision. A changed configuration, disable, or
/// reset of retry/suspension state requires `Apply` and an exact live revision.
/// After rekey, even identical configuration must explicitly adopt the current
/// lease owner; the prior owner's debit authorization is never a no-op.
///
/// # Errors
///
/// Returns [`AliasSetupError`] for mapping, lease state, owner, revision,
/// configuration-range, policy-version, or payment-asset conflicts.
pub fn classify_alias_auto_renew(
    world: &impl WorldReadOnly,
    catalog: &DataSpaceCatalog,
    authority: &AccountId,
    operation: &ConfigureAliasAutoRenew,
    now_ms: u64,
) -> Result<AliasLifecyclePlanDispositionV1, AliasSetupError> {
    let (_, record) = active_alias_lifecycle_record(world, catalog, &operation.target, now_ms)?;
    if record.owner != *authority {
        return Err(AliasSetupError::new(
            "alias.auto_renew.owner_forbidden",
            "only the exact alias resource owner may configure auto-renew",
        ));
    }
    let current =
        crate::sns::alias_auto_renew_state(world, &operation.target).map_err(sns_error)?;
    // The current authenticated lease owner can adopt a stale configuration
    // only through the exact revision CAS below. Rekey is not an implicit debit
    // authorization for the new account.
    if cfg!(all(test, sumeragi_core_mutation = "HC42"))
        && let Some(current) = current.as_ref()
        && current.owner != record.owner
    {
        return Err(AliasSetupError::new(
            "alias.auto_renew.owner_conflict",
            "persisted auto-renew owner differs from the lease owner",
        ));
    }
    if let Some(config) = operation.config.as_ref() {
        validate_alias_auto_renew_config(world, &operation.target, config)?;
    }
    let exact_clean_state = current.as_ref().map_or_else(
        || operation.config.is_none(),
        |current| {
            current.owner == record.owner
                && current.config == operation.config
                && current.failure_count == 0
                && current.next_retry_at_ms.is_none()
                && current.suspended_reason.is_none()
        },
    );
    if exact_clean_state {
        return Ok(AliasLifecyclePlanDispositionV1::NoOp);
    }
    let current_revision = current.as_ref().map_or(0, |state| state.revision);
    if current_revision != operation.expected_revision {
        return Err(AliasSetupError::new(
            "alias.auto_renew.revision_conflict",
            format!(
                "expected revision {}, actual revision is {current_revision}",
                operation.expected_revision
            ),
        ));
    }
    Ok(AliasLifecyclePlanDispositionV1::Apply)
}
fn existing_record(
    world: &impl WorldReadOnly,
    selector: &NameSelectorV1,
    now_ms: u64,
) -> Result<Option<NameRecordV1>, AliasSetupError> {
    match crate::sns::get_name_record_by_selector(world, selector, now_ms) {
        Ok(record) => Ok(Some(record)),
        Err(crate::sns::SnsError::RegistrationNotFound { .. }) => Ok(None),
        Err(error) => Err(sns_error(error)),
    }
}
fn ensure_active_parent_record(
    world: &impl WorldReadOnly,
    target: &AliasTargetV1,
    now_ms: u64,
) -> Result<(), AliasSetupError> {
    let selector = selector_for_resolved_alias_target(target)?;
    let Some(record) = existing_record(world, &selector, now_ms)? else {
        return Err(AliasSetupError::new(
            "alias.parent.missing",
            format!("required parent lease `{target}` is absent"),
        ));
    };
    if !matches!(record.status, NameStatus::Active) {
        return Err(AliasSetupError::new(
            "alias.parent.inactive",
            format!("required parent lease `{target}` is not active"),
        ));
    }
    Ok(())
}
fn validate_parent_resource(
    world: &impl WorldReadOnly,
    planned_dataspaces: &BTreeMap<iroha_model_base::name::Name, DataSpaceId>,
    planned_domains: &BTreeSet<iroha_model_base::domain::DomainId>,
    intent: &AliasIntentV1,
    now_ms: u64,
) -> Result<(), AliasSetupError> {
    let dataspace_is_planned = |name: &iroha_model_base::name::Name, id: DataSpaceId| {
        planned_dataspaces
            .get(name)
            .is_some_and(|planned| *planned == id)
    };
    match intent {
        AliasIntentV1::Dataspace(_) => Ok(()),
        AliasIntentV1::Domain(value) => {
            let parent = value.domain.parent_dataspace();
            if dataspace_is_planned(&parent.canonical_name, parent.dataspace_id) {
                Ok(())
            } else {
                ensure_active_parent_record(world, &AliasTargetV1::Dataspace(parent), now_ms)
            }
        }
        AliasIntentV1::AccountAlias(value) => {
            if let Some(parent) = value.alias.parent_domain() {
                if planned_domains.contains(&parent.canonical_name) {
                    return Ok(());
                }
                ensure_active_parent_record(world, &AliasTargetV1::Domain(parent.clone()), now_ms)?;
                if world.domains().get(&parent.canonical_name).is_none() {
                    return Err(AliasSetupError::new(
                        "alias.parent.missing",
                        format!(
                            "required parent domain `{}` is missing its derived domain state",
                            parent.canonical_name
                        ),
                    ));
                }
                Ok(())
            } else {
                let parent = iroha_data_model::alias_setup::ResolvedDataSpaceV1::new(
                    value.alias.canonical_name.dataspace.clone(),
                    value.alias.dataspace_id,
                );
                if dataspace_is_planned(&parent.canonical_name, parent.dataspace_id) {
                    Ok(())
                } else {
                    ensure_active_parent_record(world, &AliasTargetV1::Dataspace(parent), now_ms)
                }
            }
        }
    }
}
fn validate_existing_record(
    record: &NameRecordV1,
    owner: &AccountId,
    target: &AliasTargetV1,
) -> Result<(), AliasSetupError> {
    if !matches!(record.status, NameStatus::Active) {
        return Err(AliasSetupError::new(
            "alias.lifecycle.conflict",
            format!(
                "alias `{}` is not active",
                record.selector.normalized_label()
            ),
        ));
    }
    if &record.owner != owner {
        return Err(AliasSetupError::new(
            "alias.owner.conflict",
            format!(
                "alias `{}` is owned by `{}`, not `{owner}`",
                record.selector.normalized_label(),
                record.owner
            ),
        ));
    }
    let expected_controllers = [expected_controller(owner)?];
    if record.controllers.as_slice() != expected_controllers {
        return Err(AliasSetupError::new(
            "alias.controller.conflict",
            format!(
                "alias `{}` controller set differs from its exact owner controller",
                record.selector.normalized_label()
            ),
        ));
    }
    if record.metadata != alias_registration_metadata(target)? {
        return Err(AliasSetupError::new(
            "alias.metadata.conflict",
            format!(
                "alias `{}` immutable setup metadata differs",
                record.selector.normalized_label()
            ),
        ));
    }
    Ok(())
}
fn exact_permission_scope(intent: &AliasIntentV1) -> AccountAliasPermissionScope {
    match intent {
        AliasIntentV1::Dataspace(value) => {
            AccountAliasPermissionScope::Dataspace(value.dataspace.dataspace_id)
        }
        AliasIntentV1::Domain(value) => {
            AccountAliasPermissionScope::Domain(value.domain.canonical_name.clone())
        }
        AliasIntentV1::AccountAlias(value) => {
            AccountAliasPermissionScope::Alias(value.alias.clone())
        }
    }
}
/// Return the exact automatic manage/delegate/resolve permission bundle for an intent owner.
#[must_use]
pub fn exact_alias_permission_bundle(intent: &AliasIntentV1) -> [Permission; 3] {
    let scope = exact_permission_scope(intent);
    [
        CanManageAccountAlias {
            scope: scope.clone(),
        }
        .into(),
        CanDelegateAccountAliasResolution {
            scope: scope.clone(),
        }
        .into(),
        CanResolveAccountAlias { scope }.into(),
    ]
}
fn exact_permissions_present(world: &impl WorldReadOnly, intent: &AliasIntentV1) -> bool {
    let owner = alias_intent_owner(intent);
    exact_alias_permission_bundle(intent)
        .iter()
        .all(|permission| world.account_contains_inherent_permission(owner, permission))
}
fn classify_domain_state(
    world: &impl WorldReadOnly,
    intent: &iroha_data_model::alias_setup::AliasDomainIntentV1,
) -> Result<bool, AliasSetupError> {
    for (indexed_owner, domains) in world.domains_by_owner().iter() {
        if domains.contains(&intent.domain.canonical_name) && indexed_owner != &intent.owner {
            return Err(AliasSetupError::new(
                "alias.owner.conflict",
                format!(
                    "domain `{}` is indexed under owner `{indexed_owner}`, not `{}`",
                    intent.domain, intent.owner
                ),
            ));
        }
    }
    let owner_index_missing = !world
        .domains_by_owner()
        .get(&intent.owner)
        .is_some_and(|domains| domains.contains(&intent.domain.canonical_name));
    let Some(domain) = world.domains().get(&intent.domain.canonical_name) else {
        return Ok(true);
    };
    if domain.owned_by() != &intent.owner {
        return Err(AliasSetupError::new(
            "alias.owner.conflict",
            format!(
                "domain `{}` is owned by `{}`, not `{}`",
                intent.domain,
                domain.owned_by(),
                intent.owner
            ),
        ));
    }
    if !domain.metadata().is_empty() {
        return Err(AliasSetupError::new(
            "alias.metadata.conflict",
            format!(
                "domain `{}` immutable setup metadata differs",
                intent.domain
            ),
        ));
    }
    Ok(owner_index_missing)
}
fn classify_account_state(
    world: &impl WorldReadOnly,
    intent: &iroha_data_model::alias_setup::AliasAccountIntentV1,
) -> Result<bool, AliasSetupError> {
    let account = world.accounts().get(&intent.target_account);
    if account.is_none() && matches!(intent.provision, AccountProvisionV1::Existing) {
        return Err(AliasSetupError::new(
            "alias.account.missing",
            format!("target account `{}` does not exist", intent.target_account),
        ));
    }
    let alias = intent.alias.account_alias();
    match world.account_aliases().get(&alias) {
        Some(existing) if existing != &intent.target_account => {
            return Err(AliasSetupError::new(
                "alias.binding.conflict",
                format!("account alias is bound to `{existing}`"),
            ));
        }
        _ => {}
    }
    if let Some(account) = account {
        match intent.role {
            AccountAliasRoleV1::Primary => match account.label() {
                Some(existing) if existing != &alias => {
                    return Err(AliasSetupError::new(
                        "alias.primary.conflict",
                        "target account already has a different primary alias",
                    ));
                }
                _ => {}
            },
            AccountAliasRoleV1::Additional if account.label() == Some(&alias) => {
                return Err(AliasSetupError::new(
                    "alias.primary.conflict",
                    "account alias is primary but the intent requires an additional alias",
                ));
            }
            AccountAliasRoleV1::Additional => {}
        }
    }
    for (indexed_account, aliases) in world.account_aliases_by_account().iter() {
        if aliases.contains(&alias) && indexed_account != &intent.target_account {
            return Err(AliasSetupError::new(
                "alias.binding.conflict",
                format!(
                    "account alias reverse index is bound to `{indexed_account}`, not `{}`",
                    intent.target_account
                ),
            ));
        }
    }
    for (account_id, indexed_account) in world.accounts().iter() {
        if account_id != &intent.target_account && indexed_account.label() == Some(&alias) {
            return Err(AliasSetupError::new(
                "alias.primary.conflict",
                format!(
                    "account alias is already primary for `{account_id}`, not `{}`",
                    intent.target_account
                ),
            ));
        }
    }
    if let Some(record) = world.account_rekey_records().get(&alias) {
        if record.label != alias {
            return Err(AliasSetupError::new(
                "alias.binding.conflict",
                "account rekey record identity differs from its storage key",
            ));
        }
        if record.active_account_id != intent.target_account {
            return Err(AliasSetupError::new(
                "alias.binding.conflict",
                format!(
                    "account rekey record targets `{}`, not `{}`",
                    record.active_account_id, intent.target_account
                ),
            ));
        }
    }
    let account_missing = account.is_none();
    let binding_missing = world.account_aliases().get(&alias).is_none();
    let reverse_missing = !world
        .account_aliases_by_account()
        .get(&intent.target_account)
        .is_some_and(|aliases| aliases.contains(&alias));
    let rekey_missing = world.account_rekey_records().get(&alias).is_none();
    let primary_missing = matches!(intent.role, AccountAliasRoleV1::Primary)
        && account.is_some_and(|account| account.label().is_none());
    let scope_missing = account.is_some_and(|_| {
        let required_domain = alias.domain.as_ref();
        !world
            .account_scope_directory()
            .get(&intent.target_account)
            .is_some_and(|entry| {
                entry.iter().any(|(dataspace, domains)| {
                    *dataspace == alias.dataspace
                        && required_domain.is_none_or(|domain| domains.contains(domain))
                })
            })
            || required_domain.is_some_and(|domain| {
                !world
                    .account_scope_accounts()
                    .get(&(alias.dataspace, domain.clone()))
                    .is_some_and(|accounts| accounts.contains(&intent.target_account))
            })
    });
    Ok(account_missing
        || binding_missing
        || reverse_missing
        || rekey_missing
        || primary_missing
        || scope_missing)
}
/// Classify one declarative intent against live state without mutating or quoting it.
///
/// Exact existing state returns [`AliasPlanDispositionV1::NoOp`]. Missing derived
/// state or exact owner permissions returns [`AliasPlanDispositionV1::Repair`]. An
/// absent lease returns [`AliasPlanDispositionV1::Create`]. Any authoritative drift
/// returns a coded [`AliasSetupError`] and is never overwritten.
///
/// # Errors
///
/// Returns [`AliasSetupError`] for unknown/mismatched text-to-ID mappings, inactive
/// leases, owner/controller/metadata drift, binding drift, primary drift, or a
/// missing account required by [`AccountProvisionV1::Existing`].
pub fn classify_alias_intent(
    world: &impl WorldReadOnly,
    catalog: &DataSpaceCatalog,
    intent: &AliasIntentV1,
    now_ms: u64,
) -> Result<AliasPlanDispositionV1, AliasSetupError> {
    classify_alias_intent_with_planned_parents_and_endorsement_policy(
        world,
        catalog,
        &BTreeMap::new(),
        &BTreeSet::new(),
        intent,
        now_ms,
        false,
    )
}
/// Classify one declarative intent while enforcing the live domain-endorsement policy.
///
/// Per-domain policy stored in `world` overrides `default_domain_endorsement_required`, matching
/// domain registration. Because [`iroha_data_model::alias_setup::AliasDomainIntentV1`] cannot carry
/// immutable endorsement metadata, an absent domain that requires it is blocked before an
/// executable acquisition disposition can be returned.
///
/// # Errors
///
/// Returns the same coded failures as [`classify_alias_intent`], and
/// `alias.domain.endorsement_required` when an absent domain cannot be created
/// from the declarative setup model under the active policy.
pub fn classify_alias_intent_with_endorsement_policy(
    world: &impl WorldReadOnly,
    catalog: &DataSpaceCatalog,
    intent: &AliasIntentV1,
    now_ms: u64,
    default_domain_endorsement_required: bool,
) -> Result<AliasPlanDispositionV1, AliasSetupError> {
    classify_alias_intent_with_planned_parents_and_endorsement_policy(
        world,
        catalog,
        &BTreeMap::new(),
        &BTreeSet::new(),
        intent,
        now_ms,
        default_domain_endorsement_required,
    )
}
#[cfg(test)]
/// Classify an ordered intent while accepting exact parent dataspaces planned earlier.
///
/// `planned_dataspaces` must contain only canonical text/ID pairs from preceding dataspace intents
/// in the same unsplit transaction plan. Live static/SNS evidence remains authoritative: a
/// conflicting live or planned pair fails closed with `alias.catalog.mapping_conflict`.
///
/// # Errors
///
/// Returns the same coded drift errors as [`classify_alias_intent`], plus any
/// conflict between a planned parent, live state, and the child's pinned ID.
pub fn classify_alias_intent_with_planned_dataspaces(
    world: &impl WorldReadOnly,
    catalog: &DataSpaceCatalog,
    planned_dataspaces: &BTreeMap<iroha_model_base::name::Name, DataSpaceId>,
    intent: &AliasIntentV1,
    now_ms: u64,
) -> Result<AliasPlanDispositionV1, AliasSetupError> {
    classify_alias_intent_with_planned_parents(
        world,
        catalog,
        planned_dataspaces,
        &BTreeSet::new(),
        intent,
        now_ms,
    )
}
#[cfg(test)]
/// Classify an ordered intent while accepting exact parent resources planned earlier.
///
/// The planner supplies only successfully classified preceding dataspace and domain resources.
/// Execution calls [`classify_alias_intent`] instead, so each parent must already be active in the
/// transaction overlay before its child is evaluated.
///
/// # Errors
///
/// Returns the same coded drift errors as [`classify_alias_intent`], including
/// absent, inactive, or conflicting parent resources.
pub fn classify_alias_intent_with_planned_parents(
    world: &impl WorldReadOnly,
    catalog: &DataSpaceCatalog,
    planned_dataspaces: &BTreeMap<iroha_model_base::name::Name, DataSpaceId>,
    planned_domains: &BTreeSet<iroha_model_base::domain::DomainId>,
    intent: &AliasIntentV1,
    now_ms: u64,
) -> Result<AliasPlanDispositionV1, AliasSetupError> {
    classify_alias_intent_with_planned_parents_and_endorsement_policy(
        world,
        catalog,
        planned_dataspaces,
        planned_domains,
        intent,
        now_ms,
        false,
    )
}
/// Classify an ordered intent while enforcing the live domain-endorsement policy.
///
/// This is the policy-aware form of [`classify_alias_intent_with_planned_parents`]. Per-domain
/// policy stored in `world` overrides `default_domain_endorsement_required`, exactly as it does
/// during consensus domain registration.
///
/// # Errors
///
/// Returns the same coded failures as [`classify_alias_intent_with_planned_parents`],
/// and `alias.domain.endorsement_required` when an absent domain cannot be
/// represented by the declarative setup intent under the active policy.
pub fn classify_alias_intent_with_planned_parents_and_endorsement_policy(
    world: &impl WorldReadOnly,
    catalog: &DataSpaceCatalog,
    planned_dataspaces: &BTreeMap<iroha_model_base::name::Name, DataSpaceId>,
    planned_domains: &BTreeSet<iroha_model_base::domain::DomainId>,
    intent: &AliasIntentV1,
    now_ms: u64,
    default_domain_endorsement_required: bool,
) -> Result<AliasPlanDispositionV1, AliasSetupError> {
    if !matches!(intent, AliasIntentV1::AccountAlias(value) if matches!(value.provision, AccountProvisionV1::Create))
        && world.accounts().get(alias_intent_owner(intent)).is_none()
    {
        return Err(AliasSetupError::new(
            "alias.owner.missing",
            format!(
                "resource owner `{}` does not exist",
                alias_intent_owner(intent)
            ),
        ));
    }
    let target = intent.target();
    validate_text_id_pair(world, catalog, planned_dataspaces, &target, now_ms)?;
    validate_parent_resource(world, planned_dataspaces, planned_domains, intent, now_ms)?;
    let selector = selector_for_resolved_alias_target(&target)?;
    let record = existing_record(world, &selector, now_ms)?;
    if let Some(record) = &record {
        validate_existing_record(record, alias_intent_owner(intent), &target)?;
    }
    if record.is_none()
        && let AliasIntentV1::Dataspace(value) = intent
    {
        let grant = dataspace_bootstrap_grant(world, &selector)?;
        if let Some(grant) = grant {
            if grant.dataspace != value.dataspace || grant.owner != value.owner {
                return Err(AliasSetupError::new(
                    "alias.catalog.bootstrap_grant_conflict",
                    "dataspace setup must match the exact governed bootstrap grant and owner",
                ));
            }
        } else if catalog.by_id(value.dataspace.dataspace_id).is_some() {
            return Err(AliasSetupError::new(
                CATALOGUED_DATASPACE_BOOTSTRAP_REQUIRED_CODE,
                format!(
                    "catalogued dataspace `{}` ({}) must be bound by the governed genesis bootstrap before public alias setup",
                    value.dataspace.canonical_name, value.dataspace.dataspace_id
                ),
            ));
        }
    }
    let resource_needs_repair = match intent {
        AliasIntentV1::Dataspace(_) => false,
        AliasIntentV1::Domain(value) => {
            let needs_repair = classify_domain_state(world, value)?;
            if world.domains().get(&value.domain.canonical_name).is_none()
                && world
                    .domain_endorsement_policies()
                    .get(&value.domain.canonical_name)
                    .map_or(default_domain_endorsement_required, |policy| {
                        policy.required
                    })
            {
                return Err(AliasSetupError::new(
                    "alias.domain.endorsement_required",
                    format!(
                        "domain `{}` requires immutable endorsement metadata that AliasDomainIntentV1 cannot carry; create it through governed bootstrap/domain registration before requesting alias setup",
                        value.domain
                    ),
                ));
            }
            needs_repair
        }
        AliasIntentV1::AccountAlias(value) => classify_account_state(world, value)?,
    };
    if record.is_none() {
        // A catalogued dataspace reaches this branch only with an exact, replayed governance
        // grant installed before its first record. Unreserved dynamic mappings remain public.
        return Ok(AliasPlanDispositionV1::Create);
    }
    if resource_needs_repair || !exact_permissions_present(world, intent) {
        return Ok(AliasPlanDispositionV1::Repair);
    }
    Ok(AliasPlanDispositionV1::NoOp)
}
/// Return the namespace suffix expected for a resolved target.
#[must_use]
pub const fn target_suffix_id(target: &AliasTargetV1) -> u16 {
    match target {
        AliasTargetV1::Dataspace(_) => DATASPACE_ALIAS_SUFFIX_ID,
        AliasTargetV1::Domain(_) => DOMAIN_NAME_SUFFIX_ID,
        AliasTargetV1::AccountAlias(_) => ACCOUNT_ALIAS_SUFFIX_ID,
    }
}
/// Verify that the target namespace policy uses the configured, registered fee asset.
///
/// Planning calls this only after classifying an operation that will actually acquire or renew a
/// lease. This preserves free no-op and repair semantics while ensuring every executable quote
/// passes the same policy/configuration check as consensus execution.
///
/// # Errors
///
/// Returns [`AliasSetupError`] when the namespace is unknown, the configured fee asset is invalid
/// or absent, or either the policy or a pricing tier names a different payment asset.
pub fn validate_configured_alias_payment_asset(
    world: &impl WorldReadOnly,
    target: &AliasTargetV1,
    configured_fee_asset_selector: &str,
) -> Result<(), AliasSetupError> {
    let namespace =
        crate::sns::SnsNamespace::from_suffix_id(target_suffix_id(target)).map_err(sns_error)?;
    crate::sns::ensure_namespace_policy_payment_asset_matches_configured(
        world,
        namespace,
        configured_fee_asset_selector,
    )
    .map_err(|error| AliasSetupError::new("alias.quote.payment_asset_mismatch", error.to_string()))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sns::record_storage_key, state::World};
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        Registrable,
        account::{
            Account, AccountAddress,
            rekey::{AccountAlias, AccountRekeyRecord},
        },
        alias_setup::{
            AccountAliasName, AliasAccountIntentV1, AliasDataSpaceIntentV1, AliasDomainIntentV1,
            ResolvedDataSpaceV1, ResolvedDomainV1,
        },
        asset::{AssetDefinition, AssetDefinitionId},
        nexus::DataSpaceMetadata,
        sns::{NameControllerV1, NameRecordV1},
    };
    use iroha_model_base::topology::DataSpaceId;
    use norito::codec::Encode;
    use std::collections::BTreeSet;
    fn account(seed: u8) -> AccountId {
        let pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive alias classifier fixture keypair");
        AccountId::new(pair.public_key().clone())
    }
    fn world_with_accounts(accounts: &[AccountId]) -> World {
        World::with(
            [],
            accounts.iter().map(|id| Account::new(id.clone()).build(id)),
            [],
        )
    }
    fn set_primary_label_for_testing(world: &World, account_id: &AccountId, label: AccountAlias) {
        let (account_id, account_value) = iroha_data_model::IntoKeyValue::into_key_value(
            Account::new(account_id.clone())
                .with_label(Some(label))
                .build(account_id),
        );
        let mut block = world.block();
        {
            let mut transaction = block.transaction_without_telemetry(
                iroha_config::parameters::actual::LaneConfig::default(),
                0,
            );
            transaction.insert_account_for_testing(account_id, account_value);
            transaction.apply();
        }
        block.commit();
    }
    fn insert_record(world: &mut World, intent: &AliasIntentV1, owner: AccountId) {
        let target = intent.target();
        let selector = selector_for_resolved_alias_target(&target).expect("resolved selector");
        let address = AccountAddress::from_account_id(&owner).expect("controller address");
        let record = NameRecordV1::new(
            selector.clone(),
            owner,
            vec![NameControllerV1::account(&address)],
            0,
            0,
            10_000,
            20_000,
            30_000,
            alias_registration_metadata(&target).expect("setup metadata"),
        );
        world
            .smart_contract_state_mut_for_testing()
            .insert(record_storage_key(&selector), record.encode());
    }
    fn dynamic_dataspace_intent(owner: AccountId) -> AliasIntentV1 {
        let name: iroha_model_base::name::Name = "paynet".parse().expect("dataspace name");
        let dataspace_id = crate::sns::dataspace_id_for_sns_alias(name.as_ref())
            .expect("deterministic dataspace id");
        AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: ResolvedDataSpaceV1::new(name, dataspace_id),
            owner,
        })
    }
    #[test]
    fn absent_dataspace_is_create_and_requires_deterministic_id() {
        let owner = account(1);
        let world = world_with_accounts(core::slice::from_ref(&owner));
        let catalog = DataSpaceCatalog::new(Vec::new()).expect("empty dynamic catalog");
        let intent = dynamic_dataspace_intent(owner.clone());
        assert_eq!(
            classify_alias_intent(&world.view(), &catalog, &intent, 1).expect("classify create"),
            AliasPlanDispositionV1::Create
        );
        let AliasIntentV1::Dataspace(mut wrong) = intent else {
            unreachable!()
        };
        wrong.dataspace.dataspace_id = DataSpaceId::new(99);
        let error =
            classify_alias_intent(&world.view(), &catalog, &AliasIntentV1::Dataspace(wrong), 1)
                .expect_err("arbitrary new dataspace id must fail");
        assert_eq!(
            error.code(),
            crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE
        );
    }
    #[test]
    fn ungranted_dataspace_preserves_legacy_selector_normalization() {
        let owner = account(23);
        let world = world_with_accounts(core::slice::from_ref(&owner));
        let catalog = DataSpaceCatalog::new(Vec::new()).expect("empty dynamic catalog");
        let AliasIntentV1::Dataspace(mut intent) = dynamic_dataspace_intent(owner) else {
            unreachable!()
        };
        intent.dataspace.canonical_name = "PAYNET".parse().expect("legacy raw spelling");
        assert_eq!(
            classify_alias_intent(
                &world.view(),
                &catalog,
                &AliasIntentV1::Dataspace(intent),
                1
            )
            .expect("an absent grant must preserve legacy SNS normalization"),
            AliasPlanDispositionV1::Create
        );
    }
    #[test]
    fn catalogued_dataspace_requires_governed_bootstrap_record() {
        let owner = account(2);
        let mut world = world_with_accounts(core::slice::from_ref(&owner));
        let dataspace = DataSpaceId::new(7);
        let catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
            id: dataspace,
            alias: "governance".to_owned(),
            description: None,
            fault_tolerance: 1,
        }])
        .expect("catalogued dataspace");
        let intent = AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: ResolvedDataSpaceV1::new(
                "governance".parse().expect("dataspace alias"),
                dataspace,
            ),
            owner: owner.clone(),
        });
        let error = classify_alias_intent(&world.view(), &catalog, &intent, 1)
            .expect_err("public setup must not claim an operator-catalogued dataspace");
        assert_eq!(error.code(), CATALOGUED_DATASPACE_BOOTSTRAP_REQUIRED_CODE,);
        assert_eq!(
            error.message(),
            "catalogued dataspace `governance` (7) must be bound by the governed genesis bootstrap before public alias setup",
            "historical rejection bytes must remain unchanged when no grant exists"
        );
        insert_record(&mut world, &intent, owner);
        assert_eq!(
            classify_alias_intent(&world.view(), &catalog, &intent, 1)
                .expect("a governed bootstrap record establishes the owner"),
            AliasPlanDispositionV1::Repair,
            "the authenticated bootstrap owner may repair missing derived permissions",
        );
    }
    #[test]
    fn dataspace_bootstrap_grant_preserves_create_across_catalog_expansion() {
        use iroha_data_model::{alias_setup::AliasDataspaceBootstrapGrantV1, parameter::Parameter};

        let owner = account(21);
        let other = account(22);
        let world = world_with_accounts(&[owner.clone(), other.clone()]);
        let grant = AliasDataspaceBootstrapGrantV1::try_new("bpng", owner.clone())
            .expect("canonical bootstrap grant");
        let intent = AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: grant.dataspace.clone(),
            owner,
        });
        let expanded_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
            id: grant.dataspace.dataspace_id,
            alias: "bpng".to_owned(),
            description: None,
            fault_tolerance: 1,
        }])
        .expect("expanded BPNG catalog");
        let error = classify_alias_intent(&world.view(), &expanded_catalog, &intent, 1)
            .expect_err("catalogued names remain protected without a grant");
        assert_eq!(error.code(), CATALOGUED_DATASPACE_BOOTSTRAP_REQUIRED_CODE);
        {
            let mut block = world.block();
            let mut transaction = block.transaction_without_telemetry(
                iroha_config::parameters::actual::LaneConfig::default(),
                0,
            );
            transaction
                .parameters
                .get_mut()
                .set_parameter(Parameter::Custom(
                    grant
                        .clone()
                        .into_custom_parameter()
                        .expect("grant parameter"),
                ))
                .expect("valid fixture parameters");
            transaction.apply();
            block.commit();
        }
        for catalog in [DataSpaceCatalog::default(), expanded_catalog.clone()] {
            assert_eq!(
                classify_alias_intent(&world.view(), &catalog, &intent, 1)
                    .expect("the same pre-existing grant authorizes creation before and after catalog expansion"),
                AliasPlanDispositionV1::Create
            );
            let foreign = AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
                dataspace: grant.dataspace.clone(),
                owner: other.clone(),
            });
            let error = classify_alias_intent(&world.view(), &catalog, &foreign, 1)
                .expect_err("a grant reserves its owner even before catalog installation");
            assert_eq!(error.code(), "alias.catalog.bootstrap_grant_conflict");
            let noncanonical = AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
                dataspace: ResolvedDataSpaceV1::new(
                    "BPNG".parse().expect("noncanonical raw name"),
                    grant.dataspace.dataspace_id,
                ),
                owner: grant.owner.clone(),
            });
            let error = classify_alias_intent(&world.view(), &catalog, &noncanonical, 1)
                .expect_err("SNS normalization cannot hide an existing exact grant");
            assert_eq!(error.code(), "alias.catalog.bootstrap_grant_conflict");
        }
        let wrong_static_mapping = DataSpaceCatalog::new(vec![DataSpaceMetadata {
            id: DataSpaceId::new(10),
            alias: "bpng".to_owned(),
            description: None,
            fault_tolerance: 1,
        }])
        .expect("conflicting static catalog");
        let error = classify_alias_intent(&world.view(), &wrong_static_mapping, &intent, 1)
            .expect_err("a grant cannot override an existing static ID mapping");
        assert_eq!(
            error.code(),
            crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE
        );
    }
    #[test]
    fn configured_payment_asset_validation_matches_consensus_policy_check() {
        let owner = account(15);
        let payment_asset: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                .parse()
                .expect("default payment asset id");
        let payment_definition = AssetDefinition::numeric(
            payment_asset.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&owner);
        let owner_account = Account::new(owner.clone()).build(&owner);
        let mut world = World::with([], [owner_account], [payment_definition]);
        crate::sns::seed_default_namespace_policies(&mut world);
        let target = dynamic_dataspace_intent(owner.clone()).target();
        validate_configured_alias_payment_asset(&world.view(), &target, &payment_asset.to_string())
            .expect("registered configured asset matches the seeded namespace policy");
        let other_asset = AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("fees", "universal")
                .expect("alternate asset domain"),
            "other".parse().expect("alternate asset name"),
        );
        world.asset_definitions.insert(
            other_asset.clone(),
            AssetDefinition::numeric(
                other_asset.clone(),
                "other",
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&owner),
        );
        let error = validate_configured_alias_payment_asset(
            &world.view(),
            &target,
            &other_asset.to_string(),
        )
        .expect_err("a registered asset must still match the namespace payment policy");
        assert_eq!(error.code(), "alias.quote.payment_asset_mismatch");
        let error = validate_configured_alias_payment_asset(
            &world.view(),
            &target,
            "not-a-canonical-asset",
        )
        .expect_err("invalid configured fee asset must block planning");
        assert_eq!(error.code(), "alias.quote.payment_asset_mismatch");
    }
    #[test]
    fn new_dataspace_rejects_reverse_id_collision() {
        let owner = account(10);
        let world = world_with_accounts(core::slice::from_ref(&owner));
        let intent = dynamic_dataspace_intent(owner);
        let AliasIntentV1::Dataspace(value) = &intent else {
            unreachable!()
        };
        let catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
            id: value.dataspace.dataspace_id,
            alias: "different".to_owned(),
            description: None,
            fault_tolerance: 1,
        }])
        .expect("single reverse-collision catalog entry");
        let error = classify_alias_intent(&world.view(), &catalog, &intent, 1)
            .expect_err("a numeric dataspace id cannot acquire a second name");
        assert_eq!(
            error.code(),
            crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE
        );
    }
    #[test]
    fn planned_parent_mapping_allows_ordered_domain_creation_without_mutation() {
        let owner = account(7);
        let world = world_with_accounts(core::slice::from_ref(&owner));
        let catalog = DataSpaceCatalog::new(Vec::new()).expect("empty dynamic catalog");
        let parent = dynamic_dataspace_intent(owner.clone());
        let AliasIntentV1::Dataspace(parent) = parent else {
            unreachable!()
        };
        let domain = AliasIntentV1::Domain(AliasDomainIntentV1 {
            domain: ResolvedDomainV1::new(
                iroha_model_base::domain::DomainId::try_new(
                    "banka",
                    parent.dataspace.canonical_name.clone(),
                )
                .expect("domain"),
                parent.dataspace.dataspace_id,
            ),
            owner,
        });
        let error = classify_alias_intent(&world.view(), &catalog, &domain, 1)
            .expect_err("unplanned unknown parent must fail");
        assert_eq!(error.code(), "alias.catalog.unknown_mapping");
        let planned = BTreeMap::from([(
            parent.dataspace.canonical_name,
            parent.dataspace.dataspace_id,
        )]);
        assert_eq!(
            classify_alias_intent_with_planned_dataspaces(
                &world.view(),
                &catalog,
                &planned,
                &domain,
                1,
            )
            .expect("planned parent classification"),
            AliasPlanDispositionV1::Create
        );
    }
    #[test]
    fn endorsement_required_absent_domain_cannot_be_planned_for_setup() {
        let owner = account(17);
        let world = world_with_accounts(core::slice::from_ref(&owner));
        let catalog = DataSpaceCatalog::new(Vec::new()).expect("empty dynamic catalog");
        let parent = dynamic_dataspace_intent(owner.clone());
        let AliasIntentV1::Dataspace(parent) = parent else {
            unreachable!()
        };
        let domain_id = iroha_model_base::domain::DomainId::try_new(
            "protected",
            parent.dataspace.canonical_name.clone(),
        )
        .expect("protected domain");
        let intent = AliasIntentV1::Domain(AliasDomainIntentV1 {
            domain: ResolvedDomainV1::new(domain_id.clone(), parent.dataspace.dataspace_id),
            owner,
        });
        let selector = selector_for_resolved_alias_target(&intent.target())
            .expect("protected domain selector");
        let planned_dataspaces = BTreeMap::from([(
            parent.dataspace.canonical_name,
            parent.dataspace.dataspace_id,
        )]);
        let error = classify_alias_intent_with_planned_parents_and_endorsement_policy(
            &world.view(),
            &catalog,
            &planned_dataspaces,
            &BTreeSet::new(),
            &intent,
            1,
            true,
        )
        .expect_err("an endorsement-free domain intent must not yield an executable plan");
        assert_eq!(error.code(), "alias.domain.endorsement_required");
        let view = world.view();
        assert!(
            view.domains().get(&domain_id).is_none(),
            "read-only planning must not create the blocked domain"
        );
        assert!(
            crate::sns::record_by_selector(&view, &selector)
                .expect("valid SNS record state")
                .is_none(),
            "read-only planning must not acquire the blocked lease"
        );
    }
    #[test]
    fn private_dpn_owner_alias_uses_ordered_or_active_sns_without_physical_catalog() {
        let owner = account(21);
        let mut world = world_with_accounts(core::slice::from_ref(&owner));
        let catalog = DataSpaceCatalog::new(Vec::new()).expect("no physical dataspace catalog");
        let dataspace_id = crate::sns::dataspace_id_for_sns_alias("dpn").unwrap();
        let parent = AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: iroha_data_model::alias_setup::ResolvedDataSpaceV1::new(
                "dpn".parse().unwrap(),
                dataspace_id,
            ),
            owner: owner.clone(),
        });
        let alias = AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: ResolvedAccountAliasV1::new("admin@dpn".parse().unwrap(), dataspace_id),
            target_account: owner.clone(),
            provision: AccountProvisionV1::Existing,
            role: AccountAliasRoleV1::Additional,
        });
        assert!(classify_alias_intent(&world.view(), &catalog, &alias, 1).is_err());
        let planned = BTreeMap::from([("dpn".parse().unwrap(), dataspace_id)]);
        assert_eq!(
            classify_alias_intent_with_planned_dataspaces(
                &world.view(),
                &catalog,
                &planned,
                &alias,
                1,
            )
            .unwrap(),
            AliasPlanDispositionV1::Create
        );
        validate_alias_intent_authority(&world.view(), &owner, &alias).unwrap();
        insert_record(&mut world, &parent, owner);
        assert_eq!(
            classify_alias_intent(&world.view(), &catalog, &alias, 1).unwrap(),
            AliasPlanDispositionV1::Create
        );
        let mut wrong = alias;
        if let AliasIntentV1::AccountAlias(value) = &mut wrong {
            value.alias.dataspace_id = DataSpaceId::new(7);
        }
        assert!(classify_alias_intent(&world.view(), &catalog, &wrong, 1).is_err());
        assert!(catalog.by_alias("dpn").is_none());
    }

    #[test]
    fn account_alias_requires_active_or_earlier_planned_domain() {
        let owner = account(11);
        let world = world_with_accounts(core::slice::from_ref(&owner));
        let parent_dataspace = dynamic_dataspace_intent(owner.clone());
        let AliasIntentV1::Dataspace(parent_dataspace) = parent_dataspace else {
            unreachable!()
        };
        let domain_id = iroha_model_base::domain::DomainId::try_new(
            "banka",
            parent_dataspace.dataspace.canonical_name.clone(),
        )
        .expect("parent domain");
        let alias = AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: ResolvedAccountAliasV1::new(
                "merchant@banka.paynet"
                    .parse::<AccountAliasName>()
                    .expect("account alias"),
                parent_dataspace.dataspace.dataspace_id,
            ),
            target_account: owner,
            provision: AccountProvisionV1::Existing,
            role: AccountAliasRoleV1::Primary,
        });
        let planned_dataspaces = BTreeMap::from([(
            parent_dataspace.dataspace.canonical_name,
            parent_dataspace.dataspace.dataspace_id,
        )]);
        let error = classify_alias_intent_with_planned_dataspaces(
            &world.view(),
            &DataSpaceCatalog::new(Vec::new()).expect("dynamic catalog"),
            &planned_dataspaces,
            &alias,
            1,
        )
        .expect_err("a dataspace alone does not satisfy a domain-qualified alias parent");
        assert_eq!(error.code(), "alias.parent.missing");
        assert_eq!(
            classify_alias_intent_with_planned_parents(
                &world.view(),
                &DataSpaceCatalog::new(Vec::new()).expect("dynamic catalog"),
                &planned_dataspaces,
                &BTreeSet::from([domain_id]),
                &alias,
                1,
            )
            .expect("both earlier parents satisfy ordered account-alias creation"),
            AliasPlanDispositionV1::Create
        );
    }
    #[test]
    fn exact_state_is_noop_and_missing_exact_permission_is_repair() {
        let owner = account(2);
        let mut world = world_with_accounts(core::slice::from_ref(&owner));
        let catalog = DataSpaceCatalog::new(Vec::new()).expect("empty dynamic catalog");
        let intent = dynamic_dataspace_intent(owner.clone());
        insert_record(&mut world, &intent, owner.clone());
        world.account_permissions_mut_for_testing().insert(
            owner.clone(),
            exact_alias_permission_bundle(&intent).into_iter().collect(),
        );
        assert_eq!(
            classify_alias_intent(&world.view(), &catalog, &intent, 1).expect("classify no-op"),
            AliasPlanDispositionV1::NoOp
        );
        let mut permissions: BTreeSet<_> =
            exact_alias_permission_bundle(&intent).into_iter().collect();
        permissions.pop_first();
        world
            .account_permissions_mut_for_testing()
            .insert(owner, permissions);
        assert_eq!(
            classify_alias_intent(&world.view(), &catalog, &intent, 1).expect("classify repair"),
            AliasPlanDispositionV1::Repair
        );
    }
    #[test]
    fn owner_and_static_dynamic_mapping_drift_fail_closed() {
        let owner = account(3);
        let other = account(4);
        let mut world = world_with_accounts(&[owner.clone(), other.clone()]);
        let intent = dynamic_dataspace_intent(owner.clone());
        insert_record(&mut world, &intent, other);
        let dynamic_catalog = DataSpaceCatalog::new(Vec::new()).expect("empty dynamic catalog");
        let error = classify_alias_intent(&world.view(), &dynamic_catalog, &intent, 1)
            .expect_err("owner drift must fail");
        assert_eq!(error.code(), "alias.owner.conflict");
        let AliasIntentV1::Dataspace(value) = &intent else {
            unreachable!()
        };
        let conflicting_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
            id: DataSpaceId::new(value.dataspace.dataspace_id.as_u64().saturating_add(1)),
            alias: value.dataspace.canonical_text(),
            description: None,
            fault_tolerance: 1,
        }])
        .expect("conflicting static catalog");
        let error = classify_alias_intent(&world.view(), &conflicting_catalog, &intent, 1)
            .expect_err("mapping drift must fail");
        assert_eq!(
            error.code(),
            crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE
        );
    }
    #[test]
    fn account_binding_and_primary_drift_fail_closed() {
        let target = account(5);
        let other = account(6);
        let mut world = world_with_accounts(&[target.clone(), other.clone()]);
        let parent = AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: ResolvedDataSpaceV1::new(
                "universal".parse().expect("universal dataspace name"),
                DataSpaceId::UNIVERSAL,
            ),
            owner: target.clone(),
        });
        insert_record(&mut world, &parent, target.clone());
        let resolved = ResolvedAccountAliasV1::new(
            "merchant@universal"
                .parse::<AccountAliasName>()
                .expect("account alias"),
            DataSpaceId::UNIVERSAL,
        );
        let intent = AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: resolved.clone(),
            target_account: target.clone(),
            provision: AccountProvisionV1::Existing,
            role: AccountAliasRoleV1::Primary,
        });
        insert_record(&mut world, &intent, target.clone());
        world
            .account_aliases
            .insert(resolved.account_alias(), other.clone());
        let error = classify_alias_intent(&world.view(), &DataSpaceCatalog::default(), &intent, 1)
            .expect_err("binding drift must fail");
        assert_eq!(error.code(), "alias.binding.conflict");
        let different_primary = AccountAlias::domainless(
            "other".parse().expect("other label"),
            DataSpaceId::UNIVERSAL,
        );
        let mut primary_world = world_with_accounts(&[target.clone(), other]);
        set_primary_label_for_testing(&primary_world, &target, different_primary);
        insert_record(&mut primary_world, &parent, target.clone());
        insert_record(&mut primary_world, &intent, target);
        let error = classify_alias_intent(
            &primary_world.view(),
            &DataSpaceCatalog::default(),
            &intent,
            1,
        )
        .expect_err("primary drift must fail");
        assert_eq!(error.code(), "alias.primary.conflict");
    }
    #[test]
    fn missing_domain_state_is_repairable() {
        let owner = account(12);
        let mut world = world_with_accounts(core::slice::from_ref(&owner));
        let parent = dynamic_dataspace_intent(owner.clone());
        let AliasIntentV1::Dataspace(parent_value) = &parent else {
            unreachable!()
        };
        insert_record(&mut world, &parent, owner.clone());
        let domain_id = iroha_model_base::domain::DomainId::try_new(
            "banka",
            &parent_value.dataspace.canonical_name,
        )
        .expect("canonical child domain");
        let intent = AliasIntentV1::Domain(AliasDomainIntentV1 {
            domain: ResolvedDomainV1::new(domain_id.clone(), parent_value.dataspace.dataspace_id),
            owner: owner.clone(),
        });
        insert_record(&mut world, &intent, owner);
        assert_eq!(
            classify_alias_intent(&world.view(), &DataSpaceCatalog::default(), &intent, 1)
                .expect("missing canonical domain state is repairable"),
            AliasPlanDispositionV1::Repair
        );
    }
    #[test]
    fn account_reverse_primary_and_rekey_drift_fail_closed() {
        let target = account(13);
        let other = account(14);
        let mut world = world_with_accounts(&[target.clone(), other.clone()]);
        let parent = AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: ResolvedDataSpaceV1::new(
                "universal".parse().expect("universal dataspace name"),
                DataSpaceId::UNIVERSAL,
            ),
            owner: target.clone(),
        });
        insert_record(&mut world, &parent, target.clone());
        let resolved = ResolvedAccountAliasV1::new(
            "merchant@universal"
                .parse::<AccountAliasName>()
                .expect("account alias"),
            DataSpaceId::UNIVERSAL,
        );
        let alias = resolved.account_alias();
        let intent = AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: resolved,
            target_account: target.clone(),
            provision: AccountProvisionV1::Existing,
            role: AccountAliasRoleV1::Additional,
        });
        insert_record(&mut world, &intent, target.clone());
        world.account_aliases.insert(alias.clone(), target.clone());
        world
            .account_aliases_by_account
            .insert(other.clone(), BTreeSet::from([alias.clone()]));
        let error = classify_alias_intent(&world.view(), &DataSpaceCatalog::default(), &intent, 1)
            .expect_err("reverse binding drift must fail");
        assert_eq!(error.code(), "alias.binding.conflict");
        let mut primary_world = world_with_accounts(&[target.clone(), other.clone()]);
        set_primary_label_for_testing(&primary_world, &other, alias.clone());
        insert_record(&mut primary_world, &parent, target.clone());
        insert_record(&mut primary_world, &intent, target.clone());
        primary_world
            .account_aliases
            .insert(alias.clone(), target.clone());
        primary_world
            .account_aliases_by_account
            .insert(target.clone(), BTreeSet::from([alias.clone()]));
        let error = classify_alias_intent(
            &primary_world.view(),
            &DataSpaceCatalog::default(),
            &intent,
            1,
        )
        .expect_err("a second account primary must fail");
        assert_eq!(error.code(), "alias.primary.conflict");
        let mut rekey_world = world_with_accounts(&[target.clone(), other]);
        insert_record(&mut rekey_world, &parent, target.clone());
        insert_record(&mut rekey_world, &intent, target.clone());
        rekey_world
            .account_aliases
            .insert(alias.clone(), target.clone());
        rekey_world
            .account_aliases_by_account
            .insert(target.clone(), BTreeSet::from([alias.clone()]));
        let different_alias = AccountAlias::domainless(
            "different".parse().expect("different alias label"),
            DataSpaceId::UNIVERSAL,
        );
        rekey_world.account_rekey_records.insert(
            alias.clone(),
            AccountRekeyRecord::new(different_alias, target),
        );
        let error = classify_alias_intent(
            &rekey_world.view(),
            &DataSpaceCatalog::default(),
            &intent,
            1,
        )
        .expect_err("rekey record identity drift must fail");
        assert_eq!(error.code(), "alias.binding.conflict");
    }
    #[test]
    fn auto_renew_disable_planning_is_exact_noop_and_owner_only() {
        let owner = account(8);
        let other = account(9);
        let mut world = world_with_accounts(&[owner.clone(), other.clone()]);
        let intent = dynamic_dataspace_intent(owner.clone());
        insert_record(&mut world, &intent, owner.clone());
        let operation = iroha_data_model::isi::alias_setup::ConfigureAliasAutoRenew::new(
            intent.target(),
            0,
            None,
        );
        assert_eq!(
            classify_alias_auto_renew(
                &world.view(),
                &DataSpaceCatalog::default(),
                &owner,
                &operation,
                1,
            )
            .expect("absent disabled state is an exact no-op"),
            AliasLifecyclePlanDispositionV1::NoOp,
        );
        let error = classify_alias_auto_renew(
            &world.view(),
            &DataSpaceCatalog::default(),
            &other,
            &operation,
            1,
        )
        .expect_err("non-owner must not plan auto-renew configuration");
        assert_eq!(error.code(), "alias.auto_renew.owner_forbidden");
    }
    #[test]
    fn setup_authority_requires_owner_or_exact_management_scope() {
        let owner = account(10);
        let operator = account(11);
        let mut world = world_with_accounts(&[owner.clone(), operator.clone()]);
        let intent = dynamic_dataspace_intent(owner.clone());
        let error = validate_alias_intent_authority(&world.view(), &operator, &intent)
            .expect_err("an unrelated payer must not provision another owner's resource");
        assert_eq!(error.code(), "alias.setup.authority_forbidden");
        world.account_permissions.insert(
            operator.clone(),
            BTreeSet::from([Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(intent.target().dataspace_id()),
            })]),
        );
        validate_alias_intent_authority(&world.view(), &operator, &intent)
            .expect("the exact dataspace manager may provision for the explicit owner");
    }
    #[test]
    fn dynamic_account_alias_management_uses_the_resolved_exact_scope() {
        let owner = account(15);
        let operator = account(16);
        let mut world = world_with_accounts(&[owner.clone(), operator.clone()]);
        let dataspace_id = crate::sns::dataspace_id_for_sns_alias("paynet")
            .expect("deterministic dynamic dataspace id");
        let root_intent = AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: ResolvedAccountAliasV1::new(
                "merchant@paynet"
                    .parse::<AccountAliasName>()
                    .expect("dynamic root alias"),
                dataspace_id,
            ),
            target_account: owner.clone(),
            provision: AccountProvisionV1::Existing,
            role: AccountAliasRoleV1::Additional,
        });
        world.account_permissions.insert(
            operator.clone(),
            BTreeSet::from([Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(dataspace_id),
            })]),
        );
        validate_alias_intent_authority(&world.view(), &operator, &root_intent)
            .expect("resolved dynamic root alias accepts its exact dataspace scope");
        let domain_intent = AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: ResolvedAccountAliasV1::new(
                "merchant@banka.paynet"
                    .parse::<AccountAliasName>()
                    .expect("dynamic domain alias"),
                dataspace_id,
            ),
            target_account: owner,
            provision: AccountProvisionV1::Existing,
            role: AccountAliasRoleV1::Additional,
        });
        let error = validate_alias_intent_authority(&world.view(), &operator, &domain_intent)
            .expect_err("dataspace scope must not widen into a domain-qualified alias");
        assert_eq!(error.code(), "alias.setup.authority_forbidden");
        let domain = iroha_model_base::domain::DomainId::try_new("banka", "paynet")
            .expect("canonical dynamic parent domain");
        world.account_permissions.insert(
            operator.clone(),
            BTreeSet::from([Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(domain),
            })]),
        );
        validate_alias_intent_authority(&world.view(), &operator, &domain_intent)
            .expect("resolved dynamic domain alias accepts only its exact domain scope");
    }
    #[test]
    fn auto_renew_window_must_be_shorter_than_renewal_term() {
        let owner = account(12);
        let mut world = world_with_accounts(std::slice::from_ref(&owner));
        let intent = dynamic_dataspace_intent(owner.clone());
        insert_record(&mut world, &intent, owner.clone());
        let config = AliasAutoRenewConfigV1 {
            term_years: 1,
            policy_version: 1,
            payment_asset: "61CtjvNd9T3THAR65GsMVHr82Bjc"
                .parse()
                .expect("payment asset definition id"),
            max_amount: iroha_primitives::numeric::Quantity::one(),
            renew_before_expiry_ms: iroha_data_model::alias_setup::ALIAS_LEASE_YEAR_MS,
            retry_backoff_ms: 1,
            max_failures: 1,
        };
        let operation = iroha_data_model::isi::alias_setup::ConfigureAliasAutoRenew::new(
            intent.target(),
            0,
            Some(config),
        );
        let error = classify_alias_auto_renew(
            &world.view(),
            &DataSpaceCatalog::default(),
            &owner,
            &operation,
            1,
        )
        .expect_err("a renewal window as long as its term must be rejected");
        assert_eq!(error.code(), "alias.auto_renew.range_invalid");
    }
}
