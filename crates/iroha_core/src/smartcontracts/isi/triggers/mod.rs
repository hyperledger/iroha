//! This module contains implementations of smart-contract traits and
//! instructions for triggers in Iroha.
use iroha_data_model::{
    ValidationFail, isi::error::MathError, prelude::*, query::error::FindError,
    transaction::error::prelude::TransactionRejectionReason,
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_telemetry::metrics;
use std::sync::OnceLock;
pub mod set;
pub mod specialized;
/// Trigger metadata key toggled by `set_trigger_enabled` syscalls/ISIs.
pub(crate) const TRIGGER_ENABLED_METADATA_KEY: &str = "__enabled";
/// Internal registration-height metadata used to defer new trigger incarnations.
pub(crate) const TRIGGER_REGISTERED_BLOCK_HEIGHT_METADATA_KEY: &str = "__registered_block_height";
/// Internal authorization mode captured when a data trigger is registered.
pub(crate) const DATA_TRIGGER_SCOPE_AUTHORIZATION_METADATA_KEY: &str =
    "__data_scope_authorization_v1";
/// Account whose exact global-data-trigger capability authorized registration.
pub(crate) const DATA_TRIGGER_SCOPE_AUTHORIZATION_GRANTEE_METADATA_KEY: &str =
    "__data_scope_authorization_grantee_v1";
const DATA_TRIGGER_SCOPE_AUTHORIZATION_OWNED: u64 = 0;
const DATA_TRIGGER_SCOPE_AUTHORIZATION_GLOBAL: u64 = 1;
#[cfg(test)]
const DATA_TRIGGER_SCOPE_AUTHORIZATION_GENESIS_GLOBAL: u64 = 2;
fn trigger_enabled_metadata_key() -> &'static Name {
    static KEY: OnceLock<Name> = OnceLock::new();
    KEY.get_or_init(|| {
        TRIGGER_ENABLED_METADATA_KEY
            .parse()
            .expect("trigger enabled metadata key must be valid")
    })
}
fn trigger_registered_block_height_metadata_key() -> &'static Name {
    static KEY: OnceLock<Name> = OnceLock::new();
    KEY.get_or_init(|| {
        TRIGGER_REGISTERED_BLOCK_HEIGHT_METADATA_KEY
            .parse()
            .expect("trigger registration-height metadata key must be valid")
    })
}
/// Read the trigger enabled flag from metadata, defaulting to `true` when absent.
/// Malformed values fail closed and disable the trigger.
pub(crate) fn trigger_is_enabled(metadata: &Metadata) -> bool {
    match trigger_enabled_from_value(metadata.get(trigger_enabled_metadata_key()), |_, _| {
        Ok::<_, core::convert::Infallible>(())
    }) {
        Ok(enabled) => enabled,
        Err(never) => match never {},
    }
}
/// The two existing scalar decoders, in their original semantic order.
#[derive(Clone, Copy)]
enum EnabledScalar {
    Bool,
    U64,
}
/// One eligibility predicate for ordinary and original-source checked consumers.
/// Discarded typed mismatches do not acquire an owned formatted diagnostic.
fn trigger_enabled_from_value<E>(
    value: Option<&iroha_primitives::json::Json>,
    mut before_decode: impl FnMut(EnabledScalar, &iroha_primitives::json::Json) -> Result<(), E>,
) -> Result<bool, E> {
    let Some(value) = value else {
        return Ok(true);
    };
    before_decode(EnabledScalar::Bool, value)?;
    if let Ok(flag) = norito::json::from_str::<bool>(value.get()) {
        return Ok(flag);
    }
    before_decode(EnabledScalar::U64, value)?;
    if let Ok(raw) = norito::json::from_str::<u64>(value.get()) {
        return Ok(raw != 0);
    }
    Ok(false)
}
/// Return whether this exact trigger incarnation predates `current_block_height`.
///
/// Missing, malformed, same-height, and future-height lifecycle metadata all fail
/// closed. Call this again after materialized trigger IDs are reloaded because an
/// earlier callback may have replaced the ID with a new incarnation.
pub(crate) fn trigger_was_registered_before_block(
    metadata: &Metadata,
    current_block_height: u64,
) -> bool {
    metadata
        .get(trigger_registered_block_height_metadata_key())
        .and_then(|json| json.try_into_any_norito::<u64>().ok())
        .is_some_and(|height| height < current_block_height)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DataTriggerScopeAuthorization {
    Owned,
    GlobalPermission(AccountId),
}

fn data_trigger_scope_authorization_key() -> &'static Name {
    static KEY: OnceLock<Name> = OnceLock::new();
    KEY.get_or_init(|| {
        DATA_TRIGGER_SCOPE_AUTHORIZATION_METADATA_KEY
            .parse()
            .expect("data-trigger scope authorization key must be valid")
    })
}

fn data_trigger_scope_authorization_grantee_key() -> &'static Name {
    static KEY: OnceLock<Name> = OnceLock::new();
    KEY.get_or_init(|| {
        DATA_TRIGGER_SCOPE_AUTHORIZATION_GRANTEE_METADATA_KEY
            .parse()
            .expect("data-trigger scope authorization grantee key must be valid")
    })
}

fn decode_data_trigger_scope_authorization(
    metadata: &Metadata,
) -> Option<DataTriggerScopeAuthorization> {
    let mode = metadata
        .get(data_trigger_scope_authorization_key())?
        .clone()
        .try_into_any_norito::<u64>()
        .ok()?;
    let grantee = metadata.get(data_trigger_scope_authorization_grantee_key());
    match mode {
        DATA_TRIGGER_SCOPE_AUTHORIZATION_OWNED if grantee.is_none() => {
            Some(DataTriggerScopeAuthorization::Owned)
        }
        DATA_TRIGGER_SCOPE_AUTHORIZATION_GLOBAL => {
            let grantee = grantee?.clone().try_into_any_norito::<AccountId>().ok()?;
            Some(DataTriggerScopeAuthorization::GlobalPermission(grantee))
        }
        _ => None,
    }
}

/// Return whether stored data-trigger authorization metadata has the canonical v1 shape.
pub(crate) fn data_trigger_scope_authorization_is_well_formed(metadata: &Metadata) -> bool {
    decode_data_trigger_scope_authorization(metadata).is_some()
}

/// Return the exact direct-capability holder recorded for a global data trigger.
///
/// An error means the persisted v1 authorization record is not canonical and
/// callers must fail closed rather than guessing provenance.
pub(crate) fn data_trigger_global_permission_grantee(
    metadata: &Metadata,
) -> Result<Option<AccountId>, ()> {
    match decode_data_trigger_scope_authorization(metadata).ok_or(())? {
        DataTriggerScopeAuthorization::GlobalPermission(grantee) => Ok(Some(grantee)),
        DataTriggerScopeAuthorization::Owned => Ok(None),
    }
}

/// Rekey the exact global-capability holder captured in trigger metadata.
///
/// Returns whether the metadata changed. Malformed records are rejected so an
/// account migration cannot silently convert them into a different policy.
pub(crate) fn replace_data_trigger_global_permission_grantee(
    metadata: &mut Metadata,
    old: &AccountId,
    new: &AccountId,
) -> Result<bool, ()> {
    let Some(grantee) = data_trigger_global_permission_grantee(metadata)? else {
        return Ok(false);
    };
    if grantee != *old {
        return Ok(false);
    }
    metadata.insert(
        data_trigger_scope_authorization_grantee_key().clone(),
        iroha_primitives::json::Json::new(new.to_string()),
    );
    Ok(true)
}

#[cfg(test)]
pub(crate) fn owned_data_trigger_scope_metadata_for_testing() -> Metadata {
    use iroha_primitives::json::Json;

    let mut metadata = Metadata::default();
    metadata.insert(
        data_trigger_scope_authorization_key().clone(),
        Json::new(DATA_TRIGGER_SCOPE_AUTHORIZATION_OWNED),
    );
    metadata
}

#[cfg(test)]
pub(crate) fn legacy_genesis_global_scope_metadata_for_testing() -> Metadata {
    use iroha_primitives::json::Json;

    let mut metadata = Metadata::default();
    metadata.insert(
        data_trigger_scope_authorization_key().clone(),
        Json::new(DATA_TRIGGER_SCOPE_AUTHORIZATION_GENESIS_GLOBAL),
    );
    metadata
}

#[cfg(test)]
pub(crate) fn global_data_trigger_scope_metadata_for_testing(grantee: &AccountId) -> Metadata {
    use iroha_primitives::json::Json;

    let mut metadata = Metadata::default();
    metadata.insert(
        data_trigger_scope_authorization_key().clone(),
        Json::new(DATA_TRIGGER_SCOPE_AUTHORIZATION_GLOBAL),
    );
    metadata.insert(
        data_trigger_scope_authorization_grantee_key().clone(),
        Json::new(grantee.to_string()),
    );
    metadata
}
/// All instructions related to triggers.
/// - registering a trigger and validating the declared authority against
///   `CanRegisterTrigger{authority: ...}` permissions
/// - un-registering a trigger and cleaning up associated metadata
/// - adjusting trigger metadata to reflect registration height and block time
#[allow(clippy::used_underscore_binding)]
pub mod isi {
    use super::specialized::LoadedActionTrait as _;
    use super::{super::prelude::*, *};
    use iroha_data_model::isi::error::{InvalidParameterError, RepetitionError};
    use iroha_model_base::name::Name;
    const RESERVED_TRIGGER_METADATA_KEYS: [&str; 4] = [
        TRIGGER_REGISTERED_BLOCK_HEIGHT_METADATA_KEY,
        "__registered_at_ms",
        DATA_TRIGGER_SCOPE_AUTHORIZATION_METADATA_KEY,
        DATA_TRIGGER_SCOPE_AUTHORIZATION_GRANTEE_METADATA_KEY,
    ];
    pub(super) const MAX_DATA_TRIGGERS_PER_AUTHORITY: usize = 64;
    pub(super) const MAX_DATA_TRIGGERS_TOTAL: usize = 4_096;
    fn has_exact_global_data_trigger_permission(
        state_transaction: &StateTransaction<'_, '_>,
        submitting_authority: &AccountId,
        trigger_authority: &AccountId,
    ) -> bool {
        let required: Permission =
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: trigger_authority.clone(),
            }
            .into();
        state_transaction
            .world
            .account_permissions
            .get(submitting_authority)
            .is_some_and(|permissions| permissions.contains(&required))
    }
    fn account_owns_data_trigger_scope(
        state_transaction: &StateTransaction<'_, '_>,
        authority: &AccountId,
        filter: &DataEventFilter,
    ) -> bool {
        match filter {
            DataEventFilter::Account(filter) => filter.id_matcher().as_ref() == Some(authority),
            DataEventFilter::Asset(filter) => {
                let mut constrained = false;
                let mut owned = true;
                if let Some(asset) = filter.id_matcher() {
                    constrained = true;
                    owned &= asset.account() == authority;
                }
                if let Some(definition) = filter.asset_definition_matcher() {
                    constrained = true;
                    owned &= state_transaction
                        .world
                        .asset_definition(definition)
                        .is_ok_and(|definition| definition.owned_by() == authority);
                }
                if let Some(source) = filter.transfer_source_account_matcher() {
                    constrained = true;
                    owned &= source == authority;
                }
                if let Some(destination) = filter.transfer_destination_account_matcher() {
                    constrained = true;
                    owned &= destination == authority;
                }
                constrained && owned
            }
            DataEventFilter::Domain(filter) => filter.id_matcher().as_ref().is_some_and(|id| {
                state_transaction
                    .world
                    .domain(id)
                    .is_ok_and(|domain| domain.owned_by() == authority)
            }),
            DataEventFilter::AssetDefinition(filter) => {
                filter.id_matcher().as_ref().is_some_and(|id| {
                    state_transaction
                        .world
                        .asset_definition(id)
                        .is_ok_and(|definition| definition.owned_by() == authority)
                })
            }
            DataEventFilter::Nft(filter) => filter.id_matcher().as_ref().is_some_and(|id| {
                state_transaction
                    .world
                    .nft(id)
                    .is_ok_and(|nft| &nft.owned_by == authority)
            }),
            DataEventFilter::Rwa(filter) => filter.id_matcher().as_ref().is_some_and(|id| {
                state_transaction
                    .world
                    .rwa(id)
                    .is_ok_and(|rwa| &rwa.owned_by == authority)
            }),
            DataEventFilter::Trigger(filter) => filter.id_matcher().as_ref().is_some_and(|id| {
                state_transaction
                    .world
                    .triggers
                    .inspect_by_id(id, |action| action.authority() == authority)
                    .unwrap_or(false)
            }),
            DataEventFilter::Any
            | DataEventFilter::GameSession(_)
            | DataEventFilter::Peer(_)
            | DataEventFilter::Role(_)
            | DataEventFilter::Configuration(_)
            | DataEventFilter::Executor(_)
            | DataEventFilter::Proof(_)
            | DataEventFilter::VerifyingKey(_)
            | DataEventFilter::RuntimeUpgrade(_)
            | DataEventFilter::Soradns(_)
            | DataEventFilter::Sorafs(_)
            | DataEventFilter::Musubi(_)
            | DataEventFilter::SpaceDirectory(_)
            | DataEventFilter::Escrow(_)
            | DataEventFilter::Oracle(_)
            | DataEventFilter::Social(_)
            | DataEventFilter::Bridge(_)
            | DataEventFilter::Sccp(_)
            | DataEventFilter::KagemushaLoadCommitted(_)
            | DataEventFilter::Governance(_) => false,
        }
    }
    fn enforce_data_trigger_scope_and_capacity(
        state_transaction: &StateTransaction<'_, '_>,
        submitting_authority: &AccountId,
        trigger: &Trigger,
    ) -> Result<Option<DataTriggerScopeAuthorization>, Error> {
        let EventFilterBox::Data(filter) = trigger.action().filter() else {
            return Ok(None);
        };
        let trigger_authority = trigger.action().authority();
        let authorization = if account_owns_data_trigger_scope(
            state_transaction,
            trigger_authority,
            filter,
        ) {
            DataTriggerScopeAuthorization::Owned
        } else if has_exact_global_data_trigger_permission(
            state_transaction,
            submitting_authority,
            trigger_authority,
        ) {
            DataTriggerScopeAuthorization::GlobalPermission(submitting_authority.clone())
        } else {
            return Err(Error::InvalidParameter(
                InvalidParameterError::SmartContract(
                    "data trigger filter exceeds the trigger authority's exact owned scope; CanRegisterGlobalDataTrigger is required"
                        .into(),
                ),
            ));
        };
        let triggers = state_transaction.world.triggers.data_triggers();
        if triggers.len() >= MAX_DATA_TRIGGERS_TOTAL {
            return Err(Error::InvalidParameter(
                InvalidParameterError::SmartContract(format!(
                    "data trigger capacity exceeded: maximum {MAX_DATA_TRIGGERS_TOTAL}"
                )),
            ));
        }
        let authority_count = triggers
            .iter()
            .filter(|(_, action)| &action.authority == trigger_authority)
            .count();
        if authority_count >= MAX_DATA_TRIGGERS_PER_AUTHORITY {
            return Err(Error::InvalidParameter(
                InvalidParameterError::SmartContract(format!(
                    "data trigger authority capacity exceeded: maximum {MAX_DATA_TRIGGERS_PER_AUTHORITY}"
                )),
            ));
        }
        Ok(Some(authorization))
    }

    /// Revalidate the immutable authorization corridor captured at registration.
    ///
    /// Missing or malformed metadata fails closed. Owned scopes follow current
    /// ownership; global scopes follow the exact capability holder recorded at
    /// registration. Genesis uses the same exact, revocable capability corridor.
    pub(crate) fn data_trigger_scope_is_currently_authorized(
        state_transaction: &StateTransaction<'_, '_>,
        action: &super::specialized::LoadedAction<DataEventFilter>,
    ) -> bool {
        match decode_data_trigger_scope_authorization(action.metadata()) {
            Some(DataTriggerScopeAuthorization::Owned) => account_owns_data_trigger_scope(
                state_transaction,
                action.authority(),
                &action.filter,
            ),
            Some(DataTriggerScopeAuthorization::GlobalPermission(grantee)) => {
                has_exact_global_data_trigger_permission(
                    state_transaction,
                    &grantee,
                    action.authority(),
                )
            }
            None => false,
        }
    }
    pub(super) fn ensure_metadata_key_is_not_reserved(key: &Name) -> Result<(), Error> {
        if RESERVED_TRIGGER_METADATA_KEYS
            .iter()
            .any(|reserved| key.as_ref() == *reserved)
        {
            return Err(Error::InvalidParameter(
                InvalidParameterError::SmartContract(format!(
                    "Metadata key `{key}` is reserved for trigger lifecycle management",
                )),
            ));
        }
        Ok(())
    }
    fn enforce_trigger_metadata_limits(
        metadata: &Metadata,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        for (key, value) in metadata.iter() {
            ensure_metadata_key_is_not_reserved(key)?;
            crate::smartcontracts::limits::enforce_json_size(
                state_transaction,
                value,
                "max_metadata_value_bytes",
                crate::smartcontracts::limits::DEFAULT_JSON_LIMIT,
            )?;
        }
        Ok(())
    }
    fn enforce_ivm_trigger_program_policy(
        executable: &Executable,
        metadata: &Metadata,
        upper_bound: core::num::NonZeroU64,
        fuel: core::num::NonZeroU64,
        prepared_contracts: crate::smartcontracts::ivm::cache::PreparedContractCache,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<Error>> {
        let bytecode = match executable {
            Executable::Ivm(bytecode) => bytecode.as_ref(),
            Executable::IvmProved(_) => {
                return Err(
                    Error::InvalidParameter(InvalidParameterError::SmartContract(
                        "proof-backed IVM triggers are unavailable".into(),
                    ))
                    .into(),
                );
            }
            Executable::ContractCall(invocation) if invocation.arguments.is_some() => {
                return Err(Error::InvalidParameter(InvalidParameterError::SmartContract(
                    "contract trigger callbacks take their arguments from the firing event; fixed argument records are not allowed".into(),
                )).into());
            }
            Executable::Instructions(_) | Executable::ContractCall(_) | Executable::Batch(_) => {
                return Ok(());
            }
        };
        let admitted = crate::smartcontracts::ivm::cache::IvmCache::with_prepared_contract_cache(
            0,
            prepared_contracts,
        )
        .summarize_executable(bytecode)
        .map_err(|error| {
            if let Some(reason) = crate::execution_attempt::ExecutionDeferred::from_vm_error(&error)
            {
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason)
            } else {
                crate::execution_attempt::ExecutionAttemptError::Rejected(Error::InvalidParameter(
                    InvalidParameterError::SmartContract(format!(
                        "invalid IVM trigger program: {error}"
                    )),
                ))
            }
        })?;
        if matches!(
            admitted,
            crate::smartcontracts::ivm::cache::ExecutableProgramSummary::Generic(_)
        ) {
            crate::smartcontracts::ivm::validate_generic_execution_metadata(metadata).map_err(
                |error| {
                    Error::InvalidParameter(InvalidParameterError::SmartContract(error.to_string()))
                },
            )?;
        }
        crate::smartcontracts::ivm::validate_cycle_limits(admitted.metadata(), upper_bound, fuel)
            .map_err(|error| {
            Error::InvalidParameter(InvalidParameterError::SmartContract(error.to_string()))
        })?;
        Ok(())
    }
    fn is_permission_trigger_associated_with_any(
        permission: &iroha_data_model::permission::Permission,
        trigger_ids: &std::collections::BTreeSet<TriggerId>,
    ) -> bool {
        if let Ok(permission) =
            iroha_executor_data_model::permission::trigger::CanUnregisterTrigger::try_from(
                permission,
            )
        {
            return trigger_ids.contains(&permission.trigger);
        }
        if let Ok(permission) =
            iroha_executor_data_model::permission::trigger::CanModifyTrigger::try_from(permission)
        {
            return trigger_ids.contains(&permission.trigger);
        }
        if let Ok(permission) =
            iroha_executor_data_model::permission::trigger::CanExecuteTrigger::try_from(permission)
        {
            return trigger_ids.contains(&permission.trigger);
        }
        if let Ok(permission) =
            iroha_executor_data_model::permission::trigger::CanModifyTriggerMetadata::try_from(
                permission,
            )
        {
            return trigger_ids.contains(&permission.trigger);
        }
        false
    }
    pub(crate) fn remove_trigger_associated_permissions(
        state_transaction: &mut StateTransaction<'_, '_>,
        trigger_id: &TriggerId,
    ) {
        remove_trigger_associated_permissions_for_ids(
            state_transaction,
            &std::collections::BTreeSet::from([trigger_id.clone()]),
        );
    }
    /// Remove every account and role capability tied to one of the supplied trigger ids.
    ///
    /// The permission stores are each traversed once regardless of how many trigger ids
    /// were depleted together.
    pub(crate) fn remove_trigger_associated_permissions_for_ids(
        state_transaction: &mut StateTransaction<'_, '_>,
        trigger_ids: &std::collections::BTreeSet<TriggerId>,
    ) {
        if trigger_ids.is_empty() {
            return;
        }
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
                        is_permission_trigger_associated_with_any(permission, trigger_ids)
                    })
                });
            if !should_remove {
                continue;
            }
            let remove_entry = if let Some(permissions) =
                state_transaction.world.account_permissions.get_mut(&holder)
            {
                permissions.retain(|permission| {
                    !is_permission_trigger_associated_with_any(permission, trigger_ids)
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
                        is_permission_trigger_associated_with_any(permission, trigger_ids)
                    })
                });
            if !should_remove {
                continue;
            }
            let impacted_accounts = state_transaction.accounts_with_role(&role_id);
            if let Some(role) = state_transaction.world.roles.get_mut(&role_id) {
                role.permissions.retain(|permission| {
                    !is_permission_trigger_associated_with_any(permission, trigger_ids)
                });
                role.permission_epochs
                    .retain(|permission, _| role.permissions.contains(permission));
            }
            if !impacted_accounts.is_empty() {
                state_transaction.invalidate_permission_cache_for(impacted_accounts.iter());
            }
        }
    }
    #[allow(clippy::too_many_lines)]
    pub(crate) fn register_trigger_internal(
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
        trigger: Trigger,
        preauthorized_manifest_contract_subject: Option<&AccountId>,
    ) -> Result<(), Error> {
        let mut new_trigger = trigger;
        state_transaction.validate_execution_output_registration(&new_trigger)?;
        if new_trigger.action().repeats().is_depleted() {
            return Err(Error::InvalidParameter(
                InvalidParameterError::SmartContract(
                    "trigger repeat count must be greater than zero".into(),
                ),
            ));
        }
        // An outbound SCCP record is signed-only (`specs/sccp.md` §4.4): a trigger body is an
        // opaque deferred executable, so refuse the action before it is stored. Execution
        // re-checks every derived group, including contract outputs and multisig approvals.
        if crate::deferred_authority::trigger_executable_derives_sccp_outbound_record(
            new_trigger.action().executable(),
        ) {
            return Err(Error::InvalidParameter(
                InvalidParameterError::SmartContract(
                    "a trigger action cannot derive `RecordSccpMessage`; an outbound SCCP record must be a signed transaction instruction or an instruction of a multisig proposal approved by signed transactions"
                        .into(),
                ),
            ));
        }
        enforce_ivm_trigger_program_policy(
            new_trigger.action().executable(),
            new_trigger.metadata(),
            state_transaction.pipeline.ivm_max_cycles_upper_bound,
            state_transaction
                .world
                .parameters
                .get()
                .smart_contract()
                .fuel(),
            state_transaction.prepared_contract_cache(),
        )
        .map_err(|error| state_transaction.attempt_error_to_instruction_error(error))?;
        let data_scope_authorization =
            enforce_data_trigger_scope_and_capacity(state_transaction, authority, &new_trigger)?;
        {
            // Enforce minimal permission: only genesis block, the trigger owner,
            // an account with CanRegisterTrigger{authority: <owner>}, or the
            // contract lifecycle path for its exact derived and already-registered
            // subject may register the trigger. Alias-domain ownership does not
            // authorize acting as the canonical, domainless account.
            let owner = new_trigger.action().authority().clone();
            let is_preauthorized_manifest_contract_subject =
                preauthorized_manifest_contract_subject.is_some_and(|subject| subject == &owner);
            if is_preauthorized_manifest_contract_subject {
                state_transaction.world.account(&owner).map_err(|_| {
                    Error::InvalidParameter(InvalidParameterError::SmartContract(
                        format!(
                            "contract manifest trigger authority `{owner}` must be registered before activation"
                        )
                        .into(),
                    ))
                })?;
            }
            let is_genesis = state_transaction._curr_block.is_genesis();
            let is_owner = authority == &owner;
            let has_permission =
                (!is_genesis) && state_transaction.can_register_trigger_for(authority, &owner);
            if !(is_genesis
                || is_owner
                || has_permission
                || is_preauthorized_manifest_contract_subject)
            {
                return Err(Error::InvalidParameter(
                    InvalidParameterError::SmartContract(format!(
                        "Missing CanRegisterTrigger{{authority: {owner}}} permission for {authority}"
                    )),
                ));
            }
        }
        if let EventFilterBox::Time(TimeEventFilter(ExecutionTime::Schedule(schedule))) =
            new_trigger.action().filter()
        {
            if let Some(period_ms) = schedule.period_ms {
                if period_ms == 0 {
                    return Err(Error::InvalidParameter(
                        InvalidParameterError::SmartContract(
                            "Time trigger period must be greater than zero".into(),
                        ),
                    ));
                }
                let min_period_ms = state_transaction
                    .world
                    .parameters
                    .sumeragi()
                    .block_cadence_ms()
                    .get();
                if period_ms < min_period_ms {
                    return Err(Error::InvalidParameter(
                        InvalidParameterError::SmartContract(
                            format!(
                                "Time trigger period must be at least the signed block cadence of {min_period_ms} ms"
                            )
                            .into(),
                        ),
                    ));
                }
            }
        }
        if new_trigger.action().retry_policy().is_some()
            && !matches!(
                new_trigger.action().filter(),
                EventFilterBox::Time(TimeEventFilter(ExecutionTime::Schedule(_)))
            )
        {
            return Err(Error::InvalidParameter(
                InvalidParameterError::SmartContract(
                    "time-trigger retry policy is only supported for scheduled time triggers"
                        .into(),
                ),
            ));
        }
        let duplicates_enacted_payout =
            |invocation: &iroha_data_model::transaction::executable::ContractInvocation| {
                crate::validation_fee::is_enacted_validation_fee_payout_invocation(
                    state_transaction,
                    invocation,
                )
            };
        let executable_duplicates_enacted_payout = match new_trigger.action().executable() {
            Executable::ContractCall(invocation) => duplicates_enacted_payout(invocation),
            Executable::Batch(items) => items.iter().any(|item| {
                matches!(
                    item,
                    iroha_data_model::transaction::executable::ExecutableBatchItem::ContractCall(
                        invocation
                    )
                        if duplicates_enacted_payout(invocation)
                )
            }),
            Executable::Instructions(_) | Executable::Ivm(_) | Executable::IvmProved(_) => false,
        };
        if matches!(new_trigger.action().filter(), EventFilterBox::Time(_))
            && executable_duplicates_enacted_payout
        {
            return Err(Error::InvariantViolation(
                "an enacted validation-fee payout lifecycle pins its sole scheduled trigger".into(),
            ));
        }
        if let EventFilterBox::Pipeline(filter) = new_trigger.action().filter() {
            match filter {
                PipelineEventFilterBox::Transaction(filter)
                    if matches!(
                        filter.status().as_ref(),
                        Some(TransactionStatus::Approved | TransactionStatus::Rejected(_))
                    ) => {}
                PipelineEventFilterBox::Block(filter)
                    if matches!(filter.status().as_ref(), Some(BlockStatus::Approved)) => {}
                _ => {
                    return Err(Error::InvalidParameter(
                        InvalidParameterError::SmartContract(
                            "pipeline triggers may only target deterministic transaction Approved/Rejected or block Approved events"
                                .into(),
                        ),
                    ));
                }
            }
        }
        // Mark the registration block so scheduled time and pipeline callbacks do not
        // inherit a same-block match from an older incarnation of the same ID. Data
        // and explicit-call triggers intentionally remain executable in-transaction.
        {
            use iroha_primitives::json::Json;
            enforce_trigger_metadata_limits(new_trigger.action().metadata(), state_transaction)?;
            let key_height = TRIGGER_REGISTERED_BLOCK_HEIGHT_METADATA_KEY
                .parse::<Name>()
                .expect("Valid metadata key");
            let key_time = "__registered_at_ms"
                .parse::<Name>()
                .expect("Valid metadata key");
            let height = state_transaction._curr_block.height().get();
            let created_ms = state_transaction._curr_block.creation_time().as_millis();
            let created_ms = u64::try_from(created_ms).unwrap_or(u64::MAX);
            let mut metadata = new_trigger.action().clone().metadata;
            metadata.insert(key_height, Json::from(height));
            metadata.insert(key_time, Json::from(created_ms));
            if let Some(authorization) = data_scope_authorization {
                let (mode, grantee) = match authorization {
                    DataTriggerScopeAuthorization::Owned => {
                        (DATA_TRIGGER_SCOPE_AUTHORIZATION_OWNED, None)
                    }
                    DataTriggerScopeAuthorization::GlobalPermission(grantee) => {
                        (DATA_TRIGGER_SCOPE_AUTHORIZATION_GLOBAL, Some(grantee))
                    }
                };
                metadata.insert(
                    data_trigger_scope_authorization_key().clone(),
                    Json::new(mode),
                );
                if let Some(grantee) = grantee {
                    metadata.insert(
                        data_trigger_scope_authorization_grantee_key().clone(),
                        Json::new(grantee),
                    );
                }
            }
            let action = new_trigger.action().clone().with_metadata(metadata);
            new_trigger = Trigger::new(new_trigger.id().clone(), action);
        }
        if !new_trigger.action().filter().mintable() {
            match new_trigger.action().repeats() {
                Repeats::Exactly(1) => (),
                _ => {
                    return Err(MathError::Overflow.into());
                }
            }
        }
        let triggers = &mut state_transaction.world.triggers;
        let trigger_id = new_trigger.id().clone();
        let success = match new_trigger.action().filter() {
            EventFilterBox::Data(_) => triggers.add_data_trigger(
                new_trigger
                    .try_into()
                    .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
            ),
            EventFilterBox::Pipeline(_) => triggers.add_pipeline_trigger(
                new_trigger
                    .try_into()
                    .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
            ),
            EventFilterBox::Time(_time_filter) => triggers.add_time_trigger(
                new_trigger
                    .try_into()
                    .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
            ),
            EventFilterBox::ExecuteTrigger(_) => triggers.add_by_call_trigger(
                new_trigger
                    .try_into()
                    .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
            ),
            EventFilterBox::TriggerCompleted(_) => {
                unreachable!("Disallowed during deserialization");
            }
        }
        .map_err(|e| InvalidParameterError::SmartContract(e.to_string()))?;
        if !success {
            return Err(RepetitionError {
                instruction: InstructionType::Register,
                id: trigger_id.into(),
            }
            .into());
        }
        state_transaction
            .world
            .emit_events(Some(TriggerEvent::Created(trigger_id)));
        Ok(())
    }
    impl Execute for Register<Trigger> {
        #[metrics(+"register_trigger")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            register_trigger_internal(authority, state_transaction, self.object().clone(), None)
        }
    }
    impl Execute for Unregister<Trigger> {
        #[metrics(+"unregister_trigger")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let trigger_id = self.object().clone();
            if crate::validation_fee::is_enacted_validation_fee_payout_trigger(
                state_transaction,
                &trigger_id,
            ) {
                return Err(Error::InvariantViolation(
                    "an enacted validation-fee payout lifecycle pins this trigger".into(),
                ));
            }
            if state_transaction.world.triggers.remove(&trigger_id) {
                remove_trigger_associated_permissions(state_transaction, &trigger_id);
                state_transaction
                    .world
                    .emit_events(Some(TriggerEvent::Deleted(trigger_id)));
                Ok(())
            } else {
                Err(RepetitionError {
                    instruction: InstructionType::Unregister,
                    id: trigger_id.into(),
                }
                .into())
            }
        }
    }
    impl Execute for Mint<u32, Trigger> {
        #[metrics(+"mint_trigger_repetitions")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let id = self.destination().clone();
            if crate::validation_fee::is_enacted_validation_fee_payout_trigger(
                state_transaction,
                &id,
            ) {
                return Err(Error::InvariantViolation(
                    "an enacted validation-fee payout lifecycle pins this trigger".into(),
                ));
            }
            let triggers = &mut state_transaction.world.triggers;
            triggers
                .inspect_by_id(&id, |action| -> Result<(), Error> {
                    if action.mintable() {
                        Ok(())
                    } else {
                        Err(MathError::Overflow.into())
                    }
                })
                .ok_or_else(|| Error::Find(FindError::Trigger(id.clone())))??;
            triggers.mod_repeats(&id, |n| {
                n.checked_add(*self.object())
                    .ok_or(super::set::RepeatsOverflowError)
            })?;
            state_transaction
                .world
                .emit_events(Some(TriggerEvent::Extended(
                    TriggerNumberOfExecutionsChanged {
                        trigger: id,
                        by: *self.object(),
                    },
                )));
            Ok(())
        }
    }
    impl Execute for Burn<u32, Trigger> {
        #[metrics(+"burn_trigger_repetitions")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let trigger = self.destination().clone();
            if crate::validation_fee::is_enacted_validation_fee_payout_trigger(
                state_transaction,
                &trigger,
            ) {
                return Err(Error::InvariantViolation(
                    "an enacted validation-fee payout lifecycle pins this trigger".into(),
                ));
            }
            let mut removed = false;
            {
                let triggers = &mut state_transaction.world.triggers;
                triggers.mod_repeats(&trigger, |n| {
                    n.checked_sub(*self.object())
                        .ok_or(super::set::RepeatsOverflowError)
                })?;
                // Remove triggers that reached zero repeats immediately to avoid latent state
                let should_remove = triggers
                    .inspect_by_id(&trigger, |action| action.repeats().is_depleted())
                    .unwrap_or(false);
                if should_remove {
                    removed = triggers.remove(&trigger);
                }
            }
            if removed {
                remove_trigger_associated_permissions(state_transaction, &trigger);
            }
            state_transaction
                .world
                .emit_events(Some(TriggerEvent::Shortened(
                    TriggerNumberOfExecutionsChanged {
                        trigger,
                        by: *self.object(),
                    },
                )));
            Ok(())
        }
    }
    impl Execute for SetKeyValue<Trigger> {
        #[metrics(+"set_trigger_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let SetKeyValue {
                object: trigger_id,
                key,
                value,
            } = self;
            if crate::validation_fee::is_enacted_validation_fee_payout_trigger(
                state_transaction,
                &trigger_id,
            ) {
                return Err(Error::InvariantViolation(
                    "an enacted validation-fee payout lifecycle pins this trigger".into(),
                ));
            }
            ensure_metadata_key_is_not_reserved(&key)?;
            crate::smartcontracts::limits::enforce_json_size(
                state_transaction,
                &value,
                "max_metadata_value_bytes",
                crate::smartcontracts::limits::DEFAULT_JSON_LIMIT,
            )?;
            state_transaction
                .world
                .triggers
                .inspect_by_id_mut(&trigger_id, |action| {
                    action.metadata_mut().insert(key.clone(), value.clone())
                })
                .ok_or(FindError::Trigger(trigger_id.clone()))?;
            state_transaction
                .world
                .emit_events(Some(TriggerEvent::MetadataInserted(MetadataChanged {
                    target: trigger_id,
                    key,
                    value,
                })));
            Ok(())
        }
    }
    impl Execute for RemoveKeyValue<Trigger> {
        #[metrics(+"remove_trigger_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let trigger_id = self.object().clone();
            if crate::validation_fee::is_enacted_validation_fee_payout_trigger(
                state_transaction,
                &trigger_id,
            ) {
                return Err(Error::InvariantViolation(
                    "an enacted validation-fee payout lifecycle pins this trigger".into(),
                ));
            }
            ensure_metadata_key_is_not_reserved(self.key())?;
            let value = state_transaction
                .world
                .triggers
                .inspect_by_id_mut(&trigger_id, |action| {
                    action
                        .metadata_mut()
                        .remove(self.key().as_ref())
                        .ok_or_else(|| FindError::MetadataKey(self.key().clone()))
                })
                .ok_or(FindError::Trigger(trigger_id.clone()))??;
            state_transaction
                .world
                .emit_events(Some(TriggerEvent::MetadataRemoved(MetadataChanged {
                    target: trigger_id,
                    key: self.key().clone(),
                    value,
                })));
            Ok(())
        }
    }
    impl Execute for ExecuteTrigger {
        #[metrics(+"execute_trigger")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            // Enforce args payload size
            enforce_payload_limit(state_transaction, self.args())?;
            let id = self.trigger();
            let event = ExecuteTriggerEvent {
                trigger_id: id.clone(),
                authority: authority.clone(),
                args: self.args().clone(),
            };
            // Keep lookup, lifecycle cleanup, filter matching, and authorization in
            // one use-time boundary. A second preflight copy here can reject a stale
            // depleted entry before the cleanup path or drift from helper semantics.
            // Step output is intentionally dropped because completion is surfaced by events.
            let _step = state_transaction
                .execute_called_trigger(id, &event)
                .map_err(|rej| {
                    iroha_logger::debug!(
                        ?rej,
                        trigger_id = %id,
                        authority = %authority,
                        "execute_called_trigger rejected"
                    );
                    match rej {
                        TransactionRejectionReason::Validation(vf) => {
                            iroha_logger::debug!(
                                ?vf,
                                trigger_id = %id,
                                authority = %authority,
                                "validation failure while executing trigger"
                            );
                            match vf {
                                ValidationFail::InstructionFailed(ie) => {
                                    iroha_logger::debug!(
                                        ?ie,
                                        trigger_id = %id,
                                        authority = %authority,
                                        "trigger execution returned instruction error"
                                    );
                                    ie
                                }
                                ValidationFail::NotPermitted(msg) => {
                                    iroha_logger::debug!(
                                        %msg,
                                        trigger_id = %id,
                                        authority = %authority,
                                        "trigger execution not permitted"
                                    );
                                    Error::InvalidParameter(InvalidParameterError::SmartContract(
                                        msg,
                                    ))
                                }
                                other => {
                                    iroha_logger::debug!(
                                        ?other,
                                        trigger_id = %id,
                                        authority = %authority,
                                        "trigger validation produced unexpected failure"
                                    );
                                    Error::Conversion(format!("Validation failed: {other}"))
                                }
                            }
                        }
                        TransactionRejectionReason::InstructionExecution(fail) => {
                            iroha_logger::debug!(
                                ?fail,
                                trigger_id = %id,
                                authority = %authority,
                                "trigger rejected due to instruction execution fail"
                            );
                            Error::Conversion(format!("Instruction execution: {fail}"))
                        }
                        TransactionRejectionReason::TriggerExecution(err) => {
                            iroha_logger::debug!(
                                ?err,
                                trigger_id = %id,
                                authority = %authority,
                                "trigger rejected while executing nested trigger"
                            );
                            Error::Conversion(format!("Trigger execution: {err:?}"))
                        }
                        TransactionRejectionReason::AccountDoesNotExist(err) => {
                            iroha_logger::debug!(
                                ?err,
                                trigger_id = %id,
                                authority = %authority,
                                "trigger rejected because account was missing"
                            );
                            Error::Find(err)
                        }
                        TransactionRejectionReason::LimitCheck(err) => {
                            iroha_logger::debug!(
                                ?err,
                                trigger_id = %id,
                                authority = %authority,
                                "trigger rejected due to limit check"
                            );
                            Error::Conversion(format!("Limit check: {err}"))
                        }
                    }
                })?;
            Ok(())
        }
    }
    /// Enforce a maximum JSON size for metadata values.
    // centralized in smartcontracts::limits
    /// Enforce a maximum JSON size for instruction payloads.
    fn enforce_payload_limit(
        state_transaction: &mut StateTransaction<'_, '_>,
        value: &Json,
    ) -> Result<(), Error> {
        const DEFAULT_MAX: usize = 1_048_576; // 1 MiB
        const PARAM_NAME: &str = "max_instruction_payload_bytes";
        let params = state_transaction.world.parameters.get();
        let limit = if let Ok(name) = core::str::FromStr::from_str(PARAM_NAME)
            && let Some(custom) = params
                .custom()
                .get(&iroha_data_model::parameter::CustomParameterId(name))
            && let Ok(num) = custom.payload().try_into_any_norito::<u64>()
        {
            usize::try_from(num).unwrap_or(usize::MAX)
        } else {
            DEFAULT_MAX
        };
        if value.as_ref().len() > limit {
            return Err(Error::InvalidParameter(
                InvalidParameterError::SmartContract(format!(
                    "Instruction payload too large: {} > {} bytes",
                    value.as_ref().len(),
                    limit
                )),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod admission_tests {
        use super::*;

        #[test]
        fn instruction_payload_of_exactly_the_bound_is_admitted_and_one_byte_more_is_refused() {
            use crate::{
                kura::Kura,
                query::store::LiveQueryStore,
                state::{State, World},
            };
            use iroha_data_model::parameter::{CustomParameter, CustomParameterId, Parameter};
            use iroha_primitives::json::Json;
            use std::str::FromStr as _;

            /// A JSON array document of exactly `bytes` bytes: `["xx..x"]`.
            fn payload(bytes: usize) -> Json {
                let value = Json::new(vec!["x".repeat(bytes - 4)]);
                assert_eq!(value.get().len(), bytes, "the fixture has the asked size");
                value
            }
            /// A bare JSON string whose content, without its quotes, has `bytes` bytes.
            fn string_payload(bytes: usize) -> Json {
                let value = Json::new("x".repeat(bytes));
                assert_eq!(
                    value.get().len(),
                    bytes + 2,
                    "two quotes surround the content"
                );
                value
            }

            let state = State::new_for_testing(
                World::default(),
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
            );
            let header = iroha_data_model::block::BlockHeader::new(
                core::num::NonZeroU64::MIN,
                None,
                None,
                0,
                0,
            );
            let mut block = state.block(header);
            let mut transaction = block.transaction();
            let refused = |error: Error, expected: &str| {
                assert!(
                    matches!(
                        &error,
                        Error::InvalidParameter(InvalidParameterError::SmartContract(message))
                            if message == expected
                    ),
                    "unexpected refusal: {error:?}"
                );
            };
            // No custom parameter is committed: the default (1 MiB) applies and a payload
            // of exactly the default is admitted. The default is also the largest JSON
            // document the data model can hold, so no payload of one byte more exists.
            enforce_payload_limit(&mut transaction, &payload(1_048_576))
                .expect("a payload of exactly the default bound is admitted");
            assert_eq!(iroha_primitives::json::MAX_JSON_BYTES, 1_048_576);
            assert!(Json::try_new(vec!["x".repeat(1_048_576 - 3)]).is_err());
            // A committed custom parameter replaces the default: exactly its value is
            // admitted and one byte more is refused.
            let name = CustomParameterId::from_str("max_instruction_payload_bytes")
                .expect("parameter name");
            transaction
                .world
                .parameters_mut_for_testing()
                .get_mut()
                .set_parameter(Parameter::Custom(CustomParameter::new(
                    name,
                    Json::new(64_u64),
                )));
            enforce_payload_limit(&mut transaction, &payload(64))
                .expect("a payload of exactly the committed bound is admitted");
            refused(
                enforce_payload_limit(&mut transaction, &payload(65))
                    .expect_err("a payload one byte above the committed bound is refused"),
                "Instruction payload too large: 65 > 64 bytes",
            );
            // The length compared is that of `Json::as_ref`: the document, or for a bare
            // string its content without the two quotes.
            enforce_payload_limit(&mut transaction, &string_payload(64))
                .expect("a bare string is measured without its quotes");
            refused(
                enforce_payload_limit(&mut transaction, &string_payload(65))
                    .expect_err("a bare string of one content byte above the bound is refused"),
                "Instruction payload too large: 65 > 64 bytes",
            );
        }

        #[test]
        fn contract_trigger_registration_requires_event_supplied_arguments() {
            use crate::execution_attempt::ExecutionAttemptError;
            use crate::smartcontracts::ivm::cache::PreparedContractCache;
            use iroha_data_model::{
                smart_contract::ContractAddress,
                transaction::executable::{ContractArgumentRecord, ContractInvocation},
            };
            use iroha_model_base::topology::DataSpaceId;

            let mut invocation = ContractInvocation {
                contract_address: ContractAddress::derive(
                    &iroha_data_model::NetworkId::from_genesis_hash(
                        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                            b"contract callback registration test genesis",
                        )),
                    ),
                    &iroha_test_samples::ALICE_ID,
                    901,
                    DataSpaceId::UNIVERSAL,
                )
                .expect("canonical callback address"),
                expected_code_hash: iroha_crypto::Hash::new(b"callback artifact"),
                entrypoint: "on_execute".to_owned(),
                arguments: Some(
                    ContractArgumentRecord::try_new(Vec::new()).expect("bounded record"),
                ),
            };
            let bound = core::num::NonZeroU64::new(1).expect("nonzero bound");
            let check = |invocation| {
                enforce_ivm_trigger_program_policy(
                    &Executable::ContractCall(invocation),
                    &Metadata::default(),
                    bound,
                    bound,
                    PreparedContractCache::with_capacity(0),
                )
            };
            assert!(matches!(
                check(invocation.clone()),
                Err(ExecutionAttemptError::Rejected(Error::InvalidParameter(
                    InvalidParameterError::SmartContract(message)
                ))) if message.contains("firing event") && message.contains("fixed argument records")
            ));
            invocation.arguments = None;
            check(invocation).expect("callback arguments are supplied by the firing event");
        }

        #[test]
        fn generic_trigger_admission_preserves_original_pool_refusal_and_retry() {
            use crate::execution_attempt::ExecutionAttemptError;
            use crate::smartcontracts::ivm::cache::PreparedContractCache;
            use iroha_allocation::{AllocationBudget, AllocationRefusal};

            let mut program = ivm::ProgramMetadata {
                max_cycles: 10_000,
                ..ivm::ProgramMetadata::default()
            }
            .encode();
            program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
            let executable = Executable::Ivm(IvmBytecode::from_compiled(program));
            let bound = core::num::NonZeroU64::new(10_000).unwrap();
            let budget = AllocationBudget::new(0);
            let cache = PreparedContractCache::with_execution_budget(0, budget.clone());
            let result = enforce_ivm_trigger_program_policy(
                &executable,
                &Metadata::default(),
                bound,
                bound,
                cache.clone(),
            );
            let Err(ExecutionAttemptError::Deferred(reason)) = result else {
                panic!("original pool pressure must not become trigger rejection");
            };
            assert!(matches!(
                reason.allocation_refusal(),
                Some(AllocationRefusal::ExceedsLimit { limit_bytes: 0, .. })
            ));
            assert_eq!(budget.peak_reserved_bytes(), 0);
            budget.set_limit_bytes(64 * 1024 * 1024);
            enforce_ivm_trigger_program_policy(
                &executable,
                &Metadata::default(),
                bound,
                bound,
                cache,
            )
            .expect("same original pool admits after local pressure resolves");
            assert!(budget.peak_reserved_bytes() > 0);
            assert_eq!(budget.reserved_bytes(), 0);
        }

        #[test]
        fn proved_ivm_trigger_policy_rejects_before_bytecode_admission() {
            let executable =
                Executable::IvmProved(iroha_data_model::transaction::executable::IvmProved {
                    bytecode: iroha_data_model::transaction::IvmBytecode::from_compiled(Vec::new()),
                    overlay: Vec::<InstructionBox>::new().into(),
                    events_commitment: iroha_crypto::Hash::new(b"trigger-events"),
                    gas_policy_commitment: iroha_crypto::Hash::new(b"trigger-gas"),
                });
            let bound = core::num::NonZeroU64::new(1).expect("nonzero bound");
            assert!(matches!(
                enforce_ivm_trigger_program_policy(
                    &executable,
                    &Metadata::default(),
                    bound,
                    bound,
                    crate::smartcontracts::ivm::cache::PreparedContractCache::with_capacity(0),
                ),
                Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                    Error::InvalidParameter(InvalidParameterError::SmartContract(message))
                ))
                    if message == "proof-backed IVM triggers are unavailable"
            ));
        }
    }
}
pub mod query {
    //! Queries associated to triggers.
    use super::*;
    use crate::smartcontracts::isi::query::json_predicate::{
        intersect_candidate_ids, predicate_matches_with_aliases,
    };
    use crate::{
        prelude::*,
        smartcontracts::{ValidQuery, ValidSingularQuery, triggers::set::SetReadOnly},
        state::StateReadOnly,
    };
    use iroha_data_model::{
        query::{
            dsl::{CompoundPredicate, EvaluatePredicate},
            error::QueryExecutionFail as Error,
            json::PredicateJson,
            trigger::{FindTriggerById, FindTriggers},
        },
        trigger::{Trigger, TriggerId},
    };
    use mv::storage::StorageReadOnly;
    use norito::json::Value;
    use std::collections::BTreeSet;
    fn trigger_id_from_value(value: &Value) -> Option<TriggerId> {
        norito::json::from_value(value.clone()).ok()
    }
    fn trigger_candidate_ids(predicate: &PredicateJson) -> Option<BTreeSet<TriggerId>> {
        let mut best = None;
        for cond in &predicate.equals {
            if cond.field == "id" {
                intersect_candidate_ids(
                    &mut best,
                    trigger_id_from_value(&cond.value).into_iter().collect(),
                );
            }
        }
        for cond in &predicate.r#in {
            if cond.field == "id" {
                intersect_candidate_ids(
                    &mut best,
                    cond.values
                        .iter()
                        .filter_map(trigger_id_from_value)
                        .collect(),
                );
            }
        }
        best
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn trigger_candidate_ids_are_intersected() {
            let rose_id: TriggerId = "intersect_rose".parse().unwrap();
            let tulip_id: TriggerId = "intersect_tulip".parse().unwrap();
            let iris_id: TriggerId = "intersect_iris".parse().unwrap();
            let mut candidates = None;
            intersect_candidate_ids(&mut candidates, BTreeSet::from([rose_id.clone(), tulip_id]));
            intersect_candidate_ids(&mut candidates, BTreeSet::from([rose_id.clone(), iris_id]));
            assert_eq!(candidates, Some(BTreeSet::from([rose_id])));
        }
    }
    fn trigger_alias_values(trigger: &Trigger, field: &str) -> Vec<String> {
        match field {
            "id" => vec![trigger.id().to_string()],
            _ => Vec::new(),
        }
    }
    fn trigger_id_alias_values(id: &TriggerId, field: &str) -> Vec<String> {
        match field {
            "id" => vec![id.to_string()],
            _ => Vec::new(),
        }
    }
    fn predicate_matches_trigger(predicate: &PredicateJson, trigger: &Trigger) -> bool {
        predicate_matches_with_aliases(predicate, trigger, trigger_alias_values)
    }
    fn predicate_matches_trigger_id(predicate: &PredicateJson, id: &TriggerId) -> bool {
        predicate_matches_with_aliases(predicate, id, trigger_id_alias_values)
    }
    fn trigger_id_is_active(triggers: &impl SetReadOnly, id: &TriggerId) -> bool {
        triggers.active_data_trigger_ids().get(id).is_some()
            || triggers.active_pipeline_trigger_ids().get(id).is_some()
            || triggers.active_time_trigger_ids().get(id).is_some()
            || triggers.active_by_call_trigger_ids().get(id).is_some()
    }
    impl ValidQuery for FindActiveTriggerIds {
        #[metrics(+"find_active_triggers")]
        fn execute(
            self,
            filter: CompoundPredicate<TriggerId>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = TriggerId>, Error> {
            let triggers = state_ro.world().triggers();
            let predicate_json = filter.json_payload().and_then(
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution,
            );
            if let Some(candidate_ids) = predicate_json.as_ref().and_then(trigger_candidate_ids) {
                let iter: Box<dyn Iterator<Item = TriggerId> + '_> =
                    Box::new(candidate_ids.into_iter().filter(move |id| {
                        trigger_id_is_active(triggers, id)
                            && predicate_json.as_ref().map_or_else(
                                || filter.applies(id),
                                |predicate| predicate_matches_trigger_id(predicate, id),
                            )
                    }));
                return Ok(iter);
            }
            let iter: Box<dyn Iterator<Item = TriggerId> + '_> =
                Box::new(triggers.active_trigger_ids_iter().cloned());
            if filter.json_payload().is_none() {
                return Ok(iter);
            }
            // Only report triggers that are actually active (i.e., have
            // remaining executions). This makes the query resilient to any
            // edge case where a depleted trigger could temporarily remain
            // registered during a transaction before being pruned.
            Ok(Box::new(iter.filter(move |id| {
                predicate_json.as_ref().map_or_else(
                    || filter.applies(id),
                    |predicate| predicate_matches_trigger_id(predicate, id),
                )
            })))
        }
    }
    impl ValidQuery for FindTriggers {
        #[metrics(+"find_triggers")]
        fn execute(
            self,
            filter: CompoundPredicate<Trigger>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = Self::Item>, Error> {
            let triggers = state_ro.world().triggers();
            let predicate_json = filter.json_payload().and_then(
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution,
            );
            if let Some(candidate_ids) = predicate_json.as_ref().and_then(trigger_candidate_ids) {
                let iter: Box<dyn Iterator<Item = Trigger> + '_> =
                    Box::new(candidate_ids.into_iter().filter_map(move |id| {
                        triggers.trigger_by_id(&id).filter(|trigger| {
                            if let Some(predicate) = predicate_json.as_ref() {
                                predicate_matches_trigger(predicate, trigger)
                            } else {
                                filter.applies(trigger)
                            }
                        })
                    }));
                return Ok(iter);
            }
            let iter: Box<dyn Iterator<Item = Trigger> + '_> = Box::new(triggers.triggers_iter());
            if filter.json_payload().is_none() {
                return Ok(iter);
            }
            Ok(Box::new(iter.filter(move |trigger| {
                if let Some(predicate) = predicate_json.as_ref() {
                    predicate_matches_trigger(predicate, trigger)
                } else {
                    filter.applies(trigger)
                }
            })))
        }
    }
    impl ValidSingularQuery for FindTriggerById {
        #[metrics(+"find_trigger_by_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Trigger, Error> {
            let trigger = state_ro
                .world()
                .triggers()
                .trigger_by_id_bounded(self.trigger_id())?
                .ok_or_else(|| Error::Find(FindError::Trigger(self.trigger_id().clone())))?;
            Ok(trigger)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block::ValidBlock,
        kura::Kura,
        query::store::LiveQueryStore,
        smartcontracts::{
            Error, Execute, ValidQuery,
            isi::triggers::{set::SetReadOnly, specialized::SpecializedTrigger},
        },
        state::{State, World, WorldReadOnly},
        sumeragi::network_topology::Topology,
    };
    use core::num::NonZeroU64;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        block::BlockHeader,
        events::time::Schedule,
        isi::error::{InstructionExecutionError, InvalidParameterError},
        parameter::{CustomParameter, CustomParameterId, Parameter},
        permission::Permission,
        role::{Role, RoleId},
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use iroha_primitives::json::Json;
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use mv::storage::StorageReadOnly;
    use std::{str::FromStr, time::Duration};
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("trigger fixture key generation should succeed")
    }
    /// Apply the original signed genesis before exercising a trigger's executor.
    fn authenticated_trigger_state() -> State {
        use crate::sumeragi::{
            startup,
            test_chain::{CertifiedTestChain, TestChainConfig},
        };

        let config = TestChainConfig::new(World::default(), 0);
        let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
        let consensus_mode = config.consensus_mode;
        let prepared =
            CertifiedTestChain::prepare(config).expect("prepare trigger fixture genesis");
        let state = std::sync::Arc::try_unwrap(prepared.state)
            .unwrap_or_else(|_| panic!("unpublished trigger fixture State is unique"));
        startup::apply_genesis(
            &state,
            prepared.genesis.block().clone(),
            &genesis_account,
            consensus_mode.into(),
            None,
        )
        .expect("apply the trigger fixture's signed genesis");
        state
    }
    fn authenticated_trigger_header(state: &State) -> BlockHeader {
        BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            state.view().latest_block_hash(),
            None,
            1,
            0,
        )
    }
    #[test]
    fn by_call_fixture_requires_an_original_applied_root_before_dispatch() {
        let state = authenticated_trigger_state();
        assert_eq!(state.committed_height(), 1);
        assert_eq!(state.kura().blocks_count(), 1);
        let parent = state
            .view()
            .latest_block_hash()
            .expect("original genesis hash");
        assert_eq!(state.network_id_ref().into_genesis_hash(), parent);
        let header = authenticated_trigger_header(&state);
        assert_eq!(header.prev_block_hash(), Some(parent));
        let mut block = state.block(header);
        let mut transaction = block.transaction_for_callback_testing();
        assert!(crate::executor::root_scope::execution_root_scope(&mut transaction).is_ok());
        drop(transaction);
        drop(block);
        let component = State::new(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = component.block(authenticated_trigger_header(&component));
        let mut transaction = block.transaction_for_callback_testing();
        assert!(crate::executor::root_scope::execution_root_scope(&mut transaction).is_err());
    }
    fn assert_smart_contract_error_contains(error: &Error, expected: &str) {
        let Error::InvalidParameter(InvalidParameterError::SmartContract(message)) = error else {
            panic!("expected a smart-contract parameter error, got {error:?}");
        };
        assert!(
            message.contains(expected),
            "unexpected smart-contract parameter error: {error:?}"
        );
    }
    fn data_trigger(id: &str, authority: AccountId, filter: impl Into<EventFilterBox>) -> Trigger {
        Trigger::new(
            id.parse().expect("valid trigger id"),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                authority,
                filter,
            )
            .expect("valid data-trigger action"),
        )
    }
    fn by_call_trigger(id: TriggerId, authority: AccountId) -> Trigger {
        Trigger::new(
            id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                authority.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(id)
                    .under_authority(authority),
            )
            .expect("valid by-call trigger action"),
        )
    }
    #[test]
    fn checked_keypair_preserves_default_algorithm() {
        assert_eq!(checked_keypair().algorithm(), Algorithm::default());
    }
    #[test]
    fn ordinary_data_triggers_require_an_exact_owned_subject() {
        let state = State::new(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register alice");
        Register::account(Account::new(BOB_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register bob");
        stx._curr_block
            .set_height(NonZeroU64::new(2).expect("nonzero height"));

        Register::trigger(data_trigger(
            "owned_account_scope",
            ALICE_ID.clone(),
            AccountEventFilter::new().for_account(ALICE_ID.clone()),
        ))
        .execute(&ALICE_ID, &mut stx)
        .expect("the trigger authority may bind its exact account");

        for trigger in [
            data_trigger(
                "foreign_account_scope",
                ALICE_ID.clone(),
                AccountEventFilter::new().for_account(BOB_ID.clone()),
            ),
            data_trigger(
                "unbound_account_scope",
                ALICE_ID.clone(),
                AccountEventFilter::new(),
            ),
            data_trigger("any_data_scope", ALICE_ID.clone(), DataEventFilter::Any),
        ] {
            let error = Register::trigger(trigger)
                .execute(&ALICE_ID, &mut stx)
                .expect_err("ordinary data trigger must stay within an exact owned subject");
            assert_smart_contract_error_contains(&error, "CanRegisterGlobalDataTrigger");
        }
    }
    #[test]
    fn global_data_trigger_permission_is_bound_to_the_trigger_authority() {
        let state = State::new(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register alice");
        Register::account(Account::new(BOB_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register bob");
        let wrong_scope: Permission =
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: BOB_ID.clone(),
            }
            .into();
        Grant::account_permission(wrong_scope, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("seed wrong-scope genesis capability");
        stx._curr_block
            .set_height(NonZeroU64::new(2).expect("nonzero height"));
        let error = Register::trigger(data_trigger(
            "wrong_global_scope",
            ALICE_ID.clone(),
            DataEventFilter::Any,
        ))
        .execute(&ALICE_ID, &mut stx)
        .expect_err("a capability for another trigger authority must not match");
        assert_smart_contract_error_contains(&error, "CanRegisterGlobalDataTrigger");

        drop(stx);
        drop(state_block);
        let state = State::new(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut next_block = state.block(block.as_ref().header());
        let mut next = next_block.transaction();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut next)
            .expect("register alice");
        let exact: Permission =
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: ALICE_ID.clone(),
            }
            .into();
        Grant::account_permission(exact, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut next)
            .expect("seed exact genesis capability");
        next._curr_block
            .set_height(NonZeroU64::new(2).expect("nonzero height"));
        Register::trigger(data_trigger(
            "exact_global_scope",
            ALICE_ID.clone(),
            DataEventFilter::Any,
        ))
        .execute(&ALICE_ID, &mut next)
        .expect("the exact global capability authorizes global scope");
    }
    #[test]
    fn genesis_global_data_trigger_requires_prior_exact_capability_and_remains_revocable() {
        let state = State::new(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register genesis trigger authority");
        let trigger = data_trigger(
            "genesis_capability_ordering",
            ALICE_ID.clone(),
            DataEventFilter::Any,
        );
        let error = Register::trigger(trigger.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("genesis must not mint an uncredentialed global trigger");
        assert_smart_contract_error_contains(&error, "CanRegisterGlobalDataTrigger");

        let capability: Permission =
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: ALICE_ID.clone(),
            }
            .into();
        Grant::account_permission(capability.clone(), ALICE_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("grant exact genesis global-trigger capability first");
        Register::trigger(trigger)
            .execute(&ALICE_ID, &mut stx)
            .expect("capability-backed genesis global trigger registers");
        Revoke::account_permission(capability, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("revoke exact genesis global-trigger capability");
        stx.world.internal_event_buf.clear();
        Register::domain(Domain::new(
            DomainId::try_new("genesis_revoked_scope", "universal").expect("valid domain"),
        ))
        .execute(&ALICE_ID, &mut stx)
        .expect("emit data event after genesis capability revocation");
        assert!(
            stx.execute_data_triggers_dfs(&ALICE_ID)
                .expect("revoked genesis watcher must be skipped")
                .is_empty(),
            "genesis provenance must not outlive revocation",
        );
    }
    #[test]
    fn data_trigger_scope_recheck_blocks_reused_trigger_id() {
        let state = State::new(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction();
        for account in [ALICE_ID.clone(), BOB_ID.clone()] {
            Register::account(Account::new(account))
                .execute(&ALICE_ID, &mut stx)
                .expect("register account");
        }
        stx._curr_block
            .set_height(NonZeroU64::new(2).expect("nonzero height"));
        let target_id: TriggerId = "scope_reuse_target".parse().expect("valid trigger id");
        Register::trigger(by_call_trigger(target_id.clone(), ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register Alice-owned target");
        let watcher = data_trigger(
            "scope_reuse_watcher",
            ALICE_ID.clone(),
            TriggerEventFilter::new()
                .for_trigger(target_id.clone())
                .for_events(TriggerEventSet::MetadataInserted),
        );
        Register::trigger(watcher)
            .execute(&ALICE_ID, &mut stx)
            .expect("register exact owned watcher");
        Unregister::trigger(target_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("remove Alice-owned target");
        Register::trigger(by_call_trigger(target_id.clone(), BOB_ID.clone()))
            .execute(&BOB_ID, &mut stx)
            .expect("reuse target id under Bob");
        stx.world.internal_event_buf.clear();
        let key: Name = "safe_after_reuse".parse().expect("valid metadata key");
        SetKeyValue::trigger(target_id.clone(), key.clone(), Json::new(true))
            .execute(&BOB_ID, &mut stx)
            .expect("update Bob-owned replacement");
        let steps = stx
            .execute_data_triggers_dfs(&BOB_ID)
            .expect("stale watcher must be skipped, not fail the transaction");
        assert!(steps.is_empty(), "stale owner watcher must not fire");
        let stored = stx
            .world
            .triggers
            .inspect_by_id(&target_id, |action| action.metadata().get(&key).cloned())
            .flatten();
        assert_eq!(stored, Some(Json::new(true)));
    }
    #[test]
    fn data_trigger_scope_recheck_follows_domain_ownership() {
        let state = State::new(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction();
        for account in [ALICE_ID.clone(), BOB_ID.clone()] {
            Register::account(Account::new(account))
                .execute(&ALICE_ID, &mut stx)
                .expect("register account");
        }
        let domain_id = DomainId::try_new("scope_transfer", "universal").expect("valid domain");
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register Alice-owned domain");
        stx._curr_block
            .set_height(NonZeroU64::new(2).expect("nonzero height"));
        Register::trigger(data_trigger(
            "scope_transfer_watcher",
            ALICE_ID.clone(),
            DomainEventFilter::new()
                .for_domain(domain_id.clone())
                .for_events(DomainEventSet::MetadataInserted),
        ))
        .execute(&ALICE_ID, &mut stx)
        .expect("register exact owned domain watcher");
        Transfer::domain(ALICE_ID.clone(), domain_id.clone(), BOB_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("transfer domain to Bob");
        stx.world.internal_event_buf.clear();
        let key: Name = "safe_after_transfer".parse().expect("valid metadata key");
        SetKeyValue::domain(domain_id.clone(), key.clone(), Json::new(true))
            .execute(&BOB_ID, &mut stx)
            .expect("update transferred domain");
        let steps = stx
            .execute_data_triggers_dfs(&BOB_ID)
            .expect("former owner's watcher must be skipped");
        assert!(steps.is_empty(), "former owner's watcher must not fire");
        assert_eq!(
            stx.world
                .domain(&domain_id)
                .expect("domain remains registered")
                .metadata()
                .get(&key),
            Some(&Json::new(true))
        );
    }
    #[test]
    fn global_data_trigger_stops_immediately_when_exact_capability_is_revoked() {
        let state = State::new(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register Alice");
        let capability: Permission =
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: ALICE_ID.clone(),
            }
            .into();
        Grant::account_permission(capability.clone(), ALICE_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("seed exact global capability");
        stx._curr_block
            .set_height(NonZeroU64::new(2).expect("nonzero height"));
        Register::trigger(data_trigger(
            "revocable_global_watcher",
            ALICE_ID.clone(),
            DataEventFilter::Any,
        ))
        .execute(&ALICE_ID, &mut stx)
        .expect("register capability-backed global watcher");
        Revoke::account_permission(capability.clone(), ALICE_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("revoke exact global capability");
        stx.world.internal_event_buf.clear();
        Register::domain(Domain::new(
            DomainId::try_new("revoked_scope", "universal").expect("valid domain"),
        ))
        .execute(&ALICE_ID, &mut stx)
        .expect("emit data event after revocation");
        assert!(
            stx.execute_data_triggers_dfs(&ALICE_ID)
                .expect("revoked watcher must be skipped")
                .is_empty(),
            "revoked global watcher must not fire"
        );
        Grant::account_permission(capability, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("restore exact global capability");
        stx.world.internal_event_buf.clear();
        Register::domain(Domain::new(
            DomainId::try_new("restored_scope", "universal").expect("valid domain"),
        ))
        .execute(&ALICE_ID, &mut stx)
        .expect("emit data event after restoration");
        assert_eq!(
            stx.execute_data_triggers_dfs(&ALICE_ID)
                .expect("restored watcher may fire")
                .len(),
            1
        );
    }
    #[test]
    fn data_trigger_authority_capacity_rejects_the_sixty_fifth_registration() {
        let state = State::new(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction();
        for index in 0..isi::MAX_DATA_TRIGGERS_PER_AUTHORITY {
            let mut trigger: SpecializedTrigger<DataEventFilter> = data_trigger(
                &format!("authority_capacity_{index}"),
                ALICE_ID.clone(),
                DataEventFilter::Any,
            )
            .try_into()
            .expect("data trigger specializes");
            trigger.action.metadata = global_data_trigger_scope_metadata_for_testing(&ALICE_ID);
            assert!(
                stx.world
                    .triggers
                    .add_data_trigger(trigger)
                    .expect("seed data trigger")
            );
        }
        stx.world.add_account_permission(
            &ALICE_ID,
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: ALICE_ID.clone(),
            }
            .into(),
        );

        let error = Register::trigger(data_trigger(
            "authority_capacity_overflow",
            ALICE_ID.clone(),
            DataEventFilter::Any,
        ))
        .execute(&ALICE_ID, &mut stx)
        .expect_err("the sixty-fifth data trigger for one authority must be rejected");
        assert_smart_contract_error_contains(
            &error,
            "data trigger authority capacity exceeded: maximum 64",
        );
    }
    #[test]
    fn global_data_trigger_capacity_rejects_the_four_thousand_ninety_seventh_registration() {
        let state = State::new(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction();
        let authorities = (1_u8..=64)
            .map(|seed| {
                AccountId::new(
                    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                )
            })
            .collect::<Vec<_>>();
        for index in 0..isi::MAX_DATA_TRIGGERS_TOTAL {
            let trigger_authority =
                authorities[index / isi::MAX_DATA_TRIGGERS_PER_AUTHORITY].clone();
            let mut trigger: SpecializedTrigger<DataEventFilter> = data_trigger(
                &format!("global_capacity_{index}"),
                trigger_authority.clone(),
                DataEventFilter::Any,
            )
            .try_into()
            .expect("data trigger specializes");
            trigger.action.metadata =
                global_data_trigger_scope_metadata_for_testing(&trigger_authority);
            assert!(
                stx.world
                    .triggers
                    .add_data_trigger(trigger)
                    .expect("seed data trigger")
            );
        }
        stx.world.add_account_permission(
            &ALICE_ID,
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: ALICE_ID.clone(),
            }
            .into(),
        );

        let error = Register::trigger(data_trigger(
            "global_capacity_overflow",
            ALICE_ID.clone(),
            DataEventFilter::Any,
        ))
        .execute(&ALICE_ID, &mut stx)
        .expect_err("the four-thousand-ninety-seventh data trigger must be rejected");
        assert_smart_contract_error_contains(
            &error,
            "data trigger capacity exceeded: maximum 4096",
        );
    }
    fn new_dummy_block() -> crate::block::CommittedBlock {
        let (leader_public_key, leader_private_key) = checked_keypair().into_parts();
        let peer_id = iroha_model_base::peer::PeerId::new(leader_public_key);
        let topology = Topology::new(vec![peer_id]);
        ValidBlock::new_dummy_and_modify_header(&leader_private_key, |h| {
            h.set_height(NonZeroU64::new(1).unwrap());
        })
        .commit(&topology, crate::block::reserve_block_for_tests())
        .unpack(|_| {})
        .unwrap()
    }
    /// Fetch active trigger ids using a short-lived [`State::view`] guard so the caller
    /// can immediately take new mutable block scopes without deadlocking on the view lock.
    fn collect_active_trigger_ids(state: &State) -> Vec<TriggerId> {
        use iroha_data_model::query::dsl::CompoundPredicate;
        let view = state.view();
        let ids: Vec<_> = ValidQuery::execute(FindActiveTriggerIds, CompoundPredicate::PASS, &view)
            .expect("active trigger query should succeed")
            .collect();
        drop(view);
        ids
    }
    // No unit test for the cache helpers here; those are exercised indirectly
    // via existing trigger authorization tests.
    #[test]
    fn trigger_is_enabled_reads_metadata_flag() {
        let mut metadata = Metadata::default();
        assert!(
            trigger_is_enabled(&metadata),
            "missing flag defaults to enabled"
        );
        let key = TRIGGER_ENABLED_METADATA_KEY
            .parse::<Name>()
            .expect("valid metadata key");
        metadata.insert(key.clone(), Json::from(false));
        assert!(!trigger_is_enabled(&metadata), "false disables trigger");
        metadata.insert(key.clone(), Json::from(0_u64));
        assert!(!trigger_is_enabled(&metadata), "zero disables trigger");
        metadata.insert(key, Json::from(true));
        assert!(trigger_is_enabled(&metadata), "true enables trigger");
    }
    #[test]
    fn trigger_is_enabled_rejects_malformed_metadata_flag() {
        let mut metadata = Metadata::default();
        let key = TRIGGER_ENABLED_METADATA_KEY
            .parse::<Name>()
            .expect("valid metadata key");
        metadata.insert(key, Json::from(norito::json!("not-a-bool")));
        assert!(
            !trigger_is_enabled(&metadata),
            "malformed enabled flags must fail closed"
        );
    }
    #[test]
    fn trigger_registration_rejects_zero_and_over_ceiling_ivm_headers() {
        use iroha_data_model::{
            events::execute_trigger::ExecuteTriggerEventFilter,
            transaction::{Executable, IvmBytecode},
            trigger::action::{Action, Repeats},
        };
        let state = State::new(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(1).expect("non-zero block height"),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        stx._curr_block
            .set_height(NonZeroU64::new(2).expect("non-genesis block height"));
        stx.pipeline.ivm_max_cycles_upper_bound =
            NonZeroU64::new(1).expect("test ceiling is non-zero");
        let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
        Register::domain(Domain::new(domain_id))
            .execute(&ALICE_ID, &mut stx)
            .expect("register domain");
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register account");
        for (id, max_cycles, expected) in [
            ("zero_cycle_trigger", 0_u64, "omits a non-zero `max_cycles`"),
            (
                "over_cycle_trigger",
                2_u64,
                "`max_cycles` exceeds upper bound",
            ),
        ] {
            let trigger_id: TriggerId = id.parse().expect("trigger id");
            let metadata = ivm::ProgramMetadata {
                max_cycles,
                ..ivm::ProgramMetadata::default()
            };
            let mut bytecode = metadata.encode();
            bytecode.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
            let action = Action::new(
                Executable::Ivm(IvmBytecode::from_compiled(bytecode)),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants");
            let error = Register::trigger(Trigger::new(trigger_id.clone(), action))
                .execute(&ALICE_ID, &mut stx)
                .expect_err("invalid cycle header must fail trigger admission");
            assert!(
                matches!(
                    &error,
                    InstructionExecutionError::InvalidParameter(
                        InvalidParameterError::SmartContract(message)
                    ) if message.contains(expected)
                ),
                "unexpected trigger admission error: {error}"
            );
            assert!(
                stx.world
                    .triggers
                    .inspect_by_id(&trigger_id, |_| ())
                    .is_none(),
                "rejected trigger must not enter world state"
            );
        }
    }
    #[test]
    fn execute_trigger_requires_owner_or_permission() {
        use iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter;
        use iroha_executor_data_model::permission::trigger::CanExecuteTrigger;
        use iroha_test_samples::{ALICE_ID, BOB_ID};
        // Build state
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        // Prepare a block and state transaction
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction_for_callback_testing();
        stx._curr_block
            .set_height(NonZeroU64::new(2).expect("nonzero"));
        // Create domain and accounts
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(BOB_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        // Register a by-call trigger owned by Alice
        let trig_id: TriggerId = "bycall_authz_test".parse().unwrap();
        let trig = Trigger::new(
            trig_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trig_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        Register::trigger(trig)
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        // Bob cannot execute without permission
        let exec = ExecuteTrigger::new(trig_id.clone());
        assert!(exec.execute(&BOB_ID, &mut stx).is_err());
        // Grant Bob an explicit permission for this trigger
        let perm: iroha_data_model::permission::Permission = CanExecuteTrigger {
            trigger: trig_id.clone(),
        }
        .into();
        Grant::account_permission(perm, BOB_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        // Commit the permission grant and execute in the next block
        stx.apply_callback_for_testing()
            .expect("capture successful component callbacks");
        state_block.commit_world_overlay_for_testing().unwrap();
        let mut state_block2 = state.block(BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx2 = state_block2.transaction_for_callback_testing();
        let exec = ExecuteTrigger::new(trig_id);
        exec.execute(&BOB_ID, &mut stx2)
            .expect("bob should be permitted to execute trigger");
    }
    #[test]
    fn unregister_trigger_removes_associated_permissions_from_accounts_and_roles() {
        use iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter;
        use iroha_executor_data_model::permission::trigger::CanExecuteTrigger;
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(1).expect("nonzero"),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        stx._curr_block
            .set_height(NonZeroU64::new(2).expect("nonzero"));
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register domain");
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register alice");
        Register::account(Account::new(BOB_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register bob");
        let bob_id = (*BOB_ID).clone();
        let trig_id: TriggerId = "perm_cleanup".parse().expect("trigger id");
        let trig = Trigger::new(
            trig_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trig_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        Register::trigger(trig)
            .execute(&ALICE_ID, &mut stx)
            .expect("register trigger");
        let permission: Permission = CanExecuteTrigger {
            trigger: trig_id.clone(),
        }
        .into();
        Grant::account_permission(permission.clone(), bob_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("grant account permission");
        let role_id: RoleId = "TRIGGER_CLEANUP".parse().expect("role id");
        Register::role(Role::new(role_id.clone(), bob_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register role");
        Grant::role_permission(permission.clone(), role_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("grant role permission");
        assert!(
            stx.world
                .account_permissions
                .get(&bob_id)
                .is_some_and(|perms| perms.contains(&permission)),
            "bob should have direct permission before unregister"
        );
        let role = stx.world.roles.get(&role_id).expect("role should exist");
        assert!(
            role.permissions().any(|perm| perm == &permission),
            "role should include permission before unregister"
        );
        Unregister::trigger(trig_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("unregister trigger");
        assert!(
            !stx.world
                .account_permissions
                .get(&bob_id)
                .is_some_and(|perms| perms.contains(&permission)),
            "bob direct permission should be removed"
        );
        let role = stx.world.roles.get(&role_id).expect("role should exist");
        assert!(
            !role.permissions().any(|perm| perm == &permission),
            "role permission should be removed"
        );
        assert!(
            !role.permission_epochs().contains_key(&permission),
            "permission epoch should be pruned"
        );
    }
    #[test]
    fn by_call_trigger_is_pruned_after_manual_execution() {
        use iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter;
        use iroha_executor_data_model::permission::trigger::CanExecuteTrigger;
        use iroha_logger::Level;
        let state = authenticated_trigger_state();
        let mut state_block = state.block(authenticated_trigger_header(&state));
        let mut stx = state_block.transaction_for_callback_testing();
        // Trigger ownership uses universal accounts; this test needs no alias lease.
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(BOB_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        // Register a by-call trigger that may run exactly once
        let trig_id: TriggerId = "manual_once".parse().unwrap();
        let trig = Trigger::new(
            trig_id.clone(),
            Action::new(
                vec![InstructionBox::from(Log::new(Level::INFO, "ping".into()))],
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trig_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        Register::trigger(trig)
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let stale_permission: Permission = CanExecuteTrigger {
            trigger: trig_id.clone(),
        }
        .into();
        Grant::account_permission(stale_permission.clone(), BOB_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("grant execute permission for the first trigger incarnation");
        assert!(
            stx.can_execute_trigger_for(&BOB_ID, &trig_id),
            "fixture must prime the permission cache before automatic depletion"
        );
        // First execution should succeed.
        ExecuteTrigger::new(trig_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        assert!(
            !stx.world
                .account_permissions
                .get(&*BOB_ID)
                .is_some_and(|permissions| permissions.contains(&stale_permission)),
            "automatic depletion must revoke trigger-scoped permissions"
        );
        assert!(
            !stx.can_execute_trigger_for(&BOB_ID, &trig_id),
            "automatic depletion must invalidate cached trigger capabilities"
        );
        // Subsequent execution should report the trigger as missing/depleted.
        let err = ExecuteTrigger::new(trig_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("depleted by-call trigger must not run twice");
        assert!(matches!(err, Error::Find(FindError::Trigger(id)) if id == trig_id));

        // Reusing the id must not transfer a capability from the deleted trigger
        // incarnation to its replacement.
        let replacement = Trigger::new(
            trig_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trig_id.clone()),
            )
            .expect("replacement trigger action is valid"),
        );
        Register::trigger(replacement)
            .execute(&ALICE_ID, &mut stx)
            .expect("reuse depleted trigger id");
        ExecuteTrigger::new(trig_id)
            .execute(&BOB_ID, &mut stx)
            .expect_err("stale permission must not authorize the replacement trigger");
    }
    #[test]
    fn by_call_self_replacement_keeps_the_fresh_repeat_budget() {
        use crate::smartcontracts::triggers::specialized::LoadedActionTrait as _;
        use iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter;
        let state = authenticated_trigger_state();
        let mut state_block = state.block(authenticated_trigger_header(&state));
        let mut stx = state_block.transaction_for_callback_testing();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();

        let trigger_id: TriggerId = "by_call_self_replacement".parse().unwrap();
        let filter = ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone());
        let replacement = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(2),
                ALICE_ID.clone(),
                filter.clone(),
            )
            .expect("replacement action is valid"),
        );
        let original = Trigger::new(
            trigger_id.clone(),
            Action::new(
                vec![
                    InstructionBox::from(Unregister::trigger(trigger_id.clone())),
                    InstructionBox::from(Register::trigger(replacement)),
                ],
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                filter,
            )
            .expect("original action is valid"),
        );
        Register::trigger(original)
            .execute(&ALICE_ID, &mut stx)
            .unwrap();

        ExecuteTrigger::new(trigger_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("original trigger executes and installs its replacement");

        let replacement = stx
            .world
            .triggers
            .by_call_triggers()
            .get(&trigger_id)
            .expect("replacement remains registered");
        assert_eq!(replacement.repeats(), &Repeats::Exactly(2));

        ExecuteTrigger::new(trigger_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("replacement remains callable in its registration transaction");
        let replacement = stx
            .world
            .triggers
            .by_call_triggers()
            .get(&trigger_id)
            .expect("replacement retains one invocation");
        assert_eq!(replacement.repeats(), &Repeats::Exactly(1));

        let mismatched_event = ExecuteTriggerEvent {
            trigger_id: "different_trigger_id".parse().unwrap(),
            authority: ALICE_ID.clone(),
            args: Json::default(),
        };
        let rejection = stx
            .execute_called_trigger(&trigger_id, &mismatched_event)
            .expect_err("a stale ID/event pair must fail before action resolution");
        assert!(matches!(
            rejection,
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(_))
        ));
    }
    #[test]
    fn register_trigger_without_permission_is_rejected() {
        // Build state
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction();
        stx._curr_block
            .set_height(NonZeroU64::new(2).expect("nonzero"));
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(BOB_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let trig_id: TriggerId = "reg_trigger_denied".parse().unwrap();
        let trig = Trigger::new(
            trig_id,
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new(),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        let err = Register::trigger(trig)
            .execute(&BOB_ID, &mut stx)
            .expect_err("register should fail without permission");
        match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                msg,
            )) => {
                assert!(msg.contains("CanRegisterTrigger"));
                let expected = ALICE_ID.clone().to_string();
                assert!(msg.contains(&expected));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn active_alias_domain_owner_cannot_register_trigger_for_canonical_account() {
        use iroha_data_model::{
            account::{
                AccountAddress,
                rekey::{AccountAlias, AccountAliasDomain, AccountRekeyRecord},
            },
            events::execute_trigger::ExecuteTriggerEventFilter,
            sns::{NameControllerV1, NameRecordV1},
        };
        use iroha_model_base::topology::DataSpaceId;

        let domain_id = DomainId::try_new("aliasbank", "universal").expect("domain id");
        let world = World::with(
            [Domain::new(domain_id).build(&BOB_ID)],
            [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(BOB_ID.clone()).build(&BOB_ID),
            ],
            [],
        );
        let state = State::new(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(2).expect("nonzero"),
            None,
            None,
            50,
            0,
        ));
        let mut stx = state_block.transaction();
        let alias = AccountAlias::new(
            "customer".parse().expect("alias label"),
            Some(AccountAliasDomain::new(
                "aliasbank".parse().expect("alias domain"),
            )),
            DataSpaceId::UNIVERSAL,
        );
        let selector = crate::sns::selector_for_account_alias(&alias, &stx.nexus.dataspace_catalog)
            .expect("account alias selector");
        let address = AccountAddress::from_account_id(&ALICE_ID).expect("account address");
        let lease = NameRecordV1::new(
            selector.clone(),
            ALICE_ID.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        stx.world.smart_contract_state.insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&lease),
        );
        stx.world
            .insert_account_alias_binding(alias.clone(), ALICE_ID.clone());
        stx.world
            .replace_account_rekey_record(AccountRekeyRecord::new(alias.clone(), ALICE_ID.clone()));
        assert_eq!(
            crate::sns::resolve_active_account_alias(
                &stx.world,
                &stx.nexus.dataspace_catalog,
                &alias,
                stx.block_unix_timestamp_ms(),
            )
            .expect("active alias lookup"),
            Some(ALICE_ID.clone()),
            "fixture must expose an active alias in the attacker's domain",
        );

        let trigger_id: TriggerId = "alias_domain_impersonation".parse().expect("trigger id");
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
            )
            .expect("valid trigger action"),
        );
        let error = Register::trigger(trigger)
            .execute(&BOB_ID, &mut stx)
            .expect_err("alias-domain ownership must not authorize the canonical account");
        assert!(
            matches!(
                error,
                InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(ref message)
                ) if message.contains("CanRegisterTrigger")
            ),
            "unexpected registration error: {error:?}",
        );
        assert!(
            stx.world
                .triggers
                .inspect_by_id(&trigger_id, |_| ())
                .is_none(),
            "rejected trigger must not enter world state",
        );
    }
    #[test]
    fn register_trigger_with_permission_succeeds() {
        use iroha_data_model::permission::Permission;
        use iroha_primitives::json::Json;
        // Build state
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(BOB_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let trig_id: TriggerId = "reg_trigger_allowed".parse().unwrap();
        let trig = Trigger::new(
            trig_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new(),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        let payload = norito::json::object([("authority", ALICE_ID.to_string())])
            .expect("serialize permission payload");
        let perm = Permission::new("CanRegisterTrigger".into(), Json::new(payload));
        Grant::account_permission(perm, BOB_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::trigger(trig)
            .execute(&BOB_ID, &mut stx)
            .expect("register should succeed with permission");
    }
    #[test]
    fn active_trigger_ids_excludes_depleted_after_burn() {
        // Build state
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        // Bootstrap world with a domain and Alice account
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        // Register a by-call trigger with Exactly(1) repeat
        let trig_id: TriggerId = "utrig_burn_rm".parse().unwrap();
        let trig = Trigger::new(
            trig_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trig_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        Register::trigger(trig)
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        // Active IDs should include the trigger id
        {
            let mut ids = collect_active_trigger_ids(&state);
            ids.sort();
            assert!(ids.iter().any(|id| id == &trig_id));
        }
        // Burn to zero in the next block
        let mut state_block2 = state.block(BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx2 = state_block2.transaction();
        Burn::trigger_repetitions(1, trig_id.clone())
            .execute(&ALICE_ID, &mut stx2)
            .unwrap();
        stx2.apply();
        state_block2.commit_world_overlay_for_testing().unwrap();
        // Active IDs should no longer include the trigger id
        {
            let ids2 = collect_active_trigger_ids(&state);
            assert!(ids2.iter().all(|id| id != &trig_id));
        }
    }
    #[test]
    fn active_trigger_ids_excludes_disabled_trigger() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let trigger_id: TriggerId = "disabled_not_active".parse().unwrap();
        let mut metadata = Metadata::default();
        metadata.insert(
            TRIGGER_ENABLED_METADATA_KEY
                .parse::<Name>()
                .expect("valid metadata key"),
            Json::from(false),
        );
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants")
            .with_metadata(metadata),
        );
        Register::trigger(trigger)
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let ids = collect_active_trigger_ids(&state);
        assert!(
            ids.iter().all(|id| id != &trigger_id),
            "disabled trigger must not be reported active"
        );
    }
    #[test]
    fn active_trigger_ids_excludes_malformed_enabled_metadata() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let trigger_id: TriggerId = "malformed_enabled_not_active".parse().unwrap();
        let mut metadata = Metadata::default();
        metadata.insert(
            TRIGGER_ENABLED_METADATA_KEY
                .parse::<Name>()
                .expect("valid metadata key"),
            Json::from(norito::json!("definitely-not-a-bool")),
        );
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants")
            .with_metadata(metadata),
        );
        Register::trigger(trigger)
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let ids = collect_active_trigger_ids(&state);
        assert!(
            ids.iter().all(|id| id != &trigger_id),
            "malformed enabled metadata must fail closed and not be active"
        );
    }
    #[test]
    fn active_trigger_ids_recover_after_malformed_enabled_is_set_true() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let trigger_id: TriggerId = "malformed_enabled_recovers".parse().unwrap();
        let enabled_key = TRIGGER_ENABLED_METADATA_KEY
            .parse::<Name>()
            .expect("valid metadata key");
        let mut metadata = Metadata::default();
        metadata.insert(enabled_key.clone(), Json::from(norito::json!([true])));
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants")
            .with_metadata(metadata),
        );
        Register::trigger(trigger)
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let ids = collect_active_trigger_ids(&state);
        assert!(
            ids.iter().all(|id| id != &trigger_id),
            "malformed enabled metadata must initially fail closed"
        );
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        SetKeyValue::trigger(trigger_id.clone(), enabled_key, Json::from(true))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let ids = collect_active_trigger_ids(&state);
        assert!(
            ids.iter().any(|id| id == &trigger_id),
            "setting enabled=true must restore the trigger to active ids"
        );
    }
    #[test]
    fn active_trigger_ids_recover_after_disabled_enabled_flag_is_removed() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let trigger_id: TriggerId = "disabled_enabled_flag_removed".parse().unwrap();
        let enabled_key = TRIGGER_ENABLED_METADATA_KEY
            .parse::<Name>()
            .expect("valid metadata key");
        let mut metadata = Metadata::default();
        metadata.insert(enabled_key.clone(), Json::from(false));
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants")
            .with_metadata(metadata),
        );
        Register::trigger(trigger)
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let ids = collect_active_trigger_ids(&state);
        assert!(
            ids.iter().all(|id| id != &trigger_id),
            "disabled trigger must initially be inactive"
        );
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        RemoveKeyValue::trigger(trigger_id.clone(), enabled_key)
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let ids = collect_active_trigger_ids(&state);
        assert!(
            ids.iter().any(|id| id == &trigger_id),
            "removing __enabled must restore the default enabled state"
        );
    }
    #[test]
    fn active_trigger_ids_exclude_trigger_after_enabled_is_set_false() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let trigger_id: TriggerId = "enabled_flag_set_false".parse().unwrap();
        let enabled_key = TRIGGER_ENABLED_METADATA_KEY
            .parse::<Name>()
            .expect("valid metadata key");
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        Register::trigger(trigger)
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let ids = collect_active_trigger_ids(&state);
        assert!(
            ids.iter().any(|id| id == &trigger_id),
            "fresh trigger must initially be active"
        );
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        SetKeyValue::trigger(trigger_id.clone(), enabled_key, Json::from(false))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let ids = collect_active_trigger_ids(&state);
        assert!(
            ids.iter().all(|id| id != &trigger_id),
            "setting __enabled=false must remove the trigger from active ids"
        );
    }
    #[test]
    fn active_trigger_ids_follow_numeric_enabled_flag_transitions() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let trigger_id: TriggerId = "numeric_enabled_flag".parse().unwrap();
        let enabled_key = TRIGGER_ENABLED_METADATA_KEY
            .parse::<Name>()
            .expect("valid metadata key");
        let mut metadata = Metadata::default();
        metadata.insert(enabled_key.clone(), Json::from(0_u64));
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants")
            .with_metadata(metadata),
        );
        Register::trigger(trigger)
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let ids = collect_active_trigger_ids(&state);
        assert!(
            ids.iter().all(|id| id != &trigger_id),
            "__enabled=0 must disable active queries"
        );
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        SetKeyValue::trigger(trigger_id.clone(), enabled_key.clone(), Json::from(1_u64))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let ids = collect_active_trigger_ids(&state);
        assert!(
            ids.iter().any(|id| id == &trigger_id),
            "__enabled=1 must restore active queries"
        );
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(3).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        SetKeyValue::trigger(trigger_id.clone(), enabled_key, Json::from(0_u64))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let ids = collect_active_trigger_ids(&state);
        assert!(
            ids.iter().all(|id| id != &trigger_id),
            "returning __enabled to 0 must remove the trigger from active ids"
        );
    }
    #[test]
    fn register_trigger_rejects_nondeterministic_pipeline_filter() {
        use iroha_data_model::events::pipeline::{
            BlockEventFilter, BlockStatus, PipelineEventFilterBox, TransactionEventFilter,
            TransactionStatus, WitnessEventFilter,
        };
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        for (name, filter) in [
            (
                "pipeline_block_any",
                PipelineEventFilterBox::from(BlockEventFilter::new()),
            ),
            (
                "pipeline_block_created",
                PipelineEventFilterBox::from(
                    BlockEventFilter::new().for_status(BlockStatus::Created),
                ),
            ),
            (
                "pipeline_block_committed",
                PipelineEventFilterBox::from(
                    BlockEventFilter::new().for_status(BlockStatus::Committed),
                ),
            ),
            (
                "pipeline_block_applied",
                PipelineEventFilterBox::from(
                    BlockEventFilter::new().for_status(BlockStatus::Applied),
                ),
            ),
            (
                "pipeline_block_rejected",
                PipelineEventFilterBox::from(BlockEventFilter::new().for_status(
                    BlockStatus::Rejected(
                        iroha_data_model::block::error::BlockRejectionReason::EmptyBlock,
                    ),
                )),
            ),
            (
                "pipeline_tx_any",
                PipelineEventFilterBox::from(TransactionEventFilter::new()),
            ),
            (
                "pipeline_tx_queued",
                PipelineEventFilterBox::from(
                    TransactionEventFilter::new().for_status(TransactionStatus::Queued),
                ),
            ),
            (
                "pipeline_tx_expired",
                PipelineEventFilterBox::from(
                    TransactionEventFilter::new().for_status(TransactionStatus::Expired),
                ),
            ),
            (
                "pipeline_witness",
                PipelineEventFilterBox::from(WitnessEventFilter::default()),
            ),
        ] {
            let trigger_id: TriggerId = name.parse().unwrap();
            let trigger = Trigger::new(
                trigger_id,
                Action::new(
                    Vec::<InstructionBox>::new(),
                    Repeats::Exactly(1),
                    ALICE_ID.clone(),
                    filter,
                )
                .expect("trigger action fixture satisfies validation invariants"),
            );
            Register::trigger(trigger)
                .execute(&ALICE_ID, &mut stx)
                .expect_err("non-deterministic pipeline filter must be rejected");
        }
    }
    #[test]
    fn find_triggers_returns_registered_triggers_for_pass_predicate() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let mut state_block = state.block(BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut stx = state_block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let rose_id: TriggerId = "utrig_rose".parse().unwrap();
        let tulip_id: TriggerId = "utrig_tulip".parse().unwrap();
        for trigger_id in [&rose_id, &tulip_id] {
            let trigger = Trigger::new(
                trigger_id.clone(),
                Action::new(
                    Vec::<InstructionBox>::new(),
                    Repeats::Indefinitely,
                    ALICE_ID.clone(),
                    ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
                )
                .expect("trigger action fixture satisfies validation invariants"),
            );
            Register::trigger(trigger)
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
        }
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let view = state.view();
        let mut ids: Vec<_> = ValidQuery::execute(
            FindTriggers,
            iroha_data_model::query::dsl::CompoundPredicate::PASS,
            &view,
        )
        .expect("trigger query should succeed")
        .map(|trigger| trigger.id().clone())
        .collect();
        ids.sort();
        assert_eq!(ids, vec![rose_id.clone(), tulip_id.clone()]);
        let by_id: Vec<_> = ValidQuery::execute(
            FindTriggers,
            CompoundPredicate::<Trigger>::build(|predicate| {
                predicate.equals("id", rose_id.clone())
            }),
            &view,
        )
        .expect("trigger query by id should succeed")
        .map(|trigger| trigger.id().clone())
        .collect();
        assert_eq!(by_id, vec![rose_id.clone()]);
        let active_by_id: Vec<_> = ValidQuery::execute(
            FindActiveTriggerIds,
            CompoundPredicate::<TriggerId>::build(|predicate| {
                predicate.equals("id", rose_id.clone())
            }),
            &view,
        )
        .expect("active trigger id query by id should succeed")
        .collect();
        assert_eq!(active_by_id, vec![rose_id.clone()]);
        let missing_id: TriggerId = "utrig_missing".parse().unwrap();
        let missing_count = ValidQuery::execute(
            FindTriggers,
            CompoundPredicate::<Trigger>::build(|predicate| predicate.equals("id", missing_id)),
            &view,
        )
        .expect("missing trigger query by id should succeed")
        .count();
        assert_eq!(missing_count, 0);
    }
    #[test]
    fn reserved_trigger_metadata_key_is_rejected() {
        for raw in [
            "__registered_block_height",
            DATA_TRIGGER_SCOPE_AUTHORIZATION_METADATA_KEY,
            DATA_TRIGGER_SCOPE_AUTHORIZATION_GRANTEE_METADATA_KEY,
        ] {
            let key: Name = raw.parse().expect("valid name");
            let err =
                isi::ensure_metadata_key_is_not_reserved(&key).expect_err("key must be rejected");
            assert!(
                matches!(
                    err,
                    Error::InvalidParameter(InvalidParameterError::SmartContract(_))
                ),
                "unexpected error variant for {raw}: {err:?}"
            );
        }
    }
    #[test]
    fn custom_trigger_metadata_key_is_allowed() {
        let key: Name = "custom_meta".parse().expect("valid name");
        isi::ensure_metadata_key_is_not_reserved(&key).expect("custom keys should be allowed");
    }
    #[test]
    fn time_trigger_with_zero_period_is_rejected() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let trig_id: TriggerId = "time_zero_period".parse().unwrap();
        let schedule = ExecutionTime::Schedule(
            Schedule::starting_at(Duration::from_secs(0)).with_period(Duration::from_secs(0)),
        );
        let trigger = Trigger::new(
            trig_id,
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                TimeEventFilter(schedule),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        let err = Register::trigger(trigger)
            .execute(&ALICE_ID, &mut stx)
            .expect_err("zero-period time trigger must be rejected");
        match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                msg,
            )) => assert!(
                msg.contains("period must be greater than zero"),
                "unexpected message: {msg}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn time_trigger_period_shorter_than_block_cadence_is_rejected() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let trigger_id: TriggerId = "time_sub_cadence".parse().unwrap();
        let schedule = ExecutionTime::Schedule(
            Schedule::starting_at(Duration::ZERO).with_period(Duration::from_millis(1)),
        );
        let trigger = Trigger::new(
            trigger_id,
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                ALICE_ID.clone(),
                TimeEventFilter(schedule),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        let err = Register::trigger(trigger)
            .execute(&ALICE_ID, &mut stx)
            .expect_err("sub-cadence time trigger must be rejected");
        assert!(
            matches!(
                err,
                InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(ref message)
                ) if message.contains("at least the signed block cadence")
            ),
            "unexpected registration error: {err:?}"
        );
    }
    #[test]
    fn trigger_retry_policy_rejects_non_scheduled_time_trigger_on_registration() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let world = World::with(
            [Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&ALICE_ID)],
            [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
            [],
        );
        let state = State::new(world, kura, query_handle);
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction();
        let trig_id: TriggerId = "time_retry_precommit".parse().unwrap();
        let trigger = Trigger::new(
            trig_id,
            Action {
                executable: Executable::Instructions(Vec::<InstructionBox>::new().into()),
                repeats: Repeats::Exactly(1),
                authority: ALICE_ID.clone(),
                filter: EventFilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit)),
                retry_policy: Some(TimeTriggerRetryPolicy {
                    max_retries: std::num::NonZeroU32::new(1).expect("nonzero"),
                    retry_after_ms: std::num::NonZeroU64::new(5).expect("nonzero"),
                }),
                metadata: Metadata::default(),
            },
        );
        let err = Register::trigger(trigger)
            .execute(&ALICE_ID, &mut stx)
            .expect_err("precommit retry policy must be rejected");
        match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                msg,
            )) => assert!(
                msg.contains("retry policy is only supported for scheduled time triggers"),
                "unexpected message: {msg}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn trigger_registration_enforces_metadata_limit() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query_handle);
        let block = new_dummy_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let id = CustomParameterId::from_str("max_metadata_value_bytes").unwrap();
        let param = Parameter::Custom(CustomParameter::new(id, Json::new(4u32)));
        stx.world.parameters.get_mut().set_parameter(param);
        let mut metadata = Metadata::default();
        metadata.insert("oversized".parse().unwrap(), Json::new("0123456789"));
        let trigger = Trigger::new(
            "meta_limit".parse().unwrap(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new(),
            )
            .expect("trigger action fixture satisfies validation invariants")
            .with_metadata(metadata),
        );
        let err = Register::trigger(trigger)
            .execute(&ALICE_ID, &mut stx)
            .expect_err("metadata over limit must be rejected");
        match err {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                msg,
            )) => assert!(
                msg.contains("max_metadata_value_bytes"),
                "unexpected message: {msg}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
