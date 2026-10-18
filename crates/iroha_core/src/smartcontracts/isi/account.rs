//! This module contains implementations of smart-contract traits and instructions for [`Account`] structure
//! and implementations for account queries.
use super::prelude::*;
use iroha_data_model::{prelude::*, query::error::FindError};
use iroha_model_base::name::Name;
use iroha_telemetry::metrics;
/// All instructions related to accounts:
/// - minting/burning public key into account signatories
/// - minting/burning signature condition check
/// - update metadata
/// - grant permissions and roles
/// - Revoke permissions or roles
pub mod isi {
    use super::*;
    use crate::{role::RoleIdWithOwner, state::StateTransaction};
    use iroha_data_model::isi::{
        InstructionType,
        error::{InvalidParameterError, MintabilityError, RepetitionError},
    };
    use iroha_executor_data_model::isi::multisig::MultisigSpec;
    use std::num::NonZeroU64;
    fn is_idempotent_alias_permission(permission: &Permission) -> bool {
        iroha_executor_data_model::permission::account::CanManageAccountAlias::try_from(permission)
            .is_ok()
            || iroha_executor_data_model::permission::account::CanDelegateAccountAliasResolution::try_from(
                permission,
            )
            .is_ok()
            || iroha_executor_data_model::permission::account::CanResolveAccountAlias::try_from(
                permission,
            )
            .is_ok()
    }
    fn invalid_account_recovery(message: impl Into<std::string::String>) -> Error {
        Error::InvalidParameter(InvalidParameterError::SmartContract(message.into()))
    }
    fn ensure_recovery_request_generation(
        request: &AccountRecoveryRequest,
        generation: NonZeroU64,
    ) -> Result<(), Error> {
        if request.request_generation != generation {
            return Err(invalid_account_recovery(format!(
                "account recovery request generation mismatch: expected {}, received {}",
                request.request_generation, generation,
            )));
        }
        Ok(())
    }
    fn multisig_spec_key() -> Name {
        "multisig/spec"
            .parse()
            .expect("multisig spec key must be a valid name")
    }
    fn validate_multisig_spec_ttl_update(
        state_transaction: &StateTransaction<'_, '_>,
        authority: &AccountId,
        account_id: &AccountId,
        key: &Name,
        value: &Json,
    ) -> Result<bool, Error> {
        if key != &multisig_spec_key() {
            return Ok(false);
        }
        if authority != account_id {
            return Err(Error::InvariantViolation(
                format!(
                    "account metadata key `{key}` may only be updated by the native multisig account itself"
                )
                .into(),
            ));
        }
        let account = state_transaction
            .world
            .account(account_id)
            .map_err(Error::from)?;
        let current_value = account.metadata().get(key).ok_or_else(|| {
            Error::InvariantViolation(
                format!("account metadata key `{key}` is missing native multisig state").into(),
            )
        })?;
        let current_spec = MultisigSpec::try_from(current_value).map_err(|err| {
            Error::InvariantViolation(
                format!(
                    "account metadata key `{key}` contains invalid native multisig state: {err}"
                )
                .into(),
            )
        })?;
        let next_spec = MultisigSpec::try_from(value).map_err(|err| {
            Error::InvariantViolation(
                format!("account metadata key `{key}` update contains invalid native multisig state: {err}")
                    .into(),
            )
        })?;
        if current_spec.signatories != next_spec.signatories
            || current_spec.quorum != next_spec.quorum
        {
            return Err(Error::InvariantViolation(
                format!(
                    "account metadata key `{key}` update may only change native multisig transaction_ttl_ms"
                )
                .into(),
            ));
        }
        Ok(true)
    }
    fn stable_recovery_alias(
        state_transaction: &StateTransaction<'_, '_>,
        account_id: &AccountId,
    ) -> Result<AccountAlias, Error> {
        let alias = state_transaction
            .world
            .account(account_id)
            .map_err(Error::from)?
            .label()
            .cloned()
            .ok_or_else(|| {
                invalid_account_recovery(format!(
                    "account `{account_id}` must have a stable alias to use social recovery"
                ))
            })?;
        let resolved = crate::sns::resolve_active_account_alias(
            &state_transaction.world,
            &state_transaction.nexus.dataspace_catalog,
            &alias,
            state_transaction.block_unix_timestamp_ms(),
        )
        .map_err(|error| invalid_account_recovery(error.to_string()))?;
        if resolved.as_ref() != Some(account_id) {
            return Err(invalid_account_recovery(format!(
                "account `{account_id}` does not have a strictly active alias binding"
            )));
        }
        Ok(alias)
    }
    fn validate_recovery_policy(policy: &AccountRecoveryPolicy) -> Result<(), Error> {
        AccountRecoveryPolicy::new(policy.guardians.clone(), policy.quorum, policy.timelock_ms)
            .map(|_| ())
            .map_err(|err| invalid_account_recovery(err.to_string()))
    }
    fn active_account_for_alias(
        state_transaction: &StateTransaction<'_, '_>,
        alias: &AccountAlias,
    ) -> Result<AccountId, Error> {
        crate::sns::resolve_active_account_alias(
            &state_transaction.world,
            &state_transaction.nexus.dataspace_catalog,
            alias,
            state_transaction.block_unix_timestamp_ms(),
        )
        .map_err(|error| invalid_account_recovery(error.to_string()))?
        .ok_or_else(|| {
            invalid_account_recovery(format!(
                "account alias `{alias:?}` does not resolve to a strictly active account"
            ))
        })
    }
    fn current_account_is_recovery_guardian(
        policy: &AccountRecoveryPolicy,
        authority: &AccountId,
    ) -> bool {
        policy.contains_guardian(authority)
    }
    pub(super) fn ensure_recovery_request_targets_current_lineage(
        state_transaction: &StateTransaction<'_, '_>,
        request: &AccountRecoveryRequest,
        current_account: &AccountId,
    ) -> Result<(), Error> {
        if crate::sns::resolve_active_account_id_rekey_lineage_for_alias(
            &state_transaction.world,
            &state_transaction.nexus.dataspace_catalog,
            &request.alias,
            &request.active_account_id_at_proposal,
            state_transaction.block_unix_timestamp_ms(),
        )
        .map_err(|error| invalid_account_recovery(error.to_string()))?
        .as_ref()
            != Some(current_account)
        {
            return Err(invalid_account_recovery(format!(
                "account recovery request for `{:#?}` no longer matches the active alias lineage",
                request.alias
            )));
        }
        Ok(())
    }
    fn proposed_account_id(new_controller: &AccountController) -> AccountId {
        match new_controller {
            AccountController::Single(signatory) => AccountId::new(signatory.clone()),
            AccountController::Multisig(policy) => AccountId::new_multisig(policy.clone()),
        }
    }
    impl Execute for Transfer<Account, AssetDefinitionId, Account> {
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
            if !authority_is_source_owner {
                return Err(Error::InvariantViolation(
                    "Can't transfer asset definition of another account"
                        .to_owned()
                        .into(),
                ));
            }
            {
                let mut asset_definition = state_transaction
                    .world
                    .asset_definition_metadata_mut(&object)?;
                if asset_definition.owned_by() != &source {
                    return Err(Error::Find(FindError::Account(source)));
                }
                asset_definition.set_owned_by(destination.clone());
            }
            state_transaction
                .world
                .replace_asset_definition_owner_index(&object, &source, &destination);
            state_transaction.world.emit_asset_definition_event(
                AssetDefinitionEvent::OwnerChanged(AssetDefinitionOwnerChanged {
                    asset_definition: object,
                    new_owner: destination,
                }),
            );
            Ok(())
        }
    }
    impl Execute for SetKeyValue<Account> {
        #[metrics(+"set_account_key_value")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            // Destructure to move key/value once; avoid duplicate clones.
            let SetKeyValue {
                object: account_id,
                key,
                value,
            } = self;
            if key.as_ref() == iroha_data_model::validation_fee::RETAIL_FEE_ENROLLMENT_METADATA_KEY
            {
                if value.try_into_any_norito::<bool>().ok() != Some(true) {
                    return Err(Error::InvariantViolation("retail enrollment accepts only true; account classification cannot be removed".into()));
                }
                return crate::retail_fee::enroll(state_transaction, authority, &account_id)
                    .map_err(Into::into);
            }
            if key.as_ref() == iroha_data_model::smart_contract::CONTRACT_DEPLOY_NONCE_METADATA_KEY
            {
                return Err(Error::InvariantViolation(
                    format!(
                        "account metadata key `{key}` is reserved for native contract deployment state"
                    )
                    .into(),
                ));
            }
            if key.as_ref() == iroha_data_model::asset::ASSET_TRANSFER_CONTROL_METADATA_KEY {
                return Err(Error::InvariantViolation(
                    format!(
                        "account metadata key `{key}` is reserved for native asset transfer controls"
                    )
                    .into(),
                ));
            }
            if crate::smartcontracts::isi::multisig::is_reserved_multisig_metadata_key(&key) {
                let ttl_only_update = validate_multisig_spec_ttl_update(
                    state_transaction,
                    authority,
                    &account_id,
                    &key,
                    &value,
                )?;
                if !ttl_only_update {
                    return Err(Error::InvariantViolation(
                        format!(
                            "account metadata key `{key}` is reserved for native multisig state"
                        )
                        .into(),
                    ));
                }
            }
            // Enforce metadata value size limit (custom parameter or default)
            crate::smartcontracts::limits::enforce_json_size(
                state_transaction,
                &value,
                "max_metadata_value_bytes",
                crate::smartcontracts::limits::DEFAULT_JSON_LIMIT,
            )?;
            // Insert into account metadata; move key/value into the map directly.
            state_transaction
                .world
                .account_mut(&account_id)
                .map_err(Error::from)
                .map(|account| account.insert(key.clone(), value.clone()))?;
            // Emit event with a single extra clone from inserted value.
            state_transaction
                .world
                .emit_events(Some(AccountEvent::MetadataInserted(MetadataChanged {
                    target: account_id,
                    key,
                    value,
                })));
            Ok(())
        }
    }
    impl Execute for RemoveKeyValue<Account> {
        #[metrics(+"remove_account_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.object().clone();
            if self.key().as_ref()
                == iroha_data_model::validation_fee::RETAIL_FEE_ENROLLMENT_METADATA_KEY
            {
                return Err(Error::InvariantViolation(
                    "retail enrollment is consensus-owned and cannot be removed".into(),
                ));
            }
            if self.key().as_ref()
                == iroha_data_model::smart_contract::CONTRACT_DEPLOY_NONCE_METADATA_KEY
            {
                return Err(Error::InvariantViolation(
                    format!(
                        "account metadata key `{}` is reserved for native contract deployment state",
                        self.key()
                    )
                    .into(),
                ));
            }
            if self.key().as_ref() == iroha_data_model::asset::ASSET_TRANSFER_CONTROL_METADATA_KEY {
                return Err(Error::InvariantViolation(
                    format!(
                        "account metadata key `{}` is reserved for native asset transfer controls",
                        self.key()
                    )
                    .into(),
                ));
            }
            if crate::smartcontracts::isi::multisig::is_reserved_multisig_metadata_key(self.key()) {
                return Err(Error::InvariantViolation(
                    format!(
                        "account metadata key `{}` is reserved for native multisig state",
                        self.key()
                    )
                    .into(),
                ));
            }
            let value = state_transaction
                .world
                .account_mut(&account_id)
                .and_then(|account| {
                    account
                        .remove(self.key())
                        .ok_or_else(|| FindError::MetadataKey(self.key().clone()))
                })?;
            state_transaction
                .world
                .emit_events(Some(AccountEvent::MetadataRemoved(MetadataChanged {
                    target: account_id,
                    key: self.key().clone(),
                    value,
                })));
            Ok(())
        }
    }
    impl Execute for ReplaceAccountController {
        #[metrics(+"replace_account_controller")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let ReplaceAccountController {
                account,
                new_controller,
            } = self;
            let previous_controller = state_transaction
                .world
                .account(&account)
                .map_err(Error::from)?
                .id()
                .controller()
                .clone();
            let new_account = crate::smartcontracts::isi::multisig::replace_account_controller(
                authority,
                state_transaction,
                &account,
                new_controller.clone(),
            )?;
            state_transaction
                .world
                .emit_events(Some(AccountEvent::ControllerReplaced(
                    AccountControllerReplaced {
                        account: new_account,
                        previous_account: account,
                        previous_controller,
                        new_controller,
                    },
                )));
            Ok(())
        }
    }
    impl Execute for SetAccountRecoveryPolicy {
        #[metrics(+"set_account_recovery_policy")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let SetAccountRecoveryPolicy { account, policy } = self;
            validate_recovery_policy(&policy)?;
            let alias = stable_recovery_alias(state_transaction, &account)?;
            if state_transaction
                .world
                .account_recovery_requests
                .get(&alias)
                .is_some_and(AccountRecoveryRequest::is_pending)
            {
                return Err(invalid_account_recovery(format!(
                    "account recovery policy for `{alias:?}` cannot be replaced while a request is pending"
                )));
            }
            state_transaction
                .world
                .account_recovery_policies
                .insert(alias.clone(), policy.clone());
            state_transaction
                .world
                .emit_events(Some(AccountEvent::Recovery(
                    AccountRecoveryEvent::PolicySet(AccountRecoveryPolicySet {
                        account,
                        alias,
                        policy,
                    }),
                )));
            Ok(())
        }
    }
    impl Execute for ClearAccountRecoveryPolicy {
        #[metrics(+"clear_account_recovery_policy")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let ClearAccountRecoveryPolicy { account } = self;
            let alias = stable_recovery_alias(state_transaction, &account)?;
            if state_transaction
                .world
                .account_recovery_requests
                .get(&alias)
                .is_some_and(AccountRecoveryRequest::is_pending)
            {
                return Err(invalid_account_recovery(format!(
                    "account recovery policy for `{alias:?}` cannot be cleared while a request is pending"
                )));
            }
            if state_transaction
                .world
                .account_recovery_policies
                .remove(alias.clone())
                .is_none()
            {
                return Err(invalid_account_recovery(format!(
                    "account recovery policy for `{alias:?}` does not exist"
                )));
            }
            state_transaction
                .world
                .emit_events(Some(AccountEvent::Recovery(
                    AccountRecoveryEvent::PolicyCleared(AccountRecoveryPolicyCleared {
                        account,
                        alias,
                    }),
                )));
            Ok(())
        }
    }
    impl Execute for ProposeAccountRecovery {
        #[metrics(+"propose_account_recovery")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let ProposeAccountRecovery {
                alias,
                new_controller,
                request_generation,
            } = self;
            let current_account = active_account_for_alias(state_transaction, &alias)?;
            let policy = state_transaction
                .world
                .account_recovery_policies
                .get(&alias)
                .cloned()
                .ok_or_else(|| {
                    invalid_account_recovery(format!(
                        "account recovery policy for `{alias:?}` does not exist"
                    ))
                })?;
            if authority != &current_account
                && !current_account_is_recovery_guardian(&policy, authority)
            {
                return Err(invalid_account_recovery(format!(
                    "only the active account or a configured guardian may propose recovery for `{alias:?}`"
                )));
            }
            if state_transaction
                .world
                .account_recovery_requests
                .get(&alias)
                .is_some_and(AccountRecoveryRequest::is_pending)
            {
                return Err(invalid_account_recovery(format!(
                    "account recovery for `{alias:?}` already has a pending request"
                )));
            }
            let expected_generation = state_transaction
                .world
                .account_recovery_requests
                .get(&alias)
                .map_or(Ok(NonZeroU64::MIN), |previous| {
                    previous
                        .request_generation
                        .get()
                        .checked_add(1)
                        .and_then(NonZeroU64::new)
                        .ok_or_else(|| {
                            invalid_account_recovery(format!(
                                "account recovery request generation for `{alias:?}` is exhausted"
                            ))
                        })
                })?;
            if request_generation != expected_generation {
                return Err(invalid_account_recovery(format!(
                    "account recovery request generation mismatch for `{alias:?}`: expected {expected_generation}, received {request_generation}"
                )));
            }
            let candidate = proposed_account_id(&new_controller);
            if candidate == current_account {
                return Err(invalid_account_recovery(format!(
                    "replacement controller for `{alias:?}` must change the canonical account id"
                )));
            }
            if state_transaction.world.accounts.get(&candidate).is_some() {
                return Err(invalid_account_recovery(format!(
                    "replacement controller for `{alias:?}` resolves to existing account `{candidate}`"
                )));
            }
            let execute_after_ms = state_transaction
                .block_unix_timestamp_ms()
                .saturating_add(policy.timelock_ms.get());
            let request = AccountRecoveryRequest::new(
                alias.clone(),
                request_generation,
                current_account.clone(),
                new_controller,
                authority.clone(),
                execute_after_ms,
            );
            state_transaction
                .world
                .account_recovery_requests
                .insert(alias.clone(), request.clone());
            state_transaction
                .world
                .emit_events(Some(AccountEvent::Recovery(
                    AccountRecoveryEvent::Proposed(AccountRecoveryProposed {
                        account: current_account,
                        alias,
                        request,
                    }),
                )));
            Ok(())
        }
    }
    impl Execute for ApproveAccountRecovery {
        #[metrics(+"approve_account_recovery")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let ApproveAccountRecovery {
                alias,
                request_generation,
            } = self;
            let current_account = active_account_for_alias(state_transaction, &alias)?;
            let policy = state_transaction
                .world
                .account_recovery_policies
                .get(&alias)
                .cloned()
                .ok_or_else(|| {
                    invalid_account_recovery(format!(
                        "account recovery policy for `{alias:?}` does not exist"
                    ))
                })?;
            if !current_account_is_recovery_guardian(&policy, authority) {
                return Err(invalid_account_recovery(format!(
                    "account `{authority}` is not a guardian for `{alias:?}`"
                )));
            }
            let request = state_transaction
                .world
                .account_recovery_requests
                .get(&alias)
                .cloned()
                .ok_or_else(|| {
                    invalid_account_recovery(format!(
                        "account recovery request for `{alias:?}` does not exist"
                    ))
                })?;
            ensure_recovery_request_generation(&request, request_generation)?;
            if !request.is_pending() {
                return Err(invalid_account_recovery(format!(
                    "account recovery request for `{alias:?}` is not pending"
                )));
            }
            ensure_recovery_request_targets_current_lineage(
                state_transaction,
                &request,
                &current_account,
            )?;
            if request
                .cancellation_approvals
                .contains(&authority.subject_id())
            {
                return Err(invalid_account_recovery(format!(
                    "guardian `{authority}` already approved cancellation for `{alias:?}`"
                )));
            }
            let request = state_transaction
                .world
                .account_recovery_requests
                .get_mut(&alias)
                .expect("recovery request was verified immediately before mutation");
            request.approve(authority);
            let updated_request = request.clone();
            state_transaction
                .world
                .emit_events(Some(AccountEvent::Recovery(
                    AccountRecoveryEvent::Approved(AccountRecoveryApproved {
                        account: current_account,
                        alias,
                        approver: authority.clone(),
                        request: updated_request,
                    }),
                )));
            Ok(())
        }
    }
    impl Execute for CancelAccountRecovery {
        #[metrics(+"cancel_account_recovery")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let CancelAccountRecovery {
                alias,
                request_generation,
            } = self;
            let current_account = active_account_for_alias(state_transaction, &alias)?;
            let policy = state_transaction
                .world
                .account_recovery_policies
                .get(&alias)
                .cloned()
                .ok_or_else(|| {
                    invalid_account_recovery(format!(
                        "account recovery policy for `{alias:?}` does not exist"
                    ))
                })?;
            let request = state_transaction
                .world
                .account_recovery_requests
                .get(&alias)
                .cloned()
                .ok_or_else(|| {
                    invalid_account_recovery(format!(
                        "account recovery request for `{alias:?}` does not exist"
                    ))
                })?;
            ensure_recovery_request_generation(&request, request_generation)?;
            if !request.is_pending() {
                return Err(invalid_account_recovery(format!(
                    "account recovery request for `{alias:?}` is not pending"
                )));
            }
            ensure_recovery_request_targets_current_lineage(
                state_transaction,
                &request,
                &current_account,
            )?;
            let owner_can_cancel = authority == &current_account;
            let guardian_can_vote = current_account_is_recovery_guardian(&policy, authority);
            if !owner_can_cancel && !guardian_can_vote {
                return Err(invalid_account_recovery(format!(
                    "account `{authority}` is not allowed to cancel recovery for `{alias:?}`"
                )));
            }
            let request = state_transaction
                .world
                .account_recovery_requests
                .get_mut(&alias)
                .expect("recovery request was verified immediately before mutation");
            if owner_can_cancel {
                request.cancel();
            } else {
                request.approve_cancellation(authority);
                if policy.quorum_reached(&request.cancellation_approvals) {
                    request.cancel();
                }
            }
            let updated = request.clone();
            let event = if updated.is_pending() {
                AccountRecoveryEvent::CancellationApproved(AccountRecoveryCancellationApproved {
                    account: current_account,
                    alias,
                    approver: authority.clone(),
                    request: updated,
                })
            } else {
                AccountRecoveryEvent::Cancelled(AccountRecoveryCancelled {
                    account: current_account,
                    alias,
                    cancelled_by: authority.clone(),
                    request: updated,
                })
            };
            state_transaction
                .world
                .emit_events(Some(AccountEvent::Recovery(event)));
            Ok(())
        }
    }
    impl Execute for FinalizeAccountRecovery {
        #[metrics(+"finalize_account_recovery")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let FinalizeAccountRecovery {
                alias,
                request_generation,
            } = self;
            let current_account = active_account_for_alias(state_transaction, &alias)?;
            let policy = state_transaction
                .world
                .account_recovery_policies
                .get(&alias)
                .cloned()
                .ok_or_else(|| {
                    invalid_account_recovery(format!(
                        "account recovery policy for `{alias:?}` does not exist"
                    ))
                })?;
            let mut request = state_transaction
                .world
                .account_recovery_requests
                .get(&alias)
                .cloned()
                .ok_or_else(|| {
                    invalid_account_recovery(format!(
                        "account recovery request for `{alias:?}` does not exist"
                    ))
                })?;
            ensure_recovery_request_generation(&request, request_generation)?;
            if !request.is_pending() {
                return Err(invalid_account_recovery(format!(
                    "account recovery request for `{alias:?}` is not pending"
                )));
            }
            if !policy.quorum_reached(&request.approvals) {
                return Err(invalid_account_recovery(format!(
                    "account recovery request for `{alias:?}` has not reached guardian quorum"
                )));
            }
            if state_transaction.block_unix_timestamp_ms() < request.execute_after_ms {
                return Err(invalid_account_recovery(format!(
                    "account recovery request for `{alias:?}` is still timelocked"
                )));
            }
            ensure_recovery_request_targets_current_lineage(
                state_transaction,
                &request,
                &current_account,
            )?;
            request.invalidated_multisig_proposal_ids =
                crate::smartcontracts::isi::multisig::invalidate_outstanding_proposals(
                    state_transaction,
                    &current_account,
                )
                .map_err(|error| {
                    invalid_account_recovery(format!(
                        "failed to invalidate outstanding multisig proposals for `{alias:?}`: {error}"
                    ))
                })?.into_iter().map(|id| *id.as_bytes()).collect();
            let new_account = crate::smartcontracts::isi::multisig::replace_account_controller(
                authority,
                state_transaction,
                &current_account,
                request.proposed_controller.clone(),
            )?;
            request.finalize();
            state_transaction
                .world
                .account_recovery_requests
                .insert(alias.clone(), request.clone());
            state_transaction
                .world
                .emit_events(Some(AccountEvent::ControllerReplaced(
                    AccountControllerReplaced {
                        account: new_account.clone(),
                        previous_account: current_account.clone(),
                        previous_controller: current_account.controller().clone(),
                        new_controller: request.proposed_controller.clone(),
                    },
                )));
            state_transaction
                .world
                .emit_events(Some(AccountEvent::Recovery(
                    AccountRecoveryEvent::Finalized(AccountRecoveryFinalized {
                        account: new_account,
                        previous_account: current_account,
                        alias,
                        request,
                    }),
                )));
            Ok(())
        }
    }
    // centralized in smartcontracts::limits
    impl Execute for Grant<Permission, Account> {
        #[metrics(+"grant_account_permission")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.destination().clone();
            let permission = self.object().clone();
            if !crate::alias::asset_definition_alias_permission_targets_active_binding(
                &state_transaction.world,
                &permission,
                state_transaction.block_unix_timestamp_ms(),
            ) {
                return Err(Error::InvariantViolation(
                    "exact asset-definition alias permission does not target its current live binding"
                        .into(),
                ));
            }
            if crate::validation_fee::permission_targets_enacted_validation_fee_payout_trigger(
                state_transaction,
                &permission,
            )? {
                return Err(Error::InvariantViolation(
                    "an enacted validation-fee payout lifecycle forbids delegating control of its trigger"
                        .into(),
                ));
            }
            if crate::validation_fee::enacted_validation_fee_payout_runtime_permission_owner(
                state_transaction,
                &permission,
            )?
            .is_some_and(|required_owner| required_owner != account_id)
            {
                return Err(Error::InvariantViolation(
                    "an enacted validation-fee payout lifecycle forbids delegating its exact runtime permissions"
                        .into(),
                ));
            }
            // Check if account exists
            state_transaction.world.account_mut(&account_id)?;
            if state_transaction
                .world
                .account_contains_inherent_permission(&account_id, &permission)
            {
                if is_idempotent_alias_permission(&permission) {
                    return Ok(());
                }
                return Err(RepetitionError {
                    instruction: InstructionType::Grant,
                    id: permission.into(),
                }
                .into());
            }
            state_transaction
                .world
                .add_account_permission(&account_id, permission.clone());
            state_transaction
                .world
                .emit_events(Some(AccountEvent::PermissionAdded(
                    AccountPermissionChanged {
                        account: account_id.clone(),
                        permission,
                    },
                )));
            state_transaction.invalidate_permission_cache_for_account(&account_id);
            Ok(())
        }
    }
    impl Execute for Revoke<Permission, Account> {
        #[metrics(+"revoke_account_permission")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.destination().clone();
            let permission = self.object().clone();
            if crate::validation_fee::enacted_validation_fee_payout_runtime_permission_owner(
                state_transaction,
                &permission,
            )?
            .is_some_and(|required_owner| required_owner == account_id)
            {
                return Err(Error::InvariantViolation(
                    "an enacted validation-fee payout lifecycle pins its exact runtime permissions"
                        .into(),
                ));
            }
            // Check if account exists
            state_transaction.world.account(&account_id)?;
            if !state_transaction
                .world
                .remove_account_permission(&account_id, &permission)
            {
                return Err(FindError::Permission(permission.into()).into());
            }
            state_transaction
                .world
                .emit_events(Some(AccountEvent::PermissionRemoved(
                    AccountPermissionChanged {
                        account: account_id.clone(),
                        permission,
                    },
                )));
            state_transaction.invalidate_permission_cache_for_account(&account_id);
            Ok(())
        }
    }
    impl Execute for Grant<RoleId, Account> {
        #[metrics(+"grant_account_role")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.destination().clone();
            let role_id = self.object().clone();
            state_transaction.world.role(&role_id)?;
            state_transaction.world.account(&account_id)?;
            if state_transaction
                .world
                .account_roles
                .insert(
                    RoleIdWithOwner::new(account_id.clone(), role_id.clone()),
                    (),
                )
                .is_some()
            {
                return Err(RepetitionError {
                    instruction: InstructionType::Grant,
                    id: IdBox::RoleId(role_id),
                }
                .into());
            }
            state_transaction
                .world
                .emit_events(Some(AccountEvent::RoleGranted(AccountRoleChanged {
                    account: account_id.clone(),
                    role: role_id,
                })));
            state_transaction.invalidate_permission_cache_for_account(&account_id);
            Ok(())
        }
    }
    impl Execute for Revoke<RoleId, Account> {
        #[metrics(+"revoke_account_role")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.destination().clone();
            let role_id = self.object().clone();
            if state_transaction
                .world
                .account_roles
                .remove(RoleIdWithOwner {
                    account: account_id.clone(),
                    id: role_id.clone(),
                })
                .is_none()
            {
                return Err(FindError::Role(role_id).into());
            }
            state_transaction
                .world
                .emit_events(Some(AccountEvent::RoleRevoked(AccountRoleChanged {
                    account: account_id.clone(),
                    role: role_id,
                })));
            state_transaction.invalidate_permission_cache_for_account(&account_id);
            Ok(())
        }
    }
    /// Stop minting on the [`AssetDefinition`] globally.
    ///
    /// # Errors
    /// If the [`AssetDefinition`] is not `Mintable::Once`.
    #[inline]
    pub fn forbid_minting(definition: &mut AssetDefinition) -> Result<(), MintabilityError> {
        if definition.mintable() == Mintable::Once {
            definition.set_mintable(Mintable::Not);
            Ok(())
        } else {
            Err(MintabilityError::ForbidMintOnMintable)
        }
    }
    #[cfg(test)]
    mod test {
        use crate::smartcontracts::isi::Registrable as _;
        use crate::{
            block::ValidBlock,
            kura::Kura,
            query::store::LiveQueryStore,
            smartcontracts::Execute,
            state::{State, World, WorldReadOnly},
        };
        use core::num::NonZeroU64;
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_data_model::{
            isi::error::InstructionExecutionError,
            prelude::{Account, AssetDefinition, Domain, Grant, Permission, Register},
        };
        use iroha_model_base::domain::DomainId;
        use iroha_model_base::error::ParseError;
        use iroha_primitives::json::Json;
        use iroha_test_samples::{ALICE_ID, gen_account_in};
        #[test]
        fn cannot_forbid_minting_on_asset_mintable_infinitely() -> Result<(), ParseError> {
            let (authority, _authority_keypair) = gen_account_in("wonderland");
            let mut definition = {
                let __asset_definition_id =
                    iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                        DomainId::try_new("hello", "universal")?,
                        "test".parse()?,
                    );
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    "test".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            }
            .build(&authority);
            assert!(super::forbid_minting(&mut definition).is_err());
            Ok(())
        }
        fn checked_keypair() -> KeyPair {
            KeyPair::try_random().expect("account ISI fixture key generation should succeed")
        }
        #[test]
        fn checked_keypair_preserves_default_algorithm() {
            assert_eq!(checked_keypair().algorithm(), Algorithm::default());
        }
        fn new_dummy_block() -> crate::block::CommittedBlock {
            let (leader_public_key, leader_private_key) = checked_keypair().into_parts();
            let peer_id = iroha_model_base::peer::PeerId::new(leader_public_key);
            let topology = crate::sumeragi::network_topology::Topology::new(vec![peer_id]);
            ValidBlock::new_dummy_and_modify_header(&leader_private_key, |h| {
                h.set_height(NonZeroU64::new(1).unwrap());
            })
            .commit(&topology, crate::block::reserve_block_for_tests())
            .unpack(|_| {})
            .unwrap()
        }
        #[test]
        fn duplicate_alias_permission_grant_is_idempotent() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let wonderland: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
            Register::domain(Domain::new(wonderland.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(ALICE_ID.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let permission = Permission::from(
                iroha_executor_data_model::permission::account::CanManageAccountAlias {
                    scope: iroha_executor_data_model::permission::account::AccountAliasPermissionScope::Dataspace(
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    ),
                },
            );
            Grant::account_permission(permission.clone(), ALICE_ID.clone())
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Grant::account_permission(permission.clone(), ALICE_ID.clone())
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let permissions = stx
                .world
                .account_permissions_iter(&ALICE_ID)
                .unwrap()
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(permissions.len(), 1);
            assert_eq!(permissions[0], permission);
        }
        #[test]
        fn duplicate_non_alias_permission_grant_still_rejects() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let wonderland: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
            Register::domain(Domain::new(wonderland.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(ALICE_ID.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let permission = Permission::new("custom_permission".into(), Json::new(()));
            Grant::account_permission(permission.clone(), ALICE_ID.clone())
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let err = Grant::account_permission(permission.clone(), ALICE_ID.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect_err("duplicate non-alias grant must still fail");
            assert!(matches!(err, InstructionExecutionError::Repetition(_)));
        }
    }
}
/// Implementations for account queries.
pub mod query {
    use super::*;
    use crate::smartcontracts::isi::query::json_predicate::{
        predicate_value_equals_str, predicate_values_contain_str,
    };
    use crate::{
        smartcontracts::{ValidQuery, ValidSingularQuery},
        state::{StateReadOnly, WorldReadOnly},
    };
    use eyre::Result;
    use iroha_crypto::PublicKey;
    use iroha_data_model::{
        account::Account,
        permission::Permission,
        query::{
            dsl::{CompoundPredicate, EvaluatePredicate},
            error::QueryExecutionFail as Error,
            json::PredicateJson,
        },
    };
    use iroha_model_base::domain::DomainId;
    #[cfg(test)]
    use iroha_model_base::metadata::Metadata;
    use norito::json::Value;
    use std::collections::BTreeSet;
    fn account_from_entry(
        _world: &impl WorldReadOnly,
        account_id: &AccountId,
        account_value: &AccountValue,
    ) -> Account {
        let details = account_value.as_ref();
        Account {
            id: account_id.clone(),
            metadata: details.metadata.clone(),
            // Generic account queries do not carry an alias-resolution grant into this
            // projection. Keep aliases behind the dedicated, permission-checked queries.
            label: None,
            uaid: details.uaid,
            opaque_ids: details.opaque_ids.clone(),
        }
    }
    fn singular_account_from_entry(
        world: &impl WorldReadOnly,
        account_id: &AccountId,
        account_value: &AccountValue,
    ) -> Result<Account, Error> {
        let details = account_value.as_ref();
        let no_label = None::<AccountAlias>;
        crate::smartcontracts::isi::query::own_singular_query_struct::<Account, 5>(
            [
                account_id,
                &details.metadata,
                &no_label,
                &details.uaid,
                &details.opaque_ids,
            ],
            || account_from_entry(world, account_id, account_value),
        )
    }
    fn latest_ledger_time_ms(state_ro: &impl StateReadOnly) -> u64 {
        state_ro.query_ledger_time_ms()
    }
    fn strict_recovery_account(
        state_ro: &impl StateReadOnly,
        alias: &AccountAlias,
    ) -> Result<AccountId, Error> {
        crate::sns::resolve_active_account_alias(
            state_ro.world(),
            &state_ro.nexus().dataspace_catalog,
            alias,
            latest_ledger_time_ms(state_ro),
        )
        .map_err(|error| Error::Conversion(error.to_string()))?
        .ok_or(Error::NotFound)
    }
    fn recovery_request_matches_current_lineage(
        state_ro: &impl StateReadOnly,
        request: &AccountRecoveryRequest,
        current_account: &AccountId,
    ) -> Result<bool, Error> {
        Ok(
            crate::sns::resolve_active_account_id_rekey_lineage_for_alias(
                state_ro.world(),
                &state_ro.nexus().dataspace_catalog,
                &request.alias,
                &request.active_account_id_at_proposal,
                latest_ledger_time_ms(state_ro),
            )
            .map_err(|error| Error::Conversion(error.to_string()))?
            .as_ref()
                == Some(current_account),
        )
    }
    #[cfg(test)]
    fn seed_domain_name_lease(
        world: &mut crate::state::World,
        owner: &AccountId,
        domain_id: &DomainId,
    ) {
        let selector = crate::sns::selector_for_domain(domain_id).expect("selector");
        let address =
            iroha_data_model::account::AccountAddress::from_account_id(owner).expect("address");
        let record = iroha_data_model::sns::NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![iroha_data_model::sns::NameControllerV1::account(&address)],
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
    }
    #[cfg(test)]
    fn seed_manage_account_alias_dataspace_permission(
        state_transaction: &mut crate::state::StateTransaction<'_, '_>,
        authority: &AccountId,
        dataspace: iroha_model_base::topology::DataSpaceId,
    ) {
        state_transaction.world.add_account_permission(
            authority,
            Permission::from(
                iroha_executor_data_model::permission::account::CanManageAccountAlias {
                    scope:
                        iroha_executor_data_model::permission::account::AccountAliasPermissionScope::Dataspace(
                            dataspace,
                        ),
                },
            ),
        );
    }
    #[cfg(test)]
    fn alias_domain(domain: &DomainId) -> AccountAliasDomain {
        AccountAliasDomain::new(domain.name().clone())
    }
    #[cfg(test)]
    fn seed_manage_account_alias_permissions(
        state_transaction: &mut crate::state::StateTransaction<'_, '_>,
        authority: &AccountId,
        domain: &DomainId,
        dataspace: iroha_model_base::topology::DataSpaceId,
    ) {
        seed_manage_account_alias_dataspace_permission(state_transaction, authority, dataspace);
        state_transaction.world.add_account_permission(
            authority,
            Permission::from(
                iroha_executor_data_model::permission::account::CanManageAccountAlias {
                    scope:
                        iroha_executor_data_model::permission::account::AccountAliasPermissionScope::Domain(
                            domain.clone(),
                        ),
                },
            ),
        );
    }
    #[cfg(test)]
    fn seed_authority_account(world: &mut crate::state::World, authority: &AccountId) {
        let account = Account {
            id: authority.clone(),
            metadata: Metadata::default(),
            label: None,
            uaid: None,
            opaque_ids: Vec::new(),
        };
        let (account_id, account_value) = iroha_data_model::IntoKeyValue::into_key_value(account);
        world.accounts.insert(account_id, account_value);
    }
    #[cfg(test)]
    fn seed_account_alias_lease(
        state_transaction: &mut crate::state::StateTransaction<'_, '_>,
        owner: &AccountId,
        label: &AccountAlias,
    ) {
        let selector = crate::sns::active_account_alias_selector(
            state_transaction.world(),
            &state_transaction.nexus.dataspace_catalog,
            label,
            state_transaction.block_unix_timestamp_ms(),
        )
        .expect("selector");
        let address =
            iroha_data_model::account::AccountAddress::from_account_id(owner).expect("address");
        let record = iroha_data_model::sns::NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![iroha_data_model::sns::NameControllerV1::account(&address)],
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
    #[cfg(test)]
    fn seed_dynamic_dataspace_name_lease(
        state_transaction: &mut crate::state::StateTransaction<'_, '_>,
        owner: &AccountId,
        alias: &str,
        dataspace: iroha_model_base::topology::DataSpaceId,
    ) {
        let selector = crate::sns::selector_for_dataspace_alias(alias).expect("selector");
        let address = iroha_data_model::account::AccountAddress::from_account_id(owner)
            .expect("account address");
        let mut metadata = Metadata::default();
        metadata.insert(
            crate::sns::SNS_DATASPACE_ID_METADATA_KEY
                .parse()
                .expect("dataspace metadata key"),
            iroha_primitives::json::Json::new(dataspace.as_u64()),
        );
        let record = iroha_data_model::sns::NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![iroha_data_model::sns::NameControllerV1::account(&address)],
            0,
            0,
            1_000,
            2_000,
            3_000,
            metadata,
        );
        state_transaction.world.smart_contract_state.insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
    }
    enum AccountAliasValue {
        Unsupported,
        Resolved(Option<String>),
    }
    fn account_alias_value(
        account_id: &AccountId,
        account_value: &AccountValue,
        field: &str,
    ) -> AccountAliasValue {
        let details = account_value.as_ref();
        match field {
            "id" | "account" | "account_id" => {
                AccountAliasValue::Resolved(Some(account_id.to_string()))
            }
            "uaid" | "universal_account_id" => {
                AccountAliasValue::Resolved(details.uaid().map(ToString::to_string))
            }
            _ => AccountAliasValue::Unsupported,
        }
    }
    fn account_field_is_id(field: &str) -> bool {
        matches!(field, "id" | "account" | "account_id")
    }
    fn account_field_is_domain(field: &str) -> bool {
        matches!(field, "domain" | "id.domain" | "account.domain")
    }
    fn parse_account_id_value(value: &Value) -> Option<AccountId> {
        match value {
            Value::String(raw) => AccountId::parse_encoded(raw)
                .ok()
                .or_else(|| raw.parse::<PublicKey>().ok().map(AccountId::new)),
            _ => None,
        }
    }
    fn parse_account_domain_value(value: &Value) -> Option<DomainId> {
        match value {
            Value::String(raw) => DomainId::parse_fully_qualified(raw)
                .ok()
                .or_else(|| DomainId::try_new(raw, "universal").ok()),
            _ => None,
        }
    }
    fn intersect_account_id_candidates(
        candidates: &mut Option<BTreeSet<AccountId>>,
        next: BTreeSet<AccountId>,
    ) {
        if let Some(existing) = candidates {
            existing.retain(|candidate| next.contains(candidate));
            return;
        }
        *candidates = Some(next);
    }
    /// Extract account-id candidates constrained by JSON predicate clauses.
    ///
    /// Returns `None` when the predicate does not constrain id/account fields.
    /// Returns `Some(empty-set)` when id/account constraints are unsatisfiable.
    fn account_predicate_candidate_ids(predicate: &PredicateJson) -> Option<BTreeSet<AccountId>> {
        let mut candidates: Option<BTreeSet<AccountId>> = None;
        for cond in &predicate.equals {
            if !account_field_is_id(&cond.field) {
                continue;
            }
            let next = parse_account_id_value(&cond.value)
                .into_iter()
                .collect::<BTreeSet<_>>();
            intersect_account_id_candidates(&mut candidates, next);
        }
        for cond in &predicate.r#in {
            if !account_field_is_id(&cond.field) {
                continue;
            }
            let next = cond
                .values
                .iter()
                .filter_map(parse_account_id_value)
                .collect::<BTreeSet<_>>();
            intersect_account_id_candidates(&mut candidates, next);
        }
        candidates
    }
    fn account_predicate_candidate_domain_ids(
        world: &impl WorldReadOnly,
        predicate: &PredicateJson,
    ) -> Option<BTreeSet<AccountId>> {
        let mut candidates: Option<BTreeSet<AccountId>> = None;
        for cond in &predicate.equals {
            if !account_field_is_domain(&cond.field) {
                continue;
            }
            let next = parse_account_domain_value(&cond.value)
                .into_iter()
                .flat_map(|domain| world.account_subjects_in_domain(&domain))
                .collect::<BTreeSet<_>>();
            intersect_account_id_candidates(&mut candidates, next);
        }
        for cond in &predicate.r#in {
            if !account_field_is_domain(&cond.field) {
                continue;
            }
            let next = cond
                .values
                .iter()
                .filter_map(parse_account_domain_value)
                .flat_map(|domain| world.account_subjects_in_domain(&domain))
                .collect::<BTreeSet<_>>();
            intersect_account_id_candidates(&mut candidates, next);
        }
        candidates
    }
    fn merge_account_candidate_sets(
        ids: Option<BTreeSet<AccountId>>,
        domains: Option<BTreeSet<AccountId>>,
    ) -> Option<BTreeSet<AccountId>> {
        match (ids, domains) {
            (Some(ids), Some(domains)) => Some(
                ids.into_iter()
                    .filter(|account_id| domains.contains(account_id))
                    .collect(),
            ),
            (Some(ids), None) => Some(ids),
            (None, Some(domains)) => Some(domains),
            (None, None) => None,
        }
    }
    fn nonzero_asset_holders_for_definition(
        world: &impl WorldReadOnly,
        definition_id: &AssetDefinitionId,
    ) -> BTreeSet<AccountId> {
        world
            .asset_definition_nonzero_holders_iter(definition_id)
            .cloned()
            .collect()
    }
    enum AccountSimpleIdPath {
        One(AccountId),
        Set(BTreeSet<AccountId>),
    }
    fn account_predicate_simple_id_path(predicate: &PredicateJson) -> Option<AccountSimpleIdPath> {
        if !predicate.exists.is_empty() {
            return None;
        }
        if predicate.r#in.is_empty() && predicate.equals.len() == 1 {
            let cond = &predicate.equals[0];
            if !account_field_is_id(&cond.field) {
                return None;
            }
            return parse_account_id_value(&cond.value).map(AccountSimpleIdPath::One);
        }
        if predicate.equals.is_empty() && predicate.r#in.len() == 1 {
            let cond = &predicate.r#in[0];
            if !account_field_is_id(&cond.field) {
                return None;
            }
            let ids = cond
                .values
                .iter()
                .map(parse_account_id_value)
                .collect::<Option<BTreeSet<_>>>()?;
            return Some(AccountSimpleIdPath::Set(ids));
        }
        None
    }
    fn predicate_is_id_only(predicate: &PredicateJson) -> bool {
        let has_any_clause = !predicate.equals.is_empty()
            || !predicate.r#in.is_empty()
            || !predicate.exists.is_empty();
        has_any_clause
            && predicate
                .equals
                .iter()
                .all(|cond| account_field_is_id(&cond.field))
            && predicate
                .r#in
                .iter()
                .all(|cond| account_field_is_id(&cond.field))
            && predicate
                .exists
                .iter()
                .all(|field| account_field_is_id(field))
    }
    enum AccountPredicateMatch {
        Matched,
        Mismatched,
        NeedsJsonFallback(PredicateJson),
    }
    /// Evaluate account-id, UAID, and domain-alias predicate fields directly.
    ///
    /// Fields consumed here are stripped from the JSON fallback so synthetic account-domain
    /// aliases are not re-evaluated against the plain `Account` JSON shape.
    fn predicate_matches_account_aliases(
        world: &impl WorldReadOnly,
        predicate: &PredicateJson,
        account_id: &AccountId,
        account_value: &AccountValue,
    ) -> AccountPredicateMatch {
        let mut remaining = PredicateJson::default();
        for cond in &predicate.equals {
            match account_alias_value(account_id, account_value, &cond.field) {
                AccountAliasValue::Resolved(Some(alias)) => {
                    if !predicate_value_equals_str(&cond.value, &alias) {
                        return AccountPredicateMatch::Mismatched;
                    }
                }
                AccountAliasValue::Resolved(None) => return AccountPredicateMatch::Mismatched,
                AccountAliasValue::Unsupported if account_field_is_domain(&cond.field) => {
                    let Some(domain) = parse_account_domain_value(&cond.value) else {
                        return AccountPredicateMatch::Mismatched;
                    };
                    if !world.account_has_alias_domain(account_id, &domain) {
                        return AccountPredicateMatch::Mismatched;
                    }
                }
                AccountAliasValue::Unsupported => remaining.equals.push(cond.clone()),
            }
        }
        for cond in &predicate.r#in {
            match account_alias_value(account_id, account_value, &cond.field) {
                AccountAliasValue::Resolved(Some(alias)) => {
                    if !predicate_values_contain_str(&cond.values, &alias) {
                        return AccountPredicateMatch::Mismatched;
                    }
                }
                AccountAliasValue::Resolved(None) => return AccountPredicateMatch::Mismatched,
                AccountAliasValue::Unsupported if account_field_is_domain(&cond.field) => {
                    if !cond
                        .values
                        .iter()
                        .filter_map(parse_account_domain_value)
                        .any(|domain| world.account_has_alias_domain(account_id, &domain))
                    {
                        return AccountPredicateMatch::Mismatched;
                    }
                }
                AccountAliasValue::Unsupported => remaining.r#in.push(cond.clone()),
            }
        }
        for field in &predicate.exists {
            match account_alias_value(account_id, account_value, field) {
                AccountAliasValue::Resolved(Some(_)) => {}
                AccountAliasValue::Resolved(None) => return AccountPredicateMatch::Mismatched,
                AccountAliasValue::Unsupported if account_field_is_domain(field) => {
                    let Ok(domains) = world.account_domains(account_id) else {
                        return AccountPredicateMatch::Mismatched;
                    };
                    if domains.is_empty() {
                        return AccountPredicateMatch::Mismatched;
                    }
                }
                AccountAliasValue::Unsupported => remaining.exists.push(field.clone()),
            }
        }
        if remaining.is_empty() {
            AccountPredicateMatch::Matched
        } else {
            AccountPredicateMatch::NeedsJsonFallback(remaining)
        }
    }
    fn account_matches_filter(
        world: &impl WorldReadOnly,
        filter: &CompoundPredicate<Account>,
        predicate_json: Option<&PredicateJson>,
        account_id: &AccountId,
        account_value: &AccountValue,
    ) -> Option<Account> {
        if let Some(predicate) = predicate_json {
            match predicate_matches_account_aliases(world, predicate, account_id, account_value) {
                AccountPredicateMatch::Matched => {
                    return Some(account_from_entry(world, account_id, account_value));
                }
                AccountPredicateMatch::Mismatched => return None,
                AccountPredicateMatch::NeedsJsonFallback(remaining) => {
                    let account = account_from_entry(world, account_id, account_value);
                    return remaining
                        .into_compound::<Account>()
                        .map_or_else(
                            |_| filter.applies(&account),
                            |filter| filter.applies(&account),
                        )
                        .then_some(account);
                }
            }
        }
        let account = account_from_entry(world, account_id, account_value);
        filter.applies(&account).then_some(account)
    }
    impl ValidQuery for FindRolesByAccountId {
        #[metrics(+"find_roles_by_account_id")]
        fn execute(
            self,
            filter: CompoundPredicate<RoleId>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = RoleId>, Error> {
            let account_id = self.account_id();
            state_ro.world().account(account_id)?;
            Ok(state_ro
                .world()
                .account_roles_iter(account_id)
                .filter(move |&role_id| filter.applies(role_id))
                .cloned())
        }
    }
    impl ValidQuery for FindPermissionsByAccountId {
        #[metrics(+"find_permissions_by_account_id")]
        fn execute(
            self,
            filter: CompoundPredicate<Permission>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = Permission>, Error> {
            let account_id = self.account_id();
            Ok(state_ro
                .world()
                .account_permissions_iter(account_id)?
                .filter(move |&permission| filter.applies(permission))
                .cloned())
        }
    }
    impl ValidQuery for FindAccounts {
        #[metrics(+"find_accounts")]
        fn execute(
            self,
            filter: CompoundPredicate<Account>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = Account>, Error> {
            let world = state_ro.world();
            let filter_payload = filter.json_payload();
            if filter_payload.is_none() {
                let iter: Box<dyn Iterator<Item = Account> + '_> = Box::new(
                    world
                        .accounts_iter()
                        .map(|entry| account_from_entry(world, entry.id(), entry.value())),
                );
                return Ok(iter);
            }
            let predicate_json = filter_payload.and_then(
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution,
            );
            let simple_id_path = predicate_json
                .as_ref()
                .and_then(account_predicate_simple_id_path);
            if let Some(path) = simple_id_path {
                let iter: Box<dyn Iterator<Item = Account> + '_> = match path {
                    AccountSimpleIdPath::One(account_id) => {
                        Box::new(world.accounts().get_key_value(&account_id).into_iter().map(
                            |(account_id, account_value)| {
                                account_from_entry(world, account_id, account_value)
                            },
                        ))
                    }
                    AccountSimpleIdPath::Set(account_ids) => {
                        Box::new(account_ids.into_iter().filter_map(move |account_id| {
                            world.accounts().get_key_value(&account_id).map(
                                |(account_id, account_value)| {
                                    account_from_entry(world, account_id, account_value)
                                },
                            )
                        }))
                    }
                };
                return Ok(iter);
            }
            let candidate_ids = merge_account_candidate_sets(
                predicate_json
                    .as_ref()
                    .and_then(account_predicate_candidate_ids),
                predicate_json
                    .as_ref()
                    .and_then(|predicate| account_predicate_candidate_domain_ids(world, predicate)),
            );
            let id_only_predicate = predicate_json.as_ref().is_some_and(predicate_is_id_only);
            if let Some(candidates) = candidate_ids {
                let iter: Box<dyn Iterator<Item = Account> + '_> =
                    Box::new(candidates.into_iter().filter_map(move |account_id| {
                        let Some((account_id, account_value)) =
                            world.accounts().get_key_value(&account_id)
                        else {
                            return None;
                        };
                        if id_only_predicate {
                            return Some(account_from_entry(world, account_id, account_value));
                        }
                        account_matches_filter(
                            world,
                            &filter,
                            predicate_json.as_ref(),
                            account_id,
                            account_value,
                        )
                    }));
                return Ok(iter);
            }
            let iter: Box<dyn Iterator<Item = Account> + '_> =
                Box::new(world.accounts_iter().filter_map(move |entry| {
                    account_matches_filter(
                        world,
                        &filter,
                        predicate_json.as_ref(),
                        entry.id(),
                        entry.value(),
                    )
                }));
            Ok(iter)
        }
    }
    impl ValidQuery for FindAccountIds {
        #[metrics(+"find_account_ids")]
        fn execute(
            self,
            filter: CompoundPredicate<AccountId>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = AccountId>, Error> {
            let world = state_ro.world();
            let predicate_json = filter.json_payload().and_then(
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution,
            );
            if let Some(path) = predicate_json
                .as_ref()
                .and_then(account_predicate_simple_id_path)
            {
                let iter: Box<dyn Iterator<Item = AccountId> + '_> = match path {
                    AccountSimpleIdPath::One(account_id) => Box::new(
                        world
                            .accounts()
                            .get_key_value(&account_id)
                            .map(|(account_id, _)| account_id.clone())
                            .into_iter(),
                    ),
                    AccountSimpleIdPath::Set(account_ids) => {
                        Box::new(account_ids.into_iter().filter_map(move |account_id| {
                            world
                                .accounts()
                                .get_key_value(&account_id)
                                .map(|(account_id, _)| account_id.clone())
                        }))
                    }
                };
                return Ok(iter);
            }
            let candidate_ids = predicate_json
                .as_ref()
                .and_then(account_predicate_candidate_ids);
            let id_only_predicate = predicate_json.as_ref().is_some_and(predicate_is_id_only);
            if let Some(candidates) = candidate_ids {
                let iter: Box<dyn Iterator<Item = AccountId> + '_> =
                    Box::new(candidates.into_iter().filter_map(move |account_id| {
                        let Some((account_id, _)) = world.accounts().get_key_value(&account_id)
                        else {
                            return None;
                        };
                        if id_only_predicate || filter.applies(account_id) {
                            Some(account_id.clone())
                        } else {
                            None
                        }
                    }));
                return Ok(iter);
            }
            let iter: Box<dyn Iterator<Item = AccountId> + '_> = Box::new(
                world
                    .accounts_iter()
                    .map(|entry| entry.id().clone())
                    .filter(move |account_id| filter.applies(account_id)),
            );
            Ok(iter)
        }
    }
    impl ValidQuery for FindAccountsWithAsset {
        #[metrics(+"find_accounts_with_asset")]
        fn execute(
            self,
            filter: CompoundPredicate<Account>,
            state_ro: &impl StateReadOnly,
        ) -> std::result::Result<impl Iterator<Item = Account>, Error> {
            let asset_definition_id = self.asset_definition_id().clone();
            let world = state_ro.world();
            let filter_payload = filter.json_payload();
            trace!(%asset_definition_id);
            if filter_payload.is_none() {
                let subjects = nonzero_asset_holders_for_definition(world, &asset_definition_id);
                let iter: Box<dyn Iterator<Item = Account> + '_> =
                    Box::new(subjects.into_iter().filter_map(move |subject| {
                        let Some((account_id, account_value)) =
                            world.accounts().get_key_value(&subject)
                        else {
                            return None;
                        };
                        Some(account_from_entry(world, account_id, account_value))
                    }));
                return Ok(iter);
            }
            let predicate_json = filter_payload.and_then(
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution,
            );
            let simple_id_path = predicate_json
                .as_ref()
                .and_then(account_predicate_simple_id_path);
            if let Some(path) = simple_id_path {
                let holders = nonzero_asset_holders_for_definition(world, &asset_definition_id);
                let subjects = match path {
                    AccountSimpleIdPath::One(account_id) => holders
                        .contains(&account_id)
                        .then_some(account_id)
                        .into_iter()
                        .collect::<Vec<_>>(),
                    AccountSimpleIdPath::Set(account_ids) => account_ids
                        .iter()
                        .filter(|account_id| holders.contains(*account_id))
                        .cloned()
                        .collect::<Vec<_>>(),
                };
                let iter: Box<dyn Iterator<Item = Account> + '_> =
                    Box::new(subjects.into_iter().filter_map(move |subject| {
                        let Some((account_id, account_value)) =
                            world.accounts().get_key_value(&subject)
                        else {
                            return None;
                        };
                        Some(account_from_entry(world, account_id, account_value))
                    }));
                return Ok(iter);
            }
            let candidate_ids = merge_account_candidate_sets(
                predicate_json
                    .as_ref()
                    .and_then(account_predicate_candidate_ids),
                predicate_json
                    .as_ref()
                    .and_then(|predicate| account_predicate_candidate_domain_ids(world, predicate)),
            );
            let id_only_predicate = predicate_json.as_ref().is_some_and(predicate_is_id_only);
            let holders = nonzero_asset_holders_for_definition(world, &asset_definition_id);
            let subjects = match candidate_ids.as_ref() {
                Some(candidates) => candidates
                    .iter()
                    .filter(|account_id| holders.contains(*account_id))
                    .cloned()
                    .collect::<Vec<_>>(),
                None => holders.into_iter().collect::<Vec<_>>(),
            };
            let iter: Box<dyn Iterator<Item = Account> + '_> =
                Box::new(subjects.into_iter().filter_map(move |subject| {
                    let Some((account_id, account_value)) =
                        world.accounts().get_key_value(&subject)
                    else {
                        return None;
                    };
                    if id_only_predicate {
                        return Some(account_from_entry(world, account_id, account_value));
                    }
                    account_matches_filter(
                        world,
                        &filter,
                        predicate_json.as_ref(),
                        account_id,
                        account_value,
                    )
                }));
            Ok(iter)
        }
    }
    impl ValidSingularQuery for FindAccountById {
        #[metrics(+"find_account_by_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Account, Error> {
            let world = state_ro.world();
            let (account_id, account_value) = world
                .accounts()
                .get_key_value(self.account_id())
                .ok_or_else(|| Error::Find(FindError::Account(self.account_id().clone())))?;
            singular_account_from_entry(world, account_id, account_value)
        }
    }
    impl ValidSingularQuery for FindAccountByAlias {
        #[metrics(+"find_account_by_alias")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Account, Error> {
            let world = state_ro.world();
            let now_ms = latest_ledger_time_ms(state_ro);
            let account_id = crate::sns::resolve_active_account_alias(
                world,
                &state_ro.nexus().dataspace_catalog,
                self.alias(),
                now_ms,
            )
            .map_err(|error| match error {
                crate::sns::SnsError::Deferred(_) => Error::GasBudgetExceeded,
                error => Error::Conversion(error.to_string()),
            })?
            .ok_or(Error::NotFound)?;
            let (account_id, account_value) = world
                .accounts()
                .get_key_value(&account_id)
                .ok_or_else(|| Error::Find(FindError::Account(account_id.clone())))?;
            singular_account_from_entry(world, account_id, account_value)
        }
    }
    impl ValidSingularQuery for FindAliasesByAccountId {
        #[metrics(+"find_aliases_by_account_id")]
        fn execute(
            &self,
            state_ro: &impl StateReadOnly,
        ) -> Result<Vec<AccountAliasBindingRecord>, Error> {
            let now_ms = latest_ledger_time_ms(state_ro);
            let dataspace_filter = self
                .dataspace()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|dataspace| {
                    crate::sns::resolve_active_dataspace_id_by_alias(
                        state_ro.world(),
                        &state_ro.nexus().dataspace_catalog,
                        dataspace,
                        now_ms,
                    )
                    .map_err(|error| {
                        if let crate::sns::SnsError::Deferred(_) = error {
                            return Error::GasBudgetExceeded;
                        }
                        Error::Conversion(format!(
                            "invalid account alias dataspace filter `{dataspace}`: {error}"
                        ))
                    })
                })
                .transpose()?;
            let domain_filter = self
                .domain()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|domain| {
                    domain
                        .parse::<iroha_data_model::account::rekey::AccountAliasDomain>()
                        .map_err(|err| {
                            Error::Conversion(format!("invalid alias domain segment: {err}"))
                        })
                })
                .transpose()?;
            let account_id = self.account_id();
            let Some(account) = state_ro.world().accounts().get(account_id) else {
                return Err(Error::NotFound);
            };
            let labels = state_ro
                .world()
                .account_aliases_by_account()
                .get(account_id);
            let mut records = crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(
                labels.map_or(0, BTreeSet::len),
            )?;
            for label in labels.into_iter().flatten() {
                if dataspace_filter.is_some_and(|dataspace| label.dataspace != dataspace)
                    || domain_filter
                        .as_ref()
                        .is_some_and(|domain| label.domain.as_ref() != Some(domain))
                {
                    continue;
                }
                let alias = crate::sns::active_account_alias_literal(
                    state_ro.world(),
                    &state_ro.nexus().dataspace_catalog,
                    label,
                    now_ms,
                )
                .map_err(|err| {
                    Error::Conversion(format!("invalid account alias binding: {err}"))
                })?;
                if crate::sns::resolve_active_account_alias(
                    state_ro.world(),
                    &state_ro.nexus().dataspace_catalog,
                    label,
                    now_ms,
                )
                .map_err(|error| Error::Conversion(error.to_string()))?
                .as_ref()
                    != Some(account_id)
                {
                    continue;
                }
                let dataspace = crate::sns::resolve_active_dataspace_alias_by_id(
                    state_ro.world(),
                    &state_ro.nexus().dataspace_catalog,
                    label.dataspace,
                    now_ms,
                )
                .map_err(|err| {
                    Error::Conversion(format!("invalid account alias dataspace: {err}"))
                })?;
                let selector = crate::sns::active_account_alias_selector(
                    state_ro.world(),
                    &state_ro.nexus().dataspace_catalog,
                    label,
                    now_ms,
                )
                .map_err(|err| {
                    Error::Conversion(format!("invalid account alias selector: {err}"))
                })?;
                let (status, lease_expiry_ms, grace_until_ms, bound_at_ms) = {
                    let record = crate::sns::get_name_record_by_selector(
                        state_ro.world(),
                        &selector,
                        now_ms,
                    )
                    .map_err(|err| {
                        Error::Conversion(format!("invalid account alias lease record: {err}"))
                    })?;
                    (
                        record.status,
                        Some(record.expires_at_ms),
                        Some(record.grace_expires_at_ms),
                        record.registered_at_ms,
                    )
                };
                records.try_push(AccountAliasBindingRecord {
                    account_id: account_id.clone(),
                    alias,
                    dataspace,
                    domain: label.domain.as_ref().map(ToString::to_string),
                    is_primary: account.as_ref().label() == Some(label),
                    status,
                    lease_expiry_ms,
                    grace_until_ms,
                    bound_at_ms,
                })?;
            }
            records.into_vec()
        }
    }
    impl ValidSingularQuery for FindAccountRecoveryPolicyByAlias {
        #[metrics(+"find_account_recovery_policy_by_alias")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<AccountRecoveryPolicy, Error> {
            strict_recovery_account(state_ro, self.alias())?;
            state_ro
                .world()
                .account_recovery_policies()
                .get(self.alias())
                .ok_or(Error::NotFound)
                .and_then(crate::smartcontracts::isi::query::own_singular_query_value)
        }
    }
    impl ValidSingularQuery for FindAccountRecoveryRequestByAlias {
        #[metrics(+"find_account_recovery_request_by_alias")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<AccountRecoveryRequest, Error> {
            let current_account = strict_recovery_account(state_ro, self.alias())?;
            let request = state_ro
                .world()
                .account_recovery_requests()
                .get(self.alias())
                .ok_or(Error::NotFound)?;
            if !recovery_request_matches_current_lineage(state_ro, request, &current_account)? {
                return Err(Error::NotFound);
            }
            crate::smartcontracts::isi::query::own_singular_query_value(request)
        }
    }
    #[cfg(test)]
    mod tests {
        use super::super::isi::ensure_recovery_request_targets_current_lineage;
        use super::*;
        use crate::{
            block::ValidBlock,
            kura::Kura,
            query::store::LiveQueryStore,
            state::{State, World},
        };
        use core::num::NonZeroU64;
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_data_model::isi::error::{InstructionExecutionError, InvalidParameterError};
        use iroha_executor_data_model::permission::peer::CanManagePeers;
        use iroha_primitives::json::Json;
        use iroha_test_samples::{ALICE_ID, gen_account_in};
        fn checked_keypair() -> KeyPair {
            KeyPair::try_random().expect("account query fixture key generation should succeed")
        }
        fn checked_account_id() -> AccountId {
            AccountId::new(checked_keypair().public_key().clone())
        }
        #[test]
        fn checked_keypair_preserves_default_algorithm() {
            assert_eq!(checked_keypair().algorithm(), Algorithm::default());
        }
        fn new_dummy_block() -> crate::block::CommittedBlock {
            let (leader_public_key, leader_private_key) = checked_keypair().into_parts();
            let peer_id = iroha_model_base::peer::PeerId::new(leader_public_key);
            let topology = crate::sumeragi::network_topology::Topology::new(vec![peer_id]);
            ValidBlock::new_dummy_and_modify_header(&leader_private_key, |h| {
                h.set_height(NonZeroU64::new(1).unwrap());
            })
            .commit(&topology, crate::block::reserve_block_for_tests())
            .unpack(|_| {})
            .unwrap()
        }
        fn new_block_header(
            height: u64,
            creation_time_ms: u64,
        ) -> iroha_data_model::block::BlockHeader {
            iroha_data_model::block::BlockHeader::new(
                NonZeroU64::new(height).expect("non-zero block height"),
                None,
                None,
                creation_time_ms,
                0,
            )
        }
        fn new_state_with_authority() -> State {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let mut world = World::default();
            seed_authority_account(&mut world, &ALICE_ID);
            State::new(world, kura, query_handle)
        }
        fn new_state_with_authority_and_domain_lease(domain_id: &DomainId) -> State {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let mut world = World::default();
            seed_authority_account(&mut world, &ALICE_ID);
            seed_domain_name_lease(&mut world, &ALICE_ID, domain_id);
            State::new(world, kura, query_handle)
        }
        fn root_alias(label: &str) -> AccountAlias {
            AccountAlias::domainless(
                label.parse().expect("account alias label"),
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            )
        }
        fn alias_in_domain(label: &str, domain_id: &DomainId) -> AccountAlias {
            AccountAlias::new(
                label.parse().expect("account alias label"),
                Some(iroha_data_model::account::rekey::AccountAliasDomain::new(
                    domain_id.name().clone(),
                )),
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            )
        }
        #[test]
        fn generic_account_metadata_instructions_cannot_mutate_contract_deploy_nonce() {
            let state = new_state_with_authority();
            let mut block = state.block(new_block_header(1, 0));
            let mut stx = block.transaction();
            let key: Name = iroha_data_model::smart_contract::CONTRACT_DEPLOY_NONCE_METADATA_KEY
                .parse()
                .expect("reserved deployment nonce key");
            let error = SetKeyValue::account(ALICE_ID.clone(), key.clone(), Json::new(7_u64))
                .execute(&ALICE_ID, &mut stx)
                .expect_err("generic metadata write must not forge the deployment nonce");
            assert!(
                error
                    .to_string()
                    .contains("native contract deployment state")
            );
            assert!(
                stx.world
                    .account(&ALICE_ID)
                    .expect("authority account")
                    .metadata()
                    .get(&key)
                    .is_none()
            );
            stx.world
                .account_mut(&ALICE_ID)
                .expect("authority account")
                .insert(key.clone(), Json::new(7_u64));
            let error = RemoveKeyValue::account(ALICE_ID.clone(), key.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect_err("generic metadata removal must not reset the deployment nonce");
            assert!(
                error
                    .to_string()
                    .contains("native contract deployment state")
            );
            assert!(
                stx.world
                    .account(&ALICE_ID)
                    .expect("authority account")
                    .metadata()
                    .get(&key)
                    .is_some()
            );
        }
        fn register_labeled_account(
            state_transaction: &mut crate::state::StateTransaction<'_, '_>,
            authority: &AccountId,
            account_id: &AccountId,
            alias: &AccountAlias,
        ) {
            Register::account(Account::new(account_id.clone()))
                .execute(authority, state_transaction)
                .expect("register account");
            seed_account_alias_lease(state_transaction, account_id, alias);
            state_transaction
                .world
                .account_mut(account_id)
                .expect("registered account")
                .set_label(Some(alias.clone()));
            state_transaction
                .world
                .insert_account_alias_binding(alias.clone(), account_id.clone());
            state_transaction.world.replace_account_rekey_record(
                iroha_data_model::account::rekey::AccountRekeyRecord::new(
                    alias.clone(),
                    account_id.clone(),
                ),
            );
        }
        fn assert_smart_contract_error_contains(err: InstructionExecutionError, fragment: &str) {
            match err {
                InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(message),
                ) => {
                    assert!(
                        message.contains(fragment),
                        "expected smart-contract error containing `{fragment}`, got `{message}`"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
        #[test]
        fn find_accounts_with_asset_ignores_zero_holdings() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            // Setup domain and two accounts
            let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("wonderland");
            Register::account(Account::new(acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            // Register asset definition and mint zero to acc1, one to acc2
            let ad: AssetDefinitionId =
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "test_coin".parse().unwrap(),
                );
            Register::asset_definition({
                let __asset_definition_id = ad.clone();
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    "test_coin".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            let a1 = AssetId::new(ad.clone(), acc1.clone());
            let a2 = AssetId::new(ad.clone(), acc2.clone());
            // Seed a zero holding directly; a zero-amount mint is not a valid instruction.
            let (asset_id, value) =
                iroha_data_model::IntoKeyValue::into_key_value(Asset::new(a1, Quantity::zero()));
            stx.world.assets.insert(asset_id, value);
            Mint::asset_quantity(1u32, a2)
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            // Query should only return acc2
            let view = state.view();
            let results: Vec<_> = FindAccountsWithAsset::new(ad)
                .execute(CompoundPredicate::PASS, &view)
                .unwrap()
                .map(|a| a.id)
                .collect();
            assert_eq!(results, vec![acc2]);
        }
        #[test]
        fn replace_account_controller_single_to_single_preserves_linked_state() {
            let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
            let state = new_state_with_authority_and_domain_lease(&domain_id);
            let mut block = state.block(new_block_header(1, 0));
            let mut stx = block.transaction();
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let (account_id, _) = gen_account_in("wonderland");
            let alias = root_alias("merchant");
            register_labeled_account(&mut stx, &ALICE_ID, &account_id, &alias);
            let metadata_key: Name = "tier".parse().unwrap();
            stx.world
                .account_mut(&account_id)
                .unwrap()
                .insert(metadata_key.clone(), Json::new("gold"));
            stx.world
                .add_account_permission(&account_id, Permission::from(CanManagePeers));
            let asset_definition_id =
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    domain_id,
                    "rose".parse().unwrap(),
                );
            Register::asset_definition({
                let __asset_definition_id = asset_definition_id.clone();
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    "rose".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            let old_asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
            Mint::asset_quantity(5u32, old_asset_id.clone())
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let replacement_key = checked_keypair();
            let replacement_account = AccountId::new(replacement_key.public_key().clone());
            ReplaceAccountController {
                account: account_id.clone(),
                new_controller: AccountController::single(replacement_key.public_key().clone()),
            }
            .execute(&account_id, &mut stx)
            .expect("replace single-key controller");
            assert!(matches!(
                stx.world.account(&account_id),
                Err(FindError::Account(_))
            ));
            let replacement = stx.world.account(&replacement_account).unwrap();
            assert_eq!(replacement.label(), Some(&alias));
            assert!(replacement.metadata().get(&metadata_key).is_some());
            let permissions = stx
                .world
                .account_permissions
                .get(&replacement_account)
                .expect("permissions moved to replacement account");
            assert!(permissions.contains(&Permission::from(CanManagePeers)));
            let new_asset_id =
                AssetId::new(asset_definition_id.clone(), replacement_account.clone());
            assert!(stx.world.assets.get(&new_asset_id).is_some());
            let holders = stx
                .world
                .asset_definition_holders
                .get(&asset_definition_id)
                .expect("holder index should be present");
            assert!(holders.contains(&replacement_account));
            assert!(!holders.contains(&account_id));
            assert_eq!(
                stx.world.account_aliases.get(&alias),
                Some(&replacement_account)
            );
            assert_eq!(
                stx.world
                    .account_rekey_records
                    .get(&alias)
                    .expect("rekey record should survive")
                    .active_account_id,
                replacement_account
            );
        }
        #[test]
        fn set_account_recovery_policy_rejects_unlabeled_account() {
            let state = new_state_with_authority();
            let mut block = state.block(new_block_header(1, 0));
            let mut stx = block.transaction();
            let (account_id, _) = gen_account_in("wonderland");
            Register::account(Account::new(account_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let (guardian_id, _) = gen_account_in("wonderland");
            Register::account(Account::new(guardian_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let policy = AccountRecoveryPolicy::new(
                vec![RecoveryGuardian::new(guardian_id, 1)],
                1,
                NonZeroU64::new(10).unwrap(),
            )
            .unwrap();
            let err = SetAccountRecoveryPolicy {
                account: account_id,
                policy,
            }
            .execute(&ALICE_ID, &mut stx)
            .expect_err("unlabeled account should reject recovery policy");
            assert_smart_contract_error_contains(err, "stable alias");
        }
        #[test]
        fn account_recovery_flow_finalizes_after_timelock() {
            let state = new_state_with_authority();
            let owner_id = checked_account_id();
            let guardian_id = checked_account_id();
            let alias = root_alias("guardianed");
            let replacement_key = checked_keypair();
            let replacement_account = AccountId::new(replacement_key.public_key().clone());
            {
                let mut block = state.block(new_block_header(1, 0));
                let mut stx = block.transaction();
                register_labeled_account(&mut stx, &ALICE_ID, &owner_id, &alias);
                Register::account(Account::new(guardian_id.clone()))
                    .execute(&ALICE_ID, &mut stx)
                    .unwrap();
                let policy = AccountRecoveryPolicy::new(
                    vec![RecoveryGuardian::new(guardian_id.clone(), 1)],
                    1,
                    NonZeroU64::new(10).unwrap(),
                )
                .unwrap();
                SetAccountRecoveryPolicy {
                    account: owner_id.clone(),
                    policy: policy.clone(),
                }
                .execute(&owner_id, &mut stx)
                .unwrap();
                ProposeAccountRecovery {
                    alias: alias.clone(),
                    request_generation: NonZeroU64::MIN,
                    new_controller: AccountController::single(replacement_key.public_key().clone()),
                }
                .execute(&owner_id, &mut stx)
                .unwrap();
                ApproveAccountRecovery {
                    alias: alias.clone(),
                    request_generation: NonZeroU64::MIN,
                }
                .execute(&guardian_id, &mut stx)
                .unwrap();
                ApproveAccountRecovery {
                    alias: alias.clone(),
                    request_generation: NonZeroU64::MIN,
                }
                .execute(&guardian_id, &mut stx)
                .unwrap();
                let request = stx
                    .world
                    .account_recovery_requests
                    .get(&alias)
                    .expect("request should be stored");
                assert_eq!(request.approvals.len(), 1);
                let err = FinalizeAccountRecovery {
                    alias: alias.clone(),
                    request_generation: NonZeroU64::MIN,
                }
                .execute(&guardian_id, &mut stx)
                .expect_err("timelock should block immediate finalization");
                assert_smart_contract_error_contains(err, "timelocked");
                stx.apply();
                block.commit_world_overlay_for_testing().unwrap();
            }
            let mut block = state.block(new_block_header(2, 10));
            let mut stx = block.transaction();
            FinalizeAccountRecovery {
                alias: alias.clone(),
                request_generation: NonZeroU64::MIN,
            }
            .execute(&guardian_id, &mut stx)
            .expect("finalize after timelock");
            assert!(matches!(
                stx.world.account(&owner_id),
                Err(FindError::Account(_))
            ));
            assert!(stx.world.account(&replacement_account).is_ok());
            assert_eq!(
                stx.world.account_aliases.get(&alias),
                Some(&replacement_account)
            );
            let terminal_request = stx
                .world
                .account_recovery_requests
                .get(&alias)
                .expect("request should remain for audit");
            assert_eq!(terminal_request.status, AccountRecoveryStatus::Finalized);
            assert!(
                terminal_request
                    .invalidated_multisig_proposal_ids
                    .is_empty(),
                "single-key recovery must retain exact empty invalidation evidence"
            );
            assert!(
                stx.world.account_recovery_policies.get(&alias).is_some(),
                "recovery policy should remain after finalization"
            );
            let err = FinalizeAccountRecovery {
                alias: alias.clone(),
                request_generation: NonZeroU64::MIN,
            }
            .execute(&guardian_id, &mut stx)
            .expect_err("finalized request must not be replayable");
            assert_smart_contract_error_contains(err, "is not pending");
            let err = CancelAccountRecovery {
                alias: alias.clone(),
                request_generation: NonZeroU64::MIN,
            }
            .execute(&guardian_id, &mut stx)
            .expect_err("cancellation must not reverse finalized recovery");
            assert_smart_contract_error_contains(err, "is not pending");
        }
        #[test]
        fn recovery_lineage_accepts_only_explicit_account_id_rekey_suffix() {
            use iroha_data_model::account::rekey::AccountRekeyRecord;
            let state = new_state_with_authority();
            let active = checked_account_id();
            let retired = checked_account_id();
            let alias = root_alias("typed-recovery-lineage");
            let replacement = checked_keypair();
            let mut block = state.block(new_block_header(1, 50));
            let mut stx = block.transaction();
            register_labeled_account(&mut stx, &ALICE_ID, &active, &alias);
            seed_account_alias_lease(&mut stx, &active, &alias);
            let canonical = AccountRekeyRecord::new(alias.clone(), retired.clone())
                .repoint_for_account_id_rekey(active.clone())
                .expect("canonical account-id rekey fixture");
            stx.world.replace_account_rekey_record(canonical.clone());
            let request = AccountRecoveryRequest::new(
                alias.clone(),
                NonZeroU64::MIN,
                retired.clone(),
                AccountController::single(replacement.public_key().clone()),
                active.clone(),
                60,
            );
            ensure_recovery_request_targets_current_lineage(&stx, &request, &active)
                .expect("explicit retired account-id rekey must preserve recovery continuity");
            assert!(
                recovery_request_matches_current_lineage(&stx, &request, &active)
                    .expect("valid recovery lineage state")
            );
            stx.world.replace_account_rekey_record(
                AccountRekeyRecord::new(alias.clone(), retired.clone())
                    .reassign_alias_to_account(active.clone())
                    .expect("alias reassignment fixture"),
            );
            assert!(
                ensure_recovery_request_targets_current_lineage(&stx, &request, &active).is_err(),
                "ordinary alias reassignment must not preserve a prior owner's recovery request"
            );
            assert!(
                !recovery_request_matches_current_lineage(&stx, &request, &active)
                    .expect("valid reassigned lineage state")
            );
            let mut malformed = canonical.clone();
            malformed.transition_provenance.clear();
            stx.world.replace_account_rekey_record(malformed);
            assert!(
                ensure_recovery_request_targets_current_lineage(&stx, &request, &active).is_err(),
                "missing transition provenance must remain non-authorizing"
            );
            stx.world.replace_account_rekey_record(canonical);
            let current_request = AccountRecoveryRequest::new(
                alias.clone(),
                NonZeroU64::MIN,
                active.clone(),
                AccountController::single(checked_keypair().public_key().clone()),
                active.clone(),
                60,
            );
            assert!(
                recovery_request_matches_current_lineage(&stx, &current_request, &active)
                    .expect("valid current lineage state"),
                "the exact currently active account remains its own recovery lineage"
            );
        }
        #[test]
        fn account_recovery_requires_quorum_and_guardian_quorum_can_cancel() {
            let state = new_state_with_authority();
            let owner_id = checked_account_id();
            let guardian_one_id = checked_account_id();
            let guardian_two_id = checked_account_id();
            let alias = root_alias("quorum-guarded");
            let replacement_key = checked_keypair();
            let mut block = state.block(new_block_header(1, 0));
            let mut stx = block.transaction();
            register_labeled_account(&mut stx, &ALICE_ID, &owner_id, &alias);
            Register::account(Account::new(guardian_one_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(guardian_two_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let policy = AccountRecoveryPolicy::new(
                vec![
                    RecoveryGuardian::new(guardian_one_id.clone(), 1),
                    RecoveryGuardian::new(guardian_two_id.clone(), 1),
                ],
                2,
                NonZeroU64::new(10).unwrap(),
            )
            .unwrap();
            SetAccountRecoveryPolicy {
                account: owner_id.clone(),
                policy,
            }
            .execute(&owner_id, &mut stx)
            .unwrap();
            ProposeAccountRecovery {
                alias: alias.clone(),
                request_generation: NonZeroU64::MIN,
                new_controller: AccountController::single(replacement_key.public_key().clone()),
            }
            .execute(&owner_id, &mut stx)
            .unwrap();
            ApproveAccountRecovery {
                alias: alias.clone(),
                request_generation: NonZeroU64::MIN,
            }
            .execute(&guardian_one_id, &mut stx)
            .unwrap();
            let err = FinalizeAccountRecovery {
                alias: alias.clone(),
                request_generation: NonZeroU64::MIN,
            }
            .execute(&guardian_one_id, &mut stx)
            .expect_err("finalization must reject before quorum");
            assert_smart_contract_error_contains(err, "guardian quorum");
            CancelAccountRecovery {
                alias: alias.clone(),
                request_generation: NonZeroU64::MIN,
            }
            .execute(&guardian_one_id, &mut stx)
            .expect("first cancellation vote does not require a replacement approval quorum");
            assert!(matches!(
                stx.world.internal_event_buf.last().unwrap().as_ref(),
                iroha_data_model::events::data::DataEvent::Account(AccountEvent::Recovery(
                    AccountRecoveryEvent::CancellationApproved(event)
                )) if event.approver == guardian_one_id && event.request.is_pending()
            ));
            let first_vote = stx
                .world
                .account_recovery_requests
                .get(&alias)
                .unwrap()
                .clone();
            assert_eq!(first_vote.status, AccountRecoveryStatus::Pending);
            assert!(first_vote.approvals.is_empty());
            assert_eq!(
                first_vote.cancellation_approvals,
                std::collections::BTreeSet::from([guardian_one_id.subject_id(),])
            );
            let held_approve = ApproveAccountRecovery {
                alias: alias.clone(),
                request_generation: NonZeroU64::MIN,
            }
            .execute(&guardian_one_id, &mut stx)
            .expect_err("a held replacement approval cannot undo cancellation consent");
            assert_smart_contract_error_contains(held_approve, "already approved cancellation");
            assert_eq!(
                stx.world.account_recovery_requests.get(&alias),
                Some(&first_vote)
            );
            CancelAccountRecovery {
                alias: alias.clone(),
                request_generation: NonZeroU64::MIN,
            }
            .execute(&guardian_two_id, &mut stx)
            .expect("independent cancellation quorum should be able to cancel");
            assert!(matches!(
                stx.world.internal_event_buf.last().unwrap().as_ref(),
                iroha_data_model::events::data::DataEvent::Account(AccountEvent::Recovery(
                    AccountRecoveryEvent::Cancelled(event)
                )) if event.cancelled_by == guardian_two_id && !event.request.is_pending()
            ));
            let request = stx
                .world
                .account_recovery_requests
                .get(&alias)
                .expect("cancelled request should remain queryable");
            assert_eq!(request.status, AccountRecoveryStatus::Cancelled);
            assert!(request.approvals.is_empty());
            assert_eq!(request.cancellation_approvals.len(), 2);
            let err = FinalizeAccountRecovery {
                alias,
                request_generation: NonZeroU64::MIN,
            }
            .execute(&guardian_two_id, &mut stx)
            .expect_err("a canceled recovery must reject queued finalization");
            assert_smart_contract_error_contains(err, "is not pending");
        }
        #[test]
        fn account_recovery_one_cancellation_vote_cannot_veto_other_guardians_quorum() {
            let state = new_state_with_authority();
            let owner = checked_account_id();
            let guardians = [
                checked_account_id(),
                checked_account_id(),
                checked_account_id(),
            ];
            let alias = root_alias("independent-cancellation");
            let controller = AccountController::single(checked_keypair().public_key().clone());
            let policy = AccountRecoveryPolicy::new(
                guardians
                    .iter()
                    .cloned()
                    .map(|id| RecoveryGuardian::new(id, 1))
                    .collect(),
                2,
                NonZeroU64::new(10).unwrap(),
            )
            .unwrap();
            {
                let mut block = state.block(new_block_header(1, 0));
                let mut stx = block.transaction();
                register_labeled_account(&mut stx, &ALICE_ID, &owner, &alias);
                for guardian in &guardians {
                    Register::account(Account::new(guardian.clone()))
                        .execute(&ALICE_ID, &mut stx)
                        .unwrap();
                }
                SetAccountRecoveryPolicy::new(owner.clone(), policy.clone())
                    .execute(&owner, &mut stx)
                    .unwrap();
                ProposeAccountRecovery::new(alias.clone(), controller, NonZeroU64::MIN)
                    .execute(&owner, &mut stx)
                    .unwrap();
                let original = stx
                    .world
                    .account_recovery_requests
                    .get(&alias)
                    .unwrap()
                    .clone();
                let changed_policy = AccountRecoveryPolicy::new(
                    vec![RecoveryGuardian::new(guardians[0].clone(), 1)],
                    1,
                    NonZeroU64::MIN,
                )
                .unwrap();
                let replace_error = SetAccountRecoveryPolicy::new(owner.clone(), changed_policy)
                    .execute(&owner, &mut stx)
                    .expect_err("pending request must retain its exact guardian council");
                assert_smart_contract_error_contains(
                    replace_error,
                    "cannot be replaced while a request is pending",
                );
                assert_eq!(
                    stx.world.account_recovery_policies.get(&alias),
                    Some(&policy)
                );
                assert_eq!(
                    stx.world.account_recovery_requests.get(&alias),
                    Some(&original)
                );
                CancelAccountRecovery::new(alias.clone(), NonZeroU64::MIN)
                    .execute(&guardians[0], &mut stx)
                    .unwrap();
                for guardian in &guardians[1..] {
                    ApproveAccountRecovery::new(alias.clone(), NonZeroU64::MIN)
                        .execute(guardian, &mut stx)
                        .unwrap();
                }
                let eligible = stx.world.account_recovery_requests.get(&alias).unwrap();
                assert_eq!(eligible.status, AccountRecoveryStatus::Pending);
                assert_eq!(eligible.cancellation_approvals.len(), 1);
                assert!(policy.quorum_reached(&eligible.approvals));
                stx.apply();
                block.commit_world_overlay_for_testing().unwrap();
            }
            let mut block = state.block(new_block_header(2, 10));
            let mut stx = block.transaction();
            FinalizeAccountRecovery::new(alias.clone(), NonZeroU64::MIN)
                .execute(&guardians[1], &mut stx)
                .expect(
                    "one cancellation vote cannot override two independent replacement approvals",
                );
            let finalized = stx.world.account_recovery_requests.get(&alias).unwrap();
            assert_eq!(finalized.status, AccountRecoveryStatus::Finalized);
            assert_eq!(finalized.cancellation_approvals.len(), 1);
            assert_eq!(finalized.approvals.len(), 2);
        }

        #[test]
        fn account_recovery_generations_reject_stale_same_block_replacement_operations() {
            let state = new_state_with_authority();
            let owner = checked_account_id();
            let guardian = checked_account_id();
            let alias = root_alias("generation-guarded");
            let controller = AccountController::single(checked_keypair().public_key().clone());
            let generation_one = NonZeroU64::MIN;
            let generation_two = NonZeroU64::new(2).unwrap();
            let policy = AccountRecoveryPolicy::new(
                vec![RecoveryGuardian::new(guardian.clone(), 1)],
                1,
                NonZeroU64::new(10).unwrap(),
            )
            .unwrap();
            {
                let mut block = state.block(new_block_header(1, 0));
                let mut stx = block.transaction();
                register_labeled_account(&mut stx, &ALICE_ID, &owner, &alias);
                Register::account(Account::new(guardian.clone()))
                    .execute(&ALICE_ID, &mut stx)
                    .unwrap();
                SetAccountRecoveryPolicy::new(owner.clone(), policy.clone())
                    .execute(&owner, &mut stx)
                    .unwrap();
                let wrong_first =
                    ProposeAccountRecovery::new(alias.clone(), controller.clone(), generation_two)
                        .execute(&owner, &mut stx)
                        .expect_err("first generation must be one");
                assert_smart_contract_error_contains(wrong_first, "generation mismatch");
                assert!(stx.world.account_recovery_requests.get(&alias).is_none());
                ProposeAccountRecovery::new(alias.clone(), controller.clone(), generation_one)
                    .execute(&owner, &mut stx)
                    .unwrap();
                ApproveAccountRecovery::new(alias.clone(), generation_one)
                    .execute(&guardian, &mut stx)
                    .unwrap();
                CancelAccountRecovery::new(alias.clone(), generation_one)
                    .execute(&owner, &mut stx)
                    .unwrap();
                let first = stx
                    .world
                    .account_recovery_requests
                    .get(&alias)
                    .unwrap()
                    .clone();
                assert_eq!(first.status, AccountRecoveryStatus::Cancelled);
                ClearAccountRecoveryPolicy::new(owner.clone())
                    .execute(&owner, &mut stx)
                    .unwrap();
                SetAccountRecoveryPolicy::new(owner.clone(), policy)
                    .execute(&owner, &mut stx)
                    .unwrap();
                assert_eq!(
                    stx.world.account_recovery_requests.get(&alias),
                    Some(&first)
                );
                let stale_propose =
                    ProposeAccountRecovery::new(alias.clone(), controller.clone(), generation_one)
                        .execute(&owner, &mut stx)
                        .expect_err("policy replacement cannot reset generation");
                assert_smart_contract_error_contains(stale_propose, "generation mismatch");
                assert_eq!(
                    stx.world.account_recovery_requests.get(&alias),
                    Some(&first)
                );
                ProposeAccountRecovery::new(alias.clone(), controller.clone(), generation_two)
                    .execute(&owner, &mut stx)
                    .unwrap();
                let second = stx
                    .world
                    .account_recovery_requests
                    .get(&alias)
                    .unwrap()
                    .clone();
                assert_eq!(second.request_generation, generation_two);
                assert_eq!(
                    second.active_account_id_at_proposal,
                    first.active_account_id_at_proposal
                );
                assert_eq!(second.proposed_controller, first.proposed_controller);
                assert_eq!(second.proposed_by, first.proposed_by);
                assert_eq!(
                    second.execute_after_ms, first.execute_after_ms,
                    "same block replacement has identical timelock"
                );
                let stale_approve = ApproveAccountRecovery::new(alias.clone(), generation_one)
                    .execute(&guardian, &mut stx)
                    .expect_err("old approval must not vote on identical replacement");
                assert_smart_contract_error_contains(stale_approve, "generation mismatch");
                assert_eq!(
                    stx.world.account_recovery_requests.get(&alias),
                    Some(&second)
                );
                ApproveAccountRecovery::new(alias.clone(), generation_two)
                    .execute(&guardian, &mut stx)
                    .unwrap();
                let approved = stx
                    .world
                    .account_recovery_requests
                    .get(&alias)
                    .unwrap()
                    .clone();
                let stale_cancel = CancelAccountRecovery::new(alias.clone(), generation_one)
                    .execute(&owner, &mut stx)
                    .expect_err("owner's old Cancel cannot cancel replacement");
                assert_smart_contract_error_contains(stale_cancel, "generation mismatch");
                let stale_finalize = FinalizeAccountRecovery::new(alias.clone(), generation_one)
                    .execute(&guardian, &mut stx)
                    .expect_err("old Finalize must bind exact generation before timelock");
                assert_smart_contract_error_contains(stale_finalize, "generation mismatch");
                assert_eq!(
                    stx.world.account_recovery_requests.get(&alias),
                    Some(&approved)
                );
                stx.apply();
                block.commit_world_overlay_for_testing().unwrap();
            }
            let mut block = state.block(new_block_header(2, 10));
            let mut stx = block.transaction();
            let approved = stx
                .world
                .account_recovery_requests
                .get(&alias)
                .unwrap()
                .clone();
            let stale_finalize = FinalizeAccountRecovery::new(alias.clone(), generation_one)
                .execute(&guardian, &mut stx)
                .expect_err("old Finalize cannot rekey eligible replacement");
            assert_smart_contract_error_contains(stale_finalize, "generation mismatch");
            assert_eq!(
                stx.world.account_recovery_requests.get(&alias),
                Some(&approved)
            );
            assert_eq!(stx.world.account_aliases.get(&alias), Some(&owner));
            FinalizeAccountRecovery::new(alias.clone(), generation_two)
                .execute(&guardian, &mut stx)
                .expect("fresh generation retains normal quorum/timelock finalization");
            let finalized = stx.world.account_recovery_requests.get(&alias).unwrap();
            assert_eq!(finalized.request_generation, generation_two);
            assert_eq!(finalized.status, AccountRecoveryStatus::Finalized);
        }

        #[test]
        fn account_recovery_generation_overflow_preserves_terminal_history() {
            let state = new_state_with_authority();
            let owner = checked_account_id();
            let guardian = checked_account_id();
            let alias = root_alias("generation-exhausted");
            let controller = AccountController::single(checked_keypair().public_key().clone());
            let mut block = state.block(new_block_header(1, 0));
            let mut stx = block.transaction();
            register_labeled_account(&mut stx, &ALICE_ID, &owner, &alias);
            Register::account(Account::new(guardian.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let policy = AccountRecoveryPolicy::new(
                vec![RecoveryGuardian::new(guardian, 1)],
                1,
                NonZeroU64::MIN,
            )
            .unwrap();
            SetAccountRecoveryPolicy::new(owner.clone(), policy.clone())
                .execute(&owner, &mut stx)
                .unwrap();
            let mut terminal = AccountRecoveryRequest::new(
                alias.clone(),
                NonZeroU64::MAX,
                owner.clone(),
                controller.clone(),
                owner.clone(),
                1,
            );
            terminal.cancel();
            stx.world
                .account_recovery_requests
                .insert(alias.clone(), terminal.clone());
            ClearAccountRecoveryPolicy::new(owner.clone())
                .execute(&owner, &mut stx)
                .unwrap();
            SetAccountRecoveryPolicy::new(owner.clone(), policy)
                .execute(&owner, &mut stx)
                .unwrap();
            let error = ProposeAccountRecovery::new(alias.clone(), controller, NonZeroU64::MIN)
                .execute(&owner, &mut stx)
                .expect_err("exhausted generation must never wrap or reset");
            assert_smart_contract_error_contains(error, "generation");
            assert_smart_contract_error_contains(
                ProposeAccountRecovery::new(
                    alias.clone(),
                    AccountController::single(checked_keypair().public_key().clone()),
                    NonZeroU64::MAX,
                )
                .execute(&owner, &mut stx)
                .expect_err("max generation cannot be reused"),
                "is exhausted",
            );
            assert_eq!(
                stx.world.account_recovery_requests.get(&alias),
                Some(&terminal)
            );
        }

        #[test]
        fn find_accounts_returns_registered_accounts_for_pass_predicate() {
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
            let (acc1, _) = gen_account_in("wonderland");
            let (acc2, _) = gen_account_in("wonderland");
            Register::account(Account::new(acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let mut results: Vec<_> = FindAccounts
                .execute(CompoundPredicate::PASS, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            results.sort();
            let mut expected = vec![acc1, acc2];
            expected.sort();
            assert_eq!(results, expected);
        }
        #[test]
        fn find_accounts_applies_predicate() {
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
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("wonderland");
            Register::account(Account::new(acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let tier_key: Name = "tier".parse().unwrap();
            SetKeyValue::account(acc1.clone(), tier_key.clone(), Json::from("gold"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            SetKeyValue::account(acc2.clone(), tier_key, Json::from("silver"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate =
                CompoundPredicate::<Account>::build(|p| p.equals("metadata.tier", "gold"));
            let results: Vec<_> = FindAccounts
                .execute(predicate, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            assert_eq!(results, vec![acc1]);
        }
        #[test]
        fn find_accounts_applies_id_literal_predicate() {
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
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("wonderland");
            Register::account(Account::new(acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate =
                CompoundPredicate::<Account>::build(|p| p.equals("id", acc2.to_string()));
            let results: Vec<_> = FindAccounts
                .execute(predicate, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            assert_eq!(results, vec![acc2]);
        }
        #[test]
        fn find_accounts_applies_id_in_literal_predicate() {
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
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("wonderland");
            let (acc3, _kp3) = gen_account_in("wonderland");
            Register::account(Account::new(acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(acc3.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate = CompoundPredicate::<Account>::build(|p| {
                p.in_values("id", [acc2.to_string(), acc3.to_string()])
            });
            let mut results: Vec<_> = FindAccounts
                .execute(predicate, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            results.sort();
            let mut expected = vec![acc2, acc3];
            expected.sort();
            assert_eq!(results, expected);
        }
        #[test]
        fn find_accounts_filters_by_domain_with_scope_index() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let wonderland_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
            let oasis_id: DomainId = DomainId::try_new("oasis", "universal").unwrap();
            Register::domain(Domain::new(wonderland_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::domain(Domain::new(oasis_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("oasis");
            register_labeled_account(
                &mut stx,
                &ALICE_ID,
                &acc1,
                &alias_in_domain("hatter", &wonderland_id),
            );
            register_labeled_account(
                &mut stx,
                &ALICE_ID,
                &acc2,
                &alias_in_domain("merchant", &oasis_id),
            );
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate = CompoundPredicate::<Account>::build(|p| {
                p.equals("domain", wonderland_id.to_string())
            });
            let results: Vec<_> = FindAccounts
                .execute(predicate, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            assert_eq!(results, vec![acc1.clone()]);
            let predicate = CompoundPredicate::<Account>::build(|p| {
                p.in_values("domain", [wonderland_id.to_string()])
            });
            let results: Vec<_> = FindAccounts
                .execute(predicate, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            assert_eq!(results, vec![acc1.clone()]);
            let predicate = CompoundPredicate::<Account>::build(|p| p.exists("domain"));
            let results: BTreeSet<_> = FindAccounts
                .execute(predicate, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            assert_eq!(results, BTreeSet::from([acc1, acc2]));
        }
        #[test]
        fn find_accounts_applies_mixed_domain_and_metadata_predicate() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let wonderland_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
            let oasis_id: DomainId = DomainId::try_new("oasis", "universal").unwrap();
            Register::domain(Domain::new(wonderland_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::domain(Domain::new(oasis_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("wonderland");
            let (acc3, _kp3) = gen_account_in("oasis");
            register_labeled_account(
                &mut stx,
                &ALICE_ID,
                &acc1,
                &alias_in_domain("hatter", &wonderland_id),
            );
            register_labeled_account(
                &mut stx,
                &ALICE_ID,
                &acc2,
                &alias_in_domain("merchant", &wonderland_id),
            );
            register_labeled_account(
                &mut stx,
                &ALICE_ID,
                &acc3,
                &alias_in_domain("caravan", &oasis_id),
            );
            let tier_key: Name = "tier".parse().unwrap();
            SetKeyValue::account(acc1.clone(), tier_key.clone(), Json::from("gold"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            SetKeyValue::account(acc2.clone(), tier_key.clone(), Json::from("silver"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            SetKeyValue::account(acc3, tier_key, Json::from("gold"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate = CompoundPredicate::<Account>::build(|p| {
                p.equals("id.domain", wonderland_id.to_string())
                    .equals("metadata.tier", "gold")
            });
            let results: Vec<_> = FindAccounts
                .execute(predicate, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            assert_eq!(results, vec![acc1]);
        }
        #[test]
        fn find_accounts_applies_mixed_id_and_metadata_predicate() {
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
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("wonderland");
            Register::account(Account::new(acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let tier_key: Name = "tier".parse().unwrap();
            SetKeyValue::account(acc1.clone(), tier_key.clone(), Json::from("gold"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            SetKeyValue::account(acc2.clone(), tier_key, Json::from("silver"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate = CompoundPredicate::<Account>::build(|p| {
                p.equals("id", acc1.to_string())
                    .equals("metadata.tier", "gold")
            });
            let results: Vec<_> = FindAccounts
                .execute(predicate, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            assert_eq!(results, vec![acc1]);
        }
        #[test]
        fn find_account_ids_uses_direct_id_lookup_for_id_predicates() {
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
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("wonderland");
            let (acc3, _kp3) = gen_account_in("wonderland");
            for account_id in [&acc1, &acc2, &acc3] {
                Register::account(Account::new(account_id.clone()))
                    .execute(&ALICE_ID, &mut stx)
                    .unwrap();
            }
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate = CompoundPredicate::<AccountId>::build(|p| {
                p.in_values("id", [acc1.to_string(), acc3.to_string()])
            });
            let mut results: Vec<_> = FindAccountIds.execute(predicate, &view).unwrap().collect();
            results.sort();
            let mut expected = vec![acc1, acc3];
            expected.sort();
            assert_eq!(results, expected);
        }
        #[test]
        fn find_account_ids_uses_candidate_lookup_for_id_predicates_with_exists() {
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
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("wonderland");
            for account_id in [&acc1, &acc2] {
                Register::account(Account::new(account_id.clone()))
                    .execute(&ALICE_ID, &mut stx)
                    .unwrap();
            }
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate = CompoundPredicate::<AccountId>::build(|p| {
                p.in_values(
                    "id",
                    [
                        acc1.to_string(),
                        "not-an-account-id".to_owned(),
                        acc2.to_string(),
                    ],
                )
                .exists("id")
            });
            let mut results: Vec<_> = FindAccountIds.execute(predicate, &view).unwrap().collect();
            results.sort();
            let mut expected = vec![acc1, acc2];
            expected.sort();
            assert_eq!(results, expected);
        }
        #[test]
        fn find_accounts_with_asset_applies_predicate() {
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
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("wonderland");
            Register::account(Account::new(acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let ad: AssetDefinitionId =
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "test_coin".parse().unwrap(),
                );
            Register::asset_definition({
                let __asset_definition_id = ad.clone();
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    "test_coin".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            Mint::asset_quantity(1u32, AssetId::new(ad.clone(), acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Mint::asset_quantity(1u32, AssetId::new(ad.clone(), acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let tier_key: Name = "tier".parse().unwrap();
            SetKeyValue::account(acc1.clone(), tier_key.clone(), Json::from("gold"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            SetKeyValue::account(acc2.clone(), tier_key, Json::from("silver"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate =
                CompoundPredicate::<Account>::build(|p| p.equals("metadata.tier", "gold"));
            let results: Vec<_> = FindAccountsWithAsset::new(ad)
                .execute(predicate, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            assert_eq!(results, vec![acc1]);
        }
        #[test]
        fn find_accounts_with_asset_uses_nonzero_definition_asset_index() {
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
            let (zero_holder, _zero_kp) = gen_account_in("wonderland");
            let (nonzero_holder, _nonzero_kp) = gen_account_in("wonderland");
            for account_id in [&zero_holder, &nonzero_holder] {
                Register::account(Account::new(account_id.clone()))
                    .execute(&ALICE_ID, &mut stx)
                    .unwrap();
            }
            let definition_id =
                AssetDefinitionId::derive_from_components(domain_id, "test_coin".parse().unwrap());
            Register::asset_definition({
                let definition_id = definition_id.clone();
                AssetDefinition::numeric(
                    definition_id.clone(),
                    "test_coin".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            let zero_asset_id = AssetId::new(definition_id.clone(), zero_holder);
            crate::smartcontracts::isi::asset::isi::seed_numeric_asset_balance_for_test(
                &mut stx.world,
                &zero_asset_id,
                &Quantity::zero(),
            )
            .expect("zero placeholder inserted");
            Mint::asset_quantity(
                1u32,
                AssetId::new(definition_id.clone(), nonzero_holder.clone()),
            )
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            let holders = nonzero_asset_holders_for_definition(&stx.world, &definition_id);
            assert_eq!(holders, BTreeSet::from([nonzero_holder.clone()]));
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let results: Vec<_> = FindAccountsWithAsset::new(definition_id)
                .execute(CompoundPredicate::PASS, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            assert_eq!(results, vec![nonzero_holder]);
        }
        #[test]
        fn find_accounts_with_asset_filters_by_domain_with_scope_index() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let wonderland_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
            let oasis_id: DomainId = DomainId::try_new("oasis", "universal").unwrap();
            Register::domain(Domain::new(wonderland_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::domain(Domain::new(oasis_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("oasis");
            register_labeled_account(
                &mut stx,
                &ALICE_ID,
                &acc1,
                &alias_in_domain("hatter", &wonderland_id),
            );
            register_labeled_account(
                &mut stx,
                &ALICE_ID,
                &acc2,
                &alias_in_domain("merchant", &oasis_id),
            );
            let ad: AssetDefinitionId =
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    wonderland_id.clone(),
                    "test_coin".parse().unwrap(),
                );
            Register::asset_definition({
                let __asset_definition_id = ad.clone();
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    "test_coin".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            Mint::asset_quantity(1u32, AssetId::new(ad.clone(), acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Mint::asset_quantity(1u32, AssetId::new(ad.clone(), acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate = CompoundPredicate::<Account>::build(|p| {
                p.equals("domain", wonderland_id.to_string())
            });
            let results: Vec<_> = FindAccountsWithAsset::new(ad)
                .execute(predicate, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            assert_eq!(results, vec![acc1]);
        }
        #[test]
        fn find_accounts_with_asset_applies_id_literal_predicate() {
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
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("wonderland");
            Register::account(Account::new(acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let ad: AssetDefinitionId =
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "test_coin".parse().unwrap(),
                );
            Register::asset_definition({
                let __asset_definition_id = ad.clone();
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    "test_coin".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            Mint::asset_quantity(1u32, AssetId::new(ad.clone(), acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Mint::asset_quantity(1u32, AssetId::new(ad.clone(), acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate =
                CompoundPredicate::<Account>::build(|p| p.equals("id", acc2.to_string()));
            let results: Vec<_> = FindAccountsWithAsset::new(ad)
                .execute(predicate, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            assert_eq!(results, vec![acc2]);
        }
        #[test]
        fn find_accounts_with_asset_applies_id_in_literal_predicate() {
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
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("wonderland");
            let (acc3, _kp3) = gen_account_in("wonderland");
            Register::account(Account::new(acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(acc3.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let ad: AssetDefinitionId =
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "test_coin".parse().unwrap(),
                );
            Register::asset_definition({
                let __asset_definition_id = ad.clone();
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    "test_coin".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            Mint::asset_quantity(1u32, AssetId::new(ad.clone(), acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Mint::asset_quantity(1u32, AssetId::new(ad.clone(), acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate = CompoundPredicate::<Account>::build(|p| {
                p.in_values("id", [acc2.to_string(), acc3.to_string()])
            });
            let results: Vec<_> = FindAccountsWithAsset::new(ad)
                .execute(predicate, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            assert_eq!(results, vec![acc2]);
        }
        #[test]
        fn find_accounts_with_asset_applies_mixed_id_and_metadata_predicate() {
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
            let (acc1, _kp1) = gen_account_in("wonderland");
            let (acc2, _kp2) = gen_account_in("wonderland");
            Register::account(Account::new(acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let ad: AssetDefinitionId =
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "test_coin".parse().unwrap(),
                );
            Register::asset_definition({
                let __asset_definition_id = ad.clone();
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    "test_coin".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            Mint::asset_quantity(1u32, AssetId::new(ad.clone(), acc1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Mint::asset_quantity(1u32, AssetId::new(ad.clone(), acc2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let tier_key: Name = "tier".parse().unwrap();
            SetKeyValue::account(acc1.clone(), tier_key.clone(), Json::from("gold"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            SetKeyValue::account(acc2.clone(), tier_key, Json::from("silver"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate = CompoundPredicate::<Account>::build(|p| {
                p.equals("id", acc1.to_string())
                    .equals("metadata.tier", "gold")
            });
            let results: Vec<_> = FindAccountsWithAsset::new(ad)
                .execute(predicate, &view)
                .unwrap()
                .map(|account| account.id)
                .collect();
            assert_eq!(results, vec![acc1]);
        }
        #[test]
        fn find_aliases_by_account_id_returns_primary_alias_bindings() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let linked_domain: DomainId = DomainId::try_new("banka", "universal").unwrap();
            let mut world = World::default();
            seed_domain_name_lease(&mut world, &ALICE_ID, &linked_domain);
            seed_authority_account(&mut world, &ALICE_ID);
            let mut state = State::new(world, kura, query_handle);
            state.set_dataspace_catalog_for_testing(
                iroha_data_model::nexus::DataSpaceCatalog::new(vec![
                    iroha_data_model::nexus::DataSpaceMetadata::default(),
                    iroha_data_model::nexus::DataSpaceMetadata {
                        id: iroha_model_base::topology::DataSpaceId::new(9),
                        alias: "centralbank".to_owned(),
                        description: None,
                        fault_tolerance: 1,
                    },
                ])
                .expect("catalog"),
            );
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            stx.world.domains.insert(
                linked_domain.clone(),
                Domain::new(linked_domain.clone()).build(&ALICE_ID),
            );
            seed_manage_account_alias_permissions(
                &mut stx,
                &ALICE_ID,
                &linked_domain,
                iroha_model_base::topology::DataSpaceId::new(9),
            );
            let (account_id, _) = gen_account_in("banka");
            let primary_label = AccountAlias::new_in_dataspace(
                "merchant".parse().expect("label"),
                Some(alias_domain(&linked_domain)),
                iroha_model_base::topology::DataSpaceId::new(9),
            );
            seed_account_alias_lease(&mut stx, &account_id, &primary_label);
            let account = Account::new(account_id.clone())
                .with_label(Some(primary_label.clone()))
                .build(&account_id);
            let (stored_account_id, stored_value) =
                iroha_data_model::IntoKeyValue::into_key_value(account);
            stx.world.accounts.insert(stored_account_id, stored_value);
            stx.world
                .insert_account_alias_binding(primary_label.clone(), account_id.clone());
            stx.world
                .replace_account_rekey_record(AccountRekeyRecord::new(
                    primary_label.clone(),
                    account_id.clone(),
                ));
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let aliases = FindAliasesByAccountId::new(
                account_id.clone(),
                Some("centralbank".to_owned()),
                Some("banka".to_owned()),
            )
            .execute(&view)
            .unwrap();
            assert_eq!(aliases.len(), 1);
            assert_eq!(aliases[0].alias, "merchant@banka.centralbank");
            assert_eq!(aliases[0].dataspace, "centralbank");
            assert_eq!(aliases[0].domain.as_deref(), Some("banka"));
            assert!(aliases[0].is_primary);
        }
        #[test]
        fn find_aliases_by_account_id_resolves_dynamic_only_dataspace() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let mut world = World::default();
            seed_authority_account(&mut world, &ALICE_ID);
            let state = State::new(world, kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let dataspace = iroha_model_base::topology::DataSpaceId::new(42);
            seed_dynamic_dataspace_name_lease(&mut stx, &ALICE_ID, "paynet", dataspace);
            let alias = AccountAlias::domainless("merchant".parse().expect("label"), dataspace);
            seed_account_alias_lease(&mut stx, &ALICE_ID, &alias);
            stx.world
                .insert_account_alias_binding(alias.clone(), ALICE_ID.clone());
            stx.world
                .replace_account_rekey_record(AccountRekeyRecord::new(alias, ALICE_ID.clone()));
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let aliases =
                FindAliasesByAccountId::new(ALICE_ID.clone(), Some("paynet".to_owned()), None)
                    .execute(&state.view())
                    .expect("dynamic-only dataspace filter should resolve");
            assert_eq!(aliases.len(), 1);
            assert_eq!(aliases[0].alias, "merchant@paynet");
            assert_eq!(aliases[0].dataspace, "paynet");
            assert_eq!(aliases[0].domain, None);
            assert!(!aliases[0].is_primary);
        }
        #[test]
        fn sns_account_queries_defer_original_record_refusal_and_retry_without_changing_leaves() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let mut world = World::default();
            seed_authority_account(&mut world, &ALICE_ID);
            let state = State::new(world, kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let dataspace = iroha_model_base::topology::DataSpaceId::new(42);
            seed_dynamic_dataspace_name_lease(&mut stx, &ALICE_ID, "paynet", dataspace);
            let alias = AccountAlias::domainless("merchant".parse().expect("label"), dataspace);
            seed_account_alias_lease(&mut stx, &ALICE_ID, &alias);
            stx.world
                .insert_account_alias_binding(alias.clone(), ALICE_ID.clone());
            stx.world
                .replace_account_rekey_record(AccountRekeyRecord::new(alias, ALICE_ID.clone()));
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let selector = crate::sns::selector_for_dataspace_alias("paynet").unwrap();
            let key = crate::sns::record_storage_key(&selector);
            let view = state.view();
            let original = view
                .world()
                .smart_contract_state()
                .get(&key)
                .unwrap()
                .clone();
            let by_account =
                FindAliasesByAccountId::new(ALICE_ID.clone(), Some("paynet".into()), None);
            let by_alias = FindAccountByAlias::new(AccountAlias::domainless(
                "merchant".parse().unwrap(),
                dataspace,
            ));
            let limits =
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
            norito::with_decode_limits_scope(limits, || {
                assert!(matches!(
                    by_account.execute(&view),
                    Err(Error::GasBudgetExceeded)
                ));
                assert!(matches!(
                    by_alias.execute(&view),
                    Err(Error::GasBudgetExceeded)
                ));
            });
            assert_eq!(
                view.world().smart_contract_state().get(&key),
                Some(&original)
            );
            assert_eq!(by_account.execute(&view).unwrap().len(), 1);
            assert_eq!(by_alias.execute(&view).unwrap().id(), &*ALICE_ID);
            drop(view);
            let mut changed = state.block(block.as_ref().header());
            let mut tx = changed.transaction();
            tx.world.smart_contract_state.insert(key, vec![0xff]);
            assert!(matches!(by_account.execute(&tx), Err(Error::Conversion(_))));
            assert!(matches!(by_alias.execute(&tx), Err(Error::Conversion(_))));
        }
        #[test]
        fn find_aliases_by_account_id_returns_empty_when_filters_do_not_match() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let linked_domain: DomainId = DomainId::try_new("banka", "universal").unwrap();
            let mut world = World::default();
            seed_domain_name_lease(&mut world, &ALICE_ID, &linked_domain);
            seed_authority_account(&mut world, &ALICE_ID);
            let mut state = State::new(world, kura, query_handle);
            state.set_dataspace_catalog_for_testing(
                iroha_data_model::nexus::DataSpaceCatalog::new(vec![
                    iroha_data_model::nexus::DataSpaceMetadata::default(),
                    iroha_data_model::nexus::DataSpaceMetadata {
                        id: iroha_model_base::topology::DataSpaceId::new(9),
                        alias: "centralbank".to_owned(),
                        description: None,
                        fault_tolerance: 1,
                    },
                ])
                .expect("catalog"),
            );
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            stx.world.domains.insert(
                linked_domain.clone(),
                Domain::new(linked_domain.clone()).build(&ALICE_ID),
            );
            seed_manage_account_alias_permissions(
                &mut stx,
                &ALICE_ID,
                &linked_domain,
                iroha_model_base::topology::DataSpaceId::new(9),
            );
            let (account_id, _) = gen_account_in("banka");
            let primary_label = AccountAlias::new_in_dataspace(
                "merchant".parse().expect("label"),
                Some(alias_domain(&linked_domain)),
                iroha_model_base::topology::DataSpaceId::new(9),
            );
            seed_account_alias_lease(&mut stx, &account_id, &primary_label);
            let account = Account::new(account_id.clone())
                .with_label(Some(primary_label.clone()))
                .build(&account_id);
            let (stored_account_id, stored_value) =
                iroha_data_model::IntoKeyValue::into_key_value(account);
            stx.world.accounts.insert(stored_account_id, stored_value);
            stx.world
                .insert_account_alias_binding(primary_label.clone(), account_id.clone());
            stx.world
                .replace_account_rekey_record(AccountRekeyRecord::new(
                    primary_label.clone(),
                    account_id.clone(),
                ));
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let aliases = FindAliasesByAccountId::new(
                account_id,
                Some("centralbank".to_owned()),
                Some("bankb".to_owned()),
            )
            .execute(&view)
            .unwrap();
            assert!(aliases.is_empty());
        }
        #[test]
        fn find_account_by_alias_resolves_primary_alias() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let linked_domain: DomainId = DomainId::try_new("banka", "universal").unwrap();
            let mut world = World::default();
            seed_domain_name_lease(&mut world, &ALICE_ID, &linked_domain);
            seed_authority_account(&mut world, &ALICE_ID);
            let mut state = State::new(world, kura, query_handle);
            state.set_dataspace_catalog_for_testing(
                iroha_data_model::nexus::DataSpaceCatalog::new(vec![
                    iroha_data_model::nexus::DataSpaceMetadata::default(),
                    iroha_data_model::nexus::DataSpaceMetadata {
                        id: iroha_model_base::topology::DataSpaceId::new(9),
                        alias: "centralbank".to_owned(),
                        description: None,
                        fault_tolerance: 1,
                    },
                ])
                .expect("catalog"),
            );
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            Register::domain(Domain::new(linked_domain.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            seed_manage_account_alias_permissions(
                &mut stx,
                &ALICE_ID,
                &linked_domain,
                iroha_model_base::topology::DataSpaceId::new(9),
            );
            let (account_id, _) = gen_account_in("banka");
            let primary_label = AccountAlias::new_in_dataspace(
                "merchant".parse().expect("label"),
                Some(alias_domain(&linked_domain)),
                iroha_model_base::topology::DataSpaceId::new(9),
            );
            seed_account_alias_lease(&mut stx, &account_id, &primary_label);
            let account = Account::new(account_id.clone())
                .with_label(Some(primary_label.clone()))
                .build(&account_id);
            let (stored_account_id, stored_value) =
                iroha_data_model::IntoKeyValue::into_key_value(account);
            stx.world.accounts.insert(stored_account_id, stored_value);
            stx.world
                .insert_account_alias_binding(primary_label.clone(), account_id.clone());
            stx.world
                .replace_account_rekey_record(AccountRekeyRecord::new(
                    primary_label.clone(),
                    account_id.clone(),
                ));
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let account = FindAccountByAlias::new(primary_label)
                .execute(&view)
                .unwrap();
            assert_eq!(account.id(), &account_id);
        }
        #[test]
        fn find_aliases_by_account_id_returns_root_dataspace_alias_without_domain() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let mut world = World::default();
            seed_authority_account(&mut world, &ALICE_ID);
            let mut state = State::new(world, kura, query_handle);
            state.set_dataspace_catalog_for_testing(
                iroha_data_model::nexus::DataSpaceCatalog::new(vec![
                    iroha_data_model::nexus::DataSpaceMetadata::default(),
                    iroha_data_model::nexus::DataSpaceMetadata {
                        id: iroha_model_base::topology::DataSpaceId::new(9),
                        alias: "centralbank".to_owned(),
                        description: None,
                        fault_tolerance: 1,
                    },
                ])
                .expect("catalog"),
            );
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            seed_manage_account_alias_dataspace_permission(
                &mut stx,
                &ALICE_ID,
                iroha_model_base::topology::DataSpaceId::new(9),
            );
            let (account_id, _) = gen_account_in("wonderland");
            let root_label = AccountAlias::new_in_dataspace(
                "merchant".parse().expect("label"),
                None,
                iroha_model_base::topology::DataSpaceId::new(9),
            );
            seed_account_alias_lease(&mut stx, &account_id, &root_label);
            Register::account(Account::new(account_id.clone()).with_label(Some(root_label)))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let aliases =
                FindAliasesByAccountId::new(account_id, Some("centralbank".to_owned()), None)
                    .execute(&view)
                    .unwrap();
            assert_eq!(aliases.len(), 1);
            assert_eq!(aliases[0].alias, "merchant@centralbank");
            assert_eq!(aliases[0].dataspace, "centralbank");
            assert_eq!(aliases[0].domain, None);
            assert!(aliases[0].is_primary);
        }
        #[test]
        fn transfer_asset_definition_rejects_unauthorized_authority() {
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
            let (source, _) = gen_account_in("wonderland");
            let (destination, _) = gen_account_in("wonderland");
            let (intruder, _) = gen_account_in("wonderland");
            Register::account(Account::new(source.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(destination.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(intruder.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let asset_definition: AssetDefinitionId =
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "bond".parse().unwrap(),
                );
            Register::asset_definition({
                let __asset_definition_id = asset_definition.clone();
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    "bond".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            stx.world
                .asset_definition_mut(&asset_definition)
                .unwrap()
                .set_owned_by(source.clone());
            stx.world
                .replace_asset_definition_owner_index(&asset_definition, &ALICE_ID, &source);
            let err = Transfer::asset_definition(
                source.clone(),
                asset_definition.clone(),
                destination.clone(),
            )
            .execute(&intruder, &mut stx)
            .expect_err("unauthorized authority must not transfer asset definition ownership");
            assert!(
                err.to_string().contains("Can't transfer asset definition"),
                "unexpected error: {err}"
            );
            assert_eq!(
                stx.world
                    .asset_definition(&asset_definition)
                    .unwrap()
                    .owned_by(),
                &source,
                "owner must remain unchanged on failed transfer"
            );
        }
        #[test]
        fn transfer_asset_definition_allows_source_owner() {
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
            let (source, _) = gen_account_in("wonderland");
            let (destination, _) = gen_account_in("wonderland");
            Register::account(Account::new(source.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(destination.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let asset_definition: AssetDefinitionId =
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "bond".parse().unwrap(),
                );
            Register::asset_definition({
                let __asset_definition_id = asset_definition.clone();
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    "bond".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            stx.world
                .asset_definition_mut(&asset_definition)
                .unwrap()
                .set_owned_by(source.clone());
            stx.world
                .replace_asset_definition_owner_index(&asset_definition, &ALICE_ID, &source);
            Transfer::asset_definition(
                source.clone(),
                asset_definition.clone(),
                destination.clone(),
            )
            .execute(&source, &mut stx)
            .expect("source owner must be allowed to transfer ownership");
            assert_eq!(
                stx.world
                    .asset_definition(&asset_definition)
                    .unwrap()
                    .owned_by(),
                &destination
            );
            assert!(
                stx.world
                    .asset_definitions_by_owner
                    .get(&destination)
                    .is_some_and(|definitions| definitions.contains(&asset_definition)),
                "successful transfer should update the owner index",
            );
        }
    }
}
